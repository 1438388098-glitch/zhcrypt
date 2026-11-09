#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R18 握手安全回归测试
====================

两项协议缺口 (审计发现):

A. x3dh_init 可被重放: 已有的会话不会被拦住, 试解成功后直接 save_session
   覆盖 —— 棘轮状态被重置、旧明文可再次解出, 前向保密倒退。
B. 身份名与身份公钥无绑定: 接收方直接采信报文里的 sender_identity_pub,
   持有共享 token 的人可以用任意 `from` 名冒充首联系人。

本文件锁定的不变量:
  - 同一 session_id 的 init / 时间戳明显回滚的 init 必须被判定为重放
  - 真正的新握手 (新 session_id + 新时间戳) 仍然允许
  - 已处理过的 init msg_id 二次投递必须被拒 (持久化去重, 重启后仍有效)
  - 双方身份名参与 X3DH 根密钥派生: 任一方身份被替换 → 首条消息解不开
  - 身份一致时握手仍然正常 (不误伤)

运行: py -3.13 -m pytest tests/test_round18_fixes.py -q
"""
import os

import core  # noqa: E402

from chat_client import X3DH_REPLAY_SKEW_SEC, is_x3dh_replay  # noqa: E402
from localstore import LocalStore  # noqa: E402
from ratchet import (  # noqa: E402
    SessionState,
    complete_session_first_message,
    generate_x25519_keypair_raw,
    raw_to_pem_pub,
    send_message,
    x3dh_complete_session,
    x3dh_initiate_session,
)


def _b64d(s):
    return core.urlsafe_b64decode(s.encode())


def _state(session_id=b"\x11" * 16, created_at=1000.0):
    priv, pub = generate_x25519_keypair_raw()
    state = SessionState(
        session_id=session_id, my_identity="bob", peer_identity="alice",
        peer_signing_pub=b"", root_key=os.urandom(32),
        send_chain_key=os.urandom(32), recv_chain_key=os.urandom(32),
        our_ratchet_priv=priv, our_ratchet_pub=pub,
        their_ratchet_pub=b"\x00" * 32,
    )
    state.created_at = created_at
    return state


# ----------------------------------------------------------------------
# A. 重放判定
# ----------------------------------------------------------------------

def test_same_session_id_is_replay():
    state = _state()
    msg = {"id": "m1", "session_id": state.session_id.hex(), "timestamp": 999999.0}
    assert is_x3dh_replay(state, msg) is True


def test_older_timestamp_is_replay():
    state = _state(created_at=1_700_000_000.0)
    msg = {"id": "m2", "session_id": "ff" * 16,
           "timestamp": state.created_at - X3DH_REPLAY_SKEW_SEC - 1}
    assert is_x3dh_replay(state, msg) is True


def test_fresh_new_handshake_is_allowed():
    """对端重装客户端后发起的新握手: 新 session_id + 新时间戳, 必须放行。"""
    state = _state(created_at=1_700_000_000.0)
    msg = {"id": "m3", "session_id": "ab" * 16,
           "timestamp": state.created_at + 60}
    assert is_x3dh_replay(state, msg) is False


def test_clock_skew_within_tolerance_is_allowed():
    state = _state(created_at=1_700_000_000.0)
    msg = {"id": "m4", "session_id": "cd" * 16,
           "timestamp": state.created_at - X3DH_REPLAY_SKEW_SEC + 5}
    assert is_x3dh_replay(state, msg) is False


def test_no_state_is_not_replay():
    assert is_x3dh_replay(None, {"id": "m5", "session_id": "a" * 32}) is False


def test_malformed_timestamp_does_not_crash():
    state = _state(created_at=1_700_000_000.0)
    msg = {"id": "m6", "session_id": "ef" * 16, "timestamp": "not-a-number"}
    assert is_x3dh_replay(state, msg) is False


# ----------------------------------------------------------------------
# A. 持久化去重
# ----------------------------------------------------------------------

def test_mark_init_seen_dedupes(tmp_path):
    store = LocalStore(str(tmp_path / "local.db"))
    assert store.mark_init_seen("msg-1", "alice", "sid-1", 100.0) is True
    assert store.mark_init_seen("msg-1", "alice", "sid-1", 100.0) is False
    assert store.mark_init_seen("msg-2", "alice", "sid-1", 101.0) is True
    store.close()


def test_mark_init_seen_survives_reconnect(tmp_path):
    path = str(tmp_path / "local.db")
    store = LocalStore(path)
    store.mark_init_seen("msg-1", "alice", "sid-1", 100.0)
    store.close()

    reopened = LocalStore(path)          # 模拟客户端重启
    assert reopened.mark_init_seen("msg-1", "alice", "sid-1", 100.0) is False
    reopened.close()


def test_mark_init_seen_keeps_bounded_history(tmp_path):
    store = LocalStore(str(tmp_path / "local.db"))
    for i in range(20):
        store.mark_init_seen("msg-%d" % i, "alice", "sid", float(i))
    # keep=5 -> 只保留最近 5 条; 最早的那条被逐出后可以再次"首次"写入
    store.mark_init_seen("msg-new", "alice", "sid", 100.0, keep=5)
    assert store.mark_init_seen("msg-0", "alice", "sid", 0.0, keep=5) is True
    store.close()


def test_missing_msg_id_is_not_deduped(tmp_path):
    """没有 msg_id 时无法去重, 交给会话级判定兜底, 不应误杀。"""
    store = LocalStore(str(tmp_path / "local.db"))
    assert store.mark_init_seen("", "alice", "sid") is True
    assert store.mark_init_seen("", "alice", "sid") is True
    store.close()


# ----------------------------------------------------------------------
# B. 身份名参与 X3DH 根密钥派生
# ----------------------------------------------------------------------

def _x3dh_pair(responder_identity="alice", initiator_identity="bob"):
    """返回 (initiator_state, first_msg, make_responder)。

    make_responder(sender_identity=None, as_identity=None) 允许调用方故意
    错配身份, 用于验证绑定是否真的生效。
    """
    a_priv, a_pub = generate_x25519_keypair_raw()
    b_priv, b_pub = generate_x25519_keypair_raw()
    a_spk_priv, a_spk_pub = generate_x25519_keypair_raw()

    state_b, extra = x3dh_initiate_session(
        peer_identity_key_pub_pem=raw_to_pem_pub(a_pub),
        peer_signed_prekey_pub_pem=raw_to_pem_pub(a_spk_pub),
        peer_one_time_prekey_pub_b64=None,
        my_identity_priv_raw=b_priv,
        my_identity=initiator_identity,
        peer_identity=responder_identity,
        peer_signing_pub_pem=b"",
    )
    first = send_message(state_b, b"hello")

    def make_responder(sender_identity=None, as_identity=None):
        return x3dh_complete_session(
            my_identity_priv_raw=a_priv,
            my_signed_prekey_priv_raw=a_spk_priv,
            sender_identity_pub_raw=b_pub,
            sender_ephemeral_pub_raw=_b64d(extra["sender_ephemeral_pub"]),
            sender_ratchet_pub_raw=state_b.our_ratchet_pub,
            sender_signing_pub_pem=b"",
            my_identity=as_identity or responder_identity,
            sender_identity=sender_identity or initiator_identity,
            one_time_prekey_priv_raw=None,
            session_id=state_b.session_id,
        )

    return state_b, first, make_responder


def _decrypt_first(responder, state_b, first):
    return complete_session_first_message(
        responder, state_b.our_ratchet_pub,
        first["payload"]["nonce"], first["payload"]["ciphertext"], b"",
    )


def test_identity_binding_happy_path():
    state_b, first, make_responder = _x3dh_pair()
    assert _decrypt_first(make_responder(), state_b, first) == b"hello"


def test_impersonated_sender_identity_breaks_handshake():
    """把发送方身份换成 mallory: 根密钥不同, 首条消息必须解不开。"""
    state_b, first, make_responder = _x3dh_pair()
    responder = make_responder(sender_identity="mallory")
    assert _decrypt_first(responder, state_b, first) is None


def test_impersonated_responder_identity_breaks_handshake():
    """发起方以为对面是 alice, 实际是 eve: 同样必须失败。"""
    state_b, first, make_responder = _x3dh_pair(responder_identity="alice")
    responder = make_responder(as_identity="eve")
    assert _decrypt_first(responder, state_b, first) is None
