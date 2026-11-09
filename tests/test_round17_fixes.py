#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R17 消息头认证与状态事务化回归测试 (pytest)
==========================================

背景 (审计发现的三处叠加缺陷):
  1. AEAD 的 AAD 只有 session_id, ratchet_public_key / message_number /
     previous_chain_length 完全未认证, 中继可任意改写;
  2. 收到与当前不同的棘轮公钥就无条件执行 DH step, 重置整条接收链;
  3. 先推进 recv_chain_key / recv_msg_number, 再解密, 失败也不回滚。

三者叠加的后果: 篡改一个字节就能让会话永久失步, 此后所有合法消息都解不开。

本文件锁定修复后的不变量:
  - 任何字段被篡改 → 解密失败且 **状态零变更**
  - 篡改包之后, 原始合法消息仍可正常解密 (不会"被顶掉")
  - 重放同一 msg_id 被拒
  - 未带版本号的旧格式消息默认拒收
  - 会话落盘重载后 (session_id 由 bytes 变 hex 串) 仍能与对端互通
  - 真实 X3DH 首条消息与后续双向消息在 v2 AAD 下正常工作

运行: py -3.13 -m pytest tests/test_round17_fixes.py -q
"""
import copy
import os

import pytest

import core  # noqa: E402 (conftest 注入 sys.path)

from ratchet import (  # noqa: E402
    SessionState,
    complete_session_first_message,
    generate_x25519_keypair_raw,
    raw_to_pem_pub,
    receive_message,
    send_message,
    x3dh_complete_session,
    x3dh_initiate_session,
)


def _b64(raw):
    return core.urlsafe_b64encode(raw).decode()


def _b64d(s):
    return core.urlsafe_b64decode(s.encode())


def _pair(session_id=None):
    """构造一对已共享会话密钥的状态 (链路密钥互为镜像, 棘轮公钥已互换)。"""
    sid = session_id or os.urandom(16)
    a_priv, a_pub = generate_x25519_keypair_raw()
    b_priv, b_pub = generate_x25519_keypair_raw()
    ck_ab = os.urandom(32)   # alice → bob
    ck_ba = os.urandom(32)   # bob → alice

    alice = SessionState(
        session_id=sid, my_identity="alice", peer_identity="bob",
        peer_signing_pub=b"", root_key=os.urandom(32),
        send_chain_key=ck_ab, recv_chain_key=ck_ba,
        our_ratchet_priv=a_priv, our_ratchet_pub=a_pub,
        their_ratchet_pub=b_pub,
    )
    bob = SessionState(
        session_id=sid, my_identity="bob", peer_identity="alice",
        peer_signing_pub=b"", root_key=os.urandom(32),
        send_chain_key=ck_ba, recv_chain_key=ck_ab,
        our_ratchet_priv=b_priv, our_ratchet_pub=b_pub,
        their_ratchet_pub=a_pub,
    )
    return alice, bob


def _snapshot(state):
    """状态关键字段快照, 用于断言"失败不产生任何副作用"。"""
    return (
        state.root_key,
        state.send_chain_key,
        state.recv_chain_key,
        state.our_ratchet_priv,
        state.our_ratchet_pub,
        state.their_ratchet_pub,
        state.send_msg_number,
        state.recv_msg_number,
        state.prev_send_chain_len,
        {k: dict(v) for k, v in state.skipped_keys.items()},
        list(state.seen_message_ids),
    )


# ----------------------------------------------------------------------
# R17-01: 篡改棘轮公钥 → 拒绝且状态零变更, 原消息仍可解
# ----------------------------------------------------------------------

def test_tampered_ratchet_key_rejected_without_state_change():
    alice, bob = _pair()
    msg = send_message(alice, b"secret-1")
    before = _snapshot(bob)

    forged = copy.deepcopy(msg)
    forged["id"] = "forged-ratchet-pub"
    forged["payload"]["ratchet_public_key"] = _b64(os.urandom(32))

    assert receive_message(bob, forged) is None
    assert _snapshot(bob) == before, "被拒绝的消息不得改动任何会话状态"

    # 关键回归: 伪造包不得"顶掉"后续合法消息
    assert receive_message(bob, msg) == b"secret-1"
    assert bob.recv_msg_number == 1


# ----------------------------------------------------------------------
# R17-02: 篡改消息号 / 密文 → 拒绝且不影响真实消息
# ----------------------------------------------------------------------

@pytest.mark.parametrize("field", ["message_number", "nonce", "ciphertext"])
def test_tampered_payload_rejected_without_state_change(field):
    alice, bob = _pair()
    msg = send_message(alice, b"payload-bytes")
    before = _snapshot(bob)

    forged = copy.deepcopy(msg)
    forged["id"] = f"forged-{field}"
    if field == "message_number":
        forged["payload"][field] = 7
    elif field == "nonce":
        forged["payload"][field] = _b64(os.urandom(12))
    else:
        ct = bytearray(_b64d(forged["payload"][field]))
        ct[0] ^= 0x01
        forged["payload"][field] = _b64(bytes(ct))

    assert receive_message(bob, forged) is None
    assert _snapshot(bob) == before
    assert receive_message(bob, msg) == b"payload-bytes"


# ----------------------------------------------------------------------
# R17-03: 重放同一 msg_id 被拒绝
# ----------------------------------------------------------------------

def test_replay_same_msg_id_rejected():
    alice, bob = _pair()
    msg = send_message(alice, b"once")
    assert receive_message(bob, msg) == b"once"
    assert receive_message(bob, msg) is None


# ----------------------------------------------------------------------
# R17-04: 未带版本号的旧格式消息默认拒收
# ----------------------------------------------------------------------

def test_legacy_unauthenticated_header_rejected(monkeypatch):
    monkeypatch.delenv("ZHCHAT_ALLOW_LEGACY_AAD", raising=False)
    alice, bob = _pair()
    msg = send_message(alice, b"legacy")
    msg["payload"].pop("v")
    before = _snapshot(bob)
    assert receive_message(bob, msg) is None
    assert _snapshot(bob) == before


# ----------------------------------------------------------------------
# R17-05: 伪造 DH 包之后, 同一条链上的后续消息仍能正常收发
# ----------------------------------------------------------------------

def test_one_forged_packet_does_not_kill_session():
    alice, bob = _pair()
    m1 = send_message(alice, b"one")

    forged = copy.deepcopy(m1)
    forged["id"] = "forged-dh"
    forged["payload"]["ratchet_public_key"] = _b64(os.urandom(32))

    assert receive_message(bob, forged) is None
    assert receive_message(bob, m1) == b"one"

    m2 = send_message(alice, b"two")
    assert receive_message(bob, m2) == b"two"

    # 反向也正常
    back = send_message(bob, b"ack")
    assert receive_message(alice, back) == b"ack"


# ----------------------------------------------------------------------
# R17-06: 会话落盘重载 (session_id bytes → hex 串) 后仍互通
# ----------------------------------------------------------------------

def test_session_reload_keeps_aad_consistent():
    alice, bob = _pair()
    alice_reloaded = SessionState.from_dict(alice.to_dict())
    assert isinstance(alice_reloaded.session_id, str)

    msg = send_message(alice_reloaded, b"after-reload")
    assert receive_message(bob, msg) == b"after-reload"


# ----------------------------------------------------------------------
# R17-07: 真实 X3DH 握手 + 首条消息 + 双向通信
# ----------------------------------------------------------------------

def test_x3dh_first_message_and_duplex_under_v2_aad():
    a_id_priv, a_id_pub = generate_x25519_keypair_raw()
    b_id_priv, b_id_pub = generate_x25519_keypair_raw()
    b_spk_priv, b_spk_pub = generate_x25519_keypair_raw()

    state_a, extra = x3dh_initiate_session(
        peer_identity_key_pub_pem=raw_to_pem_pub(b_id_pub),
        peer_signed_prekey_pub_pem=raw_to_pem_pub(b_spk_pub),
        peer_one_time_prekey_pub_b64=None,
        my_identity_priv_raw=a_id_priv,
        my_identity="alice",
        peer_identity="bob",
        peer_signing_pub_pem=b"",
    )

    first = send_message(state_a, b"first-message")
    first["type"] = "x3dh_init"

    def _bob_state():
        return x3dh_complete_session(
            my_identity_priv_raw=b_id_priv,
            my_signed_prekey_priv_raw=b_spk_priv,
            sender_identity_pub_raw=a_id_pub,
            sender_ephemeral_pub_raw=_b64d(extra["sender_ephemeral_pub"]),
            sender_ratchet_pub_raw=state_a.our_ratchet_pub,
            sender_signing_pub_pem=b"",
            my_identity="bob",
            sender_identity="alice",
            one_time_prekey_priv_raw=None,
            session_id=state_a.session_id,
        )

    # 正常路径
    bob = _bob_state()
    plain = complete_session_first_message(
        bob, state_a.our_ratchet_pub,
        first["payload"]["nonce"], first["payload"]["ciphertext"], b"",
    )
    assert plain == b"first-message"

    # 篡改首条消息的棘轮公钥 → 必须失败 (旧实现会静默建立错误会话)
    bob_tampered = _bob_state()
    assert complete_session_first_message(
        bob_tampered, os.urandom(32),
        first["payload"]["nonce"], first["payload"]["ciphertext"], b"",
    ) is None

    # 双向: bob 回复走 send_message, alice 用 receive_message 收
    reply = send_message(bob, b"reply-from-bob")
    assert receive_message(state_a, reply) == b"reply-from-bob"

    # 继续 alice → bob
    second = send_message(state_a, b"second")
    assert receive_message(bob, second) == b"second"
