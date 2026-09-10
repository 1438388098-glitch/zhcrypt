#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R8 协议健壮性与公共 API 回归测试 (pytest)
==========================================

  - DH ratchet step 前按 previous_chain_length 预存旧链 skipped keys
  - complete_session_first_message 先验后进 (失败可重试)
  - strength 非 CJK/非 ASCII 字符集不再记 0
  - streaming.enabled 总开关闭合流式决策
  - keys: bundle 导出→peek→导入往返 / OTP 落盘→加载往返
  - session: cleanup_expired_sessions 按 mtime 回收

运行: py -3.13 -m pytest tests/test_round8_fixes.py -q
"""
import os
import time
import types

import pytest

import core  # noqa: E402 (conftest 注入 sys.path)


def _mkstate(**kw):
    from ratchet import SessionState
    defaults = dict(
        session_id="sid-123",
        my_identity="alice", peer_identity="bob", peer_signing_pub=b"",
        root_key=os.urandom(32),
        send_chain_key=os.urandom(32), recv_chain_key=os.urandom(32),
        our_ratchet_priv=os.urandom(32), our_ratchet_pub=os.urandom(32),
        their_ratchet_pub=os.urandom(32),
    )
    defaults.update(kw)
    return SessionState(**defaults)


# ----------------------------------------------------------------------
# R8-071: DH step 前预存旧链 skipped keys
# ----------------------------------------------------------------------

def test_dh_step_preserves_old_chain_skipped():
    from ratchet import receive_message, KDF_CK
    state = _mkstate(recv_msg_number=2)
    old_recv_ck = state.recv_chain_key
    old_pub = state.their_ratchet_pub
    new_pub = os.urandom(32)

    # 对端已发到 pn=4 (旧链号 2、3 在途), 随新链消息到达
    msg = {"id": "m1",
           "payload": {"ratchet_public_key": core.urlsafe_b64encode(new_pub).decode(),
                       "message_number": 0, "previous_chain_length": 4,
                       "nonce": core.urlsafe_b64encode(os.urandom(12)).decode(),
                       "ciphertext": core.urlsafe_b64encode(os.urandom(64)).decode()}}
    receive_message(state, msg)   # 解密失败(假密文)但 step 已发生

    # 旧链号 2、3 的 MK 已被预存
    from ratchet import SessionState as _S
    try:
        fp = _S._ratchet_fingerprint(old_pub)
    except TypeError:
        fp = _S._ratchet_fingerprint(state, old_pub)
    assert fp in state.skipped_keys
    assert 2 in state.skipped_keys[fp] and 3 in state.skipped_keys[fp]
    # MK 与旧链手工推导一致
    ck = old_recv_ck
    ck2, mk2 = KDF_CK(ck)
    ck3, mk3 = KDF_CK(ck2)
    assert state.skipped_keys[fp][2] == mk2
    assert state.skipped_keys[fp][3] == mk3


# ----------------------------------------------------------------------
# R8-072: 首消息先验后进
# ----------------------------------------------------------------------

def test_first_message_retry_after_failure():
    from ratchet import (SessionState, complete_session_first_message, KDF_CK)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    import base64
    state = _mkstate(recv_msg_number=0)
    sender_pub = os.urandom(32)

    # 复刻 complete_session_first_message 的初始化链推导 (确定性)
    chain = HKDF(algorithm=hashes.SHA256(), length=32 * 4,
                 salt=state.root_key,
                 info=b"zhchat-init-chains-v1").derive(sender_pub)
    ck, mk = KDF_CK(chain[:32])

    nonce = os.urandom(12)
    inner = b"hello first"
    sid = state.session_id.encode() if isinstance(state.session_id, str) else state.session_id
    ct_bad = AESGCM(mk).encrypt(os.urandom(12), inner, sid)  # 错误 nonce

    r1 = complete_session_first_message(
        state, sender_pub,
        base64.urlsafe_b64encode(nonce).decode(),
        base64.urlsafe_b64encode(ct_bad).decode(), inner)
    assert r1 is None
    # 链未推进: 相同 MK 的正确密文仍可解 (重传场景)
    ct_ok = AESGCM(mk).encrypt(nonce, inner, sid)
    r2 = complete_session_first_message(
        state, sender_pub,
        base64.urlsafe_b64encode(nonce).decode(),
        base64.urlsafe_b64encode(ct_ok).decode(), inner)
    assert r2 == inner


# ----------------------------------------------------------------------
# R8-073: strength 字符集
# ----------------------------------------------------------------------

def test_strength_non_ascii_not_zero_entropy():
    from strength import estimate_entropy, get_strength
    assert estimate_entropy("парольпарольпароль") > 0        # 西里尔
    assert estimate_entropy("パスワードパスワード") > 0        # 日文
    assert estimate_entropy("😀😀😀😀😀😀😀😀") > 0            # emoji
    s = get_strength("Пароль12345678")
    assert s["entropy"] > 0
    assert get_strength("123456")["level"] == "weak"          # 常见弱口令不受影响


# ----------------------------------------------------------------------
# R8-080: streaming.enabled 总开关
# ----------------------------------------------------------------------

def test_should_stream_enabled_switch(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_CONFIG_CACHE", {"mtime": None, "cfg": None})
    config.set_key("streaming.enabled", False)
    assert core.should_stream(100 * 1024 * 1024) is False
    config.set_key("streaming.enabled", True)
    assert core.should_stream(100 * 1024 * 1024) is True


# ----------------------------------------------------------------------
# R8-077: keys/session 公共 API
# ----------------------------------------------------------------------

def test_bundle_export_peek_import_roundtrip(tmp_path):
    from keys import KeyStore
    ks = KeyStore(str(tmp_path / "a"))
    ks.generate_identity("alice", "口令123", comment="")
    bundle = ks.export_public_key_bundle("alice")
    ks2 = KeyStore(str(tmp_path / "b"))
    assert ks2.peek_bundle_identity(bundle) == "alice"
    status = ks2.import_public_key_bundle(bundle, "alice")
    assert status in ("imported", "exists_same")
    again = ks2.import_public_key_bundle(bundle, "alice")
    assert again in ("exists_same", "imported")


def test_otp_save_load_roundtrip(tmp_path):
    from keys import KeyStore
    ks = KeyStore(str(tmp_path))
    ks.generate_identity("bob", "口令456", comment="")
    bundle = ks.generate_prekey_bundle("bob", "口令456", otp_count=5)
    assert len(bundle["one_time_prekeys"]) == 5
    keys = ks.load_otp_private_keys("bob", "口令456")
    assert keys is not None and len(keys) == 5
    spk = ks.load_signed_prekey_priv_pem("bob", "口令456")
    assert b"BEGIN PRIVATE KEY" in spk


def test_cleanup_expired_sessions_by_mtime(tmp_path, monkeypatch):
    import session as session_mod
    monkeypatch.setattr(session_mod, "SESSIONS_DIR", str(tmp_path / "s"))
    state = types.SimpleNamespace(
        my_identity="alice", peer_identity="bob",
        to_dict=lambda: {"v": 1, "n": 1})
    session_mod.save_session(state, "pwd")
    path = session_mod._session_path("alice", "bob")
    old = time.time() - 40 * 86400
    os.utime(path, (old, old))
    removed = session_mod.cleanup_expired_sessions("alice")
    assert removed == 1
    assert not os.path.exists(path)
