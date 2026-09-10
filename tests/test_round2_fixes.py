#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R2 安全加固回归测试 (pytest)
============================
锁定 R2 轮修复的行为:

  - _client_ip 的 X-Real-IP 信任开关 (ZHPREKEY_TRUST_PROXY)
  - _resolve_ssl_context 原生 TLS 配置解析
  - WS auth 只允许一次 (防换绑劫持)
  - _x25519_exchange_checked 拒绝低阶点 (PFS 路径补齐)
  - decrypt_pfs 签名字段长度校验 (恶意 sig_len 拒绝)
  - _prune_skipped 逐出最旧而非全清
  - _send_via_rest 仅对 429 指数退避重试
  - get_auth_token 使用内置共享 token 时显著警告

运行: py -3.13 -m pytest tests/test_round2_fixes.py -q
"""
import asyncio
import json
import os
import struct

import pytest

TOKEN = "test-token-12345678"


@pytest.fixture
def server(monkeypatch, tmp_path):
    """独立 server 实例: 临时 DB + 临时 FILE_DIR + 测试 token。"""
    monkeypatch.setenv("ZHPREKEY_TOKEN", TOKEN)
    monkeypatch.setenv("ZHPREKEY_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("ZHCHAT_FILE_DIR", str(tmp_path / "files"))
    import importlib
    import server as server_mod
    importlib.reload(server_mod)
    server_mod.init_db()
    server_mod.app.config["TESTING"] = True
    return server_mod


# ----------------------------------------------------------------------
# _client_ip / TLS
# ----------------------------------------------------------------------

def test_client_ip_trusts_real_ip_by_default(server):
    with server.app.test_request_context("/", headers={"X-Real-IP": "1.2.3.4"}):
        assert server._client_ip() == "1.2.3.4"


def test_client_ip_ignores_header_when_trust_proxy_off(server, monkeypatch):
    monkeypatch.setattr(server, "_TRUST_PROXY", False)
    with server.app.test_request_context("/", headers={"X-Real-IP": "1.2.3.4"}):
        assert server._client_ip() != "1.2.3.4"


def test_resolve_ssl_context(tmp_path, monkeypatch):
    import server as server_mod
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    # 未配置 → None
    monkeypatch.delenv("ZHPREKEY_TLS_CERT", raising=False)
    monkeypatch.delenv("ZHPREKEY_TLS_KEY", raising=False)
    assert server_mod._resolve_ssl_context() is None
    # 指向不存在的文件 → None
    monkeypatch.setenv("ZHPREKEY_TLS_CERT", str(tmp_path / "nope.pem"))
    monkeypatch.setenv("ZHPREKEY_TLS_KEY", str(tmp_path / "nope.key"))
    assert server_mod._resolve_ssl_context() is None
    # 都存在 → (cert, key)
    cert.write_text("-----BEGIN CERTIFICATE-----\n")
    key.write_text("-----BEGIN PRIVATE KEY-----\n")
    monkeypatch.setenv("ZHPREKEY_TLS_CERT", str(cert))
    monkeypatch.setenv("ZHPREKEY_TLS_KEY", str(key))
    assert server_mod._resolve_ssl_context() == (str(cert), str(key))


# ----------------------------------------------------------------------
# WS 认证一次性
# ----------------------------------------------------------------------

class _FakeWS:
    """最小 websocket 桩: 依序回放入站消息, 记录出站帧。"""

    def __init__(self, inbound):
        self._inbound = list(inbound)
        self.sent = []
        self.closed = False

    async def send(self, s):
        self.sent.append(s)

    async def close(self):
        self.closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._inbound:
            raise StopAsyncIteration
        return self._inbound.pop(0)


def test_ws_auth_rejected_after_authenticated(server, monkeypatch):
    import chat_server
    monkeypatch.setattr(chat_server, "AUTH_TOKEN", TOKEN)
    ws = _FakeWS([
        json.dumps({"type": "auth", "token": TOKEN, "identity": "alice"}),
        json.dumps({"type": "auth", "token": TOKEN, "identity": "bob"}),
    ])
    asyncio.run(chat_server.handler(ws))
    first = json.loads(ws.sent[0])
    second = json.loads(ws.sent[1])
    assert first["type"] == "auth_ok"
    assert second["type"] == "error" and second["code"] == 409
    assert ws.closed
    # 断连后 connected_clients 不残留
    assert "alice" not in chat_server.connected_clients


# ----------------------------------------------------------------------
# X25519 低阶点 / PFS 签名长度
# ----------------------------------------------------------------------

def test_x25519_checked_rejects_low_order_point():
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    import core
    priv = X25519PrivateKey.generate()
    zero_pub = X25519PublicKey.from_public_bytes(b"\x00" * 32)
    with pytest.raises(ValueError):
        core._x25519_exchange_checked(priv, zero_pub)
    good = X25519PrivateKey.generate()
    shared = core._x25519_exchange_checked(priv, good.public_key())
    assert len(shared) == 32 and shared != b"\x00" * 32


# ---- PFS 数据包伪造工具 (复刻 encrypt_pfs 线上格式) ----

def _forge_pfs_packet(sig_len=64, pt=b"hello pfs", truncate_inner=False):
    import core as core_mod
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization

    recv_id = X25519PrivateKey.generate()
    recv_spk = X25519PrivateKey.generate()
    snd_id = X25519PrivateKey.generate()
    snd_eph = X25519PrivateKey.generate()
    sign = Ed25519PrivateKey.generate()

    dh1 = snd_eph.exchange(recv_spk.public_key())
    dh2 = snd_id.exchange(recv_id.public_key())
    dek = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=b"zhcrypt-x3dh-v2", info=b"x3dh-master-key").derive(dh1 + dh2)

    sender = "alice"
    ts = 1700000000
    sig_body = sender.encode("utf-8") + struct.pack(">Q", ts) + pt
    sig = sign.sign(sig_body)[:sig_len] if sig_len != 64 else sign.sign(sig_body)
    inner = (struct.pack(">H", len(sender)) + sender.encode("utf-8")
             + struct.pack(">Q", ts) + pt + struct.pack(">H", sig_len) + sig)
    if truncate_inner:
        inner = inner[:-70]  # 连签名区一起截掉

    nonce = os.urandom(12)
    sender_name = sender.encode("utf-8")
    packet = (core_mod.MAGIC + bytes([core_mod.VERSION_V2, core_mod.MODE_HYBRID_PFS,
                                      core_mod.FLAG_HAS_SIGNATURE])
              + struct.pack(">H", len(sender_name)) + sender_name
              + snd_id.public_key().public_bytes_raw()
              + snd_eph.public_key().public_bytes_raw()
              + nonce
              + AESGCM(dek).encrypt(nonce, inner, None))

    def pem(key):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

    sign_pub_pem = sign.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return (packet, pem(recv_id), pem(recv_spk), sign_pub_pem)


def test_pfs_roundtrip_still_works():
    """合法 sig_len=64 的包必须照常解密且验签通过 (防误伤)。"""
    import core as core_mod
    packet, rid, rspk, sign_pub = _forge_pfs_packet(sig_len=64)
    out = core_mod.decrypt_pfs(packet, rid, rspk, sign_pub)
    assert out["plaintext"] == "hello pfs"
    assert out["verified"] is True
    assert out["sender"] == "alice"


def test_pfs_rejects_bogus_sig_len():
    import core as core_mod
    packet, rid, rspk, sign_pub = _forge_pfs_packet(sig_len=63)
    with pytest.raises(core_mod.DecryptionError):
        core_mod.decrypt_pfs(packet, rid, rspk, sign_pub)


def test_pfs_rejects_truncated_inner():
    import core as core_mod
    packet, rid, rspk, sign_pub = _forge_pfs_packet(truncate_inner=True)
    with pytest.raises(core_mod.DecryptionError):
        core_mod.decrypt_pfs(packet, rid, rspk, sign_pub)


# ----------------------------------------------------------------------
# Ratchet 乱序密钥淘汰
# ----------------------------------------------------------------------

def test_prune_skipped_evicts_oldest_not_clear_all():
    from ratchet import SessionState, MAX_SKIPPED
    state = SessionState.__new__(SessionState)
    state.skipped_keys = {"a": {i: b"k" * 32 for i in range(MAX_SKIPPED + 50)}}
    SessionState._prune_skipped(state)
    total = sum(len(v) for v in state.skipped_keys.values())
    assert total == MAX_SKIPPED
    # 逐出的是消息号最小 (最旧) 的 0..49, 新近乱序密钥保留
    assert min(state.skipped_keys["a"]) == 50


def test_prune_skipped_keeps_multiple_chains():
    from ratchet import SessionState, MAX_SKIPPED
    state = SessionState.__new__(SessionState)
    state.skipped_keys = {
        "chainA": {i: b"k" * 32 for i in range(60)},
        "chainB": {i: b"k" * 32 for i in range(60, 120)},
    }
    SessionState._prune_skipped(state)
    total = sum(len(v) for v in state.skipped_keys.values())
    assert total == MAX_SKIPPED
    assert "chainB" in state.skipped_keys  # 新链密钥未被整体清空


# ----------------------------------------------------------------------
# 429 退避重试
# ----------------------------------------------------------------------

class _RestStub:
    identity = "alice"

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def _http_request(self, method, path, msg):
        self.calls += 1
        return self._responses.pop(0)


def test_send_via_rest_retries_on_429(monkeypatch):
    import chat_client
    monkeypatch.setattr(chat_client.time, "sleep", lambda s: None)
    stub = _RestStub([{"error": "HTTP 429 rate limited"},
                      {"error": "HTTP 429 rate limited"},
                      {"error": "HTTP 429 rate limited"},
                      {"error": "HTTP 429 rate limited"}])
    err = chat_client.ChatClient._send_via_rest(stub, {"id": "m1"})
    assert "429" in err
    assert stub.calls == 4  # 首发 + 3 次退避重试


def test_send_via_rest_success_midway(monkeypatch):
    import chat_client
    monkeypatch.setattr(chat_client.time, "sleep", lambda s: None)
    stub = _RestStub([{"error": "HTTP 429 rate limited"},
                      {"status": "stored"}])
    assert chat_client.ChatClient._send_via_rest(stub, {"id": "m1"}) is None
    assert stub.calls == 2


def test_send_via_rest_no_retry_other_errors(monkeypatch):
    import chat_client
    monkeypatch.setattr(chat_client.time, "sleep", lambda s: None)
    stub = _RestStub([{"error": "HTTP 500 boom"}])
    assert "500" in chat_client.ChatClient._send_via_rest(stub, {"id": "m1"})
    assert stub.calls == 1


# ----------------------------------------------------------------------
# 内置共享 token 警告
# ----------------------------------------------------------------------

def test_get_auth_token_warns_on_shared_build_token(monkeypatch, capsys):
    import config
    monkeypatch.setattr(config, "get", lambda *a, **k: "")
    monkeypatch.setattr(config, "_load_build_token", lambda: "shared-token")
    assert config.get_auth_token() == "shared-token"
    err = capsys.readouterr().err
    assert "共享 token" in err


def test_get_auth_token_silent_when_configured(monkeypatch, capsys):
    import config
    monkeypatch.setattr(config, "get",
                        lambda key, default="": "enc-blob" if "enc" in key else "")
    monkeypatch.setattr(config, "_decrypt_token", lambda enc: "real-token")
    monkeypatch.setattr(config, "_load_build_token", lambda: "shared-token")
    assert config.get_auth_token() == "real-token"
    assert "共享 token" not in capsys.readouterr().err
