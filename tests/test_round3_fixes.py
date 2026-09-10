#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R3 性能与客户端体验回归测试 (pytest)
====================================

  - session 派生键缓存正确性 + 会话文件 salt 稳定 (格式不变)
  - encrypt_file_password_mode 流式化 (新格式 0x05) + 旧格式 (0x01) 兼容解密
  - x3dh_shared_secret 死代码已移除
  - cli strength --stdin 管道输入
  - TUI 口令缓存 TTL 过期即焚 / 总开关禁用
  - 服务端文件上传边界 (2GB 上限 413 / 非法 token 400)

运行: py -3.13 -m pytest tests/test_round3_fixes.py -q
"""
import os
import struct
import types

import pytest

TOKEN = "test-token-12345678"


@pytest.fixture
def server(monkeypatch, tmp_path):
    monkeypatch.setenv("ZHPREKEY_TOKEN", TOKEN)
    monkeypatch.setenv("ZHPREKEY_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("ZHCHAT_FILE_DIR", str(tmp_path / "files"))
    import importlib
    import server as server_mod
    importlib.reload(server_mod)
    server_mod.init_db()
    server_mod.app.config["TESTING"] = True
    return server_mod


@pytest.fixture
def client(server):
    c = server.app.test_client()
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {TOKEN}"
    return c


def _auth_headers(identity="alice", **extra):
    h = {"Authorization": f"Bearer {TOKEN}", "X-Identity": identity}
    h.update(extra)
    return h


# ----------------------------------------------------------------------
# session 派生键缓存 (R3 性能)
# ----------------------------------------------------------------------

def test_cached_wrapping_key_correct_and_cached():
    import session as session_mod
    salt = os.urandom(32)
    k1 = session_mod._cached_wrapping_key("口令A", salt)
    k2 = session_mod._cached_wrapping_key("口令A", salt)
    assert k1 is k2                       # 命中缓存 (同一对象)
    assert k1 == session_mod._cached_wrapping_key("口令A", salt)
    k3 = session_mod._cached_wrapping_key("口令B", salt)
    assert k3 != k1                       # 不同口令不同键


def test_session_file_salt_stable_across_saves(tmp_path, monkeypatch):
    """连续两次保存使用同一 salt (读自文件头), 格式保持 salt|nonce|ct。"""
    import session as session_mod
    from core import SALT_SIZE
    monkeypatch.setattr(session_mod, "SESSIONS_DIR", str(tmp_path / "sessions"))
    state = types.SimpleNamespace(
        my_identity="alice", peer_identity="bob",
        to_dict=lambda: {"n": 1})
    session_mod.save_session(state, "pwd")
    path = session_mod._session_path("alice", "bob")
    with open(path, "rb") as f:
        salt1 = f.read(SALT_SIZE)
    state.to_dict = lambda: {"n": 2}
    session_mod.save_session(state, "pwd")
    with open(path, "rb") as f:
        salt2 = f.read(SALT_SIZE)
    assert salt1 == salt2                 # salt 稳定 → 第二次保存零 Argon2


# ----------------------------------------------------------------------
# 文件密码模式流式化 + 旧格式兼容
# ----------------------------------------------------------------------

def test_encrypt_file_password_mode_streams(tmp_path):
    import core
    src = tmp_path / "secret.txt"
    payload = os.urandom(150 * 1024)      # 跨 3 个默认块
    src.write_bytes(payload)
    out = core.encrypt_file_password_mode(str(src), "口令123")
    assert out == str(src) + ".zhe"       # 命名约定不变
    with open(out, "rb") as f:
        header = f.read(6)
    assert header[:4] == core.MAGIC
    assert header[5] == core.MODE_FILE_STREAM  # 新格式为流式
    back = core.decrypt_file_password_mode(
        out, "口令123", output_path=str(tmp_path / "restored.bin"))
    with open(back, "rb") as f:
        assert f.read() == payload


def test_decrypt_file_password_mode_legacy_format(tmp_path):
    """旧版 (3.1.0) 单块 MODE_PASSWORD(0x01) 格式必须仍可解。"""
    import core
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    payload = "旧格式内容".encode("utf-8")
    salt = os.urandom(core.SALT_SIZE)
    key = core.derive_key("旧口令", salt)
    nonce = os.urandom(core.NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, payload, None)
    packet = bytearray()
    packet.extend(core.MAGIC)
    packet.append(core.VERSION)
    packet.append(core.MODE_PASSWORD)
    packet.extend(struct.pack(">III", core.ARGON2_TIME_COST,
                              core.ARGON2_MEMORY_COST, core.ARGON2_PARALLELISM))
    packet.extend(salt)
    packet.extend(nonce)
    packet.extend(ct)
    legacy = tmp_path / "legacy.zhe"
    legacy.write_bytes(bytes(packet))
    out = core.decrypt_file_password_mode(str(legacy), "旧口令")
    assert out == str(tmp_path / "legacy")  # .zhe 剥离命名约定保持
    with open(out, "rb") as f:
        assert f.read() == payload


def test_x3dh_v1_dead_code_removed():
    import core
    assert not hasattr(core, "x3dh_shared_secret")
    # ratchet 的 -v2 实现不受影响
    import ratchet
    assert hasattr(ratchet, "x3dh_initiate_session")
    assert hasattr(ratchet, "x3dh_complete_session")


# ----------------------------------------------------------------------
# cli strength --stdin
# ----------------------------------------------------------------------

def test_cli_strength_stdin(monkeypatch, capsys):
    import io
    import cli
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("Test12345!\n"))
    args = types.SimpleNamespace(password=None, stdin=True)
    cli.cmd_strength(args)
    out = capsys.readouterr().out
    assert "密码强度" in out


def test_cli_strength_stdin_empty_rejected(monkeypatch, capsys):
    import io
    import cli
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("\n"))
    args = types.SimpleNamespace(password=None, stdin=True)
    with pytest.raises(SystemExit):
        cli.cmd_strength(args)
    assert "未收到" in capsys.readouterr().err


# ----------------------------------------------------------------------
# TUI 口令缓存 TTL / 开关
# ----------------------------------------------------------------------

@pytest.fixture
def pw_cache_env(tmp_path, monkeypatch):
    """隔离的 device.key 与缓存路径。"""
    import config
    import tui
    dev = tmp_path / "device.key"
    dev.write_bytes(os.urandom(32))
    monkeypatch.setattr(config, "DEVICE_KEY_PATH", str(dev))
    monkeypatch.setattr(tui, "_pw_cache_path",
                        lambda ident: str(tmp_path / "pw" / ".pw.bin"))
    monkeypatch.setattr(tui, "_PW_CACHE_ENABLED", True)
    monkeypatch.setattr(tui, "_PW_CACHE_TTL_SECONDS", 12 * 3600)
    return tmp_path


def test_pw_cache_roundtrip(pw_cache_env):
    import tui
    assert tui._save_pw_cache("alice", "口令abc") is True
    assert tui._load_pw_cache("alice") == "口令abc"


def test_pw_cache_disabled(pw_cache_env, monkeypatch):
    import tui
    monkeypatch.setattr(tui, "_PW_CACHE_ENABLED", False)
    assert tui._save_pw_cache("alice", "x") is False
    assert tui._load_pw_cache("alice") is None
    assert not os.path.exists(tui._pw_cache_path("alice"))


def test_pw_cache_ttl_expiry(pw_cache_env):
    import tui
    assert tui._save_pw_cache("alice", "口令abc") is True
    path = tui._pw_cache_path("alice")
    # 把 mtime 拨到 TTL 之前
    old = __import__("time").time() - 13 * 3600
    os.utime(path, (old, old))
    assert tui._load_pw_cache("alice") is None   # 过期即焚
    assert not os.path.exists(path)


# ----------------------------------------------------------------------
# 服务端文件上传边界
# ----------------------------------------------------------------------

def test_file_upload_rejects_over_max_size(client):
    import server as server_mod
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": "a" * 32, "X-Recipient": "bob",
                    "X-Offset": "0",
                    "X-Total-Size": str(server_mod.MAX_FILE_SIZE + 1)}),
        data=b"x")
    assert r.status_code == 413


def test_file_upload_rejects_bad_token(client):
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": "zz-not-hex", "X-Recipient": "bob",
                    "X-Offset": "0", "X-Total-Size": "100"}),
        data=b"x")
    assert r.status_code == 400


def test_file_upload_rejects_offset_overflow(client):
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": "b" * 32, "X-Recipient": "bob",
                    "X-Offset": "50", "X-Total-Size": "10"}),
        data=b"x")
    assert r.status_code == 400
