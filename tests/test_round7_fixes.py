#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R7 边界输入与崩溃面回归测试 (pytest)
====================================

  - 五个 decrypt_* 对截断包抛 ValueError (不再 struct.error 逃逸)
  - b64_to_packet 剥粘贴空白 + 非法字符指引
  - decrypt_file_stream 拒绝恶意 chunk_len (内存分配 DoS)
  - 可否认加密双密码往返 + 错密码分派 (deniable 首次测试覆盖)
  - 损坏会话文件 load_session 返回 None
  - list_sessions / cleanup_expired_sessions 身份白名单
  - take_file_key 解密失败返回 None

运行: py -3.13 -m pytest tests/test_round7_fixes.py -q
"""
import base64 as b64mod
import json
import os
import struct
import types

import pytest

TOKEN = "test-token-12345678"

import core  # noqa: E402  (conftest 已注入 sys.path)


# ----------------------------------------------------------------------
# 截断包: 统一 ValueError
# ----------------------------------------------------------------------

@pytest.mark.parametrize("bad_packet", [
    b"ZHCR\x01\x01",                                  # 仅头部
    b"ZHCR\x01\x01" + b"\x00" * 10,                   # 头 + 部分 params
    b"ZHCR\x01\x01" + b"\x00" * 56,                   # 仍不足完整定长头
])
def test_decrypt_password_short_packet_value_error(bad_packet):
    with pytest.raises(ValueError):
        core.decrypt_password_mode(bad_packet, "x")


@pytest.mark.parametrize("bad_packet", [
    b"ZHCR\x01\x02", b"ZHCR\x01\x02" + b"\x00" * 1,   # < 8 字节
])
def test_decrypt_hybrid_short_packet_value_error(bad_packet):
    with pytest.raises(ValueError):
        core.decrypt_hybrid(bad_packet, b"priv", "pwd")


@pytest.mark.parametrize("bad_packet", [
    b"ZHCR\x02\x03", b"ZHCR\x02\x03" + b"\x00" * 4,   # < 9 字节: flags/unpack 越界面
    b"ZHCR\x02\x03" + b"\x00" * 5,                    # 9 字节: 解析后落入密钥解密失败
])
def test_decrypt_signed_short_packet_value_error(bad_packet):
    # 9 字节包结构可解析但必然解密失败, 不允许 struct.error/IndexError 逃逸
    with pytest.raises((ValueError, core.DecryptionError)):
        core.decrypt_hybrid_signed(bad_packet, b"priv", "pwd")


def test_decrypt_pfs_short_packet_value_error():
    with pytest.raises(ValueError):
        core.decrypt_pfs(b"ZHCR\x02\x04" + b"\x00" * 5, b"p", b"p")


def test_decrypt_deniable_short_packet_value_error():
    with pytest.raises(ValueError):
        core.decrypt_deniable(b"ZHCR\x02\x06" + b"\x00" * 30, "x")


# ----------------------------------------------------------------------
# b64_to_packet
# ----------------------------------------------------------------------

def test_b64_to_packet_tolerates_whitespace():
    packet = core.encrypt_password_mode("你好", "pwd")
    text = core.packet_to_b64(packet)
    noisy = "\n".join(text[i:i + 20] for i in range(0, len(text), 20))
    assert core.b64_to_packet(noisy) == packet
    assert core.b64_to_packet("  " + text + "\r\n") == packet


def test_b64_to_packet_rejects_non_ascii_with_hint():
    with pytest.raises(ValueError) as ei:
        core.b64_to_packet("密文含中文!!")
    assert "非法字符" in str(ei.value)


# ----------------------------------------------------------------------
# chunk_len 钳制
# ----------------------------------------------------------------------

def _stream_file_with_bogus_chunk_len(tmp_path, chunk_len=0xFFFFFFFF):
    """构造一个块长字段被篡改的流式文件 (头合法, 块长超大)。"""
    src = tmp_path / "s.bin"
    payload = b"A" * 1000
    src.write_bytes(payload)
    out = core.encrypt_file_stream(str(src), "pwd")
    raw = bytearray(open(out, "rb").read())
    # 头: MAGIC(4)+VER(1)+MODE(1)+params(12)+salt(32)+name_len(2)+name+count(8)
    name_len = struct.unpack(">H", raw[50:52])[0]
    count_pos = 52 + name_len
    first_chunk_len_pos = count_pos + 8 + 12      # chunk_count(8) + nonce(12)
    raw[first_chunk_len_pos:first_chunk_len_pos + 4] = struct.pack(">I", chunk_len)
    tampered = tmp_path / "tampered.zhs"
    tampered.write_bytes(bytes(raw))
    return str(tampered)


def test_decrypt_file_stream_rejects_huge_chunk_len(tmp_path):
    bad = _stream_file_with_bogus_chunk_len(tmp_path, 0xFFFFFFFF)
    with pytest.raises(ValueError):
        core.decrypt_file_stream(bad, "pwd", output_path=str(tmp_path / "o"),
                                 overwrite=True)


def test_decrypt_file_stream_accepts_normal_after_clamp(tmp_path):
    src = tmp_path / "s2.bin"
    src.write_bytes(b"B" * 1000)
    out = core.encrypt_file_stream(str(src), "pwd")
    back = core.decrypt_file_stream(out, "pwd",
                                    output_path=str(tmp_path / "o2"),
                                    overwrite=True)
    assert open(back, "rb").read() == b"B" * 1000


# ----------------------------------------------------------------------
# 可否认加密 (首次测试覆盖)
# ----------------------------------------------------------------------

def test_deniable_roundtrip_real_and_duress():
    packet = core.encrypt_deniable("真实内容", "真密码123",
                                   "伪装内容", "伪装密码456")
    real = core.decrypt_deniable(packet, "真密码123")
    assert real["type"] == "real" and real["text"] == "真实内容"
    duress = core.decrypt_deniable(packet, "伪装密码456")
    assert duress["type"] == "duress" and duress["text"] == "伪装内容"


def test_deniable_wrong_password_returns_error():
    packet = core.encrypt_deniable("a", "pwd-real", "b", "pwd-duress")
    out = core.decrypt_deniable(packet, "错密码")
    assert out["text"] is None and "错误" in (out["error"] or "")


# ----------------------------------------------------------------------
# 会话容错 / 目录逃逸
# ----------------------------------------------------------------------

def test_load_session_tolerates_corrupt_file(tmp_path, monkeypatch):
    import session as session_mod
    from core import SALT_SIZE, NONCE_SIZE, KEY_SIZE, derive_key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    monkeypatch.setattr(session_mod, "SESSIONS_DIR", str(tmp_path / "s"))
    d = tmp_path / "s" / "alice"
    d.mkdir(parents=True)
    path = d / "bob.session"
    salt = os.urandom(SALT_SIZE)
    key = derive_key("pwd", salt)
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, b"{not json", None)   # 合法加密的坏 JSON
    path.write_bytes(salt + nonce + ct)
    assert session_mod.load_session("alice", "bob", "pwd") is None


def test_session_whitelist_blocks_escape(tmp_path, monkeypatch):
    import session as session_mod
    monkeypatch.setattr(session_mod, "SESSIONS_DIR", str(tmp_path / "s"))
    evil_dir = tmp_path / "s" / ".." / "evil"
    evil_dir.mkdir(parents=True)
    (evil_dir / "victim.session").write_bytes(b"x")
    assert session_mod.list_sessions("../evil") == []
    assert session_mod.cleanup_expired_sessions("../evil") == 0
    # 合法身份不报错
    assert session_mod.list_sessions("alice") == []


def test_from_dict_rejects_unknown_version():
    from ratchet import SessionState
    with pytest.raises(ValueError):
        SessionState.from_dict({"v": 99, "my_identity": "a"})


# ----------------------------------------------------------------------
# take_file_key
# ----------------------------------------------------------------------

def test_take_file_key_corrupt_returns_none(tmp_path, monkeypatch):
    import sqlite3
    import localstore
    store = localstore.LocalStore(str(tmp_path / "l.db"))
    # 手工写入一条坏的"加密"记录 (>32 字节, 解密必失败)
    con = sqlite3.connect(str(tmp_path / "l.db"))
    con.execute("INSERT OR REPLACE INTO file_keys(msg_id, key) VALUES (?, ?)",
                ("mx", b"\x00" * 64))
    con.commit()
    con.close()
    assert store.take_file_key("mx") is None
