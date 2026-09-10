#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R11 运行时冒烟缺陷回归测试 (pytest)
====================================

  - P0: backup/restore 全流程往返 (nonce 偏移错位修复)
  - 损坏备份的错误消息非空且可读 (InvalidTag 空串问题)
  - _prompt_passphrase 非 tty stdin 读行 (getpass 挂死修复)
  - Spinner 非 tty 退化为单行输出
  - certpin 非 ASCII/空 pin 返回 False (不再 TypeError)
  - fileclient download 写盘失败返回 error 字典
  - tui accept 门禁代码在场 (仅 requested→confirmed)
  - websockets 版本约束有界

运行: py -3.13 -m pytest tests/test_round11_fixes.py -q
"""
import os
import re
import types

import pytest

import core  # noqa: E402 (conftest 注入 sys.path)

ANSI = re.compile(r"\x1b\[[0-9;]*m")


# ----------------------------------------------------------------------
# P0: backup → delete key → restore 往返
# ----------------------------------------------------------------------

def test_backup_restore_roundtrip(tmp_path, monkeypatch, capsys):
    import keys
    import cli
    keydir = str(tmp_path / "keys")
    monkeypatch.setattr(keys, "_DEFAULT_KEY_DIR", keydir)
    # 非 tty 路径: 密码经 stdin 读行 (R11); input() 喂份额
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(["口令123"]))

    ks = keys.KeyStore()
    ks.generate_identity("t1", "口令123", comment="")
    orig_pem = ks.load_private_key_pem("t1", "口令123")

    cli.cmd_backup(types.SimpleNamespace(identity="t1"))
    out = ANSI.sub("", capsys.readouterr().out)
    shares = re.findall(r"zhcrypt\|t1\|[1-5]\|[0-9a-f]{64}", out)
    assert len(shares) == 5
    assert os.path.isfile(os.path.join(keydir, "t1.backup"))

    # 模拟私钥丢失
    os.remove(os.path.join(keydir, "t1.key"))

    feed = iter(shares[:3])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(feed))
    # 恢复后需为新 .key 设置口令 (R11: 重新包裹落盘)
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(["新密码111", "新密码111"]))
    cli.cmd_restore(types.SimpleNamespace(identity="t1"))

    restored = os.path.join(keydir, "t1.key")
    assert os.path.isfile(restored), "P0: restore 必须恢复出私钥文件"
    rlog = ANSI.sub("", capsys.readouterr().out)
    assert "私钥已恢复" in rlog, f"restore 未成功: {rlog[-400:]}"
    assert ks.load_private_key_pem("t1", "新密码111") == orig_pem


def test_restore_corrupt_backup_error_not_empty(tmp_path, monkeypatch, capsys):
    import keys
    import cli
    keydir = str(tmp_path / "keys")
    monkeypatch.setattr(keys, "_DEFAULT_KEY_DIR", keydir)
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(["口令123"]))
    monkeypatch.setattr(cli, "getpass", types.SimpleNamespace(
        getpass=lambda prompt="": "口令123"))

    ks = keys.KeyStore()
    ks.generate_identity("t2", "口令123", comment="")
    cli.cmd_backup(types.SimpleNamespace(identity="t2"))
    capsys.readouterr()
    # 篡改密文 (翻转一字节) → GCM 认证失败
    bp = os.path.join(keydir, "t2.backup")
    raw = bytearray(open(bp, "rb").read())
    raw[-1] ^= 0xFF
    open(bp, "wb").write(bytes(raw))
    os.remove(os.path.join(keydir, "t2.key"))

    share = "zhcrypt|t2|1|" + "ab" * 32
    feed = iter([share, share.replace("|1|", "|2|"), share.replace("|1|", "|3|")])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(feed))
    # _err 打到 stderr 并 sys.exit(1)
    with pytest.raises(SystemExit):
        cli.cmd_restore(types.SimpleNamespace(identity="t2"))
    err_out = ANSI.sub("", capsys.readouterr().err)
    assert "恢复失败" in err_out
    # R11: 不再出现空消息 "恢复失败: "
    assert not re.search(r"恢复失败:\s*$", err_out, re.M)
    assert "认证失败" in err_out


# ----------------------------------------------------------------------
# 非 tty 输入
# ----------------------------------------------------------------------

class _FakeStdin:
    def __init__(self, lines):
        self._lines = list(lines)

    def isatty(self):
        return False

    def readline(self):
        return self._lines.pop(0) if self._lines else ""


def test_prompt_passphrase_reads_stdin_when_not_tty(monkeypatch):
    import cli
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(["pw1\n", "pw1\n"]))
    assert cli._prompt_passphrase("x: ", confirm=True) == "pw1"


def test_prompt_passphrase_empty_stdin_exits(monkeypatch, capsys):
    import cli
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin([]))
    with pytest.raises(SystemExit):
        cli._prompt_passphrase("x: ", confirm=True)


def test_spinner_silent_when_not_tty(monkeypatch):
    import cli
    buf = []

    class _Out:
        def isatty(self):
            return False

        def write(self, s):
            buf.append(s)

        def flush(self):
            pass

    monkeypatch.setattr(cli.sys, "stdout", _Out())
    with cli.Spinner("处理中...") as sp:
        assert sp._running is False        # 不启动动画线程
    out = "".join(buf)
    assert "处理中" in out and "\r" not in out


# ----------------------------------------------------------------------
# certpin 输入防线
# ----------------------------------------------------------------------

def test_verify_cert_pin_rejects_bad_inputs():
    import certpin
    assert certpin.verify_cert_pin(None, "abc") is False
    assert certpin.verify_cert_pin(b"\x00" * 10, "") is False
    assert certpin.verify_cert_pin(b"\x00" * 10, None) is False
    # 非 ASCII pin: 此前抛 TypeError, 现在返回 False
    assert certpin.verify_cert_pin(b"\x00" * 10, "中文指纹") is False


# ----------------------------------------------------------------------
# fileclient 写盘失败
# ----------------------------------------------------------------------

def test_download_write_failure_returns_error(tmp_path, monkeypatch):
    """写盘目标被目录占用时返回 error 字典 (此前 OSError 裸穿透)。"""
    from fileclient import FileClient
    fc = FileClient("http://127.0.0.1:1", "tok", "alice")

    calls = []

    def _fake_raw(self, method, url, headers=None):
        calls.append(method)
        if method == "HEAD":
            # server_size = 4
            return 200, {"Content-Length": "4"}, b""
        return 200, {"Content-Length": "4"}, b"abcd"

    monkeypatch.setattr(FileClient, "_http_raw", _fake_raw)
    # R16: GET 改走 _http_stream, 桩同步 (HEAD 仍走 _http_raw)
    import io as _io

    def _fake_stream(self, method, url, headers=None):
        calls.append(method)
        return 200, {"Content-Length": "4"}, _io.BytesIO(b"abcd")

    monkeypatch.setattr(FileClient, "_http_stream", _fake_stream)
    # dest = dest_dir/<token>.bin: 用同名目录占用, open("wb") 必抛 OSError
    (tmp_path / "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin").mkdir()
    r = fc.download("a" * 32, str(tmp_path))
    assert "写盘失败" in r.get("error", "")
    assert calls == ["HEAD", "GET"]


# ----------------------------------------------------------------------
# 其它
# ----------------------------------------------------------------------

def test_tui_accept_gate_present():
    import tui
    src = open(tui.__file__, encoding="utf-8").read()
    assert 'friend_status(peer) == "requested"' in src


def test_websockets_constraint_bounded():
    txt = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "requirements-server.txt"),
        encoding="utf-8").read()
    assert "websockets>=11,<18" in txt
