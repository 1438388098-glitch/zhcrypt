#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R16 收官轮回归测试 (pytest)
============================
  - server 响应安全头 (nosniff / DENY / no-store)
  - ZHCRYPT_DEBUG 调试日志开关
运行: py -3.13 -m pytest tests/test_round16_fixes.py -q
"""
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


def test_security_headers_present(server):
    c = server.app.test_client()
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {TOKEN}"
    r = c.get("/v1/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"


def test_debug_log_toggle(monkeypatch, capsys):
    import chat_client
    monkeypatch.setenv("ZHCRYPT_DEBUG", "1")
    monkeypatch.setattr(chat_client, "_DEBUG", True)
    chat_client._dbg("hello-debug")
    err = capsys.readouterr().err
    assert "hello-debug" in err

    monkeypatch.setattr(chat_client, "_DEBUG", False)
    chat_client._dbg("quiet")
    assert "quiet" not in capsys.readouterr().err
