#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R12 静态扫描与体验收尾回归测试 (pytest)
========================================

  - _http_request 在配置 pin+https 时走同连接固定校验路径 (TOCTOU 修复)
  - strength 词组口令按词表熵计 (不再按字符熵高估)
  - restore 覆盖现有私钥前需确认
  - KeyStore 延迟创建密钥目录
  - ChatClient 事件队列实例隔离
  - /v1/identities limit 参数校验

运行: py -3.13 -m pytest tests/test_round12_fixes.py -q
"""
import os
import queue
import types

import pytest

TOKEN = "test-token-12345678"

import core  # noqa: E402 (conftest 注入 sys.path)


def test_http_request_uses_pinned_path_when_pin_set(monkeypatch):
    from chat_client import ChatClient
    monkeypatch.setattr(ChatClient, "_get_cert_pin", lambda self: "PIN123")
    monkeypatch.setattr(ChatClient, "_pinned_http_request",
                        lambda self, method, url, data, timeout, pin:
                        {"via": "pinned", "pin": pin})
    c = ChatClient.__new__(ChatClient)
    c._server_url = "https://example.com"
    c._token = "tok"
    r = c._http_request("GET", "/v1/health")
    assert r["via"] == "pinned" and r["pin"] == "PIN123"


def test_http_request_unpinned_skips_pinned_path(monkeypatch):
    from chat_client import ChatClient
    monkeypatch.setattr(ChatClient, "_get_cert_pin", lambda self: "")
    called = []
    monkeypatch.setattr(ChatClient, "_pinned_http_request",
                        lambda self, *a, **k: called.append(1) or {})
    monkeypatch.setattr(ChatClient, "_verify_rest_cert_pin",
                        lambda self, pin: called.append(2))
    # https 无 pin: 走普通 urllib (本地无法连网 → 返回 error dict 即可)
    c = ChatClient.__new__(ChatClient)
    c._server_url = "https://127.0.0.1:1"
    c._token = "tok"
    r = c._http_request("GET", "/v1/health", timeout=1)
    assert called == [] and isinstance(r, dict)


def test_strength_word_group_entropy():
    from strength import estimate_entropy
    from wordlist import TEMP_WORDS
    pwd = "·".join(TEMP_WORDS[:6])
    e = estimate_entropy(pwd)
    assert 40 <= e <= 60          # 256^6 ≈ 48 bits, 而非字符熵的 200+


def test_strength_normal_password_unaffected():
    from strength import estimate_entropy
    # 非「全词表·分隔」输入仍走字符熵
    assert estimate_entropy("Abcdef1!Abcdef1!") > 60


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


def test_list_identities_limit_validation(server):
    c = server.app.test_client()
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {TOKEN}"
    r = c.get("/v1/identities", query_string={"limit": "abc"})
    assert r.status_code == 400
    r2 = c.get("/v1/identities")
    assert r2.status_code == 200


def test_restore_overwrite_requires_confirmation(tmp_path, monkeypatch, capsys):
    """已有私钥时 restore 必须先确认 (输入 n 即取消)。"""
    import keys
    import cli
    keydir = str(tmp_path / "keys")
    os.makedirs(keydir)
    monkeypatch.setattr(keys, "_DEFAULT_KEY_DIR", keydir)
    (tmp_path / "t1.backup").write_bytes(b"ZHCR\x02" + b"\x00" * 40)
    key_path = os.path.join(keydir, "t1.key")
    open(key_path, "wb").write(b"existing")

    feed = iter(["zhcrypt|t1|1|" + "ab" * 32,
                 "zhcrypt|t1|2|" + "cd" * 32,
                 "zhcrypt|t1|3|" + "ef" * 32,
                 "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(feed))
    with pytest.raises(SystemExit):
        cli.cmd_restore(types.SimpleNamespace(identity="t1"))
    # 原私钥未被触碰
    assert open(key_path, "rb").read() == b"existing"


def test_keystore_lazy_dir(tmp_path):
    """只读操作不再凭空创建 ~/.zhcrypt/keys 目录。"""
    from keys import KeyStore
    kd = tmp_path / "fresh-keys"
    ks = KeyStore(str(kd))
    ks.list_identities()
    assert not kd.exists()


def test_chat_client_inbound_queue_isolation():
    from chat_client import ChatClient, INBOUND
    custom = queue.Queue()
    c = ChatClient.__new__(ChatClient)
    ChatClient.__init__(c, "alice", "pw", inbound_queue=custom)
    assert c.inbound is custom
    c2 = ChatClient.__new__(ChatClient)
    ChatClient.__init__(c2, "bob", "pw")
    assert c2.inbound is INBOUND          # 默认仍为模块全局 (GUI/TUI 兼容)


import chat_client  # noqa: E402
