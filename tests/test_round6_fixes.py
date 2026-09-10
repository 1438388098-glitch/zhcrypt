#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R6 修复回归测试 (pytest)
========================

  - config.load mtime 缓存 + 返回副本隔离 + save 刷新缓存
  - should_stream 统一流式决策 (含配置覆盖)
  - cli.build_parser 可独立构造 (R6 拆分回归)
  - WS send→push 流程 / file_upload 落盘与配额 (此前零自动化测试)

运行: py -3.13 -m pytest tests/test_round6_fixes.py -q
"""
import asyncio
import base64
import json
import os

import pytest

TOKEN = "test-token-12345678"


class _FakeWS:
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


def _import_chat_server(monkeypatch, tmp_path):
    monkeypatch.setenv("ZHPREKEY_TOKEN", TOKEN)
    monkeypatch.setenv("ZHPREKEY_DB", str(tmp_path / "ws.db"))
    import importlib
    import chat_server
    importlib.reload(chat_server)
    monkeypatch.setattr(chat_server, "AUTH_TOKEN", TOKEN)
    monkeypatch.setattr(chat_server, "FILE_DIR", str(tmp_path / "files"))
    os.makedirs(chat_server.FILE_DIR, exist_ok=True)
    chat_server.init_message_db()
    return chat_server


# ----------------------------------------------------------------------
# config 缓存
# ----------------------------------------------------------------------

def test_config_cache_copy_isolation_and_invalidation(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_CONFIG_CACHE", {"mtime": None, "cfg": None})

    c1 = config.load()
    c1["pollution"] = True              # 改返回副本不得污染缓存
    c2 = config.load()
    assert "pollution" not in c2

    config.set_key("prekey_server.cert_pin", "PIN123")
    assert config.get("prekey_server.cert_pin") == "PIN123"   # save 后可见
    # mtime 相同的重复读取命中缓存 (两次返回内容一致)
    assert config.get("prekey_server.cert_pin") == "PIN123"


def test_should_stream_threshold():
    import core
    assert core.should_stream(64 * 1024) is True
    assert core.should_stream(1024) is False
    assert core.should_stream(1023) is False
    # 最低下限保护
    assert core.should_stream(512) is False


def test_should_stream_config_override(tmp_path, monkeypatch):
    import config
    import core
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_CONFIG_CACHE", {"mtime": None, "cfg": None})
    config.set_key("streaming.threshold_bytes", 10 * 1024 * 1024)
    assert core.should_stream(9 * 1024 * 1024) is False
    assert core.should_stream(11 * 1024 * 1024) is True


def test_cli_build_parser_standalone():
    from cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["encrypt", "hello", "--sign"])
    assert args.command == "encrypt"
    assert args.text == "hello"
    assert args.sign is True
    args2 = parser.parse_args(["delete", "alice", "-y"])
    assert args2.identity == "alice"
    assert args2.yes is True


# ----------------------------------------------------------------------
# WS handler 流程 (R6: 050 首次自动化覆盖)
# ----------------------------------------------------------------------

def test_ws_send_flow(monkeypatch, tmp_path):
    cs = _import_chat_server(monkeypatch, tmp_path)
    stored = []
    monkeypatch.setattr(cs, "store_message", lambda msg: stored.append(msg) or True)
    pushed = []

    async def fake_push(identity, msg):
        pushed.append(identity)
        return True

    monkeypatch.setattr(cs, "push_to_identity", fake_push)

    ws = _FakeWS([
        json.dumps({"type": "auth", "token": TOKEN, "identity": "alice"}),
        json.dumps({"type": "send", "msg": {"id": "m1", "to": "bob",
                                            "from": "fake"}}),
    ])
    asyncio.run(cs.handler(ws))
    first = json.loads(ws.sent[0])
    second = json.loads(ws.sent[1])
    assert first["type"] == "auth_ok"
    assert second == {"type": "ack", "msg_id": "m1"}
    assert pushed == ["bob"]
    # 安全修复 #1 回归: from 被强制为已认证身份
    assert stored[0]["from"] == "alice"


def test_ws_get_pending_marks_delivered(monkeypatch, tmp_path):
    cs = _import_chat_server(monkeypatch, tmp_path)
    monkeypatch.setattr(cs, "fetch_pending_messages",
                        lambda identity, limit=500: [{"id": "p1"}])
    marked = []
    monkeypatch.setattr(cs, "mark_delivered", lambda ids: marked.extend(ids))

    ws = _FakeWS([
        json.dumps({"type": "auth", "token": TOKEN, "identity": "alice"}),
        json.dumps({"type": "get_pending"}),
    ])
    asyncio.run(cs.handler(ws))
    body = json.loads(ws.sent[1])
    assert body["type"] == "pending"
    assert body["messages"] == [{"id": "p1"}]
    assert marked == ["p1"]


def test_ws_file_upload_roundtrip(monkeypatch, tmp_path):
    cs = _import_chat_server(monkeypatch, tmp_path)
    blob = os.urandom(100)
    ws = _FakeWS([
        json.dumps({"type": "auth", "token": TOKEN, "identity": "alice"}),
        json.dumps({"type": "file_upload",
                    "file_data": base64.b64encode(blob).decode("ascii"),
                    "recipient": "bob"}),
    ])
    asyncio.run(cs.handler(ws))
    ack = json.loads(ws.sent[1])
    assert ack["type"] == "file_upload_ack"
    fpath = os.path.join(cs.FILE_DIR, ack["token"])
    assert os.path.isfile(fpath)
    with open(fpath, "rb") as f:
        assert f.read() == blob
    # size 列已记录 (配额统计依据)
    import sqlite3
    con = sqlite3.connect(str(tmp_path / "ws.db"))
    row = con.execute("SELECT size, uploader FROM files WHERE token = ?",
                      (ack["token"],)).fetchone()
    con.close()
    assert row[0] == 100 and row[1] == "alice"


def test_ws_file_upload_quota(monkeypatch, tmp_path):
    cs = _import_chat_server(monkeypatch, tmp_path)
    monkeypatch.setattr(cs, "_DAILY_UPLOAD_QUOTA", 10)
    ws = _FakeWS([
        json.dumps({"type": "auth", "token": TOKEN, "identity": "alice"}),
        json.dumps({"type": "file_upload",
                    "file_data": base64.b64encode(os.urandom(64)).decode("ascii"),
                    "recipient": "bob"}),
    ])
    asyncio.run(cs.handler(ws))
    err = json.loads(ws.sent[1])
    assert err["type"] == "error" and err["code"] == 413
    assert "quota" in err["message"]
