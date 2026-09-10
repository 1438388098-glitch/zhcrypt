#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R4 修复回归测试 (pytest)
========================

  - _token_lock 守护锁为模块级单例 (并发同 token 拿到同一把锁)
  - limit / older_than_days 非数字 → 400 (不再 HTML 500)
  - JSON 顶层非对象 → 400 (REST); WS 非 dict 帧 → 错误帧不断连
  - 重复上传同一 OTP 静默去重 (唯一索引), 不再产生重复消耗
  - cli --help 可用 / 子命令退出码不再被丢弃
  - backup/restore 身份名穿越拒绝
  - chat_server missing identity 分支关闭连接

运行: py -3.13 -m pytest tests/test_round4_fixes.py -q
"""
import asyncio
import json
import os
import threading

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
# 并发 / 输入健壮性
# ----------------------------------------------------------------------

def test_token_lock_is_shared_singleton(server):
    """同 token 并发获取必须拿到同一把锁 (守护锁失效回归)。"""
    results = []

    def _grab():
        results.append(server._token_lock("tok-shared"))

    threads = [threading.Thread(target=_grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({id(l) for l in results}) == 1
    assert isinstance(results[0], type(threading.Lock()))


def test_pending_rejects_non_numeric_limit(client):
    r = client.get("/v1/messages/pending",
                   headers=_auth_headers(),
                   query_string={"identity": "alice", "limit": "abc"})
    assert r.status_code == 400
    assert r.get_json()["error"] == "invalid limit"


def test_history_rejects_non_numeric_limit(client):
    r = client.get("/v1/messages/history",
                   headers=_auth_headers(),
                   query_string={"identity": "alice", "with": "bob",
                                 "limit": "xyz"})
    assert r.status_code == 400


def test_prune_rejects_non_numeric_days(client):
    r = client.delete("/v1/messages/prune",
                      headers=_auth_headers(),
                      query_string={"older_than_days": "NaN"})
    assert r.status_code == 400


def test_message_send_rejects_array_body(client):
    r = client.post("/v1/messages/send", headers=_auth_headers(),
                    json=["not", "a", "dict"])
    assert r.status_code == 400


def test_message_ack_rejects_array_body(client):
    r = client.post("/v1/messages/ack", headers=_auth_headers(),
                    json=["m1"])
    assert r.status_code == 400


# ----------------------------------------------------------------------
# OTP 唯一性
# ----------------------------------------------------------------------

def test_duplicate_otp_upload_deduplicated(server, client):
    otp = "k" * 64
    r1 = client.post("/v1/prekey/alice", headers=_auth_headers(),
                     json={"identity_key_pub": "ik", "signed_prekey_pub": "sp",
                           "signature": "sig", "fingerprint": "fp",
                           "one_time_prekeys": [otp]})
    assert r1.status_code == 200
    assert r1.get_json()["one_time_stored"] == 1

    # 重复上传 (模拟客户端重试): 静默去重, 不产生第二行
    r2 = client.post("/v1/prekey/alice", headers=_auth_headers(),
                     json={"identity_key_pub": "ik", "signed_prekey_pub": "sp",
                           "signature": "sig", "fingerprint": "fp",
                           "one_time_prekeys": [otp]})
    assert r2.status_code == 200
    assert r2.get_json()["one_time_stored"] == 0

    r3 = client.get("/v1/prekey/remaining/alice", headers=_auth_headers())
    assert r3.get_json()["remaining"] == 1


def test_batch_upload_deduplicated(server, client):
    otp = "j" * 64
    body = {"one_time_prekeys": [otp, otp, otp]}
    r1 = client.post("/v1/prekey/batch/alice", headers=_auth_headers(),
                     json=body)
    assert r1.get_json()["stored"] == 1
    r2 = client.post("/v1/prekey/batch/alice", headers=_auth_headers(),
                     json=body)
    assert r2.get_json()["stored"] == 0


# ----------------------------------------------------------------------
# WS 帧健壮性
# ----------------------------------------------------------------------

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


def test_ws_non_dict_frame_gets_error_not_disconnect(monkeypatch):
    monkeypatch.setenv("ZHPREKEY_TOKEN", TOKEN)
    import chat_server
    monkeypatch.setattr(chat_server, "AUTH_TOKEN", TOKEN)
    ws = _FakeWS(["[1, 2, 3]", json.dumps({"type": "ping"})])
    asyncio.run(chat_server.handler(ws))
    first = json.loads(ws.sent[0])
    second = json.loads(ws.sent[1])
    assert first["type"] == "error" and first["code"] == 400
    assert second == {"type": "pong"}          # 连接未被断开
    assert not ws.closed


def test_ws_auth_missing_identity_closes(monkeypatch):
    monkeypatch.setenv("ZHPREKEY_TOKEN", TOKEN)
    import chat_server
    monkeypatch.setattr(chat_server, "AUTH_TOKEN", TOKEN)
    ws = _FakeWS([json.dumps({"type": "auth", "token": TOKEN, "identity": ""})])
    asyncio.run(chat_server.handler(ws))
    assert json.loads(ws.sent[0])["code"] == 400
    assert ws.closed                            # R4: 回错误帧后关闭


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def test_cli_help_via_subprocess():
    """zhcrypt --help 必须正常输出且退出码 0 (R4 前为报错退出码 2)。"""
    import subprocess, sys
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([sys.executable, "cli.py", "--help"],
                       cwd=repo, capture_output=True, text=True)
    assert r.returncode == 0
    assert "zhcrypt" in r.stdout


def test_backup_restore_rejects_traversal_identity(capsys):
    from keys import _validate_identity
    for bad in ("../evil", "a/b", "a\\b", "..", ""):
        with pytest.raises(ValueError):
            _validate_identity(bad)
