#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
服务端文件端点测试 (主 agent 整合)
==================================
覆盖: 分块上传 (201/409 续传协商)、并发限制、下载授权 (上传者/接收方)、
Range 下载 206、HEAD 元信息、delivered 查询、路径穿越防御。
"""
import os
import sys
import json
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
# 上传
# ----------------------------------------------------------------------

def test_upload_multiple_chunks(server, client, tmp_path):
    """两整块 + 尾块: 中间块 409 协商, 尾块 201, 文件完整。"""
    data = os.urandom(2 * 1024 * 1024 + 100)
    token = "a" * 32
    r1 = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                    "X-Offset": "0", "X-Total-Size": str(len(data))}),
        data=data[:1024 * 1024])
    assert r1.status_code == 409
    assert r1.get_json()["offset"] == 1024 * 1024

    r2 = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                    "X-Offset": str(1024 * 1024),
                    "X-Total-Size": str(len(data))}),
        data=data[1024 * 1024:2 * 1024 * 1024])
    assert r2.status_code == 409
    assert r2.get_json()["offset"] == 2 * 1024 * 1024

    r3 = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                    "X-Offset": str(2 * 1024 * 1024),
                    "X-Total-Size": str(len(data))}),
        data=data[2 * 1024 * 1024:])
    assert r3.status_code == 201
    assert r3.get_json()["token"] == token

    final_path = os.path.join(server.FILE_DIR, token)
    assert os.path.isfile(final_path)
    with open(final_path, "rb") as f:
        assert f.read() == data
    assert not os.path.exists(final_path + ".part")


def test_upload_single_chunk(server, client):
    """单块即完成 (1MB 整倍数文件, X-Total-Size 判定最后一块)。"""
    data = os.urandom(1024 * 1024)  # 恰好一块
    token = "b" * 32
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                    "X-Offset": "0", "X-Total-Size": str(len(data))}),
        data=data)
    assert r.status_code == 201
    final_path = os.path.join(server.FILE_DIR, token)
    with open(final_path, "rb") as f:
        assert f.read() == data


def test_upload_resume(server, client):
    """断点续传: 服务端已有 1.5MB, 客户端从 0 再传 → 409 offset=1.5MB。"""
    data = os.urandom(3 * 1024 * 1024)
    token = "c" * 32
    # 先传前 1.5MB (两段)
    for off, chunk in [(0, data[:1024 * 1024]),
                       (1024 * 1024, data[1024 * 1024:1536 * 1024])]:
        r = client.post("/v1/files/upload", headers=_auth_headers(
            "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                        "X-Offset": str(off), "X-Total-Size": str(len(data))}),
            data=chunk)
        assert r.status_code == 409
    # 客户端重新上传 (offset=0): 服务端协商到已接收大小
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                    "X-Offset": "0", "X-Total-Size": str(len(data))}),
        data=data[:1024 * 1024])
    assert r.status_code == 409
    assert r.get_json()["offset"] == 1536 * 1024
    # 从协商点续传剩余
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                    "X-Offset": str(1536 * 1024),
                    "X-Total-Size": str(len(data))}),
        data=data[1536 * 1024:])
    assert r.status_code == 201


def test_upload_concurrency_limit(server, client):
    """单身份并发上传 ≤2, 第三个 429。"""
    token = "f" * 32
    for i in range(2):
        r = client.post("/v1/files/upload", headers=_auth_headers(
            "alice", **{"X-Upload-Token": token[:16] + hex(i)[2:].zfill(16),
                        "X-Recipient": "bob", "X-Offset": "0",
                        "X-Total-Size": "2000000"}),
            data=b"x" * 1024)
        assert r.status_code == 409
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": "d" * 32, "X-Recipient": "bob",
                    "X-Offset": "0", "X-Total-Size": "2000000"}),
        data=b"x" * 1024)
    assert r.status_code == 429


def test_upload_session_ownership(server, client):
    """会话归属: 其他身份不能续传同一会话。"""
    token = "e" * 32
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                    "X-Offset": "0", "X-Total-Size": "2000000"}),
        data=b"x" * 1024)
    assert r.status_code == 409
    r2 = client.post("/v1/files/upload", headers=_auth_headers(
        "mallory", **{"X-Upload-Token": token, "X-Recipient": "bob",
                      "X-Offset": "0", "X-Total-Size": "2000000"}),
        data=b"x" * 1024)
    assert r2.status_code == 403


def test_upload_missing_identity(server, client):
    r = client.post("/v1/files/upload", headers={
        "Authorization": f"Bearer {TOKEN}"}, data=b"x" * 10)
    assert r.status_code == 400


def test_upload_invalid_token(server, client):
    r = client.post("/v1/files/upload", headers=_auth_headers(
        "alice", **{"X-Upload-Token": "../etc/passwd", "X-Recipient": "bob",
                    "X-Offset": "0", "X-Total-Size": "100"}),
        data=b"x" * 10)
    assert r.status_code == 400


# ----------------------------------------------------------------------
# 下载授权
# ----------------------------------------------------------------------

def _seed_file(server, client, token, data, uploader="alice", recipient="bob"):
    """直接经端点上传一个完整文件 (单块)。"""
    r = client.post("/v1/files/upload", headers=_auth_headers(
        uploader, **{"X-Upload-Token": token, "X-Recipient": recipient,
                     "X-Offset": "0", "X-Total-Size": str(len(data))}),
        data=data)
    assert r.status_code == 201


def test_download_uploader_and_recipient(server, client):
    token = "10" * 16
    data = os.urandom(2048)
    _seed_file(server, client, token, data)
    for ident in ("alice", "bob"):
        r = client.get(f"/v1/files/download/{token}",
                       headers=_auth_headers(ident))
        assert r.status_code == 200
        assert r.data == data


def test_download_forbidden(server, client):
    token = "11" * 16
    _seed_file(server, client, token, b"secret")
    r = client.get(f"/v1/files/download/{token}",
                   headers=_auth_headers("mallory"))
    assert r.status_code == 403


def test_download_not_found(server, client):
    r = client.get("/v1/files/download/" + "12" * 16,
                   headers=_auth_headers("alice"))
    assert r.status_code == 404


def test_download_path_traversal(server, client):
    """路径穿越防御: 非法 token 一律 404, 不触碰 FILE_DIR 外文件。"""
    for bad in ("..%2F..%2Fserver.py", "..\\..\\server.py", "abc", "."):
        r = client.get(f"/v1/files/download/{bad}",
                       headers=_auth_headers("alice"))
        assert r.status_code == 404


def test_download_range(server, client):
    token = "13" * 16
    data = os.urandom(4096)
    _seed_file(server, client, token, data)
    r = client.get(f"/v1/files/download/{token}",
                   headers=_auth_headers("alice", **{"Range": "bytes=1024-2047"}))
    assert r.status_code == 206
    assert r.data == data[1024:2048]


def test_head_size(server, client):
    token = "14" * 16
    data = os.urandom(1024)
    _seed_file(server, client, token, data)
    r = client.head(f"/v1/files/download/{token}",
                    headers=_auth_headers("alice"))
    assert r.status_code == 200
    assert r.headers.get("Content-Length") == str(len(data))


def test_head_not_found(server, client):
    r = client.head("/v1/files/download/" + "15" * 16,
                    headers=_auth_headers("alice"))
    assert r.status_code == 404


def test_head_forbidden(server, client):
    token = "16" * 16
    _seed_file(server, client, token, b"secret")
    r = client.head(f"/v1/files/download/{token}",
                    headers=_auth_headers("mallory"))
    assert r.status_code == 403


# ----------------------------------------------------------------------
# delivered 查询
# ----------------------------------------------------------------------

def test_delivered_query(server, client):
    with server.app.app_context():
        db = server.get_db()
        now = time.time()
        db.execute(
            "INSERT INTO messages (id, session_id, sender, recipient, type, "
            "payload_json, server_ts, delivered_at) VALUES (?,?,?,?,?,?,?,?)",
            ("m1", "s", "alice", "bob", "message", "{}", now, now))
        db.execute(
            "INSERT INTO messages (id, session_id, sender, recipient, type, "
            "payload_json, server_ts, delivered_at) VALUES (?,?,?,?,?,?,?,?)",
            ("m2", "s", "alice", "bob", "message", "{}", now, None))
        db.commit()

    r = client.get("/v1/messages/delivered?ids=m1,m2,m3&identity=bob")
    assert r.status_code == 200
    delivered = r.get_json()["delivered"]
    assert isinstance(delivered["m1"], float)
    assert delivered["m2"] is None
    assert delivered["m3"] is None  # 不存在的 id 也返回 null

    # 非收件人身份查不到 (防探测)
    r2 = client.get("/v1/messages/delivered?ids=m1&identity=mallory")
    assert r2.get_json()["delivered"] == {"m1": None}


def test_delivered_requires_identity(server, client):
    r = client.get("/v1/messages/delivered?ids=m1")
    assert r.status_code == 400
