#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R1 修复回归测试 (pytest)
========================
锁定 R1 轮修复的行为, 防止回归:

  - upload_batch / clear_prekeys / remaining_prekeys 身份名校验 + prekey 数量上限
  - message_send 收件人 to 白名单校验
  - message_ack msg_ids 类型/数量校验
  - 上传会话超时回收时同步释放互斥锁
  - 文件落盘 os.replace (Windows 上目标已存在可覆盖)
  - save_file_key 加密失败不再明文回退落盘
  - search LIKE 通配符转义
  - list_identities 损坏 meta 容错
  - DecryptionError 单一定义
  - _get_argon2_params 与 derive_key 钳制规则一致

运行: py -3.13 -m pytest tests/test_round1_fixes.py -q
"""
import os
import re
import sqlite3
import threading
import time

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
# 端点身份名校验
# ----------------------------------------------------------------------

def test_upload_batch_rejects_invalid_identity(server, client):
    r = client.post("/v1/prekey/batch/bad%7Cname",
                    headers=_auth_headers(),
                    json={"one_time_prekeys": ["k" * 32]})
    assert r.status_code == 400
    assert r.get_json()["error"] == "invalid identity"


def test_upload_batch_rejects_too_many_prekeys(server, client):
    r = client.post("/v1/prekey/batch/alice",
                    headers=_auth_headers(),
                    json={"one_time_prekeys": ["k" * 32] * 201})
    assert r.status_code == 400
    assert "max 200" in r.get_json()["error"]


def test_upload_batch_accepts_valid(server, client):
    r = client.post("/v1/prekey/batch/alice",
                    headers=_auth_headers(),
                    json={"one_time_prekeys": ["k" * 32, "j" * 32]})
    assert r.status_code == 200
    assert r.get_json()["stored"] == 2


def test_clear_prekeys_rejects_invalid_identity(server, client):
    r = client.delete("/v1/prekey/bad%7Cname", headers=_auth_headers())
    assert r.status_code == 400


def test_remaining_prekeys_rejects_invalid_identity(server, client):
    r = client.get("/v1/prekey/remaining/bad%7Cname", headers=_auth_headers())
    assert r.status_code == 400


def test_message_send_rejects_invalid_recipient(server, client):
    r = client.post("/v1/messages/send", headers=_auth_headers(),
                    json={"id": "m1", "to": "../evil", "identity": "alice",
                          "payload": {}})
    assert r.status_code == 400
    assert r.get_json()["error"] == "invalid recipient"


def test_message_send_accepts_valid_recipient(server, client):
    r = client.post("/v1/messages/send", headers=_auth_headers(),
                    json={"id": "m2", "to": "bob", "identity": "alice",
                          "payload": {"n": 1}})
    assert r.status_code == 200
    assert r.get_json()["status"] == "stored"


def test_message_ack_validates_msg_ids(server, client):
    # 非列表
    r = client.post("/v1/messages/ack", headers=_auth_headers(),
                    json={"msg_ids": "m1"})
    assert r.status_code == 400
    # 超量
    r = client.post("/v1/messages/ack", headers=_auth_headers(),
                    json={"msg_ids": [f"m{i}" for i in range(201)]})
    assert r.status_code == 400
    # 非法元素
    r = client.post("/v1/messages/ack", headers=_auth_headers(),
                    json={"msg_ids": ["ok", 123]})
    assert r.status_code == 400
    # 正常
    r = client.post("/v1/messages/ack", headers=_auth_headers(),
                    json={"msg_ids": ["m1", "m2"]})
    assert r.status_code == 200
    assert r.get_json()["acked"] == 2


# ----------------------------------------------------------------------
# 上传会话回收 / 落盘
# ----------------------------------------------------------------------

def test_purge_stale_uploads_releases_lock(server):
    tok = "b" * 32
    part = os.path.join(server.FILE_DIR, tok + ".part")
    with open(part, "wb") as f:
        f.write(b"x")
    server._upload_sessions[tok] = {
        "identity": "alice", "path": part,
        "mtime": time.time() - 3600, "total": 10, "recipient": "bob",
    }
    server._upload_locks[tok] = threading.Lock()

    server._purge_stale_upload_sessions()

    assert tok not in server._upload_sessions
    # R1 修复: 互斥锁同步释放, 不残留
    assert tok not in server._upload_locks
    assert not os.path.exists(part)


def test_upload_overwrites_existing_final_file(server, client):
    """同一 token 二次完整上传应覆盖已存在文件 (os.replace), 而非抛异常。"""
    token = "c" * 32
    body = b"hello"

    def _full_upload():
        return client.post("/v1/files/upload", headers=_auth_headers(
            "alice", **{"X-Upload-Token": token, "X-Recipient": "bob",
                        "X-Offset": "0", "X-Total-Size": str(len(body))}),
            data=body)

    r1 = _full_upload()
    assert r1.status_code == 201

    # 清掉 files 元数据行, 模拟重传场景 (避开主键冲突)
    con = sqlite3.connect(server.DB_PATH)
    con.execute("DELETE FROM files WHERE token = ?", (token,))
    con.commit()
    con.close()

    # R1 修复: 旧代码 os.rename 在 Windows 上目标已存在会抛 FileExistsError → 500
    r2 = _full_upload()
    assert r2.status_code == 201
    with open(os.path.join(server.FILE_DIR, token), "rb") as f:
        assert f.read() == body


# ----------------------------------------------------------------------
# 本地存储
# ----------------------------------------------------------------------

def test_save_file_key_no_plaintext_fallback(tmp_path, monkeypatch):
    """加密不可用时不得明文落盘, 且成功路径行为不变。"""
    import config
    import localstore
    store = localstore.LocalStore(str(tmp_path / "l.db"))

    def _boom(_key):
        raise RuntimeError("device key unavailable")

    monkeypatch.setattr(config, "encrypt_bytes", _boom)
    assert store.save_file_key("m1", b"k" * 32) is False
    assert store.take_file_key("m1") is None  # 未落盘

    monkeypatch.setattr(config, "encrypt_bytes", lambda b: b"ENC:" + b)
    monkeypatch.setattr(config, "decrypt_bytes",
                        lambda b: b[len(b"ENC:"):])
    assert store.save_file_key("m2", b"k" * 32) is True
    assert store.take_file_key("m2") == b"k" * 32


def test_search_escapes_like_wildcards(tmp_path):
    import localstore
    store = localstore.LocalStore(str(tmp_path / "l.db"))
    store.upsert_message("bob", "m1", "bob", "message", "进度%100 完成",
                         "stored", True, 3.0)
    store.upsert_message("bob", "m2", "bob", "message", "价格 100 元",
                         "stored", True, 2.0)
    store.upsert_message("bob", "m3", "bob", "message", "win_path 变量",
                         "stored", True, 1.0)
    store.upsert_message("bob", "m4", "bob", "message", "winApath 混淆",
                         "stored", True, 0.5)
    # % 按字面匹配, 不再当通配符
    assert [h["msg_id"] for h in store.search("%100")] == ["m1"]
    # _ 按字面匹配, 不再匹配任意单字符
    assert [h["msg_id"] for h in store.search("n_p")] == ["m3"]
    # 普通子串不受影响
    assert [h["msg_id"] for h in store.search("100")] == ["m1", "m2"]


# ----------------------------------------------------------------------
# keys / core
# ----------------------------------------------------------------------

def test_list_identities_tolerates_corrupt_meta(tmp_path):
    from keys import KeyStore
    ks = KeyStore(str(tmp_path))
    (tmp_path / "foo.pub").write_bytes(b"pub")
    (tmp_path / "foo.meta").write_text("{not json", encoding="utf-8")
    ids = ks.list_identities()
    assert len(ids) == 1
    assert ids[0]["identity"] == "foo"
    assert ids[0]["comment"] == ""


def test_decryption_error_single_definition():
    import core
    with open(core.__file__, encoding="utf-8") as f:
        src = f.read()
    assert len(re.findall(r"^class DecryptionError", src, re.M)) == 1


def test_argon2_params_clamped_like_derive_key(monkeypatch):
    """加密端参数钳制必须与 derive_key 一致: 越界回退默认。"""
    import config
    import core
    monkeypatch.setattr(config, "load", lambda: {"argon2id": {
        "time_cost": 100, "memory_cost": 4 * 1024 * 1024, "parallelism": 32}})
    tc, mc, pl = core._get_argon2_params()
    assert (tc, mc, pl) == (core.ARGON2_TIME_COST,
                            core.ARGON2_MEMORY_COST,
                            core.ARGON2_PARALLELISM)


def test_argon2_params_product_clamp(monkeypatch):
    """乘积钳制: memory×parallelism ≤ 2GiB, 按 memory 缩减 parallelism。"""
    import config
    import core
    monkeypatch.setattr(config, "load", lambda: {"argon2id": {
        "time_cost": 4, "memory_cost": 1024 * 1024, "parallelism": 8}})
    tc, mc, pl = core._get_argon2_params()
    assert mc * pl <= 2 * 1024 * 1024
    assert pl == 2
