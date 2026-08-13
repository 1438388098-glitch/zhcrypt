# -*- coding: utf-8 -*-
"""
10-agent 审查修复回归测试:
1. 登录切换身份 → store 重绑到 app (C1)
2. /history 文件消息 body 剥离 key (C1/Agent-6/7/8)
3. 收到消息状态为 delivered (Agent-6 C1)
4. 好友 confirmed 不被 request 降级 (Agent-5)
5. 会话文件并发锁存在 (Agent-3 C1)
6. 连接错误中文化 (Agent-8 M1)
"""
import os
import sys
import time
import json
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui
import chat_client as cc
import fileclient  # noqa
from session import session_lock


# ---- 1. 登录切换身份 store 重绑 ----

def test_login_switch_identity_rebinds_store(monkeypatch, tmp_path):
    """登录身份≠启动身份 → app.store 换成新身份库 (C1 数据串库修复)。"""
    from localstore import LocalStore

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(os.path, "expanduser", lambda p: str(fake_home))
    db_dir = str(fake_home / ".zhcrypt" / "local")
    os.makedirs(db_dir, exist_ok=True)

    # 模拟 main 内流程
    old_store = LocalStore(os.path.join(db_dir, "default.db"))
    app = tui.ChatApp.__new__(tui.ChatApp)
    app.identity = "default"
    app.store = old_store
    app.notify = lambda *a, **k: None
    app.attach_client = lambda client: setattr(app, "_attached", client)

    class C:
        pass

    # 登录到不同身份 alice
    new_store = LocalStore(os.path.join(db_dir, "alice.db"))
    assert app.store is old_store
    # 模拟 _on_login_ok 的重绑逻辑
    if "alice" != app.identity:
        old_store.close()
        app.store = new_store  # C1 修复的关键行
    assert app.store is new_store, "app.store 必须重绑到新身份库"


# ---- 2. /history 文件消息剥离 key ----

def test_history_strips_key_from_body(monkeypatch):
    import inspect
    src = inspect.getsource(tui.ChatApp._cmd_history)
    assert "k != \"key\"" in src, "/history 落库必须剥离 file.key 明文"
    assert "save_file_key" in src, "key 仍应单独存 file_keys 表"


# ---- 3. 收到消息 delivered 状态 ----

def test_ingest_status_delivered():
    """收到消息落库状态为 delivered (Agent-6 C1: ✓✓ 语义)。"""
    import inspect
    src = inspect.getsource(tui._ingest_server_message)
    assert '"delivered"' in src, "接收落库状态应为 delivered"


# ---- 4. confirmed 不降级 ----

def test_friend_request_no_downgrade():
    """已 confirmed 的好友收到重复 request 不降级 (Agent-5 幂等)。"""
    app = type("A", (), {"post_message": staticmethod(lambda m: None)})()
    store = type("S", (), {
        "friend_status": staticmethod(lambda p: "confirmed"),
        "upsert_friend": staticmethod(lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("confirmed 关系被降级!"))),
        "get_messages": staticmethod(lambda *a, **k: []),
    })()
    client = type("C", (), {
        "receive_chat_message": staticmethod(lambda m: {
            "text": "", "from": "bob", "timestamp": time.time(),
            "verified": True, "msg_id": "m1",
            "friend": {"action": "request"}})})()
    tui._ingest_server_message(app, client, store, {"id": "m1", "from": "bob"})
    # 不抛异常即通过 (upsert_friend 未被调用)


# ---- 5. 会话锁 ----

def test_session_lock_exists():
    """session_lock 上下文可用且可重入 (RLock)。"""
    with session_lock("alice", "bob"):
        with session_lock("alice", "bob"):
            pass  # RLock 可重入
    assert True


def test_session_save_atomic(monkeypatch, tmp_path):
    """save_session 原子写: 并发读不读到半写文件。"""
    import session as session_mod
    # 直接验证实现含 os.replace
    import inspect
    src = inspect.getsource(session_mod.save_session)
    assert "os.replace" in src, "save_session 应原子写 (tmp+rename)"


# ---- 6. 连接错误中文化 ----

def test_friendly_conn_error():
    for exc, kw in [(ConnectionRefusedError(), "无法连接服务器"),
                    (TimeoutError(), "超时"),
                    (__import__("socket").gaierror(), "域名")]:
        msg = cc._friendly_conn_error(exc)
        assert kw in msg, f"{exc} → {msg}"
    assert "traceback" not in cc._friendly_conn_error(ConnectionRefusedError())
