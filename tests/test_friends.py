# -*- coding: utf-8 -*-
"""
好友功能回归测试:
1. LocalStore 好友 CRUD (upsert/friend_status/list/is_friend)
2. chat_client.send_friend_msg 构造与发送
3. TUI 接收 friend 消息 → 本地好友状态更新 + toast
4. 命令解析 /add /accept /friends
"""
import os
import sys
import json
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui
import chat_client as cc
import fileclient  # noqa: F401 (chat_client 依赖)


# ----------------------------------------------------------------------
# 1. LocalStore 好友
# ----------------------------------------------------------------------

def test_friends_crud(tmp_path):
    from localstore import LocalStore
    st = LocalStore(str(tmp_path / "t.db"))
    assert st.friend_status("bob") is None
    assert st.list_friends() == []
    st.upsert_friend("bob", "requested")
    assert st.friend_status("bob") == "requested"
    assert st.is_friend("bob") is False
    st.upsert_friend("bob", "confirmed")
    assert st.is_friend("bob") is True
    st.upsert_friend("alice", "confirmed")
    lst = st.list_friends()
    assert {f["peer"] for f in lst} == {"bob", "alice"}
    only = st.list_friends(status="confirmed")
    assert {f["peer"] for f in only} == {"bob", "alice"}
    st.upsert_friend("carol", "requested")
    assert {f["peer"] for f in st.list_friends(status="requested")} == {"carol"}
    st.close()


# ----------------------------------------------------------------------
# 2. send_friend_msg
# ----------------------------------------------------------------------

def test_send_friend_msg_constructs_friend_field(monkeypatch, tmp_path):
    client = cc.ChatClient.__new__(cc.ChatClient)
    client.identity = "alice"
    client.passphrase = "pw"
    client.store = type("S", (), {"load_signing_private_key_pem": staticmethod(
        lambda *a: (_ for _ in ()).throw(FileNotFoundError))})()
    client._ws_ready = False

    class DummyState:
        def is_expired(self):
            return False

    captured = {}

    def fake_load(a, b, c):
        return DummyState()

    def fake_send(state, inner):
        captured["inner"] = inner
        return {"id": "f1"}

    monkeypatch.setattr(cc, "load_session", fake_load)
    monkeypatch.setattr(cc, "send_message", fake_send)
    monkeypatch.setattr(cc, "save_session", lambda s, p: None)
    client._send_via_rest = lambda msg: None

    r = client.send_friend_msg("bob", "request")
    assert r.get("status") == "sent"
    inner = json.loads(captured["inner"].decode("utf-8"))
    assert inner["text"] == ""
    assert inner["friend"] == {"action": "request"}

    r2 = client.send_friend_msg("bob", "bogus")
    assert r2.get("error")


# ----------------------------------------------------------------------
# 3. TUI 接收 friend 消息
# ----------------------------------------------------------------------

class _FakeApp:
    def __init__(self):
        self.posted = []
        self._current_peer = None
        self._search_active = False

    def post_message(self, m):
        self.posted.append(m)

    def _render_chat(self, *a, **k):
        pass

    def _refresh_conversations(self, *a, **k):
        pass

    def _update_status_bar(self, *a, **k):
        pass

    def query_one(self, *a, **k):
        class _V:
            def remove_children(self, *a, **k):
                pass

            def mount(self, *a, **k):
                pass

            def scroll_end(self, *a, **k):
                pass
        return _V()


class _FakeClient:
    def receive_chat_message(self, msg):
        return {
            "text": "", "from": "bob", "timestamp": time.time(),
            "verified": True, "msg_id": "m1",
            "friend": {"action": "request"},
        }


class _FakeStore:
    def __init__(self):
        self.friends = {}

    def upsert_friend(self, peer, status, ts=None):
        self.friends[peer] = status

    def friend_status(self, peer):
        return self.friends.get(peer)

    def upsert_message(self, *a, **k):
        pass

    def upsert_conversation(self, *a, **k):
        pass


def test_ingest_friend_request():
    app = _FakeApp()
    client = _FakeClient()
    store = _FakeStore()
    tui._ingest_server_message(app, client, store, {"id": "m1", "from": "bob"})
    assert store.friend_status("bob") == "requested"
    toasts = [m for m in app.posted if isinstance(m, tui.NotifyToast)]
    assert toasts and "请求添加你为好友" in str(toasts[0].text)


def test_ingest_friend_accept():
    app = _FakeApp()
    store = _FakeStore()

    class FC:
        def receive_chat_message(self, msg):
            return {"text": "", "from": "bob", "timestamp": time.time(),
                    "verified": True, "msg_id": "m2",
                    "friend": {"action": "accept"}}

    # R11 门禁: 仅 requested → confirmed; 无未决请求的 accept 被忽略
    tui._ingest_server_message(app, FC(), store, {"id": "m2", "from": "bob"})
    assert store.friend_status("bob") is None

    store.upsert_friend("bob", "requested")
    tui._ingest_server_message(app, FC(), store, {"id": "m3", "from": "bob"})
    assert store.friend_status("bob") == "confirmed"


# ----------------------------------------------------------------------
# 4. 命令表
# ----------------------------------------------------------------------

def test_command_table_has_friend_commands():
    app = tui.ChatApp.__new__(tui.ChatApp)
    table = app._dispatch_command.__code__  # 通过实例方法取表太绕, 直接查源码
    import inspect
    src = inspect.getsource(tui.ChatApp._dispatch_command)
    for cmd in ('"/add"', '"/accept"', '"/friends"'):
        assert cmd in src, f"命令 {cmd} 未注册"


def test_add_friend_open_and_thread():
    """_cmd_add_friend 解析 peer 并打开会话。"""
    app = tui.ChatApp.__new__(tui.ChatApp)
    app._current_peer = None
    app._search_active = False
    app.store = _FakeStore()
    app.notify = lambda *a, **k: None
    app.post_message = lambda m: None  # 防止后台线程崩溃泄漏
    app.client = type("C", (), {
        "send_friend_msg": staticmethod(lambda *a, **k: {"status": "sent"})})()
    opened = {}
    app._open_conversation = lambda peer: opened.__setitem__("peer", peer)
    app._cmd_add_friend("bob")
    assert opened.get("peer") == "bob"
    # 请求在后台线程发送, 稍候完成本地标记 (不阻塞命令)
    import time
    deadline = time.time() + 2
    while time.time() < deadline and app.store.friends.get("bob") is None:
        time.sleep(0.05)
    assert app.store.friends.get("bob") == "requested"


def test_send_friend_request_updates_local():
    """_send_friend_request: 发送成功 → 本地标记 requested。"""
    app = tui.ChatApp.__new__(tui.ChatApp)
    app._current_peer = None
    app.store = _FakeStore()
    app.post_message = lambda m: None

    class C:
        def send_friend_msg(self, peer, action):
            assert action == "request"
            return {"status": "sent", "msg_id": "x"}

    app.client = C()
    tui.ChatApp._send_friend_request(app, "bob")
    assert app.store.friends.get("bob") == "requested"
