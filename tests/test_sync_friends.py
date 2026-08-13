# -*- coding: utf-8 -*-
"""
服务器身份同步 + 好友列表排序 + 自动 prekey 测试:
1. fetch_server_identities 方法
2. _bootstrap_tasks: 自动上传 prekey + 同步服务器身份为好友
3. 会话列表排序: 好友 (confirmed) 置顶, 无会话好友也显示
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui
import chat_client as cc
import fileclient  # noqa


class _FakeStore:
    def __init__(self):
        self.friends = {}
        self.convs = []
        self.peers_seen = set()

    def friend_status(self, peer):
        return self.friends.get(peer)

    def upsert_friend(self, peer, status, ts=None):
        self.friends[peer] = status

    def list_friends(self):
        return [{"peer": k, "status": v, "ts": 0} for k, v in self.friends.items()]

    def list_conversations(self):
        return list(self.convs)

    def upsert_conversation(self, peer, text, ts):
        pass

    def clear_unread(self, peer):
        pass

    def get_messages(self, peer, limit=100, before_ts=None):
        return []


class _FakeApp:
    def __init__(self):
        self.posted = []
        self._current_peer = None
        self._search_active = False
        self._convs = []

    def post_message(self, m):
        self.posted.append(m)

    def _refresh_conversations(self, *a, **k):
        pass

    def _update_status_bar(self, *a, **k):
        pass

    def query_one(self, *a, **k):
        class _V:
            def __init__(self):
                self.index = -1

            def clear(self):
                pass

            def append(self, item):
                pass

            def remove_children(self):
                pass

            def mount(self, *a, **k):
                pass

            def scroll_end(self, *a, **k):
                pass
        return _V()


def test_fetch_server_identities():
    client = cc.ChatClient.__new__(cc.ChatClient)
    captured = {}

    def fake_http(method, path, body=None, timeout=15):
        captured["path"] = path
        return {"identities": [{"identity": "bob", "fingerprint": "f1",
                                "last_seen": 1.0}]}

    client._http_request = fake_http
    result = client.fetch_server_identities()
    assert captured["path"] == "/v1/identities"
    assert result[0]["identity"] == "bob"


def test_bootstrap_tasks_syncs_friends():
    """自动同步: 服务器身份 (非自己) → 本地好友 confirmed; 自己跳过;
    且通过 FriendsSynced 事件通知主线程刷新 (而非后台线程直操作 UI)。"""
    app = _FakeApp()
    app.identity = "alice"
    app.store = _FakeStore()

    class C:
        def ensure_own_prekey(self):
            return True, "prekey 充足(剩余 50)"

        def fetch_server_identities(self):
            return [{"identity": "bob", "fingerprint": "x"},
                    {"identity": "carol", "fingerprint": "y"},
                    {"identity": "alice", "fingerprint": "z"}]

    app.client = C()
    tui.ChatApp._bootstrap_tasks(app)
    assert app.store.friends.get("bob") == "confirmed"
    assert app.store.friends.get("carol") == "confirmed"
    assert "alice" not in app.store.friends, "自己不应加入好友列表"
    # 关键: 同步后应发 FriendsSynced 事件 (后台线程不直接刷新 UI)
    synced = [m for m in app.posted if isinstance(m, tui.FriendsSynced)]
    assert len(synced) == 1, "应发 FriendsSynced 事件通知主线程刷新"
    assert synced[0].added == 2


def test_bootstrap_tasks_skips_existing():
    """已存在好友关系的不覆盖 (保持 requested 等状态)。"""
    app = _FakeApp()
    app.identity = "alice"
    store = _FakeStore()
    store.friends["bob"] = "requested"  # 已有待确认关系
    app.store = store

    class C:
        def ensure_own_prekey(self):
            return True, "ok"

        def fetch_server_identities(self):
            return [{"identity": "bob", "fingerprint": "x"}]

    app.client = C()
    tui.ChatApp._bootstrap_tasks(app)
    assert store.friends.get("bob") == "requested", "不应覆盖已存在状态"


def test_conversation_sort_friends_first():
    """好友置顶排序: confirmed 组在上, 无会话好友也显示。"""
    app = _FakeApp()
    app.identity = "alice"
    store = _FakeStore()
    store.friends = {"bob": "confirmed", "stranger": None}
    store.convs = [
        {"peer": "stranger", "last_text": "hi", "last_ts": 300.0, "unread": 0},
        {"peer": "bob", "last_text": "hi2", "last_ts": 200.0, "unread": 0},
    ]
    app.store = store
    app._refresh_conversations = tui.ChatApp._refresh_conversations.__get__(app)
    # 直接调用内部排序逻辑 (通过 _convs 断言)
    app._refresh_conversations()
    peers = [str(c["peer"]) for c in app._convs]
    assert peers[0] == "bob", f"好友应置顶: {peers}"
    assert "bob" in peers and "stranger" in peers
