#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
tests/test_localstore.py — LocalStore 单元测试 (Agent-C 产出)
============================================================
覆盖 AGENTS.md §2.2 全部方法: 正常路径 + 边界 (幂等/分页/取删/并发)。
全部使用 pytest tmp_path 隔离数据库, 无共享状态。
"""

import os
import threading

import pytest

from localstore import LocalStore


def make_store(tmp_path, name="test.db"):
    return LocalStore(str(tmp_path / name))


def test_init_creates_parent_dir(tmp_path):
    nested = tmp_path / "a" / "b" / "c.db"
    store = LocalStore(str(nested))
    assert nested.parent.exists()
    store.close()


def test_init_idempotent(tmp_path):
    path = tmp_path / "s.db"
    LocalStore(path)
    LocalStore(path)


def test_upsert_conversation_roundtrip(tmp_path):
    store = make_store(tmp_path)
    store.upsert_conversation("alice", "你好", 100.0)
    store.upsert_conversation("bob", "在吗", 200.0)
    convs = store.list_conversations()
    assert [c["peer"] for c in convs] == ["bob", "alice"]  # last_ts 降序
    alice = convs[1]
    assert alice["last_text"] == "你好"
    assert alice["last_ts"] == 100.0
    assert alice["unread"] == 0
    assert alice["pinned"] == 0


def test_upsert_conversation_updates_existing(tmp_path):
    store = make_store(tmp_path)
    store.upsert_conversation("alice", "第一条", 100.0)
    store.upsert_conversation("alice", "第二条", 150.0)
    convs = store.list_conversations()
    assert len(convs) == 1
    assert convs[0]["last_text"] == "第二条"
    assert convs[0]["last_ts"] == 150.0


def test_unread_increment_and_clear(tmp_path):
    store = make_store(tmp_path)
    store.upsert_conversation("alice", "hi", 1.0)
    store.upsert_conversation("alice", "hi2", 2.0, unread_inc=True)
    store.upsert_conversation("alice", "hi3", 3.0, unread_inc=True)
    assert store.list_conversations()[0]["unread"] == 2
    store.upsert_conversation("alice", "hi4", 4.0)  # unread_inc=False 保持
    assert store.list_conversations()[0]["unread"] == 2
    store.clear_unread("alice")
    assert store.list_conversations()[0]["unread"] == 0


def test_upsert_conversation_unread_inc_on_new_peer(tmp_path):
    store = make_store(tmp_path)
    store.upsert_conversation("carol", "首条", 1.0, unread_inc=True)
    assert store.list_conversations()[0]["unread"] == 1


def test_upsert_message_roundtrip(tmp_path):
    store = make_store(tmp_path)
    store.upsert_message("alice", "m1", "alice", "text", "你好呀", "sent", 1, 123.0)
    msgs = store.get_messages("alice")
    assert len(msgs) == 1
    m = msgs[0]
    assert m["peer"] == "alice"
    assert m["msg_id"] == "m1"
    assert m["from_peer"] == "alice"
    assert m["msg_type"] == "text"
    assert m["body"] == "你好呀"
    assert m["status"] == "sent"
    assert m["verified"] == 1
    assert m["ts"] == 123.0


def test_upsert_message_idempotent_same_msg_id(tmp_path):
    store = make_store(tmp_path)
    store.upsert_message("alice", "m1", "alice", "text", "旧", "sent", 1, 100.0)
    store.upsert_message("alice", "m1", "alice", "text", "新", "delivered", 1, 150.0)
    msgs = store.get_messages("alice")
    assert len(msgs) == 1  # 同 msg_id 不重复
    assert msgs[0]["body"] == "新"
    assert msgs[0]["status"] == "delivered"
    assert msgs[0]["ts"] == 150.0


def test_upsert_message_touches_conversation_without_unread(tmp_path):
    store = make_store(tmp_path)
    store.upsert_message("bob", "m1", "bob", "text", "在吗", "sent", 0, 10.0)
    convs = store.list_conversations()
    assert len(convs) == 1
    assert convs[0]["last_text"] == "在吗"
    assert convs[0]["last_ts"] == 10.0
    assert convs[0]["unread"] == 0  # 本方法不加 unread


def test_get_messages_ascending(tmp_path):
    store = make_store(tmp_path)
    for i in range(5):
        store.upsert_message("alice", f"m{i}", "alice", "text", f"msg{i}", "sent", 0, float(i))
    msgs = store.get_messages("alice")
    assert [m["ts"] for m in msgs] == [0.0, 1.0, 2.0, 3.0, 4.0]  # 升序
    assert [m["msg_id"] for m in msgs] == [f"m{i}" for i in range(5)]


def test_get_messages_limit_default_100(tmp_path):
    store = make_store(tmp_path)
    for i in range(120):
        store.upsert_message("alice", f"m{i}", "alice", "text", f"msg{i}", "sent", 0, float(i))
    msgs = store.get_messages("alice")
    assert len(msgs) == 100


def test_get_messages_custom_limit(tmp_path):
    store = make_store(tmp_path)
    for i in range(10):
        store.upsert_message("alice", f"m{i}", "alice", "text", f"msg{i}", "sent", 0, float(i))
    msgs = store.get_messages("alice", limit=3)
    assert [m["msg_id"] for m in msgs] == ["m7", "m8", "m9"]  # 最近 3 条, 升序


def test_get_messages_before_ts_paging(tmp_path):
    store = make_store(tmp_path)
    for i in range(10):
        store.upsert_message("alice", f"m{i}", "alice", "text", f"msg{i}", "sent", 0, float(i))
    page = store.get_messages("alice", limit=3, before_ts=7.0)
    assert [m["ts"] for m in page] == [4.0, 5.0, 6.0]  # ts<7 的最近 3 条, 升序
    page2 = store.get_messages("alice", limit=3, before_ts=4.0)
    assert [m["ts"] for m in page2] == [1.0, 2.0, 3.0]
    assert store.get_messages("alice", limit=3, before_ts=0.0) == []


def test_get_messages_peer_isolation(tmp_path):
    store = make_store(tmp_path)
    store.upsert_message("alice", "m1", "alice", "text", "给alice", "sent", 0, 1.0)
    store.upsert_message("bob", "m2", "bob", "text", "给bob", "sent", 0, 2.0)
    assert store.get_messages("alice")[0]["body"] == "给alice"
    assert store.get_messages("bob")[0]["body"] == "给bob"


def test_outbox_save_and_list(tmp_path):
    store = make_store(tmp_path)
    store.save_outbox("o1", "bob", "第一条原文")
    store.save_outbox("o2", "bob", "第二条原文")
    rows = store.list_outbox()
    assert len(rows) == 2
    o = {r["msg_id"]: r for r in rows}
    assert o["o1"]["status"] == "queued"
    assert o["o1"]["attempts"] == 0
    assert o["o1"]["body"] == "第一条原文"
    assert o["o1"]["peer"] == "bob"


def test_outbox_mark_status_and_attempts(tmp_path):
    store = make_store(tmp_path)
    store.save_outbox("o1", "bob", "正文")
    store.mark_outbox("o1", "sending", attempts=1)
    row = store.list_outbox()[0]
    assert row["status"] == "sending"
    assert row["attempts"] == 1
    store.mark_outbox("o1", "failed", attempts=2)
    assert store.list_outbox() == []  # failed 不再出现在待发列表
    store.mark_outbox("o1", "queued")  # 只改状态, attempts 保持
    row = store.list_outbox()[0]
    assert row["status"] == "queued"
    assert row["attempts"] == 2


def test_outbox_save_is_replace_by_msg_id(tmp_path):
    store = make_store(tmp_path)
    store.save_outbox("o1", "bob", "v1")
    store.save_outbox("o1", "bob", "v2")
    rows = store.list_outbox()
    assert len(rows) == 1
    assert rows[0]["body"] == "v2"


def test_take_file_key_take_and_delete(tmp_path):
    store = make_store(tmp_path)
    key = b"\x00\x01\x02\x03secret-key"
    store.save_file_key("m9", key)
    got = store.take_file_key("m9")
    assert got == key
    assert store.take_file_key("m9") is None  # 二次调用返回 None (取出即删)


def test_take_file_key_missing_returns_none(tmp_path):
    store = make_store(tmp_path)
    assert store.take_file_key("不存在") is None


def test_save_file_key_replace(tmp_path):
    store = make_store(tmp_path)
    store.save_file_key("m1", b"k1")
    store.save_file_key("m1", b"k2")
    assert store.take_file_key("m1") == b"k2"


def test_search_chinese_keyword(tmp_path):
    store = make_store(tmp_path)
    store.upsert_message("alice", "m1", "alice", "text", "今天天气不错", "sent", 1, 1.0)
    store.upsert_message("alice", "m2", "bob", "text", "明天会下雨", "sent", 1, 2.0)
    store.upsert_message("alice", "m3", "alice", "text", "天气预报说晴", "sent", 1, 3.0)
    hits = store.search("天气")
    assert {h["msg_id"] for h in hits} == {"m1", "m3"}
    assert [h["ts"] for h in hits] == [3.0, 1.0]  # 按 ts 降序
    assert store.search("不存在的词") == []


def test_search_limit(tmp_path):
    store = make_store(tmp_path)
    for i in range(10):
        store.upsert_message("alice", f"m{i}", "alice", "text", f"关键字{i}", "sent", 0, float(i))
    assert len(store.search("关键字", limit=3)) == 3


def test_search_across_peers(tmp_path):
    store = make_store(tmp_path)
    store.upsert_message("alice", "m1", "alice", "text", "共享关键词", "sent", 0, 1.0)
    store.upsert_message("bob", "m2", "bob", "text", "共享关键词", "sent", 0, 2.0)
    hits = store.search("共享关键词")
    assert {h["peer"] for h in hits} == {"alice", "bob"}


def test_concurrent_upserts_no_exception(tmp_path):
    store = make_store(tmp_path)
    errors = []

    def worker(prefix):
        try:
            for i in range(100):
                store.upsert_message(
                    prefix, f"{prefix}-{i}", prefix, "text", f"body-{prefix}-{i}",
                    "sent", 0, float(i),
                )
        except Exception as e:  # noqa: BLE001 — 冒烟测试需捕获一切异常
            errors.append(e)

    t1 = threading.Thread(target=worker, args=("t1",))
    t2 = threading.Thread(target=worker, args=("t2",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert errors == []
    assert len(store.get_messages("t1")) == 100
    assert len(store.get_messages("t2")) == 100
    assert len(store.search("body-t1", limit=200)) == 100


def test_concurrent_unread_increment(tmp_path):
    store = make_store(tmp_path)
    store.upsert_conversation("alice", "start", 0.0)

    def worker(n):
        for i in range(50):
            store.upsert_conversation("alice", f"msg{i}", float(i), unread_inc=True)

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start(); t2.start()
    t1.join(); t2.join()
    assert store.list_conversations()[0]["unread"] == 100


def test_outbox_failed_list_and_delete(tmp_path):
    """list_failed_outbox 只返回 failed; delete_outbox 清理。"""
    from localstore import LocalStore
    st = LocalStore(str(tmp_path / "t.db"))
    st.save_outbox("m1", "bob", "hi")
    st.save_outbox("m2", "bob", "yo")
    st.mark_outbox("m2", "failed", attempts=3)
    st.mark_outbox("m1", "sending", attempts=1)
    failed = st.list_failed_outbox()
    assert len(failed) == 1 and failed[0]["msg_id"] == "m2" and failed[0]["attempts"] == 3
    st.delete_outbox("m2")
    assert st.list_failed_outbox() == []
    st.close()
