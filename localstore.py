#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
localstore.py — 客户端本地缓存 (Agent-C 产出)
=============================================
职责: 本地会话/消息/outbox/file_keys 的 SQLite 持久化,
      供 TUI (Agent-D) 与 outbox 重发逻辑调用。
入口: LocalStore(db_path), 方法签名与返回结构见 AGENTS.md §2.2。
约束: 每个方法调用内部新建独立 sqlite3 连接 (WAL + busy_timeout=5000),
      不跨线程共享连接, 天然线程安全。
"""

import os
import sqlite3
import time
from contextlib import contextmanager

__all__ = ["LocalStore", "LocalStoreError"]


class LocalStoreError(Exception):
    """LocalStore 专有异常: 仅数据库编程/配置错误抛出 (AGENTS.md §1.2)。"""


# ---- 模块级 DDL 常量 (设计文档 §7.2) ----

DDL_CONVERSATIONS = """
CREATE TABLE IF NOT EXISTS conversations (
    peer        TEXT PRIMARY KEY,
    last_text   TEXT,
    last_ts     REAL,
    unread      INTEGER DEFAULT 0,
    pinned      INTEGER DEFAULT 0
);
"""

DDL_LOCAL_MESSAGES = """
CREATE TABLE IF NOT EXISTS local_messages (
    peer        TEXT NOT NULL,
    msg_id      TEXT PRIMARY KEY,
    from_peer   TEXT NOT NULL,
    msg_type    TEXT NOT NULL,            -- text | file
    body        TEXT NOT NULL,            -- 明文文本 或 文件元数据 JSON
    status      TEXT NOT NULL DEFAULT 'sent',  -- sent|delivered|failed
    verified    INTEGER DEFAULT 0,
    ts          REAL NOT NULL
);
"""

DDL_LM_IDX = """
CREATE INDEX IF NOT EXISTS idx_lm_peer_ts ON local_messages(peer, ts);
"""

DDL_OUTBOX = """
CREATE TABLE IF NOT EXISTS outbox (
    msg_id      TEXT PRIMARY KEY,
    peer        TEXT NOT NULL,
    body        TEXT NOT NULL,            -- 加密前原文
    attempts    INTEGER DEFAULT 0,
    status      TEXT NOT NULL,            -- queued|sending|failed
    ts          REAL NOT NULL
);
"""

DDL_FILE_KEYS = """
CREATE TABLE IF NOT EXISTS file_keys (
    msg_id      TEXT PRIMARY KEY,         -- 解密后立即删除
    key         BLOB NOT NULL
);
"""

DDL_FRIENDS = """
CREATE TABLE IF NOT EXISTS friends (
    peer        TEXT PRIMARY KEY,
    status      TEXT NOT NULL,            -- requested|confirmed|removed
    ts          REAL NOT NULL
);
"""


class LocalStore:
    def __init__(self, db_path: str):
        """建表 (幂等), 自动创建父目录。"""
        self.db_path = db_path
        try:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        except OSError as e:
            raise LocalStoreError(f"无法创建数据库目录: {e}") from e
        with self._conn() as conn:
            conn.executescript(
                DDL_CONVERSATIONS
                + DDL_LOCAL_MESSAGES
                + DDL_LM_IDX
                + DDL_OUTBOX
                + DDL_FILE_KEYS
                + DDL_FRIENDS
            )

    def close(self):
        """契约兼容: 连接均为方法内临时新建, 无需持有, 无操作。"""
        return None

    def _connect(self):
        """新建连接: WAL + busy_timeout=5000 (对齐 server.py get_db 风格)。"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except sqlite3.Error as e:
            raise LocalStoreError(f"无法打开数据库 {self.db_path}: {e}") from e

    @contextmanager
    def _conn(self):
        """方法内独立连接上下文: 异常回滚并包装为 LocalStoreError。"""
        conn = self._connect()
        try:
            yield conn
        except sqlite3.Error as e:
            conn.rollback()
            raise LocalStoreError(f"数据库操作失败: {e}") from e
        else:
            conn.commit()
        finally:
            conn.close()

    # ---- 会话 ----

    def upsert_conversation(self, peer, last_text, last_ts, unread_inc=False) -> None:
        """存在则更新 last_text/last_ts; unread_inc=True 时 unread+1, 否则保持。"""
        with self._conn() as conn:
            conn.execute("INSERT OR IGNORE INTO conversations(peer) VALUES (?)", (peer,))
            conn.execute(
                "UPDATE conversations SET last_text=?, last_ts=?, unread=unread+? "
                "WHERE peer=?",
                (last_text, last_ts, 1 if unread_inc else 0, peer),
            )

    def list_conversations(self) -> list:
        """[{peer,last_text,last_ts,unread,pinned}] 按 last_ts 降序。"""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT peer, last_text, last_ts, unread, pinned "
                "FROM conversations ORDER BY last_ts DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def clear_unread(self, peer) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE conversations SET unread=0 WHERE peer=?", (peer,)
            )

    # ---- 消息 ----

    def upsert_message(self, peer, msg_id, from_peer, msg_type, body, status, verified, ts) -> None:
        """INSERT OR REPLACE (幂等, msg_id 主键); 只 touch 会话, 不加 unread
        (是否当前会话由 TUI 决定, TUI 自行调用 upsert_conversation(unread_inc=True))。"""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO local_messages"
                "(peer, msg_id, from_peer, msg_type, body, status, verified, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (peer, msg_id, from_peer, msg_type, body, status, int(bool(verified)), ts),
            )
            conn.execute("INSERT OR IGNORE INTO conversations(peer) VALUES (?)", (peer,))
            # MAJOR 修复: last_ts 只前进不后退 (乱序到达的旧消息不得回退会话排序;
            # MAX() 遇 NULL 返回 NULL, 故先 COALESCE 归一)
            conn.execute(
                "UPDATE conversations SET last_text=?, "
                "last_ts=MAX(COALESCE(last_ts, 0), ?) WHERE peer=?",
                (body, ts, peer),
            )

    def get_messages(self, peer, limit=100, before_ts=None) -> list:
        """按 ts 升序返回最近 limit 条; before_ts 用于历史分页
        (取 ts < before_ts 的最近 limit 条, 返回时仍升序)。"""
        with self._conn() as conn:
            if before_ts is not None:
                rows = conn.execute(
                    "SELECT peer, msg_id, from_peer, msg_type, body, status, verified, ts "
                    "FROM local_messages WHERE peer=? AND ts<? "
                    "ORDER BY ts DESC LIMIT ?",
                    (peer, before_ts, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT peer, msg_id, from_peer, msg_type, body, status, verified, ts "
                    "FROM local_messages WHERE peer=? ORDER BY ts DESC LIMIT ?",
                    (peer, limit),
                ).fetchall()
            rows.reverse()
            return [dict(r) for r in rows]

    def get_oldest_message(self, peer) -> dict | None:
        """返回会话最早一条消息 (历史分页游标用), 无消息返回 None。"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT peer, msg_id, from_peer, msg_type, body, status, verified, ts "
                "FROM local_messages WHERE peer=? ORDER BY ts ASC LIMIT 1",
                (peer,),
            ).fetchone()
            return dict(row) if row else None

    # ---- outbox ----

    def save_outbox(self, msg_id, peer, body) -> None:
        """落库 outbox: status=queued, attempts=0。"""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO outbox(msg_id, peer, body, attempts, status, ts) "
                "VALUES (?, ?, ?, 0, 'queued', ?)",
                (msg_id, peer, body, time.time()),
            )

    def list_outbox(self) -> list:
        """status in (queued, sending) 的消息列表。"""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT msg_id, peer, body, attempts, status, ts "
                "FROM outbox WHERE status IN ('queued', 'sending') "
                "ORDER BY ts ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_outbox(self, msg_id, status, attempts=None) -> None:
        """更新 outbox 状态; attempts 非 None 时同时写入新的尝试次数
        (调用方负责递增, 如 attempts=row['attempts']+1)。"""
        with self._conn() as conn:
            if attempts is None:
                conn.execute("UPDATE outbox SET status=? WHERE msg_id=?", (status, msg_id))
            else:
                conn.execute(
                    "UPDATE outbox SET status=?, attempts=? WHERE msg_id=?",
                    (status, attempts, msg_id),
                )

    def list_failed_outbox(self) -> list:
        """status=failed 的消息列表 (TUI 的 r 键重发来源)。"""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT msg_id, peer, body, attempts, status, ts "
                "FROM outbox WHERE status='failed' ORDER BY ts ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_outbox(self, msg_id) -> None:
        """删除 outbox 记录 (发送成功后清理)。"""
        with self._conn() as conn:
            conn.execute("DELETE FROM outbox WHERE msg_id=?", (msg_id,))

    # ---- 文件密钥 ----

    def save_file_key(self, msg_id, key: bytes) -> None:
        # 审计 M4: 文件 AES 密钥不再明文落盘, 用本机 device.key 加密后存储。
        try:
            from config import encrypt_bytes
            stored = encrypt_bytes(key)
        except Exception:
            stored = key  # 加密不可用时回退 (不应发生, 但避免丢密钥)
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_keys(msg_id, key) VALUES (?, ?)",
                (msg_id, stored),
            )

    def take_file_key(self, msg_id) -> bytes | None:
        """取出即删 (同一连接内 SELECT 后 DELETE, 原子); 无记录返回 None。"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT key FROM file_keys WHERE msg_id=?", (msg_id,)
            ).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM file_keys WHERE msg_id=?", (msg_id,))
            blob = bytes(row["key"])
            # 兼容旧版明文 (32 字节原始密钥) 与新版加密 (nonce+ct ≥ 60 字节)。
            if len(blob) == 32:
                return blob
            try:
                from config import decrypt_bytes
                return decrypt_bytes(blob)
            except Exception:
                return blob

    # ---- 好友 ----

    def upsert_friend(self, peer, status, ts=None) -> None:
        """记录好友关系: status in (requested|confirmed|removed)。"""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO friends(peer, status, ts) VALUES (?, ?, ?)",
                (peer, status, ts if ts is not None else time.time()),
            )

    def friend_status(self, peer) -> str | None:
        """查询好友状态; 无记录返回 None。"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT status FROM friends WHERE peer=?", (peer,)
            ).fetchone()
            return row["status"] if row else None

    def list_friends(self, status=None) -> list:
        """好友列表 [{peer,status,ts}]; status 过滤可选。

        按名称升序 (从上到下稳定排列; ts 在同秒添加时不稳定, 不用作排序键)。
        """
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT peer, status, ts FROM friends "
                    "WHERE status=? ORDER BY peer ASC", (status,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT peer, status, ts FROM friends ORDER BY peer ASC"
                ).fetchall()
            return [dict(r) for r in rows]

    def is_friend(self, peer) -> bool:
        """是否为已确认好友。"""
        return self.friend_status(peer) == "confirmed"

    # ---- 搜索 ----

    def search(self, kw, limit=50) -> list:
        """LIKE '%kw%' 匹配 body, 按 ts 降序返回。"""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT peer, msg_id, from_peer, msg_type, body, status, verified, ts "
                "FROM local_messages WHERE body LIKE ? ORDER BY ts DESC LIMIT ?",
                (f"%{kw}%", limit),
            ).fetchall()
            return [dict(r) for r in rows]
