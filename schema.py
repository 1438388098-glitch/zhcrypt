"""zhcrypt 共享数据库 schema 定义 (O9)。
集中所有 CREATE TABLE / CREATE INDEX DDL 与 add_column 迁移 helper,
修改表结构只动此处。"""
from sqlite3 import Connection

import re

# 身份名白名单 (对齐 keys._validate_identity): 仅 A-Za-z0-9_.@-, 长度 1-64,
# 禁 ".." 与 "/"、"\". 服务端必须在入口校验, 防止恶意身份名注入 (路径穿越/冒名)。
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


def valid_identity(identity):
    """服务端身份名合法性校验; 非法返回 False。"""
    if not isinstance(identity, str) or not identity:
        return False
    if ".." in identity:
        return False
    return bool(_IDENTITY_RE.match(identity))


PREKEYS_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS prekeys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identity TEXT NOT NULL,
        key_type TEXT NOT NULL DEFAULT 'signed',
        prekey_data TEXT NOT NULL,
        fingerprint TEXT,
        created_at REAL NOT NULL,
        consumed_at REAL,
        consumed INTEGER DEFAULT 0
    )
"""

IDENTITIES_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS identities (
        identity TEXT PRIMARY KEY,
        identity_key_pub TEXT NOT NULL,
        signed_prekey_pub TEXT NOT NULL,
        signed_prekey_sig TEXT NOT NULL,
        signing_public_key TEXT,
        fingerprint TEXT NOT NULL,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL
    )
"""

MESSAGES_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'message',
        payload_json TEXT NOT NULL,
        server_ts REAL NOT NULL,
        delivered_at REAL,
        delivery_ack_at REAL
    )
"""

MESSAGES_IDX_RECIPIENT_SQL = """
    CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages(recipient, delivered_at, server_ts)
"""

MESSAGES_IDX_SESSION_SQL = """
    CREATE INDEX IF NOT EXISTS idx_messages_session
    ON messages(session_id, server_ts)
"""

MESSAGES_IDX_SERVER_TS_SQL = """
    CREATE INDEX IF NOT EXISTS idx_messages_server_ts
    ON messages(server_ts)
"""

# R5: 双向会话历史查询 ((s=? AND r=?) OR (r=? AND s=?)) 的 sender 侧索引,
# 消息量增大后避免全表扫描 + 排序。
MESSAGES_IDX_PAIR_SQL = """
    CREATE INDEX IF NOT EXISTS idx_messages_pair
    ON messages(sender, recipient, server_ts)
"""

FILES_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS files (
        token TEXT PRIMARY KEY,
        uploader TEXT NOT NULL,
        intended_recipient TEXT,
        server_ts REAL NOT NULL
    )
"""

# R4: one-time prekey 唯一性 —— 重复上传/断点重试曾会产生重复行, 同一 OTP
# 可被两次握手消耗 (X3DH 复用面)。迁移去重后建唯一索引。
PREKEYS_UNIQ_DEDUPE_SQL = """
    DELETE FROM prekeys WHERE rowid NOT IN (
        SELECT MIN(rowid) FROM prekeys
        GROUP BY identity, key_type, prekey_data
    )
"""

PREKEYS_UNIQ_INDEX_SQL = """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_prekeys_uniq
    ON prekeys(identity, key_type, prekey_data)
"""


def add_column(db, table, column, col_type):
    """为已存在的表补齐列 (幂等, 用于旧库迁移)"""
    try:
        cols = [r[1] for r in db.execute("PRAGMA table_info({})".format(table))]
    except Exception:
        return
    if column not in cols:
        try:
            db.execute("ALTER TABLE {} ADD COLUMN {} {}".format(table, column, col_type))
        except Exception:
            pass
