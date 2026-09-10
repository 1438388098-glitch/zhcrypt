"""
zhchat WebSocket Server v1.0
=============================
独立的 asyncio WebSocket 消息中继服务器
端口 5003, 与 Flask prekey 服务器共享 SQLite (WAL 模式)

部署: python chat_server.py  (通过 systemd zhchat-ws)
"""
import os
import re
import sys
import json
import time
import hmac
import sqlite3
import asyncio
import hashlib
import secrets
import base64

try:
    import websockets
    import websockets.exceptions
except ImportError:
    sys.exit("websockets 未安装: pip install websockets")

import logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("zhcrypt")

from schema import (
    MESSAGES_TABLE_SQL,
    MESSAGES_IDX_RECIPIENT_SQL,
    MESSAGES_IDX_SESSION_SQL,
    FILES_TABLE_SQL,
    add_column,
    valid_identity,
)

DB_PATH = os.environ.get("ZHPREKEY_DB",
                         os.path.join(os.path.dirname(__file__), "zhprekey.db"))
AUTH_TOKEN = os.environ.get("ZHPREKEY_TOKEN", "")
if not AUTH_TOKEN:
    AUTH_TOKEN = os.environ.get("ZHCHAT_TOKEN", "")
if not AUTH_TOKEN:
    raise RuntimeError(
        "ZHPREKEY_TOKEN 或 ZHCHAT_TOKEN 环境变量未设置。\n"
        "请设置: export ZHPREKEY_TOKEN=$(python -c \"import secrets; print(secrets.token_hex(16))\")\n"
        "并将 token 配置到客户端。"
    )

PORT = int(os.environ.get("ZHCHAT_WS_PORT", "5003"))
HOST = os.environ.get("ZHCHAT_WS_HOST", "0.0.0.0")
MESSAGE_RETENTION_DAYS = int(os.environ.get("ZHCHAT_RETENTION_DAYS", "30"))
RATE_LIMIT_PER_MINUTE = int(os.environ.get("ZHCHAT_RATE_LIMIT", "30"))
# M1 修复: 与 server.py 统一从 ZHCHAT_FILE_DIR 解析文件目录 (默认 DB 同目录 files/)
FILE_DIR = os.environ.get(
    "ZHCHAT_FILE_DIR",
    os.path.join(os.path.dirname(DB_PATH), "files"),
)
os.makedirs(FILE_DIR, exist_ok=True)

connected_clients = {}
rate_limit_buckets = {}





def init_message_db():
    db = _connect()
    db.execute(MESSAGES_TABLE_SQL)
    db.execute(MESSAGES_IDX_RECIPIENT_SQL)
    db.execute(MESSAGES_IDX_SESSION_SQL)
    # V5: 文件元数据表，记录上传者与关联消息
    db.execute(FILES_TABLE_SQL)
    # 兼容旧库: 补齐 intended_recipient 列 (审计 #7)
    add_column(db, "files", "intended_recipient", "TEXT")
    db.commit()
    db.close()


def _now():
    return time.time()


def _connect():
    """统一的 SQLite 连接 (O1-B 架构优化): WAL + busy_timeout=5000。
    让 gunicorn 多 worker 与 WS 服务并发写同一库时自动等待而非报 database is locked。"""
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA busy_timeout=5000")
    return db


def record_file_upload(db, token, uploader, recipient):
    """记录文件上传元数据 (含预期接收方); recipient 为空表示仅上传者可下载"""
    db.execute(
        "INSERT INTO files (token, uploader, intended_recipient, server_ts) "
        "VALUES (?, ?, ?, ?)",
        (token, uploader, recipient or "", _now()),
    )
    db.commit()


def can_download_file(db, token, identity):
    """文件下载授权: 上传者本人或预期接收方均可下载 (审计 #7)"""
    row = db.execute(
        "SELECT uploader, intended_recipient FROM files WHERE token = ?",
        (token,),
    ).fetchone()
    if row is None:
        return False
    uploader = row["uploader"]
    recipient = row["intended_recipient"] or ""
    return identity == uploader or identity == recipient


def _resolve_file_path(token):
    """将下载 token 解析为文件绝对路径, 防御路径穿越 (CWE-22)。

    仅允许 32 位十六进制 token (与上传时 secrets.token_hex(16) 生成格式一致),
    且解析后的真实路径必须严格位于 FILE_DIR 内。任何含 ../ 或非法字符的
    token 都会返回 None, 从而杜绝读取 FILE_DIR 之外的任意文件。
    """
    if not isinstance(token, str) or not re.match(r"^[0-9a-fA-F]{32}$", token):
        return None
    file_path = os.path.join(FILE_DIR, token)
    # 二次防御: 真实路径的父目录必须等于 FILE_DIR (即便正则被绕过)
    if os.path.dirname(os.path.realpath(file_path)) != os.path.realpath(FILE_DIR):
        return None
    return file_path


def check_rate_limit(identity):
    now = _now()
    bucket = [t for t in rate_limit_buckets.get(identity, []) if now - t < 60]
    if bucket:
        rate_limit_buckets[identity] = bucket
    else:
        rate_limit_buckets.pop(identity, None)  # 防键无限增长 (内存 DoS, 审计 M5)
    if len(bucket) >= RATE_LIMIT_PER_MINUTE:
        return False
    bucket.append(now)
    rate_limit_buckets[identity] = bucket
    return True


def store_message(msg_data):
    try:
        db = _connect()
        db.execute("""
            INSERT OR IGNORE INTO messages
            (id, session_id, sender, recipient, type, payload_json, server_ts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            msg_data["id"],
            msg_data["session_id"],
            msg_data["from"],
            msg_data["to"],
            msg_data.get("type", "message"),
            json.dumps(msg_data.get("payload", {}), ensure_ascii=False),
            _now(),
        ))
        db.commit()
        db.close()
        return True
    except Exception as e:
        import sys
        log.error(f"[chat_server] store_message failed: {e}")
        return False


def mark_delivered(msg_ids):
    if not msg_ids:
        return
    db = _connect()
    now = _now()
    db.executemany(
        "UPDATE messages SET delivered_at = ? WHERE id = ?",
        [(now, mid) for mid in msg_ids],
    )
    db.commit()
    db.close()


def get_pending_messages(identity, limit=50):
    db = _connect()
    db.row_factory = sqlite3.Row
    rows = db.execute("""
        SELECT * FROM messages
        WHERE recipient = ? AND delivered_at IS NULL
        ORDER BY server_ts ASC LIMIT ?
    """, (identity, limit)).fetchall()
    db.close()
    msgs = []
    msg_ids = []
    for row in rows:
        payload = json.loads(row["payload_json"])
        msgs.append({
            "id": row["id"],
            "session_id": row["session_id"],
            "from": row["sender"],
            "to": row["recipient"],
            "type": row["type"],
            "timestamp": row["server_ts"],
            "payload": payload,
        })
        msg_ids.append(row["id"])
    if msg_ids:
        mark_delivered(msg_ids)
    return msgs


def fetch_pending_messages(identity, limit=50):
    """仅拉取 pending 消息，不标记 delivered（供 WS 使用）"""
    db = _connect()
    db.row_factory = sqlite3.Row
    rows = db.execute("""
        SELECT * FROM messages
        WHERE recipient = ? AND delivered_at IS NULL
        ORDER BY server_ts ASC LIMIT ?
    """, (identity, limit)).fetchall()
    db.close()
    msgs = []
    for row in rows:
        msgs.append({
            "id": row["id"],
            "session_id": row["session_id"],
            "from": row["sender"],
            "to": row["recipient"],
            "type": row["type"],
            "timestamp": row["server_ts"],
            "payload": json.loads(row["payload_json"]),
        })
    return msgs


def get_history(identity, peer, before_id=None, limit=50):
    db = _connect()
    db.row_factory = sqlite3.Row
    if before_id:
        rows = db.execute("""
            SELECT * FROM messages
            WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
              AND server_ts < (SELECT server_ts FROM messages WHERE id = ?)
            ORDER BY server_ts DESC LIMIT ?
        """, (identity, peer, peer, identity, before_id, limit)).fetchall()
    else:
        rows = db.execute("""
            SELECT * FROM messages
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY server_ts DESC LIMIT ?
        """, (identity, peer, peer, identity, limit)).fetchall()
    db.close()
    return [{
        "id": r["id"], "session_id": r["session_id"],
        "from": r["sender"], "to": r["recipient"],
        "type": r["type"], "timestamp": r["server_ts"],
        "payload": json.loads(r["payload_json"]),
    } for r in reversed(rows)]


def cleanup_old_messages():
    cutoff = _now() - MESSAGE_RETENTION_DAYS * 86400
    db = _connect()
    deleted = db.execute("DELETE FROM messages WHERE server_ts < ?", (cutoff,)).rowcount
    db.commit()
    db.close()
    return deleted


async def push_to_identity(identity, msg):
    ws = connected_clients.get(identity)
    if ws is None:
        return False
    try:
        await ws.send(json.dumps({
            "type": "message",
            "msg": msg,
        }, ensure_ascii=False))
        return True
    except Exception:
        # 仅当条目仍指向该连接时才移除 (防止误删同身份新连接)
        if connected_clients.get(identity) is ws:
            connected_clients.pop(identity, None)
    return False


async def handler(websocket, path=None):
    identity = None
    try:
        async for raw in websocket:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send(json.dumps(
                    {"type": "error", "code": 400, "message": "invalid json"}))
                continue
            # R4: 顶层必须是对象 —— 数组/字符串帧此前会令 .get 抛异常
            # 未捕获 → websockets 以 1011 断连而非回错误帧。
            if not isinstance(data, dict):
                await websocket.send(json.dumps(
                    {"type": "error", "code": 400, "message": "invalid frame"}))
                continue

            msg_type = data.get("type", "")

            if msg_type == "auth":
                # R2 加固: 一条连接只允许认证一次。认证后重放 auth 换绑
                # identity 会在 connected_clients 残留指向同一 socket 的旧条目,
                # 构成会话劫持/消息串号面。
                if identity is not None:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 409, "message": "already authenticated"}))
                    await websocket.close()
                    return
                token = data.get("token", "")
                ident = data.get("identity", "")
                if not hmac.compare_digest(token, AUTH_TOKEN):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 401, "message": "invalid token"}))
                    await websocket.close()
                    return
                if not ident:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 400, "message": "missing identity"}))
                    # R4: 与其他错误分支一致, 回错误帧后关闭连接
                    await websocket.close()
                    return
                # 服务端身份名校验 (审计 H4): 拒绝路径穿越/非法身份名。
                if not valid_identity(ident):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 400, "message": "invalid identity"}))
                    await websocket.close()
                    return
                identity = ident
                connected_clients[identity] = websocket
                await websocket.send(json.dumps(
                    {"type": "auth_ok", "identity": identity}))

            elif msg_type == "send":
                if not identity:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 401, "message": "not authenticated"}))
                    continue
                if not check_rate_limit(identity):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 429, "message": "rate limited"}))
                    continue

                msg = data.get("msg", {})
                # 安全修复 #1: 强制发送者身份为已认证身份, 防止伪造他人身份
                msg["from"] = identity
                if not msg.get("id") or not msg.get("to"):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 400, "message": "invalid message"}))
                    continue

                if not store_message(msg):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 500, "message": "message store failed"}))
                    continue
                await websocket.send(json.dumps(
                    {"type": "ack", "msg_id": msg["id"]}))

                pushed = await push_to_identity(msg["to"], msg)
                if pushed:
                    # D1 修复: 推送成功即标记已送达, 防止重连后 get_pending
                    # 重复拉取同一消息, 导致 Double Ratchet 重复解密错乱。
                    mark_delivered([msg["id"]])

            elif msg_type == "ping":
                await websocket.send(json.dumps({"type": "pong"}))

            elif msg_type == "get_pending":
                if not identity:
                    continue
                pending = fetch_pending_messages(identity, limit=500)
                try:
                    await websocket.send(json.dumps({
                        "type": "pending",
                        "messages": pending,
                    }, ensure_ascii=False))
                    msg_ids = [m["id"] for m in pending]
                    if msg_ids:
                        mark_delivered(msg_ids)
                except Exception:
                    pass

            elif msg_type == "file_upload":
                if not identity:
                    continue
                # 文件上传同样限流 (审计 M5): 防认证客户端循环上传写满磁盘。
                if not check_rate_limit(identity):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 429, "message": "rate limited"}))
                    continue
                file_data_b64 = data.get("file_data", "")
                if not file_data_b64:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 400, "message": "missing file_data"}))
                    continue
                if len(file_data_b64) > 50 * 1024 * 1024:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 413, "message": "file too large"}))
                    continue
                # R2 加固: 解码后再校验一次实际大小。WS 路径无分块, 单条消息
                # 即整个文件, base64 上限 + 解码上限共同构成 ~37.5MB 硬上限
                # (与 REST 分块路径的 MAX_FILE_SIZE=2GB 分级一致)。
                try:
                    file_blob = base64.b64decode(file_data_b64)
                except Exception:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 400, "message": "invalid base64"}))
                    continue
                if len(file_blob) > 37 * 1024 * 1024:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 413, "message": "file too large"}))
                    continue
                token = secrets.token_hex(16)
                file_path = os.path.join(FILE_DIR, token)
                with open(file_path, "wb") as f:
                    f.write(file_blob)
                # V5/#7: 记录上传者身份与预期接收方 (接收方由客户端在发送文件时提供)
                db = _connect()
                record_file_upload(db, token, identity, data.get("recipient", ""))
                db.close()
                await websocket.send(json.dumps({
                    "type": "file_upload_ack",
                    "token": token,
                }))

            elif msg_type == "file_download":
                if not identity:
                    continue
                # 文件下载同样限流 (审计 M5)。
                if not check_rate_limit(identity):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 429, "message": "rate limited"}))
                    continue
                token = data.get("token", "")
                file_path = _resolve_file_path(token)
                if file_path is None or not os.path.exists(file_path):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 404, "message": "file not found"}))
                    continue
                # V5/#7: 授权 = 上传者本人 或 预期接收方
                db = _connect()
                db.row_factory = sqlite3.Row
                allowed = can_download_file(db, token, identity)
                db.close()
                if not allowed:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 403, "message": "not authorized to download this file"}))
                    continue
                with open(file_path, "rb") as f:
                    file_data_b64 = base64.b64encode(f.read()).decode("ascii")
                await websocket.send(json.dumps({
                    "type": "file_download_resp",
                    "file_data": file_data_b64,
                    "token": token,
                }))                # 阅后即焚: 接收方已取到密文, 立即删除服务器文件, 不留存
                try:
                    os.remove(file_path)
                    log.info("[file] deleted after download: " + token)
                except OSError:
                    pass

            else:
                await websocket.send(json.dumps(
                    {"type": "error", "code": 400, "message": f"unknown type: {msg_type}"}))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if identity:
            # MAJOR-8 修复: 仅当当前条目仍是本连接时才移除,
            # 防止旧连接断开误删同身份的新连接条目 (实时推送静默失效)
            if connected_clients.get(identity) is websocket:
                connected_clients.pop(identity, None)


async def cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            deleted = cleanup_old_messages()
            if deleted:
                log.info(f"[cleanup] deleted {deleted} old messages")
        except Exception as e:
            log.info(f"[cleanup] error: {e}")
        try:
            # E2 修复: 正式文件保留 30 天 (与消息保留期一致), 仅回收 .part
            # 临时文件 (30 分钟)。cleanup_loop 误删正式文件会导致上传后
            # 稍晚下载即 404。
            file_cutoff = _now() - 30 * 86400
            part_cutoff = _now() - 1800
            count = 0
            for fname in os.listdir(FILE_DIR):
                fpath = os.path.join(FILE_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                mtime = os.path.getmtime(fpath)
                if fname.endswith(".part"):
                    if mtime < part_cutoff:
                        os.remove(fpath)
                        count += 1
                elif mtime < file_cutoff:
                    os.remove(fpath)
                    count += 1
            if count:
                log.info(f"[cleanup] deleted {count} old files")
        except Exception as e:
            log.info(f"[cleanup] file error: {e}")


async def main():
    init_message_db()
    log.info(f"zhchat WebSocket Server starting...")
    log.info(f"  DB: {DB_PATH}")
    log.info("  Auth Token: *** (已隐藏)")
    log.info(f"  Retention: {MESSAGE_RETENTION_DAYS} days")
    log.info(f"  Rate limit: {RATE_LIMIT_PER_MINUTE}/min")
    log.info(f"  Listening on {HOST}:{PORT}")

    async with websockets.serve(handler, HOST, PORT,
                                 ping_interval=30, ping_timeout=60,
                                 max_size=100 * 1024 * 1024):
        await cleanup_loop()


if __name__ == "__main__":
    import sys
    if sys.version_info < (3, 7):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    else:
        asyncio.run(main())
