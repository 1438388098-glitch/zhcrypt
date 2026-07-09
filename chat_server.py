"""
zhchat WebSocket Server v1.0
=============================
独立的 asyncio WebSocket 消息中继服务器
端口 5003, 与 Flask prekey 服务器共享 SQLite (WAL 模式)

部署: python chat_server.py  (通过 systemd zhchat-ws)
"""
import os
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
except ImportError:
    sys.exit("websockets 未安装: pip install websockets")

DB_PATH = os.environ.get("ZHPREKEY_DB",
                         os.path.join(os.path.dirname(__file__), "zhprekey.db"))
AUTH_TOKEN = os.environ.get("ZHPREKEY_TOKEN", "")
if not AUTH_TOKEN:
    AUTH_TOKEN = os.environ.get("ZHCHAT_TOKEN", "")
    if not AUTH_TOKEN:
        print("WARNING: ZHPREKEY_TOKEN 未设置, 使用不安全默认值")
        AUTH_TOKEN = "dev-token-change-me"

PORT = int(os.environ.get("ZHCHAT_WS_PORT", "5003"))
HOST = os.environ.get("ZHCHAT_WS_HOST", "0.0.0.0")
MESSAGE_RETENTION_DAYS = int(os.environ.get("ZHCHAT_RETENTION_DAYS", "30"))
RATE_LIMIT_PER_MINUTE = int(os.environ.get("ZHCHAT_RATE_LIMIT", "30"))
FILE_DIR = os.path.join(os.path.dirname(DB_PATH), "files")
os.makedirs(FILE_DIR, exist_ok=True)

connected_clients = {}
rate_limit_buckets = {}


def init_message_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
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
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_recipient
        ON messages(recipient, delivered_at, server_ts)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_session
        ON messages(session_id, server_ts)
    """)
    db.commit()
    db.close()


def _now():
    return time.time()


def check_rate_limit(identity):
    now = _now()
    bucket = rate_limit_buckets.get(identity, [])
    bucket = [t for t in bucket if now - t < 60]
    rate_limit_buckets[identity] = bucket
    if len(bucket) >= RATE_LIMIT_PER_MINUTE:
        return False
    bucket.append(now)
    return True


def store_message(msg_data):
    try:
        db = sqlite3.connect(DB_PATH)
        db.execute("PRAGMA journal_mode=WAL")
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
        print(f"[chat_server] store_message failed: {e}", file=sys.stderr)
        return False


def mark_delivered(msg_ids):
    if not msg_ids:
        return
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    now = _now()
    db.executemany(
        "UPDATE messages SET delivered_at = ? WHERE id = ?",
        [(now, mid) for mid in msg_ids],
    )
    db.commit()
    db.close()


def get_pending_messages(identity, limit=50):
    db = sqlite3.connect(DB_PATH)
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
    db = sqlite3.connect(DB_PATH)
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
    db = sqlite3.connect(DB_PATH)
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
    db = sqlite3.connect(DB_PATH)
    deleted = db.execute("DELETE FROM messages WHERE server_ts < ?", (cutoff,)).rowcount
    db.commit()
    db.close()
    return deleted


async def push_to_identity(identity, msg):
    if identity in connected_clients:
        ws = connected_clients[identity]
        try:
            await ws.send(json.dumps({
                "type": "message",
                "msg": msg,
            }, ensure_ascii=False))
            return True
        except Exception:
            connected_clients.pop(identity, None)
    return False


async def handler(websocket, path):
    identity = None
    try:
        async for raw in websocket:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send(json.dumps(
                    {"type": "error", "code": 400, "message": "invalid json"}))
                continue

            msg_type = data.get("type", "")

            if msg_type == "auth":
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
                if not pushed:
                    pass

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
                file_data_b64 = data.get("file_data", "")
                if not file_data_b64:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 400, "message": "missing file_data"}))
                    continue
                if len(file_data_b64) > 50 * 1024 * 1024:
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 413, "message": "file too large"}))
                    continue
                token = secrets.token_hex(16)
                file_path = os.path.join(FILE_DIR, token)
                with open(file_path, "wb") as f:
                    f.write(base64.b64decode(file_data_b64))
                await websocket.send(json.dumps({
                    "type": "file_upload_ack",
                    "token": token,
                }))

            elif msg_type == "file_download":
                if not identity:
                    continue
                token = data.get("token", "")
                file_path = os.path.join(FILE_DIR, token)
                if not os.path.exists(file_path):
                    await websocket.send(json.dumps(
                        {"type": "error", "code": 404, "message": "file not found"}))
                    continue
                with open(file_path, "rb") as f:
                    file_data_b64 = base64.b64encode(f.read()).decode("ascii")
                await websocket.send(json.dumps({
                    "type": "file_download_resp",
                    "file_data": file_data_b64,
                    "token": token,
                }))

            else:
                await websocket.send(json.dumps(
                    {"type": "error", "code": 400, "message": f"unknown type: {msg_type}"}))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if identity:
            connected_clients.pop(identity, None)


async def cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            deleted = cleanup_old_messages()
            if deleted:
                print(f"[cleanup] deleted {deleted} old messages")
        except Exception as e:
            print(f"[cleanup] error: {e}")
        try:
            cutoff = _now() - 1800
            count = 0
            for fname in os.listdir(FILE_DIR):
                fpath = os.path.join(FILE_DIR, fname)
                if os.path.isfile(fpath) and os.path.getmtime(fpath) < cutoff:
                    os.remove(fpath)
                    count += 1
            if count:
                print(f"[cleanup] deleted {count} old files")
        except Exception as e:
            print(f"[cleanup] file error: {e}")


async def main():
    init_message_db()
    print(f"zhchat WebSocket Server starting...")
    print(f"  DB: {DB_PATH}")
    print(f"  Auth Token: {AUTH_TOKEN[:8]}...")
    print(f"  Retention: {MESSAGE_RETENTION_DAYS} days")
    print(f"  Rate limit: {RATE_LIMIT_PER_MINUTE}/min")
    print(f"  Listening on {HOST}:{PORT}")

    async with websockets.serve(handler, HOST, PORT,
                                 ping_interval=30, ping_timeout=10,
                                 max_size=512 * 1024):
        await cleanup_loop()


if __name__ == "__main__":
    import sys
    if sys.version_info < (3, 7):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    else:
        asyncio.run(main())
