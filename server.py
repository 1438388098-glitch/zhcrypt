"""
zhcrypt Prekey Server v1.0
===========================
部署到阿里云 ECS, 通过宝塔 Nginx 反向代理

Flask + SQLite, 提供 X3DH 协议的 prekey 存储与分发

API:
  POST   /v1/prekey/<identity>       上传 prekey bundle
  GET    /v1/prekey/<identity>       获取并消耗一个 one-time prekey
  POST   /v1/prekey/batch/<identity> 批量上传 one-time prekeys
  GET    /v1/health                  健康检查
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import hmac
import secrets
from functools import wraps

try:
    from flask import Flask, request, jsonify, g
except ImportError:
    sys.exit("Flask 未安装: pip install flask")

import logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("zhcrypt")

from schema import (
    PREKEYS_TABLE_SQL,
    IDENTITIES_TABLE_SQL,
    MESSAGES_TABLE_SQL,
    MESSAGES_IDX_RECIPIENT_SQL,
    MESSAGES_IDX_SESSION_SQL,
    MESSAGES_IDX_SERVER_TS_SQL,
    add_column,
)

app = Flask(__name__)

# O2 (架构优化): 请求体硬上限 16MB, 防止恶意大包打挂 worker
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


@app.errorhandler(413)
def _request_too_large(e):
    return jsonify({"error": "payload too large"}), 413


@app.before_request
def _enforce_max_content_length():
    # O2 (架构优化): 全局在解析请求体前拦截超大 body, 防止 worker 被大包打爆。
    # 必须在 request.get_json 之前拦截, 否则大包已被读入内存后才轮到视图逻辑。
    cl = request.content_length
    if cl is not None and cl > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "payload too large"}), 413


# ============================================================
# 配置 (可通过环境变量覆盖)
# ============================================================
DB_PATH = os.environ.get("ZHPREKEY_DB",
                         os.path.join(os.path.dirname(__file__), "zhprekey.db"))
AUTH_TOKEN = os.environ.get("ZHPREKEY_TOKEN")
if not AUTH_TOKEN:
    raise RuntimeError(
        "ZHPREKEY_TOKEN 环境变量未设置\n"
        "export ZHPREKEY_TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(16))')\n"
        "将生成的 token 同时配置到客户端: zhcrypt set-server <url> --token <token>"
    )
MAX_UPLOAD_SIZE = 500 * 1024
MAX_ONE_TIME_PREKEYS = 200
PREKEY_EXPIRE_DAYS = int(os.environ.get("ZHPREKEY_EXPIRE_DAYS", "7"))
RATE_LIMIT = 60


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        # O1-B (架构优化): 与 chat_server 统一为 WAL; busy_timeout 让并发写者
        # 等待而非抛 database is locked (gunicorn 多 worker + WS 双写同库场景)。
        # 注: 此前为排查 signing_public_key 返回 null 临时改 DELETE, 但 null 真根因是
        # sqlite3.Row.__contains__ 语义坑, 与 WAL 无关, 故回 WAL 更合理。
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA busy_timeout=5000")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


app.teardown_appcontext(close_db)


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(PREKEYS_TABLE_SQL)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_prekeys_identity
        ON prekeys(identity, consumed, created_at)
    """)
    db.execute(IDENTITIES_TABLE_SQL)
    # 兼容已存在的库: 补齐 signing_public_key 列 (审计 #5)
    add_column(db, "identities", "signing_public_key", "TEXT")
    db.execute(MESSAGES_TABLE_SQL)
    db.execute(MESSAGES_IDX_RECIPIENT_SQL)
    db.execute(MESSAGES_IDX_SESSION_SQL)
    db.execute(MESSAGES_IDX_SERVER_TS_SQL)
    db.commit()
    db.close()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not hmac.compare_digest(token, AUTH_TOKEN):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def _now():
    return time.time()


def _hash_key(identity, key_data):
    return hashlib.sha256(f"{identity}:{key_data}".encode()).hexdigest()[:16]





# ============================================================
# API 端点
# ============================================================

@app.route("/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "time": _now(),
        "version": "1.0.0",
        "server": "zhcrypt-prekey-server",
    })


@app.route("/v1/prekey/<identity>", methods=["POST"])
@require_auth
def upload_prekey(identity):
    """
    上传 prekey bundle:
    {
        "identity_key_pub": "base64",
        "signed_prekey_pub": "base64",
        "signed_prekey_priv": "base64(加密)",
        "signature": "base64",
        "one_time_prekeys": ["base64", ...],
        "fingerprint": "hex"
    }
    同时上传 signed prekey (长期临时密钥) + 一批 one-time prekeys
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400

    if "one_time_prekeys" in data and isinstance(data["one_time_prekeys"], list):
        if len(data["one_time_prekeys"]) > MAX_ONE_TIME_PREKEYS:
            return jsonify({"error": f"max {MAX_ONE_TIME_PREKEYS} prekeys"}), 413

    required = ["identity_key_pub", "signed_prekey_pub", "signature", "fingerprint"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"missing field: {field}"}), 400

    db = get_db()

    db.execute("""
        INSERT OR REPLACE INTO identities
        (identity, identity_key_pub, signed_prekey_pub, signed_prekey_sig,
         signing_public_key, fingerprint, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?,
                COALESCE((SELECT first_seen FROM identities WHERE identity=?), ?),
                ?)
    """, (
        identity, data["identity_key_pub"], data["signed_prekey_pub"],
        data["signature"], data.get("signing_public_key", ""),
        data["fingerprint"],
        identity, _now(), _now()
    ))

    if "signed_prekey_priv" in data:
        db.execute("""
            INSERT INTO prekeys (identity, key_type, prekey_data, fingerprint, created_at)
            VALUES (?, 'signed', ?, ?, ?)
        """, (identity, data["signed_prekey_priv"], data["fingerprint"], _now()))

    one_time_count = 0
    if "one_time_prekeys" in data and isinstance(data["one_time_prekeys"], list):
        for otpk in data["one_time_prekeys"]:
            db.execute("""
                INSERT INTO prekeys (identity, key_type, prekey_data, fingerprint, created_at)
                VALUES (?, 'one_time', ?, ?, ?)
            """, (identity, otpk, data["fingerprint"], _now()))
            one_time_count += 1

    db.commit()

    return jsonify({
        "status": "ok",
        "identity": identity,
        "fingerprint": data["fingerprint"],
        "signed_prekey": "stored",
        "one_time_stored": one_time_count,
    })


@app.route("/v1/prekey/<identity>", methods=["GET"])
@require_auth
def fetch_prekey(identity):
    """
    获取该身份的 prekey bundle:
    1. 返回 signed prekey (长期临时密钥公钥 + 签名)
    2. 消耗一个 one-time prekey (返回后立即标记已用)
    """
    # V7: prekey 获取速率限制
    if not _check_prekey_rate_limit(identity):
        return jsonify({"error": "prekey rate limited"}), 429

    db = get_db()
    db.execute("BEGIN IMMEDIATE")

    id_row = db.execute("""
        SELECT * FROM identities WHERE identity = ?
    """, (identity,)).fetchone()

    if not id_row:
        db.execute("ROLLBACK")
        return jsonify({"error": "identity not found"}), 404

    otp_row = db.execute("""
        SELECT * FROM prekeys
        WHERE identity = ? AND key_type = 'one_time' AND consumed = 0
        ORDER BY created_at ASC LIMIT 1
    """, (identity,)).fetchone()

    if otp_row:
        db.execute("""
            UPDATE prekeys SET consumed = 1, consumed_at = ?
            WHERE id = ?
        """, (_now(), otp_row["id"]))
        db.commit()
        one_time_key = otp_row["prekey_data"]
    else:
        one_time_key = None

    return jsonify({
        "status": "ok",
        "identity": identity,
        "fingerprint": id_row["fingerprint"],
        "identity_key_pub": id_row["identity_key_pub"],
        "signed_prekey_pub": id_row["signed_prekey_pub"],
        "signed_prekey_sig": id_row["signed_prekey_sig"],
        "signing_public_key": id_row["signing_public_key"],
        "one_time_prekey": one_time_key,
        "has_more_otp": db.execute("""
            SELECT COUNT(*) as cnt FROM prekeys
            WHERE identity = ? AND key_type = 'one_time' AND consumed = 0
        """, (identity,)).fetchone()["cnt"] > 0,
    })


@app.route("/v1/prekey/meta/<identity>", methods=["GET"])
@require_auth
def fetch_prekey_meta(identity):
    """只读端点: 返回该身份用于 X3DH 的静态公钥 (IK/SPK/signing), 不消耗 one-time prekey。

    客户端在连接阶段调用本端点以省去手动导出/导入公钥束, 同时避免每次
    连接都消耗一个 OTP (普通 GET /v1/prekey/<id> 会消耗)。真实握手仍走
    原 GET 以取得并消耗一个 OTP。
    """
    # V7: 只读端点也做速率限制, 防止枚举/刷接口
    if not _check_prekey_rate_limit(identity):
        return jsonify({"error": "prekey rate limited"}), 429

    db = get_db()
    id_row = db.execute("""
        SELECT identity_key_pub, signed_prekey_pub, signed_prekey_sig,
               signing_public_key, fingerprint
        FROM identities WHERE identity = ?
    """, (identity,)).fetchone()
    if not id_row:
        return jsonify({"error": "identity not found"}), 404
    _ret = {
        "status": "ok",
        "identity": identity,
        "fingerprint": id_row["fingerprint"],
        "identity_key_pub": id_row["identity_key_pub"],
        "signed_prekey_pub": id_row["signed_prekey_pub"],
        "signed_prekey_sig": id_row["signed_prekey_sig"],
        "signing_public_key": id_row["signing_public_key"],
    }
    return jsonify(_ret)


@app.route("/v1/prekey/batch/<identity>", methods=["POST"])
@require_auth
def upload_batch(identity):
    """批量上传 one-time prekeys"""
    data = request.get_json(force=True)
    if not data or "one_time_prekeys" not in data:
        return jsonify({"error": "missing one_time_prekeys"}), 400

    db = get_db()
    count = 0
    for otpk in data["one_time_prekeys"]:
        db.execute("""
            INSERT INTO prekeys (identity, key_type, prekey_data, fingerprint, created_at)
            VALUES (?, 'one_time', ?, ?, ?)
        """, (identity, otpk, data.get("fingerprint", ""), _now()))
        count += 1

    db.execute("""
        UPDATE identities SET last_seen = ?
        WHERE identity = ?
    """, (_now(), identity))
    db.commit()

    return jsonify({
        "status": "ok",
        "stored": count,
    })


@app.route("/v1/prekey/<identity>", methods=["DELETE"])
@require_auth
def clear_prekeys(identity):
    """清理某个身份的所有 prekey"""
    db = get_db()
    db.execute("DELETE FROM prekeys WHERE identity = ?", (identity,))
    db.execute("DELETE FROM identities WHERE identity = ?", (identity,))
    db.commit()
    return jsonify({"status": "ok", "deleted": True})


@app.route("/v1/stats", methods=["GET"])
@require_auth
def stats():
    db = get_db()
    id_count = db.execute("SELECT COUNT(*) as cnt FROM identities").fetchone()["cnt"]
    pk_count = db.execute("SELECT COUNT(*) as cnt FROM prekeys").fetchone()["cnt"]
    expired = db.execute("""
        SELECT COUNT(*) as cnt FROM prekeys
        WHERE created_at < ?
    """, (_now() - PREKEY_EXPIRE_DAYS * 86400,)).fetchone()["cnt"]
    return jsonify({
        "identities": id_count,
        "prekeys_total": pk_count,
        "expired_prekeys": expired,
        "expire_days": PREKEY_EXPIRE_DAYS,
    })


@app.route("/v1/prekey/remaining/<identity>", methods=["GET"])
@require_auth
def remaining_prekeys(identity):
    """查看某个身份剩余的 one-time prekey 数量"""
    db = get_db()
    count = db.execute("""
        SELECT COUNT(*) as cnt FROM prekeys
        WHERE identity = ? AND key_type = 'one_time' AND consumed = 0
    """, (identity,)).fetchone()["cnt"]
    return jsonify({
        "identity": identity,
        "remaining": count,
        "recommended_upload": count < 10,
    })


MESSAGE_RATE_LIMIT = 30
MESSAGE_RETENTION_DAYS = 30

_message_rate_buckets = {}


def _check_message_rate(identity):
    now = _now()
    bucket = _message_rate_buckets.get(identity, [])
    bucket = [t for t in bucket if now - t < 60]
    _message_rate_buckets[identity] = bucket
    if len(bucket) >= MESSAGE_RATE_LIMIT:
        return False
    bucket.append(now)
    return True


_PREKEY_RATE_BUCKETS = {}


def _check_prekey_rate_limit(identity):
    """对 prekey 获取做速率限制 (审计 #10).

    以 identity 为桶 key (与服务器现有 _check_message_rate 约定一致).
    注: 服务端位于 Nginx 反代之后, request.remote_addr 为 Nginx IP,
    故不采用 _client_ip() 以避免所有请求被误判为同一来源.
    """
    now = _now()
    bucket = _PREKEY_RATE_BUCKETS.get(identity, [])
    bucket = [t for t in bucket if now - t < 60]
    _PREKEY_RATE_BUCKETS[identity] = bucket
    if len(bucket) >= RATE_LIMIT:
        return False
    bucket.append(now)
    return True


@app.route("/v1/messages/send", methods=["POST"])
@require_auth
def message_send():
    data = request.get_json(force=True)
    if not data or not data.get("id") or not data.get("to"):
        return jsonify({"error": "missing id or recipient"}), 400

    sender = data.get("from", "unknown")
    if not _check_message_rate(sender):
        return jsonify({"error": "rate limited"}), 429

    db = get_db()
    db.execute("""
        INSERT OR IGNORE INTO messages
        (id, session_id, sender, recipient, type, payload_json, server_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data["id"],
        data.get("session_id", ""),
        sender,
        data["to"],
        data.get("type", "message"),
        json.dumps(data.get("payload", {}), ensure_ascii=False),
        _now(),
    ))
    db.commit()
    return jsonify({"status": "stored", "msg_id": data["id"]})


@app.route("/v1/messages/pending", methods=["GET"])
@require_auth
def message_pending():
    identity = request.args.get("identity", "")
    limit = min(int(request.args.get("limit", "50")), 100)
    if not identity:
        return jsonify({"error": "identity required"}), 400

    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    rows = db.execute("""
        SELECT * FROM messages
        WHERE recipient = ? AND delivered_at IS NULL
        ORDER BY server_ts ASC LIMIT ?
    """, (identity, limit)).fetchall()

    msgs = []
    msg_ids = []
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
        msg_ids.append(row["id"])

    if msg_ids:
        db.executemany(
            "UPDATE messages SET delivered_at = ? WHERE id = ?",
            [(_now(), mid) for mid in msg_ids],
        )
    db.commit()
    return jsonify({"messages": msgs, "count": len(msgs)})


@app.route("/v1/messages/ack", methods=["POST"])
@require_auth
def message_ack():
    data = request.get_json(force=True)
    msg_ids = data.get("msg_ids", [])
    if not msg_ids:
        return jsonify({"error": "msg_ids required"}), 400

    db = get_db()
    db.executemany(
        "UPDATE messages SET delivery_ack_at = ? WHERE id = ?",
        [(_now(), mid) for mid in msg_ids],
    )
    db.commit()
    return jsonify({"acked": len(msg_ids)})


@app.route("/v1/messages/history", methods=["GET"])
@require_auth
def message_history():
    identity = request.args.get("identity", "")
    peer = request.args.get("with", "")
    before_id = request.args.get("before", None)
    limit = min(int(request.args.get("limit", "50")), 200)

    if not identity or not peer:
        return jsonify({"error": "identity and with required"}), 400

    db = get_db()
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

    msgs = []
    for row in reversed(rows):
        msgs.append({
            "id": row["id"],
            "session_id": row["session_id"],
            "from": row["sender"],
            "to": row["recipient"],
            "type": row["type"],
            "timestamp": row["server_ts"],
            "payload": json.loads(row["payload_json"]),
        })
    return jsonify({"messages": msgs, "count": len(msgs)})


@app.route("/v1/messages/prune", methods=["DELETE"])
@require_auth
def message_prune():
    days = int(request.args.get("older_than_days", str(MESSAGE_RETENTION_DAYS)))
    cutoff = _now() - days * 86400
    db = get_db()
    deleted = db.execute(
        "DELETE FROM messages WHERE server_ts < ?", (cutoff,)
    ).rowcount
    db.commit()
    return jsonify({"deleted": deleted, "older_than_days": days})


@app.route("/v1/identities", methods=["GET"])
@require_auth
def list_identities():
    db = get_db()
    rows = db.execute(
        "SELECT identity, fingerprint, last_seen FROM identities ORDER BY last_seen DESC"
    ).fetchall()
    idents = [{
        "identity": r["identity"],
        "fingerprint": r["fingerprint"],
        "last_seen": r["last_seen"],
    } for r in rows]
    return jsonify({"identities": idents, "count": len(idents)})


def cleanup_expired():
    """清理过期未消耗 prekeys (可设置定时任务)。返回删除条数。"""
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA busy_timeout=5000")
    cutoff = _now() - PREKEY_EXPIRE_DAYS * 86400
    cur = db.execute("DELETE FROM prekeys WHERE created_at < ? AND consumed = 0",
                     (cutoff,))
    deleted = cur.rowcount
    db.commit()
    db.close()
    return deleted


@app.route("/v1/admin/cleanup_expired", methods=["POST"])
@require_auth
def admin_cleanup_expired():
    """O6 (架构优化): 周期性清理过期未消耗 prekeys。
    应由 systemd timer / cron 周期调用, 避免 prekeys 表无限堆积。"""
    deleted = cleanup_expired()
    return jsonify({"deleted": deleted, "prekey_expire_days": PREKEY_EXPIRE_DAYS})


if __name__ == "__main__":
    init_db()
    log.info(f"zhcrypt Prekey Server starting...")
    log.info(f"  DB: {DB_PATH}")
    log.info(f"  Auth Token: {AUTH_TOKEN[:8]}...")
    log.info(f"  Prekey Expire: {PREKEY_EXPIRE_DAYS} days")
    log.info(f"  Listening on 0.0.0.0:5000")
    log.info(f"  (建议通过宝塔 Nginx 反代)")
    app.run(host="0.0.0.0", port=5000, debug=False)
else:
    init_db()
