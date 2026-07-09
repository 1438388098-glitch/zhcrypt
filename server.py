"""
zhcrypt Prekey Server v1.0
===========================
部署到阿里云 ECS ([REDACTED_IP]), 通过宝塔 Nginx 反向代理

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

app = Flask(__name__)

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
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


app.teardown_appcontext(close_db)


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
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
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_prekeys_identity
        ON prekeys(identity, consumed, created_at)
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS identities (
            identity TEXT PRIMARY KEY,
            identity_key_pub TEXT NOT NULL,
            signed_prekey_pub TEXT NOT NULL,
            signed_prekey_sig TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        )
    """)
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
         fingerprint, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?,
                COALESCE((SELECT first_seen FROM identities WHERE identity=?), ?),
                ?)
    """, (
        identity, data["identity_key_pub"], data["signed_prekey_pub"],
        data["signature"], data["fingerprint"],
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
        "one_time_prekey": one_time_key,
        "has_more_otp": db.execute("""
            SELECT COUNT(*) as cnt FROM prekeys
            WHERE identity = ? AND key_type = 'one_time' AND consumed = 0
        """, (identity,)).fetchone()["cnt"] > 0,
    })


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


def cleanup_expired():
    """清理过期 prekeys (可设置定时任务)"""
    db = sqlite3.connect(DB_PATH)
    cutoff = _now() - PREKEY_EXPIRE_DAYS * 86400
    db.execute("DELETE FROM prekeys WHERE created_at < ? AND consumed = 0",
               (cutoff,))
    db.commit()
    db.close()


if __name__ == "__main__":
    init_db()
    print(f"zhcrypt Prekey Server starting...")
    print(f"  DB: {DB_PATH}")
    print(f"  Auth Token: {AUTH_TOKEN[:8]}...")
    print(f"  Prekey Expire: {PREKEY_EXPIRE_DAYS} days")
    print(f"  Listening on 0.0.0.0:5000")
    print(f"  (建议通过宝塔 Nginx 反代)")
    app.run(host="0.0.0.0", port=5000, debug=False)
else:
    init_db()
