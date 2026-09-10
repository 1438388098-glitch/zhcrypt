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
import re
import json
import time
import sqlite3
import hashlib
import hmac
import secrets
import threading
from functools import wraps

try:
    from flask import Flask, request, jsonify, g, Response, send_file
except ImportError:
    sys.exit("Flask 未安装: pip install flask")

import logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("zhcrypt")

from schema import (
    PREKEYS_TABLE_SQL,
    PREKEYS_UNIQ_DEDUPE_SQL,
    PREKEYS_UNIQ_INDEX_SQL,
    IDENTITIES_TABLE_SQL,
    MESSAGES_TABLE_SQL,
    MESSAGES_IDX_RECIPIENT_SQL,
    MESSAGES_IDX_SESSION_SQL,
    MESSAGES_IDX_SERVER_TS_SQL,
    FILES_TABLE_SQL,
    add_column,
    valid_identity,
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

# ============================================================
# 文件传输 (v1.1: 分块上传 / Range 下载 / 断点续传)
# ============================================================
# 与 chat_server.py 共用同一 FILE_DIR (DB_PATH 同目录下 files/)
FILE_DIR = os.environ.get(
    "ZHCHAT_FILE_DIR",
    os.path.join(os.path.dirname(DB_PATH), "files"),
)
os.makedirs(FILE_DIR, exist_ok=True)

UPLOAD_CONCURRENCY_PER_IDENTITY = 2
UPLOAD_SESSION_TIMEOUT = 30 * 60  # 30min 未活动的上传会话回收
# 单文件总大小上限 (防磁盘耗尽 DoS, C2 修复)
MAX_FILE_SIZE = int(os.environ.get("ZHCHAT_MAX_FILE_SIZE", str(2 * 1024 * 1024 * 1024)))
# 上传块大小上限 (与客户端 1MB 块对齐, 防止超大块整读内存)
MAX_UPLOAD_CHUNK = 4 * 1024 * 1024

_TOKEN_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")
# 上传会话跟踪: {upload_token: {"identity": str, "path": str, "mtime": float,
#                                "total": int, "recipient": str}}
_upload_sessions = {}
# 每 token 互斥锁 (进程内, 防分块竞态双写, C3 修复)
_upload_locks = {}
# R4 修复: 守护锁必须是模块级单例 —— 原实现 `with threading.Lock()` 每次调用
# 都新建匿名锁立即获取, 恒不阻塞, check-then-insert 的竞态防护形同虚设。
_UPLOAD_LOCKS_GUARD = threading.Lock()


def _token_lock(upload_token):
    """获取 token 对应的互斥锁 (进程内)。"""
    with _UPLOAD_LOCKS_GUARD:
        if upload_token not in _upload_locks:
            _upload_locks[upload_token] = threading.Lock()
        return _upload_locks[upload_token]


def _resolve_file_path(token):
    """将下载 token 解析为文件绝对路径, 防御路径穿越 (CWE-22)。

    仅允许 32 位十六进制 token (与上传时 secrets.token_hex(16) 生成格式一致),
    且解析后的真实路径必须严格位于 FILE_DIR 内。任何含 ../ 或非法字符的
    token 都会返回 None, 从而杜绝读取 FILE_DIR 之外的任意文件。
    """
    if not isinstance(token, str) or not _TOKEN_HEX_RE.match(token):
        return None
    file_path = os.path.join(FILE_DIR, token)
    if os.path.dirname(os.path.realpath(file_path)) != os.path.realpath(FILE_DIR):
        return None
    return file_path


def _purge_stale_upload_sessions():
    """回收超时未完成的上传会话 (.part 文件 + 内存跟踪)。"""
    now = time.time()
    stale = [t for t, s in _upload_sessions.items()
             if now - s["mtime"] > UPLOAD_SESSION_TIMEOUT]
    for t in stale:
        s = _upload_sessions.pop(t, None)
        # 同步释放互斥锁, 否则长期运行下 _upload_locks 只增不减 (R1 修复)
        _upload_locks.pop(t, None)
        if s and os.path.isfile(s["path"]):
            try:
                os.remove(s["path"])
            except OSError:
                pass


def _active_uploads(identity):
    return sum(1 for s in _upload_sessions.values()
               if s["identity"] == identity)


def _record_file_upload(db, token, uploader, recipient):
    """记录文件上传元数据 (与 chat_server.record_file_upload 同构)。"""
    db.execute(
        "INSERT INTO files (token, uploader, intended_recipient, server_ts) "
        "VALUES (?, ?, ?, ?)",
        (token, uploader, recipient or "", time.time()),
    )
    db.commit()


def _can_download(db, token, identity):
    """文件下载授权: 上传者本人或预期接收方均可下载 (审计 #7)。"""
    row = db.execute(
        "SELECT uploader, intended_recipient FROM files WHERE token = ?",
        (token,),
    ).fetchone()
    if row is None:
        return False
    uploader = row["uploader"]
    recipient = row["intended_recipient"] or ""
    return identity == uploader or identity == recipient


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
    db.execute(FILES_TABLE_SQL)
    # R4: OTP 去重迁移 + 唯一索引 (防同一 one-time prekey 被消耗两次)
    db.execute(PREKEYS_UNIQ_DEDUPE_SQL)
    db.execute(PREKEYS_UNIQ_INDEX_SQL)
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
    # 服务端身份名校验 (审计 H4): 拒绝路径穿越/非法身份名, 与客户端白名单对齐。
    if not valid_identity(identity):
        return jsonify({"error": "invalid identity"}), 400

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

    # 身份所有权校验 (审计 CRITICAL-2): 同一身份的核心公钥不得被静默替换,
    # 否则任何持 token 者都能覆盖他人身份 → prekey 投毒 / MITM。
    # 仅当签名公钥或 identity 公钥相对已注册值发生变化时拒绝; 首次注册或
    # 同钥续传 (轮换 one-time prekey) 放行。显式换钥需先 DELETE 该身份。
    new_signing = data.get("signing_public_key", "") or ""
    new_idk = data.get("identity_key_pub", "") or ""
    existing = db.execute(
        "SELECT identity_key_pub, signing_public_key FROM identities WHERE identity=?",
        (identity,),
    ).fetchone()
    if existing:
        old_signing = existing["signing_public_key"] or ""
        old_idk = existing["identity_key_pub"] or ""
        key_changed = (new_signing and old_signing and new_signing != old_signing) or \
                      (new_idk and old_idk and new_idk != old_idk)
        if key_changed:
            return jsonify({"error": "身份公钥与已注册身份不一致（疑似冒充或换钥），请先删除该身份后重新注册"}), 403

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

    # 安全修复 (test_security_fixes #6): 服务端绝不存储任何私钥材料。
    # 即使客户端误传 signed_prekey_priv, 也直接忽略, 不落库。
    # R4: INSERT OR IGNORE + 唯一索引 —— 重复上传/重试不再产生重复 OTP 行,
    # 计数以实际落库为准 (total_changes 增量)。
    one_time_count = 0
    if "one_time_prekeys" in data and isinstance(data["one_time_prekeys"], list):
        before = db.total_changes
        for otpk in data["one_time_prekeys"]:
            db.execute("""
                INSERT OR IGNORE INTO prekeys (identity, key_type, prekey_data, fingerprint, created_at)
                VALUES (?, 'one_time', ?, ?, ?)
            """, (identity, otpk, data["fingerprint"], _now()))
        one_time_count = db.total_changes - before

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
    if not valid_identity(identity):
        return jsonify({"error": "invalid identity"}), 400
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
    if not valid_identity(identity):
        return jsonify({"error": "invalid identity"}), 400
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
    if not valid_identity(identity):
        return jsonify({"error": "invalid identity"}), 400
    data = request.get_json(force=True)
    if not data or "one_time_prekeys" not in data:
        return jsonify({"error": "missing one_time_prekeys"}), 400
    otpks = data["one_time_prekeys"]
    if not isinstance(otpks, list) or not otpks:
        return jsonify({"error": "one_time_prekeys must be a non-empty list"}), 400
    if len(otpks) > MAX_ONE_TIME_PREKEYS:
        return jsonify({"error": f"too many one_time_prekeys (max {MAX_ONE_TIME_PREKEYS})"}), 400

    db = get_db()
    # R4: INSERT OR IGNORE —— 重复 OTP 静默去重, stored 计实际落库数
    before = db.total_changes
    for otpk in otpks:
        db.execute("""
            INSERT OR IGNORE INTO prekeys (identity, key_type, prekey_data, fingerprint, created_at)
            VALUES (?, 'one_time', ?, ?, ?)
        """, (identity, otpk, data.get("fingerprint", ""), _now()))
    count = db.total_changes - before

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
    if not valid_identity(identity):
        return jsonify({"error": "invalid identity"}), 400
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
    if not valid_identity(identity):
        return jsonify({"error": "invalid identity"}), 400
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

# R2 加固: 是否信任反代头 X-Real-IP。默认 1 保持既有 Nginx 反代部署行为;
# 5000 端口直连暴露的部署必须设 ZHPREKEY_TRUST_PROXY=0, 否则客户端可
# 伪造 X-Real-IP 绕过限流 (该头本质是客户端可控输入)。
_TRUST_PROXY = os.environ.get("ZHPREKEY_TRUST_PROXY", "1").strip().lower() \
    not in ("0", "false", "no", "off")


def _client_ip():
    """取真实客户端 IP (兼容 Nginx 反代)。

    仅当 _TRUST_PROXY (ZHPREKEY_TRUST_PROXY!=0) 时信任 X-Real-IP —— 该头由
    Nginx `proxy_set_header X-Real-IP $remote_addr` 覆盖写入, 反代之下客户端
    无法伪造; 不回退到 X-Forwarded-For —— 其首段客户端可控, 会被伪造绕过
    限流 (审计 HIGH-3)。其余情况一律以 remote_addr 计数。
    """
    if _TRUST_PROXY:
        xri = request.headers.get("X-Real-IP", "")
        if xri:
            return xri.strip()
    return request.remote_addr or "unknown"


def _check_message_rate(key):
    now = _now()
    bucket = [t for t in _message_rate_buckets.get(key, []) if now - t < 60]
    if bucket:
        _message_rate_buckets[key] = bucket
    else:
        _message_rate_buckets.pop(key, None)  # 防键无限增长 (内存 DoS, 审计 M5)
    if len(bucket) >= MESSAGE_RATE_LIMIT:
        return False
    bucket.append(now)
    _message_rate_buckets[key] = bucket
    return True


_PREKEY_RATE_BUCKETS = {}


def _check_prekey_rate_limit(identity):
    """对 prekey 获取做速率限制 (审计 #10).

    以 identity 为桶 key (与服务器现有 _check_message_rate 约定一致).
    注: 服务端位于 Nginx 反代之后, request.remote_addr 为 Nginx IP,
    故不采用 _client_ip() 以避免所有请求被误判为同一来源.
    """
    now = _now()
    bucket = [t for t in _PREKEY_RATE_BUCKETS.get(identity, []) if now - t < 60]
    if bucket:
        _PREKEY_RATE_BUCKETS[identity] = bucket
    else:
        _PREKEY_RATE_BUCKETS.pop(identity, None)  # 防键无限增长 (内存 DoS, 审计 M5)
    if len(bucket) >= RATE_LIMIT:
        return False
    bucket.append(now)
    _PREKEY_RATE_BUCKETS[identity] = bucket
    return True


@app.route("/v1/messages/send", methods=["POST"])
@require_auth
def message_send():
    data = request.get_json(force=True)
    # R4: JSON 顶层必须是对象 —— 数组/字符串会令 .get 抛 AttributeError → 500
    if not isinstance(data, dict) or not data.get("id") or not data.get("to"):
        return jsonify({"error": "missing id or recipient"}), 400

    # 安全修复 (test_security_fixes #1-REST): 强制发送者身份字段,
    # 服务端自行决定 sender, 绝不信任客户端 "from" 字段 (防身份伪造)。
    identity = data.get("identity", "")
    if not identity:
        return jsonify({"error": "missing identity"}), 400
    # 服务端身份名校验: 发送者身份会作为 msg["from"] 中继给接收方,
    # 若为路径穿越字符串会触发接收方客户端路径拼接 (审计 H4)。
    if not valid_identity(identity):
        return jsonify({"error": "invalid identity"}), 400
    # 收件人同样过白名单: to 会作为 recipient 写库并成为对端拉取键 (R1 修复)
    if not valid_identity(data["to"]):
        return jsonify({"error": "invalid recipient"}), 400
    sender = identity

    if not _check_message_rate(_client_ip()):
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
    try:
        # R4: 非数字 limit 此前抛 ValueError → HTML 500, 现转 400
        limit = min(int(request.args.get("limit", "50")), 100)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid limit"}), 400
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
    # R4: 顶层类型校验 (数组/字符串 body 此前会 AttributeError → 500)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid body"}), 400
    msg_ids = data.get("msg_ids", [])
    if not isinstance(msg_ids, list) or not msg_ids:
        return jsonify({"error": "msg_ids required"}), 400
    if len(msg_ids) > 200:
        return jsonify({"error": "too many msg_ids (max 200)"}), 400
    if not all(isinstance(m, str) and 0 < len(m) <= 128 for m in msg_ids):
        return jsonify({"error": "invalid msg_id"}), 400

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
    try:
        limit = min(int(request.args.get("limit", "50")), 200)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid limit"}), 400

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
    try:
        days = int(request.args.get("older_than_days", str(MESSAGE_RETENTION_DAYS)))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid older_than_days"}), 400
    if days < 0:
        return jsonify({"error": "invalid older_than_days"}), 400
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


# ============================================================
# 文件传输端点 (v1.1)
# ============================================================

@app.route("/v1/files/upload", methods=["POST"])
@require_auth
def file_upload():
    """分块上传密文文件 (1MB/块, X-Upload-Token 标识会话, X-Offset 续传)。

    响应:
      201 {"token": "32hex"}            全部块上传完成 (token=X-Upload-Token)
      409 {"offset": n}                 已有部分数据, 请从 n 续传
      429 {"error": ...}                并发上传超限
    """
    identity = request.headers.get("X-Identity", "")
    upload_token = request.headers.get("X-Upload-Token", "")
    recipient = request.headers.get("X-Recipient", "")
    offset = request.headers.get("X-Offset", "")
    total = request.headers.get("X-Total-Size", "")

    if not identity:
        return jsonify({"error": "missing X-Identity"}), 400
    if not valid_identity(identity):
        return jsonify({"error": "invalid X-Identity"}), 400
    if not upload_token or not _TOKEN_HEX_RE.match(upload_token):
        return jsonify({"error": "missing/invalid X-Upload-Token"}), 400
    if not recipient:
        return jsonify({"error": "missing X-Recipient"}), 400
    try:
        offset = int(offset)
        total = int(total)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid X-Offset/X-Total-Size"}), 400
    if offset < 0 or total <= 0:
        return jsonify({"error": "invalid range"}), 400
    # C2 修复: 单文件总大小硬上限 (防磁盘耗尽 DoS)
    if total > MAX_FILE_SIZE:
        return jsonify({"error": f"file too large (max {MAX_FILE_SIZE})"}), 413

    body = request.get_data()
    if not body:
        return jsonify({"error": "empty chunk"}), 400
    if len(body) > MAX_UPLOAD_CHUNK:
        return jsonify({"error": f"chunk too large (max {MAX_UPLOAD_CHUNK})"}), 413
    if offset + len(body) > total:
        return jsonify({"error": "chunk exceeds total size"}), 400

    _purge_stale_upload_sessions()

    part_path = os.path.join(FILE_DIR, upload_token + ".part")

    # 会话存在性: 已完成的正式文件直接幂等返回
    final_path = _resolve_file_path(upload_token)
    if final_path and os.path.isfile(final_path):
        return jsonify({"token": upload_token}), 201

    # C3 修复: 同 token 分块写入全程互斥 (读-比-写原子化, 防双写竞态)
    lock = _token_lock(upload_token)
    with lock:
        # 新建会话: 并发限制 + 记录 total/recipient 指纹
        if upload_token not in _upload_sessions:
            if _active_uploads(identity) >= UPLOAD_CONCURRENCY_PER_IDENTITY:
                return jsonify({"error": "upload concurrency limit"}), 429
            _upload_sessions[upload_token] = {
                "identity": identity,
                "path": part_path,
                "mtime": time.time(),
                "total": total,
                "recipient": recipient,
            }

        session = _upload_sessions[upload_token]

        # 会话归属校验: 其他身份不得续传同一会话
        if session["identity"] != identity:
            return jsonify({"error": "upload session owned by another identity"}), 403
        # 会话指纹校验: 同 token 换文件 (total/recipient 变化) 拒绝, 防混拼
        if session["total"] != total:
            return jsonify({"error": "upload session size mismatch"}), 409
        if session["recipient"] != recipient:
            return jsonify({"error": "upload session recipient mismatch"}), 409

        # offset 对齐: 客户端首次发 0, 服务端已有数据时协商到已接收大小
        cur_size = os.path.getsize(part_path) if os.path.isfile(part_path) else 0
        if offset != cur_size:
            return jsonify({"offset": cur_size}), 409

        # 追加写入
        with open(part_path, "ab") as f:
            f.write(body)
        session["mtime"] = time.time()

        new_size = cur_size + len(body)
        if new_size < total:
            # 尚未传完: 协商续传
            return jsonify({"offset": new_size}), 409
        if new_size > total:
            _upload_sessions.pop(upload_token, None)
            _upload_locks.pop(upload_token, None)
            try:
                os.remove(part_path)
            except OSError:
                pass
            return jsonify({"error": "upload exceeds total size"}), 400

        # 全部块接收完毕: 原子落盘 + 记录元数据
        # os.replace: Windows 上目标已存在时原子覆盖; os.rename 会抛 FileExistsError (R1 修复)
        os.replace(part_path, final_path)
        _upload_sessions.pop(upload_token, None)
        _upload_locks.pop(upload_token, None)
        db = get_db()
        _record_file_upload(db, upload_token, identity, recipient)
        return jsonify({"token": upload_token}), 201


@app.route("/v1/files/download/<token>", methods=["GET"])
@require_auth
def file_download(token):
    """下载密文文件 (支持 Range 断点续传, 206 Partial Content)。

    授权 = files 表 uploader 或 intended_recipient == X-Identity。
    下载后不删除 (支持重试/续传; 由 chat_server cleanup_loop 清理过期文件)。
    """
    identity = request.headers.get("X-Identity", "")
    if not identity:
        return jsonify({"error": "missing X-Identity"}), 400
    if not valid_identity(identity):
        return jsonify({"error": "invalid X-Identity"}), 400

    file_path = _resolve_file_path(token)
    if file_path is None or not os.path.isfile(file_path):
        return jsonify({"error": "file not found"}), 404

    db = get_db()
    allowed = _can_download(db, token, identity)
    if not allowed:
        return jsonify({"error": "not authorized to download this file"}), 403

    return send_file(file_path, conditional=True)


@app.route("/v1/files/download/<token>", methods=["HEAD"])
@require_auth
def file_head(token):
    """HEAD 元信息: 200 + Content-Length=文件大小; 404 不存在; 403 未授权。"""
    identity = request.headers.get("X-Identity", "")
    if not identity:
        return jsonify({"error": "missing X-Identity"}), 400
    if not valid_identity(identity):
        return jsonify({"error": "invalid X-Identity"}), 400

    file_path = _resolve_file_path(token)
    if file_path is None or not os.path.isfile(file_path):
        return jsonify({"error": "file not found"}), 404

    db = get_db()
    allowed = _can_download(db, token, identity)
    if not allowed:
        return jsonify({"error": "not authorized to download this file"}), 403

    size = os.path.getsize(file_path)
    return Response(status=200, headers={"Content-Length": str(size)})


@app.route("/v1/messages/delivered", methods=["GET"])
@require_auth
def message_delivered():
    """批量查询消息送达时间戳 (D3: 发送方投递反馈)。

    仅返回认证身份 (identity 参数) 为收件人的消息, 防探测。
    响应: {"delivered": {"msg_id": ts 或 null}}
    """
    identity = request.args.get("identity", "")
    ids_raw = request.args.get("ids", "")
    msg_ids = [i for i in ids_raw.split(",") if i]
    if not identity:
        return jsonify({"error": "identity required"}), 400
    if not msg_ids:
        return jsonify({"error": "ids required"}), 400
    if len(msg_ids) > 200:
        return jsonify({"error": "too many ids"}), 400

    db = get_db()
    placeholders = ",".join("?" for _ in msg_ids)
    # 查询方向: 发送方 (sender=自己) 查"对方是否收到", 接收方 (recipient=自己) 亦可查
    rows = db.execute(
        f"SELECT id, delivered_at FROM messages "
        f"WHERE (sender = ? OR recipient = ?) AND id IN ({placeholders})",
        [identity, identity] + msg_ids,
    ).fetchall()
    delivered = {}
    for row in rows:
        delivered[row["id"]] = row["delivered_at"]
    # 补齐未命中 id 为 null (调用方不关心的 id 不出现)
    for mid in msg_ids:
        if mid not in delivered:
            delivered[mid] = None
    return jsonify({"delivered": delivered})


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


def _resolve_ssl_context():
    """读取 ZHPREKEY_TLS_CERT/ZHPREKEY_TLS_KEY, 两个文件都存在时返回
    (cert, key) 供 app.run(ssl_context=...) 使用, 否则返回 None (明文 HTTP)。
    R2: 兑现 docs/zhcrypt_nginx_tls.md「方案二: 原生 TLS」的文档承诺。"""
    cert = os.environ.get("ZHPREKEY_TLS_CERT", "")
    key = os.environ.get("ZHPREKEY_TLS_KEY", "")
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        return (cert, key)
    return None


if __name__ == "__main__":
    init_db()
    log.info(f"zhcrypt Prekey Server starting...")
    log.info(f"  DB: {DB_PATH}")
    log.info("  Auth Token: *** (已隐藏)")
    log.info(f"  Prekey Expire: {PREKEY_EXPIRE_DAYS} days")
    # R2: 原生 TLS (兑现 docs/zhcrypt_nginx_tls.md「方案二」承诺)。
    # 同时提供 ZHPREKEY_TLS_CERT/ZHPREKEY_TLS_KEY 环境变量即可启用,
    # 无需 Nginx; 仅建议小规模/内网部署, 生产仍推荐反代终止 TLS。
    _ssl_context = _resolve_ssl_context()
    if _ssl_context:
        log.info(f"  TLS: enabled (cert={_ssl_context[0]})")
    else:
        if os.environ.get("ZHPREKEY_TLS_CERT") or os.environ.get("ZHPREKEY_TLS_KEY"):
            log.warning("  TLS: ZHPREKEY_TLS_CERT/KEY 指向的文件不存在, 以明文 HTTP 启动!")
        else:
            log.info("  TLS: disabled (明文 HTTP; 设 ZHPREKEY_TLS_CERT/KEY 启用)")
    log.info(f"  Listening on 0.0.0.0:5000")
    log.info(f"  (建议通过宝塔 Nginx 反代, 或直连时设 ZHPREKEY_TRUST_PROXY=0)")
    app.run(host="0.0.0.0", port=5000, debug=False, ssl_context=_ssl_context)
else:
    init_db()
