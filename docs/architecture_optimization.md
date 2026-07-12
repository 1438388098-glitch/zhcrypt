# zhcrypt 架构与工程化全面优化设计文档

- **文档版本**：v1.0
- **日期**：2026-07-12
- **作者视角**：高级开发工程师（架构评审）
- **适用范围**：`zhcrypt` 端到端加密聊天系统（本地 `C:\Users\20579\zhcrypt` + 生产 `iweistoicqc5.top`）
- **目标**：在不破坏现有 X3DH / 双棘轮 / 文件 E2E 加密的前提下，消除稳定性与工程化短板
- **实施状态（2026-07-12）**：✅ **Phase 1 已完成并部署验证** — O2（请求体 16MB 上限 + 全局 `before_request` 拦截，实测 20MB 包返回 413）、O1-B（两服务统一 WAL + `busy_timeout=5000` + `_connect()` 封装）。两服务 `active`，health/meta 正常。
- **Phase 2 第一批（同日）**：✅ **O3**（拆分 `requirements-server.txt`/`requirements-client.txt`，`requirements.txt` 升级为带说明的全量聚合，已同步生产）；✅ **O6**（新增 `POST /v1/admin/cleanup_expired` 受保护端点 + `cleanup_expired()` 返回删除数 + systemd `zhprekey-cleanup.timer` 每日 03:17 触发，已 `enable` 并手动验证返回 `{"deleted":0}`）。
- **Phase 2 第二批（同日）**：✅ **O7**（删除根目录调试残留 `_calldbg.py`/`_populate.py`/`_raw.py`/`_srv_server_now.py`/`_test2.py`/乱码文件「系统」，`.gitignore` 补 `_*.py`）；✅ **O10**（`server.py`/`chat_server.py` 全部 `print` 转 `logging` + `basicConfig`，编译通过并部署）；✅ **O4**（Nginx `iweistoicqc5.conf` 顶层加 `limit_req_zone`(10r/s)+ `location ^~ /v1/` 加 `limit_req burst=30 nodelay` / `limit_req_status 429`，WS `/v1/chat` 不加；`nginx -t` 通过、`nginx -s reload` 生效，并发 50 请求实测前 30 个 200、其后出现 429）。
- **待实施**：O1-A（拆库 `prekeys.db`+`messages.db`，改动较大）/ O5（Token 单用户吊销，破坏性、单独评审）/ O8（删 chat_server 重复定义 `_check_prekey_rate_limit` 等死代码）/ O9（抽 `schema.py` 共享 DDL）/ O10 可选（gunicorn 结构化日志接入）。

---

## 1. 项目现状概览

### 1.1 部署架构（当前）

```
                         ┌──────────────────────────────────────────┐
   客户端 (gui.py / cli) │           阿里云 ECS  iweistoicqc5.top      │
   ──────────────────────┼──────────────────────────────────────────┤
   ① Prekey 管理         │  Nginx 反代                                │
      REST /v1/prekey/*  │   ├─ 127.0.0.1:5002  Flask (zhprekey.service)│
   ② 实时消息/文件       │   │     server.py  → 共享 zhprekey.db       │
      WebSocket :5003    │   └─ :5003          asyncio (zhchat-ws.service)│
                         │         chat_server.py → 共享 zhprekey.db   │
                         └──────────────────────────────────────────┘
```

两个后端服务（`server.py` = Flask prekey RESTful；`chat_server.py` = WebSocket 聊天中继）**当前共用同一个 SQLite 文件 `zhprekey.db`**，但对该文件使用了**互相冲突的 journal 模式**，且都对其中的 `messages` / `files` 表执行写操作。

### 1.2 密码学基础（已扎实，本批不改动）

- X3DH 初始握手 + 双棘轮会话密钥（ratchet.py / keys.py / core.py）
- 文件全程 AES-256-GCM E2E，服务器仅存密文、下载即焚（`chat_server.py`）
- Token 用本机 `device.key` 机器绑定 AES-GCM 加密落盘（config.py，审计 #8）
- 证书固定（`cert_pin`）接口已预留（config.py，审计 #18）
- 安全审计评分 81/90，方向正确

### 1.3 本次评审发现的问题清单（按优先级）

| ID | 优先级 | 问题 | 影响 |
|----|--------|------|------|
| O1 | P0 | 两服务共用 SQLite 且 journal 模式冲突（DELETE vs WAL）+ 双写 `messages` | `database is locked`、数据竞争 |
| O2 | P0 | Flask 上传接口无请求体大小上限（`MAX_UPLOAD_SIZE` 定义未用） | 大包 OOM 打挂 worker |
| O3 | P1 | `requirements.txt` 仅 2 行，缺 Flask/websockets/gunicorn/websocket-client | 新环境无法起服 |
| O4 | P1 | 限流为 per-worker 内存字典，gunicorn 多 worker 下被绕过 | 限流形同虚设 |
| O5 | P1 | Token 为服务器级共享凭证，无法单用户吊销 | 踢人须全量轮换 |
| O6 | P1 | `cleanup_expired()` 从未调度，过期 prekey 堆积 | 存储膨胀 |
| O7 | P2 | 根目录调试残留 + 乱码文件 `绯荤粺` | 仓库污染 |
| O8 | P2 | `chat_server.py` 重复定义 + 死代码 | 可维护性差 |
| O9 | P2 | `messages`/`files` DDL 两份各写 | schema 漂移风险 |
| O10 | P2 | 日志全用 `print` + 裸 `except: pass` | 不可追溯 |

---

## 2. P0 — 稳定性（必须修）

### 2.1 O1：数据库争用与 journal 模式统一

#### 2.1.1 根因

- `server.py` 的 `get_db()` 执行 `PRAGMA journal_mode=DELETE`（第 57 行）。
- `chat_server.py` 的 `init_message_db()` / `store_message()` / `mark_delivered()` 执行 `PRAGMA journal_mode=WAL`（第 71 / 170 / 197 行）。
- journal 模式是**库级属性**：两个进程每次建立连接都会把对方设的模式覆盖掉，DB 文件在 WAL / DELETE 之间反复横跳。
- 同时 `server.py:446` 的 `/v1/messages/send` 与 `chat_server.py:167` 的 `store_message()` **都写同一张 `messages` 表**，再加上 gunicorn 默认多 worker，多个写者竞争单文件 SQLite → 高并发下必现 `database is locked`。
- 注：此前为排查 `signing_public_key` 返回 null 曾把 server.py 改成 DELETE，但 null 的真正根因是 `sqlite3.Row.__contains__` 语义坑（已修复），**与 WAL 无关**。故此处方案应基于真实根因重新设计，而非沿用当时的临时取舍。

#### 2.1.2 方案 B（即时止血，推荐先做）

统一为 **WAL + `busy_timeout`**，让并发写者自动等待而非报错：

**`server.py` `get_db()` 改为：**
```python
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        # 与 chat_server 统一为 WAL；本机同文件系统下 -shm 可被所有进程共享，
        # 无需退回 DELETE。busy_timeout 让并发写者等待而非抛 database is locked。
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA busy_timeout=5000")
    return g.db
```

**`chat_server.py` 所有 `sqlite3.connect(DB_PATH)` 处统一加 busy_timeout**（抽一个 `_connect()` 封装）：
```python
def _connect():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA busy_timeout=5000")
    return db
```
并将 `init_message_db()` / `store_message()` / `mark_delivered()` / `get_pending_messages()` / `get_history()` / `record_file_upload()` / `can_download_file()` 中的 `sqlite3.connect(DB_PATH)` 全替换为 `_connect()`。

> 判定：WAL + `busy_timeout=5000` 对单主机、同文件系统的小规模聊天服务足够稳，改动量极小，是本项目的**最优即时方案**。

#### 2.1.3 方案 A（理想重构，长期）

将 DB 彻底拆分为两个文件，按服务归属：

| 文件 | 归属服务 | 包含表 |
|------|----------|--------|
| `prekeys.db` | Flask (zhprekey.service) | `identities`, `prekeys` |
| `messages.db` | WS (zhchat-ws.service) | `messages`, `files` |

**配置拆分：**
```python
# server.py
PREKEY_DB_PATH = os.environ.get("ZHPREKEY_PREKEY_DB",
                                 os.path.join(os.path.dirname(__file__), "prekeys.db"))

# chat_server.py
MESSAGE_DB_PATH = os.environ.get("ZHCHAT_DB",
                                 os.path.join(os.path.dirname(__file__), "messages.db"))
```

**关键决策**：`messages` / `files` 的写操作**只保留在 WS 服务**。Flask 的 `/v1/messages/*` 是早期 REST 兜底路径，与 WS 实时写形成双写。重构时二选一：
- （推荐）把 Flask 的消息相关端点标记为 deprecated 并在客户端移除 REST 兜底依赖，统一走 WS；
- 或保留 Flask 消息端点但改走只读（`message_pending`/`message_history` 只读，`message_send`/`message_ack` 删除），写仍由 WS 独占。

**一次性迁移脚本 `migrate_split_db.py`（部署前在服务器执行）：**
```python
import sqlite3, os
src = "zhprekey.db"
prekeys_db = "prekeys.db"
messages_db = "messages.db"
s = sqlite3.connect(src); s.row_factory = sqlite3.Row

# 建目标库 + 建表（省略 DDL，复用 init_db / init_message_db 逻辑）
p = sqlite3.connect(prekeys_db); p.execute("PRAGMA journal_mode=WAL")
m = sqlite3.connect(messages_db); m.execute("PRAGMA journal_mode=WAL")

p.executemany("INSERT OR REPLACE INTO identities (...) VALUES (...)",
              [dict(r) for r in s.execute("SELECT * FROM identities")])
p.executemany("INSERT OR REPLACE INTO prekeys (...) VALUES (...)",
              [dict(r) for r in s.execute("SELECT * FROM prekeys")])
m.executemany("INSERT OR REPLACE INTO messages (...) VALUES (...)",
              [dict(r) for r in s.execute("SELECT * FROM messages")])
m.executemany("INSERT OR REPLACE INTO files (...) VALUES (...)",
              [dict(r) for r in s.execute("SELECT * FROM files")])
p.commit(); m.commit(); p.close(); m.close(); s.close()
os.rename(src, src + ".migrated.bak")   # 保留原库备份
```

**部署步骤（方案 A）：**
1. 服务器停两服务 → 跑迁移脚本 → 校验两库行数。
2. 更新 `zhprekey.service` Environment 加 `ZHPREKEY_PREKEY_DB=/opt/zhprekey/prekeys.db`。
3. 更新 `zhchat-ws.service` Environment 加 `ZHCHAT_DB=/opt/zhprekey/messages.db`。
4. 改两服务源码指向新路径变量 + 用 `_connect()` 封装。
5. 重启两服务，`/v1/health`、`WS auth`、收发消息各验一遍。

#### 2.1.4 选型建议
- **本周**：落地方案 B（WAL + busy_timeout），30 分钟内消除锁错误。
- **下个迭代**：评估方案 A，若客户端已去 REST 兜底依赖则实施拆分。

---

### 2.2 O2：Flask 上传请求体大小上限

#### 2.2.1 根因
`server.py:44` 定义了 `MAX_UPLOAD_SIZE = 500 * 1024`，但全项目零引用（已 grep 确认）；且 `app` 未设 `MAX_CONTENT_LENGTH`。`upload_prekey` 用 `request.get_json(force=True)` 直接解析整个请求体，无体积闸门。

#### 2.2.2 修复（server.py 顶部，app 定义后）
```python
# 请求体硬上限 16MB（prekey bundle 远小于此；防止恶意大包 OOM）
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# 统一 413 处理
@app.errorhandler(413)
def _too_large(e):
    return jsonify({"error": "payload too large"}), 413
```
并在 `upload_prekey` 入口加显式校验（双重保险）：
```python
cl = request.content_length or 0
if cl > 16 * 1024 * 1024:
    return jsonify({"error": "payload too large"}), 413
```

#### 2.2.3 验收
`curl -X POST --data-binary @<20MB文件> .../v1/prekey/x` → 返回 413；正常 bundle → 200。

---

## 3. P1 — 安全 / 运维

### 3.1 O3：依赖清单补全

新建两份清单（旧 `requirements.txt` 仅 cryptography/argon2，无法起服）：

**`requirements-server.txt`**
```
Flask>=2.0
gunicorn>=20.0
websockets>=9.0
cryptography>=3.0
argon2-cffi>=21.1
```
**`requirements-client.txt`**
```
cryptography>=3.0
argon2-cffi>=21.1
websocket-client>=1.0
```
> 注：客户端 GUI 用 Tkinter（Python 标准库，无需列）。服务器若上 Redis 限流再加 `redis>=4.0`。

### 3.2 O4：限流跨 worker 共享

#### 3.2.1 根因
`server.py` 的 `_PREKEY_RATE_BUCKETS` / `_message_rate_buckets`（内存 dict）按 gunicorn worker 隔离，3 worker 下阈值实际 ×3 且请求被分散，易被绕过。

#### 3.2.2 即时方案：Nginx `limit_req`（反代层，最稳）
在 Nginx prekey 站点配置：
```nginx
limit_req_zone $binary_remote_addr zone=prekey:10m rate=10r/s;
server {
    location /v1/prekey/ {
        limit_req zone=prekey burst=20 nodelay;
        proxy_pass http://127.0.0.1:5002;
    }
}
```
> 注：Nginx 在反代之后，`$binary_remote_addr` 为真实客户端 IP（需确保 `proxy_set_header X-Forwarded-For` + Flask 不依赖 `remote_addr`），限流粒度正确。

#### 3.2.3 精确方案（可选）：Redis 共享桶
```python
import redis
r = redis.Redis()
def _check_prekey_rate_limit(identity):
    key = f"rl:prekey:{identity}"
    n = r.incr(key)
    if n == 1:
        r.expire(key, 60)
    return n <= RATE_LIMIT
```
适合需要按 `identity` 精确限流且多 worker 一致的场景。

### 3.3 O5：Token 单用户吊销（长期设计）

当前 token 为服务器级共享凭证，无单用户吊销能力。演进设计：

1. 新增 `tokens` 表：`(identity TEXT PRIMARY KEY, token_hash TEXT NOT NULL, created_at REAL, revoked INTEGER DEFAULT 0)`。
2. `require_auth` 改为：比对 `hmac(token, AUTH_TOKEN)` 失败 → 再查 `tokens` 表是否有某 identity 的 `token_hash` 匹配且未吊销。
3. 提供管理端点 `POST /v1/admin/revoke`（`require_admin`）按 identity 置 `revoked=1`。
4. 客户端配置改为 per-user token（注册时由服务器签发），朋友各自拿独立 token。
> 此为破坏性变更（客户端需支持多 token），列入路线图 Phase 3，不在本次 P0/P1 强制项。

### 3.4 O6：过期 prekey 清理调度

#### 3.4.1 现状
`server.py:599` `cleanup_expired()` 定义但无调用者，过期 prekey 仅靠被消耗，未消耗者堆积。

#### 3.4.2 修复
新增受保护端点 + systemd timer：
```python
@app.route("/v1/admin/cleanup", methods=["POST"])
@require_admin          # 用独立管理员 token，区别于普通 AUTH_TOKEN
def admin_cleanup():
    db = get_db()
    cutoff = _now() - PREKEY_EXPIRE_DAYS * 86400
    deleted = db.execute(
        "DELETE FROM prekeys WHERE created_at < ? AND consumed = 0", (cutoff,)
    ).rowcount
    db.commit()
    return jsonify({"deleted": deleted})
```
systemd timer（`/etc/systemd/system/zhprekey-cleanup.timer`）：
```ini
[Timer]
OnCalendar=hourly
```
搭配 `zhprekey-cleanup.service` 执行 `curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://127.0.0.1:5002/v1/admin/cleanup`。

---

## 4. P2 — 可维护性

### 4.1 O7：清理调试残留 + 强化 .gitignore

**待删除文件（根目录）：**
```
_calldbg.py  _populate.py  _raw.py  _srv_server_now.py  _test2.py
绯荤粺            # GBK 误码的"系统"，误生成垃圾文件
```
> 用回收站删除（Windows 走回收站，勿 `del /F`）。删除前确认这些非业务代码（仅为调试遗留，已被会话历史确认）。

**.gitignore 追加（若尚未覆盖）：**
```
# 调试/临时
_*.py
*.bak*
*.migrated.bak
# 运行产物
dist/ build/ dist_installer/ files/ __pycache__/ .pytest_cache/
# 凭证
.build_token
```

### 4.2 O8：删除 `chat_server.py` 重复定义与死代码

- 第 49–54 行 `PREKEY_RATE_LIMIT_PER_MINUTE` / `prekey_rate_limit_buckets` **重复定义两遍** → 保留一份。
- `_check_prekey_rate_limit(identity)` 在 WS 服务中定义却**未被 handler 调用**（WS 不处理 prekey 业务）→ 删除该函数及对应 bucket。
- 处理后 WS 服务的限流仅保留 `check_rate_limit`（消息发送用）。

### 4.3 O9：抽共享 schema 模块

新建 `schema.py`，集中所有建表 DDL，两服务 import 复用，杜绝漂移：
```python
def create_prekey_schema(db):
    db.execute("""CREATE TABLE IF NOT EXISTS identities (...)""")
    db.execute("""CREATE TABLE IF NOT EXISTS prekeys (...)""")

def create_message_schema(db):
    db.execute("""CREATE TABLE IF NOT EXISTS messages (...)""")
    db.execute("""CREATE TABLE IF NOT EXISTS files (...)""")
```
`server.py` 调 `create_prekey_schema`，`chat_server.py` 调 `create_message_schema`。

### 4.4 O10：日志 logging 化

替换全部 `print(...)` 为 `logging`，关键路径打告警：
```python
import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [zhprekey] %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("zhprekey")
```
- `store_message failed` / `file deleted after download` / `cleanup error` 等改 `log.error` / `log.info`。
- 排查裸 `except Exception: pass`（如 `message_pending` 兜底、`can_download_file` 外），改为 `log.warning` 带上下文，避免静默吞错。

---

## 5. 测试与验收矩阵

| 优化项 | 验证方法 | 通过标准 |
|--------|----------|----------|
| O1-B | 并发 50 线程同时发消息 + 上传 prekey | 无 `database is locked`，消息全部落库 |
| O1-A | 迁移后两库行数 = 原库各表之和 | 行数一致，收发正常 |
| O2 | 发 20MB 包到 `/v1/prekey` | 返回 413 |
| O3 | 新 venv `pip install -r requirements-server.txt` 后 `gunicorn server:app` | 服务起来、`/v1/health` 200 |
| O4 | Nginx 限流下超频请求 | 返回 429 |
| O6 | 触发 cleanup 端点 | 返回 deleted>0，过期 prekey 减少 |
| O7 | `git status` 干净 | 无 `_*.py` / `绯荤粺` 被跟踪 |
| O8 | `py_compile chat_server.py` | 通过，无重复定义 |
| O9 | 两服务启动 | 表结构与 schema.py 一致 |
| O10 | 运行期 `journalctl -u zhprekey` | 结构化日志可读，无静默异常 |

> 测试纪律（来自历史铁律）：本地测试用隔离 `HOME`（`$env:HOME` 指向临时目录），避免污染真实 `~/.zhcrypt`；`test_e2e.py` 直连生产会 `os.remove` 全部会话，**严禁自动跑**。

---

## 6. 实施路线图

### Phase 1（P0，本周，约 0.5 天）
1. **O2**：server.py 加 `MAX_CONTENT_LENGTH` + 413 处理（5 分钟）。
2. **O1-B**：两服务统一 WAL + `busy_timeout` + `_connect()` 封装。
3. 同步部署到 `/opt/zhprekey/server.py` 与 `chat_server.py`，重启两服务。
4. 并发压测验收。

### Phase 2（P1，下周，约 1 天）
5. **O3**：拆分 requirements，更新部署文档。
6. **O4**：Nginx `limit_req` 上线。
7. **O6**：cleanup 端点 + systemd timer。
8. **O10**：logging 化（可并行）。

### Phase 3（P2 + 长期演进，约 1.5 天）
9. **O7 / O8 / O9**：清理残留、死代码、抽 schema 模块。
10. **O1-A**：评估并落地 DB 拆分（若客户端已去 REST 兜底）。
11. **O5**：Token 单用户吊销设计落地（破坏性，单独评审）。

---

## 7. 风险与回滚

| 变更 | 风险 | 回滚 |
|------|------|------|
| O1-B WAL 改动 | 极小；WAL 需 `-wal`/`-shm` 文件，磁盘需可写 | git 回退 server.py/chat_server.py，重启 |
| O1-A DB 拆分 | 中；迁移失败可能双写错乱 | 保留 `zhprekey.db.migrated.bak`，回退环境变量指向原库 |
| O2 请求上限 | 极低 | 删除 `MAX_CONTENT_LENGTH` 配置 |
| O3/O4/O6 | 低 | 撤销配置 / 停 timer |
| O5 Token 演进 | 高（破坏性） | 独立分支，灰度发布 |

**通用铁律**（来自历史教训，务必遵守）：
- 改生产服务前先在本地用 `replace_in_file` 精准改，或加临时端点验证后立刻删；**绝不在 server.py 堆 `with open('/tmp/...')` debug 块**。
- 任何 server 行为修改必须区分服务：prekey 端点改 `server.py`+重启 `zhprekey.service`；WS 行为改 `chat_server.py`+重启 `zhchat-ws.service`。
- 本地与服务器是两份独立副本，改完必须同步并重启对应服务，否则"改了不生效"。

---

*本设计为 O1–O10 的完整方案集合，可与既有 `docs/chat_optimization_t1_t3.md`（聊天模块 UX 优化）配合使用。*
