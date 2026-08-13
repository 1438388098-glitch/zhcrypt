# zhcrypt-chat 并行开发约定 (AGENTS.md)

> 本文档是所有 subagent 的唯一契约。开工前必须完整阅读。
> 设计总纲: `zhcrypt-tui-design.md` (v1.1)

---

## 0. 环境与命令

- **Python 解释器**: `packaging\buildenv\Scripts\python.exe` (Python 3.13)
  **禁止使用系统 python (3.6, 不支持 textual)**
- **运行测试**: `packaging\buildenv\Scripts\python.exe -m pytest tests/<你的文件> -q`
- **你只能触碰自己负责的文件** (见 §3 模块归属表)。公共文件由主 agent 负责,
  任何人不得修改: `cli.py`、`requirements*.txt`、`schema.py`、`README.md`、`AGENTS.md`
- 代码风格对齐现有文件: 中文注释 + 模块头 docstring + 蛇形命名 + `{}` 格式化
- 服务端 token 认证: `Authorization: Bearer <token>`, token 来自 `ZHPREKEY_TOKEN` 环境变量

## 1. 编码规范

1. 每个新模块文件头必须有 docstring (职责、入口)
2. 函数返回约定 (与现有代码一致):
   - 成功: 返回 dict 或值, 如 `{"status": "sent", "msg_id": ...}`
   - 失败: 返回 `{"error": "人类可读中文原因"}` —— **不要抛异常** (网络/业务层)
   - 仅配置错误/编程错误可抛异常, 且必须是专有异常类 (如 `LocalStoreError`)
3. SQLite 连接统一 WAL + busy_timeout=5000 (参考 `server.py get_db`)
4. 所有时间戳统一 `time.time()` 浮点秒
5. 路径处理必须防穿越: 文件名白名单 `^[\w.\-]+$`, 目标目录必须 `os.path.realpath` 校验
6. 不引入新依赖 (除非契约明确要求)

## 2. 跨模块接口契约 (不可变更, 双向强制)

### 2.1 `fileclient.py` (Agent-B 产出)

```python
class FileClientError(Exception): ...

class FileClient:
    def __init__(self, server_url: str, auth_token: str, identity: str = ""): ...
    def upload(self, file_path: str, recipient: str, progress_cb=None,
               upload_token: str = None) -> dict
        # upload_token 可选: 传入复用会话 (跨调用断点续传), 否则自动生成
        # 成功: {"token": str}   失败: {"error": str}
    def download(self, token: str, dest_dir: str, progress_cb=None) -> dict
        # 成功: {"path": str, "size": int}   失败: {"error": str}
    def head(self, token: str) -> dict
        # 成功: {"size": int}   不存在: {"error": "not found"}   失败: {"error": str}
    # progress_cb(done: int, total: int) 每秒最多回调 1 次
```

- 上传协议: `POST {server}/v1/files/upload`, 头 `X-Identity`(客户端身份) +
  `X-Upload-Token`(32hex, 会话标识) + `X-Recipient` + `X-Offset` + `X-Total-Size`,
  请求体为**分块密文字节流**; 分块 1MB; 响应 `201 {"token":...}` (完成) 或
  `409 {"offset": n}` (续传协商); 单身份并发 ≤2 (第 3 个 429)
- 下载协议: `GET {server}/v1/files/download/<token>`, 头 `X-Identity`, 支持
  `Range: bytes=start-end` → `206`; 授权 = files 表 uploader 或 intended_recipient
- 内部 HTTP 请求封装为方法 `_http_raw(...)`, 测试通过 monkeypatch 它做 mock

### 2.2 `localstore.py` (Agent-C 产出)

```python
class LocalStoreError(Exception): ...

class LocalStore:
    def __init__(self, db_path: str): ...   # 建表, 幂等
    def close(self): ...
    def upsert_conversation(self, peer, last_text, last_ts, unread_inc=False) -> None
    def list_conversations(self) -> list   # [{peer,last_text,last_ts,unread,pinned}] 按 last_ts desc
    def clear_unread(self, peer) -> None
    def upsert_message(self, peer, msg_id, from_peer, msg_type, body, status, verified, ts) -> None
    def get_messages(self, peer, limit=100, before_ts=None) -> list   # 升序返回
    def save_outbox(self, msg_id, peer, body) -> None                 # status=queued, attempts=0
    def list_outbox(self) -> list                                     # status in (queued, sending)
    def mark_outbox(self, msg_id, status, attempts=None) -> None
    def list_failed_outbox(self) -> list                              # status=failed (TUI r 键重发)
    def delete_outbox(self, msg_id) -> None                           # 发送成功后清理
    def save_file_key(self, msg_id, key: bytes) -> None
    def take_file_key(self, msg_id) -> bytes | None                   # 取出即删
    def search(self, kw, limit=50) -> list
```

- 表结构见设计文档 §7.2, 在 `localstore.py` 内部用模块级 DDL 常量定义
- 线程安全: 所有方法内部新建连接, 不做跨线程共享连接

### 2.3 `chat_client.py` 新增方法 (Agent-B 追加, 不改现有方法)

```python
# 追加到 ChatClient 类:
def send_file(self, peer_identity: str, file_path: str, progress_cb=None) -> dict
    # 成功: {"status": "sent", "msg_id": str}  失败: {"error": str}
def download_file(self, token: str, dest_dir: str, progress_cb=None) -> dict
    # 成功: {"status": "ok", "path": str}  失败: {"error": str}
def query_delivered(self, msg_ids: list) -> dict   # {msg_id: ts 或 None}
```

- 文件消息格式 (ratchet 加密的 inner JSON 扩展):
  `{"text": "", "signature": "...", "file": {"name","size","sha256","token","key"}}`
  `key` = 文件 AES 密钥 b64。`_parse_decrypted` 需扩展: 解析到 `file` 字段时
  返回值增加 `"file": {...}` (无文件则为 None)
- `query_delivered` 调用 `GET {server}/v1/messages/delivered?ids=a,b,c`
  (Agent-A 实现), 响应 `{"delivered": {"msg_id": ts}}`

### 2.4 `tui.py` (Agent-D 产出)

```python
def main(identity: str, passphrase: str) -> int   # 退出码, cli.py `chat` 子命令调用
```

- 直接复用: `from chat_client import ChatClient, INBOUND, OUTBOUND`
  `from localstore import LocalStore`  `from fileclient import FileClient`
  `from config import get_prekey_server, get_auth_token`
- Binder 线程: 循环消费 `INBOUND` 队列 (50ms 间隔), 消息事件
  `{"action": "server_message", "data": msg}` → `client.receive_chat_message(msg)`
  解密 → `LocalStore.upsert_message` → `app.post_message(NewMessage(...))`
- 命令解析: `/send <path>` `/download <token>` `/history [n]` `/safety [peer]`
  `/search <kw>` `/connect` `/help` `/exit`
- 发送流程: `INBOUND` 中无发送事件, 直接用 `client.send_chat_message(peer, text)`
  或 `client.send_file(...)`; outbox 重发逻辑属 Agent-C, TUI 只调用其接口
- 文件下载: `client.download_file(token, downloads_dir, progress_cb)` 后
  用 `LocalStore.take_file_key(msg_id)` 取密钥解密写入 (文件名白名单校验)

### 2.5 服务端文件端点 (Agent-A 实现, 契约)

```
POST /v1/files/upload
  头: Authorization: Bearer <token>  X-Recipient: <identity>
  体: 分块密文 (每块带 X-Offset 头), 块 1MB
  响应: 201 {"token": "32hex"}  |  409 {"offset": n} (块序号不连续时)
  授权: token 校验 (require_auth)  + 记录 files 表 (uploader=X-Recipient 校验=认证身份)
GET /v1/files/download/<token>
  支持 Range, 206; 授权 = files 表 uploader 或 intended_recipient
HEAD /v1/files/download/<token>  → 200 {"size"} / 404
GET /v1/messages/delivered?ids=a,b,c
  → {"delivered": {"a": 1234567890.5, "b": null}}  (仅返回认证身份为收件人的消息)
```

- 文件存储: `FILE_DIR/<token>` (32hex), 复用 `_resolve_file_path` 风格防御 (server.py)
- 上传会话超时 30min 清理, 单身份并发上传 ≤2
- chat_server.py 修复 D1: `push_to_identity` 成功返回 True 时调用 `mark_delivered([msg_id])`

## 3. 模块归属表 (文件 → Agent)

| 文件 | 归属 | 类型 |
|---|---|---|
| `server.py` | Agent-A | 修改 (新增 4 端点 + 辅助函数) |
| `chat_server.py` | Agent-A | 修改 (D1 修复, ~10 行) |
| `tests/test_server_files.py` | Agent-A | 新建 (Flask test_client 单测) |
| `fileclient.py` | Agent-B | 新建 |
| `chat_client.py` | Agent-B | 修改 (仅追加 3 方法 + _parse_decrypted 扩展) |
| `tests/test_fileclient.py` | Agent-B | 新建 (monkeypatch _http_raw) |
| `localstore.py` | Agent-C | 新建 |
| `tests/test_localstore.py` | Agent-C | 新建 |
| `tui.py` | Agent-D | 新建 |
| `tests/test_tui_smoke.py` | Agent-D | 新建 (无头启动/退出/命令解析) |
| `cli.py` `requirements*.txt` `schema.py` `README.md` | 主 agent | 禁止触碰 |

## 4. 完成定义 (Definition of Done)

1. 负责文件已实现, 契约签名完全一致 (含参数名与返回结构)
2. 单元测试通过: `packaging\buildenv\Scripts\python.exe -m pytest tests/<文件> -q`
3. 不破坏既有测试 (可跑 `pytest tests/test_chat.py` 验证自己改过的文件)
4. 不得修改模块归属表中其他 Agent 的文件 (这是硬性纪律)

## 5. 提交时向主 agent 报告

- 完成的文件清单与行数
- 测试结果 (通过用例数)
- 契约偏差 (如有, 必须显式列出, 主 agent 统一裁决)
- 遗留问题 / 对别的模块的依赖假设
