# zhcrypt-chat 设计文档 — 轻量"类微信" CLI 版 (v1.1)

> 版本: v1.1 (修订稿) · 日期: 2026-08-07 · 状态: 待评审
> 路线: 基于 zhcrypt 拓展 (复用加密层/网络层, 新增 Textual TUI + 文件传输补强)

---

## 1. 背景与目标

### 1.1 背景

zhcrypt 已具备端到端加密通信的全部底层能力 (Argon2id / AES-256-GCM /
RSA-4096-OAEP / X3DH + Double Ratchet / TOFU 安全码 / Ed25519 验签), 以及
Flask prekey 服务 + WebSocket 消息中继 + SQLite 持久化 + 命令式 CLI。

但存在两个层面的缺口:

1. **交互层**: CLI 是"一次性命令"式 (chat-send / chat-poll), 无微信式连续
   交互体验 (会话列表、实时消息流、聊天窗口)。
2. **文件传输层**: 现有文件传输为 WS + base64, 单消息 50MB 上限、整文件
   读入内存 (峰值 ≈ 文件 × 1.4 × 2), 不符合"发文件"这一核心需求的可靠性
   与规模预期。

### 1.2 目标

| 功能 | 说明 | 优先级 |
|---|---|---|
| 交互式 TUI | 会话列表 / 聊天窗口 / 实时消息流 | P0 |
| 文本消息 | 收发 + 验签状态展示 + 失败重试 | P0 |
| 文件传输 | 分块上传、断点续传、下载、完整性校验 | P0 |
| 历史消息 | 本地缓存 + 滚动加载 | P1 |
| 未读管理 | 会话未读计数、置顶 | P1 |
| 安全码比对 | TUI 内查看/比对 TOFU 安全码 | P1 |

### 1.3 非目标 (v1)

- 群聊 (v2: 服务端预留 `group_id` 字段)
- 多端同步、已读回执 (v2)
- 图片缩略图/语音/视频通话
- 联系人发现 (沿用现有 prekey 握手)

---

## 2. 现状盘点与缺陷分析

### 2.1 可复用资产

| 模块 | 复用点 | 改动 |
|---|---|---|
| `keys.py` / `ratchet.py` / `core.py` / `session.py` | X3DH/Ratchet/密钥库/安全码 | 零改动 |
| `chat_client.py` | ChatClient 网络层、断线重连、REST 降级 | 小改 (见 §3.3) |
| `chat_server.py` | WS 中继、消息存储、授权模型 | 小改 (见 §3.2) |
| `cli.py` | 命令框架、服务器/token/cert-pin 配置 | 增加 `chat` 启动 TUI |

### 2.2 已识别的协议缺陷 (v1 必须修复)

**D1. 消息重复投递 (严重)**: `push_to_identity` 推送成功后不标记
`delivered_at`; 消息仍处于 pending 状态。接收方重连后 `get_pending`
会再次拉到同一消息 → 客户端再次调用 `receive_message` → **Double Ratchet
对同一消息解密两次, 推进链密钥, 导致会话状态错乱、后续消息全部解密失败**。

修复: push 成功即 `mark_delivered(msg_id)` (与 `get_pending` 幂等, 以 msg_id
唯一约束兜底)。

**D2. 文件传输不可扩展 (严重)**: WS base64 传输存在 50MB 硬上限、内存峰值
≈ 2.8× 文件大小、无断点续传、无进度反馈。服务端已有 Flask, 应改走
HTTP 流式端点 (见 §6)。

**D3. 发送方无投递反馈**: 客户端只知"服务器已 ack", 不知"对方是否收到"。
v1 通过 `delivered_at` 增加轻量查询, 驱动 UI 状态 (见 §5 状态机)。

**D4. 文件密钥协议未闭环**: GUI 侧文件加密 (MODE_FILE_STREAM) 的密钥传递
方式未在协议层定义。v1 统一为: **文件用一次性随机密钥 (file_key) 独立
加密, file_key 与元数据通过 ratchet 加密信道传递** (Signal 附件模型),
服务端仅持有密文, 满足 E2E 要求 (见 §6.3)。

---

## 3. 总体架构

```
┌─────────────────────────────────────────────────────┐
│  tui.py (Textual 应用, 新增)                          │
│  ┌───────────┬─────────────────────────────────────┐ │
│  │ 会话列表    │ 聊天视图                              │ │
│  │ (ListView) │ ┌───────────────────────────────┐  │ │
│  │  peer+摘要  │ │ 消息流 (虚拟化渲染, 只渲染可见)  │  │ │
│  │  未读角标   │ │ 文本/文件气泡 + 状态前缀          │  │ │
│  │  ...       │ └───────────────────────────────┘  │ │
│  │            │ 输入区 (Input + 命令解析)            │ │
│  ├───────────┴─────────────────────────────────────┤ │
│  │ 状态栏: 连接状态 · 当前会话 · 安全码提示 · 未读总数  │ │
│  └─────────────────────────────────────────────────┘ │
│  桥接层 Binder: INBOUND/OUTBOUND 队列 + Worker 泵       │
└──────────────────────────────┬──────────────────────┘
                               │
     ┌─────────────────────────┼─────────────────────────┐
     │  ChatClient (复用+小改)   │  FileClient (新增)        │
     │  WS 消息收发/握手/重连     │  HTTP 分块上传/下载        │
     └────────────┬────────────┴────────────┬────────────┘
                  │ WS                       │ HTTP
        ┌─────────▼─────────┐      ┌─────────▼─────────┐
        │ chat_server.py    │      │ server.py (Flask) │
        │ (小改: D1)         │      │ (新增文件端点)      │
        └───────────────────┘      └───────────────────┘
            共用 SQLite (WAL) + files/ 目录
```

### 3.1 组件职责

| 组件 | 职责 | 说明 |
|---|---|---|
| `tui.py` | 布局/交互/渲染, 纯 UI | 新增, ~800 行 |
| `localstore.py` | 本地会话/消息/outbox 缓存 | 新增, ~150 行 |
| `fileclient.py` | HTTP 文件分块上传/下载/续传 | 新增, ~250 行 |
| `ChatClient` | WS 消息/握手/重连 (现有) | 复用 |
| `chat_server.py` | WS 中继 (现有) | 修 D1, ~10 行 |
| `server.py` | Flask 文件端点 | 新增 ~120 行 |

### 3.2 服务端改动明细

**chat_server.py (D1 修复)**:

```python
# push_to_identity 成功后:
if await push_to_identity(msg["to"], msg):
    mark_delivered([msg["id"]])
```

**server.py (文件端点, 新增)** — 复用现有 files 表授权模型与路径防御:

```
POST /v1/files/upload          Content-Type: application/octet-stream
     Headers: Authorization: Bearer <token>
              X-Upload-Token: <client 生成 32hex>   (幂等/续传)
              X-Recipient: <identity>
     Body: 原始密文字节流 (客户端自行加密)
     → 201 {token}  |  已存在 → 200 (幂等)

GET  /v1/files/download/<token>
     Headers: Authorization: Bearer <token>
     Support: Range (断点续传), 206 Partial Content
     → 200/206 密文字节流 (授权=上传者或预期接收方)

HEAD /v1/files/download/<token>  → 校验存在性/授权
```

存储布局:

```
files/
  <token>.part    # 上传中 (分片追加)
  <token>         # 上传完成 (rename, 原子)
```

上传会话: `X-Upload-Token` + 客户端 `X-Offset` (首包 0), 服务端校验
offset 与已落盘大小一致, 否则 409 + 当前 offset (续传协商)。

### 3.3 ChatClient 小改

- 新增 `send_file(peer, path, progress_cb)` / `download_file(token, dest, progress_cb)`
  走 FileClient (不再走 WS file_upload)
- 文件消息仍是普通聊天消息: `type:"file"`, payload 携带 `{name, size,
  sha256, token, key}` (§6.3)
- 新增 `query_delivered(msg_ids) → {id: delivered_at}` 轻量端点调用 (D3)

---

## 4. 线程模型

```
后台线程 A: ChatClient._ws_loop (现有) ──┐
后台线程 B: FileClient 上传/下载 Worker ──┤
后台线程 C: Binder 泵 (消费 INBOUND, 解密, 投递) ──┐
                                              ▼
主线程: Textual 事件循环 ◄── app.post_message(NewMessage/StatusChanged)
```

| 线程 | 职责 | 同步机制 |
|---|---|---|
| 主线程 | Textual 渲染/输入 | 不阻塞 |
| 线程 C (Binder) | 轮询 INBOUND 队列 (interval 50ms), 调 `receive_chat_message` 解密, 更新 LocalStore, 向 UI post_message | queue.Queue (现有) |
| 线程 B | 文件分块读写, 通过 INBOUND 发进度事件 | queue.Queue |
| 线程 A | WS 收发 (现有) | 现有机制 |

退出序列: `/exit` → 主线程停止 Worker → ChatClient.stop() → 线程 join
(超时 3s) → LocalStore 关闭 → 退出码 0。

---

## 5. 消息生命周期与状态机

### 5.1 消息状态机 (发送方视角)

```
              用户发送
                 │
                 ▼
         ┌──────────────┐
         │  queued       │◄──────────────┐
         │ (落库 outbox) │               │
         └──────┬───────┘               │
                │ Binder 泵出队           │ 重试 (指数退避, 最多 5 次)
                ▼                       │
         ┌──────────────┐  失败         │
         │  sending      │──────────────┘
         └──────┬───────┘   (WS/REST 均失败)
                │ ack(msg_id) 收到
                ▼
         ┌──────────────┐
         │  sent         │ ◄── 服务器已落库
         └──────┬───────┘
                │ query_delivered 轮询 (30s 一次, 3 次后停止)
                ▼
         ┌──────────────┐
         │  delivered    │ ◄── 对方连接在线且已推送
         └──────────────┘
```

- 状态持久化于 `outbox` 表, 进程重启后 `queued`/`sending` 的消息自动重发
  (msg_id 不变, 服务端 `INSERT OR IGNORE` 幂等, 不会重复投递)
- 超过重试上限 → `failed`, 气泡显示 ⚠, 按 `r` 手动重发

### 5.2 接收方幂等

- 消息以 `msg_id` 全局唯一; 本地 `local_messages` 以 msg_id 为主键
- 即使服务器重复推送, `INSERT OR IGNORE` + ratchet 层依赖 D1 修复保证
  每个 msg_id 只解密一次

### 5.3 UI 状态前缀

| 前缀 | 含义 |
|---|---|
| 🕐 | 发送中 (queued/sending) |
| ✓ | 已送达服务器 (sent) |
| ✓✓ | 对方已收到 (delivered) + 验签通过 |
| ⚠ | 验签失败或发送失败 (按 r 重试) |

---

## 6. 文件传输设计

### 6.1 需求

- 支持任意大小 (v1 上限 2GB, 受磁盘约束)
- 断点续传 (网络中断后从 offset 继续)
- 进度反馈 (气泡内进度条)
- E2E: 服务端只见密文
- 完整性: sha256 校验

### 6.2 协议流

```
发送方:
  /send report.pdf
  1. 生成 file_key = secrets.token_bytes(32)   (一次性)
  2. 分块读取 (1MB/块), AES-256-GCM 流式加密 → 块级附加 AAD=offset
  3. FileClient 分块 POST 上传 (并发 2, 每块确认 offset)
  4. 完成后 POST 聊天消息 (ratchet 加密):
     {type:"file", payload:{
        name, size, sha256,
        token: <server token>,
        key: b64(file_key)      ← 经 E2E 信道传递
     }}
  5. UI: 消息气泡出现 → ✓ → 对方下载完成 → ✓✓ (D3 轮询)
接收方:
  收到 type:"file" 消息 → 气泡 [📎 report.pdf 2.3MB] [下载] [校验]
  /download <token>
  1. HEAD 确认存在 → 分块 GET (支持 Range, 断点续传)
  2. 解密 → 写 ~/.zhcrypt/downloads/<name>  (防路径穿越: 文件名白名单
     [\w.\-]+, 拒绝 .. 与保留字符)
  3. sha256 与消息携带值比对 → 一致 ✓✓ / 不一致 ⚠ 删除残留
```

### 6.3 安全模型

| 项 | 设计 |
|---|---|
| 文件加密 | 每文件独立 file_key (AES-256-GCM, 随机 nonce 前置) |
| 密钥传递 | file_key 经 ratchet 加密信道发送, 服务端不可见 |
| 密钥生命周期 | 解密成功后立即从 LocalStore 明文缓存中清除 |
| 服务端权限 | 沿用 files 表: 上传者 / 预期接收方; 下载后保留 (不删, 支持续传; 30 天后清理) |
| 完整性 | sha256 (消息内传递) 双重校验: 上传前比对 → 下载后比对 |
| 抗阻塞 | 服务端上传会话超时 (30min) 与并发数限制 (每身份 2) |

### 6.4 与现有逻辑差异

现有 WS file_upload 保留兼容 (GUI 不受影响), v1 新客户端走 HTTP 端点;
v2 将 GUI 一并迁移。

---

## 7. 数据模型

### 7.1 服务端 (改动最小)

`messages` 表不变; `files` 表不变。预留 `group_id` 列 (v2, 通过
schema.py 的 `add_column` 迁移)。

### 7.2 客户端 LocalStore (新增, 位于身份目录)

```sql
CREATE TABLE conversations (
    peer        TEXT PRIMARY KEY,
    last_text   TEXT,
    last_ts     REAL,
    unread      INTEGER DEFAULT 0,
    pinned      INTEGER DEFAULT 0
);

CREATE TABLE local_messages (
    peer        TEXT NOT NULL,
    msg_id      TEXT PRIMARY KEY,
    from_peer   TEXT NOT NULL,
    msg_type    TEXT NOT NULL,            -- text | file
    body        TEXT NOT NULL,            -- 明文文本 或 文件元数据 JSON
    status      TEXT NOT NULL DEFAULT 'sent',  -- sent|delivered|failed
    verified    INTEGER DEFAULT 0,
    ts          REAL NOT NULL
);
CREATE INDEX idx_lm_peer_ts ON local_messages(peer, ts);

CREATE TABLE outbox (                      -- 未确认消息, 崩溃恢复重发
    msg_id      TEXT PRIMARY KEY,
    peer        TEXT NOT NULL,
    body        TEXT NOT NULL,             -- 加密前原文
    attempts    INTEGER DEFAULT 0,
    status      TEXT NOT NULL,             -- queued|sending|failed
    ts          REAL NOT NULL
);

CREATE TABLE file_keys (                   -- 待解密文件密钥缓存 (明文明文只存在于本地)
    msg_id      TEXT PRIMARY KEY,          -- 解密后立即删除
    key         BLOB NOT NULL
);
```

---

## 8. TUI 交互设计

### 8.1 布局

```
┌────────────┬──────────────────────────────┐
│ 会话        │  alice                        │
│ ────────── │ ───────────────────────────── │
│ alice     │ [12:30] alice ✓✓              │
│   你好…(3) │   文件我收到了                  │
│ bob       │ ───────────────────────────── │
│   在吗?(1) │ [12:31] 我  🕐✓               │
│ carol     │   发你一个报告                  │
│ ...       │ [12:32] 我  ✓  📎 report.pdf   │
│           │   2.3MB ▓▓▓▓░░ 45%            │
│           │                               │
│           │ > /send D:\docs\report.pdf    │
├────────────┴──────────────────────────────┤
│ ● 已连接 · alice · 安全码 56A3-… · 未读 4    │
└───────────────────────────────────────────┘
```

### 8.2 快捷键

| 键 | 动作 |
|---|---|
| ↑/↓ + Enter | 切换会话 |
| Tab | 焦点 会话列表 ⇄ 输入区 |
| Ctrl+F | 搜索会话 (v1.1) |
| r | 重发失败消息 |
| d | 当前会话内下载选定文件 |
| s | 显示/比对当前会话安全码 |
| /exit | 退出 |

### 8.3 状态与边界

- 空态: 无会话时显示引导文案 (如何与对方建立首个会话)
- 连接丢失: 状态栏变 ● 重连中 (指数退避), 消息仍可输入 (进 outbox)
- 宽度 < 60 列: 警告并折叠会话列表为单列
- IME: 需 Windows Terminal + textual 最新版; 兜底 `/send-text <内容>` 命令

---

## 9. 命令一览

| 命令 | 功能 |
|---|---|
| `/send <path>` | 发送文件 (§6) |
| `/download <token> [dir]` | 下载文件 (默认 ~/.zhcrypt/downloads) |
| `/history [n]` | 加载更多历史 (默认 50) |
| `/safety [peer]` | 安全识别码 |
| `/search <kw>` | 本地消息搜索 |
| `/connect` | 手动重连 |
| `/help` `/exit` | 帮助 / 退出 |

---

## 10. 错误场景分析

| 场景 | 行为 |
|---|---|
| 对端无 prekey / 未注册 | TUI 提示, 引导对方 init + upload-prekey |
| TOFU 公钥与历史不符 | 拒绝会话, 显示安全码差异说明, 明确"换钥需带外确认" (复用 chat_client 错误语义) |
| 发送时网络断开 | 消息进 outbox, 重连后自动重发 |
| 文件上传中断 | 断点续传 (offset 协商), 3 次失败 → failed, 可 r 重试 |
| 下载解密失败 | 提示密钥可能过期/消息重复, 删除残留, 请求对方重发 |
| 服务器 429 限流 | 客户端退避, 状态栏提示 |
| 磁盘满 | 上传/下载前置检查剩余空间 (≥ 1.5× 文件大小) |

---

## 11. 安全评审要点

1. file_key 仅经 E2E 信道传递, 明文只落本地磁盘 (文件权限 0600 / Windows ACL)
2. 下载路径严格白名单, 杜绝路径穿越
3. 上传会话限流 + 超时, 防存储耗尽
4. 消息幂等由 msg_id 唯一约束 + D1 修复双保险
5. 明文缓存 (local_messages/outbox/file_keys) 权限与 ratchet 会话一致;
   提供 `zhcrypt chat --wipe-cache` 清空
6. 不引入任何新的网络端口暴露 (仅复用 5003/Flask 既有端口)

---

## 12. 测试计划

### 12.1 单元测试 (pytest)

| 目标 | 用例 |
|---|---|
| FileClient | 分片组装、offset 协商、续传后 sha256 一致 |
| LocalStore | outbox 重发选择、幂等插入、file_keys 清理 |
| 命令解析 | `/send` `/download` 参数边界、路径穿越输入 |
| 状态机 | queued→sent→delivered 转移、失败重试上限 |

### 12.2 集成测试 (双进程)

- 脚本启动 server + 两个 ChatClient 实例, 不经 UI:
  - 互发 100 条消息 → 双方 local_messages 完全一致, 无重复
  - 发送 2GB 稀疏文件 → 下载 → sha256 一致
  - 上传中断 (kill 客户端) → 重连续传 → 一致
  - 服务器重启 → pending 补拉, outbox 重发, 无重复

### 12.3 手动验收 (Windows Terminal)

按 §8 布局验收 + 中文 IME + 断网提示 + 全角符号。

---

## 13. 实施计划

| 里程碑 | 内容 | 工作量 |
|---|---|---|
| M0 | 修 D1 (push 后 mark_delivered); 补测试防回归 | 0.5 天 |
| M1 | 服务端文件端点 (upload/download/Range/续传) + FileClient | 1.5 天 |
| M2 | LocalStore + 消息状态机 + outbox 重发 + 集成测试 | 1.5 天 |
| M3 | TUI: 布局/会话列表/文本收发/状态栏 | 2 天 |
| M4 | TUI: 文件气泡/进度/快捷键/历史加载/搜索/打磨 | 2 天 |

**合计: 单人 ~7.5 个工作日。** 每里程碑含对应测试, 完成后才进下一个。

---

## 14. 验收标准 (Definition of Done)

1. 双实例文本互发: ≤2s 实时出现, 验签 ✓✓, 断网重发无重复
2. 2GB 文件传输: sha256 一致, 中断后续传成功, 进度可实时显示
3. 服务器重启 30s 内客户端自动恢复, 离线消息补齐
4. 全部单元 + 集成测试通过 (≥ 90% 覆盖率目标)
5. Windows Terminal 中文输入、快捷键、窗口缩放正常
6. 服务端与原 GUI/CLI 完全兼容 (协议向后兼容)
