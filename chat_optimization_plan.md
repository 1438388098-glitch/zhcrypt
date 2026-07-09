# zhchat v1.1 — 聊天系统优化设计文档

## 0. 版本信息

| 项 | 值 |
|----|-----|
| 版本 | v1.1 |
| 状态 | 设计阶段 |
| 关联 | zhcrypt v3.0.0 + zhchat v1.0 |

---

## 一、消息丢失修复（致命）

### 1.1 初始 get_pending 响应被 GUI 丢弃

**根源**：chat_client.py 176 在 WebSocket 认证成功后自动发送 get_pending。服务器返回 {"type":"pending","messages":[...]} 推入 INBOUND 队列。但 GUI 的 _poll_chat 和 _check_chat_connected 只处理 data["type"] == "message"，不处理 "pending"。这些消息被服务器标记为 delivered 后永久丢失。

**修复**：_poll_chat / _check_chat_connected 增加对 "pending" 类型的处理。

### 1.2 服务端先标记 delivered 再发消息

**根源**：chat_server.py get_pending_messages 先调用 mark_delivered(msg_ids) 再 await websocket.send()。如果 send 失败（客户端断开），消息已标记已送达且不会再出现于 pending 查询，永久丢失。

**修复**：方案 A（推荐）——先 send 再 mark。发送成功后再标记为 delivered。

### 1.3 store_message 无异常保护

**根源**：chat_server.py store_message 中 sqlite3.connect() / commit() 无 try/except。任何 SQLite 异常（磁盘满、WAL 锁冲突）向上传播到 handler 协程，导致协程崩溃、连接断开、消息丢失。

**修复**：store_message 加 try/except，捕获异常后记录日志，不崩溃。

### 1.4 get_pending 单次只取 50 条，无分页

**根源**：服务器 get_pending_messages 默认 limit=50。客户端只在连接时调用一次 get_pending。离线期间超过 50 条消息的剩余部分永远不会被拉取。

**修复**：客户端改为循环拉取直到取完。

---

## 二、连接稳定性（重要）

### 2.1 10 秒 recv 超时导致空闲断连

**根源**：websocket.create_connection(timeout=10) 将 socket 超时设为 10 秒。空闲 10 秒后 recv() 抛出 socket.timeout，_ws_loop 的 except Exception 捕获后触发断线重连。服务器 ping_interval=30 秒，客户端 timeout 在 ping 到达前触发。

**修复**：将 timeout 从 10 秒改为 120 秒。

### 2.2 认证失败后永久退出

**根源**：_connect_ws 中认证失败设置 self._running = False。WebSocket 线程退出后永不重试。短暂服务器重启后客户端无法自动恢复。

**修复**：改为重试模式，前 3 次认证失败继续重试，3 次后停止。

### 2.3 所有 recv 异常等同处理

**根源**：所有 recv 异常（socket.timeout、JSON 解析错误、连接关闭）都触发断线重连。JSON 解析错误本可忽略继续接收。

**修复**：区分异常类型，JSON 错误跳过，timeout 发 ping，close 才重连。

### 2.4 ws.send/recv 跨线程调用

**根源**：_send_via_ws 在主线程调用 ws.send()，_ws_loop 在守护线程调用 ws.recv()。websocket-client 库非线程安全。

**修复**：发送操作通过 queue.Queue 放入队列，_ws_loop 线程同时处理收发。

---

## 三、性能优化

### 3.1 每条消息都 save_session 写磁盘

**现状**：每次 send_message 和 receive_message 后都调用 save_session()，含 Argon2id 派生 + AES-GCM 加密 + 磁盘写入，约 200-500ms。

**优化**：内存缓存 + 30 秒或 10 条消息后统一落盘。

### 3.2 轮询间隔固定 2 秒

**现状**：_poll_chat 在 WebSocket 和 REST 两条路径同时询问消息。WS 已连接时 REST 轮询多余。

**优化**：WS 已连接时跳过 REST 轮询，断开时退到 REST 轮询。

### 3.3 无限重连无封顶

**现状**：退避到 60 秒后持续每分钟重连一次。

**优化**：退避到 60 秒后改为 5 分钟重连一次，12 次（1 小时）后停止。

---

## 四、Emoji 支持

### 4.1 技术约束

Tkinter 的 Tcl 引擎在 Windows 上无法渲染 U+FFFF 以上的 Unicode 字符。直接输入 emoji 会触发 Tcl 错误。

### 4.2 方案

| 组件 | 方案 |
|------|------|
| Emoji Picker | 按钮弹出 Toplevel 窗口，4x8 网格展示常用 emoji |
| 显示 | 输入 Unicode emoji → 发送前校验 U+FFFF 以下 → 安全渲染 |
| 内置列表 | 80 个常用 emoji（限 U+FFFF 以下） |

---

## 五、文件传输

### 5.1 方案

| 大小 | 方案 |
|------|------|
| < 500KB | Base64 嵌入 WebSocket 消息 |
| >= 500KB | MODE_FILE_STREAM 加密后 REST 上传，消息体只传 token |

### 5.2 小文件流程

1. 选择文件 → 检查大小 < 500KB
2. 读取文件内容 → AES-GCM 加密
3. 构造消息: {"type":"file","name":"doc.pdf","size":12345,"data":"<base64>"}
4. WebSocket 发送 → 服务器转发
5. 接收方识别 type=="file" → 弹出保存对话框 → 解密写入

---

## 六、聊天界面现代化

### 6.1 新旧对比

| 区域 | 现状 | 改进后 |
|------|------|--------|
| 背景色 | #fafafa | #f0f2f5 |
| 己方气泡 | 蓝色文字左对齐 | 蓝色背景右对齐圆角 |
| 对方气泡 | 灰色文字左对齐 | 白色背景左对齐圆角 |
| 时间戳 | 无 | HH:MM |
| 发送状态 | 无 | ✓ / ✓✓ |
| 输入框 | 单行 Entry | 多行 Text 自适应高度 |
| 发送按钮 | 普通 Button | 蓝色圆角按钮 |

### 6.2 配色

```
背景: #f0f2f5
己方气泡: #d1e7ff
对方气泡: #ffffff
主色调: #4a90d9
已送达勾: #34c759
```

---

## 七、实施步骤

| 阶段 | 内容 | 涉及文件 | 行数 |
|------|------|----------|------|
| P0-1 | GUI 处理 pending 类型 | gui.py | ~15 |
| P0-2 | 服务端先 send 再 mark | chat_server.py | ~15 |
| P0-3 | store_message 异常保护 | chat_server.py | ~10 |
| P0-4 | get_pending 分页循环 | chat_client.py | ~15 |
| P1 | 连接稳定性修复 | chat_client.py | ~80 |
| P2 | UI 现代化 | gui.py | ~200 |
| P3 | Emoji 支持 | gui.py + emoji.py | ~120 |
| P4 | 文件传输 | gui.py + chat_*.py | ~150 |
