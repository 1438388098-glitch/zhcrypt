# zhcrypt v1.1 — 剩余功能设计文档

## 0. 概述

本设计覆盖三个待完成功能：桌面通知、大文件传输、X3DH OTP 恢复。

| 功能 | 难度 | 优先级 |
|------|------|--------|
| X3DH OTP 恢复 | 极低（1 行） | 高 |
| 桌面通知 | 低（~30 行） | 中 |
| 大文件传输 | 中（~175 行） | 中 |

---

## 1. X3DH OTP 恢复

### 1.1 现状

`_initiate_session` 中 `peer_one_time_prekey_pub_b64=None`，X3DH 只做 2 个 DH 操作（身份密钥之间），不使用签名预密钥（SPK）和一次性预密钥（OTP）。

```python
state, init_extra = x3dh_initiate_session(
    peer_one_time_prekey_pub_b64=None,  # OTP 被禁用
    ...
)
```

### 1.2 修复

改回从服务器获取 OTP 公钥传参。接收方 `_handle_x3dh_init` 已实现遍历本地 OTP 私钥尝试解密的逻辑。

**改动**：`chat_client.py` `_initiate_session` 中一行

### 1.3 风险

- OTP 用尽时需要重新上传 prekey
- 接收方 OTP 本地列表与服务器消耗顺序一致（先进先出）

---

## 2. 桌面通知

### 2.1 需求

GUI 最小化或不在前台时，新聊天消息到达弹出 Windows 系统通知。

### 2.2 方案

用 `plyer` 库（纯 Python，跨平台）：

```python
from plyer import notification
notification.notify(
    title=f"{sender} 发来消息",
    message=text[:50],
    app_name="zhcrypt",
    timeout=5,
)
```

### 2.3 触发时机

`_display_chat_message` 中，如果接收的是对方消息（非自己发送），且窗口未激活时弹出通知。

### 2.4 条件检查

```python
if who != self.chat_identity_var.get() and self.root.state() == 'iconic':
    # 窗口最小化时弹出通知
```

### 2.5 依赖

```bash
pip install plyer
```

### 2.6 改动

`gui.py` `_display_chat_message` 中添加约 10 行。

---

## 3. 大文件传输

### 3.1 需求

从聊天输入框旁的 `File` 按钮发送大于 500KB 的文件，接收方点击下载。

### 3.2 流程

```
发送方：
1. 选择文件 → 检查大小
2. <500KB → 现有小文件逻辑（Base64 嵌入消息）
3. >=500KB → 流式加密（MODE_FILE_STREAM）→ 保存到临时文件
4. POST /v1/files/upload → 服务器返回 token
5. 构造消息：{"type":"file","name":"video.mp4","size":...,"token":"abc","key":"<base64密钥>"}
6. 消息通过 WebSocket 发送

服务器（chat_server.py）：
1. POST /v1/files/upload — 接收加密文件内容，存入 /opt/zhprekey/files/<token>
2. GET /v1/files/download/<token> — 验证身份后返回文件内容
3. 文件 30 天后自动清理

接收方：
1. 收到消息 → 识别 type=="file" 且包含 token
2. 显示文件气泡：📎 video.mp4 (15.2MB) [下载]
3. 点击下载 → GET /v1/files/download/<token> → 用 key 解密 → 保存
```

### 3.3 文件加密

使用现有 `encrypt_file_stream` 流式加密，将文件完整读入后加密为内存 bytes 上传。接收方用对应密钥解密后写入磁盘。

### 3.4 新增服务器端点

```python
POST /v1/files/upload → 请求体 bytes 流，返回 {"token":"xxx"}
GET  /v1/files/download/<token> → Authorization Bearer，返回文件 bytes
```

### 3.5 文件存储位置

```
/opt/zhprekey/files/<token>
```

保存为原始加密 bytes，文件名无关。

### 3.6 清理

`chat_server.py` 的 `cleanup_loop` 每小时检查 `files/` 目录，删除超过 30 分钟的文件。

### 3.7 改动范围

| 文件 | 改动 |
|------|------|
| `gui.py` | `_on_chat_send_file` 增加大文件分支；新增 `_on_file_download` |
| `chat_server.py` | 新增 `upload_file` / `download_file` handler，清理逻辑 |
| `server.py` | 可选：也可直接走 Flask，但为简单直接放 WebSocket 进程 |

---

## 4. 实施顺序

| 步骤 | 内容 | 行数 |
|------|------|------|
| 1 | OTP 修复（1 行） | ~1 |
| 2 | 桌面通知（`_display_chat_message` + pip plyer） | ~30 |
| 3 | 大文件传输（服务端 + 客户端） | ~200 |
| 4 | 测试 + 部署 | — |
