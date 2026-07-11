# zhcrypt 服务端 TLS / WSS 部署指南（修复审计 #3/#4）

> 目的：让客户端以 `https://` + `wss://` 访问服务端，启用传输层加密，
> 配合客户端 **证书固定（#18）** 与 **带外安全号核对（#5 残余）**，
> 彻底堵住「中间人替换 prekey bundle 劫持 X3DH 握手」的链路。

## 架构回顾

| 服务 | 进程 | 端口 | 协议 |
|------|------|------|------|
| Prekey / 消息 REST API | `server.py` (Flask) | 5000 | HTTP（由 Nginx 终止 TLS） |
| 聊天 WebSocket 中继 | `chat_server.py` (asyncio) | 5003 | WebSocket（由 Nginx 终止 TLS） |

客户端访问：
- REST：`https://你的域名/v1/...`  → Nginx → `127.0.0.1:5000`
- WS： `wss://你的域名/v1/chat`   → Nginx → `127.0.0.1:5003`

> ⚠️ 两个进程都要在后台常驻（建议用 systemd / 宝塔 计划任务 / supervisor）。
> 下面 Nginx 配置假设两者都已在本机监听 5000 与 5003。

---

## 方案一：宝塔面板（推荐，证书自动续期）

1. 宝塔「网站」→ 添加站点（你的域名，已解析到本机公网 IP）。
2. 「SSL」→ 申请 Let's Encrypt 证书，强制 HTTPS。
3. 在站点「配置文件」中，于 `server { ... }` 内插入以下反代规则
   （宝塔默认已生成 443 ssl 块，把 `location` 段加进去即可）：

```nginx
# ---- REST API (server.py:5000) ----
location /v1/ {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# ---- WebSocket 聊天中继 (chat_server.py:5003) ----
location /v1/chat {
    proxy_pass http://127.0.0.1:5003;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}

# ---- 80 -> 443 强制跳转（宝塔默认已有） ----
```

4. 安全组 / 防火墙放通 **443**（与 80）。5000、5003 仅监听本机，无需对外。

---

## 方案二：原生 TLS（无 Nginx，仅小规模/测试用）

`server.py` 已支持通过环境变量直接启用 HTTPS：

```bash
export ZHPREKEY_TLS_CERT=/path/fullchain.pem
export ZHPREKEY_TLS_KEY=/path/privkey.pem
export ZHPREKEY_PORT=5000
python server.py
```

> 注意：`chat_server.py`（WebSocket）仍走 ws，需另行在前面加 TLS 终止层
> （Nginx 或 stunnel）。**生产环境强烈建议用方案一（Nginx 统一终止 TLS）**。

---

## 启用证书固定（#18，关键一步）

TLS 仅防「无证书的中间人」；**证书固定** 能防「持合法 CA 证书的流氓中间人」。

1. 在已配好 HTTPS 后，用自带的诊断命令获取服务端证书指纹：

```bash
zhcrypt cert-pin https://你的域名
# 输出示例:
#   服务器 your.domain:443 的证书固定指纹:
#     AbCdEf...== (base64)
```

2. 把该指纹写入客户端配置（朋友安装后也要执行同样命令并填入）：

```bash
zhcrypt set-server https://你的域名 --token <你的TOKEN> --pin AbCdEf...==
```

此后客户端连接时会校验服务端证书公钥指纹，不匹配直接拒绝连接。

---

## 带外核对安全识别码（#5 残余）

即便 TLS + 证书固定都到位，**首次与某人建立会话时仍应核对安全识别码**：

- CLI：`zhcrypt chat-safety -t 对方身份`
- GUI：聊天界面「🔒安全号」按钮
- 首次发消息时客户端会自动弹出识别码，请通过**电话/当面**与对方比对是否一致。
  不一致即可能已遭中间人，切勿发送敏感信息。

---

## 上线前自检清单

- [ ] 服务端已用 HTTPS（443）对外，5000/5003 仅本机
- [ ] `zhcrypt cert-pin` 能取到指纹，且客户端已 `set-server ... --pin`
- [ ] 客户端 `wss://` 连接成功（旧版 `sslopt={}` 裸奔已修复）
- [ ] 双方首次会话完成安全识别码带外比对
- [ ] `config.json` 中 `auth_token` 为空、`auth_token_enc` 有值（#8 已加密）
