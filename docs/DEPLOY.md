# zhcrypt Prekey 服务器部署指南

## 部署到阿里云 ECS

服务器配置参考 INSTRUCTIONS.md 中的记录。

### 1. SSH 登录

```bash
ssh root@YOUR_SERVER_IP
```

### 2. 安装依赖

```bash
# Python 3 环境
apt update && apt install -y python3 python3-pip python3-venv git

# 创建虚拟环境
cd /opt
git clone https://github.com/your-username/zhcrypt-server.git  # 或手动上传
cd zhcrypt-server
python3 -m venv venv
source venv/bin/activate
pip install flask gunicorn
```

### 3. 配置 (server.py)

```bash
# 设置安全 token
export ZHPREKEY_TOKEN="your-secure-random-token-here"
export ZHPREKEY_EXPIRE_DAYS=7

# 测试运行
python server.py
# 访问 http://YOUR_SERVER_IP:5000/v1/health 确认返回 JSON
```

### 4. 通过宝塔面板配置 Nginx 反代

**宝塔面板 → 网站 → 添加站点** 或 **反向代理**：

- 目标 URL: `http://127.0.0.1:5000`
- 域名或二级目录: 例如 `prekey.YOUR_DOMAIN`
- 申请 SSL 证书 (Let's Encrypt)

**Nginx 配置（宝塔自动生成，关键部分）**：

```nginx
server {
    listen 443 ssl;
    server_name prekey.YOUR_DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 5. 配置为 systemd 服务

```bash
cat > /etc/systemd/system/zhprekey.service << 'EOF'
[Unit]
Description=zhcrypt Prekey Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zhcrypt-server
Environment=ZHPREKEY_TOKEN=your-token-here
Environment=ZHPREKEY_DB=/opt/zhcrypt-server/zhprekey.db
Environment=ZHPREKEY_EXPIRE_DAYS=7
# R5: 必须 -w 1 —— 上传会话/限流桶均为进程内状态, 多 worker 会绕过
# 并发与限流约束; 用线程扩展并发。
ExecStart=/opt/zhcrypt-server/venv/bin/gunicorn -w 1 --threads 8 -b 127.0.0.1:5000 server:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now zhprekey
systemctl status zhprekey
```

### 6. 客户端配置

部署完成后，在本机配置：

```bash
cd %USERPROFILE%\zhcrypt
zhcrypt set-server https://prekey.YOUR_DOMAIN --token your-token
zhcrypt upload-prekey default
```

### 7. 验证

```bash
# 服务端验证
curl https://prekey.YOUR_DOMAIN/v1/health

# 客户端验证
zhcrypt upload-prekey --dry-run
```

---

## 8. chat 服务 (zhchat-ws.service)

`chat_server.py` 是 WebSocket 聊天中继 (仅存加密信封, 不可读消息内容),
与 prekey 服务共用同一 DB 与 token。

### systemd 单元示例

```ini
[Unit]
Description=zhcrypt chat websocket server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zhcrypt-server
Environment=ZHCHAT_TOKEN=your-token-here
Environment=ZHCHAT_WS_PORT=5003
ExecStart=/opt/zhcrypt-server/venv/bin/python chat_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 环境变量总表

| 变量 | 默认 | 说明 |
|---|---|---|
| `ZHPREKEY_TOKEN` | (必填) | server.py 认证 token, 未设置启动即退出 |
| `ZHPREKEY_DB` | 脚本目录/zhprekey.db | SQLite 路径 (两个服务共用) |
| `ZHPREKEY_EXPIRE_DAYS` | 7 | 未消耗 prekey 保留天数 |
| `ZHPREKEY_TLS_CERT` / `ZHPREKEY_TLS_KEY` | (空) | 原生 TLS 证书/私钥 (两者都设置才启用) |
| `ZHPREKEY_TRUST_PROXY` | 1 | 是否信任 X-Real-IP; 直连暴露必须设 0 |
| `ZHPREKEY_PORT` | 5000 | 预留端口覆盖 (原生 TLS 部署时使用) |
| `ZHCHAT_TOKEN` | 回退 ZHPREKEY_TOKEN | chat_server 认证 token |
| `ZHCHAT_WS_HOST` / `ZHCHAT_WS_PORT` | 0.0.0.0 / 5003 | WS 监听地址与端口 |
| `ZHCHAT_FILE_DIR` | DB 目录/files | 文件存储目录 (两个服务共用) |
| `ZHCHAT_MAX_FILE_SIZE` | 2GiB | REST 分块上传单文件上限 |
| `ZHCHAT_DAILY_UPLOAD_QUOTA` | 500MB | WS 路径每身份每日上传配额 |

> 安全提醒: 生产环境经 Nginx 统一终止 TLS (443 → 5000/5003),
> 两个端口均只监听 127.0.0.1。
