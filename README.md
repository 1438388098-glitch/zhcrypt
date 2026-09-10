# zhcrypt

端到端加密中文通信系统。Argon2id 密钥派生 + AES-256-GCM 认证加密 + RSA-4096-OAEP-SHA512
混合加密 + X3DH/Double Ratchet 前向安全 + TOFU 安全识别码。

## 组件

| 组件 | 说明 |
|---|---|
| `zhcrypt.exe` | 命令行工具 (控制台) |
| `zhcrypt-gui.exe` | 图形界面 (tkinter) |
| `server.py` / `chat_server.py` | 自托管服务器 (Flask + websockets) |

## 快速开始

```bash
# 创建身份 (GUI 内同样支持)
zhcrypt init alice
# 加密 / 解密
zhcrypt encrypt "机密内容"
zhcrypt decrypt <密文>
# 聊天
zhcrypt chat-send -t bob "你好"
zhcrypt chat-poll
```

完整使用说明见 `manual.md` 与 `docs/` 目录 (含威胁模型、服务器部署、密钥备份恢复)。

## 安全特性

- **Argon2id** (RFC 9106 参数, 256MB 内存) — 抗 GPU/ASIC 暴力破解
- **AES-256-GCM** — 认证加密, 防篡改与密文特征泄露
- **RSA-4096 + OAEP(SHA-512)** — 混合加密
- **X3DH + Double Ratchet** — 前向安全 (会话密钥按消息推进)
- **TOFU 安全识别码** — 带外比对, 防中间人; 签名公钥突变即拒绝会话
- **证书固定 (SPKI pinning)** — 可选, 防 rogue CA

## 安全加固 (2026-08-13 授权审计)

本轮授权安全审计修复了以下问题, 已回归测试通过 (`test_all` 38/38、`test_security_fixes` 66/66、
`test_x3dh_full` 25/25、`test_chat` 18/18、单元测试 161 passed):

- **AEAD nonce 复用**: one-time prekey 批量包裹改用每份独立 nonce (原同 key+nonce 复用触发 GCM keystream 复用)。
- **prekey 身份所有权**: 服务端拒绝静默覆盖他人身份的签名公钥 (防预密钥投毒 / 冒充)。
- **路径穿越**: 流式文件解密输出名强制 basename 净化; 服务端/客户端全链路身份名白名单校验。
- **Argon2id 内存 DoS**: 增加 `memory×parallelism` 乘积钳制 (≤2GiB)。
- **限流绕过**: 消息限流键改用 `X-Real-IP` (不再信任可伪造的 `X-Forwarded-For`)。
- **临时口令熵**: 临时口令词表从 20 词扩至 256 词 (≈48 bit, 原 17.3 bit)。
- **Double Ratchet 消息号钳制**: 拒绝超大 `message_number` 跳变 (防 CPU DoS)。
- **本地密钥保护**: 文件 AES 密钥以本机 `device.key` 加密落盘; 私钥文件收紧 0600。
- **X25519 低阶点防护**: 拒绝全零共享秘密。

### 已知待办 (需协议版本升级, 列入下个大版本)

Double Ratchet post-compromise 自愈仅部分落地 (跨链乱序预存已实现,
完整重启动同步未做); 密文头 Argon2id 参数未纳入 GCM AAD (流式头靠
钳制兜底); HKDF 固定 salt; Shamir 标准安全质数; X3DH 显式 AD 绑定。
详见 `docs/autopilot_report.md` 遗留清单与 `RELEASE_NOTES_3.2.0.md`。

### 部署安全必做

- 生产环境必须启用 HTTPS/WSS + 证书固定:
  `zhcrypt set-server https://你的域名 --token <tok> --pin <指纹>`
- 服务器认证令牌仅经环境变量 `ZHPREKEY_TOKEN` 注入, 严禁提交到版本库。
- 5000 端口直连暴露 (无 Nginx) 时必须设 `ZHPREKEY_TRUST_PROXY=0`,
  否则客户端可伪造 `X-Real-IP` 绕过消息限流 (默认 1 为反代部署保持兼容)。
- 小规模/内网可启用原生 TLS (无需 Nginx, 见 `docs/zhcrypt_nginx_tls.md` 方案二):
  `ZHPREKEY_TLS_CERT=/path/cert.pem ZHPREKEY_TLS_KEY=/path/key.pem python server.py`

### 脚本化使用示例

```bash
# 密码不进 shell 历史: 管道输入检测强度
echo "你的密码" | zhcrypt strength --stdin
```

## 构建

```bash
py -3.13 -m venv packaging\buildenv
packaging\buildenv\Scripts\pip install -r requirements.lock.txt
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

产物: `packaging\dist\zhcrypt\` (含 SHA256SUMS.txt)。
依赖锁定: `requirements.lock.txt`; 软件物料清单: `SBOM.json`; 构建信息: `buildinfo.json`。

## 服务器部署

见 `docs/DEPLOY.md`。服务器认证令牌经环境变量 `ZHPREKEY_TOKEN` 注入,
客户端通过 `zhcrypt set-server <url> --token <token>` 配置。

## 许可

MIT (见 LICENSE)。第三方组件许可见 THIRD_PARTY_NOTICES.txt。
