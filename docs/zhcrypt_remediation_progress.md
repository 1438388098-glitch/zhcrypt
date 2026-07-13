# zhcrypt 安全修复进度

> 关联审计报告：`zhcrypt_security_audit_report.md`
> 测试安全网：`test_security_fixes.py`（新增）+ `test_all.py` + `test_x3dh_full.py`
> 最后更新：2026-07-10

## 本批已修复（已通过测试）

| # | 问题 | 修复 | 测试 |
|---|------|------|------|
| **#15** | `ensure_kem_keys` 生成的 `.x25519` 私钥文件格式与 `_unwrap_key` 解析格式不一致 → 自动生成的 X25519 私钥永远解密失败，聊天直接崩 | 抽出统一的 `_wrap_key_data()`（含 Argon2 参数头），`generate_identity` 与 `ensure_kem_keys` 共用 | `test_security_fixes.py` #15：自动生成后 `load_kem_private_key_pem` 成功解密 |
| **#2** | 身份名直接拼进文件路径，`../../` 可写任意目录 | 新增 `_validate_identity()` + `_validate_identity_arg` 装饰器，对所有接收 `identity` 的 `KeyStore` 方法做白名单校验（仅 `A-Za-z0-9_.@-`，禁 `..`/`/`/`\`，长度 1-64） | `test_security_fixes.py` #2：7 个恶意身份全部被拒；沙箱内验证无文件逃逸 |
| **#6** | `generate_prekey_bundle` 把**签名私钥**塞进上传 bundle，服务端还把它存进 DB | 客户端不再返回 `signed_prekey_priv`（本地 `.spk` 仍保留）；服务端 `upload_prekey` 移除存储私钥的代码块 | `test_security_fixes.py` #6：客户端 bundle 不含私钥；服务端（Flask 测试）即便误传也不存储 |
| **#14** | 启动日志打印 token 前 8 位 | `server.py` / `chat_server.py` 启动日志改为 `Auth Token: *** (已隐藏)` | 代码审查（无自动化测试） |
| **#1** | 消息发送者伪造：WebSocket `send` 用客户端自报 `msg["from"]`，且 REST `message_send` 用 `from` 作发送者/限流键，token 共享下可冒用他人身份、绕过限流 | ① WS：`chat_server.py` 强制 `msg["from"] = identity`（已认证连接身份）；② REST：`server.py` 发送者改以请求显式 `identity` 为准、`from` 被忽略，限流键改为真实客户端 IP（兼容 Nginx `X-Real-IP`/`X-Forwarded-For`） | `test_security_fixes.py` #1-REST：缺 `identity`→400；`from` 不成为存储发送者；换 `identity` 仍按同一 IP 限流(429)；WS 路径代码审查 |
| **#5** | X3DH 首次通信跳过 signed prekey 签名验证（TOFU 未落地），MITM 可冒充身份完成握手 | ① `generate_prekey_bundle` 在 bundle 中携带 Ed25519 签名公钥（公钥无密）；② `server.py` 的 `identities` 表新增 `signing_public_key` 列并随 `fetch_prekey` 返回；③ `chat_client._initiate_session` **始终校验** SPK 签名（不再静默跳过），首次接触将签名公钥固定为 TOFU，再次接触若公钥变化则拒绝（换钥/MITM 检测）；④ 响应方 `_handle_x3dh_init` 同样固定并检测对端签名公钥；⑤ 新增 `compute_safety_number` 供带外比对 | `test_security_fixes.py` #5：bundle 自验通过；首次握手固定 TOFU；SPK 签名被篡改拒绝；签名公钥突变(MITM)拒绝 |
| **#7** | 文件下载仅允许上传者本人，接收方拿不到自己收到的文件 | ① `chat_server.py` 的 `files` 表新增 `intended_recipient` 列；② 上传时记录预期接收方（GUI 已带上 `_chat_peer`）；③ 下载授权改为 `上传者 OR 预期接收方`（`can_download_file`）；④ 抽出 `record_file_upload`/`can_download_file` 便于测试 | `test_security_fixes.py` #7：上传者/接收方可下载、第三方不可、无接收方仅上传者可、不存在 token 拒绝 |
| **#10** | 消息速率限制按 `from` 计，攻击者切换 `from` 可无限发消息（消息轰炸/DB 膨胀） | 限流键改为真实客户端 IP（随 #1 REST 修复一并落地）；同时 `from` 不再决定发送者身份 | 随 #1-REST 一并覆盖测试（限流 429 + 上限拒绝） |
| **#13** | 源码注释/帮助文本硬编码公网 IP，源码泄露即暴露服务器地址 | 删除 IP，改为占位符 | `test_security_fixes.py` #13：扫描全部自研 `.py` 不再含真实 IP |
| **#14** | 启动日志打印 token 前 8 位 | `server.py` / `chat_server.py` 启动日志改为 `Auth Token: *** (已隐藏)` | `test_security_fixes.py` #14：源码扫描无 `AUTH_TOKEN[` 前缀打印，两服务器均打印 `***` |
| **#19** | WebSocket `handler(websocket, path)` 第二参数 `path` 在新版 `websockets`(11.0+) 已被移除，升级库后服务器无法启动 | 改为 `async def handler(websocket, path=None):`（`path` 未使用），同时兼容新旧两版库 | `test_security_fixes.py` #19：inspect 校验 handler 可仅以单参数(websocket) 调用 |
| **#20（审计外发现）** | 文件下载 `file_path = os.path.join(FILE_DIR, token)` 直接拼客户端传入的 `token`，含 `../` 可读 FILE_DIR 之外的任意文件（路径穿越, CWE-22） | 新增 `_resolve_file_path()`：仅允许 32 位十六进制 token（同 `secrets.token_hex(16)` 格式），且真实路径必须仍在 FILE_DIR 内；`file_download` 改用该函数 | `test_security_fixes.py` #1-WS 集成：路径穿越 token 与非法格式 token 均返回 404 |
| **#8** | Auth Token 明文存 `config.json`，机器/备份一丢即被冒充 | `config.py` 用本机 `device.key`（32B，权限 0600）以 AES-256-GCM 加密存储 token；旧明文 `auth_token` 在首次读取时自动迁移加密；新增 `auth_token_enc` 字段 | `test_security_fixes.py` #8：配置文件无明文 token、加密字段不含明文、可还原、缺设备密钥不可解密、旧明文自动迁移 |
| **#18** | 客户端不校验服务器证书指纹，持合法 CA 证书的流氓 MITM 仍可劫持 | 新增 `certpin.py`（`compute_cert_pin`/`verify_cert_pin`，SPKI SHA-256）；`chat_client._connect_ws` 在 wss 下强制证书固定，`_http_request` 在 REST 路径同样固定；`set-server --pin` / `cert-pin` 命令读写与诊断 | `test_security_fixes.py` #18：指纹计算/校验匹配+错误拒绝、配置读写 |
| **#3 / #4** | Prekey/WS 裸跑 HTTP/`ws://`，token 与内容明文 | ① 客户端 `_connect_ws` 的 `sslopt` 从 `{}` 改为 `cert_reqs=CERT_REQUIRED, check_hostname=True`（wss 必须校验 CA+主机名）；② `server.py` 支持 `ZHPREKEY_TLS_CERT`/`ZHPREKEY_TLS_KEY` 原生 TLS；③ 提供 `zhcrypt_nginx_tls.md` 宝塔 Nginx 反代（443 终止 TLS，/v1/chat 转发 5003）部署指南 | `test_security_fixes.py` #3/#4：`build_ws_sslopt` 对 wss 返回校验参数、ws 返回空 |
| **#5 残余** | 首次通信无带外安全号确认，用户无感知 MITM | `compute_safety_number` 已就绪；新增：CLI `chat-safety` 查看、`cmd_chat_send` 首次握手弹带外比对提示；GUI「🔒安全号」按钮 + 首次发消息弹窗核对 | `test_security_fixes.py` #5：安全号格式 12 组 5 位十六进制、确定性与输入敏感性 |

## 基线回归结果（修复未引入新问题）

```
test_all.py         38/38  PASS  (EXIT=0)
test_x3dh_full.py    25/25  PASS  (EXIT=0)
test_security_fixes.py 66/66  PASS  (EXIT=0)
   (累计已修: #1 #2 #3 #4 #5 #5残余 #6 #7 #8 #10 #13 #14 #18 #19 #20;
    评估无需改动: #9 #11 #12)
```

## 经评估无需改动（或属误报）

| # | 结论 |
|---|------|
| **#9** | `deserialize_private_key` 的"无密码回退"在当前架构下不可利用：密钥在磁盘上由 Argon2id+AES-GCM 包裹（`_unwrap_key` 先解密），本函数只处理内存中已解开的**未加密** PEM。改动反而可能破坏未加密 PEM 的加载，故保持原样。 |
| **#12** | 流式加密 nonce 使用 `struct.pack(">Q", chunk_index)`（uint64），2^64 块 × 64KB 远超出文件上限，**不存在 nonce 回绕**，属误报。 |
| **#11** | `_clear_bytes` 对 `bytearray` 实际有效；"虚假安全感"源于调用方对不可变 `bytes` 副本清零。属低价值加固，暂不改以避免引入风险。 |

## 待修复（低危，下一阶段）

| # | 问题 | 说明 |
|---|------|------|
| **#16** | HKDF 使用固定 salt | 低危；改需协议兼容（salt 随包传输） |
| **#17** | Shamir 用 secp256k1 质数 | 低危；迁移到标准安全质数需兼容旧份额 |

> 注：原「待修复」中的 #3/#4（TLS）、#8（Token 明文）、#18（证书固定）、#5 残余（带外安全号）
> 均已在本次修复完成，详见上方「本批已修复」表。至此审计发现的 19 个问题中，
> 仅剩 #16、#17 两个低危密码学项未处理（影响极低，且与协议兼容性耦合，建议下个迭代评估）。

## 运行方式

```bash
cd zhcrypt
python test_all.py              # 原有综合测试
python test_x3dh_full.py        # 原有 X3DH 回归
python test_security_fixes.py   # 本次新增：安全修复回归
```
