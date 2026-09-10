# zhcrypt 使用说明

zhcrypt 是一套端到端加密的中文通信系统，采用以下安全机制：

- **Argon2id** 密钥派生（默认 256MB 内存，抗 GPU/ASIC 暴力破解）
- **AES-256-GCM** 认证加密（防篡改、防密文特征泄露）
- **RSA-4096 + OAEP(SHA-512)** 混合加密
- **X3DH** 密钥协商 + **Double Ratchet** 双棘轮（前向安全）
- **安全识别码**（线下比对，防中间人）

## 安装

运行 `zhcrypt-setup.exe`，按安装向导完成。GUI 与 CLI 工具都会安装到程序目录，
并在开始菜单创建「zhcrypt GUI」入口与桌面快捷方式。

## 启动

- **GUI**：开始菜单「zhcrypt GUI」或桌面快捷方式。
- **CLI**：命令行运行 `zhcrypt.exe`。

## 基本使用

1. **创建身份**：首次启动设置主密码。该密码仅在本地经 Argon2id 派生密钥，
   不会上传服务器。
2. **确认对端**：通过「安全识别码」线下比对确认对端身份，完成 TOFU 信任绑定。
3. **加密通信**：发起聊天、发送文本与文件。
   - 小文件：密文内联于消息，可重复下载（不经服务器）。
   - 大文件：经服务器中转，下载一次即焚（阅后即焚）。
4. 通信全程端到端加密，服务器无法读取明文。

## 服务器

默认连接内置服务器。如需自托管，请修改服务器地址与认证配置
（认证令牌经环境变量 `ZHPREKEY_TOKEN` 注入，并需携带 `identity` 字段）。

自托管部署见 `docs/DEPLOY.md`（含 chat 服务与全量环境变量表）、
TLS 配置见 `docs/zhcrypt_nginx_tls.md`。

## 命令行速查

```bash
zhcrypt --help                 # 全部 29 个子命令
zhcrypt init 名字               # 创建身份
zhcrypt encrypt-file 文件       # 文件加密 (输出 .zhe)
zhcrypt chat                   # 端到端加密聊天 (TUI)
zhcrypt chat-safety -t 对端    # 查看与对端的安全识别码 (线下比对)
zhcrypt cert-pin https://域名  # 计算并固定服务器证书指纹
echo "密码" | zhcrypt strength --stdin   # 强度检测 (不进 shell 历史)
```

完整命令说明见 `docs/manual.md`。

## 安全提示

- 请使用**高强度密码**：弱密码（如 `woaini1314`）在本地可被字典攻击秒破。
- 务必**线下比对安全识别码**，防止中间人攻击。
- 大文件阅后即焚后无法再次下载，请接收方及时保存。
- 自托管直连（不经 Nginx）务必设 `ZHPREKEY_TRUST_PROXY=0`。

详见项目文档与 `docs/` 目录。
