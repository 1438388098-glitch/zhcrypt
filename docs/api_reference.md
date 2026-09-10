# core.py 公共 API 参考 (R16)

> 版本 3.2.0。所有 `decrypt_*` 失败统一抛 `core.DecryptionError`（参数/格式问题抛 `ValueError`）。

## 密文模式（magic `ZHCR`）

| 函数 | 说明 | 密文 mode |
|---|---|---|
| `encrypt_password_mode(text, password) -> bytes` / `decrypt_password_mode(packet, password)` | 口令对称加密（Argon2id + AES-256-GCM） | 0x01 |
| `encrypt_hybrid(plain, receiver_pub_pem) -> bytes` / `decrypt_hybrid(packet, priv_pem, passphrase)` | RSA-4096-OAEP 包裹 DEK 的混合加密 | 0x02 |
| `encrypt_hybrid_signed(...)` / `decrypt_hybrid_signed(...)` | 混合 + Ed25519 签名（返回 verified 字段） | 0x03 |
| `encrypt_pfs(...)` / `decrypt_pfs(...)` | X3DH 双 ECDH 前向安全（低阶点防护） | 0x04 |
| `encrypt_file_stream(path, password, ...)` / `decrypt_file_stream(...)` | 流式分块文件加密（内存 ≈ 单块 64KiB） | 0x05 |
| `encrypt_deniable(real, real_pwd, duress, duress_pwd) -> bytes` / `decrypt_deniable(packet, pwd)` | 可否认加密（劫持口令返回伪装内容） | 0x06 |
| `encrypt_file_password_mode(...)` / `decrypt_file_password_mode(...)` | 文件密码模式（R3 起委托 0x05 流式输出，兼容读旧 0x01） | 分派 |

## 工具与配套

| 函数 | 说明 |
|---|---|
| `packet_to_b64 / b64_to_packet` | 密文与 URL-safe Base64 互转（容忍粘贴空白） |
| `derive_key(password, salt, time_cost, memory_cost, parallelism)` | Argon2id 派生（越界统一钳制：time≤16、memory≤2GiB、乘积≤2GiB） |
| `x25519_ecdh / _x25519_exchange_checked` | X25519 ECDH（拒绝全零/低阶点共享秘密） |
| `ed25519_sign / ed25519_verify` | 签名与验签 |
| `should_stream(size_bytes)` | 文件是否走流式路径（`streaming.enabled`/`threshold_bytes` 可配） |
| `get_strength(password)`（strength.py） | 口令强度（支持中文/多语言字符集与词组口令） |
| `split_secret / recover_secret`（secretsharing.py） | Shamir 3-of-5（32 字节，超长拒绝、序号 1..5） |

## 密钥与会话（keys.py / ratchet.py / session.py）

| 函数 | 说明 |
|---|---|
| `KeyStore.generate_identity(name, passphrase)` | 生成 RSA-4096 + Ed25519 + X25519 三件套（Argon2id 包裹落盘） |
| `KeyStore.generate_prekey_bundle / upload` | X3DH 预密钥束（SPK 签名 + 50 枚 OTP 独立 nonce 包裹） |
| `KeyStore.import_peer_static_keys` | 对端公钥导入（自身拒绝/PEM 校验/TOFU 锚保护） |
| `KeyStore.export/import_public_key_bundle` | 公钥束（导出→peek→导入往返安全） |
| `ratchet.x3dh_initiate_session / x3dh_complete_session` | X3DH 握手（DH1-DH4，TOFU 签名公钥） |
| `ratchet.send_message / receive_message` | Double Ratchet（乱序 skipped keys 上限 100、FIFO 逐出、跳变钳制） |
| `session.save_session / load_session` | 会话加密落盘（固定 salt + 派生键缓存；损坏返回 None） |
