# 更新日志 (Changelog)

## 3.1.0 (2026-08-01)

### 安全修复 (Security)
- **运行时升级**: Python 3.6.5 (EOL) + OpenSSL 1.0.2k → Python 3.13 + OpenSSL 3.x,
  消除 15+ 项已公开 CVE (CVE-2022-0778, CVE-2020-1971, CVE-2021-3712 等)。
- **依赖升级**: cryptography 40.0.2 → 50.0.0 (消除 13 项安全通告), argon2-cffi
  21.3.0 → 25.1.0, websocket-client 1.3.1 → 1.9.0。pip-audit: 0 已知漏洞。
- **服务端**: 拒绝存储任何私钥字段; REST 消息强制 identity 字段并忽略客户端
  from (防身份伪造); 消息限流改为按客户端 IP (防绕过); 日志不再打印 token 前缀。
- **TOFU 换钥**: 签名公钥与本地记录不一致时拒绝建立会话 (原为自动覆盖, 防 MITM 静默换钥)。
- **X3DH init 协议修复**: 握手消息现携带发送方自己的签名公钥 (原误放接收方公钥,
  导致响应方 TOFU/安全识别码错误)。
- **性能/DoS**: one-time prekey 改为单一 salt 派生, 首次会话解密耗时从 ~1 分钟
  降至 <1 秒; 消除 50 次 Argon2id(256MB) 串行派生的 CPU DoS 面。

### 打包与分发 (Packaging)
- 单一运行时目录 (GUI + CLI 双入口), 体积 88.14MB → 36.67MB (-58%)。
- 删除 api-ms-*/ucrtbase 冗余转发层; 排除 setuptools/pkg_resources/wheel/bcrypt
  等构建期残留 (含 CVE-2022-40897 等)。
- EXE 增加版本资源 (3.1.0); 生成 SHA256SUMS.txt 校验清单。
- 新增: SBOM.json (CycloneDX), buildinfo.json, requirements.lock.txt,
  THIRD_PARTY_NOTICES.txt, LICENSE, docs/ 完整文档。

### 修复的源码缺陷 (Bugs)
- keys.py: set_contact_display_name 引用未定义变量 (NameError)。
- secretsharing.py: 恢复时 rstrip 尾零导致约 1/256 概率恢复失败。
- core.py: 恶意数据包解析的崩溃面 (UnicodeDecodeError/IndexError)。
- websockets 17 兼容: ConnectionClosed 导入路径。

## 3.0.0
- 首次公开发布 (X3DH + Double Ratchet 聊天, 混合加密, Shamir 备份)。

## 3.1.0-hotfix1 (2026-08-01)
- 安全修复: 红队模拟发现密文头 Argon2id 参数未校验, 伪造 time_cost=2^24 可致解密无限卡死 (CPU DoS)。derive_key 统一钳制 time<=16 / memory<=2GiB / parallelism<=16, 越界回退默认并正常拒绝。
