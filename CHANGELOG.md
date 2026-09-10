# 更新日志 (Changelog)

## 3.1.x 自动迭代批次 (2026-09-10/11, autopilot R1-R6)

### 安全 (Security)
- **服务端**: prekey/message 端点身份白名单补齐; OTP 唯一索引 (防同一 one-time
  prekey 被两次握手消耗); WS 禁止已认证连接重复 auth 换绑; 每身份每日上传配额
  (ZHCHAT_DAILY_UPLOAD_QUOTA, 默认 500MB); X-Real-IP 信任开关
  (ZHPREKEY_TRUST_PROXY=0 供直连部署); 401/403 安全事件日志; health 探测 DB。
- **客户端**: import_peer_static_keys 三重守卫 (拒绝覆盖自身/PEM 合法性校验/
  TOFU 锚保护签名公钥); 损坏公钥束明确报错 (不再静默降级); device.key 损坏
  备份告警; backup/restore 身份名穿越校验; delete/chat-delete 二次确认。
- **密码学**: decrypt_pfs 补齐 X25519 低阶点防护; 签名字段恒 64 字节校验
  (防恶意 sig_len 切片错位); 文件密码模式改流式输出 (旧 0x01 格式仍可解)。

### 性能 (Performance)
- 会话文件固定 salt + 派生键进程内缓存: 每条聊天消息省一次 Argon2id(256MiB)。
- config.json mtime 缓存; messages 双向查询 pair 索引; files.size 统计配额。
- GUI 重操作 (RSA-4096 生成/Argon2id 加解密) 移入后台线程, 界面不再假死。

### 修复 (Bugs)
- pytest 9 收集兼容 (根 __init__ 相对导入兜底); zhcrypt --help 恢复;
  子命令退出码不再丢弃; _token_lock 守护锁失效 (并发上传双写面);
  上传会话回收释放互斥锁; os.rename→os.replace (Windows 覆盖);
  history 分页同秒消息丢页 (rowid 决胜); consumed OTP 与 files 元数据行清理;
  cleanup_expired.sh 端口 5002→5000 + 重试; requirements-server.lock 补
  gunicorn/websockets; save_file_key 不再明文回退; LIKE 通配符转义;
  Argon2 参数钳制两端统一; 剪贴板 60s 自动清空; 口令缓存 TTL 与禁用开关。

### 文档/运维 (Docs & Ops)
- 原生 TLS (ZHPREKEY_TLS_CERT/KEY) 兑现 nginx_tls 文档承诺; DEPLOY 改单
  worker (--threads 8); build.ps1 可选 ISCC 安装包步骤 + 安装包 SHA256;
  统一 should_stream 流式决策; CLI/GUI 版本文案引用 __version__;
  GUI/CLI/TUI/keys/server/session/core 新增 90+ 项回归测试。

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
