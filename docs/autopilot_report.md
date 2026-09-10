# zhcrypt 自动迭代台账（autopilot R1-R15）

> 运行窗口: 2026-09-10 23:25 ~ 2026-09-11 04:30
> 每轮 10 个候选，共 15 轮 / 150 项候选全部闭环（含 3 轮验证实证型）。
> 验证门: 每轮三套件 + 全量 pytest；R13 打包实测；R14 真实双端 E2E。

## 批次总览

| 轮 | 主题 | 提交 | 重点 |
|---|---|---|---|
| R1 | 健壮性小修 | bafb226 | DecryptionError 去重/上传锁泄漏/os.replace/端点校验/LIKE 转义/pytest9 兼容 |
| R2 | 安全加固 | 78194f7 | 原生 TLS/WS 禁重复 auth/低阶点补齐/sig_len 校验/429 退避/X-Real-IP 开关 |
| R3 | 性能与体验 | 63cbe66 | 会话键缓存(每消息省一次 256MiB Argon2)/文件密码模式流式化/剪贴板自动清空 |
| R4 | CLI 可用性+并发 | 1f42c92 | --help 恢复/退出码/token_lock 失效/OTP 唯一索引/穿越校验 |
| R5 | 密钥边界+DB 维护 | 304a6e8 | import 三重守卫/设备密钥损坏告警/consumed OTP 回收/pair 索引/分页 rowid 决胜 |
| R6 | 客户端性能观测 | d278351 | GUI 后台线程化/config 缓存/should_stream/WS 配额/WS 测试/CHANGELOG |
| R7 | 边界输入崩溃面 | 6119647 | 截断包 ValueError/chunk_len 钳制/会话容错/目录逃逸白名单/spec sqlite3 |
| R8 | 协议健壮性+基建 | c446ac8 | 跨链乱序预存/首消息先验后进/Shamir 校验/原子写/CI 工作流 |
| R9-R10 | 文档发布收尾 | 2d991fc | 版本 3.2.0 单源/DEPLOY env 表/manual 双源/限流锁/混合线程化 |
| R11 | 运行时冒烟缺陷 | 311d4b5 | **P0 restore 双重修复**/getpass 挂死/accept 门禁/certpin 防线 |
| R12 | 静态扫描收尾 | 4a2acee | REST 固定 TOCTOU/队列实例隔离/词组熵/GUI 发文件线程化 |
| R13 | 打包构建实测 | efbccdd | buildenv 重建/build.ps1 BOM 修复/exe 级冒烟全过/isatty 误报修复 |
| R14 | E2E 双端实测 | b425378 | 13/13 互通/**O_BINARY 真 bug** 根治 |
| R15 | 发行重建+审计 | (本轮) | 3.2.0 发行包/pip-audit 零漏洞/SBOM/台账 |

## 高价值发现（既有审计未覆盖）

1. **P0 restore 不可用**（R11）: nonce 偏移 6→5 字节头 + 恢复 PEM 未重新包裹。
   冒烟实测复现 → 修复 → backup→删钥→restore 全链回归锁定。
2. **device.key O_BINARY**（R14）: Windows CRT 文本模式把随机密钥中的 0x0A
   翻译为 \r\n（约 12% 概率），32 字节变长 → 反复判损坏重生成、token 永久失配。
   由全量连跑的顺序性偶发暴露，O_BINARY 补齐后三连跑根治。
3. **_token_lock 守护锁失效**（R4）: `with threading.Lock()` 每次新建恒不阻塞，
   并发上传双写防护形同虚设。
4. **REST 证书固定 TOCTOU**（R12）: 校验连接与请求连接分离，重构为同连接
   握手后先验 pin 再发请求。
5. **分页同秒丢页**（R5）: Windows 时钟粒度下 server_ts 相同整页丢失，rowid 决胜。
6. **cli.spec 排除 sqlite3**（R7）: 打包后 `shell` 子命令必 ImportError。
7. **pytest 9 收集崩溃**（R1）: 根 __init__ 相对导入在 importlib 收集下炸，
   try/except 兜底 + conftest 双修复后裸 pytest 从必挂到 300+ 全过。

## 测试资产

| 资产 | 规模 | 运行方式 |
|---|---|---|
| 脚本式三套件 | 38+25+66 | `py -3.13 tests/run_core_tests.py` |
| pytest 集合（tests/ 全量） | 300+ | `py -3.13 -m pytest tests/ -q` |
| TUI 冒烟 / 登录屏 | 44+31 | `py -3.13 -m pytest tests/test_tui_smoke.py` 等 |
| 本地双端 E2E | 13 检查 | `py -3.13 tests/e2e_local_smoke.py` |
| 依赖审计 | 双 lock | `pip-audit -r requirements-{client,server}.lock.txt` |

## 遗留（协议级，建议下个大版本）

- 流式文件头字段未纳入 GCM AAD（当前靠参数钳制 + 块级认证兜底）。
- X3DH HKDF 未绑定双方身份公钥（AD 缺失，UKS 理论面）——以带外安全号比对缓解。
- HKDF 固定 salt（X3DH/chunk 派生）；Shamir 使用 secp256k1 质数。
- REST 证书固定已同连接化；WS 原生 TLS 仍建议反代终止。
- fileclient download 全量缓冲（2GB 上限时内存峰值高），可改流式。
- GUI 聊天文件传输旧管线与 send_file 双轨，建议并入。
