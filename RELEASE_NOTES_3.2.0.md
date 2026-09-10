# zhcrypt 3.2.0 发行说明

发布日期: 2026-09-11（自动迭代批次 autopilot R1-R15）
基线: 3.1.0 (2026-08-01) + 3.1.0-hotfix1

## 概要

本轮 15 个自动化迭代共完成 **142 项候选优化**，覆盖安全加固、协议健壮性、
性能、崩溃面修复、文档与发布工程。全部改动带回归测试（脚本式三套件
38+25+66，pytest 集合 300+，TUI 冒烟 45，本地双端 E2E 13 项检查全绿），
并通过 **打包实测**（PyInstaller 重建 + exe 级加解密往返 + GUI 探活）与
**真实双服务 E2E 互通实测**。

## 升级用户必读

- **强烈建议从 3.1.0 升级**: 3.1.0 发行包不含 2026-08-13 的 9 类安全修复，
  3.2.0 在其上再叠加本批全部加固。
- 新增环境变量（部署侧）: `ZHPREKEY_TRUST_PROXY`（直连暴露必须设 0）、
  `ZHPREKEY_TLS_CERT/KEY`（原生 TLS，兑现文档承诺）、
  `ZHCHAT_DAILY_UPLOAD_QUOTA`（WS 每身份每日上传配额，默认 500MB）。
- 文件密码模式 (`encrypt-file` 无 --legacy) 现输出流式格式 (0x05)；
  3.2.0 可解新旧两种格式，**3.1.0 无法解密新格式**——升级请双端同步。
- CLI 新增: `--help` / `--version` / `strength --stdin` / `delete -y` /
  `restore -y`；`restore` 现会要求为恢复的身份设置新口令（P0 修复的一部分）。

## 重点安全修复（本批新增，前次审计未覆盖项）

- **P0**: `restore` 双重缺陷（nonce 偏移 + 恢复 PEM 未重新包裹）导致
  备份恢复整体不可用——实测复现后修复并补全链回归。
- **真 bug**: `device.key` 写入缺 `O_BINARY`，随机密钥含 `\n`（约 12% 概率）
  被文本模式翻译损坏 → 反复"判损坏重生成"、token 永久失配。
- REST 证书固定改为同连接先验后发（消除 TOCTOU 选择性劫持面）。
- 好友 accept 门禁：垃圾对端无法单方面成为好友。
- OTP 唯一索引：同一 one-time prekey 不再可能被两次握手消耗。
- 流式解密 `chunk_len` 钳制：恶意密文不再可诱导近 4GiB 内存分配。
- 五个 `decrypt_*` 对截断包统一抛 `ValueError`（不再 struct.error/IndexError 逃逸）。
- `decrypt_pfs` 补齐 X25519 低阶点防护；签名字段恒 64 字节校验。
- 会话目录身份白名单（防 `../` 逃逸列举/删除）；端点身份白名单补齐。

## 性能

- 每条聊天消息节省一次 Argon2id(256MiB) 派生（会话文件固定 salt + 键缓存）。
- GUI 全部重操作（身份创建/文本与文件加解密/混合模式/聊天发文件）后台线程化。
- config.json mtime 缓存、messages 双向索引、限流桶线程锁。

## 完整清单

见 `CHANGELOG.md` 3.2.0 段与 `docs/autopilot_report.md`（15 轮问题→修复→验证台账）。

## 验证状态

| 验证 | 结果 |
|---|---|
| 脚本式三套件 (test_all / x3dh / security_fixes) | 38+25+66 全过 |
| pytest 集合（单元/端点/协议边界/修复回归） | 300+ 全过 |
| TUI 冒烟 + 登录屏 | 44+31 全过 |
| 本地双端 E2E（真实服务进程） | 13/13 |
| 打包实测（exe 级加解密往返、GUI 探活） | 全过 |
| pip-audit（双 lock） | 0 已知漏洞 |

## 已知遗留（协议级，需下个大版本）

- Double Ratchet 实际轮转（post-compromise 自愈）部分落地（跨链乱序预存已实现）。
- 密文头 Argon2id 参数未纳入 GCM AAD（流式头字段无认证，靠钳制兜底）。
- HKDF 固定 salt（X3DH/chunk）；Shamir 使用 secp256k1 质数。
- X3DH 无显式 AD 绑定（UKS 理论面，需带外安全号比对缓解——已内置）。
