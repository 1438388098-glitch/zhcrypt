# zhcrypt v3.0 中文加密系统 — 用户手册

## 目录

1. [什么是 zhcrypt](#1-什么是-zhcrypt)
2. [安装与启动](#2-安装与启动)
3. [核心概念](#3-核心概念)
4. [场景一：自己加密自己看（密码模式）](#4-场景一自己加密自己看密码模式)
5. [场景二：带数字签名发消息（签名混合模式）](#5-场景二带数字签名发消息签名混合模式)
6. [场景三：前向安全通信（PFS 模式）](#6-场景三前向安全通信pfs-模式)
7. [场景四：加密文件（流式）](#7-场景四加密文件流式)
8. [场景五：备份和恢复密钥（Shamir）](#8-场景五备份和恢复密钥shamir)
9. [场景六：可否认加密（胁迫保护）](#9-场景六可否认加密胁迫保护)
10. [场景七：临时口令分享](#10-场景七临时口令分享)
11. [完整示例：两人通信](#11-完整示例两人通信)
12. [高级功能](#12-高级功能)
13. [完整命令参考](#13-完整命令参考)
14. [安全须知](#14-安全须知)
15. [常见问题](#15-常见问题)

---

## 1. 什么是 zhcrypt

zhcrypt v3.0 是一个**军事级中英文加密系统**，保护你的隐私数据：

- 加密文本/文件，只有知道密码的人能还原
- 用公钥体系安全通信，支持前向安全 (PFS)
- 数字签名防止消息伪造
- 可否认加密在胁迫下保护真实信息
- Shamir 密钥恢复防止私钥丢失

**完整密码学栈**:

| 层 | 算法 | 用途 |
|---|------|------|
| 签名 | Ed25519 | 防止消息伪造 |
| 密钥派生 | Argon2id (256MB) | 抗 GPU/ASIC 暴力破解 |
| 对称加密 | AES-256-GCM | 认证加密，防篡改 |
| 非对称加密 | RSA-4096-OAEP | 密钥包裹交换 |
| 前向安全 | X25519 ECDH (X3DH) | 私钥泄露后历史消息仍安全 |

---

## 2. 安装与启动

### 命令行模式

```batch
cd %USERPROFILE%\zhcrypt
zhcrypt --help      # 查看所有命令
zhcrypt info        # 查看系统信息
```

### 图形界面

GUI 由安装包的开始菜单「zhcrypt GUI」入口或 `zhcrypt-gui.exe` 启动
（CLI 无 `gui` 子命令, 直接运行 `zhcrypt` 不带参数进入交互式 shell）。

---

## 3. 核心概念

### 身份 (Identity)

v3.0 的每个身份包含 **三对密钥**：

| 密钥 | 算法 | 用途 |
|---|------|------|
| RSA 公/私钥 | RSA-4096 | 加密消息 |
| Ed25519 公/私钥 | Ed25519 | 数字签名 |
| X25519 公/私钥 | X25519 | 前向安全密钥交换 |

创建身份时三对密钥同时生成，一个密码保护所有私钥：

```batch
zhcrypt init default
```

私钥文件存储在 `~/.zhcrypt/keys/`：

```
default.pub         RSA 公钥 (明文)
default.key         RSA 私钥 (Argon2id + AES-GCM 加密)
default.ed25519     签名私钥 (加密)
default.ed25519.pub 签名公钥 (明文)
default.x25519      PFS 私钥 (加密)
default.x25519.pub  PFS 公钥 (明文)
default.meta        元数据 JSON
```

### 密码 vs 私钥密码

| 名称 | 什么时候用 | 谁设置的 |
|--- |--- |--- |
| **加密密码** | 密码模式加密文本/文件时 | 你随便设 |
| **私钥密码** | 保护你的私钥文件 | 创建身份时设的 |

### 密码强度检测

v3.0 输入密码时**自动评估强度**，并给出实时反馈：

```
输入密码: ****
密码强度: 弱 (15 bits)
[警告] 这是一个常见密码，极易被字典攻破
[警告] 密码太短 (建议 12 位以上)
```

也可以用命令单独测试：

```batch
zhcrypt strength <你的密码>
```

---

## 4. 场景一：自己加密自己看（密码模式）

最简单——只需一个密码，无需身份。

### 加密

```batch
zhcrypt encrypt "这是我的秘密信息"
```

### 解密

```batch
zhcrypt decrypt <密文>
```

### 特点
- 不需要创建身份
- 记一个密码就行
- 密码遗忘则数据**永久丢失**，任何人无法恢复
- 适合：记日记、存笔记、加密配置

---

## 5. 场景二：带数字签名发消息（签名混合模式）

用 Ed25519 签名防止消息伪造——接收方能**验证发送方确实是你**。

### 准备：两人创建身份并交换公钥

```batch
# 你
zhcrypt init alice
zhcrypt export-bundle

# 张三
zhcrypt init bob
zhcrypt export-bundle
```

**`export-bundle`** 导出包含 RSA + Ed25519 + X25519 三个公钥的完整束。

互换公钥束：

```batch
# 你导入张三的公钥束
zhcrypt import-bundle <张三的公钥束Base64> bob

# 张三导入你的
zhcrypt import-bundle <你的公钥束Base64> alice
```

### 发送签名消息

```batch
zhcrypt encrypt "张三你好" -t bob -s alice --sign
```

- `-t bob`：接收方
- `-s alice`：发送方（你用 alice 的 Ed25519 私钥签名）
- `--sign`：启用数字签名

### 接收方解密并验证

```batch
zhcrypt decrypt <密文> -s bob
```

输出显示：

```
来自: alice
[成功] 签名验证通过 ✅
============================================
张三你好
============================================
```

如果消息被篡改或伪造，会显示：

```
[警告] 签名验证失败 ⚠️
```

### 原理

```
你的消息 → Ed25519(你的私钥) 生成签名
         → RSA(张三的公钥) 加密
         → 输出密文

张三收到 → RSA(张三的私钥) 解密
         → Ed25519(你的公钥) 验证签名
         → 原文 + 验证结果
```

---

## 6. 场景三：前向安全通信（PFS 模式）

**核心优势**：即使私钥明天被偷，今天发的消息依然安全。

### 工作原理

PFS 通过 **X3DH 密钥交换协议** 实现：

```
每次加密时:
  1. 生成临时 X25519 密钥对 (用后立即销毁)
  2. 三重 ECDH 计算惟一共享密钥
  3. 用这个密钥加密消息
  
私钥泄露后:
  临时密钥已销毁 → 无法重算共享密钥 → 历史消息安全
```

### 配置 Prekey 服务器

PFS 需要一个 **prekey 服务器** 来托管临时公钥（已部署在阿里云）：

```batch
zhcrypt set-server https://YOUR_SERVER/prekey --token <你的token>
zhcrypt upload-prekey default --count 50
```

每次加密前自动从服务器拉取对方的临时公钥。

### 前置条件

- 双方都已创建身份（含 X25519 密钥）
- 双方都上传了 prekey 到服务器
- 使用 `export-bundle` / `import-bundle` 交换完整公钥束

---

## 7. 场景四：加密文件（流式）

v3.0 支持**流式分块加密**——大文件不会撑爆内存。

```batch
# 加密（>64KB 自动使用流式）
zhcrypt encrypt-file 合同.pdf
# → 输出 contract.pdf.zhs

# 解密（自动识别格式）
zhcrypt decrypt-file 合同.pdf.zhs
```

### 流式 vs 传统

| 特性 | 流式模式 (.zhs) | 传统模式 (.zhe) |
|---|------|------|
| 内存占用 | ~64KB | 文件大小 |
| 10GB 文件 | ✅ 可行 | ❌ OOM |
| 防篡改 | 逐块 AEAD 检测 | 整体检测 |
| 块损坏 | 仅损坏块不可读 | 全部不可读 |

> 小文件 (<64KB) 自动用传统模式，`--legacy` 强制传统。

---

## 8. 场景五：备份和恢复密钥（Shamir）

**防止私钥丢失导致所有历史消息无法解密**。

### 备份 (3-of-5)

```batch
zhcrypt backup default
```

输出 5 个份额：

```
份额 1: zhcrypt|default|1|a1b2c3d4e5f6...
份额 2: zhcrypt|default|2|8888...
份额 3: zhcrypt|default|3|9999...
份额 4: zhcrypt|default|4|aaaa...
份额 5: zhcrypt|default|5|bbbb...
```

同时生成 `~/.zhcrypt/keys/default.backup` 文件（加密的私钥备份）。

**保存建议**：

| 份额 | 保存位置 |
|---|------|
| 1 | 打印在纸上，放保险箱 |
| 2 | USB 闪存 |
| 3 | 加密云存储 |
| 4 | 信任的朋友 |
| 5 | 备用邮箱附件 |

### 恢复 (任意 3 份)

```batch
zhcrypt restore default
```

按提示输入 3 个份额，私钥恢复完成。

> `.backup` 文件也必须保留——份额恢复的是加密密钥，需要 `.backup` 来解密私钥。

---

## 9. 场景六：可否认加密（胁迫保护）

当被逼迫交出密码时，你可以交出**胁迫密码**，对方看到的是你准备好的**假内容**。

```python
# 编程接口（CLI 暂未集成）
packet = encrypt_deniable("真实消息", "真实密码",
                          "这是一段无害的假消息", "胁迫密码")

# 真实密码 → 真实消息
result = decrypt_deniable(packet, "真实密码")
# → {"text": "真实消息", "type": "real"}

# 胁迫密码 → 假消息
result = decrypt_deniable(packet, "胁迫密码")
# → {"text": "这是一段无害的假消息", "type": "duress"}
```

**关键**：
- 攻击者无法区分哪个是真实密码（两个都能解密）
- 假消息应有合理的语义内容
- 真实和假消息长度应接近

---

## 10. 场景七：临时口令分享

不需要创建身份、不需要交换公钥——生成一个随机中文词口令，把密文和口令一起发给对方。

```batch
zhcrypt encrypt "机密消息" --temp-share
```

输出：

```
=======================================================
  一次性密码: 晚霞·青山·流水·松柏
=======================================================

密文:
WkhDUgEBAAAA...

⚠ 此密码仅显示一次, 不会存储
```

对方收到密文和口令后：

```batch
zhcrypt decrypt <密文>
# 输入密码: 晚霞·青山·流水·松柏
```

---

## 11. 完整示例：两人通信

### Alice ←→ Bob (签名 + 前向安全)

```batch
# === Alice ===
zhcrypt init alice
zhcrypt set-server https://YOUR_SERVER/prekey --token <token>
zhcrypt upload-prekey alice --count 50
zhcrypt export-bundle    # 发给 Bob

# === Bob ===
zhcrypt init bob
zhcrypt set-server https://YOUR_SERVER/prekey --token <token>
zhcrypt upload-prekey bob --count 50
zhcrypt export-bundle    # 发给 Alice

# === Alice → Bob ===
zhcrypt import-bundle <Bob的公钥束> bob
zhcrypt encrypt "周末见?" -t bob -s alice --sign

# === Bob → Alice ===
zhcrypt import-bundle <Alice的公钥束> alice
zhcrypt decrypt <密文> -s bob
# → 来自: alice
# → 签名验证通过 ✅
```

---

## 12. 高级功能

### 自适应 Argon2id 参数

随着硬件进步，可以调高加密参数以保持安全：

```batch
# 查看当前参数
zhcrypt set-params

# 调至 512MB 内存 + 8 轮迭代（更安全，更慢）
zhcrypt set-params --time 8 --mem 512

# 恢复默认
zhcrypt set-params --time 4 --mem 256
```

**新参数只影响后续加密**，已有密文不受影响（密文中嵌入了解密所需参数）。

### 公钥束导出/导入（新版）

v3.0 推荐使用 `export-bundle`/`import-bundle`（包含三个公钥）：

```batch
zhcrypt export-bundle alice    # 导出完整公钥束
zhcrypt import-bundle <束> bob # 导入
```

旧版 `export`/`import` 仅导出 RSA 公钥，向后兼容但功能不全。

### Prekey 服务器部署

prekey 服务器部署在阿里云 ECS，通过 Nginx 反代提供服务：

```
https://YOUR_SERVER/prekey/v1/health  → 健康检查
https://YOUR_SERVER/prekey/v1/prekey/<identity>  → prekey 存储/获取
```

---

## 13. 完整命令参考

| 命令 | 用途 |
|------|------|
| `zhcrypt init [name]` | 创建身份 (RSA+Ed25519+X25519) |
| `zhcrypt list` | 列出所有身份 |
| `zhcrypt delete <name>` | 删除身份 |
| `zhcrypt encrypt "text"` | 密码模式加密 |
| `zhcrypt encrypt "text" --temp-share` | 临时口令加密 |
| `zhcrypt encrypt "text" -t bob -s alice --sign` | 签名混合加密 |
| `zhcrypt decrypt <cipher> [-s identity]` | 解密 (自动识别模式) |
| `zhcrypt encrypt-file <file> [--legacy]` | 加密文件 (流式) |
| `zhcrypt decrypt-file <file> [--overwrite]` | 解密文件 |
| `zhcrypt export <name>` | 导出 RSA 公钥 (旧版) |
| `zhcrypt import <key> <name>` | 导入 RSA 公钥 (旧版) |
| `zhcrypt export-bundle [name]` | 导出完整公钥束 |
| `zhcrypt import-bundle <data> <name>` | 导入完整公钥束 |
| `zhcrypt backup [name]` | 备份私钥 (Shamir 5份额) |
| `zhcrypt restore [name]` | 恢复私钥 |
| `zhcrypt strength [password] [--stdin]` | 测试密码强度 (建议省略 password 交互输入, 或 --stdin 管道) |
| `zhcrypt set-params [--time T] [--mem MB] [--par P]` | 设置加密参数 |
| `zhcrypt set-server <url> [--token T] [--pin 指纹]` | 配置 prekey 服务器与证书固定 |
| `zhcrypt upload-prekey [name] [--count N]` | 上传 prekey |
| `zhcrypt chat` / `chat-send` / `chat-poll` / `chat-history` / `chat-status` / `chat-delete` / `chat-safety` | 端到端加密聊天 (TUI 与 REST 工具) |
| `zhcrypt cert-pin <url>` | 计算并固定服务器证书指纹 |
| `zhcrypt export-bundle` / `import-bundle` | 完整身份捆绑导出/导入 |
| `zhcrypt info` | 系统信息 |

> 完整命令以 `zhcrypt --help` 为准; 图形界面见开始菜单「zhcrypt GUI」。

---

## 14. 安全须知

### 密码强度参考

| 密码类型 | 熵值 | GPU 集群破解时间 | 等级 |
|---|------|------|------|
| 6位纯数字 | ~20 bits | **秒级** | 弱 |
| 8位纯小写 | ~38 bits | ~14 年 | 中 |
| 8位混合字母数字 | ~41 bits | ~186 年 | 中 |
| 12位全键盘字符 | ~74 bits | **宇宙年龄级** | 强 |
| 6个中文汉字 | ~74 bits | 宇宙年龄级 | 极强 |

### 密码丢失 = 永久丢失

无后门、无找回机制、无云端恢复。这是安全设计原则。

### 私钥三重保护链

```
私钥文件 (.key)
  → 外层: Argon2id(256MB) 从密码派生密钥
  → 外层: AES-256-GCM 加密 PEM
  → 内层: PKCS8 无密码编码
```

### Shamir 恢复链

```
5 个份额 (任意 3 个)
  → 恢复 256-bit 加密密钥
  → 解密 .backup 文件
  → 得到原始私钥 PEM
  → 恢复私钥
```

---

## 15. 常见问题

**Q: 公钥能用几次？**
A: 无限次。

**Q: 加密后原文件还在吗？**
A: 在的，需手动删除。

**Q: 忘记密码怎么办？**
A: 没有任何办法恢复。建议用 Shamir 备份私钥。

**Q: 能加密多大文件？**
A: 流式模式无理论限制，传统模式受内存限制。

**Q: 中文密码支持吗？**
A: 完整 Unicode 支持（中文/Emoji/特殊符号）。

**Q: v2.0 的密文能兼容吗？**
A: v3.0 自动识别并解密 v2.0 的密文。

**Q: GUI 报错怎么办？**
A: `python -c "import tkinter"` 测试 Tkinter 是否安装。

**Q: prekey 服务器需要自己搭吗？**
A: 已部署在阿里云，直接配置即可。

**Q: 前向安全 vs 普通模式性能差异？**
A: PFS 每次额外 2 次 X25519 ECDH（~微秒级），无感知。
