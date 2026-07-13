# 聊天模块优化设计文档（Tier 1 + Tier 3）

> 目标：把"开始聊天"的用户步骤从 5 步降到 ≤2 步，消除手动公钥束导出/导入；
> 连接状态改为事件驱动，握手失败给出明确可操作原因，同时**不削弱任何加密语义**。
>
> 范围：chat 模块 UX 简化（Tier 1）+ 体验润色（Tier 3）。
> 加密协议（X3DH / Double Ratchet）、服务器 auth 模型、tkinter 框架均不变。

---

## 0. 问题基线（实测依据）

### 0.1 "复杂"的来源
- **5 步手动引导**：配服务器 → 建身份 → 互相导出/导入公钥束（复制粘贴）→ 去「系统配置」上传 Prekey → 回聊天 Tab 连接（`_on_chat_setup_guide`，gui.py:1223）。
- **公钥交换全靠 copy-paste**：`_on_chat_connect`（gui.py:1292）发现本地无对方公钥就弹窗让你去「密钥管理」手动导出/导入。
- **Prekey 上传是孤立动作**：在「系统配置」单独做（gui.py `_on_upload_prekey`:1019），且**不会自动续传**。001 那次就是老 bundle 缺 `signing_public_key` 导致对方握手失败，用户毫无感知。
- **每次连接重输密码**，切身份/重连全得再敲。
- **功能散在多 Tab**：聊天 / 密钥管理 / 系统配置 / Prekey 各管一摊。

### 0.2 "不稳定"的来源
- **轮询硬超时**：`_check_chat_connected`（gui.py:1358）每 2s 查一次，最多 5 次即判"连接失败"；WS 握手稍慢或后台重连中就直接报死。
- **"连上了"≠"能发"**：X3DH 握手被推迟到**首次发消息**才做（chat_client `_initiate_session` 由 `send_chat_message` 调用），用户看到"已连接"一点发送才爆错误，割裂。
- **queue 双消费**：`_check_chat_connected` 与 `_poll_chat` 都调 `process_inbound()`，存在重复消费隐患。
- **断开后每 2s 跑 REST 兜底**：WS 没真恢复时会不停刷错。
- **Token 机器绑定**：新机器/朋友机 `device.key` 对不上 → token 解密成空 → "无效 token" → 连接失败，但提示看不出原因。

### 0.3 已确认的有利事实（减少改动量）
- 服务器 `GET /v1/prekey/<peer>` **已返回** `identity_key_pub`、`signed_prekey_pub`、`signed_prekey_sig`、`signing_public_key`、`one_time_prekey`（实测 001 拉取可见）。
- WS 线程已通过 `INBOUND.put({"action":"status","connected":...})` 推送连接状态（chat_client.py:165 / 232），`_poll_chat`（gui.py:1402）已处理 `status` 事件 → **事件驱动基座现成**。
- 服务器有 `GET /v1/prekey/remaining/<id>`（server.py:369）返回剩余 OTP 数 → 可用于"自身 prekey 是否还有效"的健康检查。

### 0.4 ⚠️ 关键约束（设计必须服从）
> **`GET /v1/prekey/<id>` 每次调用都会消耗一个 one-time prekey**（server.py:280-293，SELECT 一条 unconsumed → UPDATE consumed=1）。
> 因此：自动拉取"对方静态公钥"**不能复用现有 GET**，否则每连一次烧一个 OTP，7 天过期 + 池耗尽会让握手失败。
> 解法：新增一个**不消耗 OTP**的只读端点专门取静态公钥（见 T1-2）。OTP 只在**真实握手**时消耗。

---

## 1. 设计目标 / 非目标

**目标**
1. 用户动作收敛到：选身份 + 选/填对方 ID → 自动完成服务器配置检查、自身 prekey 续传、对方公钥拉取、握手。
2. 删掉"手动导出/导入公钥束"为必经步骤（降级为高级/离线入口）。
3. 连接状态事件驱动，无 5 次轮询硬失败；握手失败因明确、可操作。
4. 密码会话内记忆，少重输。

**非目标**
- 不改 X3DH / Double Ratchet 协议与密钥语义。
- 不改服务器 token 认证模型（仍是证书固定 + Bearer token 双认证）。
- 不换 UI 框架（仍 tkinter），不做移动端。

---

## 2. Tier 1 设计

### T1-1　连接即自动握手上 Prekey

**意图**：把"上传 Prekey"从独立手动步骤，变成连接时的静默自检；并把 X3DH 握手前移到连接阶段，让失败尽早暴露。

**连接时序（新）**
```
用户: 选身份 + 选/填对方 ID → 点"连接"
  │
  ├─(T1-3) 取密码（会话内已缓存则跳过）
  ├─(T1-1) ensure_own_prekey():
  │        GET /v1/prekey/remaining/<id>
  │        if remaining < 阈值(默认10): 自动 generate_prekey_bundle + POST 上传
  │        （需密码，已在上面拿到）
  ├─(T1-2) fetch_peer_meta():
  │        GET /v1/prekey/meta/<peer>  → 导入对方静态公钥 + TOFU
  │        404 → 提示"对方尚未上传 Prekey，请提醒对方先连接一次"
  ├─ WS 连接（事件驱动，见 T1-4）
  └─ 状态栏: "已连接 · 公钥就绪"
首次发送消息时: _initiate_session(peer) 消耗 1 个 OTP 完成 X3DH 握手
```

**改动点**
- `chat_client.py`：
  - 新增 `ensure_own_prekey(threshold=10)`：封装 `GET remaining` + 条件 `POST /v1/prekey/<id>`（复用 `generate_prekey_bundle` 逻辑）。
  - `connect(peer)` 增加 `auto_handshake=False` 参数：连接成功后调用 `_initiate_session(peer)` 并把结果（成功/失败原因）通过 `INBOUND` 推一条 `{"action":"handshake","ok":bool,"reason":str}`。
- `gui.py._on_chat_connect`：
  - 去掉"缺少对方公钥 → 去手动导入"的硬阻断，改为"正在自动拉取对方公钥…"。
  - 连接成功后立即展示握手状态（而非等首次发送）。
- 失败文案分级（复用已改的 signed-prekey 分支逻辑）：
  - token 为空/无效 → "连接失败：本地未配置 token，请在系统配置填入（朋友机需重填）"
  - 服务器不可达 → "连接失败：服务器地址错误或网络不通"
  - 对方未传 prekey → "对方尚未上传 Prekey，请提醒对方先连接一次"
  - 签名自验失败 → 保留"疑似篡改，请带外核对安全码"

**风险/回退**：自动上传 prekey 只在 remaining 低时触发，正常连接不额外传；若上传失败仅告警，不阻断聊天（对方仍能用缓存 session）。

---

### T1-2　对方公钥自动拉取（去掉手动导出/导入）

**意图**：本地无对方公钥时，自动从服务器拉取并导入，删掉 copy-paste 公钥束这一步。

**⚠️ 端点约束处理（对应 0.4）**
- 新增服务器端点 `GET /v1/prekey/meta/<id>`：
  - 返回静态公钥：`identity_key_pub`、`signed_prekey_pub`、`signed_prekey_sig`、`signing_public_key`、`has_more_otp`。
  - **不消耗任何 OTP**（只读 SELECT，不 UPDATE consumed）。
  - 复用现有速率限制 `_check_prekey_rate_limit`。
  - 404（无 signed prekey）即"对方未上传 prekey"。
- 真实 OTP 仅在 `_initiate_session` 走原 `GET /v1/prekey/<id>`（消耗 1 个）时取得 → 只在真正握手消耗，重连 resumé 不浪费。

**客户端缓存与落盘**
`keys.py` 新增 `fetch_and_store_peer_bundle(peer, meta)`：
| 来源字段 | 落盘文件 | 用途 |
|---|---|---|
| `identity_key_pub` (X25519) | `<peer>.x25519.pub` | X3DH DH 身份密钥 |
| `signed_prekey_pub` (X25519) | `<peer>.spk.x25519.pub` | X3DH signed prekey |
| `signing_public_key` (Ed25519) | `<peer>.ed25519.pub` | 签名验证 / 安全码 |
| TOFU 固定值 | `<peer>.tofu.ed25519.pub` | 首次固定（沿用 `store_tofu_signing_pub`） |

- 仅在**本地无缓存**或用户显式"刷新对方公钥"时调用 meta 端点。
- 导入后复用 `_initiate_session` 现有验签逻辑（已含 bundle 自带公钥自验 + 旧版回退分支）。
- 安全：首次仍计算安全识别码并提示**带外核对**（保持 TOFU 价值）；TOFU 冲突按已改逻辑平滑更新（服务器证书固定+token 双认证可信）。

**涉及改动**
- `server.py`：新增 `GET /v1/prekey/meta/<id>` 路由（含证书固定与速率限制，与现有端点一致）。
- `keys.py`：新增 `fetch_and_store_peer_bundle`。
- `chat_client.py`：新增 `fetch_peer_meta(peer)`（REST，证书固定）。
- `gui.py`：连接流程用自动拉取替代手动导入弹窗；「密钥管理」的导出/导入保留为"高级/离线"入口。

**向后兼容**：旧 `.pub / .ed25519.pub / .x25519.pub` 文件格式不变；`<peer>.spk.x25519.pub` 为新文件，旧客户端忽略无害。

---

### T1-3　密码会话内记住

**意图**：少重输密码。

- 聊天 Tab 连接区加勾选「本次记住密码」（默认勾选）。
- `gui` 维护内存字典 `self._cached_passphrase[identity]`；连接成功即缓存；切身份或显式"退出"清空。
- 已缓存则不弹 `simpledialog`，直接复用。
- **安全**：密码仅驻内存（与现有 `ChatClient._passphrase` 同级），不落盘、不写日志。

---

### T1-4　连接状态事件驱动

**意图**：去掉 5 次轮询硬失败 + queue 双消费，改为事件驱动。

**改动**
- 删除 `_check_chat_connected`（gui.py:1358）中的 5 次重试轮询及其内部的 `process_inbound()` 重复消费。
- `_on_chat_connect` 在 `start()` 后立即调用 `self._poll_chat()`（原本要等连接成功才启动），由 `_poll_chat` 的 `status` 事件分支（gui.py:1433）更新状态栏。
- 加**单发 watchdog**：连接后 8s 仍未收到 `connected=True` 状态 → 状态栏显示「连接失败：服务器不可达 / 地址错误」，并给可操作提示（去系统配置检查地址）。一个 `after` 定时器，非循环轮询。
- REST 兜底只在 WS 真断开（`connected=False`）时启用，且**静默**（不每 2s 刷错到聊天窗，仅状态栏小字提示）。

**效果**：握手慢/后台重连不再误报失败；连接状态实时、准确；queue 单一消费者。

---

## 3. Tier 3 设计

### T3-8　设置聚合（聊天 Tab 内嵌"设置"折叠区）

**意图**：减少切 Tab 的动线。

- 聊天 Tab 顶部或底部加一个 `ttk.LabelFrame("设置 ▸")` 折叠区（默认收起），内嵌：
  - 服务器地址（只读展示 + 「去修改」跳转系统配置）
  - 当前身份 + 「上传 Prekey」按钮（直接触发 `_on_upload_prekey` 逻辑，不再跑系统配置 Tab）
  - 对方公钥来源状态（自动拉取 / 手动导入 / 未就绪）
- 「密钥管理」的导出/导入公钥束仍保留（T1-2 后作为高级/离线入口）。

### T3-9　一步式首次引导向导

**意图**：新用户第一次打开即走完所有前置，不用看那份 5 步说明。

- 首次运行（检测 `~/.zhcrypt/config.json` 无 `default_identity` 或 identities 为空）自动弹出向导：
   1. 服务器地址（预填默认服务器，可改）
  2. 创建/选择身份 + 密码（自动 `ensure_kem_keys` + 自动传 prekey，复用 T1-1）
  3. 输入对方 ID（自动拉公钥，复用 T1-2）
  4. 自动握手 + 弹窗显示安全识别码并提示带外核对
  5. 进入聊天
- 向导复用现有 `store` / `config` / `ChatClient` 方法，**不引入新存储格式**。
- 老用户不弹（已有 identity），仍可随时从「?」按钮重看引导。

---

## 4. 影响面与改动清单

| 文件 | 函数 / 区域 | 改动类型 |
|---|---|---|
| `gui.py` | `_build_chat_tab` | 增加「记住密码」勾选 + 设置折叠区（T3-8） |
| `gui.py` | `_on_chat_connect` | 重构为自动链路（T1-1/1-2/1-3），去掉手动导入硬阻断 |
| `gui.py` | `_check_chat_connected` | **删除**，改由 `_poll_chat` 事件驱动 + 单发 watchdog（T1-4） |
| `gui.py` | `_poll_chat` | 静默 REST 兜底；处理新增 `handshake` 事件（T1-1/1-4） |
| `gui.py` | 新增 | 首次向导 `FirstRunWizard`（T3-9） |
| `chat_client.py` | `connect` / `__init__` | 支持 `auto_handshake`、推 `handshake` 事件（T1-1） |
| `chat_client.py` | 新增 | `ensure_own_prekey`、`fetch_peer_meta`（T1-1/1-2） |
| `keys.py` | 新增 | `fetch_and_store_peer_bundle`（T1-2） |
| `server.py` | 新增路由 | `GET /v1/prekey/meta/<id>`（不消耗 OTP）（T1-2） |

---

## 5. 安全与兼容性

- **加密不降级**：TOFU 固定、证书固定、token 双认证全部保留；对方公钥自动拉取仍依赖"证书固定 + token 认证"的服务器，且首次提示安全码核对。
- **OTP 消耗约束**：meta 端点只读不消耗；OTP 仅在真实握手消耗（每次新握手 1 个，合理；7 天过期 + 自动续传兜底）。
- **密码仅内存**：与现状同级，不落盘。
- **向后兼容**：旧手动导入文件格式不变；新缓存文件旧客户端忽略；旧手动流程仍可用。

---

## 6. 测试与验收

- **单元**：`ensure_own_prekey`（mock remaining→上传）、`fetch_peer_meta`（mock meta 端点、缓存落盘正确、不消耗 OTP）、`fetch_and_store_peer_bundle` 字段映射。
- **端到端**：001 ↔ lhqdesuwa 走新流程：自动拉对方公钥成功 → 连接 → 首次发送握手一次成功 → 无 MITM 误报；断线重连 resumé 正常。
- **回归**：旧手动导出/导入公钥束流程、旧「上传 Prekey」按钮仍可用。
- **OTP 校验**：连续连接 5 次但不发消息，确认 `remaining` 不因自动拉取而下降（验证 meta 端点不消耗）。

---

## 7. 实施顺序建议

1. **T1-4**（最低风险，立刻提升连接稳定性）
2. **T1-2**（需 server 改动，但降复杂度收益最大）
3. **T1-1**（握手前移 + 自身 prekey 自动续传）
4. **T1-3**（密码记忆）
5. **T3-8**（设置聚合）
6. **T3-9**（首次向导）

> 注：T1-2 的 `GET /v1/prekey/meta/<id>` 需在**服务器** `/opt/zhprekey/server.py`（prekey 服务，非 WS）同步新增并重启对应 prekey 服务才生效（线上代码与本地是两份独立副本，这是历史铁律）。

---

## 8. 实现记录（与设计的偏差 & 部署说明）

> 代码已落地（gui.py / chat_client.py / keys.py / server.py 全量 py_compile 通过、gui.py 无 lint）。

### 8.1 关键偏差：T1-1「连接时握手」不可行 → 改为「连接时自检 + 首次发送握手」
- **原因**：X3DH 发起会话**必须伴随发出第一条消息**（init 消息要送达对端才能完成握手），协议上无法在"连接但未发消息"时空握手。原设计"连接即握手"不成立。
- **实际实现**：连接时只做**安全的自身 prekey 自动续传**（`ensure_own_prekey`：GET remaining，不足自动重传）；握手仍挂在首次发送（`send_chat_message` → `_initiate_session`），但错误提示已做明确分级（token 空 / 服务器不可达 / 对方未传 prekey / 签名自验失败）。
- **额外收益**：`_initiate_session` 验签通过后新增 `_cache_peer_keys`，把对端静态公钥缓存到本地（`<peer>.x25519.pub` / `.spk.x25519.pub` / `.ed25519.pub`），对方自动出现在联系人列表，安全码可离线计算。

### 8.2 T1-2「对方公钥自动拉取」双路径
- 新增服务器 `GET /v1/prekey/meta/<id>`（只读，不消耗 OTP，从 `identities` 表取静态公钥）。
- 客户端 `fetch_peer_meta` 在连接后**后台线程**调用：端点存在→拉取并 `import_peer_static_keys` 缓存（不消耗 OTP）；端点不存在(404/405)或对方未注册→**优雅降级**（提示"发起聊天时将自动完成密钥交换"），不阻断；首次发送握手走原 GET 自动补全。
- 对方 ID 选择器改为 `state="normal"` 可输入，去掉"缺少对方公钥→强制手动导入"硬阻断。

### 8.3 T1-4 事件驱动
- 删除 `_check_chat_connected` 的 5 次轮询及其内部 `process_inbound` 重复消费（修复 queue 双消费隐患）。
- `_on_chat_connect` 直接启动 `_poll_chat`（WS 线程本就 push status 事件），加**单发 10s 看门狗**给出明确失败原因；连接成功取消看门狗、标记 `_ever_connected`。
- REST 兜底仅在 `_ever_connected`（曾连上又断开）时启用，避免初始建链阶段每 2s 刷错。

### 8.4 待办（部署 & 手动验证）
- **服务器部署**：`server.py` 新增的 `meta` 端点须同步到 `/opt/zhprekey/server.py` 并重启对应 prekey 服务（与 WS 是两个进程）；未部署时客户端自动降级，功能不受影响。
- **手动验证**：001↔lhqdesuwa 走新流程（直接输入对方 ID→连接→发送首条消息）验证自动握手 + 无 MITM 误报；断线重连 resumé；密码"记住"勾选；设置折叠区；首次向导（清空 identities 触发）。
- **未自动化测试**：GUI 交互与 WS 联调需真机/真服务器手动跑；已离线单测 `import_peer_static_keys` 文件映射正确。
