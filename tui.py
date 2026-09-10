"""
zhcrypt-chat Textual TUI v1.0
=============================
职责: 会话列表 / 聊天窗口 / 消息渲染 / 命令解析 / 文件收发调度 / 状态栏

入口: main(identity, passphrase) -> int  (由 cli.py `chat` 子命令调用)

线程模型 (设计文档 §4):
  后台线程 C (Binder): 50ms 轮询 chat_client.INBOUND 全局队列, 调用
    receive_chat_message 解密 → LocalStore 落库 → app.post_message(NewMessage...)
  后台线程 B (文件 Worker): /send /download 在独立线程执行, 进度经
    Progress 消息投递到 UI (App.post_message 线程安全)
  主线程: Textual 事件循环, 只做 UI 与本地调度, 不阻塞

依赖契约 (AGENTS.md §2):
  chat_client.ChatClient / INBOUND / OUTBOUND / init_client (现有)
  chat_client.send_file / download_file (Agent-B 追加, 未就绪时优雅降级)
  localstore.LocalStore (Agent-C, 未就绪时 main() 返回错误码)
  fileclient.FileClient (Agent-B, 未就绪时 main() 返回错误码)
  config.get_prekey_server / get_auth_token

消息渲染 (设计 §5.3 / §8.1):
  [HH:MM] <对方身份> <状态前缀>
  <正文>   (自己消息整行右对齐缩进)
  前缀: 🕐 发送中 / ✓ 已送达 / ✓✓ 对方已收到且验签通过 / ⚠ 失败或验签失败
"""

import os
import re
import sys
import json
import time
import queue
import hashlib
import threading

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import (Button, Checkbox, Footer, Header, Input, Label,
                             ListItem, ListView, Static)
from textual import on

from chat_client import ChatClient, INBOUND, OUTBOUND, init_client
from core import urlsafe_b64decode

# localstore / fileclient 由其他 Agent 并行产出; 未就绪时优雅降级,
# main() 会给出明确错误信息, 保证 `import tui` 本身永不失败。
try:
    from localstore import LocalStore, LocalStoreError  # noqa: F401
except ImportError:  # pragma: no cover - Agent-C 尚未产出
    LocalStore = None
    LocalStoreError = RuntimeError
try:
    from fileclient import FileClient, FileClientError  # noqa: F401
except ImportError:  # pragma: no cover - Agent-B 尚未产出
    FileClient = None
    FileClientError = RuntimeError
try:
    from config import get_prekey_server, get_auth_token
except ImportError:  # pragma: no cover
    get_prekey_server = lambda: ""
    get_auth_token = lambda: ""

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

BINDER_INTERVAL = 0.05            # Binder 轮询间隔 50ms
MAX_VISIBLE = 200                 # 消息虚拟化: 只渲染最近 200 条
MAX_HISTORY = 200                 # /history 单次拉取上限
DEFAULT_HISTORY = 50              # /history 默认条数
AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
FILE_CHUNK_SIZE = 1 << 20         # 分块 1MB (与设计 §6.2 一致)
# 身份名白名单 (与 keys.py `_IDENTITY_RE` 严格一致: 防路径穿越 + URL 安全;
# 登录屏 / /add / /open 三处统一。注意: 不支持中文身份名, 与 keys 层校验一致)
IDENTITY_RE = r"[A-Za-z0-9_.@-]{1,64}"
_SAFE_NAME_RE = re.compile(r"^[\w.\-]+$")
_WINDOWS_RESERVED = ({"CON", "PRN", "AUX", "NUL"}
                     | {f"COM{i}" for i in range(1, 10)}
                     | {f"LPT{i}" for i in range(1, 10)})

# ---------------------------------------------------------------------------
# 纯函数 (可单测)
# ---------------------------------------------------------------------------


def parse_command(line):
    """解析输入行 → (cmd, args)。

    - 普通文本 → ("text", 原文)
    - "/命令"  → ("/命令"小写, 参数串, 空参数为 "")
    - 空行     → ("", "")
    示例: "/send D:\\docs\\report.pdf" → ("/send", "D:\\docs\\report.pdf")
    """
    if not isinstance(line, str):
        return "", ""
    line = line.strip()
    if not line:
        return "", ""
    if not line.startswith("/"):
        return "text", line
    parts = line.split(None, 1)
    cmd = parts[0].lower()
    args = parts[1].strip() if len(parts) > 1 else ""
    return cmd, args


def is_safe_filename(name):
    r"""文件名白名单校验 (AGENTS.md §1.5 / 设计 §6.2): ^[\w.\-]+$, 防路径穿越。

    额外拒绝: 空名 / "." / ".." / 长度 > 128 / Windows 保留设备名 (CON/NUL 等)。
    注意: Python 的 \w 含 Unicode 字符, 中文文件名放行 (不含路径分隔符, 无穿越风险)。
    """
    if not isinstance(name, str):
        return False
    if not name or len(name) > 128:
        return False
    if name in (".", ".."):
        return False
    if not _SAFE_NAME_RE.match(name):
        return False
    stem = name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        return False
    return True


_STATUS_TEXT = {
    "queued": "🕐",
    "sending": "🕐",
    "sent": "✓",
    "delivered": "✓✓",
    "failed": "⚠",
}


def status_prefix(status, verified=True):
    """消息状态 → UI 前缀 (设计 §5.3): 🕐/✓/✓✓/⚠。"""
    if verified is False:
        return "⚠"
    return _STATUS_TEXT.get(str(status), "✓")


def fmt_time(ts):
    """时间戳 → "[HH:MM]" 时间串。"""
    try:
        return time.strftime("%H:%M", time.localtime(float(ts)))
    except Exception:
        return "--:--"


def fmt_file_size(size):
    """字节数 → 人类可读 (B/KB/MB/GB/TB)。"""
    try:
        size = float(size)
    except Exception:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return (f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}")
        size /= 1024
    return "?"


def truncate(text, n):
    """截断为 ≤n 个字符, 超长加省略号。"""
    text = str(text).replace("\n", " ")
    return text if len(text) <= n else text[:n] + "…"


def build_bubble(peer, text, status="sent", ts=None, verified=True,
                 file_meta=None, is_self=False, width=60):
    """渲染一条消息气泡 (纯文本, 供 Static(markup=False) 显示)。

    输出示例 (自己消息右对齐缩进, 按 width 参数撑满):
        [12:30] alice ✓✓
        文件我收到了
        [12:31] 我  ✓
        📎 report.pdf (2.3MB) [下载]
    """
    name = "我" if is_self else str(peer)
    prefix = status_prefix(status, verified)
    ts_str = fmt_time(ts if ts else time.time())
    header = f"[{ts_str}] {name} {prefix}"
    if file_meta:
        fname = str(file_meta.get("name", "未知文件"))
        fsize = fmt_file_size(file_meta.get("size", 0))
        token = str(file_meta.get("token", "") or "")
        body = f"📎 {fname} ({fsize})"
        if not is_self and token:
            # P0-5 修复: token 明文可见 (可直接复制 /download <token>),
            # 不再只有不可点击的死文案 [下载]
            body += f"\n    token: {token}"
            body += "\n    按 d 下载, 或 /download <token>"
    else:
        body = str(text or "")
    # 对齐由 CSS (bubble-row) 处理, 此处只输出内容
    return f"{header}\n{body}"


def _row_get(row, key, default=None):
    """兼容 dict / sqlite3.Row / 对象的字段读取。"""
    try:
        if isinstance(row, dict):
            return row.get(key, default)
        if hasattr(row, "keys"):        # sqlite3.Row 等
            return row[key] if key in row.keys() else default
        return getattr(row, key, default)
    except Exception:
        return default


def format_search_results(kw, rows, identity="我"):
    """渲染本地搜索结果为多行文本 (纯函数, 便于单测)。"""
    out = [f'-- 搜索 "{kw}" 共 {len(rows)} 条 --']
    for r in rows:
        ts = fmt_time(_row_get(r, "ts", 0))
        who = _row_get(r, "from_peer", "")
        who = "我" if str(who) == str(identity) else str(who)
        body = str(_row_get(r, "body", ""))
        if _row_get(r, "msg_type", "text") == "file":
            try:
                meta = json.loads(body) if body else {}
                body = f"[文件] {meta.get('name', '?')}"
            except Exception:
                body = "[文件]"
        out.append(f"[{ts}] {who}: {truncate(body, 40)}")
    return "\n".join(out)


def sha256_file(path):
    """流式计算文件 sha256 (十六进制小写)。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def decrypt_file_stream(file_key, cipher_path, out_path, chunk_size=FILE_CHUNK_SIZE):
    """用 file_key 解密文件密文 → 明文写 out_path。成功返回 "", 失败返回中文错误。

    格式假设 (设计 §6.2, 与 Agent-B 的 send_file 加密格式对齐):
      密文 = [nonce 12B] + N × [AES-GCM 块]  每块加密 ≤1MB 明文,
      每块 AAD = 该块明文起始偏移量的 ASCII 十进制串; GCM tag 16B 追加块尾。
    若分块解密失败, 兜底尝试单块格式 (nonce + 整体密文, AAD=None)。
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as e:
        return f"缺少 cryptography 依赖: {e}"
    if len(file_key) != AES_KEY_SIZE:
        return f"文件密钥长度错误: {len(file_key)} (应为 {AES_KEY_SIZE})"
    # 主路径: 分块 AAD=offset
    try:
        with open(cipher_path, "rb") as fi, open(out_path, "wb") as fo:
            nonce = fi.read(GCM_NONCE_SIZE)
            if len(nonce) != GCM_NONCE_SIZE:
                return "密文格式错误: nonce 缺失"
            aesgcm = AESGCM(file_key)
            offset = 0
            while True:
                block = fi.read(chunk_size + GCM_TAG_SIZE)
                if not block:
                    break
                if len(block) < GCM_TAG_SIZE:
                    return "密文被截断"
                plain = aesgcm.decrypt(nonce, block, str(offset).encode("ascii"))
                fo.write(plain)
                offset += len(plain)
        return ""
    except Exception as e:
        # 兜底: 单块格式
        try:
            with open(cipher_path, "rb") as fi:
                data = fi.read()
            if len(data) <= GCM_NONCE_SIZE:
                return f"解密失败: 密文过短 ({e})"
            nonce, ct = data[:GCM_NONCE_SIZE], data[GCM_NONCE_SIZE:]
            plain = AESGCM(file_key).decrypt(nonce, ct, None)
            with open(out_path, "wb") as fo:
                fo.write(plain)
            return ""
        except Exception as e2:
            return f"解密失败: {e2}"


# ---------------------------------------------------------------------------
# 自定义 Message (后台线程 → 主线程事件)
# ---------------------------------------------------------------------------


class NewMessage(Message):
    """新消息到达 (Binder 解密落库后投递到 UI)。"""

    def __init__(self, peer, msg_id, from_peer, msg_type, body, verified, ts):
        super().__init__()
        self.peer = peer
        self.msg_id = msg_id
        self.from_peer = from_peer
        self.msg_type = msg_type
        self.body = body
        self.verified = bool(verified)
        self.ts = ts


class StatusChanged(Message):
    """连接状态变化: connected=True 已连接 / False 重连中。"""

    def __init__(self, connected):
        super().__init__()
        self.connected = bool(connected)


class Progress(Message):
    """文件收发进度: kind=send/download, done/total 字节数。"""

    def __init__(self, kind, done, total, token):
        super().__init__()
        self.kind = kind
        self.done = done
        self.total = total
        self.token = token


class NotifyToast(Message):
    """后台线程发起的 Toast 提示 (主线程 notify, 线程安全)。"""

    def __init__(self, text, severity="information", timeout=None):
        super().__init__()
        self.text = str(text)
        self.severity = severity
        self.timeout = timeout


class FriendsSynced(Message):
    """后台同步服务器身份完成 → 主线程刷新好友列表。"""

    def __init__(self, added=0):
        super().__init__()
        self.added = added


class SendStateChanged(Message):
    """发送状态变化 (queued/sent/failed) → 主线程增量更新气泡。"""

    def __init__(self, peer, msg_id, status):
        super().__init__()
        self.peer = peer
        self.msg_id = msg_id
        self.status = status


# ---------------------------------------------------------------------------
# Binder 线程 (设计 §4 线程 C)
# ---------------------------------------------------------------------------


def binder_loop(app, client, store, stop_event):
    """后台线程 C: 轮询消费 chat_client.INBOUND, 解密落库并投递 UI。

    一次 tick 排空队列 (M10 修复: pending 批量补拉 200 条不必等 200×50ms)。
    退出: stop_event 置位后退出 (on_unmount / main 收尾触发)。
    """
    while not stop_event.wait(BINDER_INTERVAL):
        drained = 0
        while True:
            try:
                item = INBOUND.get_nowait()
            except queue.Empty:
                break
            try:
                handle_inbound_item(app, client, store, item)
            except Exception:
                continue
            drained += 1
            if drained >= 500:
                break  # 单 tick 处理上限, 防无限积压拖死线程


def handle_inbound_item(app, client, store, item):
    """处理单条 INBOUND 事件 (独立函数便于单测)。

    server_message 的 data 是服务端 WS 信封 (chat_server.py):
      {"type":"message","msg":{...}}     实时推送
      {"type":"pending","messages":[...]} 重连后离线补拉
      {"type":"ack"/"auth_ok"/...}       忽略 (发送状态由主线程直接驱动)
    """
    action = item.get("action") if isinstance(item, dict) else None
    if action == "status":
        app.post_message(StatusChanged(bool(item.get("connected", False))))
    elif action == "error":
        app.post_message(NotifyToast(str(item.get("message", "未知错误")), severity="error"))
    elif action == "server_message":
        data = item.get("data")
        if not isinstance(data, dict):
            return
        frame_type = data.get("type")
        if frame_type == "message":
            msg = data.get("msg")
            if isinstance(msg, dict):
                _ingest_server_message(app, client, store, msg)
        elif frame_type == "pending":
            for msg in (data.get("messages") or []):
                if isinstance(msg, dict):
                    _ingest_server_message(app, client, store, msg)
        # ack / auth_ok / error 帧: 忽略 (发送状态由发送路径直接更新)


def _ingest_server_message(app, client, store, msg):
    """receive_chat_message 解密 → LocalStore 落库 → NewMessage 投递。"""
    try:
        result = client.receive_chat_message(msg)
    except Exception as e:
        app.post_message(NotifyToast(f"消息处理异常: {e}", severity="error"))
        return
    if result is None:
        # C2 修复: 无法解密的消息不再静默丢弃 — 提示用户 (重复投递
        # 是正常重连场景, 无 msg_id 可去重时静默; 有 msg_id 且本地
        # 已存在才是重复, 否则提示解密失败)
        try:
            dup = bool(msg.get("id")) and store.get_messages(
                str(msg.get("from", "")), limit=1) or []
            dup = any(str(r.get("msg_id", "")) == str(msg.get("id", ""))
                      for r in dup)
        except Exception:
            dup = False
        if not dup:
            app.post_message(NotifyToast(
                "收到一条无法解密的消息 (可能乱序/对方更换密钥)。"
                "可请对方重发", severity="warning"))
        return
    if result.get("error"):
        app.post_message(NotifyToast(f"消息解密失败: {result['error']}", severity="error"))
        return

    peer = result.get("from") or msg.get("from") or ""
    msg_id = result.get("msg_id") or msg.get("id") or ""
    if not peer or not msg_id:
        return
    ts = float(result.get("timestamp") or time.time())
    verified = bool(result.get("verified", False))
    file_meta = result.get("file") or None
    friend_meta = result.get("friend") or None

    # 好友关系消息: 不落消息流, 只更新本地好友状态 + 通知
    if friend_meta and isinstance(friend_meta, dict):
        action = friend_meta.get("action", "")
        if action == "request":
            # M5 修复: confirmed 关系不被重复请求降级 (幂等)
            cur = None
            try:
                cur = store.friend_status(peer)
            except Exception:
                pass
            if cur not in ("confirmed",):
                try:
                    store.upsert_friend(peer, "requested", ts)
                except Exception:
                    pass
                app.post_message(NotifyToast(
                    f"👋 {peer} 请求添加你为好友 — 输入 /accept {peer} 接受"))
            # confirmed 时静默忽略重复请求
        elif action == "accept":
            try:
                store.upsert_friend(peer, "confirmed", ts)
            except Exception:
                pass
            app.post_message(NotifyToast(f"✅ {peer} 接受了你的好友请求"))
        elif action == "remove":
            try:
                store.upsert_friend(peer, "removed", ts)
            except Exception:
                pass
            app.post_message(NotifyToast(f"🚫 {peer} 已删除好友关系"))
        # 好友消息触发会话列表刷新
        try:
            if hasattr(app, "post_message"):
                app.post_message(NewMessage(peer=peer, msg_id=msg_id,
                                            from_peer=peer, msg_type="friend",
                                            body=f"[好友] {action}",
                                            verified=verified, ts=ts))
        except Exception:
            pass
        return

    if file_meta:
        msg_type = "file"
        # S1 修复: body 剥离 file.key 明文 (密钥仅存 file_keys 表, 随取随删;
        # 避免密钥永久明文驻留 local_messages)
        body_meta = {k: v for k, v in file_meta.items() if k != "key"}
        body = json.dumps(body_meta, ensure_ascii=False)
        key_b64 = file_meta.get("key")
        if key_b64:
            try:
                store.save_file_key(msg_id, urlsafe_b64decode(str(key_b64).encode()))
            except Exception:
                pass
        last_text = f"[文件] {file_meta.get('name', '')}"
    else:
        msg_type = "text"
        body = str(result.get("text", ""))
        last_text = body

    try:
        store.upsert_message(peer, msg_id, peer, msg_type, body, "delivered",
                             1 if verified else 0, ts)
        current = getattr(app, "_current_peer", None)
        store.upsert_conversation(peer, last_text, ts, unread_inc=(peer != current))
    except Exception as e:
        app.post_message(NotifyToast(f"本地存储失败: {e}", severity="error"))
        return
    app.post_message(NewMessage(peer=peer, msg_id=msg_id, from_peer=peer,
                                msg_type=msg_type, body=body, verified=verified, ts=ts))


# ---------------------------------------------------------------------------
# 文案
# ---------------------------------------------------------------------------

GUIDANCE_TEXT = (
    "还没有会话。\n"
    "· 加好友: 输入 /add <对方身份> 发送好友请求\n"
    "· 对方接受后, 你就能直接聊天和发文件了\n"
    "· 对方需已在同一服务器注册 (init + 上传 prekey)\n"
    "· 安全码比对: 按 s, 与对方当面核对"
)

HELP_TEXT = (
    "zhcrypt-chat 帮助\n"
    "────────────────\n"
    "三步上手:\n"
    "  1. 加好友   /add <对方身份>  (对方 /accept 接受)\n"
    "  2. 聊天     直接输入文字回车, 切换会话用 ↑/↓+Enter\n"
    "  3. 发文件   /send <文件路径>  下载见文件消息提示\n"
    "────────────────\n"
    "常用:\n"
    "  查看好友   /friends\n"
    "  历史消息   /history [n]\n"
    "  安全码比对 s  (防窃听, 与对方当面核对)\n"
    "  退出       /exit\n"
    "高级: /search <词> /download <token> /connect /send-text <内容>"
)


# ---------------------------------------------------------------------------
# Textual 应用
# ---------------------------------------------------------------------------

_CSS = """
Screen { layout: vertical; }
#body { height: 1fr; }
#conv-panel { width: 28%; min-width: 20; border-right: solid $primary;
              padding: 0 1; }
#conv-list { height: 1fr; }
#chat-panel { width: 1fr; layout: vertical; }
#chat-view { height: 1fr; padding: 0 1; overflow-y: auto; }
#chat-input { dock: bottom; margin: 0 1 1 1; }
#status-bar { height: 1; background: $panel; color: $text-muted; padding: 0 1; }
.bubble { margin: 0 2 1 2; }
.bubble.self { text-align: right; color: $text; }

/* 会话列表项: 好友 ★ 高亮 */
#conv-list ListItem { padding: 0 1; }
#conv-list ListItem.--highlight { background: $primary; color: $text; }

#login-box { width: 66; height: auto; border: round $accent;
             padding: 2 4; background: $panel; }
#login-title { text-style: bold; text-align: center;
               margin-bottom: 1; color: $text; }
#login-hint { color: $text-muted; margin-bottom: 2; }
#login-identity { margin-bottom: 1; }
#login-pw { margin-bottom: 1; }
#login-remember-btn { width: 100%; margin-bottom: 1; }
#login-btn { width: 100%; margin-top: 1; }
"""


class ChatApp(App):
    """zhcrypt-chat 主应用 (布局见设计 §8.1)。"""

    TITLE = "zhcrypt-chat"
    CSS = _CSS
    BINDINGS = [
        Binding("r", "retry_failed", "重发失败"),
        Binding("s", "show_safety", "安全码"),
        Binding("d", "download_latest", "下载文件"),
        Binding("c", "toggle_conversations", "会话列表"),
        Binding("ctrl+f", "focus_search", "搜索"),
    ]

    def __init__(self, client, store, file_client, identity):
        super().__init__()
        self.client = client
        self.store = store
        self.file_client = file_client
        self.identity = identity
        self._current_peer = None
        self._connected = False
        self._convs = []
        self._binder = None
        self._binder_stop = threading.Event()
        self._search_active = False
        self._progress = ""
        self._progress_timer = None
        self._input_placeholder = "输入消息回车发送 · /add 加好友 · /send 发文件 · /help 帮助"
        self._login_cb = None
        self._login_cancel = None

    def attach_client(self, client):
        """登录成功后挂接 ChatClient 并启动 Binder (登录屏回调)。"""
        self.client = client
        self.identity = client.identity
        self.sub_title = f"身份: {self.identity}"
        self._binder_stop.set()
        self._binder_stop = threading.Event()
        self._binder = threading.Thread(
            target=binder_loop,
            args=(self, self.client, self.store, self._binder_stop),
            name="zhcrypt-binder", daemon=True,
        )
        self._binder.start()
        # 启动后台任务: 自动上传 prekey + 同步服务器身份到好友列表
        threading.Thread(target=self._bootstrap_tasks, daemon=True).start()
        # 登录后确保左侧列表可见 (窄窗口适配)
        self._update_layout_for_width()
        self._refresh_conversations(seed_sessions=True)
        self._update_status_bar()
        convs = self._convs
        if convs:
            self._open_conversation(str(_row_get(convs[0], "peer", "")))

    # ---- 生命周期 ------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="body"):
            with VerticalScroll(id="conv-panel"):
                yield ListView(id="conv-list")
            with Vertical(id="chat-panel"):
                yield VerticalScroll(id="chat-view")
                yield Input(placeholder=self._input_placeholder, id="chat-input")
        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self):
        self.sub_title = f"身份: {self.identity}"
        # 未登录 (无 ChatClient): 先弹登录屏, 成功后再初始化
        if self.client is None:
            login = LoginScreen(self.identity, on_ok=self._login_cb,
                                on_cancel=self._login_cancel)
            self.push_screen(login)
            return
        self._start_chat_screen()

    def _start_chat_screen(self):
        """登录成功后初始化主界面。"""
        self._refresh_conversations(seed_sessions=True)
        self._update_layout_for_width()
        convs = self._convs
        if convs:
            self._open_conversation(str(_row_get(convs[0], "peer", "")))
        self._update_status_bar()
        if not self._binder or not self._binder.is_alive():
            self._binder_stop = threading.Event()
            self._binder = threading.Thread(
                target=binder_loop,
                args=(self, self.client, self.store, self._binder_stop),
                name="zhcrypt-binder", daemon=True,
            )
            self._binder.start()
        # 启动后台任务: 自动上传 prekey + 同步服务器身份到好友列表 (私人服务器)
        threading.Thread(target=self._bootstrap_tasks, daemon=True).start()

    def _bootstrap_tasks(self):
        """启动后台任务: ① 自动上传自身 prekey; ② 拉取服务器身份列表并
        同步为好友 (私人服务器: 服务器上的注册用户 = 你的好友)。"""
        # ① 自动上传 prekey (一次): 注册/登录后无需手动 upload-prekey
        try:
            ok, msg = self.client.ensure_own_prekey()
            self.post_message(NotifyToast(f"prekey {msg}", severity="information"))
        except Exception:
            pass
        # ② 同步服务器身份 → 本地好友 (跳过自己)
        try:
            result = self.client.fetch_server_identities()
        except Exception:
            result = {}
        if isinstance(result, dict) and result.get("error"):
            self.post_message(NotifyToast(
                f"好友同步失败: {result['error']}", severity="error"))
            return
        added = 0
        for it in (result or []):
            peer = str(it.get("identity", ""))
            if not peer or peer == self.identity:
                continue
            try:
                if self.store.friend_status(peer) is None:
                    self.store.upsert_friend(peer, "confirmed")
                    added += 1
            except Exception:
                pass
        if added:
            self.post_message(NotifyToast(f"已从服务器同步 {added} 位好友"))
            # 线程安全: 不能在后台线程直接操作 UI, 发事件让主线程刷新
            self.post_message(FriendsSynced(added=added))

    def on_unmount(self):
        # 退出序列 (设计 §4): 停 Binder → join 超时 3s (client.stop/store.close 由 main 收尾)
        self._binder_stop.set()
        if self._binder and self._binder.is_alive():
            self._binder.join(timeout=3)

    def on_resize(self, event):
        # 宽度 <60 折叠会话列表 (设计 §8.3)
        self._update_layout_for_width(event.size.width if event.size else None)

    def on_input_submitted(self, event: Input.Submitted):
        line = event.value
        event.input.value = ""
        cmd, args = parse_command(line)
        if cmd == "text":
            self._send_text(args)
        elif cmd:
            self._dispatch_command(cmd, args)

    def on_list_view_selected(self, event: ListView.Selected):
        # M6 修复: 用事件自带的索引, 避免列表重建竞态下索引错位
        idx = event.list_view.index
        if idx is None:
            return
        if 0 <= idx < len(self._convs):
            self._open_conversation(str(_row_get(self._convs[idx], "peer", "")))

    # ---- 自定义消息处理 --------------------------------------------------

    def on_new_message(self, msg: NewMessage):
        if msg.peer == self._current_peer:
            if self._search_active:
                self._render_chat(msg.peer)
            else:
                self._mount_bubble(msg.peer, {
                    "peer": msg.peer, "msg_id": msg.msg_id, "from_peer": msg.from_peer,
                    "msg_type": msg.msg_type, "body": msg.body, "status": "delivered",
                    "verified": 1 if msg.verified else 0, "ts": msg.ts,
                })
                # 新消息自动滚动到底 (用户在历史上方浏览时除外)
                try:
                    view = self.query_one("#chat-view", VerticalScroll)
                    if view.scroll_y >= view.max_scroll_y - 2:
                        view.scroll_end(animate=True)
                except Exception:
                    pass
        else:
            self._search_active = False
        self._refresh_conversations()
        self._update_status_bar()

    def on_send_state_changed(self, msg: SendStateChanged):
        """发送状态变化: 增量刷新对应气泡 (不整窗重建)。"""
        if msg.peer == self._current_peer:
            self._render_chat(msg.peer)
        self._refresh_conversations()
        self._update_status_bar()

    def on_status_changed(self, msg: StatusChanged):
        self._connected = msg.connected
        self._update_status_bar()

    def on_friends_synced(self, msg: FriendsSynced):
        """好友同步完成 (后台线程发事件) → 主线程刷新列表。"""
        self._refresh_conversations()
        self._update_status_bar()

    def on_progress(self, msg: Progress):
        pct = int(msg.done * 100 / msg.total) if msg.total else 100
        label = "上传" if msg.kind == "send" else "下载"
        if msg.done >= msg.total:
            self._progress = f" {label} {msg.token} 完成"
        else:
            self._progress = f" {label} {msg.token} {pct}%"
        self._update_status_bar()
        # M7 修复: 单一定时器, 取消旧的再建 (防 timer 泄漏/竞态)
        try:
            if self._progress_timer is not None:
                self._progress_timer.stop()
        except Exception:
            pass
        self._progress_timer = self.set_timer(5.0, self._clear_progress)

    def on_notify_toast(self, msg: NotifyToast):
        try:
            self.notify(msg.text, severity=msg.severity, timeout=msg.timeout)
        except Exception:
            pass

    # ---- 快捷键动作 ------------------------------------------------------

    def action_retry_failed(self):
        """r: 重发当前会话内 status=failed 的消息。"""
        peer = self._current_peer
        if not peer:
            self.notify("请先选择会话", severity="warning")
            return
        failed = self._load_failed(peer)
        if not failed:
            self.notify("当前会话没有可重发的失败消息")
            return
        ok = 0
        for m in failed:
            body = str(_row_get(m, "body", "") or "")
            if not body:
                continue
            try:
                result = self.client.send_chat_message(peer, body)
            except Exception as e:
                self.notify(f"重发异常: {e}", severity="error")
                continue
            if result.get("error"):
                self.notify(f"重发失败: {result['error']}", severity="error")
                continue
            old_id = _row_get(m, "msg_id", "")
            ts = time.time()
            try:
                self.store.upsert_message(peer, result.get("msg_id") or f"local-{ts:.6f}",
                                          self.identity, "text", body, "sent", 1, ts)
            except Exception:
                pass
            try:
                # 重发成功: 从 outbox 移除 (list_failed_outbox 只查 failed,
                # 且 outbox 语义为"未确认消息", 已送达即应清理)
                if old_id:
                    self.store.delete_outbox(old_id)
            except Exception:
                pass
            ok += 1
        self._render_chat(peer)
        self._refresh_conversations()
        self._update_status_bar()
        self.notify(f"已重发 {ok} 条失败消息" if ok else "重发全部失败", severity="warning" if not ok else "information")

    def action_show_safety(self):
        """s: 显示当前会话安全码。"""
        peer = self._current_peer
        if not peer:
            self.notify("请先选择会话", severity="warning")
            return
        self._show_safety(peer)

    def action_download_latest(self):
        """d: 下载当前会话最近一条未下载的文件消息。"""
        peer = self._current_peer
        if not peer:
            self.notify("请先选择会话", severity="warning")
            return
        try:
            rows = self.store.get_messages(peer, limit=MAX_VISIBLE) or []
        except Exception:
            rows = []
        for r in reversed(rows):
            if _row_get(r, "msg_type", "text") != "file":
                continue
            body = str(_row_get(r, "body", ""))
            try:
                meta = json.loads(body) if body else {}
            except Exception:
                continue
            token = meta.get("token", "")
            if token:
                meta = dict(meta)
                meta["msg_id"] = _row_get(r, "msg_id", "")
                self._start_download(token, meta)
                return
        self.notify("当前会话没有可下载的文件", severity="warning")

    def action_toggle_conversations(self):
        """c: 聚焦会话列表 (列表始终可见, 此键用于快速切到列表选择)。"""
        try:
            lv = self.query_one("#conv-list", ListView)
            lv.focus()
        except Exception:
            pass

    def action_focus_search(self):
        """Ctrl+F: 聚焦输入框并预填 /search。"""
        try:
            inp = self.query_one("#chat-input", Input)
            inp.focus()
            inp.value = "/search "
        except Exception:
            pass

    # ---- 内部工具 --------------------------------------------------------

    def _update_layout_for_width(self, width=None):
        """窗口宽度适配: 左侧会话列表始终显示; 窄窗口时压缩宽度, 不隐藏。

        (原设计 <60 列折叠列表, 用户反馈导致"左侧空了" — 已改为始终可见)
        """
        try:
            panel = self.query_one("#conv-panel")
        except Exception:
            return
        if width is None:
            try:
                width = int(self.size.width)
            except Exception:
                width = 100
        # 窄窗口 (<=60 列): 压缩到 22% 宽; 常规窗口 28%
        if int(width) <= 60:
            panel.styles.width = "22%"
        else:
            panel.styles.width = "28%"
        panel.display = True

    def _clear_progress(self):
        self._progress = ""
        self._progress_timer = None
        self._update_status_bar()

    def _update_status_bar(self):
        try:
            sb = self.query_one("#status-bar", Static)
        except Exception:
            return
        conn = "● 已连接" if self._connected else "● 重连中"
        peer = self._current_peer or "无会话"
        unread = sum(int(_row_get(c, "unread", 0) or 0) for c in self._convs)
        sb.update(f"{conn} · {peer} · 未读 {unread}{self._progress} · "
                  f"快捷键: Tab切换 s安全码 r重发 /help帮助")

    def _refresh_conversations(self, seed_sessions=False):
        """重建会话列表; seed_sessions 时从 session.list_sessions 补入历史会话。"""
        if seed_sessions:
            try:
                from session import list_sessions
                known = {str(_row_get(c, "peer", "")) for c in (self.store.list_conversations() or [])}
                for s in list_sessions(self.identity) or []:
                    peer = s.get("peer")
                    if peer and str(peer) not in known:
                        self.store.upsert_conversation(str(peer), "(新会话)",
                                                       s.get("mtime", time.time()))
            except Exception:
                pass
        try:
            convs = self.store.list_conversations() or []
        except Exception:
            convs = []
        # 好友标记缓存 + 好友列表 (可能无会话)
        try:
            friends = self.store.list_friends() or []
            friend_status = {str(_row_get(f, "peer", "")): str(_row_get(f, "status", ""))
                             for f in friends}
        except Exception:
            friends = []
            friend_status = {}
        # 好友 (confirmed) 置顶: 好友组在上 (按最近活跃降序), 其余在下。
        # 无会话的好友也显示 (同步自服务器), 点击即可发消息。
        conv_map = {str(_row_get(c, "peer", "")): c for c in convs}
        confirmed = []
        others = []
        for c in convs:
            peer = str(_row_get(c, "peer", ""))
            if friend_status.get(peer) == "confirmed":
                confirmed.append(c)
            else:
                others.append(c)
        for f in friends:
            peer = str(_row_get(f, "peer", ""))
            # M6 修复: 只有 confirmed 好友进置顶组; requested/removed 归入其他组
            if peer and str(_row_get(f, "status", "")) == "confirmed" \
                    and peer not in conv_map:
                confirmed.append({"peer": peer, "last_text": "(新好友)",
                                  "last_ts": _row_get(f, "ts", 0), "unread": 0})
        confirmed.sort(key=lambda c: float(_row_get(c, "last_ts", 0) or 0), reverse=True)
        others.sort(key=lambda c: float(_row_get(c, "last_ts", 0) or 0), reverse=True)
        convs = confirmed + others
        self._convs = list(convs)
        try:
            lv = self.query_one("#conv-list", ListView)
            lv.clear()
            # 好友 (confirmed) 置顶 ★, 无会话好友显示为新好友; 其余在下。
            # 列表项与 self._convs 一一对应 (无分组标题行, 索引不偏移)。
            for i, c in enumerate(convs):
                peer = str(_row_get(c, "peer", ""))
                if not peer:
                    continue
                last = truncate(_row_get(c, "last_text", ""), 20)
                unread = int(_row_get(c, "unread", 0) or 0)
                badge = f" ({unread})" if unread else ""
                fst = friend_status.get(peer)
                fmark = "★ " if fst == "confirmed" else ("… " if fst == "requested" else "")
                safe_id = re.sub(r"[^A-Za-z0-9_\-]", "_", peer)
                lv.append(ListItem(Label(f"{fmark}{peer}\n{last}{badge}"),
                                   id=f"conv-{i}-{safe_id}"))
            # 滚动定位: 默认回到顶部 (好友组可见); 仅当用户当前会话
            # 存在时才跟随, 且优先让好友组始终在可视范围
            if self._current_peer:
                target = None
                for i, c in enumerate(convs):
                    if str(_row_get(c, "peer", "")) == self._current_peer:
                        target = i
                        break
                if target is not None and target < len(convs):
                    lv.index = target
            else:
                lv.index = 0
        except Exception:
            pass

    def _open_conversation(self, peer):
        peer = peer or ""
        if not peer or peer == self._current_peer:
            return
        self._current_peer = peer
        self._search_active = False
        try:
            self.store.clear_unread(peer)
        except Exception:
            pass
        self._render_chat(peer)
        self._refresh_conversations()
        self._update_status_bar()

    def _render_chat(self, peer, anchor_oldest=False):
        """虚拟化渲染消息。

        anchor_oldest=True: 从最早消息开始渲染窗口 (刚 /history 加载的旧消息
        可见, M1 修复); 否则渲染最近 MAX_VISIBLE 条。
        """
        view = self.query_one("#chat-view", VerticalScroll)
        view.remove_children()
        try:
            if anchor_oldest:
                # 取全部消息再取最早 MAX_VISIBLE 条 (本地通常不会超过几千条)
                all_msgs = self.store.get_messages(peer, limit=10000) or []
                msgs = all_msgs[:MAX_VISIBLE]
                older = len(all_msgs) > len(msgs)
            else:
                msgs = self.store.get_messages(peer, limit=MAX_VISIBLE + 1) or []
                older = len(msgs) > MAX_VISIBLE
                msgs = msgs[-MAX_VISIBLE:]
        except Exception:
            msgs = []
            older = False
        if not msgs:
            view.mount(Static(GUIDANCE_TEXT, classes="bubble"))
            return
        if older:
            view.mount(Static("┄ 更早消息: 输入 /history 50 加载 ┄", classes="bubble hint"))
        for row in msgs:
            self._mount_bubble(peer, row)
        view.scroll_end(animate=False)

    def _mount_bubble(self, peer, row):
        view = self.query_one("#chat-view", VerticalScroll)
        is_self = str(_row_get(row, "from_peer", "")) == self.identity
        status = str(_row_get(row, "status", "sent"))
        verified = bool(_row_get(row, "verified", 0))
        ts = _row_get(row, "ts", time.time())
        try:
            width = max(int(self.size.width) - 6, 40)
        except Exception:
            width = 100
        body = _row_get(row, "body", "")
        if _row_get(row, "msg_type", "text") == "file":
            meta = {}
            if isinstance(body, str) and body:
                try:
                    meta = json.loads(body)
                except Exception:
                    meta = {}
            bubble = build_bubble(peer, "", status, ts, verified, file_meta=meta,
                                  is_self=is_self, width=width)
        else:
            bubble = build_bubble(peer, body, status, ts, verified,
                                  is_self=is_self, width=width)
        # 自己消息右对齐由 CSS (bubble.self { text-align: right; }) 处理,
        # 直接挂载 Static (不能先建容器再 mount, Textual 会报 MountError)
        view.mount(Static(bubble, classes="bubble" + (" self" if is_self else ""),
                          markup=False))
        # M11 修复: 增量挂载也裁剪, 防止 widget 无界增长
        try:
            while len(view.children) > MAX_VISIBLE + 5:
                oldest = view.children[0]
                oldest.remove()
        except Exception:
            pass

    # ---- 发送 ------------------------------------------------------------

    def _send_text(self, text):
        """发送文本 (异步: 后台线程执行 X3DH/网络, 不阻塞 UI)。"""
        text = text.strip()
        if not text:
            return
        peer = self._current_peer
        if not peer:
            self.notify("请先选择会话 (/open <对方身份> 开始新会话)", severity="warning")
            return
        self._search_active = False
        self._render_chat(peer)
        threading.Thread(target=self._send_text_worker,
                         args=(peer, text), daemon=True).start()

    def _send_text_worker(self, peer, text):
        """后台线程: 发送文本 → 落库 → 通知主线程刷新。"""
        ts0 = time.time()
        out_id = f"local-{ts0:.6f}"
        try:
            self.store.save_outbox(out_id, peer, text)
        except Exception:
            pass
        # 立即在界面显示"发送中"气泡 (🕐)
        try:
            self.store.upsert_message(peer, out_id, self.identity, "text", text,
                                      "queued", 1, ts0)
            self.store.upsert_conversation(peer, text, ts0)
        except Exception:
            pass
        self.post_message(SendStateChanged(peer=peer, msg_id=out_id, status="queued"))
        try:
            result = self.client.send_chat_message(peer, text)
        except Exception as e:
            self._send_failed(peer, text, out_id, f"发送异常: {e}")
            return
        if result.get("error"):
            self._send_failed(peer, text, out_id, f"发送失败: {result['error']}")
            return
        ts = time.time()
        msg_id = result.get("msg_id") or f"local-{ts:.6f}"
        try:
            self.store.delete_outbox(out_id)
            self.store.upsert_message(peer, msg_id, self.identity, "text", text,
                                      "sent", 1, ts)
            self.store.upsert_conversation(peer, text, ts)
        except Exception:
            pass
        self.post_message(SendStateChanged(peer=peer, msg_id=msg_id, status="sent"))
        self.post_message(NewMessage(peer=peer, msg_id=msg_id, from_peer=self.identity,
                                     msg_type="text", body=text, verified=True, ts=ts))

    def _send_failed(self, peer, text, out_id, reason):
        """发送失败: 消息以 failed 状态落库 (界面可见 ⚠), 可 r 重发。"""
        try:
            self.store.mark_outbox(out_id, "failed")
            self.store.upsert_message(peer, out_id, self.identity, "text", text,
                                      "failed", 0, time.time())
            self.store.upsert_conversation(peer, text, time.time())
        except Exception:
            pass
        self.post_message(NotifyToast(
            f"{reason} (消息已保留, 按 r 重发)", severity="error"))
        self.post_message(SendStateChanged(peer=peer, msg_id=out_id, status="failed"))

    def _send_file_worker(self, peer, path):
        """后台线程执行 send_file, 进度经 Progress 消息回报。"""
        def cb(done, total):
            self.post_message(Progress(kind="send", done=done, total=total,
                                       token=os.path.basename(path)))
        try:
            result = self.client.send_file(peer, path, progress_cb=cb)
        except Exception as e:
            self.post_message(NotifyToast(f"文件发送异常: {e}", severity="error"))
            return
        if result.get("error"):
            self.post_message(NotifyToast(f"文件发送失败: {result['error']}", severity="error"))
            return
        ts = time.time()
        meta = {"name": os.path.basename(path), "size": os.path.getsize(path),
                "sha256": sha256_file(path)}
        msg_id = result.get("msg_id") or f"local-{ts:.6f}"
        try:
            self.store.upsert_message(peer, msg_id, self.identity, "file",
                                      json.dumps(meta, ensure_ascii=False), "sent", 1, ts)
            self.store.upsert_conversation(peer, f"[文件] {meta['name']}", ts)
        except Exception as e:
            self.post_message(NotifyToast(f"本地落库失败: {e}", severity="error"))
        self.post_message(NewMessage(peer=peer, msg_id=msg_id, from_peer=self.identity,
                                     msg_type="file", body=json.dumps(meta, ensure_ascii=False),
                                     verified=True, ts=ts))

    # ---- 文件下载 ---------------------------------------------------------

    def _find_file_meta(self, token, peer):
        """在会话消息中按 token 查找文件元数据 + msg_id (用于取 file_key)。"""
        try:
            rows = self.store.get_messages(peer, limit=MAX_VISIBLE) or []
        except Exception:
            rows = []
        for r in rows:
            if _row_get(r, "msg_type", "text") != "file":
                continue
            body = str(_row_get(r, "body", ""))
            try:
                meta = json.loads(body) if body else {}
            except Exception:
                continue
            if meta.get("token") == token:
                return meta, _row_get(r, "msg_id", "")
        return None, None

    def _start_download(self, token, meta=None):
        """启动下载 (后台线程), 文件名 + token 白名单校验前置。"""
        if not is_safe_filename(str(meta.get("name", ""))):
            self.notify(f"文件名不合法, 拒绝下载: {meta.get('name')!r}", severity="error")
            return
        # token 白名单 (32hex, 服务端格式): 防远端可控 token 拼路径穿越
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", token):
            self.notify(f"文件 token 不合法, 拒绝下载: {token!r}", severity="error")
            return
        dest_dir = os.path.join(os.path.expanduser("~"), ".zhcrypt", "downloads")
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except OSError as e:
            self.notify(f"无法创建下载目录: {e}", severity="error")
            return
        threading.Thread(target=self._download_worker,
                         args=(token, meta.get("msg_id", ""), meta.get("name", ""),
                               meta.get("sha256", ""), dest_dir),
                         name="zhcrypt-download", daemon=True).start()
        self.notify(f"开始下载 {meta.get('name')} ...")

    def _download_worker(self, token, msg_id, name, expect_sha256, dest_dir):
        """后台线程: download_file → take_file_key → 解密 → sha256 校验。"""
        tmp_dir = os.path.join(dest_dir, ".tmp")
        try:
            os.makedirs(tmp_dir, exist_ok=True)
        except OSError:
            tmp_dir = dest_dir
        cipher_path = os.path.join(tmp_dir, f"{token}.enc")

        def cb(done, total):
            self.post_message(Progress(kind="download", done=done, total=total, token=token))

        try:
            result = self.client.download_file(token, tmp_dir, progress_cb=cb)
        except Exception as e:
            self.post_message(NotifyToast(f"下载异常: {e}", severity="error"))
            return
        if result.get("error"):
            self.post_message(NotifyToast(f"下载失败: {result['error']}", severity="error"))
            return
        cipher_path = result.get("path") or cipher_path

        key = None
        try:
            key = self.store.take_file_key(msg_id)
        except Exception:
            key = None
        if key is None:
            self._remove_quietly(cipher_path)
            self.post_message(NotifyToast(f"{name}: 文件密钥缺失或已过期, 请对方重发",
                                          severity="error"))
            return

        def _restore_key():
            """解密/校验失败后回写密钥, 允许重试下载 (m8 修复: 取出即删不再烧钥)。"""
            try:
                self.store.save_file_key(msg_id, key)
            except Exception:
                pass

        final = os.path.join(dest_dir, name)
        try:
            err = decrypt_file_stream(key, cipher_path, final)
        except Exception as e:
            err = str(e)
        if err:
            _restore_key()
            self._remove_quietly(cipher_path)
            self._remove_quietly(final)
            self.post_message(NotifyToast(f"{name}: 解密失败 ({err})", severity="error"))
            return
        if expect_sha256:
            try:
                actual = sha256_file(final)
            except Exception:
                actual = ""
            if actual.lower() != str(expect_sha256).lower():
                _restore_key()
                self._remove_quietly(cipher_path)
                self._remove_quietly(final)
                self.post_message(NotifyToast(f"{name}: sha256 校验不一致, 已删除残留",
                                              severity="error"))
                return
        self._remove_quietly(cipher_path)
        self.post_message(NotifyToast(f"已保存: {final}"))

    @staticmethod
    def _remove_quietly(path):
        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    # ---- 命令分发 ---------------------------------------------------------

    def _dispatch_command(self, cmd, args):
        table = {
            "/send": self._cmd_send,
            "/download": self._cmd_download,
            "/history": self._cmd_history,
            "/safety": self._cmd_safety,
            "/search": self._cmd_search,
            "/connect": self._cmd_connect,
            "/help": self._cmd_help,
            "/exit": self._cmd_exit,
            "/open": self._cmd_open,
            "/send-text": self._cmd_send_text,
            "/add": self._cmd_add_friend,
            "/accept": self._cmd_accept_friend,
            "/friends": self._cmd_friends,
        }
        fn = table.get(cmd)
        if fn:
            fn(args)
        else:
            self.notify(f"未知命令 {cmd}, 输入 /help 查看帮助", severity="warning")

    def _cmd_send(self, args):
        """/send <path>: 后台线程上传文件。"""
        peer = self._current_peer
        if not peer:
            self.notify("请先选择会话", severity="warning")
            return
        path = (args or "").strip().strip('"').strip("'")
        if not path:
            self.notify("用法: /send <文件路径>", severity="warning")
            return
        if not os.path.isfile(path):
            self.notify(f"文件不存在: {path}", severity="warning")
            return
        if not hasattr(self.client, "send_file"):
            self.notify("当前客户端不支持文件发送 (需 Agent-B 的 send_file)", severity="error")
            return
        self.notify(f"开始上传 {os.path.basename(path)} ...")
        threading.Thread(target=self._send_file_worker, args=(peer, path),
                         name="zhcrypt-sendfile", daemon=True).start()

    def _cmd_download(self, args):
        """/download <token>: 下载对应文件消息的附件。"""
        token = (args or "").strip()
        if not token:
            self.notify("用法: /download <token>", severity="warning")
            return
        peer = self._current_peer
        if not peer:
            self.notify("请先选择会话", severity="warning")
            return
        meta, msg_id = self._find_file_meta(token, peer)
        if meta is None:
            self.notify(f"当前会话未找到 token 对应的文件消息: {token}",
                        severity="warning")
            return
        meta = dict(meta)
        meta["msg_id"] = msg_id
        self._start_download(token, meta)

    def _cmd_history(self, args):
        """/history [n]: 拉取更早历史消息并落库刷新视图。"""
        peer = self._current_peer
        if not peer:
            self.notify("请先选择会话", severity="warning")
            return
        try:
            n = int((args or "").strip() or DEFAULT_HISTORY)
            n = max(1, min(n, MAX_HISTORY))
        except ValueError:
            n = DEFAULT_HISTORY
        try:
            # 游标 = 本地最早一条消息 (不是最新! 之前取最新导致 /history
            # 永远拉同一窗口无法翻页)
            if hasattr(self.store, "get_oldest_message"):
                oldest = self.store.get_oldest_message(peer)
            else:
                msgs = self.store.get_messages(peer, limit=1) or []
                oldest = msgs[0] if msgs else None
        except Exception:
            oldest = None
        before_id = _row_get(oldest, "msg_id") if oldest else None
        self.notify("正在拉取历史消息 ...")
        try:
            results = self.client.get_history(peer, before_id=before_id, limit=n)
        except Exception as e:
            self.notify(f"拉取历史异常: {e}", severity="error")
            return
        k = 0
        for r in results:
            if r.get("error"):
                self.notify(f"历史消息拉取失败: {r['error']}", severity="error")
                continue
            msg_id = r.get("msg_id", "")
            if not msg_id:
                continue
            from_peer = r.get("from") or peer
            ts = float(r.get("timestamp") or time.time())
            verified = bool(r.get("verified", False))
            file_meta = r.get("file") or None
            if file_meta:
                # S1 修复 (与 _ingest_server_message 一致): body 剥离 file.key 明文
                body_meta = {k: v for k, v in file_meta.items() if k != "key"}
                msg_type, body = "file", json.dumps(body_meta, ensure_ascii=False)
                if file_meta.get("key"):
                    try:
                        self.store.save_file_key(msg_id, urlsafe_b64decode(
                            str(file_meta["key"]).encode()))
                    except Exception:
                        pass
                last_text = f"[文件] {file_meta.get('name', '')}"
            else:
                msg_type, body = "text", str(r.get("text", ""))
                last_text = body
            try:
                self.store.upsert_message(peer, msg_id, from_peer, msg_type, body,
                                          "sent", 1 if verified else 0, ts)
                self.store.upsert_conversation(peer, last_text, ts)
            except Exception:
                continue
            k += 1
        # M1 修复: 渲染窗口锚定到最早消息, 刚加载的旧消息立即可见
        self._render_chat(peer, anchor_oldest=True)
        self._refresh_conversations()
        self._update_status_bar()
        self.notify(f"已加载 {k} 条历史消息")

    def _cmd_safety(self, args):
        """/safety [peer]: 安全识别码比对。"""
        peer = (args or "").strip() or self._current_peer
        if not peer:
            self.notify("用法: /safety [对方身份]", severity="warning")
            return
        self._show_safety(peer)

    def _show_safety(self, peer):
        try:
            result = self.client.get_safety_number(peer)
        except Exception as e:
            self.notify(f"安全码计算异常: {e}", severity="error")
            return
        if result.get("error"):
            self.notify(f"安全码不可用: {result['error']}", severity="error")
            return
        sn = str(result.get("safety_number", ""))
        grouped = " ".join(sn[i:i + 5] for i in range(0, len(sn), 5)) if sn else "(无)"
        late = " [回退服务器公钥, 请带外确认]" if result.get("late_pin") else ""
        self.notify(f"与 {peer} 的安全码:\n{grouped}{late}", title="安全码", timeout=15)

    def _cmd_search(self, args):
        """/search <kw>: 本地消息搜索。"""
        kw = (args or "").strip()
        if not kw:
            self.notify("用法: /search <关键词>", severity="warning")
            return
        try:
            rows = self.store.search(kw, limit=50) or []
        except Exception as e:
            self.notify(f"搜索失败: {e}", severity="error")
            return
        self._search_active = True
        view = self.query_one("#chat-view", VerticalScroll)
        view.remove_children()
        view.mount(Static(format_search_results(kw, rows, self.identity),
                          classes="bubble", markup=False))

    def _cmd_connect(self, args):
        """/connect: 手动重连。"""
        try:
            self.client.start()
        except Exception as e:
            self.notify(f"重连失败: {e}", severity="error")
            return
        self.notify("已请求重连 ...")

    def _cmd_help(self, args):
        self._search_active = False
        view = self.query_one("#chat-view", VerticalScroll)
        view.remove_children()
        view.mount(Static(HELP_TEXT, classes="bubble", markup=False))

    def _cmd_exit(self, args):
        self.exit(0)

    def _cmd_open(self, args):
        """/open <peer>: 打开 (或新建) 与对方的会话。"""
        peer = (args or "").strip()
        if not peer or not re.fullmatch(IDENTITY_RE, peer):
            self.notify("对方身份不合法 (仅限字母数字 ._-@+ 且 ≤64 字符)",
                        severity="warning")
            return
        try:
            self.store.upsert_conversation(peer, "(新会话)", time.time())
        except Exception:
            pass
        self._open_conversation(peer)

    def _cmd_send_text(self, args):
        """/send-text <内容>: IME 异常时的发送兜底 (设计 §8.3)。"""
        self._send_text(args)

    # ---- 好友 -------------------------------------------------------------

    def _cmd_add_friend(self, args):
        """/add <peer>: 发送好友请求 (对方在线时自动弹出确认, 离线时请求保留)。"""
        peer = (args or "").strip()
        if not peer or not re.fullmatch(IDENTITY_RE, peer):
            self.notify("用法: /add <对方身份>", severity="warning")
            return
        # 无会话先建立 (好友请求本身就是第一条消息, 会自动 X3DH 握手)
        try:
            self.store.upsert_conversation(peer, "(好友请求)", time.time())
        except Exception:
            pass
        self._open_conversation(peer)
        # 后台发送请求, 避免阻塞 UI
        threading.Thread(target=self._send_friend_request, args=(peer,),
                         name="zhcrypt-friend", daemon=True).start()

    def _send_friend_request(self, peer):
        try:
            result = self.client.send_friend_msg(peer, "request")
        except Exception as e:
            self.post_message(NotifyToast(f"发送好友请求异常: {e}", severity="error"))
            return
        if result.get("error"):
            self.post_message(NotifyToast(
                f"好友请求失败: {result['error']}", severity="error"))
            return
        if result.get("first_contact"):
            self.post_message(NotifyToast(
                f"首次会话! 请与 {peer} 带外核对安全码后再信任", severity="warning"))
        try:
            self.store.upsert_friend(peer, "requested")
        except Exception:
            pass
        self.post_message(NotifyToast(f"已向 {peer} 发送好友请求, 等待对方确认"))

    def _cmd_accept_friend(self, args):
        """/accept [peer]: 接受好友请求 (未指定时接受当前会话对方的请求)。"""
        peer = (args or "").strip() or self._current_peer
        if not peer:
            self.notify("用法: /accept <对方身份> (或先打开对方会话)", severity="warning")
            return
        try:
            result = self.client.send_friend_msg(peer, "accept")
        except Exception as e:
            self.notify(f"接受好友异常: {e}", severity="error")
            return
        if result.get("error"):
            self.notify(f"接受失败: {result['error']}", severity="error")
            return
        try:
            self.store.upsert_friend(peer, "confirmed")
        except Exception:
            pass
        self.notify(f"你和 {peer} 现在是好友了")
        self._refresh_conversations()

    def _cmd_friends(self, args):
        """/friends: 查看好友列表。"""
        try:
            friends = self.store.list_friends() or []
        except Exception:
            friends = []
        if not friends:
            self.notify("还没有好友。用 /add <对方身份> 添加")
            return
        lines = []
        for f in friends:
            mark = "★" if f.get("status") == "confirmed" else "…"
            lines.append(f"  {mark} {f.get('peer', '?')} "
                         f"({'已添加' if f.get('status') == 'confirmed' else '等待确认'})")
        self.notify("好友列表:\n" + "\n".join(lines))

    # ---- 重发辅助 ---------------------------------------------------------

    def _load_failed(self, peer):
        """读取当前会话 status=failed 的消息 (源自 outbox, 按会话过滤)。

        优先使用 LocalStore.list_failed_outbox(若有); 否则回退扫描 get_messages 结果。
        """
        rows = []
        try:
            if hasattr(self.store, "list_failed_outbox"):
                for r in (self.store.list_failed_outbox() or []):
                    if str(_row_get(r, "peer", "")) == peer:
                        rows.append(r)
            elif hasattr(self.store, "list_failed"):
                rows = self.store.list_failed(peer) or []
            else:
                for r in (self.store.get_messages(peer, limit=500) or []):
                    if str(_row_get(r, "status", "")) == "failed":
                        rows.append(r)
        except Exception:
            rows = []
        return rows


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 登录屏 (TUI 内登录: 打开即进界面, 密码在界面内输入)
# ---------------------------------------------------------------------------


def _pw_cache_path(identity):
    """记住密码的存储路径 (本机, 与 ratchet 会话同目录)。

    M14 修复: 文件名用 sha256 前缀, 避免消毒后碰撞 ("a+b" 与 "a_b"
    曾映射到同一文件, 导致跨身份取到别人密码)。
    """
    h = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return os.path.join(os.path.expanduser("~"), ".zhcrypt", "local",
                        f".pw_{h}.bin")


# R3: 记住密码的可配置时效与总开关。
#   ZHCRYPT_PW_CACHE=0        完全禁用记住密码 (口令不落盘)
#   ZHCRYPT_PW_CACHE_TTL=秒   缓存有效期, 默认 12 小时, 过期即焚
_PW_CACHE_ENABLED = os.environ.get("ZHCRYPT_PW_CACHE", "1").strip().lower() \
    not in ("0", "false", "no", "off")
try:
    _PW_CACHE_TTL_SECONDS = max(60, int(os.environ.get("ZHCRYPT_PW_CACHE_TTL",
                                                       str(12 * 3600))))
except ValueError:
    _PW_CACHE_TTL_SECONDS = 12 * 3600


def _save_pw_cache(identity, passphrase):
    """记住密码 (AES-256-GCM 加密, 密钥来自 config 的 device.key)。

    AAD 绑定身份: 防跨身份串号 (GCM tag 校验).
    """
    if not _PW_CACHE_ENABLED:
        return False
    try:
        from config import DEVICE_KEY_PATH
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        path = _pw_cache_path(identity)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(DEVICE_KEY_PATH):
            return False
        with open(DEVICE_KEY_PATH, "rb") as f:
            key = f.read()
        if len(key) != 32:
            return False
        nonce = os.urandom(12)
        aad = identity.encode("utf-8")
        ct = AESGCM(key).encrypt(nonce, passphrase.encode("utf-8"), aad)
        with open(path, "wb") as f:
            f.write(nonce + ct)
        return True
    except Exception:
        return False


def _load_pw_cache(identity):
    """读取记住的密码; 无缓存/过期/解密失败/身份不匹配返回 None。"""
    if not _PW_CACHE_ENABLED:
        return None
    try:
        from config import DEVICE_KEY_PATH
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        path = _pw_cache_path(identity)
        if not os.path.isfile(path) or not os.path.exists(DEVICE_KEY_PATH):
            return None
        # R3: TTL 过期即焚, 避免口令缓存无限期驻留磁盘
        if time.time() - os.path.getmtime(path) > _PW_CACHE_TTL_SECONDS:
            try:
                os.remove(path)
            except OSError:
                pass
            return None
        with open(DEVICE_KEY_PATH, "rb") as f:
            key = f.read()
        with open(path, "rb") as f:
            blob = f.read()
        if len(key) != 32 or len(blob) <= 12:
            return None
        aad = identity.encode("utf-8")
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad).decode("utf-8")
    except Exception:
        return None


class LoginScreen(ModalScreen):
    """TUI 内登录屏 (全屏遮罩, 不透明背景, 居中卡片)。

    完整登录表单: 身份名 + 密码。身份不存在时自动创建 (注册),
    登录后自动上传 prekey / 同步好友。
    """

    CSS = """
    LoginScreen {
        align: center middle;
        /* 遮罩: 不透明背景盖住下层聊天界面 */
        background: $background;
    }
    #login-box {
        width: 66;
        height: auto;
        border: round $accent;
        padding: 2 4;
        background: $panel;
    }
    #login-title { text-style: bold; text-align: center;
                   margin-bottom: 1; color: $text; }
    #login-hint { color: $text-muted; margin-bottom: 2; }
    #login-identity { margin-bottom: 1; }
    #login-pw { margin-bottom: 1; }
    #login-remember-btn { width: 100%; margin-bottom: 1; }
    #login-btn { width: 100%; margin-top: 1; }
    #login-warn { color: $warning; margin-top: 1; text-align: center; }
    """

    def __init__(self, identity, on_ok, on_cancel=None):
        super().__init__()
        self._identity = identity
        self._on_ok = on_ok
        self._on_cancel = on_cancel
        self._remember = False

    def compose(self) -> ComposeResult:
        with Vertical(id="login-box"):
            yield Static("zhcrypt 登录", id="login-title")
            yield Static("身份名不存在时自动注册 · 密码用于加密本地密钥",
                         id="login-hint")
            yield Input(value=self._identity or "",
                        placeholder="身份名 (你的账号, 朋友靠它找到你)",
                        id="login-identity")
            yield Input(placeholder="私钥密码", password=True, id="login-pw")
            yield Button("☐ 记住密码 (本机免输入)", id="login-remember-btn")
            yield Button("登 录", id="login-btn", variant="primary")

    def on_mount(self):
        self.query_one("#login-identity", Input).focus()

    def _toggle_remember(self):
        self._remember = not self._remember
        box = self.query_one("#login-remember-btn", Button)
        box.label = "☑ 记住密码 (本机免输入)" if self._remember \
            else "☐ 记住密码 (本机免输入)"

    def _do_login(self):
        ident = self.query_one("#login-identity", Input).value.strip()
        pw = self.query_one("#login-pw", Input).value
        remember = self._remember
        if not ident:
            self.notify("请输入身份名", severity="error")
            return
        if not pw:
            self.notify("请输入密码", severity="error")
            return
        # 身份名白名单 (防路径穿越 + URL 传输)
        if not re.fullmatch(IDENTITY_RE, ident):
            self.notify("身份名不合法: 仅限字母/数字/._-@, 最长 64 字符",
                        severity="error")
            return
        # 验证密码: 身份存在 → 解锁; 不存在 → 自动创建 (注册)
        try:
            from keys import KeyStore
            store = KeyStore()
            if not _identity_exists(ident):
                store.generate_identity(ident, pw, comment="tui-login")
            else:
                # 已有身份: 用 RSA 主私钥验证密码 (所有身份必有 .key,
                # 最可靠)。x25519 缺失/格式不一致不阻断登录, 由
                # ensure_kem_keys 自动修复 (旧身份升级场景)。
                store.load_private_key(ident, pw)
            store.ensure_kem_keys(ident, pw)
        except Exception as e:
            self.notify(f"密码错误或身份异常: {e}", severity="error")
            return
        if remember:
            _save_pw_cache(ident, pw)
        self.dismiss(True)
        self._on_ok(ident, pw)

    def on_button_pressed(self, event):
        if event.button.id == "login-btn":
            self._do_login()
        elif event.button.id == "login-remember-btn":
            self._toggle_remember()

    def on_input_submitted(self, event):
        if event.input.id == "login-pw":
            self._do_login()

    def on_key(self, event):
        if event.key == "escape":
            if self._on_cancel:
                self._on_cancel()
            self.app.exit(0)
            return


def _identity_exists(identity):
    try:
        from keys import KeyStore
        KeyStore().load_public_key(identity)
        return True
    except Exception:
        return False


def main(identity: str, passphrase: str = None) -> int:
    """TUI 入口 (由 cli.py `chat` 子命令调用), 返回进程退出码。

    passphrase 为 None 时显示登录屏 (TUI 内输入密码/创建身份),
    登录成功后才建立 ChatClient; 退出序列 (设计 §4): app.run() 返回 →
    on_unmount 已停 Binder → client.stop() → LocalStore.close()。
    """
    if LocalStore is None or FileClient is None:
        print("[tui] localstore.py / fileclient.py 尚未就绪 (并行开发中), "
              "无法启动聊天界面", file=sys.stderr)
        return 2
    db_dir = os.path.join(os.path.expanduser("~"), ".zhcrypt", "local")
    try:
        os.makedirs(db_dir, exist_ok=True)
    except OSError as e:
        print(f"[tui] 无法创建本地数据目录 {db_dir}: {e}", file=sys.stderr)
        return 2

    store = LocalStore(os.path.join(db_dir, f"{identity}.db"))
    file_client = FileClient(get_prekey_server(), get_auth_token())

    # 免密直达: 有记住的密码就直接进, 否则走登录屏
    if not passphrase:
        passphrase = _load_pw_cache(identity)
    if passphrase:
        # M13 修复: 缓存密码先用 RSA 主私钥验证; 失败则清除缓存回落登录屏
        # (避免静默进入坏会话, 直到首次发送/接收才暴露)
        try:
            from keys import KeyStore
            KeyStore().load_private_key(identity, passphrase)
        except Exception:
            try:
                os.remove(_pw_cache_path(identity))
            except Exception:
                pass
            passphrase = None

    if passphrase:
        try:
            client = init_client(identity, passphrase)
        except Exception as e:
            print(f"[tui] 初始化失败: {e}", file=sys.stderr)
            passphrase = None
            client = None
        if client is not None:
            app = ChatApp(client=client, store=store, file_client=file_client,
                          identity=identity)
    else:
        app = ChatApp(client=None, store=store, file_client=file_client,
                      identity=identity)

    def _on_login_ok(ident, pw):
        nonlocal store
        # 登录身份可能与启动时的默认身份不同 → 重建对应的本地库
        if ident != app.identity:
            try:
                store.close()
            except Exception:
                pass
            store = LocalStore(os.path.join(db_dir, f"{ident}.db"))
            # C1 修复: 必须把新 store 绑回 app, 否则 Binder/收发全部写旧库
            app.store = store
        try:
            client = init_client(ident, pw)
        except Exception as e:
            app.notify(f"登录初始化失败: {e}", severity="error")
            return
        try:
            app.attach_client(client)
        except Exception as e:
            app.notify(f"进入聊天失败: {e}", severity="error")

    def _on_login_cancel():
        try:
            store.close()
        except Exception:
            pass

    app._login_cb = _on_login_ok
    app._login_cancel = _on_login_cancel

    try:
        rc = app.run()
    finally:
        try:
            if app.client is not None:
                app.client.stop()
        except Exception:
            pass
        try:
            store.close()
        except Exception:
            pass
    return rc if isinstance(rc, int) else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python tui.py <identity> [passphrase]", file=sys.stderr)
        sys.exit(2)
    pw = sys.argv[2] if len(sys.argv) > 2 else None
    sys.exit(main(sys.argv[1], pw))
