# -*- coding: utf-8 -*-
"""真实场景回归: 模拟 chat_server 推送的完整 WS 帧序列 → TUI 信封解包 →
文件消息 key 落库 → 下载解密闭环。验证 Agent-7 C1 修复后 TUI 不再丢消息。"""
import io
import os
import sys
import json
import time
import base64
import hashlib
import threading
import tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import tui
from tui import handle_inbound_item, NewMessage, NotifyToast

FAIL = []


def check(cond, msg):
    print(("   OK: " if cond else "   FAIL: ") + msg)
    if not cond:
        FAIL.append(msg)


class FakeApp:
    def __init__(self, current_peer="bob"):
        self.posted = []
        self._current_peer = current_peer

    def post_message(self, m):
        self.posted.append(m)


class FakeStore:
    """真实 LocalStore 语义的最小替身 (验证 key 落库/取出)。"""

    def __init__(self):
        self.keys = {}
        self.rows = []
        self.file_meta = {}

    def save_file_key(self, msg_id, key):
        self.keys[msg_id] = key

    def take_file_key(self, msg_id):
        return self.keys.pop(msg_id, None)

    def upsert_message(self, peer, msg_id, from_peer, mtype, body, status, verified, ts):
        self.rows.append((msg_id, mtype, body))
        if mtype == "file":
            self.file_meta[msg_id] = json.loads(body)

    def upsert_conversation(self, peer, text, ts, unread_inc=False):
        pass


class FakeChatClient:
    """真实 ChatClient 解密逻辑的最小替身: 返回带 file 元数据的结果。"""

    def __init__(self):
        self.received = []

    def receive_chat_message(self, msg):
        # 与真实 _parse_decrypted 返回结构一致
        self.received.append(msg)
        return {
            "text": "", "from": msg.get("from", "alice"),
            "timestamp": time.time(), "verified": True,
            "msg_id": msg.get("id", "m1"),
            "file": {
                "name": "报告.pdf", "size": 12345,
                "sha256": "deadbeef" * 8,
                "token": "aa" * 16,
                "key": base64.urlsafe_b64encode(b"\x01" * 32).decode(),
            },
        }


# ---------- 场景 1: 实时推送帧 (与 chat_server push_to_identity 完全一致) ----------
print("== 场景 1: 实时推送信封 (type=message)")
app = FakeApp()
client = FakeChatClient()
store = FakeStore()

handle_inbound_item(app, client, store, {
    "action": "server_message",
    "data": {"type": "message",
             "msg": {"id": "real-1", "from": "alice", "to": "bob"}},
})
check(len(client.received) == 1, "消息已进入解密层 (信封解包成功)")
check("real-1" in store.keys, "file_key 已落库 (msg_id=real-1)")
check("key" not in store.file_meta.get("real-1", {}), "local_messages body 不含明文 key")
has_newmsg = any(isinstance(m, NewMessage) for m in app.posted)
check(has_newmsg, "UI 收到 NewMessage 事件")
has_toast = any(isinstance(m, NotifyToast) for m in app.posted)
check(not has_toast, "无错误 toast (不再出现 'from' KeyError)")

# ---------- 场景 2: 离线补拉帧 (与 chat_server get_pending 响应一致) ----------
print("== 场景 2: 离线补拉信封 (type=pending)")
app2 = FakeApp()
client2 = FakeChatClient()
store2 = FakeStore()
handle_inbound_item(app2, client2, store2, {
    "action": "server_message",
    "data": {"type": "pending",
             "messages": [{"id": "p1", "from": "alice"},
                          {"id": "p2", "from": "alice"}]},
})
check(len(client2.received) == 2, "两条 pending 消息均进入解密层")
check("p1" in store2.keys and "p2" in store2.keys, "两个文件 key 均落库")

# ---------- 场景 3: 下载闭环 (take_file_key + 解密格式兼容) ----------
print("== 场景 3: 下载解密闭环")
key = store.take_file_key("real-1")
check(key == b"\x01" * 32, "take_file_key 取出密钥")
# 用 chat_client 的真实单块 AESGCM 格式造密文, 验证 TUI 的 decrypt_file_stream
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
plain = b"PDF content" * 100
nonce = b"\x02" * 12
ct = AESGCM(key).encrypt(nonce, plain, None)
cipher_path = os.path.join(tempfile.mkdtemp(), "f.enc")
with open(cipher_path, "wb") as f:
    f.write(nonce + ct)
out_path = cipher_path + ".out"
err = tui.decrypt_file_stream(key, cipher_path, out_path)
check(err == "", f"decrypt_file_stream 解密成功 (err={err!r})")
with open(out_path, "rb") as f:
    check(f.read() == plain, "解密密文与原文一致")

print()
if FAIL:
    print(f"REAL-SCENARIO FAILED: {len(FAIL)}")
    sys.exit(1)
print("REAL-SCENARIO ALL PASSED")
