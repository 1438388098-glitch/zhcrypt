# -*- coding: utf-8 -*-
"""好友功能端到端: 真实服务器 + 双客户端, friend 消息走 ratchet 链路。"""
import io
import os
import sys
import time
import threading
import tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TOKEN = "e2e-friend-token-abcdef123456"
WORK = tempfile.mkdtemp(prefix="zhcrypt_friend_")
os.environ["ZHPREKEY_DB"] = os.path.join(WORK, "zhprekey.db")
os.environ["ZHPREKEY_TOKEN"] = TOKEN
os.environ["ZHCHAT_FILE_DIR"] = os.path.join(WORK, "files")
os.environ["ZHCHAT_WS_PORT"] = "5096"

FAIL = []


def check(cond, msg):
    print(("   OK: " if cond else "   FAIL: ") + msg)
    if not cond:
        FAIL.append(msg)


import asyncio
import server as sm
import chat_server as csm
sm.init_db()
csm.init_message_db()

threading.Thread(target=lambda: sm.app.run(host="127.0.0.1", port=5097,
                                          debug=False, use_reloader=False),
                 daemon=True).start()


def run_ws():
    asyncio.run(csm.main())


threading.Thread(target=run_ws, daemon=True).start()
time.sleep(2)

import config as cfg
import chat_client as ccm
ccm.get_prekey_server = lambda: "http://127.0.0.1:5097"
ccm.get_auth_token = lambda: TOKEN

from keys import KeyStore
from chat_client import ChatClient

IDA = f"fnd_{os.getpid()}_alice"
IDB = f"fnd_{os.getpid()}_bob"

for ident, pw in ((IDA, "pw-a"), (IDB, "pw-b")):
    ks = KeyStore()
    try:
        ks.generate_identity(ident, pw, comment="f")
    except Exception:
        pass
    ks.ensure_kem_keys(ident, pw)


def mk(ident, pw):
    c = ChatClient(ident, pw)
    c._ws_url = "ws://127.0.0.1:5096/v1/chat"
    c.start()
    return c


def drain(client, want, timeout=15):
    got = []
    deadline = time.time() + timeout
    while time.time() < deadline and len(got) < want:
        for item in client.process_inbound():
            if item.get("action") == "server_message":
                data = item["data"]
                if data.get("type") == "message":
                    r = client.receive_chat_message(data["msg"])
                    if r and "error" not in r:
                        got.append(r)
        time.sleep(0.2)
    return got


print("== 好友端到端 ==")
alice = mk(IDA, "pw-a")
bob = mk(IDB, "pw-b")
time.sleep(1.5)
alice.ensure_own_prekey()
bob.ensure_own_prekey()
time.sleep(0.5)

# 1) alice 发好友请求 (自动建会话握手)
r = alice.send_friend_msg(IDB, "request")
check(not r.get("error"), f"alice 发好友请求: {r.get('error') or 'sent'}")
got = drain(bob, 2)
friend_msgs = [g for g in got if g.get("friend")]
check(len(friend_msgs) >= 1, f"bob 收到好友请求消息 {len(friend_msgs)} 条")
if friend_msgs:
    check(friend_msgs[0]["friend"]["action"] == "request",
          f"bob 解密识别 action=request (verified={friend_msgs[0].get('verified')})")

# 2) bob 接受
r2 = bob.send_friend_msg(IDA, "accept")
check(not r2.get("error"), f"bob 接受: {r2.get('error') or 'sent'}")
got2 = drain(alice, 2)
acc = [g for g in got2 if g.get("friend")]
check(len(acc) >= 1 and acc[0]["friend"]["action"] == "accept",
      "alice 收到 accept 确认")

# 3) 好友后正常聊天仍可用
r3 = alice.send_chat_message(IDB, "好友后第一条消息")
check(not r3.get("error"), "好友后文本发送")
got3 = drain(bob, 1)
check(len(got3) >= 1 and got3[0].get("text") == "好友后第一条消息", "bob 收到好友消息")

alice.stop()
bob.stop()

print()
if FAIL:
    print(f"FRIEND-E2E FAILED: {len(FAIL)}")
    sys.exit(1)
print("FRIEND-E2E ALL PASSED")
