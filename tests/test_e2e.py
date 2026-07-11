#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhchat 端到端双向通信测试
测试双方互发 10 条消息，验证 100% 双向到达率
"""

import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import set_prekey_server
# H6: 从环境变量读取服务器配置，避免硬编码
SERVER_URL = os.environ.get("ZHCHAT_TEST_SERVER", "https://iweistoicqc5.top")
AUTH_TOKEN = os.environ.get("ZHCHAT_TEST_TOKEN", "[REDACTED_TOKEN]")

set_prekey_server(SERVER_URL, AUTH_TOKEN)

print("刷新双方 prekey...")
from keys import KeyStore
ks = KeyStore()
def upload(identity, pw):
    import urllib.request, ssl
    bundle = ks.generate_prekey_bundle(identity, pw, otp_count=5)
    data = json.dumps(dict(bundle, identity=identity), ensure_ascii=False).encode()
    req = urllib.request.Request(SERVER_URL + '/v1/prekey/' + identity, data=data, method='POST')
    req.add_header('Authorization', 'Bearer ' + AUTH_TOKEN)
    req.add_header('Content-Type', 'application/json')
    urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30)

upload('default', 'zhcrypt_preshared_password_2024_07_09!')
upload('bob', 'bob123456')
print("  done")

from chat_client import ChatClient

PASS = 0
FAIL = 0

def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label} {detail}")

def process_inbound(client, label):
    """从 INBOUND 队列中提取所有消息"""
    results = []
    for it in client.process_inbound():
        if it.get("action") == "server_message":
            d = it["data"]
            msgs = []
            if d.get("type") == "message" and "msg" in d:
                msgs = [d["msg"]]
            elif d.get("type") == "pending":
                msgs = d.get("messages", [])
            for m in msgs:
                if isinstance(m, dict) and "from" in m:
                    r = client.receive_chat_message(m)
                    if r and "error" not in r:
                        results.append(r)
    return results

def poll_rest(client):
    res = client.poll_messages()
    return [r for r in res if "error" not in r]

print("=" * 60)
print("  zhchat 双向通信测试")
print("=" * 60)
print()
print("清理旧会话...")
home = os.path.expanduser("~/.zhcrypt/sessions")
for r, d, f in os.walk(home):
    for fn in f:
        if fn.endswith(".session"):
            os.remove(os.path.join(r, fn))

print("启动 default 和 bob 客户端...")
default = ChatClient("default", "zhcrypt_preshared_password_2024_07_09!")
bob = ChatClient("bob", "bob123456")
default.start()
bob.start()
time.sleep(3)

print()
print("=== 测试 1: default → bob 发送 3 条 ===")
sent_count = 0
for i in range(3):
    result = default.send_chat_message("bob", f"msg{i}_from_default")
    if result.get("error"):
        print(f"  发送失败: {result['error']}")
        break
    sent_count += 1
    time.sleep(0.5)

check("default 发送 3 条消息", sent_count == 3)
time.sleep(2)

print()
print("=== 测试 2: bob 接收 default 的消息 ===")
bob_items = process_inbound(bob, "bob")
bob_poll = poll_rest(bob)
all_bob = bob_items + bob_poll
received_default = [m for m in all_bob if m.get("from") == "default"]
check("bob 收到 default 的消息", len(received_default) == 3,
      f"(收到 {len(received_default)}/3)")
for m in received_default:
    print(f"  来自 default: {m['text']}")

print()
print("=== 测试 3: bob → default 回复 3 条 ===")
sent_count = 0
for i in range(3):
    result = bob.send_chat_message("default", f"reply{i}_from_bob")
    if result.get("error"):
        print(f"  发送失败: {result['error']}")
        break
    sent_count += 1
    time.sleep(0.5)

check("bob 回复 3 条消息", sent_count == 3)
time.sleep(2)

print()
print("=== 测试 4: default 接收 bob 的回复 ===")
def_items = process_inbound(default, "default")
def_poll = poll_rest(default)
all_def = def_items + def_poll
received_bob = [m for m in all_def if m.get("from") == "bob"]
check("default 收到 bob 的回复", len(received_bob) == 3,
      f"(收到 {len(received_bob)}/3)")
for m in received_bob:
    print(f"  来自 bob: {m['text']}")

print()
print("=== 测试 5: 持续互发 10 条 ===")
msgs_from_default = [f"d{i}_to_bob" for i in range(5)]
msgs_from_bob = [f"b{i}_to_default" for i in range(5)]

# default 先发 5 条
for text in msgs_from_default:
    default.send_chat_message("bob", text)
    time.sleep(0.5)

time.sleep(2)

# bob 接收
bob_items = process_inbound(bob, "bob")
bob_poll = poll_rest(bob)
all_bob = bob_items + bob_poll
received_d = [m for m in all_bob if m.get("from") == "default"]
check("default 的 5 条消息被 bob 接收", len(received_d) >= 5,
      f"(bob 收到 {len(received_d)}/5)")

# bob 回复 5 条
for text in msgs_from_bob:
    bob.send_chat_message("default", text)
    time.sleep(0.5)

time.sleep(2)

# default 接收
def_items = process_inbound(default, "default")
def_poll = poll_rest(default)
all_def = def_items + def_poll
received_b = [m for m in all_def if m.get("from") == "bob"]
check("bob 的 5 条消息被 default 接收", len(received_b) >= 5,
      f"(default 收到 {len(received_b)}/5)")

print()
print("=== 测试 6: 断线重连后消息不丢失 ===")
print("  断开 default 并重连...")
default.stop()
time.sleep(2)
# 重连前先让 bob 发一条
bob.send_chat_message("default", "msg_while_offline")
time.sleep(1)

default2 = ChatClient("default", "zhcrypt_preshared_password_2024_07_09!")
default2.start()
time.sleep(3)

def2_items = process_inbound(default2, "default2")
def2_poll = poll_rest(default2)
all_def2 = def2_items + def2_poll
offline_msg = [m for m in all_def2 if m.get("text") == "msg_while_offline"]
check("断线期间的消息在重连后送达", len(offline_msg) >= 1)
default2.stop()

print()
print("=" * 60)
print(f"  测试结果汇总")
print(f"  通过: {PASS}  |  失败: {FAIL}")
if FAIL == 0:
    print("  双向通信测试通过！")
else:
    print(f"  有 {FAIL} 项失败")
print("=" * 60)

default.stop()
bob.stop()

if FAIL > 0:
    sys.exit(1)
