# -*- coding: utf-8 -*-
"""
第一轮功能拓展集成测试 (主 agent):
A. 断线重连: bob 离线时 alice 发消息 → bob 重连后补齐, 且无重复投递 (D1 回归)
B. 上传中断续传: 服务端已有部分 .part, 客户端重新上传从协商 offset 继续
C. 并发上传限制: 单身份 >2 个活动上传被 429
"""
import io
import os
import sys
import time
import json
import threading
import tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TOKEN = "e2e-test-token-abcdef123456"
WORK = tempfile.mkdtemp(prefix="zhcrypt_e2e2_")
os.environ["ZHPREKEY_DB"] = os.path.join(WORK, "zhprekey.db")
os.environ["ZHPREKEY_TOKEN"] = TOKEN
os.environ["ZHCHAT_FILE_DIR"] = os.path.join(WORK, "files")
os.environ["ZHCHAT_WS_PORT"] = "5094"

FAIL = []


def step(name):
    print(f"== {name}")


def check(cond, msg):
    if cond:
        print(f"   OK: {msg}")
    else:
        print(f"   FAIL: {msg}")
        FAIL.append(msg)


import asyncio
import server as server_mod
import chat_server as chat_server_mod

server_mod.init_db()
chat_server_mod.init_message_db()

threading.Thread(
    target=lambda: server_mod.app.run(host="127.0.0.1", port=5091, debug=False, use_reloader=False),
    daemon=True).start()

def run_ws():
    asyncio.run(chat_server_mod.main())

threading.Thread(target=run_ws, daemon=True).start()
time.sleep(2)

import config as config_mod
import chat_client as chat_client_mod
chat_client_mod.get_prekey_server = lambda: "http://127.0.0.1:5091"
chat_client_mod.get_auth_token = lambda: TOKEN

from keys import KeyStore
from chat_client import ChatClient

IDA = f"e2e2_{os.getpid()}_alice"
IDB = f"e2e2_{os.getpid()}_bob"

for ident, pw in ((IDA, "pw-a"), (IDB, "pw-b")):
    store = KeyStore()
    try:
        store.generate_identity(ident, pw, comment="e2e2")
    except FileExistsError:
        pass
    store.ensure_kem_keys(ident, pw)


def make_client(ident, pw):
    c = ChatClient(ident, pw)
    c._ws_url = "ws://127.0.0.1:5094/v1/chat"
    c.start()
    return c


def drain(client, want, timeout=15):
    """轮询 INBOUND 直到收到 want 条可解密消息。返回消息列表。"""
    got = []
    deadline = time.time() + timeout
    while time.time() < deadline and len(got) < want:
        for item in client.process_inbound():
            if item.get("action") == "server_message":
                data = item["data"]
                if data.get("type") == "message":
                    res = client.receive_chat_message(data["msg"])
                    if res and "error" not in res:
                        got.append(res)
        time.sleep(0.2)
    return got


step("A1. 建立会话 (alice→bob 首条)")
alice = make_client(IDA, "pw-a")
bob = make_client(IDB, "pw-b")
time.sleep(1.5)
alice.ensure_own_prekey()
bob.ensure_own_prekey()
time.sleep(0.5)

r = alice.send_chat_message(IDB, "first")
check(not r.get("error"), "alice 首条发送")
got = drain(bob, 1)
check(len(got) == 1, "bob 收到首条")

step("A2. bob 离线, alice 发 3 条")
bob.stop()
time.sleep(1)
for i in range(3):
    r = alice.send_chat_message(IDB, f"offline-msg-{i}")
    check(not r.get("error"), f"离线消息 {i} 已发送")

step("A3. bob 重连, 补齐消息且不重复")
bob2 = make_client(IDB, "pw-b")
got2 = drain(bob2, 3)
texts = [g.get("text") for g in got2]
check(len(got2) == 3, f"bob 收到 {len(got2)} 条 (期望 3, 无重复)")
check(sorted(texts) == sorted([f"offline-msg-{i}" for i in range(3)]),
      f"内容齐全: {sorted(texts)}")

step("A4. bob 在线时 alice 发 1 条 (推送路径)")
r = alice.send_chat_message(IDB, "online-msg")
got3 = drain(bob2, 1)
check(len(got3) == 1 and got3[0].get("text") == "online-msg", "在线推送单条到达")

step("A5. 重复投递防护 (D1): 消息 id 全唯一)")
seen_ids = []
for client in (bob2,):
    seen_ids.extend(g.get("msg_id") for g in drain(client, 0))
all_known = []
for g in got + got2 + got3:
    all_known.append(g.get("msg_id"))
check(len(set(all_known)) == len(all_known), f"消息 id 无重复 ({len(all_known)} 条)")

alice.stop()
bob2.stop()

# ---------------- B. 上传中断续传 ----------------
step("B1. 上传中断: 手动造 .part 部分数据")
import fileclient as fc_mod
from fileclient import FileClient, CHUNK_SIZE

fc = FileClient("http://127.0.0.1:5091", TOKEN, IDA)
data = os.urandom(3 * CHUNK_SIZE + 500)

# 直接经端点传前 1.5MB (两段)
upload_token = "ab" * 16
for off, chunk in [(0, data[:CHUNK_SIZE]),
                   (CHUNK_SIZE, data[CHUNK_SIZE:1536 * 1024])]:
    r = fc._http_raw("POST", "http://127.0.0.1:5091/v1/files/upload",
                     headers=fc._auth_headers({
                         "X-Upload-Token": upload_token,
                         "X-Recipient": IDB,
                         "X-Offset": str(off),
                         "X-Total-Size": str(len(data)),
                     }), body=chunk)
    assert r[0] == 409, r
check(os.path.exists(os.path.join(os.environ["ZHCHAT_FILE_DIR"], upload_token + ".part")),
      "服务端存在 .part 部分文件")

step("B2. 客户端重新上传 (复用会话 token) → 从协商 offset 续传 → 201")
tmp = os.path.join(WORK, "resume.bin")
with open(tmp, "wb") as f:
    f.write(data)
res = fc.upload(tmp, IDB, upload_token=upload_token)
check(not res.get("error"), f"续传上传: {res.get('error') or 'ok'}")
if not res.get("error"):
    check(res["token"] == upload_token, "续传 token 一致 (会话幂等)")
    final_path = os.path.join(os.environ["ZHCHAT_FILE_DIR"], upload_token)
    with open(final_path, "rb") as f:
        check(f.read() == data, "续传后文件完整一致")
    check(not os.path.exists(final_path + ".part"), ".part 已 rename 为正式文件")

# ---------------- C. 并发上传限制 ----------------
step("C1. 单身份并发上传 >2 → 429")
for i in range(2):
    r = fc._http_raw("POST", "http://127.0.0.1:5091/v1/files/upload",
                     headers=fc._auth_headers({
                         "X-Upload-Token": ("cd" + str(i)).ljust(32, "0"),
                         "X-Recipient": IDB,
                         "X-Offset": "0",
                         "X-Total-Size": "2000000",
                     }), body=b"x" * 1024)
    assert r[0] == 409, (r[0], r[2])
r = fc._http_raw("POST", "http://127.0.0.1:5091/v1/files/upload",
                 headers=fc._auth_headers({
                     "X-Upload-Token": "ee" * 16,
                     "X-Recipient": IDB,
                     "X-Offset": "0",
                     "X-Total-Size": "2000000",
                 }), body=b"x" * 1024)
check(r[0] == 429, f"第 3 个并发上传被拒 (HTTP {r[0]})")

print()
if FAIL:
    print(f"ROUND1 FAILED: {len(FAIL)} 项失败")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("ROUND1 ALL PASSED")
