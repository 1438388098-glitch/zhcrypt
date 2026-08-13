# -*- coding: utf-8 -*-
"""
端到端集成测试 (主 agent 整合): 本地起 Flask server + WS server,
双身份 alice/bob 走完整链路: 身份生成 → prekey 上传 → X3DH 握手 →
文本互发 → 文件发送 → 文件下载解密 → sha256 校验。
"""
import io
import os
import sys
import time
import json
import hashlib
import threading
import tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TOKEN = "e2e-test-token-abcdef123456"
WORK = tempfile.mkdtemp(prefix="zhcrypt_e2e_")
os.environ["ZHPREKEY_DB"] = os.path.join(WORK, "zhprekey.db")
os.environ["ZHPREKEY_TOKEN"] = TOKEN
os.environ["ZHCHAT_FILE_DIR"] = os.path.join(WORK, "files")
os.environ["ZHCHAT_WS_PORT"] = "5093"

FAIL = []


def step(name):
    print(f"== {name}")


def check(cond, msg):
    if cond:
        print(f"   OK: {msg}")
    else:
        print(f"   FAIL: {msg}")
        FAIL.append(msg)


# ---------- 1. 启动服务端 ----------
import asyncio
import server as server_mod
import chat_server as chat_server_mod

server_mod.init_db()
chat_server_mod.init_message_db()

flask_thread = threading.Thread(
    target=lambda: server_mod.app.run(host="127.0.0.1", port=5091, debug=False, use_reloader=False),
    daemon=True)
flask_thread.start()

def run_ws():
    asyncio.run(chat_server_mod.main())

ws_thread = threading.Thread(target=run_ws, daemon=True)
ws_thread.start()
time.sleep(2)

print(f"工作目录: {WORK}")
step("1. 服务端启动 (Flask 5091 + WS 5093)")

# ---------- 2. 配置客户端指向本地 ----------
import config as config_mod
import chat_client as chat_client_mod
# 直接 patch chat_client 模块级配置函数 (绕开 ~/.zhcrypt/config.json 真实配置)
chat_client_mod.get_prekey_server = lambda: "http://127.0.0.1:5091"
chat_client_mod.get_auth_token = lambda: TOKEN
# 同时 patch fileclient 内部使用的 config (upload/download 走 ChatClient 传入, 不需)
config_mod.get_prekey_server = lambda: "http://127.0.0.1:5091"
config_mod.get_auth_token = lambda: TOKEN

# ---------- 3. 初始化身份 ----------
from keys import KeyStore
from chat_client import ChatClient

IDENT_A = f"e2e_{os.getpid()}_alice"
IDENT_B = f"e2e_{os.getpid()}_bob"

step("2. 生成身份 alice/bob")
for ident, pw in ((IDENT_A, "pw-alice"), (IDENT_B, "pw-bob")):
    store = KeyStore()
    try:
        store.generate_identity(ident, pw, comment=f"e2e")
    except FileExistsError:
        pass
    store.ensure_kem_keys(ident, pw)
print(f"   身份已生成: {IDENT_A} / {IDENT_B}")

# ---------- 4. 连接 + 上传 prekey ----------
step("3. 客户端连接 + 上传 prekey")
alice = ChatClient(IDENT_A, "pw-alice")
bob = ChatClient(IDENT_B, "pw-bob")
# 本地无 Nginx 反代: 显式把 WS 指向 chat_server 端口 (生产由 Nginx 同一端口分流)
alice._ws_url = "ws://127.0.0.1:5093/v1/chat"
bob._ws_url = "ws://127.0.0.1:5093/v1/chat"
alice.start()
bob.start()
time.sleep(1.5)

for name, client in (("alice", alice), ("bob", bob)):
    ok, msg = client.ensure_own_prekey()
    check(ok, f"{name} prekey: {msg}")

time.sleep(0.5)

# ---------- 5. 文本互发 (X3DH 握手 + ratchet) ----------
step("4. 文本消息: alice → bob (首次 X3DH)")
r = alice.send_chat_message(IDENT_B, "你好 bob, 这是第一条消息")
check(not r.get("error"), f"alice 发送: {r.get('error') or 'sent'}")

received = []
deadline = time.time() + 10
while time.time() < deadline and not received:
    for item in bob.process_inbound():
        if item.get("action") == "server_message":
            data = item["data"]
            if data.get("type") == "message":
                res = bob.receive_chat_message(data["msg"])
                if res and "error" not in res:
                    received.append(res)
    time.sleep(0.2)
check(len(received) >= 1, f"bob 收到 {len(received)} 条")
if received:
    check(received[0].get("text") == "你好 bob, 这是第一条消息", "bob 解密文本正确")
    check(received[0].get("verified") is True or received[0].get("verified") is False,
          "消息已解密 (verified 字段存在)")

# ---------- 6. bob 回复 ----------
step("5. 文本消息: bob → alice (ratchet 连续消息)")
r2 = bob.send_chat_message(IDENT_A, "收到! 文件发过来吧")
check(not r2.get("error"), f"bob 发送: {r2.get('error') or 'sent'}")

received2 = []
deadline = time.time() + 10
while time.time() < deadline and not received2:
    for item in alice.process_inbound():
        if item.get("action") == "server_message":
            data = item["data"]
            if data.get("type") == "message":
                res = alice.receive_chat_message(data["msg"])
                if res and "error" not in res:
                    received2.append(res)
    time.sleep(0.2)
check(len(received2) >= 1, f"alice 收到 {len(received2)} 条")
if received2:
    check(received2[0].get("text") == "收到! 文件发过来吧", "alice 解密文本正确")

# ---------- 7. 文件传输 (大文件 2MB 含多个分块) ----------
step("6. 文件发送: alice → bob (2.5MB, 3 个分块)")
big_file = os.path.join(WORK, "big_report.bin")
payload = os.urandom(2 * 1024 * 1024 + 512 * 1024)
with open(big_file, "wb") as f:
    f.write(payload)

progress_hits = []
def prog(done, total):
    progress_hits.append((done, total))

r3 = alice.send_file(IDENT_B, big_file, progress_cb=prog)
check(not r3.get("error"), f"alice 发送文件: {r3.get('error') or 'sent'}")

received3 = []
deadline = time.time() + 15
while time.time() < deadline and not received3:
    for item in bob.process_inbound():
        if item.get("action") == "server_message":
            data = item["data"]
            if data.get("type") == "message":
                res = bob.receive_chat_message(data["msg"])
                if res and "error" not in res:
                    received3.append(res)
    time.sleep(0.2)
check(len(received3) >= 1, f"bob 收到文件消息 {len(received3)} 条")
file_meta = None
if received3:
    file_meta = received3[0].get("file")
    check(file_meta is not None, "消息含 file 元数据")
    if file_meta:
        check(file_meta.get("name") == "big_report.bin", "文件名正确")
        check(file_meta.get("size") == len(payload), "文件大小正确")
        check(file_meta.get("sha256") == hashlib.sha256(payload).hexdigest(), "sha256 正确")
        check(file_meta.get("token") and len(file_meta["token"]) == 32, "token 32hex")
        check(file_meta.get("key") and len(file_meta["key"]) > 0, "file_key 已随消息传递")

# ---------- 8. bob 下载 + 解密 ----------
step("7. 文件下载 + 解密校验")
if file_meta:
    token = file_meta["token"]
    dest = os.path.join(WORK, "downloads")
    os.makedirs(dest, exist_ok=True)
    from base64 import urlsafe_b64decode
    key = urlsafe_b64decode(file_meta["key"].encode())
    check(len(key) == 32, "file_key 32 字节")

    r4 = bob.download_file(token, dest)
    check(not r4.get("error"), f"bob 下载: {r4.get('error') or 'ok'}")
    if not r4.get("error"):
        cipher_path = r4["path"]
        out_path = os.path.join(dest, "decrypted.bin")
        # 用 ChatClient.decrypt_file 单块解密 (与 send_file 加密格式一致)
        r5 = ChatClient.decrypt_file(cipher_path, file_meta["key"], "decrypted.bin",
                                     file_meta["sha256"])
        check(not r5.get("error"), f"解密: {r5.get('error') or 'ok'}")
        if not r5.get("error"):
            with open(r5["path"], "rb") as f:
                got = f.read()
            check(got == payload, "解密文件与原文完全一致 (sha256 同源)")

# ---------- 9. 进度回调 ----------
step("8. 进度回调检查")
check(len(progress_hits) >= 1, f"上传进度回调 {len(progress_hits)} 次")
if progress_hits:
    check(progress_hits[-1][0] == progress_hits[-1][1], "最终进度 done == total")

# ---------- 10. 历史消息 ----------
step("9. 历史消息拉取")
hist = bob.get_history(IDENT_A, limit=50)
check(isinstance(hist, list), f"历史拉取 {len(hist)} 条")

# ---------- 11. delivered 状态 ----------
step("10. delivered 查询")
r6 = alice.query_delivered([r.get("msg_id", "") for r in received2] or ["none"])
check(not r6.get("error"), f"delivered 查询: {r6.get('error') or 'ok'}")

alice.stop()
bob.stop()

print()
if FAIL:
    print(f"E2E FAILED: {len(FAIL)} 项失败")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("E2E ALL PASSED")
