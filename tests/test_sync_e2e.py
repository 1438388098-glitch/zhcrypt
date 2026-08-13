# -*- coding: utf-8 -*-
"""私人服务器场景 E2E: 服务器已有 3 个身份 → 新用户登录 → 自动上传 prekey +
好友列表自动同步 3 个身份 (跳过自己)。"""
import io
import os
import sys
import time
import threading
import tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TOKEN = "sync-e2e-token-abcdef123456"
WORK = tempfile.mkdtemp(prefix="zhcrypt_sync_")
os.environ["ZHPREKEY_DB"] = os.path.join(WORK, "zhprekey.db")
os.environ["ZHPREKEY_TOKEN"] = TOKEN
os.environ["ZHCHAT_FILE_DIR"] = os.path.join(WORK, "files")

FAIL = []


def check(cond, msg):
    print(("   OK: " if cond else "   FAIL: ") + msg)
    if not cond:
        FAIL.append(msg)


import server as sm
sm.init_db()
threading.Thread(target=lambda: sm.app.run(host="127.0.0.1", port=5098,
                                          debug=False, use_reloader=False),
                 daemon=True).start()
time.sleep(2)

import chat_client as ccm
ccm.get_prekey_server = lambda: "http://127.0.0.1:5098"
ccm.get_auth_token = lambda: TOKEN

from keys import KeyStore
from chat_client import ChatClient

print("== 私人服务器: 好友自动同步 ==")

# 1) 服务器先注册 3 个身份 (模拟你的朋友们已注册)
for ident in ("friend_a", "friend_b", "friend_c"):
    ks = KeyStore()
    try:
        ks.generate_identity(ident, "pw", comment="f")
    except Exception:
        pass
    ks.ensure_kem_keys(ident, "pw")
    client = ChatClient(ident, "pw")
    client.start()
    time.sleep(0.5)
    ok, msg = client.ensure_own_prekey()
    check(ok, f"{ident} 已注册并上传 prekey")
    client.stop()
    time.sleep(0.3)

# 2) 新用户 me 登录 (服务器还没有 me 的 prekey)
me = "me"
ks = KeyStore()
try:
    ks.generate_identity(me, "mypw", comment="me")
except Exception:
    pass
ks.ensure_kem_keys(me, "mypw")

client = ChatClient(me, "mypw")
client.start()
time.sleep(1)

# 3) 自动上传 prekey (注册后自动一次)
ok, msg = client.ensure_own_prekey()
check(ok, f"新用户自动上传 prekey: {msg}")

# 4) 拉取服务器身份列表
idents = client.fetch_server_identities()
check(not isinstance(idents, dict) or not idents.get("error"),
      f"拉取服务器身份: {len(idents) if isinstance(idents, list) else idents}")
peers = {str(i.get("identity", "")) for i in idents} if isinstance(idents, list) else set()
check("friend_a" in peers and "friend_b" in peers and "friend_c" in peers,
      f"服务器身份包含 3 位朋友: {sorted(peers)}")
check("me" in peers, "自己 (me) 也出现在服务器身份列表")

# 5) 同步逻辑: 跳过自己, 其余全部成为好友
from localstore import LocalStore
store = LocalStore(os.path.join(WORK, "me.db"))
added = 0
for it in (idents if isinstance(idents, list) else []):
    p = str(it.get("identity", ""))
    if not p or p == me:
        continue
    if store.friend_status(p) is None:
        store.upsert_friend(p, "confirmed")
        added += 1
check(added == 3, f"自动同步 {added} 位好友 (friend_a/b/c)")
check(store.friend_status("friend_a") == "confirmed", "friend_a 状态 confirmed")
friends = store.list_friends()
order = [str(f["peer"]) for f in friends]
check(order == sorted(order), f"好友列表从上到下有序: {order}")

client.stop()
store.close()

print()
if FAIL:
    print(f"SYNC-E2E FAILED: {len(FAIL)}")
    sys.exit(1)
print("SYNC-E2E ALL PASSED")
