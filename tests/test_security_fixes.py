#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt 安全修复回归测试
======================
锁定审计报告中已修复的问题, 防止后续改动引入回归:

  #2  身份名路径穿越 (KeyStore 身份校验)
  #6  签名私钥不再上传/存储 (generate_prekey_bundle / server)
  #15 KEM 私钥文件格式修复 (ensure_kem_keys 与 _unwrap_key 格式一致)

运行: python test_security_fixes.py
"""

import os
import sys
import json
import shutil
import tempfile
import importlib
import secrets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from keys import KeyStore
from core import (generate_rsa_key_pair, serialize_public_key,
                 urlsafe_b64decode, ed25519_verify)

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
    return condition


def section(msg):
    print(f"\n{'='*60}\n  {msg}\n{'='*60}")


# ============================================================
# #2 身份名路径穿越
# ============================================================
section("#2 身份名路径穿越防护")

# 使用独立沙箱目录, 避免系统临时目录里的无关文件干扰逃逸检测
sandbox = tempfile.mkdtemp(prefix="zhcrypt_secfix_sandbox_")
tmp = os.path.join(sandbox, "keydir")
os.makedirs(tmp)

try:
    store = KeyStore(tmp)
    malicious = [
        "../../etc/evil",
        "../escape",
        "a/../b",
        "foo\\bar",
        "..",
        "a b",
        "中文名",
    ]
    rejected = 0
    for name in malicious:
        try:
            store.generate_identity(name, "pw123")
            print(f"  [WARN] 未拒绝恶意身份: {name!r}")
        except ValueError:
            rejected += 1
        except Exception as e:
            print(f"  [WARN] 恶意身份 {name!r} 抛出了非预期异常: {e!r}")
    check("所有恶意身份名均被拒绝", rejected == len(malicious),
          f"(拒绝 {rejected}/{len(malicious)})")

    # 导入路径同样必须拒绝恶意身份
    _, pub = generate_rsa_key_pair()
    pub_b64 = __import__("base64").urlsafe_b64encode(
        serialize_public_key(pub)).decode("ascii")
    import_rejected = False
    try:
        store.import_public_key_b64(pub_b64, "../../evil_import")
    except ValueError:
        import_rejected = True
    check("import_public_key_b64 拒绝恶意身份", import_rejected)

    # 正常身份名仍应正常工作 (白名单内)
    store.generate_identity("alice_normal", "pw123")
    check("合法身份名可正常创建",
          os.path.exists(os.path.join(tmp, "alice_normal.pub")))

    # 确认没有任何文件被写到沙箱内的 key_dir 之外
    outside = []
    for root, dirs, files in os.walk(sandbox):
        if root == tmp or root.startswith(tmp + os.sep):
            continue
        outside.extend(os.path.join(root, f) for f in files)
    check("无文件被写到 key_dir 之外", len(outside) == 0,
          f"(发现 {outside})")
except Exception as e:
    FAIL += 1
    print(f"  [FAIL] #2 测试异常: {e!r}")
finally:
    shutil.rmtree(sandbox, ignore_errors=True)


# ============================================================
# #15 KEM 私钥文件格式修复 (修复前: ensure_kem_keys 生成的 .x25519 无法被 _unwrap_key 解密)
# ============================================================
section("#15 KEM 私钥文件格式一致性")

tmp = tempfile.mkdtemp(prefix="zhcrypt_secfix_kem_")

try:
    store = KeyStore(tmp)
    store.generate_identity("kemuser", "kempw")
    # 模拟旧身份: 删除自动生成的 X25519 密钥, 触发 ensure_kem_keys 重新生成
    os.remove(os.path.join(tmp, "kemuser.x25519"))
    os.remove(os.path.join(tmp, "kemuser.x25519.pub"))

    generated = store.ensure_kem_keys("kemuser", "kempw")
    check("ensure_kem_keys 检测到缺失并生成", generated is True)

    # 关键: 生成的 .x25519 必须能被正确解密 (修复前会抛 DecryptionError)
    try:
        priv_pem = store.load_kem_private_key_pem("kemuser", "kempw")
        ok_kem = priv_pem.startswith(b"-----BEGIN")
    except Exception as e:
        ok_kem = False
        print(f"  [WARN] load_kem_private_key_pem 失败: {e!r}")
    check("ensure_kem_keys 生成的私钥可正常解密", ok_kem)
except Exception as e:
    FAIL += 1
    print(f"  [FAIL] #15 测试异常: {e!r}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)


# ============================================================
# #6 签名私钥不再进入上传 bundle (客户端)
# ============================================================
section("#6 客户端: prekey bundle 不含签名私钥")

tmp = tempfile.mkdtemp(prefix="zhcrypt_secfix_pk_")

try:
    store = KeyStore(tmp)
    store.generate_identity("pkuser", "pkpw")
    store.ensure_kem_keys("pkuser", "pkpw")
    bundle = store.generate_prekey_bundle("pkuser", "pkpw", otp_count=3)

    check("bundle 不含 signed_prekey_priv", "signed_prekey_priv" not in bundle)
    check("bundle 仍含 signed_prekey_pub", "signed_prekey_pub" in bundle)
    check("bundle 仍含 signature", "signature" in bundle)
    check("bundle 含 one_time_prekeys", len(bundle.get("one_time_prekeys", [])) == 3)
except Exception as e:
    FAIL += 1
    print(f"  [FAIL] #6 客户端测试异常: {e!r}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)


# ============================================================
# #6 服务端: 即便误传私钥也不存储 (需要 Flask)
# ============================================================
section("#6 服务端: 拒绝存储签名私钥")

try:
    importlib.import_module("flask")
    flask_available = True
except Exception:
    flask_available = False

if not flask_available:
    print("  [SKIP] Flask 未安装, 跳过服务端测试")
else:
    tmp = tempfile.mkdtemp(prefix="zhcrypt_secfix_srv_")
    os.environ["ZHPREKEY_TOKEN"] = "secfix_test_token"
    os.environ["ZHPREKEY_DB"] = os.path.join(tmp, "test_zhprekey.db")
    try:
        server = importlib.import_module("server")
        client = server.app.test_client()
        bundle = {
            "identity_key_pub": "AAA",
            "signed_prekey_pub": "BBB",
            "signature": "CCC",
            "fingerprint": "ffff",
            "signed_prekey_priv": "PRIVATE_SHOULD_NOT_BE_STORED",
            "one_time_prekeys": ["OT1", "OT2"],
        }
        r = client.post("/v1/prekey/alice", json=bundle,
                        headers={"Authorization": "Bearer secfix_test_token"})
        check("上传接口返回 200", r.status_code == 200,
              f"(status={r.status_code}, body={r.get_data(as_text=True)[:120]})")

        import sqlite3
        db = sqlite3.connect(server.DB_PATH)
        rows = db.execute(
            "SELECT key_type, prekey_data FROM prekeys").fetchall()
        db.close()
        leaked = any(kt == "signed" or "PRIVATE_SHOULD_NOT_BE_STORED" in (d or "")
                     for kt, d in rows)
        check("服务端未存储任何私钥", not leaked, f"(rows={rows})")
    except Exception as e:
        FAIL += 1
        print(f"  [FAIL] #6 服务端测试异常: {e!r}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================
# #5 首次通信签名校验 (TOFU)
# ============================================================
section("#5 首次通信签名校验 (TOFU)")

tmp5 = tempfile.mkdtemp(prefix="zhcrypt_secfix5_")
tmp5a = os.path.join(tmp5, "alice")
tmp5b = os.path.join(tmp5, "bob")
tmp5c = os.path.join(tmp5, "carol")
try:
    # alice / bob / carol 各用独立 keystore (真实场景下对端不是本地身份)
    store_a = KeyStore(tmp5a)
    store_b = KeyStore(tmp5b)
    store_c = KeyStore(tmp5c)
    pw5 = "secfix-pw-5"
    store_a.generate_identity("alice", pw5)
    store_b.generate_identity("bob", pw5)
    store_c.generate_identity("carol", pw5)
    store_a.ensure_kem_keys("alice", pw5)
    store_b.ensure_kem_keys("bob", pw5)
    store_c.ensure_kem_keys("carol", pw5)

    # 5a: bundle 现携带签名公钥, 且 SPK 签名可被该公钥验证
    bundle5 = store_b.generate_prekey_bundle("bob", pw5)
    check("bundle 含 signing_public_key", bool(bundle5.get("signing_public_key")))
    _spk_pub = urlsafe_b64decode(bundle5["signed_prekey_pub"].encode())
    _spk_sig = urlsafe_b64decode(bundle5["signature"].encode())
    _sign_pub = urlsafe_b64decode(bundle5["signing_public_key"].encode())
    check("签名公钥可验证 SPK 签名", ed25519_verify(_sign_pub, _spk_pub, _spk_sig))

    # 5b: TOFU store/load round-trip
    store_a.store_tofu_signing_pub("dave", _sign_pub)
    check("TOFU 读取一致", store_a.load_tofu_signing_pub("dave") == _sign_pub)

    # 5c: 集成 - 首次通信握手并固定 TOFU (alice 的 store 里没有 bob 这个本地身份)
    from chat_client import ChatClient as _CC

    def _fake_get(method, path, body=None, timeout=15):
        if method == "GET" and path.startswith("/v1/prekey/"):
            return {
                "status": "ok", "identity": "bob",
                "fingerprint": bundle5["fingerprint"],
                "identity_key_pub": bundle5["identity_key_pub"],
                "signed_prekey_pub": bundle5["signed_prekey_pub"],
                "signed_prekey_sig": bundle5["signature"],
                "signing_public_key": bundle5["signing_public_key"],
                "one_time_prekey": bundle5["one_time_prekeys"][0],
                "has_more_otp": True,
            }
        return {"error": "noop"}

    a = _CC("alice", pw5)
    a.store = store_a
    a._http_request = _fake_get
    res5 = a._initiate_session("bob")
    check("首次通信握手成功", "error" not in res5, str(res5))
    check("TOFU 已固定 bob 签名公钥",
          store_a.load_tofu_signing_pub("bob") == _sign_pub)
    check("返回首次接触标记", res5.get("first_contact") is True)
    check("返回 safety number", bool(res5.get("safety_number")))

    # 5d: SPK 签名被篡改 -> 拒绝
    def _fake_get_badsig(method, path, body=None, timeout=15):
        r = _fake_get(method, path, body, timeout)
        if method == "GET" and path.startswith("/v1/prekey/"):
            import base64 as _b64
            sig = bytearray(urlsafe_b64decode(r["signed_prekey_sig"].encode()))
            sig[0] ^= 0xFF
            r["signed_prekey_sig"] = _b64.urlsafe_b64encode(bytes(sig)).decode()
        return r

    a3 = _CC("alice", pw5)
    a3.store = store_a
    a3._http_request = _fake_get_badsig
    res5d = a3._initiate_session("bob")
    check("SPK 签名被篡改被拒绝",
          "error" in res5d and "签名验证失败" in res5d["error"], str(res5d))

    # 5e: 换钥检测 - 已记录的签名公钥与 bundle 不一致 -> 拒绝 (MITM/换钥)
    carol_sign = store_c.load_signing_public_key("carol")
    store_a.store_tofu_signing_pub("bob", carol_sign)  # 模拟已记录为错误公钥
    a2 = _CC("alice", pw5)
    a2.store = store_a
    a2._http_request = _fake_get
    res5e = a2._initiate_session("bob")
    check("签名公钥突变(MITM/换钥)被拒绝",
          "error" in res5e and "不一致" in res5e["error"], str(res5e))
except Exception as e:
    FAIL += 1
    print(f"  [FAIL] #5 测试异常: {e!r}")
finally:
    shutil.rmtree(tmp5, ignore_errors=True)


# ============================================================
# #7 文件下载权限模型 (上传者 / 接收方)
# ============================================================
section("#7 文件下载权限模型")

tmp7 = tempfile.mkdtemp(prefix="zhcrypt_secfix7_")
try:
    os.environ.setdefault("ZHPREKEY_TOKEN", secrets.token_hex(16))
    os.environ["ZHPREKEY_DB"] = os.path.join(tmp7, "test_zhprekey.db")
    import sqlite3 as _sql
    from chat_server import record_file_upload, can_download_file

    db7 = _sql.connect(":memory:")
    db7.row_factory = _sql.Row
    db7.execute("CREATE TABLE files (token TEXT PRIMARY KEY, uploader TEXT NOT NULL, intended_recipient TEXT, server_ts REAL NOT NULL)")

    record_file_upload(db7, "t1", "alice", "bob")
    check("上传者可下载自己的文件", can_download_file(db7, "t1", "alice"))
    check("接收方可下载文件", can_download_file(db7, "t1", "bob"))
    check("第三方不可下载", not can_download_file(db7, "t1", "carol"))

    record_file_upload(db7, "t2", "alice", "")
    check("无接收方时仅上传者可下载",
          can_download_file(db7, "t2", "alice") and
          not can_download_file(db7, "t2", "bob"))
    check("不存在的 token 被拒绝", not can_download_file(db7, "nx", "alice"))
except Exception as e:
    FAIL += 1
    print(f"  [FAIL] #7 测试异常: {e!r}")
finally:
    shutil.rmtree(tmp7, ignore_errors=True)


# ============================================================
# #1-REST 发送者伪造 + #10 限流绕过 (REST 消息接口)
# ============================================================
section("#1-REST 发送者伪造 + #10 限流绕过 (REST)")

try:
    importlib.import_module("flask")
    flask_available = True
except Exception:
    flask_available = False

if not flask_available:
    print("  [SKIP] Flask 未安装, 跳过 REST 接口测试")
else:
    tmp1 = tempfile.mkdtemp(prefix="zhcrypt_secfix1_")
    os.environ["ZHPREKEY_TOKEN"] = "secfix1_token"
    os.environ["ZHPREKEY_DB"] = os.path.join(tmp1, "test_zhprekey.db")
    try:
        server = importlib.import_module("server")
        server.AUTH_TOKEN = "secfix1_token"
        server.DB_PATH = os.path.join(tmp1, "test_zhprekey.db")
        server.init_db()
        client = server.app.test_client()
        H = {"Authorization": "Bearer secfix1_token"}

        # 1) 缺少 identity -> 400 (强制服务端决定发送者, 不再信任客户端 from)
        r = client.post("/v1/messages/send",
                        json={"id": "m0", "to": "bob"}, headers=H)
        check("缺少 identity 被拒绝 (400)", r.status_code == 400,
              f"(status={r.status_code})")

        # 2) 携带 from 也只允许以 identity 作为发送者 (from 被忽略)
        r = client.post("/v1/messages/send",
                        json={"id": "m1", "to": "bob", "identity": "alice",
                              "from": "bob"},
                        headers=H)
        check("带 identity 的消息被接受 (200)", r.status_code == 200,
              f"(status={r.status_code}, body={r.get_data(as_text=True)[:120]})")

        import sqlite3 as _sql
        db1 = _sql.connect(server.DB_PATH)
        db1.row_factory = _sql.Row
        row = db1.execute("SELECT sender FROM messages WHERE id=?",
                          ("m1",)).fetchone()
        db1.close()
        check("存储的发送者为 identity(alice), 而非 from(bob)",
              row is not None and row["sender"] == "alice")

        # 3) #10: 速率限制按真实客户端 IP 计, 不因切换 from/identity 绕过
        old_limit = server.MESSAGE_RATE_LIMIT
        server.MESSAGE_RATE_LIMIT = 3
        server._message_rate_buckets.clear()
        try:
            sent = 0
            blocked = False
            for i in range(5):
                rr = client.post(
                    "/v1/messages/send",
                    json={"id": f"rl{i}", "to": "bob",
                          "identity": f"user{i}"},  # 每次换 identity, 仍应被同一 IP 限流
                    headers=H)
                if rr.status_code == 429:
                    blocked = True
                else:
                    sent += 1
            check("切换 identity 仍被同一 IP 限流 (429)", blocked,
                  f"(sent={sent})")
            check("达到上限后拒绝 (最多 3 条/分钟)", sent <= 3,
                  f"(sent={sent})")
        finally:
            server.MESSAGE_RATE_LIMIT = old_limit
            server._message_rate_buckets.clear()
    except Exception as e:
        FAIL += 1
        print(f"  [FAIL] #1-REST 测试异常: {e!r}")
    finally:
        shutil.rmtree(tmp1, ignore_errors=True)


# ============================================================
# #13 源码无硬编码公网 IP (防止源码泄露暴露服务器地址)
# ============================================================
section("#13 源码无硬编码公网 IP")

# 注意: 本测试已被移动到 tests/ 子目录, 源码在项目根(父目录),
# 因此 PROJECT_ROOT 必须取父目录才能正确扫描源码中的硬编码 IP/Token。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OWN_PY_FILES = [f for f in os.listdir(PROJECT_ROOT)
                if f.endswith(".py") and f != "test_security_fixes.py"]

ip_leaked = []
for fn in OWN_PY_FILES:
    try:
        with open(os.path.join(PROJECT_ROOT, fn), "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception:
        continue
    # 仅检测已知的生产服务器 IP, 避免误报 loopback/localhost
    if "[REDACTED_IP]" in content:
        ip_leaked.append(fn)
check("所有自研源文件均不含硬编码公网 IP", len(ip_leaked) == 0,
      f"(命中: {ip_leaked})")
check("server.py 模块注释已去除 IP",
      "[REDACTED_IP]" not in open(os.path.join(PROJECT_ROOT, "server.py"),
                                 encoding="utf-8", errors="ignore").read())


# ============================================================
# #14 Auth Token 不泄露到源码/日志 (防止前缀泄露)
# ============================================================
section("#14 Auth Token 不泄露到源码/日志")

token_leak = []
for fn in OWN_PY_FILES:
    try:
        with open(os.path.join(PROJECT_ROOT, fn), "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception:
        continue
    # 任何形如 AUTH_TOKEN[:N] / AUTH_TOKEN[0: / print(AUTH_TOKEN 前缀 的写法都视为泄露
    if "AUTH_TOKEN[" in content or "AUTH_TOKEN[:8]" in content \
            or "AUTH_TOKEN[:4]" in content:
        token_leak.append(fn)
check("源码中不存在 Token 前缀打印", len(token_leak) == 0, f"(命中: {token_leak})")
for srv in ("server.py", "chat_server.py"):
    c = open(os.path.join(PROJECT_ROOT, srv), encoding="utf-8", errors="ignore").read()
    check(f"{srv} 启动打印已隐藏 Token (***)",
          'Auth Token: ***' in c or 'Auth Token: *** (已隐藏)' in c)


# ============================================================
# #19 WebSocket handler 签名兼容 (websockets 11+ 单参数调用)
# ============================================================
section("#19 WebSocket handler 签名兼容 (websockets 11+)")

try:
    import inspect
    import websockets as _wsmod
    cs = importlib.import_module("chat_server")
    sig = inspect.signature(cs.handler)
    params = list(sig.parameters)
    check("handler 首个参数为 websocket",
          len(params) >= 1 and params[0] == "websocket",
          f"(params={params})")
    if len(params) >= 2:
        has_default = sig.parameters[params[1]].default is not inspect.Parameter.empty
        check("handler 第二参数有默认值(兼容新版 websockets 单参调用)",
              has_default, f"(param={params[1]})")
    else:
        check("handler 仅需 websocket 单参数(新版 websockets)", True)
    # 实际绑定: 仅传 websocket 不应抛 TypeError
    try:
        sig.bind(object())
        bound_ok = True
    except TypeError:
        bound_ok = False
    check("handler 可仅以单参数(websocket)调用", bound_ok)
except Exception as e:
    FAIL += 1
    print(f"  [FAIL] #19 测试异常: {e!r}")


# ============================================================
# #1-WS + 文件下载路径穿越 (WebSocket 服务端集成测试)
#   真实跑 handler: 验证发送者伪造防护 与 token 路径穿越防护
# ============================================================
section("#1-WS 发送者伪造 + 文件下载 token 路径穿越 (WS 集成)")

try:
    import asyncio
    import base64 as _b64mod
    import sqlite3 as _sqlmod

    os.environ.setdefault("ZHCHAT_TOKEN", "TKWSTEST_WS")
    os.environ["ZHPREKEY_DB"] = os.path.join(
        tempfile.mkdtemp(prefix="zhcrypt_wssec_"), "wssec.db")

    cs = importlib.import_module("chat_server")
    cs.AUTH_TOKEN = "TKWSTEST_WS"
    _ws_tmp = tempfile.mkdtemp(prefix="zhcrypt_wssec_files_")
    cs.FILE_DIR = _ws_tmp
    os.makedirs(_ws_tmp, exist_ok=True)
    cs.DB_PATH = os.environ["ZHPREKEY_DB"]
    cs.init_message_db()

    class _FakeWS:
        def __init__(self, incoming):
            self._q = list(incoming)
            self.sent = []
        def __aiter__(self):
            return self
        async def __anext__(self):
            if not self._q:
                raise _wsmod.exceptions.ConnectionClosed(1000, "eof")
            return self._q.pop(0)
        async def send(self, data):
            self.sent.append(json.loads(data))
        async def close(self):
            pass

    async def _run_ws_security():
        res = {}
        # Session 1: alice 认证 -> 发送伪造 from 的消息 -> 上传文件
        up = _FakeWS([
            json.dumps({"type": "auth", "token": "TKWSTEST_WS", "identity": "alice"}),
            json.dumps({"type": "send",
                        "msg": {"id": "m1", "to": "bob", "from": "carol",
                                "session_id": "sess-m1"}}),
            json.dumps({"type": "file_upload",
                        "file_data": _b64mod.b64encode(b"hello-bob").decode(),
                        "recipient": "bob"}),
        ])
        await cs.handler(up)
        res["send_ack"] = any(m.get("type") == "ack" and m.get("msg_id") == "m1"
                              for m in up.sent)
        res["upload_ack"] = next((m for m in up.sent
                                  if m.get("type") == "file_upload_ack"), None)
        _db = _sqlmod.connect(cs.DB_PATH)
        _db.row_factory = _sqlmod.Row
        _row = _db.execute("SELECT sender FROM messages WHERE id=?",
                           ("m1",)).fetchone()
        _db.close()
        res["sender"] = _row["sender"] if _row else None

        # Session 2: bob 下载 (合法 token / 路径穿越 token / 非法 token)
        tok = res["upload_ack"]["token"] if res["upload_ack"] else None
        down = _FakeWS([
            json.dumps({"type": "auth", "token": "TKWSTEST_WS", "identity": "bob"}),
            json.dumps({"type": "file_download", "token": tok}),
            json.dumps({"type": "file_download", "token": "../../../../etc/passwd"}),
            json.dumps({"type": "file_download", "token": "not-a-token"}),
        ])
        await cs.handler(down)
        res["dl_ok"] = any(m.get("type") == "file_download_resp" and m.get("token") == tok
                           for m in down.sent)
        # 按响应顺序断言: 合法下载返回 resp, 随后两个恶意 token 均返回 404
        # (handler 的 error 响应不回显 token, 故按请求顺序匹配)
        _dl_msgs = [m for m in down.sent
                    if m.get("type") in ("file_download_resp", "error")]
        res["dl_traversal_blocked"] = (
            len(_dl_msgs) >= 2 and
            _dl_msgs[1].get("type") == "error" and
            _dl_msgs[1].get("code") in (400, 404))
        res["dl_invalid_blocked"] = (
            len(_dl_msgs) >= 3 and
            _dl_msgs[2].get("type") == "error" and
            _dl_msgs[2].get("code") in (400, 404))
        return res

    # 兼容 Python 3.6 (asyncio.run 为 3.7+), 与 chat_server.py 运行路径一致
    _loop = asyncio.new_event_loop()
    try:
        _res = _loop.run_until_complete(_run_ws_security())
    finally:
        _loop.close()

    check("WS 认证后发送消息收到 ack", _res.get("send_ack") is True)
    check("WS 发送者伪造被覆盖(存储 sender=alice, 非 carol)",
          _res.get("sender") == "alice", f"(sender={_res.get('sender')})")
    check("文件上传返回 token", _res.get("upload_ack") is not None)
    if _res.get("upload_ack"):
        import re as _re
        check("上传 token 为 32 位十六进制",
              bool(_re.match(r"^[0-9a-f]{32}$", _res["upload_ack"]["token"])))
    check("接收方 bob 可下载自己收到的文件(#7 WS 层)", _res.get("dl_ok") is True)
    check("文件下载 token 路径穿越被拦截(404/400)",
          _res.get("dl_traversal_blocked") is True)
    check("非法格式 token 被拒绝(404/400)",
          _res.get("dl_invalid_blocked") is True)

    # 清理临时文件目录
    shutil.rmtree(_ws_tmp, ignore_errors=True)
    shutil.rmtree(os.path.dirname(cs.DB_PATH), ignore_errors=True)
except Exception as e:
    FAIL += 1
    print(f"  [FAIL] #1-WS 集成测试异常: {e!r}")


# ============================================================
# #8 Auth Token 加密存储 (设备密钥, 不再明文落盘)
# ============================================================
section("#8 Auth Token 设备密钥加密存储")

import config as _cfg
_secfix_tmp = tempfile.mkdtemp(prefix="zhcrypt_secfix_cfg8_")
_cfg.CONFIG_DIR = _secfix_tmp
_cfg.CONFIG_PATH = os.path.join(_secfix_tmp, "config.json")
_cfg.DEVICE_KEY_PATH = os.path.join(_secfix_tmp, "device.key")

_cfg.set_prekey_server("https://prekey.example.com", "super-secret-token-xyz")
_raw = json.load(open(_cfg.CONFIG_PATH, "r", encoding="utf-8"))
check("#8 配置文件中不含明文 token", _raw["prekey_server"].get("auth_token", "") == "")
check("#8 配置文件中存在加密 token", bool(_raw["prekey_server"].get("auth_token_enc", "")))
check("#8 明文 token 未出现在加密字段中",
      "super-secret-token-xyz" not in _raw["prekey_server"]["auth_token_enc"])
check("#8 get_auth_token 可还原 token", _cfg.get_auth_token() == "super-secret-token-xyz")
check("#8 device.key 已生成为 32 字节",
      os.path.exists(_cfg.DEVICE_KEY_PATH) and os.path.getsize(_cfg.DEVICE_KEY_PATH) == 32)

# 迁移: 旧版明文 auth_token 在读取时自动加密重写
_cfg2 = json.load(open(_cfg.CONFIG_PATH, "r", encoding="utf-8"))
_cfg2["prekey_server"]["auth_token"] = "legacy-plain-token"
_cfg2["prekey_server"]["auth_token_enc"] = ""
json.dump(_cfg2, open(_cfg.CONFIG_PATH, "w", encoding="utf-8"))
check("#8 旧明文 token 迁移后仍可读", _cfg.get_auth_token() == "legacy-plain-token")
_raw2 = json.load(open(_cfg.CONFIG_PATH, "r", encoding="utf-8"))
check("#8 迁移后明文已被清除", _raw2["prekey_server"].get("auth_token", "") == "")

# 设备密钥不同 (另一台机器) 无法解密
_secfix_tmp2 = tempfile.mkdtemp(prefix="zhcrypt_secfix_cfg8b_")
_cfg.CONFIG_DIR = _secfix_tmp2
_cfg.CONFIG_PATH = os.path.join(_secfix_tmp2, "config.json")
_cfg.DEVICE_KEY_PATH = os.path.join(_secfix_tmp2, "device.key")
# 复制加密配置, 但 device.key 不同 -> 解密失败返回空
shutil.copyfile(os.path.join(_secfix_tmp, "config.json"), _cfg.CONFIG_PATH)
check("#8 缺少对应设备密钥时 token 不可解密", _cfg.get_auth_token() == "")

# ============================================================
# #18 证书固定 (certificate pinning)
# ============================================================
section("#18 证书固定 (certpin)")

import certpin as _certpin
from cryptography import x509 as _x509
from cryptography.x509.oid import NameOID as _NameOID
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import ec as _ec
import datetime as _dt
_k = _ec.generate_private_key(_ec.SECP256R1())
_subj = _iss = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, u"zhcrypt-test")])
_cert = (_x509.CertificateBuilder().subject_name(_subj).issuer_name(_iss)
         .public_key(_k.public_key()).serial_number(12345)
         .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
         .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365))
         .sign(_k, _hashes.SHA256()))
_der = _cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization",
                                     fromlist=["Encoding"]).Encoding.DER)
_pin = _certpin.compute_cert_pin(_der)
check("#18 指纹计算非空", bool(_pin))
check("#18 正确指纹校验通过", _certpin.verify_cert_pin(_der, _pin) is True)
check("#18 错误指纹校验拒绝", _certpin.verify_cert_pin(_der, "INVALIDPIN==") is False)

# 证书固定配置读写
_cfg.CONFIG_DIR = _secfix_tmp
_cfg.CONFIG_PATH = os.path.join(_secfix_tmp, "config.json")
_cfg.DEVICE_KEY_PATH = os.path.join(_secfix_tmp, "device.key")
_cfg.set_cert_pin(_pin)
check("#18 cert_pin 已写入配置", _cfg.get_cert_pin() == _pin)
_cfg.set_cert_pin("")
check("#18 cert_pin 可清除", _cfg.get_cert_pin() == "")

# ============================================================
# #3/#4 wss 必须启用证书校验 (build_ws_sslopt)
# ============================================================
section("#3/#4 wss 启用 TLS 证书校验")

import ssl as _ssl
import chat_client as _cc
_wss_opt = _cc.build_ws_sslopt("wss://prekey.example.com/v1/chat")
check("#3/#4 wss sslopt 要求校验证书", _wss_opt.get("cert_reqs") == _ssl.CERT_REQUIRED)
check("#3/#4 wss sslopt 要求校验主机名", _wss_opt.get("check_hostname") is True)
_ws_opt = _cc.build_ws_sslopt("ws://localhost:5000/v1/chat")
check("#3/#4 ws (明文) 不启用证书校验", _ws_opt == {})

# ============================================================
# #5 残余 安全识别码可计算/可获取 (带外比对基础)
# ============================================================
section("#5 残余 安全识别码")

from keys import compute_safety_number as _csn
_dummy_a = b"a" * 32
_dummy_b = b"b" * 32
_sn1 = _csn(_dummy_a, _dummy_b)
_sn2 = _csn(_dummy_a, _dummy_b)
check("#5 安全识别码格式为 12 组 5 位十六进制",
      len(_sn1.split()) == 12 and all(len(g) == 5 for g in _sn1.split()))
check("#5 相同输入得到稳定识别码", _sn1 == _sn2)
check("#5 安全识别码对称: (A,B) 与 (B,A) 得到同一号码 (双方可比对)",
      _csn(_dummy_a, _dummy_b) == _csn(_dummy_b, _dummy_a))
check("#5 不同对端公钥得到不同识别码",
      _csn(_dummy_a, _dummy_b) != _csn(_dummy_a, b"c" * 32))
check("#5 空公钥得到确定识别码 (60 位十六进制)", len(_csn(b"", b"").split()) == 12)

# ============================================================
# 汇总
# ============================================================
print(f"\n{'='*60}")
print(f"  安全修复回归测试汇总")
print(f"  通过: {PASS}  |  失败: {FAIL}")
if FAIL == 0:
    print("  全部通过！")
else:
    print(f"  有 {FAIL} 项失败")
print("=" * 60)

if FAIL > 0:
    sys.exit(1)
