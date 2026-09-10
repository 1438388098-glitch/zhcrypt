#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
本地双端 E2E 冒烟 (R14 新增, 真实服务进程)
==========================================
起真实的 server.py (REST:5000) 与 chat_server.py (WS:5003),
双身份 alice/bob 完成预密钥上传、X3DH 握手、双向 ratchet 多轮、
文件端到端传输与安全号一致性验证。

用法:  py -3.13 tests/e2e_local_smoke.py
说明:  使用临时 DB/文件目录与随机 token, 不触碰真实 ~/.zhcrypt;
       客户端身份密钥写入脚本临时目录。端口 5000/5003 被占用时请先释放。
退出码: 0 全部通过; 1 存在失败项。
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TOKEN = "e2e-" + os.urandom(8).hex()
PASSPHRASE = "e2e-口令-123456"


def wait_port(port, timeout=30):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def wait_server(base, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(base + "/v1/health",
                                         headers={"Authorization": f"Bearer {TOKEN}"})
            with urllib.request.urlopen(req, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def make_identity(home, name):
    """在隔离 home 里生成身份并写入服务配置。"""
    keys_dir = os.path.join(home, ".zhcrypt", "keys")
    from keys import KeyStore
    ks = KeyStore(keys_dir)
    ks.generate_identity(name, PASSPHRASE, comment="e2e")
    cfg_path = os.path.join(home, ".zhcrypt", "config.json")
    os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
    import json as _json
    from config import DEFAULT_CONFIG
    cfg = _json.loads(_json.dumps(DEFAULT_CONFIG))
    cfg["prekey_server"]["url"] = "http://127.0.0.1:5000"
    cfg["prekey_server"]["auth_token_enc"] = ""
    cfg["prekey_server"]["auth_token"] = TOKEN   # E2E 临时环境, 允许明文
    with open(cfg_path, "w", encoding="utf-8") as f:
        _json.dump(cfg, f, ensure_ascii=False, indent=2)
    return ks


def upload_prekeys(ks, name, cfg_home):
    """客户端上传 prekey bundle (走 ChatClient 同款 REST 路径)。"""
    import chat_client as cc
    bundle = ks.generate_prekey_bundle(name, PASSPHRASE, otp_count=10)
    body = {
        "identity_key_pub": bundle["identity_key_pub"],
        "signed_prekey_pub": bundle["signed_prekey_pub"],
        "signature": bundle["signature"],
        "signing_public_key": bundle.get("signing_public_key", ""),
        "fingerprint": bundle["fingerprint"],
        "one_time_prekeys": bundle["one_time_prekeys"],
    }
    from config import get_auth_token  # noqa: F401  (仅为保持与客户端一致导入面)
    token = TOKEN
    req = urllib.request.Request(
        f"http://127.0.0.1:5000/v1/prekey/{name}",
        data=__import__("json").dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.status == 200, r.status


def main():
    tmp = tempfile.mkdtemp(prefix="zhcrypt_e2e_")
    env = os.environ.copy()
    env["ZHPREKEY_TOKEN"] = TOKEN
    env["ZHPREKEY_DB"] = os.path.join(tmp, "e2e.db")
    env["ZHCHAT_FILE_DIR"] = os.path.join(tmp, "files")
    os.makedirs(env["ZHCHAT_FILE_DIR"], exist_ok=True)
    env["PYTHONIOENCODING"] = "utf-8"

    ok, failed = [], []

    def check(label, cond, detail=""):
        (ok if cond else failed).append(label)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label} {detail}")

    procs = []
    try:
        print(">> 启动本地服务 (REST:5000 / WS:5003)")
        procs.append(subprocess.Popen([sys.executable, "server.py"],
                                      cwd=ROOT, env=env,
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen([sys.executable, "chat_server.py"],
                                      cwd=ROOT, env=env,
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
        check("服务启动与 health", wait_server("http://127.0.0.1:5000")
              and wait_port(5003))
        if failed:
            return finish(ok, failed)

        print(">> 生成双身份并上传预密钥")
        home_a = os.path.join(tmp, "alice")
        home_b = os.path.join(tmp, "bob")
        ks_a = make_identity(home_a, "alice")
        ks_b = make_identity(home_b, "bob")
        upload_prekeys(ks_a, "alice", home_a)
        upload_prekeys(ks_b, "bob", home_b)
        check("预密钥上传", True)

        # 客户端加载本地配置 (隔离 home)
        for h in (home_a, home_b):
            pass
        os.environ_bak = None
        # chat_client/config 按展开 home 读配置: 用子进程语义太重,
        # 这里直接注入两个客户端的 URL/token 并隔离各自的本地目录。
        import chat_client as cc

        alice = cc.ChatClient("alice", PASSPHRASE)
        alice._server_url = "http://127.0.0.1:5000"
        alice._token = TOKEN
        alice.store = ks_a
        bob = cc.ChatClient("bob", PASSPHRASE)
        bob._server_url = "http://127.0.0.1:5000"
        bob._token = TOKEN
        bob.store = ks_b

        # 会话目录隔离 (session.py 全局 SESSIONS_DIR)
        import session as session_mod
        session_mod.SESSIONS_DIR = os.path.join(tmp, "sessions")
        import localstore as ls_mod
        alice_store_local = ls_mod.LocalStore(os.path.join(tmp, "alice.db"))
        bob_store_local = ls_mod.LocalStore(os.path.join(tmp, "bob.db"))

        print(">> X3DH 握手: alice → bob 首消息")
        r = alice.send_chat_message("bob", "你好 bob, 第 1 条")
        check("alice 首消息发送 (X3DH init)", not r.get("error"), str(r)[:120])

        time.sleep(1.0)
        got_bob = bob.poll_messages()
        texts_b = [m.get("text") for m in (got_bob or []) if isinstance(m, dict)]
        check("bob 收到并解密首消息", any("第 1 条" in t for t in texts_b if t),
              str(texts_b)[:160])

        print(">> 双向 ratchet 多轮")
        r2 = bob.send_chat_message("alice", "hi alice, 回复第 2 条")
        check("bob 回复 (ratchet 建立发送链)", not r2.get("error"))
        time.sleep(1.0)
        got_a = alice.poll_messages()
        texts_a = [m.get("text") for m in (got_a or []) if isinstance(m, dict)]
        check("alice 解密 bob 回复", any("第 2 条" in t for t in texts_a if t),
              str(texts_a)[:160])

        for i in range(3, 6):
            r = alice.send_chat_message("bob", f"往返 {i}")
            check(f"alice→bob 第 {i} 条发送", not r.get("error"))
        time.sleep(1.5)
        got_bob = bob.poll_messages()
        texts_b = [m.get("text") for m in (got_bob or []) if isinstance(m, dict)]
        check("bob 解密后续 3 条", sum(1 for t in texts_b if t and "往返" in t) == 3,
              str(texts_b)[:200])

        print(">> 安全号一致性")
        sa = alice.get_safety_number("bob")
        sb = bob.get_safety_number("alice")
        check("双端安全号一致", sa and sa == sb, f"{sa} vs {sb}")

        print(">> 文件端到端")
        fpath = os.path.join(tmp, "payload.bin")
        payload = os.urandom(200 * 1024)
        open(fpath, "wb").write(payload)
        rf = alice.send_file("bob", fpath)
        check("alice 发送文件", not rf.get("error"), str(rf)[:120])
        if not rf.get("error"):
            time.sleep(1.5)
            got_bob = bob.poll_messages() or []
            token = key_b64 = sha = None
            for m in got_bob:
                if isinstance(m, dict) and m.get("file"):
                    fi = m["file"]
                    token, key_b64, sha = (fi.get("token"), fi.get("key"),
                                           fi.get("sha256"))
                    break
            if token and key_b64:
                dl = os.path.join(tmp, "bob_dl")
                os.makedirs(dl, exist_ok=True)
                rd = bob.download_file(token, dl)
                dec_r = bob.decrypt_file(rd["path"], key_b64, "payload.out", sha)
                dec = dec_r["path"] if isinstance(dec_r, dict) else dec_r
                dec_bytes = open(dec, "rb").read()
                check("bob 下载并解密文件 (sha256 一致)",
                      hashlib.sha256(dec_bytes).digest() == hashlib.sha256(payload).digest())
            else:
                check("bob 获取文件元数据", False, "未找到 [FILE] token/key")

    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=10)
            except Exception:
                p.kill()
        print(">> 服务已停止")
    return finish(ok, failed)


def finish(ok, failed):
    print(f"\n==== E2E 汇总: 通过 {len(ok)} / 失败 {len(failed)} ====")
    for f in failed:
        print(f"  [失败] {f}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
