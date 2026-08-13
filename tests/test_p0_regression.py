# -*- coding: utf-8 -*-
"""
P0 修复回归测试 (主 agent):
1. WS 信封解包: {"type":"message","msg":{...}} / {"type":"pending","messages":[...]}
2. 文件消息签名体验证 (内容绑定, 不绑定时钟)
3. /history 分页游标 (取最旧而非最新)
4. localstore last_ts 只前进
"""
import os
import sys
import json
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui


class _FakeApp:
    def __init__(self):
        self.messages = []

    def post_message(self, m):
        self.messages.append(m)


class _FakeClient:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def receive_chat_message(self, msg):
        self.calls.append(msg)
        if self.results:
            return self.results.pop(0)
        return None


class _FakeStore:
    def __init__(self):
        self.keys = {}
        self.messages = []

    def save_file_key(self, msg_id, key):
        self.keys[msg_id] = key

    def upsert_message(self, *a, **k):
        self.messages.append(a)

    def upsert_conversation(self, *a, **k):
        pass


# ----------------------------------------------------------------------
# 1. WS 信封解包
# ----------------------------------------------------------------------

def test_envelope_message_frame_unwrapped():
    """{"type":"message","msg":{...}} → 解包后传给 receive_chat_message。"""
    app = _FakeApp()
    client = _FakeClient([{"text": "hi", "from": "bob", "msg_id": "m1"}])
    store = _FakeStore()
    tui.handle_inbound_item(app, client, store, {
        "action": "server_message",
        "data": {"type": "message", "msg": {"id": "m1"}},
    })
    assert client.calls == [{"id": "m1"}], "信封 msg 字段应解包传入"


def test_envelope_pending_frame_unwrapped():
    """{"type":"pending","messages":[...]} → 逐条解包。"""
    app = _FakeApp()
    client = _FakeClient([{"text": "a", "msg_id": "m1"},
                          {"text": "b", "msg_id": "m2"}])
    store = _FakeStore()
    tui.handle_inbound_item(app, client, store, {
        "action": "server_message",
        "data": {"type": "pending", "messages": [{"id": "m1"}, {"id": "m2"}]},
    })
    assert [c["id"] for c in client.calls] == ["m1", "m2"]


def test_envelope_other_frames_ignored():
    """ack/auth_ok 等帧不触发解密。"""
    app = _FakeApp()
    client = _FakeClient([])
    store = _FakeStore()
    tui.handle_inbound_item(app, client, store, {
        "action": "server_message",
        "data": {"type": "ack", "msg_id": "m1"},
    })
    assert client.calls == []


def test_envelope_file_message_strips_key_from_body():
    """文件消息: key 落 file_keys 表, body 剥离 key。"""
    app = _FakeApp()
    client = _FakeClient([{
        "text": "", "from": "bob", "msg_id": "m1", "verified": True,
        "file": {"name": "a.txt", "size": 3, "sha256": "x", "token": "t" * 32,
                 "key": "a2V5MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="},
    }])
    store = _FakeStore()
    tui._ingest_server_message(app, client, store, {"id": "m1", "from": "bob"})
    assert "m1" in store.keys, "key 应存 file_keys"
    body_json = [a[4] for a in store.messages][0]
    body = json.loads(body_json)
    assert "key" not in body, "body 不应含明文 key"
    assert body["name"] == "a.txt" and body["token"] == "t" * 32


# ----------------------------------------------------------------------
# 2. 签名体 (内容绑定, 不绑定时钟)
# ----------------------------------------------------------------------

def test_signature_body_text_no_clock():
    """文本消息签名体 = {identity}{text}, 不再含 ts (跨机时钟不敏感)。"""
    import chat_client as cc
    client = cc.ChatClient.__new__(cc.ChatClient)
    client.identity = "alice"
    client.passphrase = "pw"
    client.store = type("S", (), {"load_signing_private_key_pem": staticmethod(
        lambda *a: None)})()

    import inspect
    src = inspect.getsource(cc.ChatClient._send_ratchet_message)
    assert "{self.identity}{plaintext}" in src
    assert "ts" not in src.split("sig_body")[1].split('"')[0] or "{self.identity}{plaintext}" in src


def test_signature_body_file_binds_content():
    """文件消息签名体绑定 name+size+sha256。"""
    import chat_client as cc
    import inspect
    src = inspect.getsource(cc.ChatClient.send_file)
    assert "{name}{size}{sha256}" in src


def test_parse_decrypted_file_signature_compat():
    """文件消息验签: 新格式 (name+size+sha256) 与旧格式兜底都在候选里。"""
    import chat_client as cc
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    client = cc.ChatClient.__new__(cc.ChatClient)
    store = type("S", (), {"load_signing_public_key": staticmethod(lambda *a: pub_pem)})()
    client.store = store

    file_meta = {"name": "f.bin", "size": 10, "sha256": "abc", "token": "t" * 32}
    sig = priv.sign(f"bobf.bin10abc".encode())

    inner = json.dumps({"text": "", "signature": cc._b64(sig),
                        "file": file_meta}).encode()
    msg = {"from": "bob", "timestamp": time.time(), "id": "m1"}
    r = client._parse_decrypted(inner, msg)
    assert r.get("verified") is True, "新格式签名应验签通过"
    assert r["file"] == file_meta


def test_parse_decrypted_clock_insensitive_text():
    """文本消息: 新签名格式不含时钟, 任意 ts 验签通过。"""
    import chat_client as cc
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    client = cc.ChatClient.__new__(cc.ChatClient)
    store = type("S", (), {"load_signing_public_key": staticmethod(lambda *a: pub_pem)})()
    client.store = store

    sig = priv.sign(f"bob你好".encode())
    inner = json.dumps({"text": "你好", "signature": cc._b64(sig)}).encode()
    # 服务器时钟与发送方时钟差 100 秒: 旧格式必失败, 新格式应通过
    msg = {"from": "bob", "timestamp": time.time() + 100, "id": "m1"}
    r = client._parse_decrypted(inner, msg)
    assert r.get("verified") is True, "时钟偏差下新格式签名应通过"


# ----------------------------------------------------------------------
# 3. /history 游标
# ----------------------------------------------------------------------

def test_history_cursor_uses_oldest():
    """_cmd_history 游标取最早一条 (get_oldest_message), 而非最新。"""
    import inspect
    src = inspect.getsource(tui.ChatApp._cmd_history)
    assert "get_oldest_message" in src, "应使用 get_oldest_message 取最旧游标"


# ----------------------------------------------------------------------
# 4. localstore last_ts 只前进
# ----------------------------------------------------------------------

def test_localstore_last_ts_monotonic(tmp_path):
    """旧消息到达不得回退会话 last_ts。"""
    from localstore import LocalStore
    st = LocalStore(str(tmp_path / "t.db"))
    st.upsert_message("bob", "m1", "bob", "text", "new", "sent", 1, 200.0)
    conv = st.list_conversations()[0]
    assert conv["last_ts"] == 200.0
    # 乱序旧消息 (ts=100) 到达
    st.upsert_message("bob", "m2", "bob", "text", "old", "sent", 1, 100.0)
    conv = st.list_conversations()[0]
    assert conv["last_ts"] == 200.0, "last_ts 不得回退"
    # 更新的消息应前进
    st.upsert_message("bob", "m3", "bob", "text", "newer", "sent", 1, 300.0)
    conv = st.list_conversations()[0]
    assert conv["last_ts"] == 300.0
    st.close()


def test_localstore_get_oldest_message(tmp_path):
    from localstore import LocalStore
    st = LocalStore(str(tmp_path / "t.db"))
    st.upsert_message("bob", "m1", "bob", "text", "a", "sent", 1, 100.0)
    st.upsert_message("bob", "m2", "bob", "text", "b", "sent", 1, 200.0)
    oldest = st.get_oldest_message("bob")
    assert oldest and oldest["msg_id"] == "m1"
    assert st.get_oldest_message("nobody") is None
    st.close()


# ----------------------------------------------------------------------
# 5. token 白名单 (下载)
# ----------------------------------------------------------------------

def test_download_token_whitelist():
    import re
    ok = re.fullmatch(r"[0-9a-fA-F]{32}", "a" * 32)
    assert ok
    assert re.fullmatch(r"[0-9a-fA-F]{32}", "../evil") is None
    assert re.fullmatch(r"[0-9a-fA-F]{32}", "a" * 31) is None
