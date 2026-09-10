#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
文件传输层测试 (Agent-B)
========================
通过 monkeypatch FileClient._http_raw 模拟服务端, 覆盖:
  - 分块上传 (成功 / 断点续传 409 / 失败 / 死循环防护)
  - Range 下载 (全新 / 续传追加 / 200 整文件覆盖 / 目录缺失 / 404)
  - HEAD 元信息 / 进度回调节流
  - 真实文件 + 假服务器的端到端一致性  - ChatClient.send_file / download_file / decrypt_file / query_delivered
    / _parse_decrypted file 瀛楁 (娴呮祴, monkeypatch 渚濊禆)
"""

import os
import sys
import json
import time
import hashlib
import secrets

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fileclient
from fileclient import FileClient, CHUNK_SIZE
from core import urlsafe_b64encode as _b64e

# ----------------------------------------------------------------------
# 测试基础设施: 假服务器 (替换 _http_raw)
# ----------------------------------------------------------------------


def make_client(server="https://example.com", token="tok123"):
    return FileClient(server, token)


class FakeClock:
    """可控时钟: step>0 时每次调用递增。"""

    def __init__(self, start=1000.0, step=0.0):
        self.now = start
        self.step = step

    def __call__(self):
        v = self.now
        self.now += self.step
        return v


def freeze_clock(monkeypatch, step=0.0):
    clock = FakeClock(step=step)
    monkeypatch.setattr("time.time", clock)
    return clock


class MockUploadServer:
    """上传服务端模拟: 脚本化响应序列。"""

    def __init__(self, responses, token="deadbeef" * 4):
        self.responses = list(responses)
        self.calls = []          # [(method, url, headers, body)]
        self.token = token

    def handle(self, method, url, headers=None, body=None, timeout=60):
        self.calls.append((method, url, dict(headers or {}), body))
        assert method == "POST"
        assert headers["Authorization"] == "Bearer tok123"
        assert headers["X-Recipient"] == "bob"
        status, payload = self.responses.pop(0)
        return status, {}, json.dumps(payload).encode("utf-8")


class MockDownloadServer:
    """下载服务端模拟: 静态密文 + 可选 Range 支持。"""

    def __init__(self, data, token="a" * 32, range_support=True):
        self.data = data
        self.token = token
        self.range_support = range_support
        self.calls = []

    def handle(self, method, url, headers=None, body=None, timeout=60):
        headers = dict(headers or {})
        self.calls.append((method, url, headers))
        assert headers["Authorization"] == "Bearer tok123"
        if method == "HEAD":
            return 200, {"Content-Length": str(len(self.data))}, b""
        rng = headers.get("Range")
        if rng and self.range_support:
            start = int(rng.split("=")[1].split("-")[0])
            end = len(self.data) - 1
            return 206, {"Content-Range": f"bytes {start}-{end}/{len(self.data)}"}, \
                self.data[start:]
        if rng:
            return 200, {}, self.data
        return 200, {}, self.data


def patch_stream(monkeypatch, server):
    """R16: download 的 GET 已改走 _http_stream(分块读), 测试桩同步:
    复用同一假服务器, 把整包 body 包成 BytesIO 读取器。"""
    import io

    def _stream(self, method, url, headers=None):
        status, headers2, body = server.handle(method, url, headers)
        return status, headers2, io.BytesIO(body)

    monkeypatch.setattr(FileClient, "_http_stream", _stream)


@pytest.fixture
def fc(monkeypatch):
    client = make_client()
    return client


# ----------------------------------------------------------------------
# 上传
# ----------------------------------------------------------------------

def test_upload_success(monkeypatch, tmp_path):
    """两整块 + 尾块上传, 逐块 X-Offset 正确, 201 返回 token。"""
    data = secrets.token_bytes(2 * CHUNK_SIZE + 100)
    p = tmp_path / "cipher.bin"
    p.write_bytes(data)
    server = MockUploadServer([(409, {"offset": CHUNK_SIZE}),
                               (409, {"offset": 2 * CHUNK_SIZE}),
                               (201, {"token": "t0" * 16})])
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)

    result = FileClient("https://example.com", "tok123").upload(str(p), "bob")

    assert result == {"token": "t0" * 16}
    offsets = [int(h["X-Offset"]) for _, _, h, _ in server.calls]
    assert offsets == [0, CHUNK_SIZE, 2 * CHUNK_SIZE]
    # 每块体积 == 1MB (尾块除外)
    assert len(server.calls[0][3]) == CHUNK_SIZE
    assert len(server.calls[1][3]) == CHUNK_SIZE
    assert len(server.calls[2][3]) == 100


def test_upload_resume_alignment(monkeypatch, tmp_path):
    """首块 409 offset=1048576 后, 从协商偏移续传 (非块对齐亦可)。"""
    data = secrets.token_bytes(3 * CHUNK_SIZE)
    p = tmp_path / "cipher.bin"
    p.write_bytes(data)
    # 服务端已有 1.5MB 数据
    resume_at = 1572864
    server = MockUploadServer([(409, {"offset": resume_at}),
                               (201, {"token": "r1" * 16})])
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)

    result = FileClient("https://example.com", "tok123").upload(str(p), "bob")

    assert result == {"token": "r1" * 16}
    offsets = [int(h["X-Offset"]) for _, _, h, _ in server.calls]
    assert offsets == [0, resume_at]
    # 续传块从协商偏移处读 1MB
    assert server.calls[1][3] == data[resume_at:resume_at + CHUNK_SIZE]


def test_upload_failure_500(monkeypatch, tmp_path):
    p = tmp_path / "cipher.bin"
    p.write_bytes(b"x" * 100)
    server = MockUploadServer([(500, {"error": "internal"})])
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)

    result = FileClient("https://example.com", "tok123").upload(str(p), "bob")

    assert result["error"]
    assert "HTTP 500" in result["error"]


def test_upload_stall_guard(monkeypatch, tmp_path):
    """409 offset 不前进时拒绝继续, 防死循环。"""
    p = tmp_path / "cipher.bin"
    p.write_bytes(b"x" * (CHUNK_SIZE + 10))
    server = MockUploadServer([(409, {"offset": 0})])
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)

    result = FileClient("https://example.com", "tok123").upload(str(p), "bob")

    assert result["error"]
    assert "拒绝继续" in result["error"]
    assert len(server.calls) == 1


def test_upload_missing_file(monkeypatch, tmp_path):
    server = MockUploadServer([])
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)
    result = FileClient("https://example.com", "tok123").upload(
        str(tmp_path / "nope.bin"), "bob")
    assert result["error"]
    assert "文件不存在" in result["error"]
    assert server.calls == []


def test_upload_network_error(monkeypatch, tmp_path):
    p = tmp_path / "cipher.bin"
    p.write_bytes(b"x" * 100)

    def boom(method, url, headers=None, body=None, timeout=60):
        raise fileclient.FileClientError("连接被拒绝")

    monkeypatch.setattr(FileClient, "_http_raw", staticmethod(boom))
    result = FileClient("https://example.com", "tok123").upload(str(p), "bob")
    assert result["error"]
    assert "网络错误" in result["error"]


# ----------------------------------------------------------------------
# 下载
# ----------------------------------------------------------------------

def test_download_fresh(monkeypatch, tmp_path):
    """全新下载: HEAD 拿 size, 整文件 GET, 写 dest/<token>.bin。"""
    cipher = secrets.token_bytes(500000)
    token = "b" * 32
    server = MockDownloadServer(cipher, token=token)
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)
    dest = tmp_path / "dl"
    dest.mkdir()

    result = FileClient("https://example.com", "tok123").download(token, str(dest))

    assert result["size"] == len(cipher)
    assert result["path"] == str(dest / f"{token}.bin")
    assert (dest / f"{token}.bin").read_bytes() == cipher
    # 无 Range 请求 (全新下载)
    for _, _, h in server.calls:
        assert "Range" not in h


def test_download_resume_append(monkeypatch, tmp_path):
    """本地已有部分密文, 从已有大小发起 Range 请求, 206 追加写。"""
    cipher = secrets.token_bytes(2 * CHUNK_SIZE + 123)
    token = "c" * 32
    dest = tmp_path / "dl"
    dest.mkdir()
    target = dest / f"{token}.bin"
    partial = cipher[: 1572864]                       # 宸叉湁 1.5MB
    target.write_bytes(partial)
    server = MockDownloadServer(cipher, token=token)
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)

    result = FileClient("https://example.com", "tok123").download(token, str(dest))

    assert result["size"] == len(cipher)
    assert target.read_bytes() == cipher
    range_headers = [h["Range"] for _, _, h in server.calls if "Range" in h]
    assert range_headers == ["bytes=1572864-"]


def test_download_server_ignores_range(monkeypatch, tmp_path):
    """服务端不支持 Range (200 整文件): 覆盖写, 不追加。"""
    cipher = secrets.token_bytes(300000)
    token = "d" * 32
    dest = tmp_path / "dl"
    dest.mkdir()
    target = dest / f"{token}.bin"
    target.write_bytes(b"stale-partial-data")
    server = MockDownloadServer(cipher, token=token, range_support=False)
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)

    result = FileClient("https://example.com", "tok123").download(token, str(dest))

    assert result["size"] == len(cipher)
    assert target.read_bytes() == cipher


def test_download_missing_dest_dir(monkeypatch, tmp_path):
    server = MockDownloadServer(b"data", token="e" * 32)
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)
    result = FileClient("https://example.com", "tok123").download(
        "e" * 32, str(tmp_path / "no_such_dir"))
    assert result["error"]
    assert "目录不存在" in result["error"]
    assert server.calls == []


def test_download_404(monkeypatch, tmp_path):
    dest = tmp_path / "dl"
    dest.mkdir()

    def not_found(method, url, headers=None, body=None, timeout=60):
        if method == "HEAD":
            return 404, {}, b""
        return 404, {}, b""

    monkeypatch.setattr(FileClient, "_http_raw", staticmethod(not_found))
    import io as _io
    monkeypatch.setattr(FileClient, "_http_stream",
                        staticmethod(lambda self, method, url, headers=None:
                                     (404, {}, _io.BytesIO(b""))))
    result = FileClient("https://example.com", "tok123").download("f" * 32, str(dest))
    assert result["error"] == "not found"


def test_download_invalid_token(monkeypatch, tmp_path):
    dest = tmp_path / "dl"
    dest.mkdir()

    def spy(method, url, headers=None, body=None, timeout=60):
        raise AssertionError("不应发起请求")

    monkeypatch.setattr(FileClient, "_http_raw", spy)
    # 璺緞绌胯秺 token
    result = FileClient("https://example.com", "tok123").download("../evil", str(dest))
    assert result["error"]
    # 闈炴硶瀛楃
    result = FileClient("https://example.com", "tok123").download("a/b", str(dest))
    assert result["error"]


# ----------------------------------------------------------------------
# HEAD 元信息

def test_head_size(monkeypatch):
    def handle(method, url, headers=None, body=None, timeout=60):
        assert method == "HEAD"
        return 200, {}, json.dumps({"size": 424242}).encode("utf-8")

    monkeypatch.setattr(FileClient, "_http_raw", staticmethod(handle))
    assert FileClient("https://example.com", "tok123").head("g" * 32) == \
        {"size": 424242}


def test_head_content_length_fallback(monkeypatch):
    def handle(method, url, headers=None, body=None, timeout=60):
        return 200, {"Content-Length": "777"}, b""

    monkeypatch.setattr(FileClient, "_http_raw", staticmethod(handle))
    assert FileClient("https://example.com", "tok123").head("g" * 32) == \
        {"size": 777}


def test_head_not_found(monkeypatch):
    def handle(method, url, headers=None, body=None, timeout=60):
        return 404, {}, b""

    monkeypatch.setattr(FileClient, "_http_raw", staticmethod(handle))
    assert FileClient("https://example.com", "tok123").head("h" * 32) == \
        {"error": "not found"}


# ----------------------------------------------------------------------
    # 进度回调节流 (每秒最多 1 次)
# ----------------------------------------------------------------------

def test_progress_throttle_frozen_clock(monkeypatch, tmp_path):
    """时钟静止: 多次进度机会只回调 2 次 (首个即时回调 + 完成必回调)。"""
    data = secrets.token_bytes(3 * CHUNK_SIZE + 10)
    p = tmp_path / "cipher.bin"
    p.write_bytes(data)
    server = MockUploadServer([(409, {"offset": CHUNK_SIZE}),
                               (409, {"offset": 2 * CHUNK_SIZE}),
                               (201, {"token": "t1" * 16})])
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)
    freeze_clock(monkeypatch, step=0.0)

    calls = []
    result = FileClient("https://example.com", "tok123").upload(
        str(p), "bob", progress_cb=lambda d, t: calls.append((d, t)))

    assert result == {"token": "t1" * 16}
    # 3 次进度回调 (2x 409 + 完成), 但同一秒内节流为 2 次
    assert calls[0] == (CHUNK_SIZE, len(data))
    assert calls[1] == (len(data), len(data))


def test_progress_throttle_advancing_clock(monkeypatch, tmp_path):
    """时钟每步 >1s: 每块回调 1 次 (节流通过)。"""
    data = secrets.token_bytes(3 * CHUNK_SIZE + 10)
    p = tmp_path / "cipher.bin"
    p.write_bytes(data)
    server = MockUploadServer([(409, {"offset": CHUNK_SIZE}),
                               (409, {"offset": 2 * CHUNK_SIZE}),
                               (201, {"token": "t2" * 16})])
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)
    freeze_clock(monkeypatch, step=2.0)

    calls = []
    result = FileClient("https://example.com", "tok123").upload(
        str(p), "bob", progress_cb=lambda d, t: calls.append((d, t)))

    assert result == {"token": "t2" * 16}
    assert len(calls) == 3
    assert calls[0] == (CHUNK_SIZE, len(data))
    assert calls[1] == (2 * CHUNK_SIZE, len(data))
    assert calls[2] == (len(data), len(data))


def test_progress_cb_download(monkeypatch, tmp_path):
    cipher = secrets.token_bytes(100000)
    token = "i" * 32
    dest = tmp_path / "dl"
    dest.mkdir()
    server = MockDownloadServer(cipher, token=token)
    monkeypatch.setattr(FileClient, "_http_raw", server.handle)
    patch_stream(monkeypatch, server)

    calls = []
    result = FileClient("https://example.com", "tok123").download(
        token, str(dest), progress_cb=lambda d, t: calls.append((d, t)))

    assert result["size"] == len(cipher)
    # R16: 流式下载按块回报进度 (至少一次), 单调递增且最后一次为完成值
    assert len(calls) >= 1
    sizes = [d for d, _ in calls]
    assert sizes == sorted(sizes)
    assert calls[-1] == (len(cipher), len(cipher))


# ----------------------------------------------------------------------
    # 端到端一致性 (真实文件 + 假服务器)
# ----------------------------------------------------------------------

def test_upload_download_e2e_consistency(monkeypatch, tmp_path):
    """2.5MB 真实随机文件: 上传拿 token; 下载 (含续传) 还原一致。"""
    original = secrets.token_bytes(int(2.5 * CHUNK_SIZE))
    p = tmp_path / "cipher.bin"
    p.write_bytes(original)
    token = "j" * 32

    # 服务端校验 X-Offset 连续性, 按偏移拼装
    buf = {}
    def upload_server(method, url, headers=None, body=None, timeout=60):
        headers = dict(headers or {})
        offset = int(headers["X-Offset"])
        assert headers["X-Recipient"] == "bob"
        buf[offset] = body
        if offset + len(body) >= len(original):
            return 201, {}, json.dumps({"token": token}).encode("utf-8")
        return 409, {}, json.dumps({"offset": offset + len(body)}).encode("utf-8")

    monkeypatch.setattr(FileClient, "_http_raw", staticmethod(upload_server))

    import io as _io

    def _stream_dl(self, method, url, headers=None):
        # R16: 委托当前 _http_raw (本测试各阶段会重挂), 整包包成 BytesIO
        status, hdrs, body = FileClient._http_raw(method, url, headers=headers)
        return status, hdrs, _io.BytesIO(body)

    monkeypatch.setattr(FileClient, "_http_stream", _stream_dl)

    result = FileClient("https://example.com", "tok123").upload(str(p), "bob")
    assert result == {"token": token}
    assembled = b"".join(buf[k] for k in sorted(buf))
    assert assembled == original

    # 下载: 先下前半段 (模拟断开), 再从已有大小续传
    cipher = original
    dest = tmp_path / "dl"
    dest.mkdir()

    def download_server(method, url, headers=None, body=None, timeout=60):
        headers = dict(headers or {})
        if method == "HEAD":
            return 200, {"Content-Length": str(len(cipher))}, b""
        rng = headers.get("Range")
        if rng:
            start = int(rng.split("=")[1].split("-")[0])
            return 206, {"Content-Range": f"bytes {start}-{len(cipher) - 1}/{len(cipher)}"}, \
                cipher[start:]
        return 200, {}, cipher

    monkeypatch.setattr(FileClient, "_http_raw", staticmethod(download_server))
    fc = FileClient("https://example.com", "tok123")

    # 第一次下载只拿到前半段 (模拟部分写入)
    half = len(cipher) // 2
    (dest / f"{token}.bin").write_bytes(cipher[:half])
    result = fc.download(token, str(dest))
    assert result["size"] == len(cipher)
    assert (dest / f"{token}.bin").read_bytes() == cipher


# ----------------------------------------------------------------------
# ChatClient 文件方法 (浅测, monkeypatch 依赖)
# ----------------------------------------------------------------------

def _make_chat_client():
    import chat_client as cc
    client = cc.ChatClient.__new__(cc.ChatClient)
    client.identity = "alice"
    client.passphrase = "pw"
    client._server_url = "https://example.com"
    client._token = "tok123"
    client._ws_ready = False
    return client


class _RaisingStore:
    """签名私钥读取失败 → sig_b64 为空 (容错路径)。"""

    def load_signing_private_key_pem(self, identity, passphrase):
        raise FileNotFoundError("no key")


class _CapturingStore:
    """记录请求的签名私钥 (返回假 PEM), 验证签名体。"""

    def __init__(self, pem):
        self.pem = pem
        self.requested = []

    def load_signing_private_key_pem(self, identity, passphrase):
        self.requested.append((identity, passphrase))
        return self.pem


def _make_ed25519_pem():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_send_file_message_structure(monkeypatch, tmp_path):
    """send_file: inner 消息含 file 字段; 密钥不出现临时文件; 上传后清理。"""
    import chat_client as cc
    plain = secrets.token_bytes(200000)
    src = tmp_path / "secret.txt"
    src.write_bytes(plain)
    client = _make_chat_client()
    client.store = _RaisingStore()
    client._ws_ready = False

    # --- monkeypatch 依赖 ---
    class DummyState:
        def is_expired(self):
            return False

    fake_state = DummyState()
    captured = {}

    def fake_load_session(my_id, peer_id, passphrase):
        assert peer_id == "bob"
        return fake_state

    def fake_send_message(state, inner):
        captured["inner"] = inner
        return {"id": "msg-1", "to": "bob", "timestamp": 1.0}

    monkeypatch.setattr(cc, "load_session", fake_load_session)
    monkeypatch.setattr(cc, "send_message", fake_send_message)
    monkeypatch.setattr(cc, "save_session", lambda s, p: None)

    upload_calls = []

    class FakeFileClient:
        def __init__(self, url, token, identity=""):
            assert url == "https://example.com"
            assert token == "tok123"

        def upload(self, file_path, recipient, progress_cb=None):
            upload_calls.append((file_path, recipient))
            # 临时密文文件存在, 且不含明文
            with open(file_path, "rb") as f:
                blob = f.read()
            assert plain not in blob
            assert len(blob) == len(plain) + 12 + 16   # nonce + GCM tag
            return {"token": "tok-file-1"}

    monkeypatch.setattr(fileclient, "FileClient", FakeFileClient)

    def fake_send_rest(msg):
        captured["wire_msg"] = msg
        return None

    client._send_via_rest = fake_send_rest

    result = client.send_file("bob", str(src))

    assert result["status"] == "sent"
    assert result["msg_id"] == "msg-1"
    # 上传的临时文件已清理 (密钥/密文不落盘)
    assert upload_calls and not os.path.exists(upload_calls[0][0])
    # inner 消息结构
    inner = json.loads(captured["inner"].decode("utf-8"))
    assert inner["text"] == ""
    assert inner["signature"] == ""        # 签名私钥缺失时留空 (容错)
    f = inner["file"]
    assert f["name"] == "secret.txt"
    assert f["size"] == len(plain)
    assert f["sha256"] == hashlib.sha256(plain).hexdigest()
    assert f["token"] == "tok-file-1"
    from base64 import urlsafe_b64decode as b64d
    assert len(b64d(f["key"].encode("ascii"))) == 32
    # 发送后 wire 消息带 id
    assert captured["wire_msg"]["id"] == "msg-1"


def test_send_file_signature_body(monkeypatch, tmp_path):
    """send_file: 签名体为 f"{identity}{name}{size}{sha256}" (内容绑定, 不绑定时钟)。"""
    import chat_client as cc
    from cryptography.hazmat.primitives import serialization

    src = tmp_path / "doc.pdf"
    src.write_bytes(b"pdf-bytes")
    client = _make_chat_client()
    pem = _make_ed25519_pem()
    store = _CapturingStore(pem)
    client.store = store
    client._ws_ready = False

    class DummyState:
        def is_expired(self):
            return False

    monkeypatch.setattr(cc, "load_session", lambda a, b, c: DummyState())
    captured = {}

    def fake_send_message(state, inner):
        captured["inner"] = inner
        return {"id": "m2"}

    monkeypatch.setattr(cc, "send_message", fake_send_message)
    monkeypatch.setattr(cc, "save_session", lambda s, p: None)
    client._send_via_rest = lambda msg: None

    class FakeFileClient:
        def __init__(self, url, token, identity=""):
            pass

        def upload(self, file_path, recipient, progress_cb=None):
            return {"token": "t3"}

    monkeypatch.setattr(fileclient, "FileClient", FakeFileClient)

    result = client.send_file("bob", str(src))

    assert result["status"] == "sent"
    inner = json.loads(captured["inner"].decode("utf-8"))
    assert inner["signature"]  # 有签名
    priv = serialization.load_pem_private_key(pem, password=None)
    pub = priv.public_key()
    import hashlib as _hl
    sha = _hl.sha256(b"pdf-bytes").hexdigest()
    pub.verify(
        __import__("base64").urlsafe_b64decode(inner["signature"].encode("ascii")),
        f"alicedoc.pdf{len(b'pdf-bytes')}{sha}".encode("utf-8"))
    assert store.requested == [("alice", "pw")]


def test_send_file_no_session(monkeypatch, tmp_path):
    import chat_client as cc
    src = tmp_path / "x.bin"
    src.write_bytes(b"data")
    client = _make_chat_client()
    client.store = _RaisingStore()

    monkeypatch.setattr(cc, "load_session", lambda a, b, c: None)

    uploaded = []

    class FakeFileClient:
        def __init__(self, url, token, identity=""):
            pass

        def upload(self, file_path, recipient, progress_cb=None):
            uploaded.append(file_path)
            return {"token": "t4"}

    monkeypatch.setattr(fileclient, "FileClient", FakeFileClient)

    result = client.send_file("bob", str(src))
    assert result["error"]
    assert "无可用会话" in result["error"]
    # 无会话时不执行上传


def test_send_file_upload_failure(monkeypatch, tmp_path):
    import chat_client as cc
    src = tmp_path / "x.bin"
    src.write_bytes(b"data")
    client = _make_chat_client()
    client.store = _RaisingStore()

    class DummyState:
        def is_expired(self):
            return False

    monkeypatch.setattr(cc, "load_session", lambda a, b, c: DummyState())

    class FakeFileClient:
        def __init__(self, url, token, identity=""):
            pass

        def upload(self, file_path, recipient, progress_cb=None):
            return {"error": "HTTP 500"}

    monkeypatch.setattr(fileclient, "FileClient", FakeFileClient)
    monkeypatch.setattr(cc, "send_message", lambda s, i: {"id": "x"})

    result = client.send_file("bob", str(src))
    assert result["error"]
    assert "HTTP 500" in result["error"]


def test_send_file_missing_file(monkeypatch, tmp_path):
    import chat_client as cc
    client = _make_chat_client()
    client.store = _RaisingStore()

    class FakeFileClient:
        def __init__(self, url, token, identity=""):
            pass

        def upload(self, file_path, recipient, progress_cb=None):
            raise AssertionError("不应上传")

    monkeypatch.setattr(fileclient, "FileClient", FakeFileClient)
    result = client.send_file("bob", str(tmp_path / "nope"))
    assert result["error"]
    assert "文件不存在" in result["error"]


def test_download_file_ok(monkeypatch, tmp_path):
    import chat_client as cc
    client = _make_chat_client()
    dest = tmp_path / "dl"
    dest.mkdir()

    class FakeFileClient:
        def __init__(self, url, token, identity=""):
            assert token == "tok123"

        def download(self, token, dest_dir, progress_cb=None):
            return {"path": str(dest / f"{token}.bin"), "size": 99}

    monkeypatch.setattr(fileclient, "FileClient", FakeFileClient)
    result = client.download_file("k" * 32, str(dest))
    assert result["status"] == "ok"
    assert result["token"] == "k" * 32
    assert result["path"]


def test_download_file_error(monkeypatch, tmp_path):
    import chat_client as cc
    client = _make_chat_client()

    class FakeFileClient:
        def __init__(self, url, token, identity=""):
            pass

        def download(self, token, dest_dir, progress_cb=None):
            return {"error": "not found"}

    monkeypatch.setattr(fileclient, "FileClient", FakeFileClient)
    result = client.download_file("k" * 32, str(tmp_path))
    assert result["error"] == "not found"


# ----------------------------------------------------------------------
# decrypt_file (静态方法, 真实加解密往返)
# ----------------------------------------------------------------------

def _make_cipher(plain, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plain, None)
    return nonce + ct


def test_decrypt_file_roundtrip(tmp_path):
    import chat_client as cc
    plain = secrets.token_bytes(30000)
    key = secrets.token_bytes(32)
    cipher = _make_cipher(plain, key)
    cipher_path = tmp_path / ("k" * 32 + ".bin")
    cipher_path.write_bytes(cipher)

    result = cc.ChatClient.decrypt_file(
        str(cipher_path), _b64e(key), "out.txt",
        hashlib.sha256(plain).hexdigest())

    assert result["status"] == "ok"
    out = tmp_path / "out.txt"
    assert out.read_bytes() == plain


def test_decrypt_file_sha256_mismatch(tmp_path):
    import chat_client as cc
    plain = secrets.token_bytes(1000)
    key = secrets.token_bytes(32)
    cipher_path = tmp_path / "c.bin"
    cipher_path.write_bytes(_make_cipher(plain, key))

    result = cc.ChatClient.decrypt_file(
        str(cipher_path), _b64e(key), "out.txt", "0" * 64)
    assert result["error"]
    assert "sha256" in result["error"]
    assert not (tmp_path / "out.txt").exists()


def test_decrypt_file_wrong_key(tmp_path):
    import chat_client as cc
    plain = secrets.token_bytes(1000)
    key = secrets.token_bytes(32)
    cipher_path = tmp_path / "c.bin"
    cipher_path.write_bytes(_make_cipher(plain, key))

    result = cc.ChatClient.decrypt_file(
        str(cipher_path), _b64e(secrets.token_bytes(32)), "out.txt", "")
    assert result["error"]
    assert "解密失败" in result["error"]


def test_decrypt_file_bad_filename(tmp_path):
    import chat_client as cc
    key = secrets.token_bytes(32)
    cipher_path = tmp_path / "c.bin"
    cipher_path.write_bytes(_make_cipher(b"x" * 100, key))

    for bad in ("../evil", "a/b", "a\\b", "x y.txt"):
        result = cc.ChatClient.decrypt_file(
            str(cipher_path), _b64e(key), bad, "")
        assert result["error"], bad


# ----------------------------------------------------------------------
# query_delivered / _parse_decrypted
# ----------------------------------------------------------------------

def test_query_delivered(monkeypatch):
    import chat_client as cc
    client = _make_chat_client()
    seen = {}

    def fake_http(method, path, body=None, timeout=15):
        seen["path"] = path
        return {"delivered": {"a1": 1234567890.5, "b2": None}}

    client._http_request = fake_http
    result = client.query_delivered(["a1", "b2"])

    assert seen["path"] == "/v1/messages/delivered?ids=a1,b2&identity=alice"
    assert result == {"a1": 1234567890.5, "b2": None}


def test_query_delivered_error(monkeypatch):
    import chat_client as cc
    client = _make_chat_client()
    client._http_request = lambda m, p, body=None, timeout=15: {"error": "HTTP 500"}
    result = client.query_delivered(["a1"])
    assert result["error"] == "HTTP 500"


def test_parse_decrypted_file_field():
    """_parse_decrypted: 有 file 字段时返回 file dict, 无则 None。"""
    import chat_client as cc
    client = _make_chat_client()
    client.store = _RaisingStore()

    with_file = json.dumps({
        "text": "",
        "signature": "",
        "file": {"name": "a.txt", "size": 5, "sha256": "x",
                 "token": "tok", "key": "keyb64"},
    }, ensure_ascii=False).encode("utf-8")
    msg = {"from": "bob", "to": "alice", "timestamp": 1.0, "id": "m1"}

    r1 = client._parse_decrypted(with_file, msg)
    assert r1["text"] == ""
    assert r1["file"]["name"] == "a.txt"
    assert r1["file"]["token"] == "tok"
    assert r1["file"]["key"] == "keyb64"

    no_file = json.dumps({"text": "hi", "signature": ""},
                         ensure_ascii=False).encode("utf-8")
    r2 = client._parse_decrypted(no_file, msg)
    assert r2["text"] == "hi"
    assert r2["file"] is None


def test_send_file_to_wire_roundtrip(monkeypatch, tmp_path):
    """端到端: send_file 密文上传 → 下载 → decrypt_file 还原原文。"""
    import chat_client as cc
    plain = secrets.token_bytes(100000)
    src = tmp_path / "report.docx"
    src.write_bytes(plain)
    token = "l" * 32

    # --- 上传服务端 mock: 拼接分块 ---
    buf = {}

    def upload_server(method, url, headers=None, body=None, timeout=60):
        headers = dict(headers or {})
        offset = int(headers["X-Offset"])
        buf[offset] = body
        total = len(plain) + 12 + 16
        if offset + len(body) >= total:
            return 201, {}, json.dumps({"token": token}).encode("utf-8")
        return 409, {}, json.dumps({"offset": offset + len(body)}).encode("utf-8")

    # --- 下载服务端 mock ---
    cipher_assembled = {}

    def download_server(method, url, headers=None, body=None, timeout=60):
        if method == "HEAD":
            return 200, {"Content-Length": str(total_len())}, b""
        rng = (dict(headers or {})).get("Range")
        data = cipher_assembled["data"]
        if rng:
            start = int(rng.split("=")[1].split("-")[0])
            return 206, {"Content-Range": f"bytes {start}-{len(data) - 1}/{len(data)}"}, \
                data[start:]
        return 200, {}, data

    total_len = lambda: len(cipher_assembled.get("data", b""))

    # 先测 send_file (upload 阶段): 用真实 FileClient, _http_raw 被替换
    client = _make_chat_client()
    client.store = _RaisingStore()
    client._ws_ready = False

    class DummyState:
        def is_expired(self):
            return False

    monkeypatch.setattr(cc, "load_session", lambda a, b, c: DummyState())
    inner_captured = {}

    def fake_send_message(state, inner):
        inner_captured["inner"] = inner
        return {"id": "m-e2e"}

    monkeypatch.setattr(cc, "send_message", fake_send_message)
    monkeypatch.setattr(cc, "save_session", lambda s, p: None)
    client._send_via_rest = lambda msg: None

    # FileClient 真实类, _http_raw 被替换为 upload_server
    monkeypatch.setattr(fileclient.FileClient, "_http_raw", staticmethod(upload_server))
    result = client.send_file("bob", str(src))
    assert result["status"] == "sent"

    # 从上传分块拼出完整密文 (与 send_file 内部一致: nonce + ct)
    cipher = b"".join(buf[k] for k in sorted(buf))
    assert len(cipher) == len(plain) + 12 + 16

    # 解密密文验证原文一致
    from base64 import urlsafe_b64decode as b64d
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    inner = json.loads(inner_captured["inner"].decode("utf-8"))
    key = b64d(inner["file"]["key"].encode("ascii"))
    decrypted = AESGCM(key).decrypt(cipher[:12], cipher[12:], None)
    assert decrypted == plain

    # 下载到本地 (密文文件)
    dest = tmp_path / "dl"
    dest.mkdir()
    cipher_assembled["data"] = cipher
    monkeypatch.setattr(fileclient.FileClient, "_http_raw", staticmethod(download_server))
    import io as _io2

    def _stream_dl(self, method, url, headers=None):
        status, hdrs, body = fileclient.FileClient._http_raw(
            method, url, headers=headers)
        return status, hdrs, _io2.BytesIO(body)

    monkeypatch.setattr(fileclient.FileClient, "_http_stream", _stream_dl)
    dl = client.download_file(token, str(dest))
    assert dl["status"] == "ok"

    # 解密还原并校验 sha256
    out = cc.ChatClient.decrypt_file(
        dl["path"], inner["file"]["key"], inner["file"]["name"],
        inner["file"]["sha256"])
    assert out["status"] == "ok"
    assert (tmp_path / "dl" / "report.docx").read_bytes() == plain
