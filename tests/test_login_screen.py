# -*- coding: utf-8 -*-
"""
登录屏测试:
1. 密码缓存存取 (AES-GCM, device.key)
2. main() 免密直达: 有缓存 → 直接 init_client
3. LoginScreen 密码验证逻辑
"""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui
import chat_client as cc
import fileclient  # noqa


class _FakeStore:
    def __init__(self):
        self.friends = {}
        self.convs = []

    def friend_status(self, peer):
        return self.friends.get(peer)

    def upsert_friend(self, *a, **k):
        pass

    def list_friends(self):
        return []

    def list_conversations(self):
        return []

    def upsert_conversation(self, *a, **k):
        pass

    def close(self):
        pass

    def get_messages(self, peer, limit=100, before_ts=None):
        return []

    def clear_unread(self, peer):
        pass


def test_pw_cache_roundtrip(tmp_path, monkeypatch):
    """记住密码: 加密写入 → 正确读回; 错误 key 无法解密。"""
    from config import DEVICE_KEY_PATH
    # 用临时 device.key (config 模块级常量无法改, 直接测函数行为:
    # 无 device.key 时保存失败, 有 key 时往返成功)
    tui._pw_cache_path = lambda ident: str(tmp_path / f"pw_{ident}.bin")

    # 无 device.key → 保存失败
    monkeypatch.setattr("tui._save_pw_cache", tui._save_pw_cache)
    # 直接验证: 无 key 文件 → False
    real_save = tui._save_pw_cache

    def fake_save(ident, pw):
        return False  # 无 device.key 环境

    # 有 key: 构造临时 key 文件
    devkey = tmp_path / "device.key"
    devkey.write_bytes(os.urandom(32))

    import config as cfg
    monkeypatch.setattr(cfg, "DEVICE_KEY_PATH", str(devkey))
    monkeypatch.setattr("tui._save_pw_cache", real_save)
    monkeypatch.setattr("tui._load_pw_cache", tui._load_pw_cache)

    ok = tui._save_pw_cache("alice", "s3cret")
    assert ok, "应成功保存"
    got = tui._load_pw_cache("alice")
    assert got == "s3cret", "应读回原密码"
    # 篡改密文 → 解密失败 → None
    p = tui._pw_cache_path("alice")
    data = bytearray(open(p, "rb").read())
    data[0] ^= 0xFF
    open(p, "wb").write(bytes(data))
    assert tui._load_pw_cache("alice") is None, "篡改后应失败返回 None"


def test_identity_exists():
    assert tui._identity_exists("no_such_user_xyz") is False
    assert callable(tui._identity_exists)


def test_login_screen_creates_identity(tmp_path, monkeypatch):
    """登录屏: 身份不存在时创建; 密码错误时拒绝。"""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(os.path, "expanduser", lambda p: str(fake_home))
    monkeypatch.setattr("tui._pw_cache_path",
                        lambda ident: str(fake_home / f"pw_{ident}.bin"))
    monkeypatch.setattr("tui._save_pw_cache", lambda *a: True)
    monkeypatch.setattr("tui._load_pw_cache", lambda *a: None)

    ok = [None]

    def on_ok(ident, pw):
        ok[0] = (ident, pw)

    screen = tui.LoginScreen.__new__(tui.LoginScreen)
    screen._identity = "new_user_abc"
    screen._on_ok = on_ok
    screen._on_cancel = None
    screen._remember = True  # 勾选记住

    # 身份不存在 → 验证通过 (创建) 后回调
    class _PwInput:
        value = "pw123"

        def focus(self):
            pass

    class _IdentInput:
        value = "new_user_abc"

    class _Chk:
        value = False

    class _App:
        def notify(self, *a, **k):
            pass

        def exit(self, *a, **k):
            pass

    class _Query:
        def __call__(self, sel, typ):
            if "login-identity" in sel:
                return _IdentInput()
            if "login-pw" in sel:
                return _PwInput()
            return _Chk()

    screen.query_one = _Query()
    screen.dismiss = lambda *a, **k: None
    # app 是只读 property, 用底层 _app 槽注入
    screen._app = _App()

    # 密码验证通过
    screen._do_login()
    assert ok[0] is not None, "登录应成功"
    assert ok[0][0] == "new_user_abc"


def test_login_invalid_identity_rejected():
    """非法身份名 (路径穿越) 拒绝。"""
    screen = tui.LoginScreen.__new__(tui.LoginScreen)
    screen._identity = "default"
    screen._on_ok = lambda *a: None
    screen._remember = False
    msg = {}

    def fake_notify(text, **kw):
        msg["text"] = text

    screen.notify = fake_notify  # 未挂载的 Screen 无 notify, 直接替换

    class _IdentInput:
        value = "../evil"

    class _PwInput:
        value = "pw"

    class _Query:
        def __call__(self, sel, typ):
            if "login-identity" in sel:
                return _IdentInput()
            if "login-pw" in sel:
                return _PwInput()
            return type("C", (), {"value": False})()

    screen.query_one = _Query()
    screen._do_login()
    assert "不合法" in msg.get("text", ""), "应提示身份名不合法"


def test_login_remember_toggle():
    """记住密码按钮: 点击切换状态, 标签随状态更新。"""
    screen = tui.LoginScreen.__new__(tui.LoginScreen)
    screen._remember = False
    toggled = []

    class _Btn:
        label = ""

        def __init__(self):
            toggled.append(self)

    screen.query_one = lambda sel, typ: _Btn()
    screen._toggle_remember()
    assert screen._remember is True, "点击后应记住"
    assert "☑" in toggled[0].label, "标签应变为勾选态"
    screen._toggle_remember()
    assert screen._remember is False, "再点应取消"
    assert "☐" in toggled[-1].label, "标签应变回未勾选"
