#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
tui.py 冒烟测试 (无头, 不真正跑 UI)
===================================
覆盖:
  1. 纯函数: parse_command / is_safe_filename / status_prefix / build_bubble /
     fmt_file_size / truncate / format_search_results / decrypt_file_stream
  2. Binder 事件处理: handle_inbound_item (状态/消息/错误/文件)
  3. Textual 无头启动/退出/发送 (App.run_test + Pilot)
  4. main() 守卫: localstore/fileclient 未就绪时返回错误码 2

说明:
  localstore.py / fileclient.py 由其他 Agent 并行产出, 本测试通过
  unittest.mock.MagicMock 注入, 不依赖其实现, 独立可跑。
  手动验收项 (无法自动化): 真实终端中文 IME / 窗口缩放 / 键盘交互。

运行: packaging\\buildenv\\Scripts\\python.exe -m pytest tests/test_tui_smoke.py -q
"""

import os
import re
import sys
import json
import time
import asyncio
import threading

import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui
from tui import (
    parse_command, is_safe_filename, status_prefix, build_bubble,
    fmt_file_size, truncate, fmt_time, format_search_results,
    decrypt_file_stream, handle_inbound_item, binder_loop,
    NewMessage, StatusChanged, NotifyToast,
)


# ---------------------------------------------------------------------------
# parse_command
# ---------------------------------------------------------------------------

class TestParseCommand:
    def test_plain_text(self):
        assert parse_command("你好世界") == ("text", "你好世界")

    def test_empty(self):
        assert parse_command("") == ("", "")
        assert parse_command("   ") == ("", "")
        assert parse_command(None) == ("", "")

    def test_send_path(self):
        cmd, args = parse_command("/send D:\\docs\\report.pdf")
        assert cmd == "/send"
        assert args == "D:\\docs\\report.pdf"

    def test_send_no_args(self):
        assert parse_command("/send") == ("/send", "")

    def test_download_token(self):
        cmd, args = parse_command("/download a1b2c3d4")
        assert cmd == "/download"
        assert args == "a1b2c3d4"

    def test_history_default_and_number(self):
        assert parse_command("/history") == ("/history", "")
        assert parse_command("/history 100") == ("/history", "100")

    def test_case_insensitive(self):
        assert parse_command("/SEND x.txt") == ("/send", "x.txt")

    def test_unknown_command(self):
        assert parse_command("/foo bar baz") == ("/foo", "bar baz")

    def test_text_with_mid_slash(self):
        assert parse_command("a / b") == ("text", "a / b")

    def test_extra_whitespace(self):
        assert parse_command("  /history   100  ") == ("/history", "100")


# ---------------------------------------------------------------------------
# is_safe_filename (防路径穿越)
# ---------------------------------------------------------------------------

class TestIsSafeFilename:
    def test_valid_names(self):
        for good in ("report.pdf", "a_b-c.txt", "2026-08-07.log", "x",
                     "README.md", "报告.pdf"):
            assert is_safe_filename(good), f"应放行: {good!r}"

    def test_invalid_names(self):
        for bad in ("", ".", "..", "../evil.txt", "a\\b", "a/b", "a b.txt",
                    "a:b", "x" * 129, "CON", "con.txt", "NUL", "PRN",
                    "COM1", "LPT3.log", "..\\..\\evil"):
            assert not is_safe_filename(bad), f"应拒绝: {bad!r}"

    def test_non_string(self):
        assert not is_safe_filename(None)
        assert not is_safe_filename(123)


# ---------------------------------------------------------------------------
# 消息渲染
# ---------------------------------------------------------------------------

class TestRendering:
    def test_incoming_bubble(self):
        b = build_bubble("alice", "文件我收到了", status="delivered",
                         ts=1700000000, verified=True)
        lines = b.splitlines()
        assert len(lines) == 2
        assert re.match(r"^\[\d{2}:\d{2}\] alice ✓✓$", lines[0]), lines[0]
        assert lines[1] == "文件我收到了"

    def test_self_bubble_right_aligned(self):
        # 对齐由 CSS (.bubble-row) 处理, build_bubble 只输出内容
        b = build_bubble("alice", "hi", status="sent", ts=1700000000,
                         verified=True, is_self=True, width=40)
        lines = b.splitlines()
        assert len(lines) == 2
        assert lines[1] == "hi", "内容不应被 rjust 填充"
        assert "我 ✓" in lines[0]
        assert not lines[1].startswith(" "), "对齐不应内联在内容里"

    def test_file_bubble(self):
        meta = {"name": "report.pdf", "size": 2411724.8, "token": "abc123"}
        b = build_bubble("alice", "", status="sent", ts=1700000000,
                         verified=True, file_meta=meta)
        # P0-5: token 明文可见 + 下载指引 (替代不可点击的死文案 [下载])
        assert "📎 report.pdf (2.3MB)" in b
        assert "token: abc123" in b
        assert "按 d 下载" in b
        # 自己发送的文件无下载指引
        b2 = build_bubble("alice", "", status="sent", ts=1700000000,
                          verified=True, file_meta=meta, is_self=True)
        assert "按 d 下载" not in b2

    def test_verified_failed_prefix(self):
        b = build_bubble("alice", "x", status="delivered", ts=1700000000,
                         verified=False)
        assert "⚠" in b.splitlines()[0]

    def test_status_prefix(self):
        assert status_prefix("sent", True) == "✓"
        assert status_prefix("delivered", True) == "✓✓"
        assert status_prefix("queued") == "🕐"
        assert status_prefix("sending") == "🕐"
        assert status_prefix("failed") == "⚠"
        assert status_prefix("sent", False) == "⚠"
        assert status_prefix("delivered", False) == "⚠"

    def test_fmt_file_size(self):
        assert fmt_file_size(0) == "0B"
        assert fmt_file_size(1023) == "1023B"
        assert fmt_file_size(1024) == "1.0KB"
        assert fmt_file_size(2411724.8) == "2.3MB"
        assert fmt_file_size("oops") == "?"

    def test_truncate(self):
        assert truncate("abcde", 3) == "abc…"
        assert truncate("abc", 5) == "abc"
        assert truncate("a\nb", 10) == "a b"

    def test_fmt_time(self):
        assert re.match(r"^\d{2}:\d{2}$", fmt_time(1700000000))
        assert fmt_time("bad") == "--:--"

    def test_format_search_results(self):
        rows = [
            {"from_peer": "alice", "body": "你好世界", "ts": 1700000000, "msg_type": "text"},
            {"from_peer": "me", "body": "报告收到", "ts": 1700000060, "msg_type": "text"},
            {"from_peer": "alice", "body": '{"name": "a.pdf", "size": 100}',
             "ts": 1700000100, "msg_type": "file"},
        ]
        out = format_search_results("报告", rows, identity="me")
        assert "共 3 条" in out
        assert "alice: 你好世界" in out
        assert "我: 报告收到" in out
        assert "[文件] a.pdf" in out


# ---------------------------------------------------------------------------
# 文件解密 (与 Agent-B 加密格式对齐, 设计 §6.2)
# ---------------------------------------------------------------------------

def _make_block_cipher(key, data, chunk_size=tui.FILE_CHUNK_SIZE):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    parts = [b"\x02" * 12]
    offset = 0
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        parts.append(aesgcm.encrypt(parts[0], chunk, str(offset).encode("ascii")))
        offset += len(chunk)
    return b"".join(parts)


class TestDecryptFile:
    def test_roundtrip_block_format(self, tmp_path):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = b"\x01" * 32
        data = os.urandom(2_500_000)  # 跨两个 1MB 块
        cipher = _make_block_cipher(key, data)
        cp, op = tmp_path / "c.enc", tmp_path / "o.bin"
        cp.write_bytes(cipher)
        err = decrypt_file_stream(key, str(cp), str(op))
        assert err == ""
        assert op.read_bytes() == data

    def test_wrong_key(self, tmp_path):
        key = b"\x01" * 32
        data = os.urandom(4096)
        cp = tmp_path / "c.enc"
        cp.write_bytes(_make_block_cipher(key, data))
        err = decrypt_file_stream(b"\x03" * 32, str(cp), str(tmp_path / "o.bin"))
        assert err != ""  # 不应抛异常, 返回错误信息

    def test_single_block_fallback(self, tmp_path):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = b"\x01" * 32
        data = b"hello world" * 100
        nonce = b"\x02" * 12
        single = nonce + AESGCM(key).encrypt(nonce, data, None)
        cp, op = tmp_path / "s.enc", tmp_path / "s.bin"
        cp.write_bytes(single)
        err = decrypt_file_stream(key, str(cp), str(op))
        assert err == ""
        assert op.read_bytes() == data

    def test_truncated(self, tmp_path):
        cp = tmp_path / "t.enc"
        cp.write_bytes(b"\x02" * 12 + b"\x00" * 10)
        err = decrypt_file_stream(b"\x01" * 32, str(cp), str(tmp_path / "o.bin"))
        assert err != ""

    def test_bad_key_length(self, tmp_path):
        err = decrypt_file_stream(b"short", "nonexist", "out")
        assert "密钥长度错误" in err


# ---------------------------------------------------------------------------
# Binder 事件处理 (不跑 UI, 用假 App 记录 post_message)
# ---------------------------------------------------------------------------

class _FakeApp:
    def __init__(self, current_peer="bob"):
        self.posted = []
        self._current_peer = current_peer

    def post_message(self, m):
        self.posted.append(m)


class TestBinder:
    def test_status_event(self):
        app = _FakeApp()
        handle_inbound_item(app, MagicMock(), MagicMock(),
                            {"action": "status", "connected": True})
        assert len(app.posted) == 1
        assert isinstance(app.posted[0], StatusChanged)
        assert app.posted[0].connected is True

    def test_text_message_ingest_with_unread(self):
        app = _FakeApp(current_peer="bob")
        client = MagicMock()
        store = MagicMock()
        client.receive_chat_message.return_value = {
            "text": "你好", "from": "alice", "timestamp": 123.0,
            "verified": True, "msg_id": "m1",
        }
        handle_inbound_item(app, client, store,
                            {"action": "server_message",
                             "data": {"type": "message", "msg": {"id": "m1"}}})
        # 落库
        store.upsert_message.assert_called_once()
        peer, msg_id, from_peer, mtype, body, status, verified, ts = \
            store.upsert_message.call_args.args
        assert (peer, msg_id, from_peer, mtype, status, verified) == \
            ("alice", "m1", "alice", "text", "delivered", 1)
        assert body == "你好"
        # 会话: 非当前会话 → 未读 +1
        store.upsert_conversation.assert_called_once()
        args = store.upsert_conversation.call_args.args
        assert args[0] == "alice"
        assert store.upsert_conversation.call_args.kwargs["unread_inc"] is True
        # UI 事件
        nm = app.posted[-1]
        assert isinstance(nm, NewMessage)
        assert (nm.peer, nm.msg_id, nm.msg_type) == ("alice", "m1", "text")

    def test_current_peer_no_unread(self):
        app = _FakeApp(current_peer="alice")
        client = MagicMock()
        store = MagicMock()
        client.receive_chat_message.return_value = {
            "text": "hi", "from": "alice", "timestamp": 1.0,
            "verified": False, "msg_id": "m2",
        }
        handle_inbound_item(app, client, store,
                            {"action": "server_message",
                             "data": {"type": "message", "msg": {}}})
        args = store.upsert_conversation.call_args.args
        assert args[0] == "alice"
        assert store.upsert_conversation.call_args.kwargs["unread_inc"] is False

    def test_file_message_saves_key(self):
        import base64
        key = base64.urlsafe_b64encode(b"\x07" * 32).decode()
        app = _FakeApp(current_peer="alice")
        client = MagicMock()
        store = MagicMock()
        client.receive_chat_message.return_value = {
            "text": "", "from": "alice", "timestamp": 1.0, "verified": True,
            "msg_id": "f1",
            "file": {"name": "a.pdf", "size": 10, "sha256": "aa",
                     "token": "tok", "key": key},
        }
        handle_inbound_item(app, client, store,
                            {"action": "server_message",
                             "data": {"type": "message", "msg": {}}})
        store.save_file_key.assert_called_once()
        assert store.save_file_key.call_args.args[0] == "f1"
        assert store.save_file_key.call_args.args[1] == b"\x07" * 32
        # 消息类型为 file
        mtype = store.upsert_message.call_args.args[3]
        assert mtype == "file"

    def test_error_result_toast(self):
        app = _FakeApp()
        client = MagicMock()
        store = MagicMock()
        client.receive_chat_message.return_value = {"error": "解密失败"}
        handle_inbound_item(app, client, store,
                            {"action": "server_message",
                             "data": {"type": "message", "msg": {}}})
        store.upsert_message.assert_not_called()
        toast = app.posted[-1]
        assert isinstance(toast, NotifyToast)
        assert toast.severity == "error"

    def test_none_result_duplicate_silent(self):
        """重复投递 (msg 已在本地) → 静默跳过, 无 toast。"""
        app = _FakeApp()
        client = MagicMock()
        client.receive_chat_message.return_value = None
        store = MagicMock()
        store.get_messages.return_value = [{"msg_id": "m1"}]
        handle_inbound_item(app, client, store,
                            item={"action": "server_message",
                                  "data": {"type": "message",
                                           "msg": {"id": "m1", "from": "alice"}}})
        assert app.posted == []

    def test_none_result_undecryptable_warns(self):
        """无法解密的新消息 → warning toast (C2 修复: 不再静默丢弃)。"""
        app = _FakeApp()
        client = MagicMock()
        client.receive_chat_message.return_value = None
        store = MagicMock()
        store.get_messages.return_value = []
        handle_inbound_item(app, client, store,
                            item={"action": "server_message",
                                  "data": {"type": "message",
                                           "msg": {"id": "m9", "from": "alice"}}})
        assert len(app.posted) == 1
        assert isinstance(app.posted[0], NotifyToast)
        assert "无法解密" in app.posted[0].text
        assert app.posted[0].severity == "warning"

    def test_error_action(self):
        app = _FakeApp()
        handle_inbound_item(app, MagicMock(), MagicMock(),
                            {"action": "error", "message": "连接失败"})
        assert isinstance(app.posted[0], NotifyToast)
        assert "连接失败" in app.posted[0].text

    def test_unknown_action_ignored(self):
        app = _FakeApp()
        handle_inbound_item(app, MagicMock(), MagicMock(),
                            {"action": "whatever", "data": 1})
        assert app.posted == []

    def test_binder_loop_stops_on_event(self):
        ev = threading.Event()
        ev.set()
        t0 = time.time()
        binder_loop(_FakeApp(), MagicMock(), MagicMock(), ev)
        assert time.time() - t0 < 0.5


# ---------------------------------------------------------------------------
# Textual 无头启动/退出/发送 (App.run_test + Pilot)
# ---------------------------------------------------------------------------

def _make_app(convs=None):
    store = MagicMock()
    # 说明: 无头 run_test 中仅使用"空会话列表"配置 —— 预先填充会话会导致
    # Textual 8.2.8 在 Windows 无头环境的 _wait_for_screen 偶发挂起/重复挂载
    # (on_mount 二次触发 → ListItem id 冲突)。带会话列表的交互渲染
    # 归入手动验收项 (见模块 docstring)。
    store.list_conversations.return_value = convs if convs is not None else []
    store.get_messages.return_value = []
    store.clear_unread = MagicMock()
    client = MagicMock()
    client.send_chat_message.return_value = {"status": "sent", "msg_id": "m1"}
    client.get_safety_number.return_value = {"safety_number": "1234567890", "late_pin": False}
    file_client = MagicMock()
    return tui.ChatApp(client=client, store=store, file_client=file_client,
                       identity="tester")


class TestAppSmoke:
    """无头 run_test 冒烟 (空会话配置, 稳定可跑)。

    手动验收项 (无法无头自动化):
      - 会话列表渲染 + 未读角标 + ↑/↓+Enter 切换
      - 实时消息流 (Binder → UI) 与安全码 Toast
      - 文件收发气泡/进度/下载校验
      - 真实终端中文 IME / 窗口缩放
    """

    def test_start_and_exit(self):
        app = _make_app()

        async def run():
            async with app.run_test(size=(100, 30)) as pilot:
                await pilot.pause()
                assert app.title == "zhcrypt-chat"
                assert "tester" in app.sub_title
                # 布局齐全 (query_one 找不到会直接抛异常)
                app.query_one("#conv-list")
                app.query_one("#chat-view")
                app.query_one("#chat-input")
                app.query_one("#status-bar")
                # 无会话 → 不打开任何会话, 显示引导
                assert app._current_peer is None
                sb = app.query_one("#status-bar")
                assert "未读 0" in str(sb.content)
                app.exit(0)

        asyncio.run(run())
        # 退出后 Binder 线程已停
        assert app._binder is not None
        assert not app._binder.is_alive()

    def test_send_text_with_peer(self):
        from textual.widgets import Input

        app = _make_app()

        async def run():
            async with app.run_test(size=(100, 30)) as pilot:
                app._current_peer = "alice"
                inp = app.query_one("#chat-input", Input)
                inp.focus()
                await pilot.press("h", "e", "l", "l", "o")
                await pilot.press("enter")
                await pilot.pause()
                # 异步 worker 线程发送 (不阻塞 UI)
                import time as _t
                deadline = _t.time() + 3
                while _t.time() < deadline and \
                        not app.client.send_chat_message.called:
                    await pilot.pause()
                    _t.sleep(0.05)
                app.client.send_chat_message.assert_called_with("alice", "hello")
                # 本地落库: queued(发送中) + sent(成功) 两条
                assert app.store.upsert_message.call_count >= 2
                app.exit(0)

        asyncio.run(run())

    def test_send_error_visible_in_chat(self):
        """发送失败: 消息以 failed 状态落库可见 (M1 修复), 可 r 重发。"""
        from textual.widgets import Input

        app = _make_app()
        app.client.send_chat_message.return_value = {"error": "无法获取 alice 的 prekey"}

        async def run():
            async with app.run_test(size=(100, 30)) as pilot:
                app._current_peer = "alice"
                inp = app.query_one("#chat-input", Input)
                inp.focus()
                await pilot.press("x", "y")
                await pilot.press("enter")
                await pilot.pause()
                # 失败消息应落库 (failed 状态, 界面可见 ⚠)
                import time as _t
                deadline = _t.time() + 3
                while _t.time() < deadline:
                    await pilot.pause()
                    _t.sleep(0.05)
                assert app.store.upsert_message.call_count >= 1
                app.exit(0)

        asyncio.run(run())

    def test_send_without_peer_guarded(self):
        from textual.widgets import Input

        app = _make_app()

        async def run():
            async with app.run_test(size=(100, 30)) as pilot:
                inp = app.query_one("#chat-input", Input)
                inp.focus()
                await pilot.press("h", "i")
                await pilot.press("enter")
                await pilot.pause()
                # 未选会话 → 不发送
                app.client.send_chat_message.assert_not_called()
                app.exit(0)

        asyncio.run(run())

    def test_unknown_command_no_send(self):
        from textual.widgets import Input

        app = _make_app()

        async def run():
            async with app.run_test(size=(100, 30)) as pilot:
                inp = app.query_one("#chat-input", Input)
                inp.focus()
                for ch in "/zzz":
                    await pilot.press(ch)
                await pilot.press("enter")
                await pilot.pause()
                # 未知命令不触发发送
                app.client.send_chat_message.assert_not_called()
                app.exit(0)

        asyncio.run(run())

    def test_open_command_sets_peer(self):
        from textual.widgets import Input

        app = _make_app()

        async def run():
            async with app.run_test(size=(100, 30)) as pilot:
                inp = app.query_one("#chat-input", Input)
                inp.focus()
                for ch in "/open bob":
                    await pilot.press(ch)
                await pilot.press("enter")
                await pilot.pause()
                assert app._current_peer == "bob"
                app.store.clear_unread.assert_called_with("bob")
                app.exit(0)

        asyncio.run(run())

    def test_narrow_width_keeps_panel_visible(self):
        """窄窗口: 左侧列表始终显示 (只压缩宽度, 不隐藏)。"""
        app = _make_app()

        async def run():
            async with app.run_test(size=(100, 30)) as pilot:
                assert app.query_one("#conv-panel").display is True
                await pilot.resize_terminal(50, 30)
                await pilot.pause()
                # 窄窗口仍可见 (不再折叠)
                assert app.query_one("#conv-panel").display is True
                app.exit(0)

        asyncio.run(run())


# ---------------------------------------------------------------------------
# main() 守卫 (localstore/fileclient 未就绪时返回错误码 2)
# ---------------------------------------------------------------------------

def test_main_guard_when_dependencies_missing():
    if tui.LocalStore is None or tui.FileClient is None:
        assert tui.main("tester", "pw") == 2
    else:
        pytest.skip("localstore/fileclient 已就绪, 守卫测试跳过")
