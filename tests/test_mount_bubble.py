# -*- coding: utf-8 -*-
"""
消息挂载回归测试 (MountError 修复):
_mount_bubble 直接挂载 Static (不创建中间容器), 自己消息右对齐由 CSS 处理。
"""
import os
import sys
import time
import inspect

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui


class _FakeView:
    def __init__(self):
        self.mounted = []

    def mount(self, w):
        self.mounted.append(w)

    def query_one(self, *a, **k):
        return self

    def remove_children(self):
        pass

    def scroll_end(self, *a, **k):
        pass


def _make_app():
    app = tui.ChatApp.__new__(tui.ChatApp)
    app.identity = "me"
    view = _FakeView()
    app.query_one = lambda *a, **k: view
    return app, view


def test_mount_bubble_no_intermediate_container():
    """不创建未挂载的中间容器 (MountError 根因: box.mount 于未挂载 box)。"""
    src = inspect.getsource(tui.ChatApp._mount_bubble)
    assert "box = Vertical(" not in src
    assert "view.mount(Static(bubble" in src


def test_mount_bubble_self_right_align_css():
    assert "text-align: right" in tui._CSS


def test_mount_bubble_incoming():
    app, view = _make_app()
    row = {"peer": "bob", "from_peer": "bob", "msg_type": "text",
           "body": "你好", "status": "sent", "verified": 1, "ts": time.time()}
    app._mount_bubble("bob", row)
    assert len(view.mounted) == 1


def test_mount_bubble_self():
    app, view = _make_app()
    row = {"peer": "bob", "from_peer": "me", "msg_type": "text",
           "body": "你也好", "status": "sent", "verified": 1, "ts": time.time()}
    app._mount_bubble("bob", row)
    assert len(view.mounted) == 1


def test_mount_bubble_file():
    app, view = _make_app()
    row = {"peer": "bob", "from_peer": "bob", "msg_type": "file",
           "body": '{"name":"a.pdf","size":12345,"token":"t"}',
           "status": "sent", "verified": 1, "ts": time.time()}
    app._mount_bubble("bob", row)
    assert len(view.mounted) == 1
