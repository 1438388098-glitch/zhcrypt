#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""pytest 共享配置 (R7 新增)。

1. 统一把仓库根插入 sys.path —— 测试模块直接 import server/chat_server/core 等;
   不再依赖 `python -m pytest` 的 cwd 注入 (裸 pytest 此前必挂)。
2. collect_ignore: 脚本式套件在收集期就会全量执行 (副作用 + 重复耗时),
   它们由 tests/run_core_tests.py 单独驱动, 不进入 pytest 收集。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

collect_ignore = [
    # 脚本式套件: 收集期即全量执行 (副作用/耗时/可能 sys.exit),
    # 由 tests/run_core_tests.py 或手工驱动, 不进入 pytest 收集。
    "test_all.py",
    "test_security_fixes.py",
    "test_x3dh_full.py",       # 函数需要 spk/otp 参数, 由模块级脚本驱动
    "test_chat.py",            # def test(name) 参数化脚本驱动
    "test_e2e.py",             # 需要真实服务器 + ZHCHAT_TEST_TOKEN
    "test_e2e_integration.py",
    "test_friend_e2e.py",
    "test_real_scenario.py",
    "test_round1_integration.py",
    "test_sync_e2e.py",
    "test_first_run.py",       # 关闭 stdio, 与 pytest 捕获不兼容
    "e2e_local_smoke.py",      # R14: 真实双服务进程 E2E, 单独手工运行
    "run_core_tests.py",
    "security_audit.py",       # 攻击模拟平台 (非测试)
]
