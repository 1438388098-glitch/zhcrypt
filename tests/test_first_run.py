# -*- coding: utf-8 -*-
"""验证首次运行引导逻辑 (cli._ensure_identity)"""
import sys
import io
import os
import tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 隔离: 临时 HOME, 不碰真实 ~/.zhcrypt
fake_home = tempfile.mkdtemp(prefix="fresh_home_")
os.environ["USERPROFILE"] = fake_home
os.environ["HOME"] = fake_home

import cli

FAIL = []


def check(cond, msg):
    print(("  OK: " if cond else "  FAIL: ") + msg)
    if not cond:
        FAIL.append(msg)


print("== 场景 1: 全新用户 (无任何身份) → 应引导创建 ===")
inputs = iter(["", "pw123", "pw123"])  # 身份名回车(用默认), 密码, 确认
cli.input = lambda prompt="": next(inputs)
cli.getpass.getpass = lambda prompt="": "pw123"
cli.Spinner = type("Spinner", (), {"__init__": lambda s, m: None,
                                   "__enter__": lambda s: None,
                                   "__exit__": lambda s, *a: None})
result = cli._ensure_identity("default")
check(result is not None, f"返回身份: {result}")
check(result and result[0] == "default", "默认身份名 default")
from keys import KeyStore
ks = KeyStore()
try:
    ks.load_public_key("default")
    check(True, "default 身份已创建")
except Exception:
    check(False, "default 身份创建失败")

print()
print("== 场景 2: 有身份但默认身份不存在 → 应列出已有身份 ==")
# 先建一个身份 alice
ks.generate_identity("alice", "pw9", comment="x")
cli.input = lambda prompt="": "alice"
cli.getpass.getpass = lambda prompt="": "pw9"
result2 = cli._ensure_identity("nonexistent_default")
check(result2 is not None and result2[0] == "alice",
      f"应选已有身份 alice (得到 {result2})")

print()
print("== 场景 3: 身份存在 → 直接输密码 ==")
cli.getpass.getpass = lambda prompt="": "pw9"
result3 = cli._ensure_identity("alice")
check(result3 is not None and result3[0] == "alice" and result3[1] == "pw9",
      "直接返回已有身份")

print()
if FAIL:
    print(f"FIRST-RUN CHECK FAILED: {len(FAIL)}")
    sys.exit(1)
print("FIRST-RUN ALL PASSED")
