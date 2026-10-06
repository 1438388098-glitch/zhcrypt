#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
统一核心回归入口 (R1 新增)
========================
一键运行三套核心脚本式测试 (test_all / test_x3dh_full / test_security_fixes),
自动设置 PYTHONPATH 到仓库根, 汇总退出码: 任一失败即退出 1。

用法:
  python tests/run_core_tests.py              # 全部
  python tests/run_core_tests.py test_all     # 只跑名称含关键字的套件
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITES = ["test_all.py", "test_x3dh_full.py", "test_security_fixes.py"]


def _force_utf8_streams():
    """强制本进程输出用 UTF-8, 不依赖控制台代码页。

    Windows 下 stdout 走管道时默认按 locale (cp1252) 编码, 本脚本与子套件
    都要打印中文, 会抛 UnicodeEncodeError。旧解释器无 reconfigure 时静默跳过。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main():
    _force_utf8_streams()
    argv = sys.argv[1:]
    suites = [s for s in SUITES if not argv or any(a in s for a in argv)]
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    # 子套件同样直接打印中文: 显式给它们 UTF-8 输出, 避免继承 cp1252 管道编码。
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    failed = []
    for suite in suites:
        path = os.path.join(ROOT, "tests", suite)
        print(f"\n{'='*60}\n>>> 运行 {suite}\n{'='*60}")
        r = subprocess.run([sys.executable, path], env=env)
        # 本仓库位于云同步目录时可能遇到瞬时文件竞争 (sharing violation),
        # 失败先重试一次再判定, 避免环境抖动污染验证结果。
        if r.returncode != 0:
            print(f">>> {suite} 失败 (exit={r.returncode}), 重试一次...")
            r = subprocess.run([sys.executable, path], env=env)
        if r.returncode != 0:
            failed.append(suite)
    print(f"\n{'='*60}")
    if failed:
        print(f"失败套件: {', '.join(failed)}")
        return 1
    print(f"全部 {len(suites)} 套件通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
