#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R16: 会话锁并发压测
==================
锁定 C1 修复语义: 并发「读-改-写」必须经 session_lock 串行化,
最终状态无丢失更新 (不加锁时 8×25 次必然丢更新)。
运行: py -3.13 -m pytest tests/test_session_lock_stress.py -q
"""
import json
import os
import threading

import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import session as session_mod
from core import SALT_SIZE, NONCE_SIZE


@pytest.fixture
def sess_env(tmp_path, monkeypatch):
    monkeypatch.setattr(session_mod, "SESSIONS_DIR", str(tmp_path / "s"))
    d = session_mod._peer_dir("alice")
    return session_mod._session_path("alice", "bob")


def _write_counter(path, key, n):
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, json.dumps({"n": n}).encode("utf-8"), None)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(salt + nonce + ct)
    os.replace(tmp, path)


def _read_counter(path, key):
    with open(path, "rb") as f:
        data = f.read()
    salt_i = data[:SALT_SIZE]
    k = session_mod._cached_wrapping_key("pwd", salt_i)
    nonce, ct = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE], data[SALT_SIZE + NONCE_SIZE:]
    return json.loads(AESGCM(k).decrypt(nonce, ct, None).decode("utf-8"))["n"]


salt = os.urandom(SALT_SIZE)


def test_session_lock_prevents_lost_updates(sess_env):
    """8 线程 × 25 次持锁计数递增: 终值必须为 200 (无丢失更新)。"""
    key = session_mod._cached_wrapping_key("pwd", salt)
    _write_counter(sess_env, key, 0)

    errors = []

    def worker():
        for _ in range(25):
            try:
                with session_mod.session_lock("alice", "bob"):
                    n = _read_counter(sess_env, key)
                    _write_counter(sess_env, key, n + 1)
            except Exception as e:  # pragma: no cover
                errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[:3]
    assert _read_counter(sess_env, key) == 200


def test_lock_is_reentrant_same_thread(sess_env):
    """同线程可重入 (RLock), 嵌套 load→save 不自锁。"""
    key = session_mod._cached_wrapping_key("pwd", salt)
    _write_counter(sess_env, key, 0)
    with session_mod.session_lock("alice", "bob"):
        with session_mod.session_lock("alice", "bob"):
            _write_counter(sess_env, key, 7)
    assert _read_counter(sess_env, key) == 7
