#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhchat 集成测试
===============
测试 Double Ratchet 协议、会话管理、消息收发
"""

import os
import sys
import json
import time
import secrets
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASSED = 0
FAILED = 0


def test(name):
    global PASSED, FAILED
    PASSED += 1
    print(f"  [{PASSED + FAILED:02d}] {name}...", end=" ")
    return True


def fail(msg=""):
    global PASSED, FAILED
    FAILED += 1
    PASSED -= 1
    print(f"FAIL {msg}" if msg else "FAIL")
    return False


def ok():
    print("PASS 通过")


def test_kdf_chain():
    from ratchet import KDF_CK, KDF_RK, KEY_SIZE

    test("KDF_CK 派生链密钥和消息密钥")
    ck = secrets.token_bytes(KEY_SIZE)
    new_ck, mk = KDF_CK(ck)
    if len(new_ck) != KEY_SIZE or len(mk) != KEY_SIZE:
        return fail("密钥长度错误")
    if new_ck == ck:
        return fail("CK 未变化")
    if mk == new_ck:
        return fail("MK 不应等于 CK")
    ok()

    test("KDF_CK 确定性: 相同输入产生相同输出")
    new_ck2, mk2 = KDF_CK(ck)
    if new_ck != new_ck2 or mk != mk2:
        return fail("非确定性")
    ok()

    test("KDF_RK 派生根密钥和链密钥")
    rk = secrets.token_bytes(KEY_SIZE)
    dh = secrets.token_bytes(KEY_SIZE)
    new_rk, ck_out = KDF_RK(rk, dh)
    if len(new_rk) != KEY_SIZE or len(ck_out) != KEY_SIZE:
        return fail("密钥长度错误")
    if new_rk == rk:
        return fail("RK 未变化")
    ok()


def test_session_state():
    from ratchet import SessionState, KEY_SIZE, generate_x25519_keypair_raw

    test("SessionState 创建和序列化")
    sid = secrets.token_bytes(16)
    priv, pub = generate_x25519_keypair_raw()
    rk = secrets.token_bytes(KEY_SIZE)
    cks = secrets.token_bytes(KEY_SIZE)
    ckr = secrets.token_bytes(KEY_SIZE)
    their_pub = secrets.token_bytes(32)

    state = SessionState(
        session_id=sid,
        my_identity="alice",
        peer_identity="bob",
        peer_signing_pub=b"fake-pub",
        root_key=rk,
        send_chain_key=cks,
        recv_chain_key=ckr,
        our_ratchet_priv=priv,
        our_ratchet_pub=pub,
        their_ratchet_pub=their_pub,
    )

    d = state.to_dict()
    if d["v"] != 1:
        return fail("版本号错误")
    if d["my_identity"] != "alice":
        return fail("身份错误")
    if d["peer_identity"] != "bob":
        return fail("对方身份错误")
    ok()

    test("SessionState 反序列化")
    state2 = SessionState.from_dict(d)
    if state2.my_identity != "alice":
        return fail("my_identity")
    if state2.send_msg_number != 0:
        return fail("send_msg_number")
    if state2.root_key != rk:
        return fail("root_key 不匹配")
    ok()

    test("SessionState 跳过密钥存储")
    state.skipped_keys = {"abc": {1: secrets.token_bytes(KEY_SIZE)}}
    d2 = state.to_dict()
    state3 = SessionState.from_dict(d2)
    if "abc" not in state3.skipped_keys:
        return fail("skipped_keys 丢失")
    if 1 not in state3.skipped_keys["abc"]:
        return fail("skipped 消息号丢失")
    ok()

    test("SessionState seen_message_ids LRU")
    for i in range(1500):
        state._mark_seen(f"msg-{i}")
    if len(state.seen_message_ids) > 1000:
        return fail(f"LRU 未生效: {len(state.seen_message_ids)}")
    ok()


def test_session_persistence():
    from ratchet import SessionState, KEY_SIZE, generate_x25519_keypair_raw
    from session import save_session, load_session, delete_session, list_sessions

    test("save_session 和 load_session")
    sid = secrets.token_bytes(16)
    priv, pub = generate_x25519_keypair_raw()
    state = SessionState(
        session_id=sid, my_identity="alice", peer_identity="bob",
        peer_signing_pub=b"pub",
        root_key=secrets.token_bytes(KEY_SIZE),
        send_chain_key=secrets.token_bytes(KEY_SIZE),
        recv_chain_key=secrets.token_bytes(KEY_SIZE),
        our_ratchet_priv=priv, our_ratchet_pub=pub,
        their_ratchet_pub=secrets.token_bytes(32),
    )
    save_session(state, "testpassword")
    loaded = load_session("alice", "bob", "testpassword")
    if loaded is None:
        return fail("加载失败")
    if loaded.my_identity != "alice":
        return fail("身份不匹配")
    if loaded.root_key != state.root_key:
        return fail("根密钥不匹配")
    ok()

    test("load_session 错误密码返回 None")
    loaded = load_session("alice", "bob", "wrongpassword")
    if loaded is not None:
        return fail("错误密码应返回 None")
    ok()

    test("list_sessions 列出会话")
    sessions = list_sessions("alice")
    if not any(s["peer"] == "bob" for s in sessions):
        return fail("未找到 bob 会话")
    ok()

    test("delete_session 删除会话")
    delete_session("alice", "bob")
    loaded = load_session("alice", "bob", "testpassword")
    if loaded is not None:
        return fail("删除后仍可加载")
    ok()


def test_send_receive():
    from ratchet import (
        SessionState, KEY_SIZE, generate_x25519_keypair_raw,
        send_message, receive_message,
    )

    test("正常发送和接收消息")
    alice_priv, alice_pub = generate_x25519_keypair_raw()
    bob_priv, bob_pub = generate_x25519_keypair_raw()

    alice_state = SessionState(
        session_id=secrets.token_bytes(16),
        my_identity="alice", peer_identity="bob",
        peer_signing_pub=b"bob-pub",
        root_key=secrets.token_bytes(KEY_SIZE),
        send_chain_key=secrets.token_bytes(KEY_SIZE),
        recv_chain_key=secrets.token_bytes(KEY_SIZE),
        our_ratchet_priv=alice_priv, our_ratchet_pub=alice_pub,
        their_ratchet_pub=bob_pub,
    )
    bob_state = SessionState(
        session_id=alice_state.session_id,
        my_identity="bob", peer_identity="alice",
        peer_signing_pub=b"alice-pub",
        root_key=alice_state.root_key,
        send_chain_key=b"\x00" * KEY_SIZE,
        recv_chain_key=alice_state.send_chain_key,
        our_ratchet_priv=bob_priv, our_ratchet_pub=bob_pub,
        their_ratchet_pub=alice_pub,
    )

    plaintext = "Hello zhchat!"
    inner = json.dumps({"text": plaintext, "signature": ""}, ensure_ascii=False).encode("utf-8")
    msg = send_message(alice_state, inner)

    if msg["type"] != "message":
        return fail("消息类型错误")
    if msg["from"] != "alice":
        return fail("发送者错误")

    plain = receive_message(bob_state, msg)
    if plain is None:
        return fail("解密失败")
    result = json.loads(plain.decode("utf-8"))
    if result["text"] != plaintext:
        return fail(f"明文不匹配: {result['text']}")
    ok()

    test("多条消息连续收发")
    for i in range(5):
        inner = json.dumps({"text": f"msg{i}", "signature": ""}, ensure_ascii=False).encode("utf-8")
        msg = send_message(alice_state, inner)
        plain = receive_message(bob_state, msg)
        result = json.loads(plain.decode("utf-8"))
        if result["text"] != f"msg{i}":
            return fail(f"消息 {i} 不匹配")
    ok()

    test("消息去重")
    plain = receive_message(bob_state, msg)
    if plain is not None:
        return fail("重复消息应返回 None")
    ok()


def test_dh_ratchet():
    from ratchet import (
        SessionState, KEY_SIZE, generate_x25519_keypair_raw,
        send_message, receive_message, KDF_RK, x25519_ecdh_raw,
    )

    test("DH 棘轮触发后消息正常收发")
    alice_priv, alice_pub = generate_x25519_keypair_raw()
    bob_priv, bob_pub = generate_x25519_keypair_raw()

    rk = secrets.token_bytes(KEY_SIZE)
    alice_ck_s = secrets.token_bytes(KEY_SIZE)
    alice_ck_r = secrets.token_bytes(KEY_SIZE)
    bob_ck_s = alice_ck_r
    bob_ck_r = alice_ck_s

    alice_state = SessionState(
        session_id=secrets.token_bytes(16),
        my_identity="alice", peer_identity="bob",
        peer_signing_pub=b"bob-pub", root_key=rk,
        send_chain_key=alice_ck_s, recv_chain_key=alice_ck_r,
        our_ratchet_priv=alice_priv, our_ratchet_pub=alice_pub,
        their_ratchet_pub=bob_pub,
    )
    bob_state = SessionState(
        session_id=alice_state.session_id,
        my_identity="bob", peer_identity="alice",
        peer_signing_pub=b"alice-pub", root_key=rk,
        send_chain_key=bob_ck_s, recv_chain_key=bob_ck_r,
        our_ratchet_priv=bob_priv, our_ratchet_pub=bob_pub,
        their_ratchet_pub=alice_pub,
    )

    inner = json.dumps({"text": "msg1"}, ensure_ascii=False).encode("utf-8")
    msg1 = send_message(alice_state, inner)
    plain1 = receive_message(bob_state, msg1)
    if plain1 is None:
        return fail("msg1 解密失败")
    if json.loads(plain1.decode("utf-8"))["text"] != "msg1":
        return fail("msg1 内容不匹配")

    bob_new_priv, bob_new_pub = generate_x25519_keypair_raw()
    dh_a = x25519_ecdh_raw(bob_new_priv, bob_state.their_ratchet_pub)
    new_rk, new_ck_s = KDF_RK(bob_state.root_key, dh_a)
    bob_state.root_key = new_rk
    bob_state.send_chain_key = new_ck_s
    bob_state.our_ratchet_priv = bob_new_priv
    bob_state.our_ratchet_pub = bob_new_pub
    bob_state.send_msg_number = 0
    bob_state.prev_send_chain_len = 0

    inner2 = json.dumps({"text": "reply1"}, ensure_ascii=False).encode("utf-8")
    msg2 = send_message(bob_state, inner2)

    plain2 = receive_message(alice_state, msg2)
    if plain2 is None:
        return fail("DH 棘轮后 msg2 解密失败")
    result2 = json.loads(plain2.decode("utf-8"))
    if result2["text"] != "reply1":
        return fail(f"DH 棘轮后内容不匹配: {result2['text']}")

    inner3 = json.dumps({"text": "msg3"}, ensure_ascii=False).encode("utf-8")
    msg3 = send_message(alice_state, inner3)
    plain3 = receive_message(bob_state, msg3)
    if plain3 is None:
        return fail("DH 棘轮后 msg3 解密失败")

    r3 = json.loads(plain3.decode("utf-8"))
    if r3["text"] != "msg3":
        return fail(f"msg3 内容不匹配: {r3['text']}")

    ok()


def test_skipped_messages():
    from ratchet import (
        SessionState, KEY_SIZE, generate_x25519_keypair_raw,
        send_message, receive_message, try_decrypt_skipped,
    )

    test("乱序消息缓存与回补")
    alice_priv, alice_pub = generate_x25519_keypair_raw()
    bob_priv, bob_pub = generate_x25519_keypair_raw()

    rk = secrets.token_bytes(KEY_SIZE)
    alice_state = SessionState(
        session_id=secrets.token_bytes(16),
        my_identity="alice", peer_identity="bob",
        peer_signing_pub=b"bob-pub", root_key=rk,
        send_chain_key=secrets.token_bytes(KEY_SIZE),
        recv_chain_key=secrets.token_bytes(KEY_SIZE),
        our_ratchet_priv=alice_priv, our_ratchet_pub=alice_pub,
        their_ratchet_pub=bob_pub,
    )
    bob_state = SessionState(
        session_id=alice_state.session_id,
        my_identity="bob", peer_identity="alice",
        peer_signing_pub=b"alice-pub", root_key=rk,
        send_chain_key=b"\x00" * KEY_SIZE,
        recv_chain_key=alice_state.send_chain_key,
        our_ratchet_priv=bob_priv, our_ratchet_pub=bob_pub,
        their_ratchet_pub=alice_pub,
    )

    msgs = []
    for i in range(5):
        inner = json.dumps({"text": f"msg{i}"}, ensure_ascii=False).encode("utf-8")
        msgs.append(send_message(alice_state, inner))

    plain4 = receive_message(bob_state, msgs[4])
    if plain4 is None:
        return fail("msg4 解密失败")

    plain0 = receive_message(bob_state, msgs[0])
    if plain0 is None:
        return fail("msg0 解密失败 (应缓存密钥)")

    result = json.loads(plain0.decode("utf-8"))
    if result["text"] != "msg0":
        return fail(f"msg0 内容不对: {result['text']}")

    plain2 = receive_message(bob_state, msgs[2])
    result2 = json.loads(plain2.decode("utf-8"))
    if result2["text"] != "msg2":
        return fail(f"msg2 内容不对: {result2['text']}")

    plain1 = receive_message(bob_state, msgs[1])
    result1 = json.loads(plain1.decode("utf-8"))
    if result1["text"] != "msg1":
        return fail(f"msg1 内容不对: {result1['text']}")

    plain3 = receive_message(bob_state, msgs[3])
    result3 = json.loads(plain3.decode("utf-8"))
    if result3["text"] != "msg3":
        return fail(f"msg3 内容不对: {result3['text']}")

    ok()


def test_tamper_detection():
    from ratchet import (
        SessionState, KEY_SIZE, generate_x25519_keypair_raw,
        send_message, receive_message,
    )

    test("篡改密文检测")
    alice_priv, alice_pub = generate_x25519_keypair_raw()
    bob_priv, bob_pub = generate_x25519_keypair_raw()

    alice_state = SessionState(
        session_id=secrets.token_bytes(16),
        my_identity="alice", peer_identity="bob",
        peer_signing_pub=b"bob-pub",
        root_key=secrets.token_bytes(KEY_SIZE),
        send_chain_key=secrets.token_bytes(KEY_SIZE),
        recv_chain_key=secrets.token_bytes(KEY_SIZE),
        our_ratchet_priv=alice_priv, our_ratchet_pub=alice_pub,
        their_ratchet_pub=bob_pub,
    )
    bob_state = SessionState(
        session_id=alice_state.session_id,
        my_identity="bob", peer_identity="alice",
        peer_signing_pub=b"alice-pub",
        root_key=alice_state.root_key,
        send_chain_key=b"\x00" * KEY_SIZE,
        recv_chain_key=alice_state.send_chain_key,
        our_ratchet_priv=bob_priv, our_ratchet_pub=bob_pub,
        their_ratchet_pub=alice_pub,
    )

    inner = json.dumps({"text": "test"}, ensure_ascii=False).encode("utf-8")
    msg = send_message(alice_state, inner)

    tampered_ciphertext = msg["payload"]["ciphertext"]
    from base64 import urlsafe_b64decode, urlsafe_b64encode
    raw = bytearray(urlsafe_b64decode(tampered_ciphertext.encode("ascii")))
    if len(raw) > 10:
        raw[10] = raw[10] ^ 0xFF
    msg["payload"]["ciphertext"] = urlsafe_b64encode(bytes(raw)).decode("ascii")

    plain = receive_message(bob_state, msg)
    if plain is not None:
        return fail("篡改密文应解密失败")
    ok()


def test_session_expiry():
    from ratchet import SessionState, KEY_SIZE, generate_x25519_keypair_raw

    test("会话过期检测")
    state = SessionState(
        session_id=secrets.token_bytes(16),
        my_identity="alice", peer_identity="bob",
        peer_signing_pub=b"bob-pub",
        root_key=secrets.token_bytes(KEY_SIZE),
        send_chain_key=secrets.token_bytes(KEY_SIZE),
        recv_chain_key=secrets.token_bytes(KEY_SIZE),
        our_ratchet_priv=secrets.token_bytes(32),
        our_ratchet_pub=secrets.token_bytes(32),
        their_ratchet_pub=secrets.token_bytes(32),
    )
    state.last_active = time.time() - 31 * 86400
    if not state.is_expired():
        return fail("31天前应已过期")
    state.last_active = time.time()
    if state.is_expired():
        return fail("刚创建不应过期")
    ok()


def run():
    global PASSED, FAILED
    PASSED = 0
    FAILED = 0

    print("=" * 60)
    print("  zhchat 集成测试")
    print("=" * 60)

    test_kdf_chain()
    test_session_state()
    test_session_persistence()
    test_send_receive()
    test_dh_ratchet()
    test_skipped_messages()
    test_tamper_detection()
    test_session_expiry()

    print()
    print("=" * 60)
    print(f"  测试结果汇总")
    print(f"  总测试数: {PASSED + FAILED}")
    print(f"  通过: {PASSED}  PASS")
    print(f"  失败: {FAILED}")
    if FAILED == 0:
        print(f"  全部 {PASSED} 项测试通过!")
    print("=" * 60)

    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    run()
