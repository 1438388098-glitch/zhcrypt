#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt 全量回归测试（X3DH + Double Ratchet + 双向通信）
覆盖：无 SPK、有 SPK、有 SPK+OTP 三种场景
"""
import sys, os, json, secrets, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    generate_x25519_key_pair, serialize_x25519_private_key,
    serialize_x25519_public_key,
    generate_ed25519_key_pair, serialize_ed25519_public_key,
)
from ratchet import (
    x3dh_initiate_session, x3dh_complete_session,
    complete_session_first_message, send_message, receive_message,
    pem_priv_to_raw, _b64, _b64d, KEY_SIZE,
)
from session import save_session, load_session, delete_session

PASS = 0
FAIL = 0

def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label} {detail}")
    return condition

def make_inner(text="test"):
    return json.dumps({"text": text, "signature": ""}, ensure_ascii=False).encode("utf-8")

def test_x3dh_scenario(spk, otp):
    label = f"X3DH(SPK={spk}, OTP={otp})"
    # Alice keys
    a_id_priv, a_id_pub = generate_x25519_key_pair()
    a_id_priv_raw = pem_priv_to_raw(serialize_x25519_private_key(a_id_priv))
    # Bob keys
    b_id_priv, b_id_pub = generate_x25519_key_pair()
    b_id_priv_raw = pem_priv_to_raw(serialize_x25519_private_key(b_id_priv))
    b_id_pub_raw = serialize_x25519_public_key(b_id_pub)
    _, b_sign = generate_ed25519_key_pair()
    b_sign_pem = serialize_ed25519_public_key(b_sign)

    if spk:
        b_spk_priv, b_spk_pub = generate_x25519_key_pair()
        b_spk_priv_raw = pem_priv_to_raw(serialize_x25519_private_key(b_spk_priv))
        b_spk_pub_pem = serialize_x25519_public_key(b_spk_pub)
    else:
        b_spk_priv_raw = b_id_priv_raw
        b_spk_pub_pem = b_id_pub_raw

    if otp and spk:
        b_otp_priv, b_otp_pub = generate_x25519_key_pair()
        b_otp_priv_raw = pem_priv_to_raw(serialize_x25519_private_key(b_otp_priv))
        b_otp_b64 = _b64(serialize_x25519_public_key(b_otp_pub))
    else:
        b_otp_priv_raw = None
        b_otp_b64 = None

    # Alice init
    st_a, extra = x3dh_initiate_session(
        peer_identity_key_pub_pem=b_id_pub_raw,
        peer_signed_prekey_pub_pem=b_spk_pub_pem,
        peer_one_time_prekey_pub_b64=b_otp_b64,
        my_identity_priv_raw=a_id_priv_raw,
        my_identity="alice", peer_identity="bob",
        peer_signing_pub_pem=b_sign_pem,
    )

    # Bob complete
    st_b = x3dh_complete_session(
        my_identity_priv_raw=b_id_priv_raw,
        my_signed_prekey_priv_raw=b_spk_priv_raw,
        sender_identity_pub_raw=_b64d(extra["sender_identity_pub"]),
        sender_ephemeral_pub_raw=_b64d(extra["sender_ephemeral_pub"]),
        sender_ratchet_pub_raw=st_a.our_ratchet_pub,
        sender_signing_pub_pem=b_sign_pem,
        my_identity="bob", sender_identity="alice",
        one_time_prekey_priv_raw=b_otp_priv_raw,
        session_id=st_a.session_id,
    )

    if not check(f"{label} root_key match", st_a.root_key == st_b.root_key):
        return False

    msg = send_message(st_a, make_inner("hello"))
    plain = complete_session_first_message(
        st_b, st_a.our_ratchet_pub,
        msg["payload"]["nonce"], msg["payload"]["ciphertext"], b"",
    )
    if not check(f"{label} first msg decrypt", plain is not None):
        return False
    check(f"{label} plaintext", json.loads(plain.decode("utf-8"))["text"] == "hello")

    # Bidirectional exchange
    st_b.their_ratchet_pub = st_a.our_ratchet_pub
    # Bob reply (x3dh_reply)
    msg2 = send_message(st_b, make_inner("reply"))
    msg2["type"] = "x3dh_reply"
    plain2 = receive_message(st_a, msg2)
    check(f"{label} bob reply decrypt", plain2 is not None)

    # Simulate real chat_client flow: save after each step, then reload
    save_session(st_a, "testpass")
    save_session(st_b, "testpass")

    loaded_a = load_session("alice", "bob", "testpass")
    loaded_b = load_session("bob", "alice", "testpass")
    check(f"{label} save/load roundtrip", loaded_a is not None and loaded_b is not None)

    # Alice sends msg2 after reload (this is where the bug was: send_chain_key overwritten)
    loaded_a.their_ratchet_pub = loaded_b.our_ratchet_pub
    msg3 = send_message(loaded_a, make_inner("msg2_after_reload"))
    plain3 = receive_message(loaded_b, msg3)
    check(f"{label} alice msg2 after reload", plain3 is not None,
          "(send_chain_key overwritten bug)" if plain3 is None else "")

    # Bob replies after reload
    loaded_b.their_ratchet_pub = loaded_a.our_ratchet_pub
    msg4 = send_message(loaded_b, make_inner("reply2_after_reload"))
    plain4 = receive_message(loaded_a, msg4)
    check(f"{label} bob reply2 after reload", plain4 is not None)

    delete_session("alice", "bob")
    delete_session("bob", "alice")
    return True

def test_session_persistence_with_x3dh():
    print("\n--- 会话持久化 + X3DH ---")
    a_id_priv, a_id_pub = generate_x25519_key_pair()
    a_id_priv_raw = pem_priv_to_raw(serialize_x25519_private_key(a_id_priv))
    b_id_priv, b_id_pub = generate_x25519_key_pair()
    b_id_priv_raw = pem_priv_to_raw(serialize_x25519_private_key(b_id_priv))
    b_id_pub_raw = serialize_x25519_public_key(b_id_pub)
    _, b_sign = generate_ed25519_key_pair()
    b_sign_pem = serialize_ed25519_public_key(b_sign)

    st_a, extra = x3dh_initiate_session(
        peer_identity_key_pub_pem=b_id_pub_raw,
        peer_signed_prekey_pub_pem=b_id_pub_raw,
        peer_one_time_prekey_pub_b64=None,
        my_identity_priv_raw=a_id_priv_raw,
        my_identity="alice", peer_identity="bob",
        peer_signing_pub_pem=b_sign_pem,
    )

    st_b = x3dh_complete_session(
        my_identity_priv_raw=b_id_priv_raw,
        my_signed_prekey_priv_raw=b_id_priv_raw,
        sender_identity_pub_raw=_b64d(extra["sender_identity_pub"]),
        sender_ephemeral_pub_raw=_b64d(extra["sender_ephemeral_pub"]),
        sender_ratchet_pub_raw=st_a.our_ratchet_pub,
        sender_signing_pub_pem=b_sign_pem,
        my_identity="bob", sender_identity="alice",
        one_time_prekey_priv_raw=None,
        session_id=st_a.session_id,
    )

    # Simulate first message exchange
    msg = send_message(st_a, make_inner("hello"))
    plain = complete_session_first_message(
        st_b, st_a.our_ratchet_pub,
        msg["payload"]["nonce"], msg["payload"]["ciphertext"], b"",
    )
    check("first msg decrypt before save", plain is not None)

    # Simulate save/load
    save_session(st_a, "testpass")
    save_session(st_b, "testpass")
    loaded_a = load_session("alice", "bob", "testpass")
    loaded_b = load_session("bob", "alice", "testpass")

    check("load session alice", loaded_a is not None and loaded_a.root_key == st_a.root_key)
    check("load session bob", loaded_b is not None and loaded_b.root_key == st_b.root_key)

    # Send after reload
    loaded_a.their_ratchet_pub = loaded_b.our_ratchet_pub
    loaded_b.their_ratchet_pub = loaded_a.our_ratchet_pub

    msg2 = send_message(loaded_a, make_inner("after reload"))
    plain2 = receive_message(loaded_b, msg2)
    check("msg after reload", plain2 is not None)

    delete_session("alice", "bob")
    delete_session("bob", "alice")

def run():
    global PASS, FAIL
    PASS = FAIL = 0
    print("=" * 60)
    print("  zhcrypt 全量回归测试")
    print("=" * 60)

    test_x3dh_scenario(spk=False, otp=False)
    test_x3dh_scenario(spk=True, otp=False)
    test_x3dh_scenario(spk=True, otp=True)
    test_session_persistence_with_x3dh()

    print()
    print("=" * 60)
    print(f"  通过: {PASS}  |  失败: {FAIL}")
    if FAIL == 0:
        print("  全部测试通过！")
    else:
        print(f"  有 {FAIL} 项失败")
    print("=" * 60)

    if FAIL > 0:
        sys.exit(1)

if __name__ == "__main__":
    run()
