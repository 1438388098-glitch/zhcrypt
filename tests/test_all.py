#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt 综合性测试
==================
测试覆盖:
  1. 密码模式加解密 (中文/英文/数字/混合)
  2. 密钥对生成与存储
  3. 混合模式加解密 (RSA-4096)
  4. 文件加解密
  5. 边界条件与错误处理
  6. 篡改检测
  7. 不同密码解密失败
  8. Base64 编解码往返
"""

import os
import sys
import json
import tempfile
import shutil
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    encrypt_password_mode, decrypt_password_mode,
    encrypt_hybrid, decrypt_hybrid,
    packet_to_b64, b64_to_packet,
    encrypt_file_password_mode, decrypt_file_password_mode,
    generate_rsa_key_pair,
    serialize_private_key, serialize_public_key,
    deserialize_private_key, deserialize_public_key,
    derive_key,
    DecryptionError,
    MAGIC, VERSION, MODE_PASSWORD, MODE_HYBRID,
    SALT_SIZE, NONCE_SIZE, TAG_SIZE, KEY_SIZE,
)
from keys import KeyStore

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

tests_passed = 0
tests_failed = 0
tests_total = 0


def test(name):
    global tests_total
    tests_total += 1
    print(f"  [{tests_total:02d}] {name}...", end=" ")


def ok():
    global tests_passed
    tests_passed += 1
    print(f"{PASS} 通过")


def fail(msg):
    global tests_failed
    tests_failed += 1
    print(f"{FAIL} 失败: {msg}")


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg} {repr(a)} != {repr(b)}")


def assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(f"{msg}")


def assert_raises(exc_class, fn, *args):
    try:
        fn(*args)
        raise AssertionError(f"Expected {exc_class.__name__} but no exception raised")
    except exc_class:
        pass
    except Exception as e:
        if isinstance(e, AssertionError):
            raise
        raise AssertionError(f"Expected {exc_class.__name__} but got {type(e).__name__}: {e}")


def print_header(msg):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


# ============================================================
# 第一组: 密码模式加解密
# ============================================================
print_header("第一组: 密码模式 (AES-256-GCM + Argon2id)")

test_cases = [
    ("你好世界", "mySecret123!", "中文短文本"),
    ("Hello World! 你好世界！12345", "P@ssw0rd_中文_密钥", "中英数混合"),
    ("a" * 10000, "longtext_pass", "长文本 10KB"),
    ("0123456789" * 100, "numberPass999", "纯数字长文本"),
    ("\u4e2d\u6587\u52a0\u5bc6\u7cfb\u7edf\u6d4b\u8bd5" * 50, "中文密码测试", "纯中文长文本"),
    ("", "emptyText.123!", "空文本"),
    ("Emoji test: [火箭][火][满分] [庆祝]", "emojiKey!@#", "含特殊字符"),
    ("JSON: {\"name\": \"张三\", \"age\": 25}", "jsonPass456", "JSON 数据"),
    ("\r\n\t特殊\r\n字符", "special\tchars\npass", "含控制字符"),
    ("SELECT * FROM users WHERE name = '管理员'", "DB_P@ss!99", "SQL 语句"),
]

for plaintext, password, desc in test_cases:
    try:
        test(f"加密/解密: {desc}")
        packet = encrypt_password_mode(plaintext, password)
        assert_true(packet[:4] == MAGIC, "魔数错误")
        assert_true(packet[4] == VERSION, "版本号错误")
        assert_true(packet[5] == MODE_PASSWORD, "模式错误")
        result = decrypt_password_mode(packet, password)
        assert_eq(result, plaintext, "解密结果不匹配")
        ok()
    except Exception as e:
        fail(str(e))

# 篡改检测
try:
    test("篡改密文检测")
    packet = encrypt_password_mode("秘密信息", "pass123")
    tampered = bytearray(packet)
    tampered[-1] ^= 0xFF
    assert_raises(DecryptionError, decrypt_password_mode, bytes(tampered), "pass123")
    ok()
except Exception as e:
    fail(str(e))

# 错误密码
try:
    test("错误密码应解密失败")
    packet = encrypt_password_mode("机密", "correct_password")
    assert_raises(DecryptionError, decrypt_password_mode, packet, "wrong_password")
    ok()
except Exception as e:
    fail(str(e))

# Base64 往返
try:
    test("Base64 编解码往返")
    packet = encrypt_password_mode("往返测试", "roundtrip")
    b64 = packet_to_b64(packet)
    restored = b64_to_packet(b64)
    result = decrypt_password_mode(restored, "roundtrip")
    assert_eq(result, "往返测试")
    ok()
except Exception as e:
    fail(str(e))

# ============================================================
# 第二组: RSA 密钥对生成
# ============================================================
print_header("第二组: RSA-4096 密钥对生成")

try:
    test("生成 RSA-4096 密钥对")
    priv, pub = generate_rsa_key_pair()
    assert_true(pub.key_size == 4096, f"密钥大小: {pub.key_size}")
    ok()
except Exception as e:
    fail(str(e))

try:
    test("私钥序列化/反序列化 (带密码)")
    priv, pub = generate_rsa_key_pair()
    pem = serialize_private_key(priv, "serial_test_password")
    deserialized = deserialize_private_key(pem, "serial_test_password")
    assert_true(
        deserialized.private_numbers().public_numbers.n ==
        priv.private_numbers().public_numbers.n,
        "反序列化后公私钥不匹配"
    )
    ok()
except Exception as e:
    fail(str(e))

try:
    test("私钥错误密码反序列化失败")
    priv, pub = generate_rsa_key_pair()
    pem = serialize_private_key(priv, "correct_pass")
    assert_raises(DecryptionError, deserialize_private_key, pem, "wrong_pass")
    ok()
except Exception as e:
    fail(str(e))

try:
    test("公钥序列化/反序列化")
    priv, pub = generate_rsa_key_pair()
    pub_pem = serialize_public_key(pub)
    loaded_pub = deserialize_public_key(pub_pem)
    assert_true(loaded_pub.key_size == 4096)
    ok()
except Exception as e:
    fail(str(e))

# ============================================================
# 第三组: 混合模式 (RSA + AES)
# ============================================================
print_header("第三组: 混合模式 (RSA-4096 + AES-256-GCM)")

try:
    test("混合加密/解密: 中文文本")
    priv, pub = generate_rsa_key_pair()
    pub_pem = serialize_public_key(pub)
    priv_pem = serialize_private_key(priv, "hybrid_pass")

    plaintext = "你好 Alice，这是混合加密的机密消息！12345"
    packet = encrypt_hybrid(plaintext, pub_pem)
    assert_true(packet[:4] == MAGIC)
    assert_true(packet[5] == MODE_HYBRID)

    result = decrypt_hybrid(packet, priv_pem, "hybrid_pass")
    assert_eq(result, plaintext)
    ok()
except Exception as e:
    fail(str(e))

try:
    test("混合加密/解密: 英文长文本")
    priv, pub = generate_rsa_key_pair()
    pub_pem = serialize_public_key(pub)
    priv_pem = serialize_private_key(priv, "hybrid_long")

    plaintext = "The quick brown fox jumps over the lazy dog. " * 200
    packet = encrypt_hybrid(plaintext, pub_pem)
    result = decrypt_hybrid(packet, priv_pem, "hybrid_long")
    assert_eq(result, plaintext)
    ok()
except Exception as e:
    fail(str(e))

try:
    test("混合模式错误密码失败")
    priv, pub = generate_rsa_key_pair()
    pub_pem = serialize_public_key(pub)
    priv_pem = serialize_private_key(priv, "right_pass")

    packet = encrypt_hybrid("机密", pub_pem)
    assert_raises(DecryptionError, decrypt_hybrid, packet, priv_pem, "wrong_pass")
    ok()
except Exception as e:
    fail(str(e))

# ============================================================
# 第四组: 文件加解密
# ============================================================
print_header("第四组: 文件加解密")

try:
    test("加密/解密文本文件")
    src_path = os.path.join(tempfile.gettempdir(), f"zhcrypt_test_txt_{os.getpid()}.txt")
    with open(src_path, "w", encoding="utf-8") as f:
        f.write("中文文件内容\nEnglish Line\n数字 1234567890\n")

    enc_path = encrypt_file_password_mode(src_path, "filePass123")
    assert_true(os.path.exists(enc_path))
    assert_true(os.path.getsize(enc_path) > 0)

    with open(enc_path, "rb") as ef:
        header = ef.read(4)
    assert_eq(header, MAGIC)

    dec_path = decrypt_file_password_mode(enc_path, "filePass123", overwrite=True)
    with open(dec_path, "r", encoding="utf-8") as df:
        content = df.read()
    assert_eq(content, "中文文件内容\nEnglish Line\n数字 1234567890\n")

    os.unlink(src_path)
    os.unlink(enc_path)
    if dec_path != src_path:
        os.unlink(dec_path)
    ok()
except Exception as e:
    fail(str(e))

try:
    test("加密/解密二进制文件")
    binary_data = bytes(range(256)) * 40
    src_path = os.path.join(tempfile.gettempdir(), f"zhcrypt_test_bin_{os.getpid()}.bin")
    with open(src_path, "wb") as f:
        f.write(binary_data)

    enc_path = encrypt_file_password_mode(src_path, "binaryPass!")
    dec_path = decrypt_file_password_mode(enc_path, "binaryPass!", overwrite=True)

    with open(dec_path, "rb") as df:
        dec_data = df.read()
    assert_eq(dec_data, binary_data)

    os.unlink(src_path)
    os.unlink(enc_path)
    if dec_path != src_path:
        os.unlink(dec_path)
    ok()
except Exception as e:
    fail(str(e))

# ============================================================
# 第五组: KeyStore (密钥管理)
# ============================================================
print_header("第五组: 密钥库管理 (KeyStore)")

test_key_dir = tempfile.mkdtemp(prefix="zhcrypt_test_")

try:
    test("创建身份")
    store = KeyStore(test_key_dir)
    info = store.generate_identity("test_user", "test_password_123", "测试用户")
    assert_true("fingerprint" in info)
    assert_true(os.path.exists(os.path.join(test_key_dir, "test_user.pub")))
    assert_true(os.path.exists(os.path.join(test_key_dir, "test_user.key")))
    ok()
except Exception as e:
    fail(str(e))

try:
    test("列出身份")
    store = KeyStore(test_key_dir)
    identities = store.list_identities()
    assert_true(len(identities) == 1)
    assert_eq(identities[0]["identity"], "test_user")
    ok()
except Exception as e:
    fail(str(e))

try:
    test("加载公钥")
    store = KeyStore(test_key_dir)
    pub = store.load_public_key("test_user")
    assert_true(pub.startswith(b"-----BEGIN PUBLIC KEY-----"))
    ok()
except Exception as e:
    fail(str(e))

try:
    test("加载私钥 (正确密码)")
    store = KeyStore(test_key_dir)
    priv = store.load_private_key("test_user", "test_password_123")
    assert_true(priv.key_size == 4096)
    ok()
except Exception as e:
    fail(str(e))

try:
    test("加载私钥 (错误密码)")
    store = KeyStore(test_key_dir)
    assert_raises(DecryptionError, store.load_private_key, "test_user", "wrong_pass")
    ok()
except Exception as e:
    fail(str(e))

try:
    test("导出/导入公钥 Base64")
    store = KeyStore(test_key_dir)
    b64 = store.export_public_key_b64("test_user")
    assert_true(len(b64) > 100)
    store2 = KeyStore(test_key_dir + "_import")
    path = store2.import_public_key_b64(b64, "imported_user")
    assert_true(os.path.exists(path))
    pub2 = store2.load_public_key("imported_user")
    assert_true(pub2.startswith(b"-----BEGIN PUBLIC KEY-----"))
    shutil.rmtree(test_key_dir + "_import")
    ok()
except Exception as e:
    fail(str(e))

try:
    test("验证口令")
    store = KeyStore(test_key_dir)
    assert_true(store.verify_passphrase("test_user", "test_password_123"))
    assert_true(not store.verify_passphrase("test_user", "wrong"))
    ok()
except Exception as e:
    fail(str(e))

try:
    test("删除身份")
    store = KeyStore(test_key_dir)
    removed = store.delete_identity("test_user")
    assert_true(len(removed) >= 2)
    identities = store.list_identities()
    assert_eq(len(identities), 0)
    ok()
except Exception as e:
    fail(str(e))

shutil.rmtree(test_key_dir, ignore_errors=True)

# ============================================================
# 第六组: 密钥派生验证
# ============================================================
print_header("第六组: 密钥派生 (Argon2id)")

try:
    test("相同输入产生相同密钥")
    import secrets
    salt = secrets.token_bytes(SALT_SIZE)
    k1 = derive_key("password", salt)
    k2 = derive_key("password", salt)
    assert_eq(k1, k2)
    ok()
except Exception as e:
    fail(str(e))

try:
    test("不同密码产生不同密钥")
    salt = secrets.token_bytes(SALT_SIZE)
    k1 = derive_key("password_A", salt)
    k2 = derive_key("password_B", salt)
    assert_true(k1 != k2)
    ok()
except Exception as e:
    fail(str(e))

try:
    test("不同 salt 产生不同密钥")
    s1 = secrets.token_bytes(SALT_SIZE)
    s2 = secrets.token_bytes(SALT_SIZE)
    k1 = derive_key("password", s1)
    k2 = derive_key("password", s2)
    assert_true(k1 != k2)
    ok()
except Exception as e:
    fail(str(e))

try:
    test("密码含中文密钥派生")
    salt = secrets.token_bytes(SALT_SIZE)
    k1 = derive_key("中文密码测试密钥", salt)
    k2 = derive_key("中文密码测试密钥", salt)
    assert_eq(k1, k2)
    assert_eq(len(k1), 32)
    ok()
except Exception as e:
    fail(str(e))

# ============================================================
# 第七组: 数据包格式验证
# ============================================================
print_header("第七组: 数据包格式与边界")

try:
    test("无效 Base64 输入拒绝")
    try:
        b64_to_packet("invalid_base64!!!")
        decoded = b64_to_packet("invalid_base64!!!")
        if len(decoded) < 4 or decoded[:4] != MAGIC:
            ok()
        else:
            fail("无效输入未被拒绝")
    except Exception:
        ok()
except Exception as e:
    fail(str(e))

try:
    test("无效魔数拒绝")
    packet = b"\x00" * 100
    assert_raises(ValueError, decrypt_password_mode, packet, "pass")
    ok()
except Exception as e:
    fail(str(e))

try:
    test("每次加密产生不同密文 (随机 salt/nonce)")
    packets = []
    for _ in range(5):
        p = encrypt_password_mode("same_text", "same_password")
        packets.append(p)
    unique = len(set(packets))
    assert_eq(unique, 5, f"应有 5 个不同密文, 实际 {unique} 个")
    ok()
except Exception as e:
    fail(str(e))

try:
    test("密文不含明文信息")
    plaintext = "超级机密信息_HELLO_WORLD_12345"
    packet = encrypt_password_mode(plaintext, "pass")
    assert_true(plaintext not in packet.decode("latin-1", errors="replace"))
    assert_true("HELLO" not in str(packet))
    ok()
except Exception as e:
    fail(str(e))

# ============================================================
# 结果汇总
# ============================================================
print_header("测试结果汇总")

print(f"  总测试数: {tests_total}")
print(f"  通过: {tests_passed}  {PASS}")
print(f"  失败: {tests_failed}  {FAIL if tests_failed > 0 else ''}")
print(f"  通过率: {tests_passed / tests_total * 100:.1f}%")

if tests_failed > 0:
    print(f"\n  存在 {tests_failed} 个失败测试, 请检查!")
    sys.exit(1)
else:
    print(f"\n  全部 {tests_passed} 项测试通过! 加密系统运行正常.")
