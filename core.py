"""
zhcrypt 核心密码学模块
======================
混合加密系统：Argon2id 密钥派生 + AES-256-GCM 对称加密 + RSA-4096 非对称加密
支持中文、英文、数字及所有 UTF-8 字符

安全特性：
  - Argon2id (RFC 9106 推荐参数): 内存硬化, 抗 GPU/ASIC 攻击
  - AES-256-GCM: 认证加密 (AEAD), 防篡改
  - RSA-4096-OAEP-SHA512: 量子前安全, 最优非对称填充
  - 每次加密使用随机 salt/nonce, 防彩虹表与重放攻击
  - 常数时间 HMAC 比对, 防时序侧信道
"""

import os
import struct
import hashlib
import hmac
import secrets
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from argon2.low_level import hash_secret_raw, Type

__version__ = "3.2.0"

MAGIC = b"ZHCR"
VERSION = 1
VERSION_V2 = 2
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32

MODE_PASSWORD = 0x01
MODE_HYBRID = 0x02
MODE_HYBRID_SIGNED = 0x03
MODE_HYBRID_PFS = 0x04
MODE_FILE_STREAM = 0x05

FLAG_HAS_SIGNATURE = 1
CHUNK_SIZE_DEFAULT = 65536
MODE_DENIABLE = 0x06

ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 256 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = KEY_SIZE

RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537


def _secure_compare(a: bytes, b: bytes) -> bool:
    """常数时间比较, 防止时序攻击"""
    return hmac.compare_digest(a, b)


def _clear_bytes(data: bytearray):
    """安全清除内存中的敏感数据"""
    data[:] = b"\x00" * len(data)


# R6: CLI(64KiB) 与 GUI(10MB) 曾各用一套流式阈值且互不一致, 统一由
# should_stream 决策; 可经 config streaming.threshold_bytes 覆盖。
STREAM_THRESHOLD_DEFAULT = 64 * 1024


def should_stream(size_bytes: int) -> bool:
    """文件加解密是否走流式分块路径 (R6: CLI/GUI 统一决策入口)。

    3.1.x 起文件密码模式本身也产出流式格式, 阈值主要影响分块大小与
    内存占用; 预留配置接入点 (streaming.threshold_bytes, 最低 1KiB)。
    """
    try:
        from config import get
        # R8: streaming.enabled 总开关 (原为无消费者的死配置键, 现接线)
        if not get("streaming.enabled", True):
            return False
        threshold = int(get("streaming.threshold_bytes", STREAM_THRESHOLD_DEFAULT))
    except Exception:
        threshold = STREAM_THRESHOLD_DEFAULT
    return size_bytes >= max(1024, threshold)


def _get_argon2_params():
    """从配置文件读取 Argon2id 参数 (如果可用)

    安全钳制与 derive_key 完全一致 (time ∈ [1,16]、memory ∈ [8MiB,2GiB]、
    parallelism ∈ [1,16]、memory×parallelism ≤ 2GiB)。加密端必须把解密端
    (derive_key) 会采用的参数写进密文头, 两端钳制规则漂移会导致配置越界时
    写出的密文在解密端按默认参数派生而永远解不开 (R1 修复, 原 time 上限 100
    且无 parallelism/乘积钳制)。
    """
    tc, mc, pl = ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM
    try:
        from config import load
        cfg = load()
        a = cfg.get("argon2id", {})
        tc = int(a.get("time_cost", tc))
        mc = int(a.get("memory_cost", mc))
        pl = int(a.get("parallelism", pl))
    except Exception:
        pass
    try:
        if not (1 <= tc <= 16):
            tc = ARGON2_TIME_COST
        if not (8 * 1024 <= mc <= 2 * 1024 * 1024):
            mc = ARGON2_MEMORY_COST
        if not (1 <= pl <= 16):
            pl = ARGON2_PARALLELISM
        max_total = 2 * 1024 * 1024  # 2 GiB (单位 KiB)
        if mc * pl > max_total:
            pl = max(1, max_total // mc)
    except (TypeError, ValueError):
        tc = ARGON2_TIME_COST
        mc = ARGON2_MEMORY_COST
        pl = ARGON2_PARALLELISM
    return (tc, mc, pl)


def derive_key(password: str, salt: bytes,
               time_cost: int = ARGON2_TIME_COST,
               memory_cost: int = ARGON2_MEMORY_COST,
               parallelism: int = ARGON2_PARALLELISM,
               hash_len: int = ARGON2_HASH_LEN) -> bytes:
    """
    使用 Argon2id 从密码派生 AES-256 密钥

    Argon2id 参数选择依据 RFC 9106:
      - time_cost=4:    迭代轮数, 平衡安全与性能
      - memory_cost=256MB: 内存成本, 抗 GPU 暴力破解
      - parallelism=4:  并行度, 匹配现代 CPU 核心数

    Args:
        password: 用户密码 (支持中文/英文/任意 Unicode)
        salt: 随机盐值 (32 字节)
        time_cost: 时间成本
        memory_cost: 内存成本 (KB)
        parallelism: 并行度
        hash_len: 输出密钥长度

    Returns:
        bytes: 派生的 256 位密钥
    """
    # 安全钳制 (红队模拟发现: 密文头参数可被伪造为极大值导致派生无限卡死):
    # 解密路径的参数来自密文包头, 攻击者翻转字节即可构造 time_cost=2^32 级
    # 的派生请求, 单次派生需数月/数十年, 形成 CPU DoS。这里统一钳制:
    #   time_cost    ∈ [1, 16]     (超过 16 轮无现实意义, 按默认回退)
    #   memory_cost  ∈ [8 MiB, 2 GiB]
    #   parallelism  ∈ [1, 16]
    # 钳制后若与加密时参数不一致, 解密将正常失败 (拒绝), 而非卡死。
    try:
        if not (1 <= int(time_cost) <= 16):
            time_cost = ARGON2_TIME_COST
        if not (8 * 1024 <= int(memory_cost) <= 2 * 1024 * 1024):
            memory_cost = ARGON2_MEMORY_COST
        if not (1 <= int(parallelism) <= 16):
            parallelism = ARGON2_PARALLELISM
    except (TypeError, ValueError):
        time_cost = ARGON2_TIME_COST
        memory_cost = ARGON2_MEMORY_COST
        parallelism = ARGON2_PARALLELISM

    # 乘积钳制 (审计 HIGH-4): Argon2 总内存 = memory_cost × parallelism。
    # 单项钳制不足以防止 memory=2GiB × parallelism=16 = 32GiB 的内存耗尽 DoS。
    # 限制总内存 ≤ 2GiB, 超出时按 memory 优先缩减 parallelism (最低 1)。
    try:
        max_total = 2 * 1024 * 1024  # 2 GiB (单位 KiB)
        if int(memory_cost) * int(parallelism) > max_total:
            parallelism = max(1, max_total // int(memory_cost))
    except (TypeError, ValueError):
        pass

    password_bytes = password.encode("utf-8")
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
        version=19,
    )
    return key


def encrypt_password_mode(plaintext: str, password: str,
                          time_cost: int = None,
                          memory_cost: int = None,
                          parallelism: int = None) -> bytes:
    cfg_tc, cfg_mc, cfg_pl = _get_argon2_params()
    if time_cost is None:
        time_cost = cfg_tc
    if memory_cost is None:
        memory_cost = cfg_mc
    if parallelism is None:
        parallelism = cfg_pl
    """
    密码模式加密 (对称加密, 仅需密码)

    加密流程:
      1. 生成 32 字节随机 salt
      2. Argon2id 派生 256 位密钥
      3. 生成 12 字节随机 nonce
      4. AES-256-GCM 加密明文
      5. 构造输出包: MAGIC|VERSION|MODE|PARAMS|SALT|NONCE|CIPHERTEXT|TAG

    Args:
        plaintext: 明文字符串 (支持中文等 Unicode)
        password: 用户密码
        time_cost: Argon2 时间成本
        memory_cost: Argon2 内存成本
        parallelism: Argon2 并行度

    Returns:
        bytes: 加密后的二进制数据包
    """
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt, time_cost, memory_cost, parallelism, KEY_SIZE)

    nonce = secrets.token_bytes(NONCE_SIZE)
    plaintext_bytes = plaintext.encode("utf-8")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    params = struct.pack(">III", time_cost, memory_cost, parallelism)

    packet = bytearray()
    packet.extend(MAGIC)
    packet.append(VERSION)
    packet.append(MODE_PASSWORD)
    packet.extend(params)
    packet.extend(salt)
    packet.extend(nonce)
    packet.extend(ciphertext)

    key_bytes = bytearray(key)
    _clear_bytes(key_bytes)

    return bytes(packet)


def decrypt_password_mode(packet: bytes, password: str) -> str:
    """
    密码模式解密

    解密流程:
      1. 解析包头: MAGIC|VERSION|MODE|PARAMS|SALT|NONCE|CIPHERTEXT(含TAG)
      2. 验证魔数和版本
      3. Argon2id 重新派生密钥
      4. AES-256-GCM 解密并验证认证标签
      5. 解密失败则抛出异常

    Args:
        packet: 加密数据包
        password: 用户密码

    Returns:
        str: 解密后的明文字符串

    Raises:
        ValueError: 数据包格式错误
        DecryptionError: 密码错误或数据被篡改
    """
    if len(packet) < 4:
        raise ValueError("数据包太短, 不是有效的 zhcrypt 格式")

    magic = packet[:4]
    if magic != MAGIC:
        raise ValueError("无效的魔数, 不是 zhcrypt 加密数据")

    version = packet[4]
    if version != VERSION:
        raise ValueError(f"不支持的版本: {version}")

    mode = packet[5]
    if mode != MODE_PASSWORD:
        raise ValueError(f"数据包不是密码模式 (mode={mode}), 请使用对应的解密方法")

    offset = 6
    # R7: 截断包防护 —— params(12) 的 struct.unpack 需要完整头部
    if len(packet) < offset + 12 + SALT_SIZE + NONCE_SIZE:
        raise ValueError("数据包过短或已损坏")
    params_end = offset + 12
    time_cost, memory_cost, parallelism = struct.unpack(">III", packet[offset:params_end])

    offset = params_end
    salt = packet[offset:offset + SALT_SIZE]

    offset += SALT_SIZE
    nonce = packet[offset:offset + NONCE_SIZE]

    offset += NONCE_SIZE
    ciphertext_with_tag = packet[offset:]

    if len(ciphertext_with_tag) < TAG_SIZE:
        raise ValueError("密文数据不完整")

    key = derive_key(password, salt, time_cost, memory_cost, parallelism, KEY_SIZE)

    try:
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        key_bytes = bytearray(key)
        _clear_bytes(key_bytes)
        raise DecryptionError("解密失败: 密码错误或数据已被篡改")

    key_bytes = bytearray(key)
    _clear_bytes(key_bytes)

    return plaintext_bytes.decode("utf-8")


def generate_rsa_key_pair():
    """
    生成 RSA-4096 密钥对

    Returns:
        tuple: (private_key, public_key) cryptography 密钥对象
    """
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key, passphrase: str) -> bytes:
    """
    将 RSA 私钥序列化为 PEM 格式并用密码加密

    Args:
        private_key: RSA 私钥对象
        passphrase: 保护私钥的密码

    Returns:
        bytes: 加密后的 PEM 格式私钥
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    )


def serialize_private_key_raw(private_key) -> bytes:
    """序列化 RSA 私钥为 PEM (无密码封装, 供外层 Argon2id 加密场景使用)"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem_data: bytes, passphrase: str):
    """
    从加密的 PEM 数据加载 RSA 私钥

    Args:
        pem_data: 加密的 PEM 格式私钥
        passphrase: 私钥密码

    Returns:
        RSA 私钥对象

    Raises:
        DecryptionError: 密码错误
    """
    try:
        return serialization.load_pem_private_key(
            pem_data,
            password=passphrase.encode("utf-8") if passphrase else None,
            backend=default_backend(),
        )
    except Exception:
        try:
            return serialization.load_pem_private_key(
                pem_data, password=None, backend=default_backend(),
            )
        except (ValueError, TypeError) as e:
            raise DecryptionError(f"私钥解密失败: 密码错误或密钥文件损坏 ({e})")


def serialize_public_key(public_key) -> bytes:
    """将 RSA 公钥序列化为 PEM 格式"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_data: bytes):
    """从 PEM 数据加载 RSA 公钥"""
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend(),
    )


def encrypt_hybrid(plaintext: str, public_key_pem: bytes) -> bytes:
    """
    混合加密模式 (RSA + AES)
    适用于安全共享: 发送方使用接收方的公钥加密

    加密流程:
      1. 生成随机 256-bit 数据加密密钥 (DEK)
      2. 用 RSA-4096-OAEP-SHA512 加密 DEK
      3. 用 AES-256-GCM + DEK 加密明文
      4. 输出: MAGIC|VERSION|MODE_HYBRID|ENC_DEK|NONCE|CIPHERTEXT|TAG

    Args:
        plaintext: 明文字符串
        public_key_pem: 接收方 PEM 格式公钥

    Returns:
        bytes: 加密后的数据包
    """
    public_key = deserialize_public_key(public_key_pem)
    dek = secrets.token_bytes(KEY_SIZE)

    encrypted_dek = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None,
        ),
    )

    nonce = secrets.token_bytes(NONCE_SIZE)
    plaintext_bytes = plaintext.encode("utf-8")

    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    packet = bytearray()
    packet.extend(MAGIC)
    packet.append(VERSION)
    packet.append(MODE_HYBRID)
    packet.extend(struct.pack(">H", len(encrypted_dek)))
    packet.extend(encrypted_dek)
    packet.extend(nonce)
    packet.extend(ciphertext)

    dek_bytes = bytearray(dek)
    _clear_bytes(dek_bytes)

    return bytes(packet)


def decrypt_hybrid(packet: bytes, private_key_pem: bytes,
                   private_key_passphrase: str) -> str:
    """
    混合模式解密

    解密流程:
      1. 解析包头
      2. 用私钥密码解密 RSA 私钥
      3. 用 RSA 私钥解密 DEK
      4. 用 AES-256-GCM + DEK 解密密文

    Args:
        packet: 加密数据包
        private_key_pem: PEM 格式加密私钥
        private_key_passphrase: 私钥密码

    Returns:
        str: 解密后的明文
    """
    if len(packet) < 4:
        raise ValueError("数据包太短")

    if packet[:4] != MAGIC:
        raise ValueError("无效的魔数")

    if packet[4] != VERSION:
        raise ValueError(f"不支持的版本: {packet[4]}")

    mode = packet[5]
    if mode != MODE_HYBRID:
        raise ValueError("数据包不是混合模式")

    # R7: 截断包防护 —— enc_dek_len 的 unpack 需要 ≥8 字节
    if len(packet) < 8:
        raise ValueError("数据包过短或已损坏")

    offset = 6
    enc_dek_len = struct.unpack(">H", packet[offset:offset + 2])[0]
    offset += 2
    encrypted_dek = packet[offset:offset + enc_dek_len]
    offset += enc_dek_len
    nonce = packet[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext_with_tag = packet[offset:]

    private_key = deserialize_private_key(private_key_pem, private_key_passphrase)

    try:
        dek = private_key.decrypt(
            encrypted_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        )
    except (ValueError, TypeError) as e:
        raise DecryptionError(f"DEK 解密失败: 私钥或密码错误 ({e})")

    try:
        aesgcm = AESGCM(dek)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        dek_bytes = bytearray(dek)
        _clear_bytes(dek_bytes)
        raise DecryptionError("解密失败: 密文已损坏或被篡改")

    dek_bytes = bytearray(dek)
    _clear_bytes(dek_bytes)

    return plaintext_bytes.decode("utf-8")


def packet_to_b64(packet: bytes) -> str:
    """将二进制加密包转为 URL-safe Base64 字符串"""
    return urlsafe_b64encode(packet).decode("ascii")


def b64_to_packet(b64_string: str) -> bytes:
    """将 URL-safe Base64 字符串还原为二进制加密包。

    R7: 剪贴板/消息复制常夹带换行与首尾空白, 先剥离再解码;
    非法字符时抛出带指引的 ValueError (原先为晦涩的 binascii.Error)。
    """
    b64_string = "".join(b64_string.split())
    try:
        b64_string.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise ValueError("密文含非法字符: 只接受 Base64 (URL-safe) 字符")
    padding = 4 - len(b64_string) % 4
    if padding != 4:
        b64_string += "=" * padding
    return urlsafe_b64decode(b64_string.encode("ascii"))


def encrypt_file_password_mode(filepath: str, password: str, output_path: str = None):
    """密码模式加密文件 (R3: 委托流式实现, 大文件不再整读内存)。

    3.1.0 及之前产出单块 MODE_PASSWORD(0x01) 格式, 整文件读入内存, 大文件
    会内存耗尽; 现改产 MODE_FILE_STREAM(0x05) 流式格式, 内存占用 ≈ 单块
    (默认 64KiB)。输出文件名约定不变 (默认 <name>.zhe);
    decrypt_file_password_mode 按头部 mode 自动分派, 新旧格式均可解。
    注意: 旧版程序无法识别新格式 (仅保证向前兼容旧文件)。
    """
    if output_path is None:
        output_path = filepath + ".zhe"
    return encrypt_file_stream(filepath, password, output_path=output_path)


def decrypt_file_password_mode(filepath: str, password: str, output_path: str = None,
                               overwrite: bool = False):
    """密码模式解密文件 (R3: 按头部 mode 自动分派新旧格式)"""
    with open(filepath, "rb") as f:
        header = f.read(8)

    if len(header) >= 6 and header[:4] == MAGIC and header[5] == MODE_FILE_STREAM:
        # 新格式: 流式解密; 输出名沿用密码模式的命名约定
        if output_path is None:
            if filepath.endswith(".zhe"):
                output_path = filepath[:-4]
            else:
                output_path = filepath + ".dec"
        return decrypt_file_stream(filepath, password, output_path=output_path,
                                   overwrite=overwrite)

    if header[:4] != MAGIC:
        raise ValueError("不是 zhcrypt 加密文件")

    mode = header[5]
    if mode != MODE_PASSWORD:
        raise ValueError("文件不是密码模式加密")

    with open(filepath, "rb") as f:
        packet = f.read()

    offset = 6
    # R7: 截断包防护 —— 完整定长头为 params(12)+salt(32)+nonce(12),
    # 短包会让 struct.unpack 抛 struct.error 逃过调用方的 ValueError 捕获。
    if len(packet) < offset + 12 + SALT_SIZE + NONCE_SIZE:
        raise ValueError("数据包过短或已损坏")
    params_end = offset + 12
    time_cost, memory_cost, parallelism = struct.unpack(">III", packet[offset:params_end])
    offset = params_end
    salt = packet[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = packet[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext_with_tag = packet[offset:]

    key = derive_key(password, salt, time_cost, memory_cost, parallelism, KEY_SIZE)

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        key_bytes = bytearray(key)
        _clear_bytes(key_bytes)
        raise DecryptionError("解密失败: 密码错误或文件已损坏")

    key_bytes = bytearray(key)
    _clear_bytes(key_bytes)

    if output_path is None:
        if filepath.endswith(".zhe"):
            output_path = filepath[:-4]
        else:
            output_path = filepath + ".dec"

    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError(f"输出文件 {output_path} 已存在, 使用 --overwrite 覆盖")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return output_path


# ============================================================
# Ed25519 数字签名
# ============================================================

def generate_ed25519_key_pair():
    """生成 Ed25519 签名密钥对"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_ed25519_private_key(private_key) -> bytes:
    """序列化 Ed25519 私钥为 PEM"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_ed25519_public_key(public_key) -> bytes:
    """序列化 Ed25519 公钥为 PEM"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_ed25519_private_key(pem_data: bytes):
    """从 PEM 加载 Ed25519 私钥"""
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())


def deserialize_ed25519_public_key(pem_data: bytes):
    """从 PEM 加载 Ed25519 公钥"""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def ed25519_sign(private_key_pem: bytes, message: bytes) -> bytes:
    """用 Ed25519 私钥签名消息"""
    private_key = deserialize_ed25519_private_key(private_key_pem)
    return private_key.sign(message)


def ed25519_verify(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
    """验证 Ed25519 签名, 返回 True/False"""
    try:
        public_key = deserialize_ed25519_public_key(public_key_pem)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


# ============================================================
# X25519 密钥交换 (ECDH)
# ============================================================

def generate_x25519_key_pair():
    """生成 X25519 密钥交换密钥对"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_x25519_private_key(private_key) -> bytes:
    """序列化 X25519 私钥为 PKCS8 PEM"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_x25519_public_key(public_key) -> bytes:
    """序列化 X25519 公钥为 SubjectPublicKeyInfo PEM"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_x25519_private_key(pem_data: bytes):
    """从 PEM 加载 X25519 私钥"""
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())


def deserialize_x25519_public_key(pem_data: bytes):
    """从 PEM 加载 X25519 公钥"""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def x25519_ecdh(private_key_pem: bytes, public_key_pem: bytes) -> bytes:
    """
    X25519 ECDH 密钥交换
    返回 32 字节共享秘密
    """
    private_key = deserialize_x25519_private_key(private_key_pem)
    public_key = deserialize_x25519_public_key(public_key_pem)
    shared = private_key.exchange(public_key)
    # 低阶点/恶意公钥防护 (审计 M7): 共享秘密全零意味着对端公钥为低阶点,
    # 会使 ECDH 结果落入可枚举小集合。RFC 7748 §6.1 要求拒绝。
    if shared == b"\x00" * 32:
        raise ValueError("X25519 共享秘密为全零 (低阶点/恶意公钥)")
    return shared


def _x25519_exchange_checked(private_key, public_key) -> bytes:
    """对象级 X25519 ECDH, 拒绝全零共享秘密 (低阶点公钥)。

    供内部已持有密钥对象的路径 (如 decrypt_pfs) 复用, 与 x25519_ecdh 的
    PEM 级防护保持同一策略 (审计 M7 补齐, R2)。
    """
    shared = private_key.exchange(public_key)
    if not shared or shared == b"\x00" * 32:
        raise ValueError("X25519 共享秘密为全零 (低阶点/恶意公钥)")
    return shared


# R3 清理: 删除无任何调用方的 x3dh_shared_secret (core 旧版 X3DH, salt=-v1,
# DH 组合与聊天实际使用的 ratchet.x3dh_* -v2 不一致, 属易误用的双轨死代码)。
# 聊天协议的 X3DH 见 ratchet.py x3dh_initiate_session / x3dh_complete_session。


# ============================================================
# 签名混合模式 (MODE_HYBRID_SIGNED = 0x03)
# ============================================================

def encrypt_hybrid_signed(
    plaintext: str,
    receiver_pub_pem: bytes,
    sender_signing_priv_pem: bytes,
    sender_identity: str,
) -> bytes:
    """
    带 Ed25519 签名的混合加密 (Sign-then-Encrypt)

    流程:
      1. 构造签名体: sender_identity || timestamp || plaintext
      2. 用 Ed25519 私钥签名
      3. 构造明文: sender_identity || timestamp || plaintext || signature
      4. 用 RSA-4096 (接收方公钥) 包裹 AES 密钥 → 加密

    包格式:
      MAGIC(4) | VERSION(1) | MODE_HYBRID_SIGNED(1) | FLAGS(1) |
      ENC_DEK_LEN(2) | ENC_DEK(var) | NONCE(12) | CIPHERTEXT+TAG(var)
    """
    timestamp = struct.pack(">Q", int(time.time()))
    sender_bytes = sender_identity.encode("utf-8")
    sender_len = struct.pack(">H", len(sender_bytes))
    plaintext_bytes = plaintext.encode("utf-8")

    sig_body = sender_bytes + timestamp + plaintext_bytes
    sig = ed25519_sign(sender_signing_priv_pem, sig_body)

    inner = sender_len + sender_bytes + timestamp + plaintext_bytes + \
            struct.pack(">H", len(sig)) + sig

    public_key = deserialize_public_key(receiver_pub_pem)
    dek = secrets.token_bytes(KEY_SIZE)

    encrypted_dek = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None,
        ),
    )

    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, inner, None)

    packet = bytearray()
    packet.extend(MAGIC)
    packet.append(VERSION_V2)
    packet.append(MODE_HYBRID_SIGNED)
    packet.append(FLAG_HAS_SIGNATURE)
    packet.extend(struct.pack(">H", len(encrypted_dek)))
    packet.extend(encrypted_dek)
    packet.extend(nonce)
    packet.extend(ciphertext)

    dek_bytes = bytearray(dek)
    _clear_bytes(dek_bytes)

    return bytes(packet)


def decrypt_hybrid_signed(
    packet: bytes,
    receiver_priv_pem: bytes,
    receiver_passphrase: str,
    expected_sender_identity: str = None,
    sender_signing_pub_pem: bytes = None,
) -> dict:
    """
    带签名验证的混合解密 (Decrypt-then-Verify)

    返回:
      {"plaintext": str, "sender": str, "verified": bool, "timestamp": int}
    """
    if len(packet) < 4:
        raise ValueError("数据包太短")
    if packet[:4] != MAGIC:
        raise ValueError("无效魔数")
    if packet[4] != VERSION_V2:
        raise ValueError(f"不支持的版本: {packet[4]}")
    if packet[5] != MODE_HYBRID_SIGNED:
        raise ValueError("不是签名混合模式")

    # R7: flags = packet[6] 与后续 unpack 需要完整头部, 截断包统一 ValueError
    if len(packet) < 9:
        raise ValueError("数据包过短或已损坏")

    flags = packet[6]
    has_sig = bool(flags & FLAG_HAS_SIGNATURE)

    # R7: 截断包防护 —— enc_dek_len 的 unpack 需要 ≥9 字节
    if len(packet) < 9:
        raise ValueError("数据包过短或已损坏")
    offset = 7
    enc_dek_len = struct.unpack(">H", packet[offset:offset + 2])[0]
    offset += 2
    encrypted_dek = packet[offset:offset + enc_dek_len]
    offset += enc_dek_len
    nonce = packet[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext_with_tag = packet[offset:]

    private_key = deserialize_private_key(receiver_priv_pem, receiver_passphrase)

    try:
        dek = private_key.decrypt(
            encrypted_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        )
    except (ValueError, TypeError) as e:
        raise DecryptionError(f"DEK 解密失败: 私钥或密码错误 ({e})")

    try:
        aesgcm = AESGCM(dek)
        inner = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        raise DecryptionError("解密失败: 密文已损坏或被篡改")

    try:
        offset = 0
        sender_len = struct.unpack(">H", inner[offset:offset + 2])[0]
        offset += 2
        sender = inner[offset:offset + sender_len].decode("utf-8")
        offset += sender_len
        ts = struct.unpack(">Q", inner[offset:offset + 8])[0]
        offset += 8
    except (struct.error, UnicodeDecodeError, IndexError):
        raise DecryptionError("解密失败: 明文结构损坏")

    if not has_sig:
        try:
            plaintext = inner[offset:].decode("utf-8")
        except UnicodeDecodeError:
            raise DecryptionError("解密失败: 明文结构损坏")
        return {"plaintext": plaintext, "sender": sender, "verified": False, "timestamp": ts}

    # R2 加固: Ed25519 签名恒 64 字节, 尾部布局固定为 sig_len(2)|sig(64)。
    # 恶意 sig_len 会使切片错位 (把密文尾部拼进明文且绕过校验语义), 直接拒绝。
    if len(inner) < offset + 66:
        raise DecryptionError("解密失败: 明文结构损坏")
    sig_len = struct.unpack(">H", inner[-66:-64])[0]
    if sig_len != 64:
        raise DecryptionError("解密失败: 签名字段长度非法")
    sig = inner[-sig_len:]
    plaintext_bytes = inner[offset:-sig_len - 2]
    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("解密失败: 明文结构损坏")

    sig_body = sender.encode("utf-8") + struct.pack(">Q", ts) + plaintext_bytes

    verified = False
    if sender_signing_pub_pem is not None:
        try:
            verified = ed25519_verify(sender_signing_pub_pem, sig_body, sig)
        except Exception:
            verified = False

    return {"plaintext": plaintext, "sender": sender, "verified": verified, "timestamp": ts}


# ============================================================
# X3DH PFS 模式 (MODE_HYBRID_PFS = 0x04)
# ============================================================

def encrypt_pfs(
    plaintext: str,
    receiver_identity_pub_pem: bytes,
    receiver_signed_prekey_pub_pem: bytes,
    sender_longterm_priv_pem: bytes,
    sender_signing_priv_pem: bytes,
    sender_identity: str,
) -> bytes:
    """
    X3DH PFS 加密 (双 ECDH, 前向安全)

    包格式:
      MAGIC(4) | VERSION_V2(1) | MODE_HYBRID_PFS(1) | FLAGS(1) |
      SENDER_ID_LEN(2) | SENDER_ID(var) |
      SENDER_ID_PUB_RAW(32) | SENDER_EPH_PUB_RAW(32) |
      NONCE(12) | CIPHERTEXT+TAG(var)
    """
    sender_eph_priv, sender_eph_pub = generate_x25519_key_pair()
    sender_eph_priv_pem = serialize_x25519_private_key(sender_eph_priv)

    sender_longterm_pub = deserialize_x25519_private_key(sender_longterm_priv_pem).public_key()
    sender_id_pub_raw = sender_longterm_pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    sender_eph_pub_raw = sender_eph_pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    dh1 = x25519_ecdh(sender_eph_priv_pem, receiver_signed_prekey_pub_pem)
    dh2 = x25519_ecdh(sender_longterm_priv_pem, receiver_identity_pub_pem)
    master = HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE,
        salt=b"zhcrypt-x3dh-v2", info=b"x3dh-master-key",
    ).derive(dh1 + dh2)

    plaintext_bytes = plaintext.encode("utf-8")
    sender_bytes = sender_identity.encode("utf-8")
    sender_len = struct.pack(">H", len(sender_bytes))
    ts = struct.pack(">Q", int(time.time()))

    sig_body = sender_bytes + ts + plaintext_bytes
    sig = ed25519_sign(sender_signing_priv_pem, sig_body)
    sig_len = struct.pack(">H", len(sig))
    inner = sender_len + sender_bytes + ts + plaintext_bytes + sig_len + sig

    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(master)
    ciphertext = aesgcm.encrypt(nonce, inner, None)

    packet = bytearray()
    packet.extend(MAGIC)
    packet.append(VERSION_V2)
    packet.append(MODE_HYBRID_PFS)
    packet.append(FLAG_HAS_SIGNATURE)
    packet.extend(sender_len + sender_bytes)
    packet.extend(sender_id_pub_raw)
    packet.extend(sender_eph_pub_raw)
    packet.extend(nonce)
    packet.extend(ciphertext)

    return bytes(packet)


def decrypt_pfs(
    packet: bytes,
    receiver_identity_priv_pem: bytes,
    receiver_signed_prekey_priv_pem: bytes,
    sender_signing_pub_pem: bytes = None,
) -> dict:
    """
    解密 X3DH PFS 模式密文

    参数:
      packet: 加密包
      receiver_identity_priv_pem: 接收方身份私钥 (X25519)
      receiver_signed_prekey_priv_pem: 接收方签名预密钥私钥 (X25519)
      sender_signing_pub_pem: 发送方 Ed25519 签名公钥 (由调用方提供)
    """
    if len(packet) < 4 or packet[:4] != MAGIC:
        raise ValueError("无效魔数")
    if packet[4] != VERSION_V2 or packet[5] != MODE_HYBRID_PFS:
        raise ValueError("不是 PFS 模式")
    # R7: sender_len 的 unpack 需要 ≥10 字节 (offset 7 + 2)
    if len(packet) < 10:
        raise ValueError("数据包过短或已损坏")

    flags = packet[6]
    has_sig = bool(flags & FLAG_HAS_SIGNATURE)

    offset = 7
    sender_len = struct.unpack(">H", packet[offset:offset + 2])[0]
    offset += 2
    try:
        sender = packet[offset:offset + sender_len].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("无效的发件人字段")
    offset += sender_len

    sender_id_pub_raw = packet[offset:offset + 32]
    offset += 32
    sender_eph_pub_raw = packet[offset:offset + 32]
    offset += 32

    nonce = packet[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext_with_tag = packet[offset:]

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    sender_id_pub = X25519PublicKey.from_public_bytes(sender_id_pub_raw)
    sender_eph_pub = X25519PublicKey.from_public_bytes(sender_eph_pub_raw)

    receiver_identity_priv = deserialize_x25519_private_key(receiver_identity_priv_pem)
    receiver_signed_prekey_priv = deserialize_x25519_private_key(
        receiver_signed_prekey_priv_pem
    )

    dh1 = _x25519_exchange_checked(receiver_signed_prekey_priv, sender_eph_pub)
    dh2 = _x25519_exchange_checked(receiver_identity_priv, sender_id_pub)

    master = HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE,
        salt=b"zhcrypt-x3dh-v2", info=b"x3dh-master-key",
    ).derive(dh1 + dh2)

    try:
        aesgcm = AESGCM(master)
        inner = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        raise DecryptionError("解密失败: 密文已损坏或密钥不匹配")

    try:
        off = 0
        sender_len2 = struct.unpack(">H", inner[off:off + 2])[0]
        off += 2
        sender_name = inner[off:off + sender_len2].decode("utf-8")
        off += sender_len2
        ts = struct.unpack(">Q", inner[off:off + 8])[0]
        off += 8
    except (struct.error, UnicodeDecodeError, IndexError):
        raise DecryptionError("解密失败: 明文结构损坏")

    if not has_sig:
        try:
            plaintext = inner[off:].decode("utf-8")
        except UnicodeDecodeError:
            raise DecryptionError("解密失败: 明文结构损坏")
        return {"plaintext": plaintext, "sender": sender, "verified": False, "timestamp": ts}

    # R2 加固: 同 hybrid_signed —— 签名长度必须恰为 64 字节, 否则拒绝
    if len(inner) < off + 66:
        raise DecryptionError("解密失败: 明文结构损坏")
    sig_len = struct.unpack(">H", inner[-66:-64])[0]
    if sig_len != 64:
        raise DecryptionError("解密失败: 签名字段长度非法")
    sig = inner[-sig_len:]
    plaintext_bytes = inner[off:-sig_len - 2]
    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("解密失败: 明文结构损坏")

    sig_body = sender_name.encode("utf-8") + struct.pack(">Q", ts) + plaintext_bytes
    verified = False
    if sender_signing_pub_pem is not None:
        try:
            verified = ed25519_verify(sender_signing_pub_pem, sig_body, sig)
        except Exception:
            pass

    return {"plaintext": plaintext, "sender": sender_name, "verified": verified, "timestamp": ts}


class DecryptionError(Exception):
    """解密失败异常"""
    pass


# ============================================================
# 流式文件加密 (MODE_FILE_STREAM = 0x05)
# ============================================================

def _chunk_encrypt(chunk_data, master_key, chunk_index, nonce_base):
    """加密单个块，返回 (nonce, encrypted_with_tag)"""
    chunk_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"zhcrypt-chunk-key-v1" + struct.pack(">Q", chunk_index),
    ).derive(master_key)

    custom_nonce = nonce_base[:4] + struct.pack(">Q", chunk_index)[:8]
    aad = struct.pack(">Q", chunk_index)

    aesgcm = AESGCM(chunk_key)
    encrypted = aesgcm.encrypt(custom_nonce, chunk_data, aad)
    return custom_nonce, encrypted


def _chunk_decrypt(encrypted_chunk, master_key, chunk_index, nonce):
    """解密单个块，返回明文"""
    chunk_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"zhcrypt-chunk-key-v1" + struct.pack(">Q", chunk_index),
    ).derive(master_key)

    aad = struct.pack(">Q", chunk_index)
    aesgcm = AESGCM(chunk_key)
    return aesgcm.decrypt(nonce, encrypted_chunk, aad)


def encrypt_file_stream(filepath, password, output_path=None, chunk_size=CHUNK_SIZE_DEFAULT):
    """
    流式文件加密 (分块 + 每块独立派生密钥)

    包格式:
      MAGIC(4) | VERSION(1) | MODE_FILE_STREAM(1) |
      ARGON2_PARAMS(12) | SALT(32) |
      NAME_LEN(2) | ORIG_NAME(var) |
      CHUNK_COUNT(8) |
      [NONCE(12) | CHUNK_LEN(4) | ENCRYPTED_DATA(var)] × N

    内存占用 ≈ chunk_size + 少量固定开销
    """
    salt = secrets.token_bytes(SALT_SIZE)
    tc, mc, pl = _get_argon2_params()
    master_key = derive_key(password, salt, time_cost=tc, memory_cost=mc, parallelism=pl)
    nonce_base = secrets.token_bytes(4)

    basename = os.path.basename(filepath)
    name_bytes = basename.encode("utf-8")
    name_len = struct.pack(">H", len(name_bytes))

    if output_path is None:
        output_path = filepath + ".zhs"

    # 写入文件头
    header = bytearray()
    header.extend(MAGIC)
    header.append(VERSION_V2)
    header.append(MODE_FILE_STREAM)
    header.extend(struct.pack(">III", tc, mc, pl))
    header.extend(salt)
    header.extend(name_len + name_bytes)

    with open(output_path, "wb") as out:
        # Placeholder for chunk count
        header_no_count = bytes(header)
        total_chunks_pos = len(header_no_count)
        header_no_count += b"\x00" * 8
        out.write(header_no_count)

        chunk_index = 0
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                nonce, encrypted = _chunk_encrypt(chunk, master_key, chunk_index, nonce_base)
                out.write(nonce)
                out.write(struct.pack(">I", len(encrypted)))
                out.write(encrypted)
                chunk_index += 1

        # 回写总块数
        out.seek(total_chunks_pos)
        out.write(struct.pack(">Q", chunk_index))

    key_bytes = bytearray(master_key)
    _clear_bytes(key_bytes)

    return output_path


def decrypt_file_stream(filepath, password, output_path=None, overwrite=False):
    """
    流式文件解密
    自动检测块大小（从文件头读取）
    """
    with open(filepath, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("不是 zhcrypt 加密文件")

        version = f.read(1)
        mode = f.read(1)
        if mode != bytes([MODE_FILE_STREAM]):
            raise ValueError("不是流式加密文件")

        params = f.read(12)
        time_cost, memory_cost, parallelism = struct.unpack(">III", params)
        salt = f.read(SALT_SIZE)
        name_len = struct.unpack(">H", f.read(2))[0]
        name_bytes = f.read(name_len)
        original_name = name_bytes.decode("utf-8")

        # 路径穿越防护 (审计 HIGH-2): 原始文件名来自密文头, 未纳入 GCM 认证,
        # 客户端可控。强制取 basename 剥离任何目录分量, 拒绝空名/纯 "."/".."。
        original_name = os.path.basename(original_name).strip()
        if not original_name or original_name in (".", ".."):
            original_name = "decrypted"

        chunk_count = struct.unpack(">Q", f.read(8))[0]

        master_key = derive_key(password, salt, time_cost, memory_cost, parallelism, KEY_SIZE)

        if output_path is None:
            output_path = filepath
            if output_path.endswith(".zhs"):
                output_path = os.path.join(os.path.dirname(filepath), original_name)
            else:
                output_path = output_path + ".dec"

        if os.path.exists(output_path) and not overwrite:
            raise FileExistsError(f"输出文件 {output_path} 已存在, 使用 --overwrite 覆盖")

        with open(output_path, "wb") as out:
            for i in range(chunk_count):
                nonce = f.read(NONCE_SIZE)
                chunk_len_data = f.read(4)
                if len(chunk_len_data) < 4:
                    raise ValueError(f"文件截断: 块 {i} 长度数据不完整")
                chunk_len = struct.unpack(">I", chunk_len_data)[0]
                # R7: chunk_len 来自未认证的密文头, 恶意文件可诱导一次近
                # 4GiB 的内存分配 (DoS)。合法块长 ≤ 默认块大小 + GCM tag,
                # 超限直接拒绝。
                if chunk_len > CHUNK_SIZE_DEFAULT + 16 + 32:
                    raise ValueError(f"非法块长: {chunk_len} (超过上限)")
                encrypted_chunk = f.read(chunk_len)
                if len(encrypted_chunk) < chunk_len:
                    raise ValueError(f"文件截断: 块 {i} 数据不完整")
                plain_chunk = _chunk_decrypt(encrypted_chunk, master_key, i, nonce)
                out.write(plain_chunk)

        key_bytes = bytearray(master_key)
        _clear_bytes(key_bytes)

    return output_path


# ============================================================
# 可否认加密 (MODE_DENIABLE = 0x06)
# ============================================================

def encrypt_deniable(real_text: str, real_password: str,
                     duress_text: str, duress_password: str) -> bytes:
    """
    可否认加密

    用两个密码分别加密真实消息和假消息, 存入同一密文包
    攻击者无法区分哪个密码/消息是真实的

    包格式:
      MAGIC(4) | VERSION(1) | MODE_DENIABLE(1) |
      PARAMS(12) |
      SALT_REAL(32) | NONCE_REAL(12) | REAL_LEN(4) | REAL_CT+TAG(var) |
      SALT_DURESS(32) | NONCE_DURESS(12) | DUR_LEN(4) | DUR_CT+TAG(var)
    """
    salt_real = secrets.token_bytes(SALT_SIZE)
    # R7: 与其它模式一致, 参数走统一钳制并写入包头 (原硬编码默认值,
    # 用户降配 Argon2 后 deniable 仍跑 256MiB×4)
    tc_r, mc_r, pl_r = _get_argon2_params()
    key_real = derive_key(real_password, salt_real, time_cost=tc_r,
                          memory_cost=mc_r, parallelism=pl_r)
    nonce_real = secrets.token_bytes(NONCE_SIZE)
    real_pt = real_text.encode("utf-8")
    aesgcm = AESGCM(key_real)
    real_ct = aesgcm.encrypt(nonce_real, real_pt, None)

    salt_duress = secrets.token_bytes(SALT_SIZE)
    key_duress = derive_key(duress_password, salt_duress, time_cost=tc_r,
                            memory_cost=mc_r, parallelism=pl_r)
    nonce_duress = secrets.token_bytes(NONCE_SIZE)
    duress_pt = duress_text.encode("utf-8")
    aesgcm2 = AESGCM(key_duress)
    duress_ct = aesgcm2.encrypt(nonce_duress, duress_pt, None)

    params = struct.pack(">III", tc_r, mc_r, pl_r)

    packet = bytearray()
    packet.extend(MAGIC)
    packet.append(VERSION_V2)
    packet.append(MODE_DENIABLE)
    packet.extend(params)
    packet.extend(salt_real)
    packet.extend(nonce_real)
    packet.extend(struct.pack(">I", len(real_ct)))
    packet.extend(real_ct)
    packet.extend(salt_duress)
    packet.extend(nonce_duress)
    packet.extend(struct.pack(">I", len(duress_ct)))
    packet.extend(duress_ct)

    for kb in [bytearray(key_real), bytearray(key_duress)]:
        _clear_bytes(kb)

    return bytes(packet)


def decrypt_deniable(packet: bytes, password: str) -> dict:
    """
    解密可否认加密包

    返回:
      {"text": str, "type": "real"|"duress", "error": None}
      或 {"text": None, "type": None, "error": "错误信息"}
    """
    if len(packet) < 6 or packet[:4] != MAGIC:
        raise ValueError("无效魔数")
    if packet[4] != VERSION_V2:
        raise ValueError(f"不支持的版本: {packet[4]}")
    if packet[5] != MODE_DENIABLE:
        raise ValueError("不是可否认加密模式")

    offset = 6
    # R7: 截断包防护 —— 定长头 params(12)+salt(32)+nonce(12)+real_len(4)
    if len(packet) < offset + 12 + SALT_SIZE + NONCE_SIZE + 4:
        raise ValueError("数据包过短或已损坏")
    time_cost, memory_cost, parallelism = struct.unpack(">III", packet[offset:offset + 12])
    offset += 12

    salt_real = packet[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce_real = packet[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    real_len = struct.unpack(">I", packet[offset:offset + 4])[0]
    offset += 4
    real_ct = packet[offset:offset + real_len]
    offset += real_len

    salt_duress = packet[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce_duress = packet[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    duress_len = struct.unpack(">I", packet[offset:offset + 4])[0]
    offset += 4
    duress_ct = packet[offset:offset + duress_len]

    key = derive_key(password, salt_real, time_cost, memory_cost, parallelism)
    key_duress = derive_key(password, salt_duress, time_cost, memory_cost, parallelism)

    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce_real, real_ct, None)
        return {"text": pt.decode("utf-8"), "type": "real"}
    except Exception:
        pass

    aesgcm2 = AESGCM(key_duress)
    try:
        pt = aesgcm2.decrypt(nonce_duress, duress_ct, None)
        return {"text": pt.decode("utf-8"), "type": "duress"}
    except Exception:
        return {"text": None, "type": None, "error": "密码错误或数据损坏"}
