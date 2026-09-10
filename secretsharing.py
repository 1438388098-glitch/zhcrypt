"""
zhcrypt Shamir 秘密共享 (3-of-5)
基于 SECP256K1 质数 (P = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1)
将私钥 (SHA256) 分割为 5 份, 任意 3 份可恢复
"""

import secrets

PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SHARES_TOTAL = 5
SHARES_THRESHOLD = 3
BYTE_LEN = 32


def _bytes_to_int(data):
    return int.from_bytes(data, "big")


def _int_to_bytes(value, length=BYTE_LEN):
    return value.to_bytes(length, "big")


def _eval_poly(coefficients, x):
    result = 0
    for c in reversed(coefficients):
        result = (result * x + c) % PRIME
    return result


def _lagrange_interpolate(points, x):
    result = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = (num * (x - xj)) % PRIME
                den = (den * (xi - xj)) % PRIME
        result = (result + yi * num * pow(den, PRIME - 2, PRIME)) % PRIME
    return result


def split_secret(secret_bytes: bytes, total=SHARES_TOTAL, threshold=SHARES_THRESHOLD):
    if len(secret_bytes) > BYTE_LEN:
        # R8: 不再静默截断 —— 调用方传 >32 字节密钥会恢复出错误密钥。
        raise ValueError(f"秘密长度 {len(secret_bytes)} 超过上限 {BYTE_LEN} 字节, "
                         f"请先自行哈希 (如 SHA-256) 再分片")
    secret_padded = secret_bytes.ljust(BYTE_LEN, b"\x00")
    secret_int = _bytes_to_int(secret_padded)

    coefficients = [secret_int]
    for _ in range(threshold - 1):
        coefficients.append(secrets.randbelow(PRIME))

    shares = []
    for i in range(1, total + 1):
        y = _eval_poly(coefficients, i)
        shares.append((i, _int_to_bytes(y, BYTE_LEN).hex()))

    return shares


def recover_secret(shares: list, threshold=SHARES_THRESHOLD) -> bytes:
    if len(shares) < threshold:
        raise ValueError(f"需要至少 {threshold} 个份额, 当前只有 {len(shares)} 个")

    if len({idx for idx, _ in shares}) != len(shares):
        raise ValueError("份额序号存在重复, 请检查输入")

    # R8: 序号范围校验 —— idx=0 会让插值直接返回秘密值, 负数/超 total
    # 属畸形输入, 一律拒绝。
    for idx, _ in shares:
        if not (1 <= idx <= SHARES_TOTAL):
            raise ValueError(f"份额序号超出范围: {idx}")

    points = [(idx, _bytes_to_int(bytes.fromhex(hex_data)))
              for idx, hex_data in shares[:threshold]]

    secret_int = _lagrange_interpolate(points, 0)
    # 修复: 不再 rstrip 尾零 —— 若秘密字节本身以 0x00 结尾, rstrip 会截断密钥,
    # 导致 AES-GCM 解密失败、备份无法恢复 (约 1/256 概率)。长度恒为 BYTE_LEN。
    return _int_to_bytes(secret_int, BYTE_LEN)


def format_share(identity: str, idx: int, hex_data: str) -> str:
    return f"zhcrypt|{identity}|{idx}|{hex_data}"


def parse_share(text: str):
    parts = text.strip().split("|", 3)
    if len(parts) != 4 or parts[0] != "zhcrypt":
        raise ValueError("无效的份额格式")
    return parts[1], int(parts[2]), parts[3]
