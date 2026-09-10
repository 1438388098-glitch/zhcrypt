"""
zhcrypt 密码强度检测模块
========================
判断标准:
  < 30 bits  → 弱   (GPU 分钟级可破)
  30-50 bits → 中   (GPU 集群数月)
  50-80 bits → 强   (GPU 集群千年级)
  > 80 bits  → 极强 (宇宙年龄级)
"""

import math
import hashlib
import re

COMMON_WEAK = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "sunshine", "qwerty123", "admin",
    "letmein", "monkey", "dragon", "abc123", "trustno1", "master",
    "passw0rd", "iloveyou", "welcome", "shadow", "pass123", "test123",
    "woaini", "1314520", "5201314", "zhang", "wang", "li", "zhao",
}

KEYBOARD_PATTERNS = re.compile(
    r"(qwerty|asdfgh|zxcvbn|qazwsx|1q2w3e|12qwas|qweasd|"
    r"wasd|qwer|asdf|zxcv|poiu|lkjh|mnbv)"
)


def _char_set_size(password):
    sets = 0
    if re.search(r"[a-z]", password): sets += 26
    if re.search(r"[A-Z]", password): sets += 26
    if re.search(r"[0-9]", password): sets += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;':\",./<>?`~\\]", password): sets += 33
    if re.search(r"[\u4e00-\u9fff]", password): sets += 5000
    # R8: 其它非 ASCII 字符 (西里尔/日文/emoji 等) 不再计 0 —— 记为
    # ~200 的经验集合大小, 避免多语用户的强口令被系统性误判为弱。
    if sets == 0 or re.search(r"[^\x00-\x7f\u4e00-\u9fff]", password):
        sets += 200
    return max(sets, 1)


def estimate_entropy(password: str) -> float:
    # R12: 「词·词·词」形词表口令按词表熵计算 —— 字符熵会把 6 词临时口令
    # 高估到 200+ bits (实际 256^6 ≈ 48 bits)。
    try:
        from wordlist import TEMP_WORDS
        parts = password.split("·")
        if len(parts) >= 3 and all(p in TEMP_WORDS for p in parts):
            return math.log2(len(TEMP_WORDS)) * len(parts)
    except Exception:
        pass

    charset = _char_set_size(password)
    entropy = math.log2(charset) * len(password)

    if re.search(r"(.)\1{3,}", password):
        entropy *= 0.5
    if KEYBOARD_PATTERNS.search(password.lower()):
        entropy *= 0.5
    if re.match(r"^\d+$", password):
        entropy *= 0.3
    if re.match(r"^[a-z]+$", password):
        entropy *= 0.5

    return entropy


def check_common_password(password: str) -> bool:
    return password.lower() in COMMON_WEAK


def get_strength(password: str) -> dict:
    entropy = estimate_entropy(password)
    is_common = check_common_password(password)
    is_short = len(password) < 8
    is_digit_only = password.isdigit()

    if is_common or entropy < 20:
        level = "weak"
        score = 1
        color = "red"
    elif entropy < 30:
        level = "weak"
        score = 2
        color = "red"
    elif entropy < 50:
        level = "medium"
        score = 3
        color = "orange"
    elif entropy < 80:
        level = "strong"
        score = 4
        color = "green"
    else:
        level = "very_strong"
        score = 5
        color = "darkgreen"

    warnings = []
    if is_common:
        warnings.append("这是一个常见密码，极易被字典攻破")
    if is_short:
        warnings.append("密码太短 (建议 12 位以上)")
    if is_digit_only:
        warnings.append("只有数字，字符集太小")
    if entropy < 30:
        warnings.append(f"密码强度弱 ({entropy:.0f} bits)")

    return {
        "entropy": entropy,
        "score": score,
        "level": level,
        "color": color,
        "warnings": warnings,
        "common": is_common,
    }
