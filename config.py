"""
zhcrypt v3.0 - 配置管理模块
管理 ~/.zhcrypt/config.json
"""

import os
import json
import secrets

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover
    AESGCM = None

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".zhcrypt")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
# 审计 #8: Auth Token 不再以明文落盘, 用本机设备密钥加密后存储。
# device.key 是机器绑定的本地密钥 (权限 0600), 仅在本机可解密 token。
# 即便 config.json 被同步到云盘/备份泄露, 没有 device.key 也无法还原 token。
DEVICE_KEY_PATH = os.path.join(CONFIG_DIR, "device.key")


def _load_build_token():
    """本地打包用默认 token: 仅从被 .gitignore 忽略的 .build_token 读取,
    避免将凭证写入版本库。文件不存在时返回空串(需用户手动配置)。"""
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".build_token")
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return ""


DEFAULT_CONFIG = {
    "version": "3.0.0",
    "argon2id": {
        "time_cost": 4,
        "memory_cost": 262144,
        "parallelism": 4,
    },
    "default_identity": "default",
    "pfs_enabled": True,
    "signature_enabled": True,
    "prekey_server": {
        "url": "https://iweistoicqc5.top",
        "auth_token": "",
        "auth_token_enc": "",
        "cert_pin": "",
        "auto_upload_prekeys": True,
        "prekey_rotate_seconds": 3600,
    },
    "file_encryption": {
        "chunk_size_bytes": 65536,
        "legacy_mode": False,
    },
    "streaming": {
        "enabled": True,
        "chunk_size": 65536,
    },
    "gui": {
        "last_tab": 0,
        "window_width": 720,
        "window_height": 560,
    },
}


def ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)


def load():
    ensure_config_dir()
    if not os.path.exists(CONFIG_PATH):
        save(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        _deep_merge(merged, cfg)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save(cfg):
    ensure_config_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def get(key_path, default=None):
    cfg = load()
    keys = key_path.split(".")
    val = cfg
    for k in keys:
        if isinstance(val, dict):
            val = val.get(k)
        else:
            return default
        if val is None:
            return default
    return val


def set_key(key_path, value):
    cfg = load()
    keys = key_path.split(".")
    obj = cfg
    for k in keys[:-1]:
        if k not in obj or not isinstance(obj[k], dict):
            obj[k] = {}
        obj = obj[k]
    obj[keys[-1]] = value
    save(cfg)


def _load_device_key():
    """读取或生成本机设备密钥 (32 字节), 用于加密 Auth Token (审计 #8)。"""
    ensure_config_dir()
    if os.path.exists(DEVICE_KEY_PATH):
        with open(DEVICE_KEY_PATH, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
    key = secrets.token_bytes(32)
    fd = os.open(DEVICE_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        os.chmod(DEVICE_KEY_PATH, 0o600)
    except OSError:
        pass
    return key


def _encrypt_token(plaintext: str) -> str:
    """用设备密钥以 AES-256-GCM 加密 token, 返回 hex(nonce+ciphertext)。"""
    if AESGCM is None:
        raise RuntimeError("cryptography 不可用, 无法加密 token")
    key = _load_device_key()
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return (nonce + ct).hex()


def _decrypt_token(hexblob: str) -> str:
    """解密 _encrypt_token 的产物, 失败抛异常。"""
    key = _load_device_key()
    raw = bytes.fromhex(hexblob)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def encrypt_bytes(plaintext: bytes) -> bytes:
    """用设备密钥 AES-256-GCM 加密任意字节 (供 localstore 加密文件密钥等)。

    返回 nonce(12) + ciphertext+tag。设备密钥缺失/损坏时抛异常。
    """
    if AESGCM is None:
        raise RuntimeError("cryptography 不可用, 无法加密")
    key = _load_device_key()
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_bytes(blob: bytes) -> bytes:
    """解密 encrypt_bytes 的产物; 失败抛异常。"""
    key = _load_device_key()
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def set_prekey_server(url: str, token: str = None):
    """配置 prekey 服务器地址; 若提供 token, 以设备密钥加密存储 (审计 #8), 不落明文。"""
    cfg = load()
    cfg["prekey_server"]["url"] = url
    if token is not None:
        if token == "":
            cfg["prekey_server"]["auth_token"] = ""
            cfg["prekey_server"]["auth_token_enc"] = ""
        else:
            cfg["prekey_server"]["auth_token_enc"] = _encrypt_token(token)
            cfg["prekey_server"]["auth_token"] = ""  # 清掉任何残留明文
    save(cfg)


def get_prekey_server():
    return get("prekey_server.url", "")


def get_auth_token():
    """返回 Auth Token (自动解密, 无需调用方提供口令)。

    兼容迁移: 旧版明文 auth_token 会在首次读取时自动加密重写, 不再以明文留存。
    """
    enc = get("prekey_server.auth_token_enc", "")
    if enc:
        try:
            return _decrypt_token(enc)
        except Exception:
            return ""
    legacy = get("prekey_server.auth_token", "")
    if legacy:
        # 自动迁移为加密存储, 消除明文落盘
        try:
            cfg = load()
            cfg["prekey_server"]["auth_token_enc"] = _encrypt_token(legacy)
            cfg["prekey_server"]["auth_token"] = ""
            save(cfg)
        except Exception:
            pass
        return legacy
    # 零配置兜底: 任何位置都未配置 token 时, 仅内存返回 .build_token (分发给朋友用),
    # 不落盘、不写入 DEFAULT_CONFIG (审计 M3: 防首次运行把真实 token 明文写进 config.json)。
    return _load_build_token()


def set_cert_pin(pin: str):
    """设置服务端证书固定指纹 (SPKI SHA-256, base64), 审计 #18。"""
    set_key("prekey_server.cert_pin", pin or "")


def get_cert_pin():
    """读取服务端证书固定指纹; 空字符串表示未启用固定。"""
    return get("prekey_server.cert_pin", "")


def _deep_merge(base, override):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
