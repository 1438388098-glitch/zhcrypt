"""
zhcrypt 密钥管理模块
====================
RSA 密钥对生成、存储、加载、验证
支持口令加密保护私钥, 口令派生使用 Argon2id
"""

import os
import json
import struct
import secrets
import hashlib
import datetime

from core import (
    derive_key, SALT_SIZE, KEY_SIZE,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
    generate_rsa_key_pair,
    serialize_private_key, serialize_public_key,
    serialize_private_key_raw,
    deserialize_private_key, deserialize_public_key,
    generate_ed25519_key_pair, serialize_ed25519_private_key, serialize_ed25519_public_key,
    deserialize_ed25519_private_key, deserialize_ed25519_public_key,
    ed25519_sign, ed25519_verify,
    generate_x25519_key_pair, serialize_x25519_private_key, serialize_x25519_public_key,
    deserialize_x25519_private_key, deserialize_x25519_public_key,
    x25519_ecdh,
    DecryptionError,
)
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import re
import functools
import inspect


# 身份名校验：仅允许安全字符, 防止路径穿越 (审计 #2)
def _atomic_write_json(path, data):
    """R8: 原子写 JSON 文件 (tmp + os.replace)。

    GUI 后台线程化后, .meta/.otpkeys/.spk 的写方与加载路径存在并发窗口,
    半写文件会让 json.load 直接崩; 复制 session.py 的原子写范式。
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


_IDENTITY_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


def _validate_identity(identity):
    """校验身份名合法性, 拒绝路径穿越字符 (../、斜杠等)"""
    if not isinstance(identity, str) or not identity:
        raise ValueError("身份名不能为空")
    if ".." in identity:
        raise ValueError("非法身份名: %r (不允许 '..')" % identity)
    if not _IDENTITY_RE.match(identity):
        raise ValueError(
            "非法身份名: %r (仅允许字母/数字/._@-, 长度 1-64)" % identity
        )
    return identity


def _validate_identity_arg(func):
    """装饰器: 自动校验方法参数中的 identity, 防止路径穿越写文件

    注意: 实例方法调用时 self 已被消耗, 故 identity 在 *args 中的位置为 idx-1。
    """
    sig = inspect.signature(func)
    params = list(sig.parameters)
    idx = params.index("identity") if "identity" in params else None

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if idx is not None:
            if len(args) > idx - 1:
                _validate_identity(args[idx - 1])
            elif "identity" in kwargs:
                _validate_identity(kwargs["identity"])
        return func(self, *args, **kwargs)

    return wrapper


def compute_safety_number(my_signing_pub_pem: bytes,
                          peer_signing_pub_pem: bytes) -> str:
    """计算双方可带外比对的 safety number (60 hex, 5 位一组)。

    由我方与对端 Ed25519 签名公钥拼接后取 SHA-256 得到。首次通信后,
    双方应口头/带外比对这个号码是否一致, 以确认没有中间人。

    注意: 必须对两份公钥做顺序归一化(按字节序排序后再拼接), 否则 A 看 B 与
    B 看 A 的拼接顺序不同, 得到的号码不一致, 带外比对永远失败。
    """
    a = my_signing_pub_pem or b""
    b = peer_signing_pub_pem or b""
    combined = b"".join(sorted([a, b]))
    digest = hashlib.sha256(combined).hexdigest()
    return " ".join(digest[i:i + 5] for i in range(0, 60, 5))


def _wrap_key_data(passphrase, key_bytes):
    """用 Argon2id + AES-256-GCM 包裹密钥字节。

    格式: [params(12)|salt(32)|nonce(12)|ciphertext]
    与 _unwrap_key 解析格式保持一致 (修复审计 #15 格式不一致问题)。
    """
    salt = secrets.token_bytes(SALT_SIZE)
    wrapping_key = derive_key(passphrase, salt)
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(wrapping_key).encrypt(nonce, key_bytes, None)
    result = bytearray()
    result.extend(struct.pack(">III", ARGON2_TIME_COST,
                              ARGON2_MEMORY_COST, ARGON2_PARALLELISM))
    result.extend(salt)
    result.extend(nonce)
    result.extend(encrypted)
    return bytes(result)


_DEFAULT_KEY_DIR = os.path.join(os.path.expanduser("~"), ".zhcrypt", "keys")
_DEFAULT_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".zhcrypt")


def _restrict_private(path: str):
    """收紧私钥文件权限到 0600 (POSIX); Windows 上为尽力而为, 不抛异常。"""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def default_key_dir():
    return _DEFAULT_KEY_DIR


def ensure_key_dir():
    os.makedirs(_DEFAULT_KEY_DIR, exist_ok=True)


class KeyStore:
    """
    用户密钥库

    存储结构 (~/.zhcrypt/keys/):
      <identity>.pub          - 公钥 PEM (明文)
      <identity>.key          - 私钥 PEM (Argon2id 密钥加密)
      <identity>.meta         - 密钥元数据 JSON
      config.json             - 全局配置 (默认身份等)

    私钥加密流程 (_wrap_key_data, R10 修正文档与实现一致):
      1. 生成随机 32 字节 salt
      2. Argon2id(password, salt) → 256-bit wrapping key
         (实际实现直接以 Argon2id 输出作为 AES-GCM 密钥, 此前文档声称的
          HKDF-Expand("zhcrypt-key-wrap") 步骤并不存在; 若引入该步骤属
          协议变更, 需迁移旧密钥文件)
      3. AES-256-GCM(wrapping_key, private_key_pem) → 加密私钥
      4. 存储: params(12) | salt(32) | nonce(12) | ciphertext+tag
    """

    def __init__(self, key_dir: str = None):
        self.key_dir = key_dir or _DEFAULT_KEY_DIR
        os.makedirs(self.key_dir, exist_ok=True)

    @_validate_identity_arg
    def generate_identity(self, identity: str, passphrase: str,
                          comment: str = ""):
        """
        为指定身份生成 RSA-4096 + Ed25519 + X25519 密钥对

        存储文件:
          <identity>.pub        - RSA 公钥 (PEM)
          <identity>.key        - RSA 私钥 (Argon2id + AES-GCM 包裹)
          <identity>.ed25519      - Ed25519 私钥 (包裹)
          <identity>.ed25519.pub - Ed25519 公钥 (PEM)
          <identity>.x25519      - X25519 私钥 (包裹)
          <identity>.x25519.pub - X25519 公钥 (PEM)
          <identity>.meta       - 元数据 JSON
        """
        public_path = os.path.join(self.key_dir, f"{identity}.pub")
        private_path = os.path.join(self.key_dir, f"{identity}.key")
        sig_priv_path = os.path.join(self.key_dir, f"{identity}.ed25519")
        sig_pub_path = os.path.join(self.key_dir, f"{identity}.ed25519.pub")
        kem_priv_path = os.path.join(self.key_dir, f"{identity}.x25519")
        kem_pub_path = os.path.join(self.key_dir, f"{identity}.x25519.pub")
        meta_path = os.path.join(self.key_dir, f"{identity}.meta")

        for p in [public_path, private_path, sig_priv_path, sig_pub_path,
                  kem_priv_path, kem_pub_path]:
            if os.path.exists(p):
                raise FileExistsError(f"身份 '{identity}' 已存在: {p}")

        private_key, public_key = generate_rsa_key_pair()
        sig_priv, sig_pub = generate_ed25519_key_pair()
        kem_priv, kem_pub = generate_x25519_key_pair()

        public_pem = serialize_public_key(public_key)
        with open(public_path, "wb") as f:
            f.write(public_pem)

        with open(sig_pub_path, "wb") as f:
            f.write(serialize_ed25519_public_key(sig_pub))

        with open(kem_pub_path, "wb") as f:
            f.write(serialize_x25519_public_key(kem_pub))

        rsa_key_pem = serialize_private_key_raw(private_key)
        with open(private_path, "wb") as f:
            f.write(_wrap_key_data(passphrase, rsa_key_pem))
        _restrict_private(private_path)

        with open(sig_priv_path, "wb") as f:
            f.write(_wrap_key_data(passphrase, serialize_ed25519_private_key(sig_priv)))
        _restrict_private(sig_priv_path)

        with open(kem_priv_path, "wb") as f:
            f.write(_wrap_key_data(passphrase, serialize_x25519_private_key(kem_priv)))
        _restrict_private(kem_priv_path)

        meta = {
            "identity": identity,
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "comment": comment,
            "algorithm": "RSA-4096",
            "signing": "Ed25519",
            "kem": "X25519",
            "kdf": "Argon2id",
            "verification_hash": hashlib.sha256(
                public_pem + identity.encode("utf-8")
            ).hexdigest(),
        }
        _atomic_write_json(meta_path, meta)

        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        return {
            "identity": identity,
            "fingerprint": fingerprint,
        }

    def _unwrap_key(self, path: str, passphrase: str) -> bytes:
        """从包裹文件中解码并解密密钥数据"""
        with open(path, "rb") as f:
            wrapped_data = f.read()
        if len(wrapped_data) < 12 + SALT_SIZE + 12 + 16:
            raise ValueError("密钥文件损坏")
        offset = 0
        time_cost, memory_cost, parallelism = struct.unpack(
            ">III", wrapped_data[offset:offset + 12]
        )
        offset += 12
        salt = wrapped_data[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        nonce = wrapped_data[offset:offset + 12]
        offset += 12
        encrypted = wrapped_data[offset:]
        wrapping_key = derive_key(passphrase, salt, time_cost, memory_cost, parallelism)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(wrapping_key)
        try:
            return aesgcm.decrypt(nonce, encrypted, None)
        except Exception:
            raise DecryptionError("私钥解密失败: 口令错误或密钥文件损坏")

    @_validate_identity_arg
    def load_public_key(self, identity: str):
        """加载指定身份的 RSA 公钥"""
        path = os.path.join(self.key_dir, f"{identity}.pub")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的公钥不存在: {path}")
        with open(path, "rb") as f:
            return f.read()

    @_validate_identity_arg
    def load_signing_public_key(self, identity: str) -> bytes:
        """加载指定身份的 Ed25519 签名公钥"""
        path = os.path.join(self.key_dir, f"{identity}.ed25519.pub")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的签名公钥不存在: {path}")
        with open(path, "rb") as f:
            return f.read()

    @_validate_identity_arg
    def load_signing_private_key_pem(self, identity: str, passphrase: str) -> bytes:
        """加载解密后的 Ed25519 私钥 PEM"""
        path = os.path.join(self.key_dir, f"{identity}.ed25519")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的签名私钥不存在: {path}")
        return self._unwrap_key(path, passphrase)

    @_validate_identity_arg
    def load_kem_public_key_pem(self, identity: str) -> bytes:
        """加载指定身份的 X25519 KEM 公钥"""
        path = os.path.join(self.key_dir, f"{identity}.x25519.pub")
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"身份 '{identity}' 缺少 X25519 密钥 (用于聊天)。\n"
                f"请创建新身份: zhcrypt init <新名字>\n"
                f"或使用已有身份中的: default")
        with open(path, "rb") as f:
            return f.read()

    @_validate_identity_arg
    def load_kem_private_key_pem(self, identity: str, passphrase: str) -> bytes:
        """加载解密后的 X25519 私钥 PEM"""
        path = os.path.join(self.key_dir, f"{identity}.x25519")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的 KEM 私钥不存在: {path}")
        return self._unwrap_key(path, passphrase)

    @_validate_identity_arg
    def ensure_kem_keys(self, identity: str, passphrase: str) -> bool:
        """如果身份缺少 X25519 密钥对, 自动生成 (用于兼容旧版身份)"""
        pub_path = os.path.join(self.key_dir, f"{identity}.x25519.pub")
        priv_path = os.path.join(self.key_dir, f"{identity}.x25519")
        if os.path.exists(pub_path) and os.path.exists(priv_path):
            return False
        from core import generate_x25519_key_pair, serialize_x25519_private_key, serialize_x25519_public_key, derive_key, SALT_SIZE
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets
        kem_priv, kem_pub = generate_x25519_key_pair()
        with open(pub_path, "wb") as f:
            f.write(serialize_x25519_public_key(kem_pub))
        with open(priv_path, "wb") as f:
            f.write(_wrap_key_data(passphrase, serialize_x25519_private_key(kem_priv)))
        _restrict_private(priv_path)
        meta_path = os.path.join(self.key_dir, f"{identity}.meta")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as mf:
                    meta = json.load(mf)
                meta["kem_upgraded"] = True
                _atomic_write_json(meta_path, meta)
            except Exception:
                pass
        return True

    @_validate_identity_arg
    def load_private_key(self, identity: str, passphrase: str):
        """加载并解密 RSA 私钥 (兼容新旧两种存储格式)"""
        path = os.path.join(self.key_dir, f"{identity}.key")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的私钥不存在: {path}")
        private_pem = self._unwrap_key(path, passphrase)
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.backends import default_backend as _be
        try:
            return _ser.load_pem_private_key(private_pem, password=None, backend=_be())
        except Exception:
            return _ser.load_pem_private_key(
                private_pem, password=passphrase.encode("utf-8"), backend=_be()
            )

    @_validate_identity_arg
    def load_private_key_pem(self, identity: str, passphrase: str) -> bytes:
        """加载解密后的 RSA 私钥 PEM 数据"""
        path = os.path.join(self.key_dir, f"{identity}.key")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的私钥不存在: {path}")
        return self._unwrap_key(path, passphrase)

    def list_identities(self):
        """列出所有已存储的身份"""
        identities = []
        for fname in os.listdir(self.key_dir):
            if fname.endswith(".pub") and not fname.endswith(".ed25519.pub") \
                    and not fname.endswith(".x25519.pub"):
                identity = fname[:-4]
                meta_path = os.path.join(self.key_dir, f"{identity}.meta")
                meta = {}
                if os.path.exists(meta_path):
                    try:
                        with open(meta_path, "r", encoding="utf-8") as mf:
                            meta = json.load(mf)
                    except (OSError, ValueError):
                        # 损坏/非法的 meta 文件不应让身份列举整体失败 (R1 修复)
                        meta = {}
                pub_path = os.path.join(self.key_dir, fname)
                if os.path.exists(pub_path):
                    with open(pub_path, "rb") as pf:
                        fingerprint = hashlib.sha256(pf.read()).hexdigest()[:16]
                identities.append({
                    "identity": identity,
                    "fingerprint": fingerprint,
                    "comment": meta.get("comment", ""),
                    "created": meta.get("created", ""),
                    "capabilities": f"RSA+Ed25519+X25519",
                })
        return identities

    @_validate_identity_arg
    def delete_identity(self, identity: str):
        """删除指定身份的所有密钥文件"""
        removed = []
        for ext in [".pub", ".key", ".meta",
                    ".ed25519", ".ed25519.pub",
                    ".x25519", ".x25519.pub",
                    ".otpkeys", ".backup", ".spk"]:
            path = os.path.join(self.key_dir, f"{identity}{ext}")
            if os.path.exists(path):
                os.remove(path)
                removed.append(path)
        if not removed:
            raise FileNotFoundError(f"身份 '{identity}' 不存在")
        return removed

    @_validate_identity_arg
    def verify_passphrase(self, identity: str, passphrase: str) -> bool:
        """验证身份口令是否正确"""
        try:
            self.load_private_key(identity, passphrase)
            return True
        except DecryptionError:
            return False
        except Exception:
            return False

    @_validate_identity_arg
    def load_otp_private_keys(self, identity: str, passphrase: str) -> list:
        """
        加载本地存储的 OTP 私钥

        返回: [(index, X25519私钥对象), ...]
        每个密钥已解密, 可用于 PFS 解密
        """
        otp_path = os.path.join(self.key_dir, f"{identity}.otpkeys")
        if not os.path.exists(otp_path):
            return []

        with open(otp_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        from core import urlsafe_b64decode
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        keys = []
        key_cache = {}
        for entry in data.get("keys", []):
            try:
                salt = urlsafe_b64decode(entry["salt"].encode("ascii"))
                nonce = urlsafe_b64decode(entry["nonce"].encode("ascii"))
                enc_priv = urlsafe_b64decode(entry["enc_priv"].encode("ascii"))
                if salt not in key_cache:
                    key_cache[salt] = derive_key(passphrase, salt)
                wrapping_key = key_cache[salt]
                pem = AESGCM(wrapping_key).decrypt(nonce, enc_priv, None)
                priv = deserialize_x25519_private_key(pem)
                keys.append((entry["index"], priv))
            except Exception:
                continue

        return keys

    @_validate_identity_arg
    def load_signed_prekey_priv_pem(self, identity: str, passphrase: str) -> bytes:
        """加载本地存储的签名预密钥私钥 (PEM)"""
        spk_path = os.path.join(self.key_dir, f"{identity}.spk")
        if not os.path.exists(spk_path):
            return None
        with open(spk_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        from core import urlsafe_b64decode
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt = urlsafe_b64decode(data["salt"].encode("ascii"))
        nonce = urlsafe_b64decode(data["nonce"].encode("ascii"))
        enc_priv = urlsafe_b64decode(data["enc_priv"].encode("ascii"))
        wrapping_key = derive_key(passphrase, salt)
        return AESGCM(wrapping_key).decrypt(nonce, enc_priv, None)

    @_validate_identity_arg
    def store_tofu_signing_pub(self, peer_identity: str, pub_pem: bytes):
        """TOFU: 记录首次接触到的对端 Ed25519 签名公钥 (防中间人换钥)

        文件名使用独立后缀 .tofu.ed25519.pub, 避免与本地身份或带外导入的
        公钥文件 (<peer>.ed25519.pub) 冲突。
        """
        path = os.path.join(self.key_dir, f"{peer_identity}.tofu.ed25519.pub")
        with open(path, "wb") as f:
            f.write(pub_pem)

    @_validate_identity_arg
    def load_tofu_signing_pub(self, peer_identity: str) -> bytes:
        """TOFU: 读取已记录的对端签名公钥; 未记录则抛 FileNotFoundError"""
        path = os.path.join(self.key_dir, f"{peer_identity}.tofu.ed25519.pub")
        if not os.path.exists(path):
            raise FileNotFoundError(f"未记录 {peer_identity} 的 TOFU 签名公钥")
        with open(path, "rb") as f:
            return f.read()

    @_validate_identity_arg
    def export_public_key_b64(self, identity: str) -> str:
        """导出 Base64 编码的 RSA 公钥 (旧版兼容)"""
        from core import urlsafe_b64encode
        pub = self.load_public_key(identity)
        return urlsafe_b64encode(pub).decode("ascii")

    @_validate_identity_arg
    def export_public_key_bundle(self, identity: str) -> str:
        """
        导出完整公钥束 (RSA + Ed25519 + X25519)
        返回 JSON 格式的 Base64 字符串
        """
        from core import urlsafe_b64encode
        import base64
        bundle = {
            "version": 3,
            "type": "zhcrypt_public_key_bundle",
            "identity": identity,
            "rsa_pub": urlsafe_b64encode(self.load_public_key(identity)).decode("ascii"),
            "ed25519_pub": urlsafe_b64encode(
                self.load_signing_public_key(identity)
            ).decode("ascii"),
            "x25519_pub": urlsafe_b64encode(
                self.load_kem_public_key_pem(identity)
            ).decode("ascii"),
        }
        return base64.urlsafe_b64encode(
            json.dumps(bundle, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")

    def peek_bundle_identity(self, encoded: str):
        """从公钥束中读取对方身份 (用于导入时自动命名)。

        仅识别 v3 格式 (zhcrypt_public_key_bundle)。旧版 / 非法内容返回 None。
        用途: 导入时无需手填名字, 直接用束内身份即可, 避免与对方在服务器
        注册的身份不一致导致聊天握手失败 (X3DH 用该名字去 GET /v1/prekey/{名字})。
        """
        import base64
        from core import urlsafe_b64decode
        try:
            decoded = base64.urlsafe_b64decode(encoded.encode("ascii"))
            bundle = json.loads(decoded.decode("utf-8"))
            if bundle.get("type") == "zhcrypt_public_key_bundle":
                return bundle.get("identity")
        except Exception:
            return None
        return None

    @_validate_identity_arg
    def import_public_key_bundle(self, encoded: str, identity: str,
                                 display_name: str = None):
        """导入他人公钥束 (自动检测新旧格式)。

        返回状态: "imported" (新导入) | "exists_same" (已存在且公钥相同) | "imported_legacy" (旧版)
        display_name: 仅本地显示的备注 (不影响路由, 路由恒用 identity)

        R5 修复: 载荷带 v3 束类型标记但解析失败 (缺字段/跨版本损坏) 时,
        明确抛 ValueError, 不再静默降级把整段 base64 当 RSA 公钥写入
        <name>.pub (后续加密才报模糊错误)。
        """
        from core import urlsafe_b64decode
        import base64
        bundle = None
        try:
            decoded = base64.urlsafe_b64decode(encoded.encode("ascii"))
            bundle = json.loads(decoded.decode("utf-8"))
        except Exception:
            bundle = None
        if isinstance(bundle, dict) and bundle.get("type") == "zhcrypt_public_key_bundle":
            try:
                return self._do_import_bundle(bundle, identity, display_name)
            except KeyError as e:
                raise ValueError(f"公钥束损坏: 缺少字段 {e}") from e
            except (ValueError, TypeError) as e:
                raise ValueError(f"公钥束损坏或版本不支持: {e}") from e
        self.import_public_key_b64(encoded, identity, display_name)
        return "imported_legacy"

    def _do_import_bundle(self, bundle: dict, identity: str,
                          display_name: str = None):
        """导入公钥束到磁盘。返回 "imported" 或 "exists_same"。"""
        from core import urlsafe_b64decode
        rsa_pub = urlsafe_b64decode(bundle["rsa_pub"].encode("ascii"))
        ed_pub = urlsafe_b64decode(bundle["ed25519_pub"].encode("ascii"))
        x_pub = urlsafe_b64decode(bundle["x25519_pub"].encode("ascii"))

        base = self.key_dir
        pub_path = os.path.join(base, f"{identity}.pub")
        if os.path.exists(pub_path):
            # 已存在: 与待导入比对, 相同则视为已导入 (跳过, 不报错)
            with open(pub_path, "rb") as f:
                existing = f.read()
            if existing == rsa_pub:
                return "exists_same"
            raise FileExistsError(
                f"身份 '{identity}' 已存在且公钥不同。\n"
                f"如需替换为新公钥, 请先在「联系人」中删除该身份再导入。")

        for fn, data in [(f"{identity}.pub", rsa_pub),
                         (f"{identity}.ed25519.pub", ed_pub),
                         (f"{identity}.x25519.pub", x_pub)]:
            path = os.path.join(base, fn)
            with open(path, "wb") as f:
                f.write(data)

        meta = {
            "identity": identity,
            "imported": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "type": "imported_public_key_bundle",
        }
        if display_name:
            meta["display_name"] = display_name
        _atomic_write_json(os.path.join(base, f"{identity}.meta"), meta)
        return "imported"

    @_validate_identity_arg
    def import_public_key_b64(self, b64_pub: str, identity: str,
                              display_name: str = None):
        """从 Base64 导入旧版 RSA 公钥"""
        from core import urlsafe_b64decode
        pub_pem = urlsafe_b64decode(b64_pub)
        public_path = os.path.join(self.key_dir, f"{identity}.pub")
        if os.path.exists(public_path):
            with open(public_path, "rb") as f:
                existing = f.read()
            if existing == pub_pem:
                return "exists_same"
            raise FileExistsError(f"身份 '{identity}' 已存在且公钥不同")
        with open(public_path, "wb") as f:
            f.write(pub_pem)
        meta = {
            "identity": identity,
            "imported": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "type": "imported_public_key",
        }
        if display_name:
            meta["display_name"] = display_name
        meta_path = os.path.join(self.key_dir, f"{identity}.meta")
        _atomic_write_json(meta_path, meta)
        return "imported"

    def get_contact_display_name(self, identity: str):
        """读取对方公钥的本地备注 (display_name)。无则返回 None。

        仅用于显示, 不影响加密路由 (路由恒用 identity)。
        """
        import os as _os
        meta_path = _os.path.join(self.key_dir, f"{identity}.meta")
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            return meta.get("display_name") or None
        except Exception:
            return None

    def set_contact_display_name(self, identity: str, display_name: str):
        """更新对方公钥的本地备注 (display_name)。"""
        import os as _os
        meta_path = _os.path.join(self.key_dir, f"{identity}.meta")
        meta = {}
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            pass
        if display_name:
            meta["display_name"] = display_name
        elif "display_name" in meta:
            del meta["display_name"]
        _atomic_write_json(meta_path, meta)
        return meta_path

    @_validate_identity_arg
    def import_peer_static_keys(self, identity: str, idk_b64: str = None,
                                spk_b64: str = None, signing_b64: str = None) -> dict:
        """自动导入对端静态公钥 (R5 加固: 三重守卫, 返回 {"updated","skipped"})。

        用于『连接时自动拉取对方公钥』(Tier 1 优化): 服务器是证书固定 + token
        双认证的, 其返回的静态公钥可信。与手动 export/import 公钥束不同, 这里
        不消费 one-time prekey, 也不要求 RSA 公钥, 仅需 X3DH 所需的:
          - identity_key_pub (X25519) -> <peer>.x25519.pub
          - signed_prekey_pub (X25519) -> <peer>.spk.x25519.pub
          - signing_public_key (Ed25519) -> <peer>.ed25519.pub
        覆盖写以便对方换 prekey 后平滑更新, 但 R5 加固:
          1. 对端名与本地身份同名 -> 拒绝 (防覆盖自身公钥);
          2. 写盘前验证解码结果确为对应类型的合法公钥 (防垃圾/损坏数据落盘);
          3. 对端已有 TOFU 锚且新签名公钥与锚不一致 -> 跳过签名公钥更新
             (防服务器被控时静默替换验签锚点), 其余字段照常更新。
        """
        from core import urlsafe_b64decode

        base = self.key_dir
        # 守卫 1: 拒绝覆盖自身
        if os.path.exists(os.path.join(base, f"{identity}.key")):
            return {"updated": [], "skipped": ["refused: identity is local"]}
        if os.path.exists(os.path.join(base, f"{identity}.tofu.ed25519.pub")):
            tofu = self.load_tofu_signing_pub(identity)
            if tofu and signing_b64:
                try:
                    if urlsafe_b64decode(signing_b64.encode("ascii")) != tofu:
                        # 守卫 3: 签名公钥与 TOFU 锚不一致, 跳过更新
                        signing_b64 = None
                except Exception:
                    signing_b64 = None

        mapping = []
        if idk_b64:
            mapping.append((f"{identity}.x25519.pub",
                            urlsafe_b64decode(idk_b64.encode("ascii")),
                            "x25519"))
        if spk_b64:
            mapping.append((f"{identity}.spk.x25519.pub",
                            urlsafe_b64decode(spk_b64.encode("ascii")),
                            "x25519"))
        if signing_b64:
            mapping.append((f"{identity}.ed25519.pub",
                            urlsafe_b64decode(signing_b64.encode("ascii")),
                            "ed25519"))
        updated, skipped = [], []
        for fn, data, kind in mapping:
            # 守卫 2: 写盘前验证 PEM 确为对应类型的合法公钥
            try:
                if kind == "x25519":
                    deserialize_x25519_public_key(data)
                else:
                    deserialize_ed25519_public_key(data)
            except Exception:
                skipped.append(fn)
                continue
            path = os.path.join(base, fn)
            try:
                with open(path, "wb") as f:
                    f.write(data)
                updated.append(fn)
            except Exception:
                # 单文件失败不应中断其它字段写入
                skipped.append(fn)
        return {"updated": updated, "skipped": skipped}

    @_validate_identity_arg
    def generate_prekey_bundle(self, identity: str, passphrase: str,
                               otp_count: int = 50) -> dict:
        """
        生成 X3DH prekey bundle，供上传到 prekey 服务器

        返回:
        {
            "identity_key_pub": "base64-X25519公钥",
            "signed_prekey_pub": "base64-X25519签名预密钥",
            "signature": "base64-Ed25519签名 (对 signed_prekey_pub 的签名)",
            "signing_public_key": "base64-Ed25519签名公钥 (供首次通信自验, 公钥无密) ",
            "one_time_prekeys": ["base64-X25519公钥", ...],
            "fingerprint": "hex-指纹"
        }
        """
        from core import urlsafe_b64encode

        identity_key_pem = self.load_kem_public_key_pem(identity)
        identity_key = deserialize_x25519_public_key(identity_key_pem)

        prekey_priv, prekey_pub = generate_x25519_key_pair()
        prekey_pub_pem = serialize_x25519_public_key(prekey_pub)
        prekey_priv_pem = serialize_x25519_private_key(prekey_priv)

        sign_priv_pem = self.load_signing_private_key_pem(identity, passphrase)
        sig = ed25519_sign(sign_priv_pem, prekey_pub_pem)

        otp_public_keys = []
        otp_entries = []
        # 性能修复 (动态测试发现): 全部 OTP 共用同一个 salt 派生包密钥,
        # 避免 load_otp_private_keys 对每个 OTP 各做一次 Argon2id(256MB) 派生
        # (50 次串行派生会致首次会话解密 ~1 分钟, 且可被恶意 x3dh_init 当 CPU DoS)。
        # 安全: 复用 salt (→同密钥) 合法, 但 nonce 必须每份唯一 —— 否则同一
        # (key, nonce) 下 50 份密文复用 GCM keystream, 触发 Joux forbidden attack
        # 与已知明文恢复 (审计 CRITICAL: AEAD nonce 复用)。
        otp_salt = secrets.token_bytes(SALT_SIZE)
        otp_wrapping_key = derive_key(passphrase, otp_salt)
        for i in range(otp_count):
            otp_priv, otp_pub = generate_x25519_key_pair()
            otp_pub_b64 = urlsafe_b64encode(
                serialize_x25519_public_key(otp_pub)
            ).decode("ascii")
            otp_public_keys.append(otp_pub_b64)

            otp_priv_pem = serialize_x25519_private_key(otp_priv)
            otp_nonce = secrets.token_bytes(12)  # 每份 OTP 独立 nonce
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            enc_priv = AESGCM(otp_wrapping_key).encrypt(otp_nonce, otp_priv_pem, None)
            otp_entries.append({
                "index": i,
                "salt": urlsafe_b64encode(otp_salt).decode("ascii"),
                "nonce": urlsafe_b64encode(otp_nonce).decode("ascii"),
                "enc_priv": urlsafe_b64encode(enc_priv).decode("ascii"),
            })

        otp_path = os.path.join(self.key_dir, f"{identity}.otpkeys")
        _atomic_write_json(otp_path, {"version": 1, "keys": otp_entries})

        spk_path = os.path.join(self.key_dir, f"{identity}.spk")
        spk_salt = secrets.token_bytes(SALT_SIZE)
        spk_nonce = secrets.token_bytes(12)
        spk_wrapping_key = derive_key(passphrase, spk_salt)
        spk_enc = AESGCM(spk_wrapping_key).encrypt(spk_nonce, prekey_priv_pem, None)
        spk_data = {
            "salt": urlsafe_b64encode(spk_salt).decode("ascii"),
            "nonce": urlsafe_b64encode(spk_nonce).decode("ascii"),
            "enc_priv": urlsafe_b64encode(spk_enc).decode("ascii"),
        }
        _atomic_write_json(spk_path, spk_data)

        fingerprint = hashlib.sha256(identity_key_pem).hexdigest()[:16]

        return {
            "identity_key_pub": urlsafe_b64encode(identity_key_pem).decode("ascii"),
            "signed_prekey_pub": urlsafe_b64encode(prekey_pub_pem).decode("ascii"),
            "signature": urlsafe_b64encode(sig).decode("ascii"),
            "signing_public_key": urlsafe_b64encode(
                self.load_signing_public_key(identity)
            ).decode("ascii"),
            "one_time_prekeys": otp_public_keys,
            "fingerprint": fingerprint,
        }
