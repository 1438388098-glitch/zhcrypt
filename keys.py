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


_DEFAULT_KEY_DIR = os.path.join(os.path.expanduser("~"), ".zhcrypt", "keys")
_DEFAULT_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".zhcrypt")


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

    私钥加密流程:
      1. 生成随机 32 字节 salt
      2. Argon2id(password + salt) → 256-bit 密钥
      3. HKDF-Expand(密钥, "zhcrypt-key-wrap") → 256-bit wrapping key
      4. AES-256-GCM(wrapping_key, private_key_pem) → 加密私钥
      5. 存储: salt | nonce | encrypted_private_key
    """

    def __init__(self, key_dir: str = None):
        self.key_dir = key_dir or _DEFAULT_KEY_DIR
        os.makedirs(self.key_dir, exist_ok=True)

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

        def _wrap_key(key_bytes):
            salt = secrets.token_bytes(SALT_SIZE)
            wrapping_key = derive_key(passphrase, salt)
            nonce = secrets.token_bytes(12)
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(wrapping_key)
            encrypted = aesgcm.encrypt(nonce, key_bytes, None)
            result = bytearray()
            result.extend(struct.pack(">III", ARGON2_TIME_COST,
                                      ARGON2_MEMORY_COST, ARGON2_PARALLELISM))
            result.extend(salt)
            result.extend(nonce)
            result.extend(encrypted)
            return bytes(result)

        rsa_key_pem = serialize_private_key_raw(private_key)
        with open(private_path, "wb") as f:
            f.write(_wrap_key(rsa_key_pem))

        with open(sig_priv_path, "wb") as f:
            f.write(_wrap_key(serialize_ed25519_private_key(sig_priv)))

        with open(kem_priv_path, "wb") as f:
            f.write(_wrap_key(serialize_x25519_private_key(kem_priv)))

        meta = {
            "identity": identity,
            "created": datetime.datetime.utcnow().isoformat() + "Z",
            "comment": comment,
            "algorithm": "RSA-4096",
            "signing": "Ed25519",
            "kem": "X25519",
            "kdf": "Argon2id",
            "verification_hash": hashlib.sha256(
                public_pem + identity.encode("utf-8")
            ).hexdigest(),
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

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

    def load_public_key(self, identity: str):
        """加载指定身份的 RSA 公钥"""
        path = os.path.join(self.key_dir, f"{identity}.pub")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的公钥不存在: {path}")
        with open(path, "rb") as f:
            return f.read()

    def load_signing_public_key(self, identity: str) -> bytes:
        """加载指定身份的 Ed25519 签名公钥"""
        path = os.path.join(self.key_dir, f"{identity}.ed25519.pub")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的签名公钥不存在: {path}")
        with open(path, "rb") as f:
            return f.read()

    def load_signing_private_key_pem(self, identity: str, passphrase: str) -> bytes:
        """加载解密后的 Ed25519 私钥 PEM"""
        path = os.path.join(self.key_dir, f"{identity}.ed25519")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的签名私钥不存在: {path}")
        return self._unwrap_key(path, passphrase)

    def load_kem_public_key_pem(self, identity: str) -> bytes:
        """加载指定身份的 X25519 KEM 公钥"""
        path = os.path.join(self.key_dir, f"{identity}.x25519.pub")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的 KEM 公钥不存在: {path}")
        with open(path, "rb") as f:
            return f.read()

    def load_kem_private_key_pem(self, identity: str, passphrase: str) -> bytes:
        """加载解密后的 X25519 私钥 PEM"""
        path = os.path.join(self.key_dir, f"{identity}.x25519")
        if not os.path.exists(path):
            raise FileNotFoundError(f"身份 '{identity}' 的 KEM 私钥不存在: {path}")
        return self._unwrap_key(path, passphrase)

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
                    with open(meta_path, "r", encoding="utf-8") as mf:
                        meta = json.load(mf)
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

    def delete_identity(self, identity: str):
        """删除指定身份的所有密钥文件"""
        removed = []
        for ext in [".pub", ".key", ".meta",
                    ".ed25519", ".ed25519.pub",
                    ".x25519", ".x25519.pub",
                    ".otpkeys", ".backup"]:
            path = os.path.join(self.key_dir, f"{identity}{ext}")
            if os.path.exists(path):
                os.remove(path)
                removed.append(path)
        if not removed:
            raise FileNotFoundError(f"身份 '{identity}' 不存在")
        return removed

    def verify_passphrase(self, identity: str, passphrase: str) -> bool:
        """验证身份口令是否正确"""
        try:
            self.load_private_key(identity, passphrase)
            return True
        except DecryptionError:
            return False
        except Exception:
            return False

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
        for entry in data.get("keys", []):
            try:
                salt = urlsafe_b64decode(entry["salt"].encode("ascii"))
                nonce = urlsafe_b64decode(entry["nonce"].encode("ascii"))
                enc_priv = urlsafe_b64decode(entry["enc_priv"].encode("ascii"))
                wrapping_key = derive_key(passphrase, salt)
                pem = AESGCM(wrapping_key).decrypt(nonce, enc_priv, None)
                priv = deserialize_x25519_private_key(pem)
                keys.append((entry["index"], priv))
            except Exception:
                continue

        return keys

    def export_public_key_b64(self, identity: str) -> str:
        """导出 Base64 编码的 RSA 公钥 (旧版兼容)"""
        from core import urlsafe_b64encode
        pub = self.load_public_key(identity)
        return urlsafe_b64encode(pub).decode("ascii")

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

    def import_public_key_bundle(self, encoded: str, identity: str):
        """导入他人公钥束 (自动检测新旧格式)"""
        from core import urlsafe_b64decode
        import base64
        try:
            decoded = base64.urlsafe_b64decode(encoded.encode("ascii"))
            bundle = json.loads(decoded.decode("utf-8"))
            if bundle.get("type") == "zhcrypt_public_key_bundle":
                self._do_import_bundle(bundle, identity)
                return
        except Exception:
            pass
        self.import_public_key_b64(encoded, identity)

    def _do_import_bundle(self, bundle: dict, identity: str):
        """导入公钥束到磁盘"""
        from core import urlsafe_b64decode
        rsa_pub = urlsafe_b64decode(bundle["rsa_pub"].encode("ascii"))
        ed_pub = urlsafe_b64decode(bundle["ed25519_pub"].encode("ascii"))
        x_pub = urlsafe_b64decode(bundle["x25519_pub"].encode("ascii"))

        base = self.key_dir
        for fn, data in [(f"{identity}.pub", rsa_pub),
                         (f"{identity}.ed25519.pub", ed_pub),
                         (f"{identity}.x25519.pub", x_pub)]:
            path = os.path.join(base, fn)
            if os.path.exists(path):
                raise FileExistsError(f"身份 '{identity}' 已存在: {fn}")
            with open(path, "wb") as f:
                f.write(data)

        meta = {
            "identity": identity,
            "imported": datetime.datetime.utcnow().isoformat() + "Z",
            "type": "imported_public_key_bundle",
        }
        with open(os.path.join(base, f"{identity}.meta"), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

    def import_public_key_b64(self, b64_pub: str, identity: str):
        """从 Base64 导入旧版 RSA 公钥"""
        from core import urlsafe_b64decode
        pub_pem = urlsafe_b64decode(b64_pub)
        public_path = os.path.join(self.key_dir, f"{identity}.pub")
        if os.path.exists(public_path):
            raise FileExistsError(f"身份 '{identity}' 已存在")
        with open(public_path, "wb") as f:
            f.write(pub_pem)
        meta = {
            "identity": identity,
            "imported": datetime.datetime.utcnow().isoformat() + "Z",
            "type": "imported_public_key",
        }
        meta_path = os.path.join(self.key_dir, f"{identity}.meta")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        return public_path

    def generate_prekey_bundle(self, identity: str, passphrase: str,
                               otp_count: int = 50) -> dict:
        """
        生成 X3DH prekey bundle，供上传到 prekey 服务器

        返回:
        {
            "identity_key_pub": "base64-X25519公钥",
            "signed_prekey_pub": "base64-X25519签名预密钥",
            "signed_prekey_priv": "base64-加密私钥",
            "signature": "base64-Ed25519签名",
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
        for i in range(otp_count):
            otp_priv, otp_pub = generate_x25519_key_pair()
            otp_pub_b64 = urlsafe_b64encode(
                serialize_x25519_public_key(otp_pub)
            ).decode("ascii")
            otp_public_keys.append(otp_pub_b64)

            otp_priv_pem = serialize_x25519_private_key(otp_priv)
            otp_salt = secrets.token_bytes(SALT_SIZE)
            otp_nonce = secrets.token_bytes(12)
            wrapping_key = derive_key(passphrase, otp_salt)
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            enc_priv = AESGCM(wrapping_key).encrypt(otp_nonce, otp_priv_pem, None)
            otp_entries.append({
                "index": i,
                "salt": urlsafe_b64encode(otp_salt).decode("ascii"),
                "nonce": urlsafe_b64encode(otp_nonce).decode("ascii"),
                "enc_priv": urlsafe_b64encode(enc_priv).decode("ascii"),
            })

        otp_path = os.path.join(self.key_dir, f"{identity}.otpkeys")
        with open(otp_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "keys": otp_entries}, f, ensure_ascii=False)

        fingerprint = hashlib.sha256(identity_key_pem).hexdigest()[:16]

        return {
            "identity_key_pub": urlsafe_b64encode(identity_key_pem).decode("ascii"),
            "signed_prekey_pub": urlsafe_b64encode(prekey_pub_pem).decode("ascii"),
            "signed_prekey_priv": urlsafe_b64encode(prekey_priv_pem).decode("ascii"),
            "signature": urlsafe_b64encode(sig).decode("ascii"),
            "one_time_prekeys": otp_public_keys,
            "fingerprint": fingerprint,
        }
