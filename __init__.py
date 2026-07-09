"""zhcrypt v3.0 - 中文加密系统"""
from .core import (
    __version__,
    encrypt_password_mode,
    decrypt_password_mode,
    encrypt_hybrid,
    decrypt_hybrid,
    encrypt_hybrid_signed,
    decrypt_hybrid_signed,
    encrypt_file_stream,
    decrypt_file_stream,
    encrypt_file_password_mode,
    decrypt_file_password_mode,
    packet_to_b64,
    b64_to_packet,
    generate_rsa_key_pair,
    serialize_public_key,
    serialize_private_key,
    DecryptionError,
)
from .config import load, save, get, set_key
from .strength import get_strength, estimate_entropy
from .secretsharing import split_secret, recover_secret
