"""zhcrypt v3.0 - 中文加密系统"""
# R1 兼容性修复: pytest 9 (importlib 收集模式) 会把本文件按无名模块 "__init__"
# 导入, 相对导入随即抛 ImportError 并阻塞整个 tests/ 的收集。这里捕获该情况,
# 仅保留版本号兜底; 正常以包方式导入时行为不变。
try:
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
except ImportError:
    __version__ = "3.2.0"
