"""
zhcrypt 证书固定 (certificate pinning) 工具 — 审计 #18
===================================================

用途: 在 wss 连接时, 校验服务端证书的公钥指纹 (SPKI SHA-256) 是否与用户
预先记录的固定值一致。即便存在流氓 CA 签发了伪造证书, 只要指纹不匹配就
拒绝连接, 从而阻断中间人攻击 (配合审计 #3/#4 的 TLS 启用)。

pin 的计算方式 (与主流实现一致):
    PIN = base64( SHA256( SubjectPublicKeyInfo(DER) ) )
"""

import base64
import hashlib
import hmac
import ssl
import socket

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)


def compute_cert_pin(der_cert):
    """由 DER 编码的证书计算 SPKI SHA-256 pin (base64 字符串)。"""
    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def verify_cert_pin(der_cert, expected_pin):
    """校验服务端证书指纹是否等于预期 pin (恒定时间比较, 防时序)。

    R11: 非 ASCII pin 会让 hmac.compare_digest 抛 TypeError (调用侧不在
    try 内, 会被泛化成"连接错误"), 这里统一做输入防线后返回 False。
    """
    if not der_cert or not expected_pin or not isinstance(expected_pin, str):
        return False
    expected_pin = expected_pin.strip()
    try:
        expected_pin.encode("ascii")
    except UnicodeEncodeError:
        return False
    actual = compute_cert_pin(der_cert)
    return hmac.compare_digest(actual, expected_pin)


def fetch_cert_pin(host, port=443, server_name=None, timeout=10):
    """诊断工具: 连接自有服务器并取回其证书 pin, 供用户记录到配置中。

    仅用于获取你自己服务器的 pin (防御侧工具, 非攻击用途)。
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 仅读取证书, 不校验
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name or host) as s:
            der = s.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError("无法获取服务端证书")
    return compute_cert_pin(der)
