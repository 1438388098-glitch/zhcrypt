#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt - 中文加密系统 CLI
===========================
中英文混合加密系统，基于 Argon2id + AES-256-GCM + RSA-4096

用法:
  zhcrypt init [identity]          初始化身份，生成 RSA 密钥对
  zhcrypt encrypt <text>            密码模式加密文本
  zhcrypt decrypt <ciphertext>      密码模式解密文本
  zhcrypt encrypt-file <file>       加密文件
  zhcrypt decrypt-file <file>       解密文件
  zhcrypt send <text> -t <to>       向指定身份发送加密消息 (混合模式)
  zhcrypt receive <ciphertext>      接收并解密混合模式消息
  zhcrypt export [identity]         导出公钥 (用于分享)
  zhcrypt import <b64key> <name>    导入他人公钥
  zhcrypt list                      列出所有身份
  zhcrypt delete <identity>         删除身份
  zhcrypt info                      显示系统信息
"""

import os
import sys
import argparse
import getpass
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    __version__,
    encrypt_password_mode, decrypt_password_mode,
    packet_to_b64, b64_to_packet,
    encrypt_file_password_mode, decrypt_file_password_mode,
    DecryptionError, MAGIC, MODE_PASSWORD, MODE_HYBRID,
    serialize_public_key,
    encrypt_hybrid, decrypt_hybrid,
    encrypt_hybrid_signed, decrypt_hybrid_signed,
    MODE_HYBRID_SIGNED, VERSION_V2,
)
from keys import KeyStore
from config import load, save, set_prekey_server, get_prekey_server, get_auth_token


class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _fail(msg: str):
    print(f"{Color.RED}[错误] {msg}{Color.RESET}", file=sys.stderr)
    sys.exit(1)


def _ok(msg: str):
    print(f"{Color.GREEN}[成功] {msg}{Color.RESET}")


def _warn(msg: str):
    print(f"{Color.YELLOW}[警告] {msg}{Color.RESET}")


def _info(msg: str):
    print(f"{Color.CYAN}{msg}{Color.RESET}")


def _prompt_passphrase(prompt: str = "输入密码: ", confirm: bool = True) -> str:
    pwd = getpass.getpass(prompt)
    if not pwd:
        _fail("密码不能为空")

    from strength import get_strength
    s = get_strength(pwd)
    if s["warnings"]:
        for w in s["warnings"]:
            _warn(w)

    level_name = {"weak": "弱", "medium": "中", "strong": "强", "very_strong": "极强"}
    _info(f"  密码强度: {level_name.get(s['level'], '?')} ({s['entropy']:.0f} bits)")

    if s["level"] == "weak" and len(pwd.encode("utf-8")) < 12:
        _warn("密码过弱, 建议使用更长/更复杂的密码")

    if confirm:
        pwd2 = getpass.getpass("确认密码: ")
        if pwd != pwd2:
            _fail("两次输入的密码不一致")
    return pwd


def cmd_init(args):
    store = KeyStore()
    identity = args.identity or "default"
    comment = args.comment or ""
    _info(f"正在为身份 '{identity}' 生成 RSA-4096 密钥对...")
    pwd = _prompt_passphrase("设置私钥密码 (支持中文): ")
    try:
        info = store.generate_identity(identity, pwd, comment)
        _ok(f"身份 '{identity}' 创建成功")
        _info(f"  指纹: {info['fingerprint']}")
        _info(f"  密钥类型: RSA-4096, Ed25519, X25519")
    except FileExistsError as e:
        _fail(str(e))


def cmd_list(args):
    store = KeyStore()
    identities = store.list_identities()
    if not identities:
        _info("尚未创建任何身份, 请先运行 'zhcrypt init'")
        return
    _info(f"{Color.BOLD}{'身份':<16} {'指纹':<18} {'备注':<20} {'创建时间'}{Color.RESET}")
    _info("-" * 80)
    for id_ in identities:
        print(f"{id_['identity']:<16} {id_['fingerprint']:<18} {id_['comment']:<20} {id_['created']}")


def cmd_encrypt(args):
    text = args.text
    if not text:
        text = sys.stdin.read().strip()
        if not text:
            _fail("请提供要加密的文本 (-t 或管道输入)")

    if args.temp_share:
        words = ["山茶", "东风", "白云", "松柏", "流水", "明月", "清风", "远山",
                 "晨露", "晚霞", "飞鸟", "落叶", "寒星", "暖阳", "翠竹", "幽兰",
                 "碧海", "青天", "古道", "长亭"]
        import secrets
        chosen = [secrets.choice(words) for _ in range(4)]
        temp_pwd = "·".join(chosen)
        packet = encrypt_password_mode(text, temp_pwd)
        b64 = packet_to_b64(packet)
        print("")
        print(f"{Color.BOLD}{'='*55}{Color.RESET}")
        print(f"{Color.GREEN}  一次性密码: {temp_pwd}{Color.RESET}")
        print(f"{Color.BOLD}{'='*55}{Color.RESET}")
        print(f"\n密文:")
        print(b64)
        print(f"\n{Color.YELLOW}⚠ 此密码仅显示一次, 不会存储{Color.RESET}")
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(b64)
            _ok(f"密文已保存到: {args.output}")
        return

    if args.sign:
        return cmd_encrypt_signed(args)

    if args.to:
        return _cmd_send(text, args)

    pwd = _prompt_passphrase("输入加密密码: ")
    packet = encrypt_password_mode(text, pwd)
    b64 = packet_to_b64(packet)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(b64)
        _ok(f"密文已保存到: {args.output}")
    else:
        _info("=" * 60)
        _info(f"{Color.BOLD}密文 (Base64):{Color.RESET}")
        print(b64)
        _info("=" * 60)
        _info("将此密文发送给持有相同密码的人以解密")


def _cmd_send(text, args):
    store = KeyStore()
    recipient = args.to
    pub_key = store.load_public_key(recipient)
    info = f"--sender={args.sender or 'default'}\n{text}"
    packet = encrypt_hybrid(info, pub_key)
    b64 = packet_to_b64(packet)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(b64)
        _ok(f"密文已保存到: {args.output}")
    else:
        _info("=" * 60)
        _info(f"{Color.BOLD}混合加密密文 (发送给 {recipient}):{Color.RESET}")
        print(b64)
        _info("=" * 60)


def cmd_decrypt(args):
    ciphertext = args.ciphertext
    if not ciphertext:
        ciphertext = sys.stdin.read().strip()
        if not ciphertext:
            _fail("请提供要解密的密文 (-c 或管道输入)")

    try:
        packet = b64_to_packet(ciphertext)
    except Exception:
        _fail("无效的 Base64 编码密文")

    mode = packet[5] if len(packet) > 5 else None

    if mode == MODE_PASSWORD:
        pwd = _prompt_passphrase("输入解密密码: ", confirm=False)
        try:
            plaintext = decrypt_password_mode(packet, pwd)
        except DecryptionError as e:
            _fail(str(e))
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(plaintext)
            _ok(f"明文已保存到: {args.output}")
        else:
            _info("=" * 60)
            _info(f"{Color.BOLD}明文:{Color.RESET}")
            print(plaintext)
            _info("=" * 60)
    elif mode == MODE_HYBRID:
        _cmd_receive_hybrid(packet, args)
    else:
        _fail("无法识别密文格式")


def _cmd_receive_hybrid(packet, args):
    store = KeyStore()
    identity = args.sender or "default"
    pwd = _prompt_passphrase(f"输入私钥密码 '{identity}': ", confirm=False)
    private_key_pem = store.load_private_key_pem(identity, pwd)
    try:
        plaintext = decrypt_hybrid(packet, private_key_pem, pwd)
    except DecryptionError as e:
        _fail(str(e))

    if "\n" in plaintext:
        sender, _, msg = plaintext.partition("\n")
        sender = sender.replace("--sender=", "")
        _info(f"{Color.CYAN}来自: {sender}{Color.RESET}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(plaintext)
        _ok(f"明文已保存到: {args.output}")
    else:
        _info("=" * 60)
        _info(f"{Color.BOLD}明文:{Color.RESET}")
        print(plaintext)
        _info("=" * 60)


def cmd_encrypt_file(args):
    filepath = args.file
    if not os.path.exists(filepath):
        _fail(f"文件不存在: {filepath}")
    pwd = _prompt_passphrase("输入加密密码: ")

    from config import get
    chunk_size = get("streaming.chunk_size", 65536)

    size = os.path.getsize(filepath)
    use_legacy = args.legacy or size < 65536

    try:
        if use_legacy:
            out = encrypt_file_password_mode(filepath, pwd, args.output)
            _info("  (使用传统全量模式)")
        else:
            out = encrypt_file_stream(filepath, pwd, args.output, chunk_size=int(chunk_size))
            _info("  (使用流式分块模式)")
        _ok(f"文件已加密: {out}")
        _info(f"  原始大小: {os.path.getsize(filepath):,} bytes")
        _info(f"  加密大小: {os.path.getsize(out):,} bytes")
    except Exception as e:
        _fail(str(e))


def cmd_decrypt_file(args):
    filepath = args.file
    if not os.path.exists(filepath):
        _fail(f"文件不存在: {filepath}")
    pwd = _prompt_passphrase("输入解密密码: ", confirm=False)
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            _ = f.read(1)   # version
            mode_byte = f.read(1)
    except Exception:
        _fail("无法读取文件头")

    if magic != b"ZHCR":
        # Try legacy mode
        try:
            out = decrypt_file_password_mode(filepath, pwd, args.output, args.overwrite)
            _ok(f"文件已解密: {out}")
        except Exception as e:
            _fail(str(e))
        return

    try:
        if mode_byte == bytes([0x05]):
            out = decrypt_file_stream(filepath, pwd, args.output, args.overwrite)
        else:
            out = decrypt_file_password_mode(filepath, pwd, args.output, args.overwrite)
        _ok(f"文件已解密: {out}")
    except Exception as e:
        _fail(str(e))


def cmd_export(args):
    store = KeyStore()
    identity = args.identity or "default"
    b64 = store.export_public_key_b64(identity)
    _info("=" * 60)
    _info(f"{Color.BOLD}公钥 [Base64] - {identity}:{Color.RESET}")
    print(b64)
    _info("=" * 60)
    _info("将此公钥分享给要向你发送加密消息的人")


def cmd_import(args):
    store = KeyStore()
    try:
        path = store.import_public_key_b64(args.b64key, args.name)
        _ok(f"公钥已导入为身份 '{args.name}': {path}")
    except Exception as e:
        _fail(str(e))


def cmd_delete(args):
    store = KeyStore()
    try:
        removed = store.delete_identity(args.identity)
        for p in removed:
            _info(f"已删除: {p}")
        _ok(f"身份 '{args.identity}' 已删除")
    except Exception as e:
        _fail(str(e))


def cmd_info(args):
    _info(f"""
{Color.BOLD}  zhcrypt v{__version__} - 中文加密系统{Color.RESET}

{Color.CYAN}密码算法栈:{Color.RESET}
  ├── 密钥派生   Argon2id (RFC 9106, 256MB 内存)
  ├── 对称加密   AES-256-GCM (认证加密)
  └── 非对称加密 RSA-4096-OAEP-SHA512

{Color.CYAN}密钥存储:{Color.RESET}
  └── {os.path.expanduser('~')}\\.zhcrypt\\keys\\

{Color.CYAN}安全特性:{Color.RESET}
  ├── 每次加密使用随机 Salt (32B) + Nonce (12B)
  ├── AEAD 认证标签防篡改
  ├── 常数时间比较防时序攻击
  └── 私钥双重加密 (Argon2id + AES-GCM)
""")
    store = KeyStore()
    identities = store.list_identities()
    if identities:
        _info(f"{Color.BOLD}已注册身份 ({len(identities)}):{Color.RESET}")
        for id_ in identities:
            _info(f"  {id_['identity']}  [{id_['fingerprint']}]")


def cmd_set_server(args):
    """配置 prekey 服务器地址"""
    url = args.url.rstrip("/")
    token = args.token or ""
    if not url.startswith("http"):
        _fail("服务器地址必须以 http:// 或 https:// 开头")
    set_prekey_server(url, token)
    _ok(f"Prekey 服务器已设置为: {url}")


def cmd_import_bundle(args):
    """导入新版公钥束 (RSA + Ed25519 + X25519)"""
    store = KeyStore()
    try:
        store.import_public_key_bundle(args.bundle, args.name)
        _ok(f"公钥束已导入为身份 '{args.name}'")
        _info("  包含: RSA-4096 + Ed25519 + X25519")
    except Exception as e:
        _fail(str(e))


def cmd_export_bundle(args):
    """导出新版公钥束"""
    store = KeyStore()
    identity = args.identity or "default"
    try:
        bundle = store.export_public_key_bundle(identity)
        _info("=" * 60)
        _info(f"{Color.BOLD}公钥束 (RSA+Ed25519+X25519) - {identity}:{Color.RESET}")
        print(bundle)
        _info("=" * 60)
    except Exception as e:
        _fail(str(e))


def cmd_upload_prekey(args):
    """生成并上传 prekey bundle 到服务器"""
    import urllib.request
    import base64
    import json as json_mod

    store = KeyStore()
    identity = args.identity or "default"
    url = get_prekey_server()
    if not url:
        _fail("未配置 prekey 服务器, 请先运行 'zhcrypt set-server <url>'")

    pwd = _prompt_passphrase(f"输入私钥密码 '{identity}': ", confirm=False)
    try:
        bundle = store.generate_prekey_bundle(identity, pwd, otp_count=args.count)
    except Exception as e:
        _fail(f"生成 prekey 失败: {e}")

    if args.dry_run:
        _info("Dry run - 生成的 bundle (不上传):")
        for k, v in bundle.items():
            if isinstance(v, list):
                _info(f"  {k}: [{len(v)} items]")
            else:
                _info(f"  {k}: {str(v)[:60]}...")
        return

    _info(f"正在上传 prekey bundle 到 {url}...")
    try:
        body = json_mod.dumps(bundle).encode("utf-8")
        full_url = f"{url}/v1/prekey/{identity}"
        req = urllib.request.Request(
            full_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {get_auth_token()}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json_mod.loads(resp.read())
        _ok(f"Prekey 上传成功!")
        _info(f"  身份: {identity}")
        _info(f"  Signed prekey: 已存储")
        _info(f"  One-time prekeys: {len(bundle['one_time_prekeys'])} 个")
    except Exception as e:
        _fail(f"上传失败: {e}")


def cmd_encrypt_signed(args):
    """带签名的混合加密"""
    store = KeyStore()
    text = args.text
    if not text:
        text = sys.stdin.read().strip()
    if not text:
        _fail("请提供要加密的文本")
    receiver = args.to
    sender = args.sender or "default"
    if not receiver:
        _fail("请指定接收方 (-t <identity>)")

    try:
        pub_pem = store.load_public_key(receiver)
        pwd = _prompt_passphrase(f"输入签名私钥密码 '{sender}': ", confirm=False)
        sign_priv_pem = store.load_signing_private_key_pem(sender, pwd)

        packet = encrypt_hybrid_signed(text, pub_pem, sign_priv_pem, sender)
        b64 = packet_to_b64(packet)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(b64)
            _ok(f"签名密文已保存到: {args.output}")
        else:
            _info("=" * 60)
            _info(f"{Color.BOLD}签名加密密文 (发送方: {sender} → {receiver}):{Color.RESET}")
            print(b64)
            _info("=" * 60)
    except Exception as e:
        _fail(str(e))


def cmd_decrypt_signed(args):
    """解密带签名的密文"""
    store = KeyStore()
    ciphertext = args.ciphertext
    if not ciphertext:
        ciphertext = sys.stdin.read().strip()
    if not ciphertext:
        _fail("请提供密文")

    try:
        packet = b64_to_packet(ciphertext)
    except Exception:
        _fail("无效的 Base64 密文")

    mode = packet[5] if len(packet) > 5 else None
    version = packet[4] if len(packet) > 4 else 1

    if mode == MODE_PASSWORD:
        cmd_decrypt(args)
        return
    elif mode == MODE_HYBRID:
        cmd_decrypt(args)
        return
    elif mode == MODE_HYBRID_SIGNED:
        identity = args.sender or "default"
        pwd = _prompt_passphrase(f"输入私钥密码 '{identity}': ", confirm=False)
        try:
            priv_pem = store.load_private_key_pem(identity, pwd)
            result = decrypt_hybrid_signed(packet, priv_pem, pwd)
            _info(f"{Color.CYAN}来自: {result['sender']}{Color.RESET}")
            if result['verified']:
                _ok(f"签名验证通过 ✅")
            else:
                _warn(f"签名验证失败或未签名 ⚠️")
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(result["plaintext"])
                _ok(f"明文已保存到: {args.output}")
            else:
                _info("=" * 60)
                print(result["plaintext"])
                _info("=" * 60)
        except Exception as e:
            _fail(str(e))
    else:
        _fail(f"不支持的加密模式: {mode}")


def cmd_backup(args):
    """备份私钥 (Shamir 5 份额)"""
    from secretsharing import split_secret, format_share
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import hashlib

    store = KeyStore()
    identity = args.identity or "default"
    pwd = _prompt_passphrase(f"输入私钥密码 '{identity}': ", confirm=False)

    try:
        key_pem = store.load_private_key_pem(identity, pwd)
        encrypt_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(encrypt_key)
        encrypted_pem = aesgcm.encrypt(nonce, key_pem, None)

        backup_path = os.path.join(store.key_dir, f"{identity}.backup")
        with open(backup_path, "wb") as f:
            f.write(MAGIC + struct.pack(">B", VERSION_V2) + nonce + encrypted_pem)

        shares = split_secret(encrypt_key, total=5, threshold=3)

        _info(f"{Color.BOLD}私钥恢复份额 (3-of-5):{Color.RESET}")
        _info(f"备份文件: {backup_path}")
        _info("")
        for idx, hex_data in shares:
            share_text = format_share(identity, idx, hex_data)
            print(f"  {Color.YELLOW}份额 {idx}{Color.RESET}: {share_text}")
        _info("")
        _info(f"恢复命令: zhcrypt restore {identity}")
    except Exception as e:
        _fail(str(e))


def cmd_restore(args):
    """从份额恢复私钥"""
    from secretsharing import recover_secret, parse_share
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    store = KeyStore()
    identity = args.identity or "default"
    backup_path = os.path.join(store.key_dir, f"{identity}.backup")
    if not os.path.exists(backup_path):
        _fail(f"备份文件不存在: {backup_path}")

    _info(f"需要 3 个份额来恢复身份 '{identity}'")

    collected = []
    while len(collected) < 3:
        try:
            line = input(f"  份额 {len(collected)+1}: ").strip()
            if not line:
                break
            id_, idx, data = parse_share(line)
            if id_ != identity:
                _warn(f"份额属于 '{id_}', 请确认")
            collected.append((idx, data))
        except (ValueError, EOFError, KeyboardInterrupt) as e:
            _fail(str(e))

    if len(collected) < 3:
        _fail(f"需要 3 个份额, 只提供了 {len(collected)} 个")

    try:
        encrypt_key = recover_secret(collected, threshold=3)

        with open(backup_path, "rb") as f:
            data = f.read()
        if data[:4] != MAGIC:
            _fail("备份文件格式错误")
        nonce = data[6:18]
        encrypted_pem = data[18:]

        aesgcm = AESGCM(encrypt_key)
        key_pem = aesgcm.decrypt(nonce, encrypted_pem, None)

        key_path = os.path.join(store.key_dir, f"{identity}.key")
        with open(key_path, "wb") as f:
            f.write(key_pem)

        _ok("私钥已恢复!")
        _info(f"已写入: {key_path}")
    except Exception as e:
        _fail(f"恢复失败: {e}")


def cmd_strength(args):
    """测试密码强度"""
    from strength import get_strength
    if args.password:
        pwd = args.password
    else:
        import getpass
        pwd = getpass.getpass("输入要测试的密码: ")
    s = get_strength(pwd)
    level_name = {"weak": "弱", "medium": "中", "strong": "强", "very_strong": "极强"}
    _info(f"密码强度: {level_name.get(s['level'], '?')}")
    _info(f"信息熵:   {s['entropy']:.1f} bits")
    _info(f"评分:     {s['score']}/5")
    if s["warnings"]:
        for w in s["warnings"]:
            _warn(w)


def cmd_set_params(args):
    from config import load, save
    cfg = load()
    changed = False
    if args.time is not None:
        cfg["argon2id"]["time_cost"] = args.time
        changed = True
    if args.mem is not None:
        cfg["argon2id"]["memory_cost"] = args.mem * 1024
        changed = True
    if args.par is not None:
        cfg["argon2id"]["parallelism"] = args.par
        changed = True
    if not changed:
        _info(f"当前参数: time={cfg['argon2id']['time_cost']}, "
              f"mem={cfg['argon2id']['memory_cost']/1024:.0f}MB, "
              f"par={cfg['argon2id']['parallelism']}")
        _info("使用 --time / --mem / --par 修改参数")
        return
    save(cfg)
    _ok("参数已更新:")
    _info(f"  time_cost = {cfg['argon2id']['time_cost']}")
    _info(f"  memory_cost = {cfg['argon2id']['memory_cost']/1024:.0f} MB")
    _info(f"  parallelism = {cfg['argon2id']['parallelism']}")
    _warn("新参数仅影响后续加密, 已有密文不受影响")


def main():
    parser = argparse.ArgumentParser(
        prog="zhcrypt",
        description="中文加密系统 v3.0 - 支持签名+PFS+流式加密",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
示例:
  zhcrypt init                     初始化身份
  zhcrypt encrypt-file doc.pdf     流式加密文件
  zhcrypt backup default           备份私钥 (5份额)
  zhcrypt restore default          恢复私钥
  zhcrypt strength <password>      测试密码强度
        """),
    )

    sub = parser.add_subparsers(dest="command", help="子命令")

    p_init = sub.add_parser("init", help="初始化身份, 生成 RSA+Ed25519+X25519 密钥对")
    p_init.add_argument("identity", nargs="?", default="default", help="身份名称")
    p_init.add_argument("-c", "--comment", default="", help="备注")

    p_list = sub.add_parser("list", help="列出所有身份")

    p_enc = sub.add_parser("encrypt", help="加密文本 (密码/混合/签名模式)")
    p_enc.add_argument("text", nargs="?", default=None, help="要加密的文本")
    p_enc.add_argument("-o", "--output", default=None, help="输出文件路径")
    p_enc.add_argument("-t", "--to", default=None, help="接收方身份 (混合模式)")
    p_enc.add_argument("-s", "--sender", default=None, help="发送方身份 (签名)")
    p_enc.add_argument("--sign", action="store_true", default=False,
                       help="使用数字签名 (需要发送方身份)")
    p_enc.add_argument("--temp-share", action="store_true", default=False,
                       help="生成一次性密码分享")

    p_dec = sub.add_parser("decrypt", help="解密文本 (自动识别模式)")
    p_dec.add_argument("ciphertext", nargs="?", default=None, help="Base64 密文")
    p_dec.add_argument("-o", "--output", default=None, help="输出文件路径")
    p_dec.add_argument("-s", "--sender", default=None, help="接收方/自己的身份")

    p_ef = sub.add_parser("encrypt-file", help="加密文件 (流式)")
    p_ef.add_argument("file", help="要加密的文件路径")
    p_ef.add_argument("-o", "--output", default=None, help="输出文件路径")
    p_ef.add_argument("--legacy", action="store_true", help="使用传统全量模式 (非流式)")

    p_df = sub.add_parser("decrypt-file", help="解密文件")
    p_df.add_argument("file", help="要解密的文件路径")
    p_df.add_argument("-o", "--output", default=None, help="输出文件路径")
    p_df.add_argument("--overwrite", action="store_true", help="覆盖已存在文件")

    p_export = sub.add_parser("export", help="导出 RSA 公钥 (Base64, 旧版)")
    p_export.add_argument("identity", nargs="?", default="default", help="身份名称")

    p_import = sub.add_parser("import", help="导入 RSA 公钥 (旧版)")
    p_import.add_argument("b64key", help="Base64 公钥")
    p_import.add_argument("name", help="为该公钥指定的名称")

    p_export_bundle = sub.add_parser("export-bundle",
                                     help="导出完整公钥束 (RSA+Ed25519+X25519)")
    p_export_bundle.add_argument("identity", nargs="?", default="default",
                                 help="身份名称")

    p_import_bundle = sub.add_parser("import-bundle",
                                     help="导入完整公钥束")
    p_import_bundle.add_argument("bundle", help="公钥束 (Base64 JSON)")
    p_import_bundle.add_argument("name", help="为该身份指定的名称")

    p_del = sub.add_parser("delete", help="删除身份")
    p_del.add_argument("identity", help="要删除的身份名称")

    p_info = sub.add_parser("info", help="显示系统信息")

    p_ss = sub.add_parser("set-server", help="配置 prekey 服务器地址")
    p_ss.add_argument("url", help="服务器 URL (如 https://[REDACTED_IP])")
    p_ss.add_argument("--token", default="", help="API 鉴权 Token")

    p_upload = sub.add_parser("upload-prekey", help="上传 prekey 到服务器")
    p_upload.add_argument("identity", nargs="?", default="default", help="身份名称")
    p_upload.add_argument("--count", type=int, default=50,
                          help="One-time prekey 数量")
    p_upload.add_argument("--dry-run", action="store_true",
                          help="仅显示不上传")

    p_enc_s = sub.add_parser("encrypt-signed", help="带签名的混合加密")
    p_enc_s.add_argument("text", nargs="?", default=None, help="明文")
    p_enc_s.add_argument("-o", "--output", default=None, help="输出文件")
    p_enc_s.add_argument("-t", "--to", required=True, help="接收方身份")
    p_enc_s.add_argument("-s", "--sender", default="default", help="发送方身份")

    p_backup = sub.add_parser("backup", help="备份私钥 (Shamir 5-of-3 份额)")
    p_backup.add_argument("identity", nargs="?", default="default", help="身份名称")

    p_restore = sub.add_parser("restore", help="从份额恢复私钥")
    p_restore.add_argument("identity", nargs="?", default="default", help="身份名称")

    p_strength = sub.add_parser("strength", help="测试密码强度")
    p_strength.add_argument("password", nargs="?", default=None, help="要测试的密码")

    p_params = sub.add_parser("set-params", help="设置 Argon2id 加密参数")
    p_params.add_argument("--time", type=int, default=None, help="时间成本 (默认 4)")
    p_params.add_argument("--mem", type=int, default=None, help="内存成本 MB (默认 256)")
    p_params.add_argument("--par", type=int, default=None, help="并行度 (默认 4)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    commands = {
        "init": cmd_init,
        "list": cmd_list,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "encrypt-file": cmd_encrypt_file,
        "decrypt-file": cmd_decrypt_file,
        "export": cmd_export,
        "import": cmd_import,
        "export-bundle": cmd_export_bundle,
        "import-bundle": cmd_import_bundle,
        "delete": cmd_delete,
        "info": cmd_info,
        "set-server": cmd_set_server,
        "upload-prekey": cmd_upload_prekey,
        "encrypt-signed": cmd_encrypt_signed,
        "backup": cmd_backup,
        "restore": cmd_restore,
        "strength": cmd_strength,
        "set-params": cmd_set_params,
    }

    cmd = commands.get(args.command)
    if cmd:
        cmd(args)


if __name__ == "__main__":
    main()
