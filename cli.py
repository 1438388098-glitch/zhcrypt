#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt — 中文加密系统 CLI
===========================
基于 Argon2id + AES-256-GCM + RSA-4096 + X3DH/Double Ratchet
"""

import os
import sys
import re
import time
import struct
import secrets
import threading
import argparse
import getpass
import textwrap
import datetime

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1)
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
LIBDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
if os.path.isdir(LIBDIR):
    sys.path.insert(0, LIBDIR)

from core import (
    __version__,
    encrypt_password_mode, decrypt_password_mode,
    packet_to_b64, b64_to_packet,
    encrypt_file_password_mode, decrypt_file_password_mode,
    encrypt_file_stream, decrypt_file_stream,
    DecryptionError, MAGIC, MODE_PASSWORD, MODE_HYBRID,
    encrypt_hybrid, decrypt_hybrid,
    encrypt_hybrid_signed, decrypt_hybrid_signed,
    MODE_HYBRID_SIGNED, VERSION_V2,
)
from keys import KeyStore
from config import load, save, set_prekey_server, get_prekey_server, get_auth_token, set_cert_pin

# ── Terminal Graphics ─────────────────────────────────────────────

S = type("S", (), {
    "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "BLUE": "\033[94m", "MAGENTA": "\033[95m", "CYAN": "\033[96m",
    "BOLD": "\033[1m", "DIM": "\033[2m", "RESET": "\033[0m",
    "GRAY": "\033[38;5;245m",
})()

W = 58

def _err(msg):
    print(f"  {S.RED}错误{S.RESET}  {msg}", file=sys.stderr)
    sys.exit(1)

def _ok(msg):
    print(f"  {S.GREEN}成功{S.RESET}  {msg}")

def _warn(msg):
    print(f"  {S.YELLOW}警告{S.RESET}  {msg}")

def _info(msg):
    print(f"  {S.CYAN}信息{S.RESET}  {msg}")

def _dim(msg):
    print(f"  {S.GRAY}{msg}{S.RESET}")

def _header(msg):
    print(f"\n  {S.BOLD}{S.CYAN}── {msg}{S.RESET}")

def _sep():
    print(f"  {S.GRAY}{'─'*W}{S.RESET}")

def _kv(k, v):
    print(f"  {S.DIM}{k}:{S.RESET} {v}")

def _panel(title, body_lines, color=S.CYAN):
    tl = f"{S.BOLD}{color}┌─ {title} "
    pad = W - len(title) - 4
    print(f"{tl}{'─' * max(0, pad)}┐{S.RESET}")
    for line in body_lines:
        print(f"  {color}│{S.RESET} {line}")
    print(f"  {S.GRAY}└{'─' * (W-2)}┘{S.RESET}")

def _card(title, items, color=S.CYAN):
    print(f"\n  {S.BOLD}{color}◆ {title}{S.RESET}")
    for k, v in items:
        print(f"    {S.DIM}{k}:{S.RESET} {v}")

def _tree(roots):
    for i, (label, val, children) in enumerate(roots):
        prefix = "└─" if i == len(roots)-1 else "├─"
        print(f"  {S.GRAY}{prefix}{S.RESET} {S.CYAN}{label}{S.RESET} {val}")
        if children:
            for j, (cl, cv) in enumerate(children):
                cpref = "   └─" if j == len(children)-1 else "   ├─"
                print(f"  {S.GRAY}{cpref}{S.RESET} {S.DIM}{cl}:{S.RESET} {cv}")

def _bar(score, total=5, length=20):
    fill = int((score / total) * length) if total else 0
    colors = [S.RED, S.YELLOW, S.GREEN, S.GREEN]
    c = colors[min(score, len(colors)-1)] if score > 0 else S.GRAY
    bar = f"{c}{'█' * fill}{S.GRAY}{'░' * (length - fill)}{S.RESET}"
    return f"{bar}  {score}/{total}"

def _prompt_passphrase(prompt="密码: ", confirm=True):
    # R11: 非交互管道下 Windows getpass 等待控制台按键会无限挂起;
    # 检测非 tty 时改读 stdin 行 (脚本场景接受回显)。
    def _read_line():
        line = sys.stdin.readline()
        if not line:
            _err("stdin 已关闭, 无法读取密码")
            raise SystemExit(1)
        return line.rstrip("\r\n")

    interactive = sys.stdin.isatty()
    if interactive:
        pwd = getpass.getpass(f"  {S.BOLD}▶{S.RESET} {prompt}")
    else:
        pwd = _read_line()
    if not pwd:
        _err("密码不能为空")
    from strength import get_strength
    s = get_strength(pwd)
    if s["warnings"]:
        for w in s["warnings"]:
            _warn(w)
    level_map = {"weak": "弱", "medium": "中", "strong": "强", "very_strong": "极强"}
    _info(f"密码强度 {_bar(s['score'])}  {level_map.get(s['level'], '?')}  {s['entropy']:.0f} bits")
    if s["level"] == "weak" and len(pwd.encode("utf-8")) < 12:
        _warn("密码过弱, 建议使用更长/更复杂的密码")
    if confirm:
        pwd2 = getpass.getpass(f"  {S.BOLD}▶{S.RESET} 确认密码: ") if interactive else _read_line()
        if pwd != pwd2:
            _err("两次输入的密码不一致")
    return pwd

# ── Spinner ─────────────────────────────────────────────────────────

class Spinner:
    chars = "|/-\\"
    def __init__(self, msg="处理中..."):
        self.msg = msg
        self._running = False
        self._thread = None

    def start(self):
        # R11: 非 tty (管道/重定向) 下 \r 动画只会刷屏污染输出, 跳过动画
        if not sys.stdout.isatty():
            self._running = False
            return self
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self):
        i = 0
        while self._running:
            sys.stdout.write(f"\r  {S.CYAN}{self.chars[i % len(self.chars)]}{S.RESET} {self.msg}  ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1

    def stop(self, ok=True):
        self._running = False
        if self._thread:
            self._thread.join()
            label = f"{S.GREEN}完成{S.RESET}" if ok else f"{S.RED}失败{S.RESET}"
            sys.stdout.write(f"\r  {label}  {self.msg}  \n")
            sys.stdout.flush()
        elif not sys.stdout.isatty():
            # R11: 非 tty 退化路径, 仅输出一行结论
            label = f"{S.GREEN}完成{S.RESET}" if ok else f"{S.RED}失败{S.RESET}"
            sys.stdout.write(f"  {label}  {self.msg}\n")
            sys.stdout.flush()

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop(ok=a[0] is None)


# ═══════════════════════════════════════════════════════════════════
#  CLI Commands
# ═══════════════════════════════════════════════════════════════════

def cmd_init(args):
    store = KeyStore()
    identity = args.identity or "default"
    comment = args.comment or ""
    print()
    _card("创建身份", [("名称", identity)])
    pwd = _prompt_passphrase("设置私钥密码: ")
    try:
        with Spinner("正在生成 RSA-4096 + Ed25519 + X25519 密钥..."):
            info = store.generate_identity(identity, pwd, comment)
        _sep()
        _panel("创建成功", [
            f"{S.GREEN}身份{S.RESET}    {identity}",
            f"{S.GREEN}指纹{S.RESET}    {info['fingerprint']}",
            f"{S.GREEN}密钥{S.RESET}    RSA-4096, Ed25519, X25519",
        ], S.GREEN)
    except FileExistsError as e:
        _err(str(e))

def cmd_list(args):
    store = KeyStore()
    identities = store.list_identities()
    if not identities:
        _info("暂无身份, 请先运行 init")
        return
    _sep()
    for id_ in identities:
        fp = id_['fingerprint']
        comment = id_['comment'] or ''
        created = id_['created'][:10] if id_['created'] else ''
        print(f"  {S.GREEN}{id_['identity']:<16}{S.RESET}"
              f" {S.DIM}{fp:<18}{S.RESET}"
              f" {S.GRAY}{comment:<20}{S.RESET}"
              f" {S.GRAY}{created}{S.RESET}")
    _sep()
    _dim(f"共 {len(identities)} 个身份")

def cmd_encrypt(args):
    text = args.text
    if not text:
        text = sys.stdin.read().strip()
        if not text:
            _err("请提供要加密的文本")

    if args.temp_share:
        # 审计 HIGH-1: 临时口令熵从 20^4(17.3 bit) 提升到 256^6(≈48 bit)
        from wordlist import TEMP_WORDS
        chosen = [secrets.choice(TEMP_WORDS) for _ in range(6)]
        temp_pwd = "·".join(chosen)
        packet = encrypt_password_mode(text, temp_pwd)
        b64 = packet_to_b64(packet)
        print()
        _panel("一次性口令", [
            f"  {S.GREEN}{temp_pwd}{S.RESET}"
        ], S.GREEN)
        _panel("密文", [b64], S.GRAY)
        _warn("此密码仅显示一次, 不会存储")
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
    with Spinner("正在加密..."):
        packet = encrypt_password_mode(text, pwd)
        b64 = packet_to_b64(packet)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(b64)
        _ok(f"密文已保存到: {args.output}")
    else:
        print()
        _panel("密文 (Base64)", [b64], S.CYAN)
        _dim("将此密文发送给持有相同密码的人以解密")

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
        print()
        _panel(f"混合加密 → {recipient}", [b64], S.GREEN)

def cmd_decrypt(args):
    ciphertext = args.ciphertext
    if not ciphertext:
        ciphertext = sys.stdin.read().strip()
        if not ciphertext:
            _err("请提供要解密的密文")
    try:
        packet = b64_to_packet(ciphertext)
    except Exception:
        _err("无效的 Base64 编码密文")

    mode = packet[5] if len(packet) > 5 else None

    if mode == MODE_PASSWORD:
        pwd = _prompt_passphrase("输入解密密码: ", confirm=False)
        with Spinner("正在解密..."):
            try:
                plaintext = decrypt_password_mode(packet, pwd)
            except DecryptionError as e:
                _err(str(e))
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(plaintext)
            _ok(f"明文已保存到: {args.output}")
        else:
            print()
            _panel("明文", [f"{S.GREEN}{plaintext}{S.RESET}"], S.GREEN)
    elif mode == MODE_HYBRID:
        _cmd_receive_hybrid(packet, args)
    else:
        _err(f"无法识别密文格式")

def _cmd_receive_hybrid(packet, args):
    store = KeyStore()
    identity = args.sender or "default"
    pwd = _prompt_passphrase(f"私钥密码 '{identity}': ", confirm=False)
    private_key_pem = store.load_private_key_pem(identity, pwd)
    try:
        plaintext = decrypt_hybrid(packet, private_key_pem, pwd)
    except DecryptionError as e:
        _err(str(e))
    if "\n" in plaintext:
        sender, _, msg = plaintext.partition("\n")
        sender = sender.replace("--sender=", "")
        _info(f"来自: {S.CYAN}{sender}{S.RESET}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(plaintext)
        _ok(f"明文已保存到: {args.output}")
    else:
        print()
        _panel("明文", [f"{S.GREEN}{plaintext}{S.RESET}"], S.GREEN)

def cmd_encrypt_file(args):
    filepath = args.file
    if not os.path.exists(filepath):
        _err(f"文件不存在: {filepath}")
    pwd = _prompt_passphrase("输入加密密码: ")
    from config import get
    from core import should_stream
    chunk_size = get("streaming.chunk_size", 65536)
    size = os.path.getsize(filepath)
    # R6: 阈值决策统一走 core.should_stream (原写死 64KiB, 与 GUI 10MB 不一致);
    # 两种路径自 3.1.x 起均输出流式格式, 差别仅在分块与内存占用。
    use_legacy = args.legacy or not should_stream(size)
    try:
        with Spinner("正在加密文件..."):
            if use_legacy:
                out = encrypt_file_password_mode(filepath, pwd, args.output)
                mode_str = "传统全量"
            else:
                out = encrypt_file_stream(filepath, pwd, args.output, chunk_size=int(chunk_size))
                mode_str = "流式分块"
        _sep()
        _card("加密完成", [
            ("文件", os.path.basename(out)),
            ("模式", mode_str),
            ("原始大小", f"{size:,} bytes"),
            ("加密大小", f"{os.path.getsize(out):,} bytes"),
        ], S.GREEN)
    except Exception as e:
        _err(str(e))

def cmd_decrypt_file(args):
    filepath = args.file
    if not os.path.exists(filepath):
        _err(f"文件不存在: {filepath}")
    pwd = _prompt_passphrase("输入解密密码: ", confirm=False)
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            _ = f.read(1)
            mode_byte = f.read(1)
    except Exception:
        _err("无法读取文件头")
    try:
        with Spinner("正在解密文件..."):
            if magic != b"ZHCR":
                out = decrypt_file_password_mode(filepath, pwd, args.output, args.overwrite)
            elif mode_byte == bytes([0x05]):
                out = decrypt_file_stream(filepath, pwd, args.output, args.overwrite)
            else:
                out = decrypt_file_password_mode(filepath, pwd, args.output, args.overwrite)
        _sep()
        _card("解密完成", [
            ("文件", os.path.basename(out)),
            ("输出路径", out),
        ], S.GREEN)
    except Exception as e:
        _err(str(e))

def cmd_export(args):
    store = KeyStore()
    identity = args.identity or "default"
    b64 = store.export_public_key_b64(identity)
    _panel(f"公钥 — {identity}", [b64], S.CYAN)
    _dim("将此公钥分享给要向你发送加密消息的人")

def cmd_import(args):
    store = KeyStore()
    try:
        path = store.import_public_key_b64(args.b64key, args.name)
        _ok(f"公钥已导入为身份 '{args.name}'")
    except Exception as e:
        _err(str(e))

def cmd_export_bundle(args):
    store = KeyStore()
    identity = args.identity or "default"
    try:
        bundle = store.export_public_key_bundle(identity)
        _panel(f"公钥束 — {identity}  (RSA + Ed25519 + X25519)", [bundle], S.CYAN)
    except Exception as e:
        _err(str(e))

def cmd_import_bundle(args):
    store = KeyStore()
    try:
        store.import_public_key_bundle(args.bundle, args.name)
        _ok(f"公钥束已导入为身份 '{args.name}'")
        _dim("包含: RSA-4096 + Ed25519 + X25519")
    except Exception as e:
        _err(str(e))

def cmd_delete(args):
    store = KeyStore()
    identity = args.identity
    # R5: 物理删除全部密钥 (私钥不可恢复) 前必须确认; -y 供脚本跳过
    if not getattr(args, "yes", False):
        answer = input(f"  将永久删除身份 '{identity}' 的全部密钥 (不可恢复)。\n"
                       f"  输入身份名以确认: ").strip()
        if answer != identity:
            _err("确认输入不匹配, 已取消")
            return
    try:
        removed = store.delete_identity(identity)
        for p in removed:
            _dim(f"已删除: {os.path.basename(p)}")
        _ok(f"身份 '{identity}' 已删除")
    except Exception as e:
        _err(str(e))

def cmd_info(args):
    store = KeyStore()
    identities = store.list_identities()
    _header(f"zhcrypt v{__version__}")
    _tree([
        ("密钥派生", f"{S.CYAN}Argon2id{S.RESET} (256 MB, RFC 9106)", []),
        ("对称加密", f"{S.CYAN}AES-256-GCM{S.RESET} (AEAD)", []),
        ("非对称加密", f"{S.CYAN}RSA-4096-OAEP-SHA512{S.RESET}", []),
        ("数字签名", f"{S.CYAN}Ed25519{S.RESET}", []),
        ("密钥交换", f"{S.CYAN}X25519{S.RESET}", []),
        ("前向安全", f"{S.CYAN}X3DH + Double Ratchet{S.RESET}", []),
    ])
    print()
    _kv("密钥存储", os.path.expanduser("~") + "\\.zhcrypt\\keys\\")
    if identities:
        print()
        _info(f"已注册身份 ({len(identities)})")
        for id_ in identities:
            print(f"     {S.GREEN}{id_['identity']:<16}{S.RESET} [{S.GRAY}{id_['fingerprint']}{S.RESET}]")

def cmd_set_server(args):
    url = args.url.rstrip("/")
    token = args.token or ""
    if not url.startswith("http"):
        _err("服务器地址必须以 http:// 或 https:// 开头")
    set_prekey_server(url, token)
    if getattr(args, "pin", None):
        set_cert_pin(args.pin)
        _ok(f"已启用证书固定: {args.pin}")
    _ok(f"Prekey 服务器已设置为: {url}")

def cmd_upload_prekey(args):
    import urllib.request
    import json as json_mod
    store = KeyStore()
    identity = args.identity or "default"
    url = get_prekey_server()
    if not url:
        _err("未配置 prekey 服务器, 请先运行 set-server")
    pwd = _prompt_passphrase(f"私钥密码 '{identity}': ", confirm=False)
    try:
        bundle = store.generate_prekey_bundle(identity, pwd, otp_count=args.count)
    except Exception as e:
        _err(f"生成 prekey 失败: {e}")
    if args.dry_run:
        _dim("预演 — 生成的 bundle (不上传):")
        for k, v in bundle.items():
            if isinstance(v, list):
                _info(f"{k}: [{len(v)} 个密钥]")
            else:
                _dim(f"  {k}: {str(v)[:60]}...")
        return
    with Spinner(f"正在上传到 {url}..."):
        try:
            body = json_mod.dumps(bundle).encode("utf-8")
            full_url = f"{url}/v1/prekey/{identity}"
            req = urllib.request.Request(full_url, data=body, headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {get_auth_token()}",
            }, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json_mod.loads(resp.read())
        except Exception as e:
            _err(f"上传失败: {e}")
    _ok("Prekey 上传成功")
    _kv("身份", identity)
    _kv("签名预密钥", "已存储")
    _kv("一次性预密钥", f"{len(bundle['one_time_prekeys'])} 个")

def cmd_encrypt_signed(args):
    store = KeyStore()
    text = args.text
    if not text:
        text = sys.stdin.read().strip()
    if not text:
        _err("请提供要加密的文本")
    receiver = args.to
    sender = args.sender or "default"
    if not receiver:
        _err("请指定接收方 (-t)")
    try:
        pub_pem = store.load_public_key(receiver)
        pwd = _prompt_passphrase(f"签名私钥密码 '{sender}': ", confirm=False)
        sign_priv_pem = store.load_signing_private_key_pem(sender, pwd)
        with Spinner("正在签名加密..."):
            packet = encrypt_hybrid_signed(text, pub_pem, sign_priv_pem, sender)
            b64 = packet_to_b64(packet)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(b64)
            _ok(f"签名密文已保存到: {args.output}")
        else:
            _panel(f"签名加密  {sender} → {receiver}", [b64], S.GREEN)
    except Exception as e:
        _err(str(e))

def cmd_decrypt_signed(args):
    store = KeyStore()
    ciphertext = args.ciphertext
    if not ciphertext:
        ciphertext = sys.stdin.read().strip()
    if not ciphertext:
        _err("请提供密文")
    try:
        packet = b64_to_packet(ciphertext)
    except Exception:
        _err("无效的 Base64 密文")
    mode = packet[5] if len(packet) > 5 else None
    if mode in (MODE_PASSWORD, MODE_HYBRID):
        cmd_decrypt(args)
        return
    elif mode == MODE_HYBRID_SIGNED:
        identity = args.sender or "default"
        pwd = _prompt_passphrase(f"私钥密码 '{identity}': ", confirm=False)
        try:
            priv_pem = store.load_private_key_pem(identity, pwd)
            result = decrypt_hybrid_signed(packet, priv_pem, pwd)
            print()
            _header(f"来自 {result['sender']} 的消息")
            if result['verified']:
                _ok("签名验证通过")
            else:
                _warn("签名验证失败或未签名")
            _sep()
            _panel("明文", [f"{S.GREEN}{result['plaintext']}{S.RESET}"], S.GREEN)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(result["plaintext"])
        except Exception as e:
            _err(str(e))
    else:
        _err(f"不支持的加密模式: {mode}")

def cmd_backup(args):
    from secretsharing import split_secret, format_share
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from keys import _validate_identity
    store = KeyStore()
    identity = args.identity or "default"
    # R4 修复: 身份名拼进备份文件路径, 必须过白名单 (此前 "../x" 可写 key_dir 外)
    try:
        _validate_identity(identity)
    except ValueError as e:
        _err(str(e))
        return
    pwd = _prompt_passphrase(f"私钥密码 '{identity}': ", confirm=False)
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
        _card("备份信息", [
            ("身份", identity),
            ("备份文件", backup_path),
            ("恢复命令", f"zhcrypt restore {identity}"),
        ], S.YELLOW)
        print()
        _panel("Shamir 份额 (3-of-5 可恢复)", [
            f"{S.GRAY}请将以下 5 个份额分散保存至不同位置{S.RESET}"
        ], S.YELLOW)
        _sep()
        for idx, hex_data in shares:
            share_text = format_share(identity, idx, hex_data)
            print(f"  {S.YELLOW}份额 {idx}{S.RESET}  {S.GRAY}{share_text}{S.RESET}")
        _sep()
    except Exception as e:
        _err(str(e))

def cmd_restore(args):
    from secretsharing import recover_secret, parse_share
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from keys import _validate_identity
    store = KeyStore()
    identity = args.identity or "default"
    # R4 修复: 同 cmd_backup —— 白名单校验防路径穿越
    try:
        _validate_identity(identity)
    except ValueError as e:
        _err(str(e))
        return
    backup_path = os.path.join(store.key_dir, f"{identity}.backup")
    if not os.path.exists(backup_path):
        _err(f"备份文件不存在: {backup_path}")
    _info(f"需要 3 个份额来恢复身份 '{identity}'")
    collected = []
    while len(collected) < 3:
        try:
            line = input(f"  {S.BOLD}▶{S.RESET} 份额 {len(collected)+1}: ").strip()
            if not line:
                break
            id_, idx, data = parse_share(line)
            if id_ != identity:
                _warn(f"份额属于 '{id_}', 请确认")
            collected.append((idx, data))
        except (ValueError, EOFError, KeyboardInterrupt) as e:
            _err(str(e))
    if len(collected) < 3:
        _err(f"需要 3 个份额, 只提供了 {len(collected)} 个")
    try:
        encrypt_key = recover_secret(collected, threshold=3)
        with open(backup_path, "rb") as f:
            data = f.read()
        if data[:4] != MAGIC:
            _err("备份文件格式错误")
        nonce = data[5:17]
        encrypted_pem = data[17:]
        aesgcm = AESGCM(encrypt_key)
        key_pem = aesgcm.decrypt(nonce, encrypted_pem, None)
        key_path = os.path.join(store.key_dir, f"{identity}.key")
        # R11 P0 修复(续): 恢复出的 PEM 必须重新以用户口令 Argon2id 包裹
        # 落盘 —— 原实现把裸 PEM 直接写进 .key, 与 _unwrap_key 的包裹格式
        # 不符, 恢复后一切解密仍 InvalidTag (备份功能整体不可用的第二层)。
        new_pwd = _prompt_passphrase(
            f"为恢复的身份 '{identity}' 设置新密码: ", confirm=True)
        from keys import _wrap_key_data, _restrict_private
        wrapped = _wrap_key_data(new_pwd, key_pem)
        with open(key_path, "wb") as f:
            f.write(wrapped)
        try:
            _restrict_private(key_path)
        except Exception:
            pass
        _ok("私钥已恢复!")
        _kv("路径", key_path)
    except Exception as e:
        # R11: InvalidTag 等 GCM 异常的 str() 为空串, 统一补类型名;
        # 认证失败专译为可读文案 (此前输出 "恢复失败: " 空消息)
        detail = str(e) or type(e).__name__
        if type(e).__name__ == "InvalidTag":
            detail = "认证失败 (份额/密码错误或备份文件损坏)"
        _err(f"恢复失败: {detail}")

def cmd_strength(args):
    from strength import get_strength
    if getattr(args, "stdin", False):
        # R3: 管道输入, 供脚本使用 (避免密码进 shell 历史)
        pwd = sys.stdin.readline().rstrip("\r\n")
        if not pwd:
            _err("--stdin 未收到密码输入")
            return
    elif args.password:
        pwd = args.password
    else:
        pwd = getpass.getpass(f"  {S.BOLD}▶{S.RESET} 输入要测试的密码: ")
    s = get_strength(pwd)
    level_map = {"weak": "弱", "medium": "中", "strong": "强", "very_strong": "极强"}
    level = level_map.get(s["level"], "?")
    print(f"\n  {S.BOLD}密码强度{S.RESET}")
    _sep()
    print(f"  {_bar(s['score'])}  {level}  {s['entropy']:.1f} bits")
    _sep()
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
        _card("Argon2id 参数", [
            ("时间成本", str(cfg['argon2id']['time_cost'])),
            ("内存成本", f"{cfg['argon2id']['memory_cost']/1024:.0f} MB"),
            ("并行度", str(cfg['argon2id']['parallelism'])),
        ], S.CYAN)
        _dim("使用 --time / --mem / --par 修改")
        return
    save(cfg)
    _ok("参数已更新")
    _kv("时间成本", str(cfg['argon2id']['time_cost']))
    _kv("内存成本", f"{cfg['argon2id']['memory_cost']/1024:.0f} MB")
    _kv("并行度", str(cfg['argon2id']['parallelism']))
    _warn("新参数仅影响后续加密, 已有密文不受影响")

def cmd_chat_safety(args):
    from config import get
    identity = args.identity or get("default_identity", "default")
    peer = args.peer
    passphrase = getpass.getpass(f"  {S.BOLD}▶{S.RESET} [{identity}] 私钥密码: ")
    from chat_client import ChatClient
    client = ChatClient(identity, passphrase)
    result = client.get_safety_number(peer)
    if isinstance(result, dict) and "safety_number" in result:
        _panel(f"与 {peer} 的安全识别码", [result['safety_number']], S.YELLOW)
        _warn("请通过电话/当面等带外方式比对是否一致")
        _warn("若不一致可能遭到中间人攻击, 请勿发送敏感信息!")
    else:
        _warn(f"尚未与 '{peer}' 建立会话")
        _info("先发送一条消息完成首次握手, 再查看安全识别码")

def cmd_cert_pin(args):
    from urllib.parse import urlparse
    from certpin import fetch_cert_pin
    parsed = urlparse(args.url)
    if parsed.scheme not in ("https", "wss"):
        _err("请提供 https:// 或 wss:// 地址")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 443)
    with Spinner(f"正在获取 {host}:{port} 的证书..."):
        try:
            pin = fetch_cert_pin(host, port, server_name=host)
        except Exception as e:
            _err(f"获取证书指纹失败: {e}")
    _ok(f"服务器 {host}:{port} 的证书固定指纹")
    print(f"  {S.GREEN}{pin}{S.RESET}")
    _dim(f"添加到配置: zhcrypt set-server {args.url} --pin {pin}")

def _ensure_identity(identity):
    """确保本地身份存在; 不存在则引导全新用户交互式创建。

    返回 (identity, passphrase) 或 None (用户取消)。
    """
    from keys import KeyStore
    store = KeyStore()
    exists = False
    try:
        store.load_public_key(identity)
        exists = True
    except Exception:
        exists = False
    if exists:
        passphrase = getpass.getpass(f"  {S.BOLD}▶{S.RESET} [{identity}] 私钥密码: ")
        return identity, passphrase

    # 本机已有其他身份: 列出供选择, 而不是静默创建新身份
    local_ids = []
    try:
        for it in store.list_identities():
            nm = it.get("identity", "")
            if nm and nm != identity:
                local_ids.append(nm)
    except Exception:
        pass
    if local_ids:
        print()
        _panel("身份不存在", [
            f"默认身份 [{identity}] 在本机不存在。",
            f"本机已有身份: {', '.join(local_ids)}",
        ], S.YELLOW)
        ans = input(f"  {S.BOLD}▶{S.RESET} 输入要使用的身份名 (回车创建新身份): ").strip()
        if ans and ans in local_ids:
            identity = ans
            passphrase = getpass.getpass(f"  {S.BOLD}▶{S.RESET} [{identity}] 私钥密码: ")
            return identity, passphrase
        if ans and ans not in local_ids:
            identity = ans
    else:
        # 全新用户引导: 让用户起自己的名字, 而不是用陌生人的账号
        print()
        _panel("首次使用", [
            f"本机还没有任何身份。",
            "为了与他人端到端加密通信, 请创建一个属于你自己的身份。",
            "身份名相当于你的账号名, 朋友需要知道它才能与你通信。",
        ], S.CYAN)
        name = input(f"  {S.BOLD}▶{S.RESET} 你的身份名 (回车使用 {identity}): ").strip()
        identity = name or identity

    # 身份名白名单: 防路径穿越 + 便于 URL 传输
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", identity):
        _err(f"身份名不合法: 仅允许字母/数字/下划线/点/短横线/@, 最长 64 字符")
        return None
    print()
    pwd1 = getpass.getpass(f"  {S.BOLD}▶{S.RESET} 设置 [{identity}] 私钥密码: ")
    if not pwd1:
        _err("密码不能为空")
        return None
    pwd2 = getpass.getpass(f"  {S.BOLD}▶{S.RESET} 确认密码: ")
    if pwd1 != pwd2:
        _err("两次密码不一致")
        return None
    try:
        with Spinner("正在生成加密密钥 (RSA-4096 + Ed25519 + X25519)..."):
            store.generate_identity(identity, pwd1, comment="first-run")
    except FileExistsError:
        pass  # 并发创建, 视为成功
    except Exception as e:
        _err(f"创建身份失败: {e}")
        return None
    _ok(f"身份 [{identity}] 创建成功")
    # 注册后自动上传 prekey 一次: 好友/他人才能找到你
    try:
        from chat_client import ChatClient
        client = ChatClient(identity, pwd1)
        with Spinner("正在上传 prekey 到服务器..."):
            client.start()
            time.sleep(1)
            ok, msg = client.ensure_own_prekey()
        client.stop()
        if ok:
            _ok(f"prekey 已上传: {msg}")
        else:
            _warn(f"prekey 上传待重试: {msg}")
    except Exception as e:
        _warn(f"prekey 自动上传未完成 (进入 TUI 后会重试): {e}")
    return identity, pwd1


def cmd_chat_tui(args=None):
    """启动交互式 TUI 聊天 (轻量类微信, 聊天+文件)。

    设计: 一切操作 (登录/创建身份/prekey/加好友) 都在 TUI 界面内完成,
    命令行只负责把用户带进界面。
    """
    from config import get
    identity = args.identity if args else None
    identity = identity or get("default_identity", "default")
    try:
        from tui import main as tui_main
    except ImportError as e:
        _err(f"TUI 依赖缺失: {e} (请安装 textual: pip install textual)")
        return 1
    try:
        # 密码/身份创建全部交给 TUI 登录屏处理
        return tui_main(identity)
    except KeyboardInterrupt:
        _ok("再见")
        return 0
    except Exception as e:
        # M18 修复: 顶层兜底, 崩溃不再整屏 traceback
        import traceback
        try:
            log_path = os.path.join(os.path.expanduser("~"), ".zhcrypt",
                                    "local", "tui.log")
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now()}] TUI 异常:\n")
                traceback.print_exc(file=f)
        except Exception:
            pass
        _err(f"聊天界面异常退出: {e} (详情见 ~/.zhcrypt/local/tui.log)")
        return 3

def cmd_chat_send(args):
    from config import get
    identity = args.identity or get("default_identity", "default")
    peer = args.peer
    passphrase = getpass.getpass(f"  {S.BOLD}▶{S.RESET} [{identity}] 私钥密码: ")
    from chat_client import ChatClient
    client = ChatClient(identity, passphrase)
    with Spinner("正在连接..."):
        client.start()
        time.sleep(1)
    if args.text:
        text = args.text
    else:
        text = input(f"  {S.BOLD}▶{S.RESET} 消息: ")
    result = client.send_chat_message(peer, text)
    if result.get("error"):
        _err(result["error"])
    elif result.get("first_contact"):
        sn = result.get("safety_number", "")
        _warn("首次与此联系人建立端到端加密会话!")
        _panel("安全识别码", [sn], S.YELLOW)
        _warn("请与对方带外核对安全识别码是否一致")
        _ok(f"已发送 (id={result.get('msg_id', '?')[:8]}...)")
    else:
        _ok(f"已发送 (id={result.get('msg_id', '?')[:8]}...)")
    client.stop()

def cmd_chat_poll(args):
    from config import get
    identity = args.identity or get("default_identity", "default")
    passphrase = getpass.getpass(f"  {S.BOLD}▶{S.RESET} [{identity}] 私钥密码: ")
    from chat_client import ChatClient
    client = ChatClient(identity, passphrase)
    with Spinner("正在连接..."):
        client.start()
        time.sleep(0.5)
    items = client.process_inbound()
    for item in items:
        if item.get("action") == "status":
            status = f"{S.GREEN}已连接{S.RESET}" if item.get("connected") else f"{S.RED}未连接{S.RESET}"
            _info(f"WebSocket {status}")
        elif item.get("action") == "server_message":
            data = item["data"]
            if data.get("type") == "message":
                result = client.receive_chat_message(data["msg"])
                if result and "error" not in result:
                    ts = datetime.datetime.fromtimestamp(result["timestamp"]).strftime("%H:%M")
                    label = f" {S.GREEN}[已验证]{S.RESET}" if result.get("verified") else ""
                    print(f"  {S.CYAN}[{result['from']}]{S.RESET} {result['text']}{label}")
                elif result and "error" in result:
                    _warn(f"({result['error']})")
    polls = client.poll_messages()
    for r in polls:
        if "error" not in r:
            ts = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M")
            label = f" {S.GREEN}[已验证]{S.RESET}" if r.get("verified") else ""
            print(f"  {S.CYAN}[{r['from']}]{S.RESET} {r['text']}{label}")
    if not items and not polls:
        _info("暂无新消息")
    client.stop()

def cmd_chat_history(args):
    from config import get
    identity = args.identity or get("default_identity", "default")
    peer = args.peer
    passphrase = getpass.getpass(f"  {S.BOLD}▶{S.RESET} [{identity}] 私钥密码: ")
    from chat_client import ChatClient
    client = ChatClient(identity, passphrase)
    with Spinner("正在连接..."):
        client.start()
        time.sleep(0.5)
    msgs = client.get_history(peer, limit=args.limit or 50)
    if not msgs:
        _info("无历史消息")
        client.stop()
        return
    _header(f"与 {peer} 的聊天记录")
    _sep()
    for r in msgs:
        if "error" in r:
            _warn(f"(跳过: {r['error']})")
            continue
        ts = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%m-%d %H:%M")
        label = f" {S.GREEN}已验证{S.RESET}" if r.get("verified") else ""
        who = f"{S.CYAN}{r['from']}{S.RESET}" if r['from'] != identity else f"{S.GREEN}你{S.RESET}"
        print(f"  {S.GRAY}[{ts}]{S.RESET} {who}: {r['text']}{label}")
    _sep()
    client.stop()

def cmd_chat_status(args):
    from config import get
    identity = args.identity or get("default_identity", "default")
    from session import list_sessions
    sessions = list_sessions(identity)
    if not sessions:
        _info(f"[{identity}] 暂无活跃会话")
    else:
        _card(f"会话列表 — {identity}", [
            (s['peer'], f"最后活跃: {datetime.datetime.fromtimestamp(s['mtime']).strftime('%Y-%m-%d %H:%M')}")
            for s in sessions
        ], S.CYAN)
        _dim(f"共 {len(sessions)} 个会话")

def cmd_chat_delete(args):
    from config import get
    identity = args.identity or get("default_identity", "default")
    peer = args.peer
    # R5: 删除会话前确认; -y 供脚本跳过
    if not getattr(args, "yes", False):
        answer = input(f"  将删除与 {peer} 的加密会话 (需重新握手)。确认? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            _err("已取消")
            return
    from session import delete_session
    delete_session(identity, peer)
    _ok(f"已删除与 {peer} 的会话")


# ═══════════════════════════════════════════════════════════════════
#  PATH Installation
# ═══════════════════════════════════════════════════════════════════

def cmd_install_path(args):
    """将 zhcrypt 目录添加到系统 PATH 环境变量"""
    zhcrypt_dir = os.path.dirname(os.path.abspath(__file__))
    bat_path = os.path.join(zhcrypt_dir, "zhcrypt.bat")
    if not os.path.exists(bat_path):
        _err(f"找不到 {bat_path}")
    import subprocess
    ps_code = '''
$dir = "%s"
$current = [Environment]::GetEnvironmentVariable("Path", "User")
if ($current -split ";" -notcontains $dir) {
    [Environment]::SetEnvironmentVariable("Path", "$current;$dir", "User")
    Write-Output "added"
} else {
    Write-Output "exists"
}
''' % zhcrypt_dir
    try:
        r = subprocess.Popen(["powershell", "-Command", ps_code],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = r.communicate(timeout=15)
        out_text = out.decode("utf-8", errors="replace").strip()
        err_text = err.decode("utf-8", errors="replace").strip()
        if err_text:
            _info(err_text)
        if r.returncode == 0:
            if "added" in out_text:
                _ok("zhcrypt 已添加到 PATH，重启终端后可直接使用 zhcrypt 命令")
            else:
                _ok("zhcrypt 已在 PATH 中")
                _info("如果 zhcrypt 仍不可用，请重启终端或手动添加:")
                _dim('  setx PATH "%%PATH%%;' + zhcrypt_dir + '"')
        else:
            _err("添加 PATH 失败: %s" % (err_text or "未知错误"))
    except Exception as e:
        _err("执行失败: %s" % e)


# ═══════════════════════════════════════════════════════════════════
#  Interactive TUI Shell
# ═══════════════════════════════════════════════════════════════════

def _shell_help():
    sep = "─" * 48
    return f"""
  {S.BOLD}{S.CYAN}zhcrypt v{__version__}{S.RESET}  交互式 Shell
  {S.GRAY}{sep}{S.RESET}

  {S.BOLD}身份{S.RESET}
    {S.GREEN}init{S.RESET}            创建新身份
    {S.GREEN}list{S.RESET}            列出所有身份
    {S.GREEN}delete{S.RESET}          删除身份
    {S.GREEN}info{S.RESET}            系统信息

  {S.BOLD}加解密{S.RESET}
    {S.GREEN}encrypt{S.RESET}         加密文本
    {S.GREEN}decrypt{S.RESET}         解密文本
    {S.GREEN}encrypt-file{S.RESET}    加密文件
    {S.GREEN}decrypt-file{S.RESET}    解密文件
    {S.GREEN}encrypt-signed{S.RESET}  签名 + 加密

  {S.BOLD}密钥 / 服务器{S.RESET}
    {S.GREEN}export{S.RESET}          导出公钥
    {S.GREEN}import{S.RESET}          导入公钥
    {S.GREEN}export-bundle{S.RESET}   导出公钥束
    {S.GREEN}import-bundle{S.RESET}   导入公钥束
    {S.GREEN}set-server{S.RESET}      配置服务器
    {S.GREEN}upload-prekey{S.RESET}   上传 Prekey
    {S.GREEN}cert-pin{S.RESET}        证书指纹

  {S.BOLD}安全聊天{S.RESET}
    {S.GREEN}chat-send{S.RESET}       发送消息
    {S.GREEN}chat-poll{S.RESET}       检查新消息
    {S.GREEN}chat-history{S.RESET}    聊天记录
    {S.GREEN}chat-status{S.RESET}     会话状态
    {S.GREEN}chat-delete{S.RESET}     删除会话
    {S.GREEN}chat-safety{S.RESET}     安全识别码

  {S.BOLD}工具{S.RESET}
    {S.GREEN}strength{S.RESET}        密码强度测试
    {S.GREEN}set-params{S.RESET}      调整 Argon2id 参数
    {S.GREEN}backup{S.RESET}          私钥备份
    {S.GREEN}restore{S.RESET}         私钥恢复
    {S.GREEN}install-path{S.RESET}    添加到 PATH

  {S.BOLD}Shell{S.RESET}
    {S.GREEN}help{S.RESET}            显示此帮助
    {S.GREEN}exit{S.RESET} / {S.GREEN}quit{S.RESET}    退出
    {S.GREEN}clear{S.RESET}           清屏
"""

def _shell_header():
    print(f"""
  {S.BOLD}{S.CYAN}╔══════════════════════════════════════════╗{S.RESET}
  {S.BOLD}{S.CYAN}║      zhcrypt v{__version__}  交互式终端     ║{S.RESET}
  {S.BOLD}{S.CYAN}║      中文加密系统 · 输入 help 查看命令    ║{S.RESET}
  {S.BOLD}{S.CYAN}╚══════════════════════════════════════════╝{S.RESET}
""")

def cmd_shell(args=None):
    """交互式 TUI Shell — 类 Claude Code 体验"""
    _shell_header()
    try:
        import readline
    except ImportError:
        pass

    while True:
        try:
            line = input(f"  {S.BOLD}{S.CYAN}zhcrypt{S.RESET}{S.BOLD}❯{S.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            _ok("再见")
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        rest = parts[1:] if len(parts) > 1 else []

        if cmd in ("exit", "quit", "q"):
            _ok("再见")
            break
        elif cmd in ("help", "?", "h"):
            print(textwrap.dedent(_shell_help()))
        elif cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            _shell_header()
        else:
            _exec_shell_command(cmd, rest)

def _exec_shell_command(cmd, args_list):
    """在 shell 中执行一个命令（子进程复用完整 argparse）"""
    try:
        script = os.path.abspath(__file__)
        cmdline = [sys.executable, script, cmd] + args_list
        import subprocess
        subprocess.run(cmdline)
    except Exception as e:
        _err(f"执行失败: {e}")


# ═══════════════════════════════════════════════════════════════════
#  Main Entry
# ═══════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) == 1:
        cmd_shell()
        return


    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "init": cmd_init, "list": cmd_list, "shell": cmd_shell,
        "encrypt": cmd_encrypt, "decrypt": cmd_decrypt,
        "encrypt-file": cmd_encrypt_file, "decrypt-file": cmd_decrypt_file,
        "export": cmd_export, "import": cmd_import,
        "export-bundle": cmd_export_bundle, "import-bundle": cmd_import_bundle,
        "delete": cmd_delete, "info": cmd_info,
        "set-server": cmd_set_server, "upload-prekey": cmd_upload_prekey,
        "encrypt-signed": cmd_encrypt_signed, "backup": cmd_backup,
        "restore": cmd_restore, "strength": cmd_strength,
        "set-params": cmd_set_params,
        "chat-send": cmd_chat_send, "chat-poll": cmd_chat_poll,
        "chat-history": cmd_chat_history, "chat-status": cmd_chat_status,
        "chat-delete": cmd_chat_delete, "chat-safety": cmd_chat_safety,
        "cert-pin": cmd_cert_pin, "install-path": cmd_install_path,
        "chat": cmd_chat_tui,
    }
    fn = dispatch.get(args.command)
    if fn:
        try:
            rc = fn(args)
        except KeyboardInterrupt:
            print()
            _err("已取消")
            sys.exit(130)
        except (FileNotFoundError, ValueError, DecryptionError) as e:
            # R6: 常见业务异常映射为中文错误信息, 不再裸抛 traceback
            # (AGENTS.md 约定: 失败返回中文错误, 不抛异常)
            _err(str(e))
            sys.exit(1)
        except Exception as e:
            _err(f"执行失败: {e}")
            sys.exit(1)
        # R4 修复: 不再丢弃子命令退出码 —— 返回非零 int 的命令 (如 chat)
        # 以该码退出, 脚本调用方才能感知失败
        if isinstance(rc, int) and rc != 0:
            sys.exit(rc)

def build_parser():
    """构造顶层 argparse 解析器 (R6: 自 main 拆出, 便于测试与维护)。"""
    parser = argparse.ArgumentParser(
        prog="zhcrypt",
        description="zhcrypt - 中文端到端加密工具 (文件加密 / E2E 聊天 / Shamir 备份)",
        # R4 修复: 恢复顶层 -h/--help (此前 add_help=False 使 zhcrypt --help
        # 直接报错退出码 2, 新用户无入门路径)
    )
    parser.add_argument("-V", "--version", action="version",
                        version=f"zhcrypt {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init")
    p_init.add_argument("identity", nargs="?", default="default")
    p_init.add_argument("-c", "--comment", default="")

    sub.add_parser("list")
    sub.add_parser("shell")

    p_enc = sub.add_parser("encrypt")
    p_enc.add_argument("text", nargs="?", default=None)
    p_enc.add_argument("-o", "--output", default=None)
    p_enc.add_argument("-t", "--to", default=None)
    p_enc.add_argument("-s", "--sender", default=None)
    p_enc.add_argument("--sign", action="store_true", default=False)
    p_enc.add_argument("--temp-share", action="store_true", default=False)

    p_dec = sub.add_parser("decrypt")
    p_dec.add_argument("ciphertext", nargs="?", default=None)
    p_dec.add_argument("-o", "--output", default=None)
    p_dec.add_argument("-s", "--sender", default=None)

    p_ef = sub.add_parser("encrypt-file")
    p_ef.add_argument("file")
    p_ef.add_argument("-o", "--output", default=None)
    p_ef.add_argument("--legacy", action="store_true")

    p_df = sub.add_parser("decrypt-file")
    p_df.add_argument("file")
    p_df.add_argument("-o", "--output", default=None)
    p_df.add_argument("--overwrite", action="store_true")

    p_export = sub.add_parser("export")
    p_export.add_argument("identity", nargs="?", default="default")

    p_import = sub.add_parser("import")
    p_import.add_argument("b64key")
    p_import.add_argument("name")

    p_export_bundle = sub.add_parser("export-bundle")
    p_export_bundle.add_argument("identity", nargs="?", default="default")

    p_import_bundle = sub.add_parser("import-bundle")
    p_import_bundle.add_argument("bundle")
    p_import_bundle.add_argument("name")

    p_del = sub.add_parser("delete")
    p_del.add_argument("identity")
    p_del.add_argument("-y", "--yes", action="store_true",
                       help="跳过确认 (供脚本使用)")

    sub.add_parser("info")

    p_ss = sub.add_parser("set-server")
    p_ss.add_argument("url")
    p_ss.add_argument("--token", default="")
    p_ss.add_argument("--pin", default=None)

    p_upload = sub.add_parser("upload-prekey")
    p_upload.add_argument("identity", nargs="?", default="default")
    p_upload.add_argument("--count", type=int, default=50)
    p_upload.add_argument("--dry-run", action="store_true")

    p_enc_s = sub.add_parser("encrypt-signed")
    p_enc_s.add_argument("text", nargs="?", default=None)
    p_enc_s.add_argument("-o", "--output", default=None)
    p_enc_s.add_argument("-t", "--to", required=True)
    p_enc_s.add_argument("-s", "--sender", default="default")

    p_backup = sub.add_parser("backup")
    p_backup.add_argument("identity", nargs="?", default="default")

    p_restore = sub.add_parser("restore")
    p_restore.add_argument("identity", nargs="?", default="default")

    p_strength = sub.add_parser("strength")
    p_strength.add_argument("password", nargs="?", default=None,
                            help="[不建议] 明文密码会进入 shell 历史; "
                                 "省略此参数交互输入, 或用 --stdin")
    p_strength.add_argument("--stdin", action="store_true",
                            help="从 stdin 读取密码 (供脚本管道使用)")

    p_params = sub.add_parser("set-params")
    p_params.add_argument("--time", type=int, default=None)
    p_params.add_argument("--mem", type=int, default=None)
    p_params.add_argument("--par", type=int, default=None)

    p_chat = sub.add_parser("chat")
    p_chat.add_argument("-i", "--identity", default=None)

    p_chat_send = sub.add_parser("chat-send")
    p_chat_send.add_argument("text", nargs="?", default=None)
    p_chat_send.add_argument("-t", "--peer", required=True)
    p_chat_send.add_argument("-i", "--identity", default=None)

    p_chat_poll = sub.add_parser("chat-poll")
    p_chat_poll.add_argument("-i", "--identity", default=None)

    p_chat_history = sub.add_parser("chat-history")
    p_chat_history.add_argument("-t", "--peer", required=True)
    p_chat_history.add_argument("-i", "--identity", default=None)
    p_chat_history.add_argument("-n", "--limit", type=int, default=50)

    p_chat_status = sub.add_parser("chat-status")
    p_chat_status.add_argument("-i", "--identity", default=None)

    p_chat_delete = sub.add_parser("chat-delete")
    p_chat_delete.add_argument("-t", "--peer", required=True)
    p_chat_delete.add_argument("-i", "--identity", default=None)
    p_chat_delete.add_argument("-y", "--yes", action="store_true",
                               help="跳过确认 (供脚本使用)")

    p_chat_safety = sub.add_parser("chat-safety")
    p_chat_safety.add_argument("-t", "--peer", required=True)
    p_chat_safety.add_argument("-i", "--identity", default=None)

    p_cert_pin = sub.add_parser("cert-pin")
    p_cert_pin.add_argument("url")

    sub.add_parser("install-path")


    return parser

if __name__ == "__main__":
    main()
