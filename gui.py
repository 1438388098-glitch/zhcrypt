#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt GUI - 中文加密系统图形面板
基于 Tkinter + ttk, 无需额外安装
"""

import os
import sys
import time
import json
import base64
import threading

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
LIBDIR = os.path.join(BASE, "lib")
if os.path.isdir(LIBDIR):
    sys.path.insert(0, LIBDIR)

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from core import (
    encrypt_password_mode, decrypt_password_mode,
    encrypt_hybrid, decrypt_hybrid,
    packet_to_b64, b64_to_packet,
    encrypt_file_password_mode, decrypt_file_password_mode,
    encrypt_file_stream, decrypt_file_stream,
    should_stream, __version__,
    DecryptionError,
)
from keys import KeyStore

import tkinter.font as tkfont

# 高 DPI 清晰化：必须在创建 Tk() 之前声明 DPI 感知，否则高分屏上界面发虚
try:
    if sys.platform == "win32":
        from ctypes import windll
        try:
            windll.shcore.SetProcessDpiAwareness(2)  # 每显示器 DPI 感知
        except Exception:
            windll.user32.SetProcessDPIAware()
except Exception:
    pass



class ToolTip:
    """Tkinter 组件悬停提示框"""
    def __init__(self, widget, text, delay=400):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tip_window = None
        self._after_id = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)

    def _schedule(self, event=None):
        self._after_id = self.widget.after(self.delay, self._show)

    def _show(self):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_pointerx() + 10
        y = self.widget.winfo_pointery() + 10
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#f2f2f2", foreground="#222222",
                         relief=tk.SOLID, borderwidth=1,
                         font=("Microsoft YaHei", 9),
                         wraplength=380, padx=6, pady=4)
        label.pack()

    def _hide(self, event=None):
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


class StrengthBar(ttk.Frame):
    """密码强度指示条"""
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.canvas = tk.Canvas(self, width=120, height=14, bd=0, highlightthickness=0)
        self.canvas.pack()
        self.canvas.create_rectangle(0, 0, 120, 14, fill="#ddd", outline="")
        self._bar = self.canvas.create_rectangle(0, 0, 0, 14, fill="#ccc", outline="")
        self._label = self.canvas.create_text(60, 7, text="", font=("Microsoft YaHei", 8))
        self.set(0, "")

    def set(self, score, label):
        colors = ["#ddd", "#bbb", "#999", "#777", "#555", "#333"]
        widths = [0, 24, 48, 72, 96, 120]
        idx = max(0, min(score, 5))
        self.canvas.itemconfig(self._bar, fill=colors[idx], width=widths[idx])
        self.canvas.coords(self._bar, 0, 0, widths[idx], 14)
        self.canvas.itemconfig(self._label, text=label)


class ZhCryptGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"zhcrypt - 中文加密系统 v{__version__}")
        self.root.geometry("720x560")
        self.root.minsize(600, 440)

        try:
            self.root.iconbitmap()
        except Exception:
            pass

        self.style = ttk.Style()
        self.style.theme_use("clam")

        # 统一字体：全程序使用微软雅黑，提升中文清晰度与一致性
        try:
            tkfont.nametofont("TkDefaultFont").configure(family="Microsoft YaHei", size=9)
            tkfont.nametofont("TkTextFont").configure(family="Microsoft YaHei", size=9)
            tkfont.nametofont("TkFixedFont").configure(family="Consolas", size=9)
        except Exception:
            pass


        self.store = KeyStore()
        self._chat_client = None
        self._chat_peer = None
        self._chat_poll_id = None

        # ---- 统一「我是谁」：全局当前身份，各 tab 共享，不再各自设置 ----
        self.current_identity_var = tk.StringVar()
        self.chat_identity_var = self.current_identity_var
        self.hybrid_sender_var = self.current_identity_var
        self.cfg_pk_identity_var = self.current_identity_var

        self._build_menu()
        self._build_identity_bar()
        self._build_notebook()
        self._build_status_bar()
        self._refresh_identity_list()
        self._refresh_cfg_identities()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="初始化身份", command=self._on_init_identity)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._on_close)
        menubar.add_cascade(label="文件", menu=file_menu)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="聊天教程", command=self._on_help_chat)
        help_menu.add_command(label="混合加密教程", command=self._on_help_hybrid)
        help_menu.add_command(label="文件加密教程", command=self._on_help_file)
        help_menu.add_command(label="文本加密教程", command=self._on_help_text)
        help_menu.add_command(label="密钥管理教程", command=self._on_help_keys)
        help_menu.add_separator()
        help_menu.add_command(label="关于", command=self._on_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

    def _build_identity_bar(self):
        """统一的「我是谁」栏：全局当前身份，所有 tab 共享，切一处即全联动。"""
        bar = ttk.Frame(self.root)
        bar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=(5, 0))
        ttk.Label(bar, text="我是:").pack(side=tk.LEFT, padx=(0, 4))
        self.identity_combo = ttk.Combobox(bar, textvariable=self.current_identity_var,
                                           state="readonly", width=22)
        self.identity_combo.pack(side=tk.LEFT)
        self.identity_combo.bind("<<ComboboxSelected>>", self._on_identity_change)

    def _on_identity_change(self, event=None):
        """全局身份变更：断开旧聊天会话、刷新对方列表与前置检查。"""
        if self._chat_client:
            try:
                self._chat_client.stop()
            except Exception:
                pass
            self._chat_client = None
        if getattr(self, "_chat_watchdog_id", None):
            try:
                self.root.after_cancel(self._chat_watchdog_id)
            except Exception:
                pass
            self._chat_watchdog_id = None
        self._ever_connected = False
        self._cached_passphrase = {}
        self._chat_peer = None
        if hasattr(self, "chat_status_label"):
            self.chat_status_label.config(text="● 未连接", foreground="#999")
        self._refresh_chat_contacts()
        self._refresh_readiness()

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 0))

        self.tab_text = ttk.Frame(self.notebook)
        self.tab_file = ttk.Frame(self.notebook)
        self.tab_keys = ttk.Frame(self.notebook)
        self.tab_hybrid = ttk.Frame(self.notebook)
        self.tab_config = ttk.Frame(self.notebook)
        self.tab_chat = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_text, text=" 文本加解密 ")
        self.notebook.add(self.tab_file, text=" 文件加解密 ")
        self.notebook.add(self.tab_keys, text=" 密钥管理 ")
        self.notebook.add(self.tab_hybrid, text=" 混合模式 ")
        self.notebook.add(self.tab_config, text=" 系统配置 ")
        self.notebook.add(self.tab_chat, text="  聊天  ")

        self._build_text_tab()
        self._build_file_tab()
        self._build_keys_tab()
        self._build_hybrid_tab()
        self._build_config_tab()
        self._build_chat_tab()

    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="就绪")
        status = ttk.Label(self.root, textvariable=self.status_var,
                           relief=tk.SUNKEN, anchor=tk.W, padding=(8, 2))
        status.pack(side=tk.BOTTOM, fill=tk.X)

    def _set_status(self, text, duration=0):
        self.status_var.set(text)
        if duration > 0:
            self.root.after(duration, lambda: self.status_var.set("就绪"))

    def _make_password_frame(self, parent, text="密码"):
        """创建密码输入行 (标签 + 输入框 + 显示/隐藏按钮)"""
        frame = ttk.Frame(parent)
        ttk.Label(frame, text=f"{text}:").pack(side=tk.LEFT, padx=(0, 4))
        show_var = tk.BooleanVar(value=False)
        entry = ttk.Entry(frame, show="*")
        entry.pack(side=tk.LEFT, padx=(0, 4), fill=tk.X, expand=True)
        btn = ttk.Checkbutton(frame, text="显示", variable=show_var,
                              command=lambda: entry.config(
                                  show="" if show_var.get() else "*"))
        btn.pack(side=tk.LEFT)
        return frame, entry, show_var

    # ---- P1 辅助：前置检查条 / 联系人单源 ----
    def _set_pill(self, pill, label, ok):
        """前置检查条单个状态点（实用性）。"""
        pill.config(text=f"{label} {'[OK]' if ok else '[待处理]'}",
                    bg=("#E7F7EF" if ok else "#FFF6E0"),
                    fg=("#1FA971" if ok else "#8a6500"))

    def _load_contacts(self):
        """问题6 修复：联系人（对方公钥）单一来源。
        扫描 ~/.zhcrypt/keys/*.pub（排除我的 ed25519/x25519 公钥）。
        返回 [(identity, display_name), ...]；display_name 为本地备注, 可能为空。
        聊天下拉与密钥管理联系人区共用, 确保来源唯一。"""
        import os as _os
        peers = []
        try:
            d = _os.path.join(_os.path.expanduser("~"), ".zhcrypt", "keys")
            if _os.path.exists(d):
                for fn in _os.listdir(d):
                    if fn.endswith(".pub") and not fn.endswith(".ed25519.pub") \
                            and not fn.endswith(".x25519.pub"):
                        ident = fn[:-4]
                        if ident:
                            disp = self.store.get_contact_display_name(ident)
                            peers.append((ident, disp))
        except Exception:
            pass
        return sorted(set(peers), key=lambda x: (x[1] or x[0]).lower())

    # ============================================================
    # Tab 1: 文本加解密
    # ============================================================
    def _build_text_tab(self):
        main = ttk.Frame(self.tab_text, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="加密文本 (支持中文/英文/数字/Emoji)",
                  font=("", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))

        ttk.Label(main, text="输入明文:").pack(anchor=tk.W)
        text_input_frame = ttk.Frame(main)
        text_input_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 8))
        self.text_input_sb = ttk.Scrollbar(text_input_frame, orient=tk.VERTICAL)
        self.text_input = tk.Text(text_input_frame, height=8, wrap=tk.WORD,
                                  font=("Consolas", 10),
                                  yscrollcommand=self.text_input_sb.set)
        self.text_input_sb.config(command=self.text_input.yview)
        self.text_input_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        pwd_row = ttk.Frame(main)
        pwd_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(pwd_row, text="加密密码:").pack(side=tk.LEFT, padx=(0, 4))
        self.text_pwd_entry = ttk.Entry(pwd_row, width=20, show="*")
        self.text_pwd_entry.pack(side=tk.LEFT, padx=(0, 4))
        self.text_pwd_show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pwd_row, text="显示", variable=self.text_pwd_show_var,
                        command=lambda: self.text_pwd_entry.config(
                            show="" if self.text_pwd_show_var.get() else "*")
                        ).pack(side=tk.LEFT, padx=(0, 8))
        self.text_strength_bar = StrengthBar(pwd_row)
        self.text_strength_bar.pack(side=tk.LEFT, padx=(0, 4))
        self.text_pwd_entry.bind("<KeyRelease>", self._on_text_password_change)

        self.text_strength_label = ttk.Label(pwd_row, text="未检测", font=("Microsoft YaHei", 8))
        self.text_strength_label.pack(side=tk.LEFT)
        ToolTip(self.text_strength_bar,
                "密码强度实时评估。条越长、颜色越深表示越强\n(弱<30bits → 极强>80bits)\n每次密钥派生使用 Argon2id(256MB)")

        btn_row = ttk.Frame(main)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(btn_row, text="加密", command=self._on_text_encrypt).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="解密", command=self._on_text_decrypt).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="复制密文", command=self._on_copy_output).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="清空", command=self._on_clear_text).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="临时口令", command=self._on_temp_share).pack(side=tk.LEFT)
        ToolTip(btn_row.winfo_children()[-1],
                "生成随机中文词口令(4词组合)，加密后口令只显示一次。\n适合临时分享：将口令+密文分别发给对方。")

        ttk.Label(main, text="输出结果:").pack(anchor=tk.W)
        text_output_frame = ttk.Frame(main)
        text_output_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self.text_output_sb = ttk.Scrollbar(text_output_frame, orient=tk.VERTICAL)
        self.text_output = tk.Text(text_output_frame, height=6, wrap=tk.WORD,
                                   font=("Consolas", 10), bg="#f5f5f5",
                                   yscrollcommand=self.text_output_sb.set)
        self.text_output_sb.config(command=self.text_output.yview)
        self.text_output_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.text_sig_status = ttk.Label(main, text="", font=("Microsoft YaHei", 9))
        self.text_sig_status.pack(anchor=tk.W)

    def _on_text_password_change(self, event=None):
        pwd = self.text_pwd_entry.get()
        if not pwd:
            self.text_strength_bar.set(0, "")
            self.text_strength_label.config(text="未检测")
            return
        from strength import get_strength
        s = get_strength(pwd)
        level_map = {"weak": "弱", "medium": "中", "strong": "强", "very_strong": "极强"}
        score_map = {"weak": 1, "medium": 3, "strong": 4, "very_strong": 5}
        self.text_strength_bar.set(score_map.get(s["level"], 0),
                                   level_map.get(s["level"], ""))
        self.text_strength_label.config(
            text=f"{level_map.get(s['level'], '?')} ({s['entropy']:.0f} bits)")

    def _on_text_encrypt(self):
        plain = self.text_input.get("1.0", "end-1c").strip()
        if not plain:
            messagebox.showwarning("警告", "请输入要加密的文本")
            return
        pwd = self.text_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入加密密码")
            return
        try:
            def _work():
                packet = encrypt_password_mode(plain, pwd)
                return packet_to_b64(packet)

            def _done(b64):
                self.text_output.delete("1.0", tk.END)
                self.text_output.insert("1.0", b64)
                self.text_sig_status.config(text="")
                self._set_status(f"加密完成 (明文 {len(plain)} 字符 -> 密文 {len(b64)} 字符)", 6000)

            # R6: Argon2id 派生移入后台线程, 防主线程假死
            self._run_bg(_work, _done, busy_msg="正在加密 (Argon2id 派生中)...")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {e}")

    def _on_text_decrypt(self):
        cipher = self.text_input.get("1.0", "end-1c").strip()
        if not cipher:
            cipher = self.text_output.get("1.0", "end-1c").strip()
        if not cipher:
            messagebox.showwarning("警告", "请输入密文")
            return
        pwd = self.text_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入解密密码")
            return
        try:
            packet = b64_to_packet(cipher)
            mode = packet[5] if len(packet) > 5 else None

            if mode in (3, 4):
                # 问题5 修复：路由无关解密。混合格式密文统一引导到「混合模式」标签，
                # 自动复制密文并切换，不再让用户自己找入口。
                self._copy_to_clipboard(cipher)
                self.notebook.select(self.tab_hybrid)
                messagebox.showinfo("已切换解密入口",
                    "检测到这是【公钥·混合】密文，已为你切换到「混合模式」标签，\n"
                    "密文已复制到剪贴板，直接粘贴即可解密。")
                return
            else:
                def _work():
                    return decrypt_password_mode(packet, pwd)

                def _done(plain):
                    self.text_output.delete("1.0", tk.END)
                    self.text_output.insert("1.0", plain)
                    self.text_sig_status.config(text="")
                    self._set_status("解密成功", 6000)

                # R6: Argon2id 派生移入后台线程
                self._run_bg(_work, _done, busy_msg="正在解密 (Argon2id 派生中)...")
        except DecryptionError as e:
            messagebox.showerror("解密失败", str(e))
        except ValueError as e:
            messagebox.showerror("格式错误", str(e))
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {e}")

    def _decrypt_signed(self, packet, passphrase):
        try:
            from core import decrypt_hybrid_signed
            store_key = KeyStore()
            idents = store_key.list_identities()
            if not idents:
                raise DecryptionError("无可用身份")
            cur = self.current_identity_var.get()
            identity = cur if cur in [i["identity"] for i in idents] else idents[0]["identity"]
            priv_pem = store_key.load_private_key_pem(identity, passphrase)
            result = decrypt_hybrid_signed(packet, priv_pem, passphrase)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", result["plaintext"])
            if result["verified"]:
                self.text_sig_status.config(
                    text=f"签名验证通过 (来自: {result['sender']})")
            else:
                self.text_sig_status.config(
                    text=f"签名验证失败 (来自: {result['sender']})")
            self._set_status("解密成功", 6000)
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {e}")

    def _run_bg(self, work, on_done, on_error=None, busy_msg="处理中..."):
        """R6: 重活 (RSA-4096 / Argon2id) 放后台线程, 结果经 after() 回主线程。

        原实现文本/文件加解密与身份生成都在 Tk 主线程同步执行, 界面假死
        数十秒; 后台线程异常还会静默死亡, 这里统一兜底回调。
        """
        self._set_status(busy_msg, 0)

        def _worker():
            try:
                result = work()
            except Exception as e:
                self.root.after(0, lambda err=e: (
                    on_error(err) if on_error
                    else messagebox.showerror("错误", f"操作失败: {err}")))
                return
            self.root.after(0, lambda r=result: on_done(r))

        threading.Thread(target=_worker, daemon=True).start()

    def _contact_display(self, ident):
        """联系人显示备注缓存 (R6: 原实现对每个 peer 每次刷新都重读 meta)。"""
        cache = getattr(self, "_display_name_cache", None)
        if cache is None:
            cache = self._display_name_cache = {}
        if ident not in cache:
            try:
                cache[ident] = self.store.get_contact_display_name(ident) or ident
            except Exception:
                cache[ident] = ident
        return cache[ident]

    def _copy_to_clipboard(self, text, clear_after_ms=60000):
        """复制到剪贴板, 默认 60 秒后自动清空 (R3: 防明文/密文常驻剪贴板)。"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        if clear_after_ms:
            def _auto_clear():
                try:
                    if self.root.clipboard_get() == text:
                        self.root.clipboard_clear()
                except Exception:
                    pass  # 剪贴板被占用/内容已被替换时不必处理
            self.root.after(clear_after_ms, _auto_clear)

    def _on_copy_output(self):
        text = self.text_output.get("1.0", "end-1c").strip()
        if text:
            self._copy_to_clipboard(text)
            self._set_status("已复制到剪贴板 (60 秒后自动清空)", 3000)

    def _on_clear_text(self):
        self.text_input.delete("1.0", tk.END)
        self.text_output.delete("1.0", tk.END)
        self.text_sig_status.config(text="")

    def _on_temp_share(self):
        plain = self.text_input.get("1.0", "end-1c").strip()
        if not plain:
            messagebox.showwarning("警告", "请输入要加密的文本")
            return
        import secrets
        # 审计 HIGH-1: 临时口令熵从 20^4(17.3 bit) 提升到 256^6(≈48 bit)
        from wordlist import TEMP_WORDS
        chosen = [secrets.choice(TEMP_WORDS) for _ in range(6)]
        temp_pwd = "·".join(chosen)
        try:
            packet = encrypt_password_mode(plain, temp_pwd)
            b64 = packet_to_b64(packet)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0",
                f"┌─ 一次性口令 ─────────────────────┐\n"
                f"│  {temp_pwd}\n"
                f"└────────────────────────────────────┘\n\n"
                f"密文:\n{b64}")
            self.text_sig_status.config(
                text="此口令仅显示一次, 不会存储")
            self._set_status("临时口令已生成", 6000)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {e}")

    # ============================================================
    # Tab 2: 文件加解密
    # ============================================================
    def _build_file_tab(self):
        main = ttk.Frame(self.tab_file, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="文件加密 / 解密",
                  font=("", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))

        ttk.Label(main, text="选择文件:").pack(anchor=tk.W)
        pick_row = ttk.Frame(main)
        pick_row.pack(fill=tk.X, pady=(2, 4))
        self.file_path_var = tk.StringVar()
        ttk.Entry(pick_row, textvariable=self.file_path_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Button(pick_row, text="浏览...", command=self._on_browse_file).pack(side=tk.LEFT)

        pwd_frame, self.file_pwd_entry, _ = self._make_password_frame(main)
        pwd_frame.pack(anchor=tk.W, pady=(4, 8))

        btn_row = ttk.Frame(main)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(btn_row, text="加密文件", command=self._on_file_encrypt).pack(
            side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="解密文件", command=self._on_file_decrypt).pack(
            side=tk.LEFT, padx=(0, 6))

        ttk.Label(main, text="操作日志:").pack(anchor=tk.W)
        file_log_frame = ttk.Frame(main)
        file_log_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 0))
        self.file_log_sb = ttk.Scrollbar(file_log_frame, orient=tk.VERTICAL)
        self.file_log = tk.Text(file_log_frame, height=10, wrap=tk.WORD, font=("Consolas", 9),
                                bg="#f5f5f5", state=tk.DISABLED,
                                yscrollcommand=self.file_log_sb.set)
        self.file_log_sb.config(command=self.file_log.yview)
        self.file_log_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _file_log_append(self, text):
        self.file_log.config(state=tk.NORMAL)
        self.file_log.insert(tk.END, text + "\n")
        self.file_log.see(tk.END)
        self.file_log.config(state=tk.DISABLED)

    def _on_browse_file(self):
        path = filedialog.askopenfilename(title="选择文件")
        if path:
            self.file_path_var.set(path)

    def _on_file_encrypt(self):
        path = self.file_path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("警告", "请选择有效文件")
            return
        pwd = self.file_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入加密密码")
            return
        def _enc_work():
            src_size = os.path.getsize(path)
            # R6: 统一 should_stream 决策 (原 GUI 写死 10MB, CLI 写死 64KiB)
            if should_stream(src_size):
                out = encrypt_file_stream(path, pwd)
                return out, "流式分块"
            out = encrypt_file_password_mode(path, pwd)
            return out, "全量"

        def _enc_done(result):
            out, note = result
            self._file_log_append(f"  ({note})" if note != "流式分块" else "  (使用流式分块模式)")
            out_size = os.path.getsize(out)
            self._file_log_append(f"  -> {out} ({out_size:,} bytes)")
            self._set_status(f"加密完成: {os.path.basename(out)}", 8000)

        def _enc_error(e):
            self._file_log_append(f"  [错误] {e}")
            messagebox.showerror("错误", str(e))

        self._file_log_append(f"[加密] {path} ({os.path.getsize(path):,} bytes)")
        # R6: 移入后台线程
        self._run_bg(_enc_work, _enc_done, on_error=_enc_error,
                     busy_msg="正在加密文件 (Argon2id 派生中)...")

    def _on_file_decrypt(self):
        path = self.file_path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("警告", "请选择有效文件")
            return
        pwd = self.file_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入解密密码")
            return
        try:
            self._file_log_append(f"[解密] {path}")
            with open(path, "rb") as f:
                hdr = f.read(6)  # MAGIC(4) + VERSION(1) + MODE(1)

            if hdr[:4] != b"ZHCR":
                use_stream = False
            else:
                use_stream = hdr[5:6] == bytes([5])

            def _work():
                # R6: 统一走流式判定, 解密 (Argon2id 派生) 移入后台线程
                if use_stream:
                    return decrypt_file_stream(path, pwd, overwrite=False)
                return decrypt_file_password_mode(path, pwd, overwrite=False)

            def _done(out):
                self._file_log_append(f"  -> {out}")
                self._set_status(f"解密完成: {os.path.basename(out)}", 8000)

            def _error(e):
                if isinstance(e, FileExistsError):
                    if messagebox.askyesno("确认覆盖", "输出文件已存在，是否覆盖?"):
                        def _work2():
                            if use_stream:
                                return decrypt_file_stream(path, pwd, overwrite=True)
                            return decrypt_file_password_mode(path, pwd, overwrite=True)

                        def _done2(out):
                            self._file_log_append(f"  -> {out}")
                            self._set_status(f"解密完成: {os.path.basename(out)}", 8000)

                        self._run_bg(_work2, _done2, on_error=_error,
                                     busy_msg="正在解密 (Argon2id 派生中)...")
                    return
                self._file_log_append(f"  [错误] {e}")
                if isinstance(e, DecryptionError):
                    messagebox.showerror("解密失败", str(e))
                else:
                    messagebox.showerror("错误", str(e))

            self._run_bg(_work, _done, on_error=_error,
                         busy_msg="正在解密 (Argon2id 派生中)...")
        except Exception as e:
            self._file_log_append(f"  [错误] {e}")
            messagebox.showerror("错误", str(e))

    # ============================================================
    # Tab 3: 密钥管理
    # ============================================================
    def _build_keys_tab(self):
        main = ttk.Frame(self.tab_keys, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="密钥管理",
                  font=("", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))

        top_row = ttk.Frame(main)
        top_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(top_row, text="新建身份", command=self._on_init_identity).pack(
            side=tk.LEFT, padx=(0, 4))
        ttk.Button(top_row, text="删除选中身份", command=self._on_delete_identity).pack(
            side=tk.LEFT)
        ttk.Button(top_row, text="刷新列表", command=self._refresh_identity_list).pack(
            side=tk.RIGHT)

        columns = ("identity", "fingerprint", "comment", "created")
        tree_frame = ttk.Frame(main)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.tree_sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings",
                                 selectmode="browse", height=6,
                                 yscrollcommand=self.tree_sb.set)
        self.tree_sb.config(command=self.tree.yview)
        self.tree_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.heading("identity", text="身份")
        self.tree.heading("fingerprint", text="指纹")
        self.tree.heading("comment", text="备注")
        self.tree.heading("created", text="创建时间")
        self.tree.column("identity", width=100)
        self.tree.column("fingerprint", width=140)
        self.tree.column("comment", width=150)
        self.tree.column("created", width=180)

        export_import_frame = ttk.LabelFrame(main, text="公钥交换 (聊天用)", padding=8)
        export_import_frame.pack(fill=tk.X, pady=(0, 8))

        btn_row1 = ttk.Frame(export_import_frame)
        btn_row1.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(btn_row1, text="导出并复制公钥束",
                   command=self._on_export_bundle).pack(side=tk.LEFT)

        sep = ttk.Separator(export_import_frame, orient=tk.HORIZONTAL)
        sep.pack(fill=tk.X, pady=(0, 8))

        imp_paste_frame = ttk.Frame(export_import_frame)
        imp_paste_frame.pack(fill=tk.X, pady=(0, 4))
        self.import_paste_text = tk.Text(imp_paste_frame, height=2, wrap=tk.WORD,
                                          font=("Consolas", 8))
        self.import_paste_text.pack(fill=tk.X, expand=True)
        imp_bottom = ttk.Frame(export_import_frame)
        imp_bottom.pack(fill=tk.X)
        ttk.Label(imp_bottom, text="备注(仅本地显示, 可留空):").pack(side=tk.LEFT, padx=(0, 4))
        self.import_name_entry = ttk.Entry(imp_bottom, width=16)
        self.import_name_entry.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(imp_bottom, text="导入对方公钥束",
                   command=self._on_import_bundle).pack(side=tk.LEFT)

        # ---- 问题6：联系人（对方公钥）统一展示区 ----
        contact_frame = ttk.LabelFrame(main, text="联系人（对方公钥）", padding=8)
        contact_frame.pack(fill=tk.X, pady=(0, 8))
        cf = ttk.Frame(contact_frame)
        cf.pack(fill=tk.X)
        self.contact_listbox = tk.Listbox(cf, height=4, font=("Microsoft YaHei", 9))
        self.contact_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        cb_col = ttk.Frame(cf)
        cb_col.pack(side=tk.LEFT, fill=tk.Y)
        ttk.Button(cb_col, text="删除联系人", command=self._on_delete_contact).pack(pady=(0, 4))
        ttk.Button(cb_col, text="刷新", command=self._refresh_contact_list).pack()

    def _refresh_contact_list(self):
        try:
            self.contact_listbox.delete(0, tk.END)
            self._contact_idents = []
            for ident, disp in self._load_contacts():
                self.contact_listbox.insert(tk.END, disp or ident)
                self._contact_idents.append(ident)
        except Exception:
            pass

    def _on_delete_contact(self):
        sel = self.contact_listbox.curselection()
        if not sel:
            messagebox.showwarning("警告", "请先选择要删除的联系人")
            return
        ident = self._contact_idents[sel[0]]
        disp = self.contact_listbox.get(sel[0])
        if not messagebox.askyesno("确认删除",
                                   f"删除联系人 '{disp}' 的公钥？\n之后将无法向其加密，需重新导入。"):
            return
        import os as _os
        path = _os.path.join(_os.path.expanduser("~"), ".zhcrypt", "keys", ident + ".pub")
        try:
            if _os.path.exists(path):
                _os.remove(path)
            self._refresh_contact_list()
            self._refresh_chat_contacts()
            self._set_status(f"已删除联系人 '{name}'", 4000)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _refresh_identity_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        try:
            identities = self.store.list_identities()
            for id_ in identities:
                self.tree.insert("", tk.END, values=(
                    id_["identity"],
                    id_["fingerprint"],
                    id_["comment"],
                    id_["created"],
                ))
        except Exception as e:
            self._set_status(f"身份列表刷新失败: {e}", 3000)

    def _refresh_cfg_identities(self):
        try:
            ids = [id_["identity"] for id_ in self.store.list_identities()]
            self.identity_combo["values"] = ids
            cur = self.cfg_pk_identity_var.get()
            if not cur or cur not in ids:
                if ids:
                    self.cfg_pk_identity_var.set(ids[0])
        except Exception:
            pass
        self._refresh_chat_contacts()

    def _get_selected_identity(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("警告", "请先选择一个身份")
            return None
        return self.tree.item(sel[0], "values")[0]

    def _on_init_identity(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("创建新身份")
        dialog.geometry("360x220")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="身份名称:").pack(anchor=tk.W)
        name_entry = ttk.Entry(frame, width=30)
        name_entry.insert(0, "default")
        name_entry.pack(fill=tk.X, pady=(2, 8))

        ttk.Label(frame, text="备注 (可选):").pack(anchor=tk.W)
        comment_entry = ttk.Entry(frame, width=30)
        comment_entry.pack(fill=tk.X, pady=(2, 8))

        ttk.Label(frame, text="设置私钥密码:").pack(anchor=tk.W)
        pwd_entry = ttk.Entry(frame, width=30, show="*")
        pwd_entry.pack(fill=tk.X, pady=(2, 2))

        def do_init():
            name = name_entry.get().strip()
            pwd = pwd_entry.get()
            comment = comment_entry.get().strip()
            if not name or not pwd:
                messagebox.showwarning("警告", "名称和密码不能为空", parent=dialog)
                return
            import re as _re
            if not _re.match(r"^[a-zA-Z0-9\u4e00-\u9fff_-]+$", name):
                messagebox.showwarning("警告", "身份名只能包含字母、数字、中文、下划线或连字符", parent=dialog)
                return
            if len(pwd.encode("utf-8")) < 8:
                if not messagebox.askyesno("确认", "密码较短, 是否继续?", parent=dialog):
                    return

            # R6: RSA-4096 生成 + 多次 Argon2id 派生需数十秒, 移入后台线程
            def _work():
                return self.store.generate_identity(name, pwd, comment)

            def _done(info):
                self._refresh_identity_list()
                self._refresh_hybrid_identities()
                messagebox.showinfo("成功", f"身份 '{name}' 创建成功!\n指纹: {info['fingerprint']}",
                                    parent=dialog)
                dialog.destroy()

            def _error(e):
                messagebox.showerror("错误", str(e), parent=dialog)

            self._run_bg(_work, _done, on_error=_error,
                         busy_msg="正在生成密钥 (RSA-4096 + Argon2id, 需数十秒)...")
            return

        ttk.Button(frame, text="创建", command=do_init).pack(pady=(8, 0))

    def _on_delete_identity(self):
        identity = self._get_selected_identity()
        if not identity:
            return
        if not messagebox.askyesno("确认删除",
                                   f"确定要删除身份 '{identity}' 吗?\n私钥将永久丢失!"):
            return
        try:
            self.store.delete_identity(identity)
            self._refresh_identity_list()
            self._refresh_hybrid_identities()
            self._set_status(f"已删除身份 '{identity}'", 4000)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ============================================================
    # Tab 4: 混合模式
    # ============================================================
    def _build_hybrid_tab(self):
        main = ttk.Frame(self.tab_hybrid, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="混合加密模式 (RSA-4096 + AES-256-GCM)",
                  font=("", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))

        sender_frame = ttk.Frame(main)
        sender_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(sender_frame, text="接收方:").pack(side=tk.LEFT, padx=(0, 4))
        self.hybrid_receiver_var = tk.StringVar()
        self.hybrid_receiver_combo = ttk.Combobox(sender_frame,
                                                  textvariable=self.hybrid_receiver_var,
                                                  width=18, state="readonly")
        self.hybrid_receiver_combo.pack(side=tk.LEFT)

        ttk.Label(main, text="输入明文:").pack(anchor=tk.W)
        hybrid_input_frame = ttk.Frame(main)
        hybrid_input_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 6))
        self.hybrid_input_sb = ttk.Scrollbar(hybrid_input_frame, orient=tk.VERTICAL)
        self.hybrid_input = tk.Text(hybrid_input_frame, height=6, wrap=tk.WORD,
                                    font=("Consolas", 10),
                                    yscrollcommand=self.hybrid_input_sb.set)
        self.hybrid_input_sb.config(command=self.hybrid_input.yview)
        self.hybrid_input_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.hybrid_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        pwd_frame, self.hybrid_pwd_entry, _ = self._make_password_frame(
            main, "你的私钥密码")
        pwd_frame.pack(anchor=tk.W, pady=(0, 8))

        btn_row = ttk.Frame(main)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(btn_row, text="加密并发送", command=self._on_hybrid_encrypt).pack(
            side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="解密接收的密文", command=self._on_hybrid_decrypt).pack(
            side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="复制密文", command=self._on_hybrid_copy).pack(side=tk.LEFT)

        ttk.Label(main, text="密文输出:").pack(anchor=tk.W)
        hybrid_output_frame = ttk.Frame(main)
        hybrid_output_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 0))
        self.hybrid_output_sb = ttk.Scrollbar(hybrid_output_frame, orient=tk.VERTICAL)
        self.hybrid_output = tk.Text(hybrid_output_frame, height=6, wrap=tk.WORD,
                                     font=("Consolas", 10), bg="#f5f5f5",
                                     yscrollcommand=self.hybrid_output_sb.set)
        self.hybrid_output_sb.config(command=self.hybrid_output.yview)
        self.hybrid_output_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.hybrid_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # ============================================================
    # Tab 5: 系统配置 (新增)
    # ============================================================
    def _build_config_tab(self):
        from config import load as _cl, get_auth_token as _gat
        cfg = _cl()
        main = ttk.Frame(self.tab_config, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="Argon2id 加密参数",
                  font=("", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))

        frame_params = ttk.LabelFrame(main, text="密钥派生参数", padding=10)
        frame_params.pack(fill=tk.X, pady=(0, 10))

        row1 = ttk.Frame(frame_params)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="时间成本 (迭代):").pack(side=tk.LEFT)
        init_time = cfg.get("argon2id", {}).get("time_cost", 4)
        self.cfg_time_var = tk.IntVar(value=init_time)
        s_time = ttk.Scale(row1, from_=1, to=16, variable=self.cfg_time_var,
                           orient=tk.HORIZONTAL, length=200,
                           command=lambda v: self.cfg_time_label.config(text=str(int(float(v)))))
        s_time.pack(side=tk.LEFT, padx=8)
        self.cfg_time_label = ttk.Label(row1, text=str(init_time), width=3)
        self.cfg_time_label.pack(side=tk.LEFT)
        ToolTip(s_time, "Argon2id 迭代轮数。越高越安全但越慢。\n每增加一倍，暴力破解成本翻倍。推荐值: 4")

        row2 = ttk.Frame(frame_params)
        row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="内存成本 (MB):").pack(side=tk.LEFT)
        init_mem = cfg.get("argon2id", {}).get("memory_cost", 262144) // 1024
        self.cfg_mem_var = tk.IntVar(value=init_mem)
        s_mem = ttk.Scale(row2, from_=32, to=1024, variable=self.cfg_mem_var,
                          orient=tk.HORIZONTAL, length=200,
                          command=lambda v: self.cfg_mem_label.config(text=str(int(float(v)))))
        s_mem.pack(side=tk.LEFT, padx=8)
        self.cfg_mem_label = ttk.Label(row2, text=str(init_mem), width=4)
        self.cfg_mem_label.pack(side=tk.LEFT)
        ToolTip(s_mem, "Argon2id 内存用量(MB)。内存硬化抵抗 GPU 攻击。\n256MB 为推荐值。512MB 更安全但不明显增加解密时间。")

        row3 = ttk.Frame(frame_params)
        row3.pack(fill=tk.X, pady=4)
        ttk.Label(row3, text="并行度:").pack(side=tk.LEFT)
        self.cfg_par_var = tk.IntVar(value=4)
        s_par = ttk.Scale(row3, from_=1, to=16, variable=self.cfg_par_var,
                          orient=tk.HORIZONTAL, length=200,
                          command=lambda v: self.cfg_par_label.config(text=str(int(float(v)))))
        s_par.pack(side=tk.LEFT, padx=8)
        self.cfg_par_label = ttk.Label(row3, text="4", width=3)
        self.cfg_par_label.pack(side=tk.LEFT)
        ToolTip(s_par, "Argon2id 并行线程数。通常设为 CPU 核心数。\n不影响安全性，只影响计算速度。")

        ttk.Button(frame_params, text="应用参数", command=self._on_apply_params).pack(anchor=tk.W, pady=4)

        frame_prekey = ttk.LabelFrame(main, text="Prekey 服务器", padding=10)
        frame_prekey.pack(fill=tk.X, pady=(0, 10))

        row_url = ttk.Frame(frame_prekey)
        row_url.pack(fill=tk.X, pady=4)
        ttk.Label(row_url, text="URL:").pack(side=tk.LEFT)
        self.cfg_pk_url_var = tk.StringVar(value=cfg.get("prekey_server", {}).get("url", ""))
        entry_url = ttk.Entry(row_url, textvariable=self.cfg_pk_url_var, width=40)
        entry_url.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        ToolTip(entry_url, "Prekey 服务器 URL。用于前向安全(PFS)通信\n的临时公钥存储与分发。部署在阿里云 ECS。")

        row_token = ttk.Frame(frame_prekey)
        row_token.pack(fill=tk.X, pady=4)
        ttk.Label(row_token, text="Auth Token:").pack(side=tk.LEFT)
        self.cfg_pk_token_var = tk.StringVar(value=_gat())
        entry_token = ttk.Entry(row_token, textvariable=self.cfg_pk_token_var, width=40, show="*")
        entry_token.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        ToolTip(entry_token, "服务器认证令牌 (Auth Token)。与 URL 一起保存,\n本机用设备密钥加密存储;换机器/新环境需重新填写。")

        row_pk_btn = ttk.Frame(frame_prekey)
        row_pk_btn.pack(fill=tk.X, pady=4)
        ttk.Button(row_pk_btn, text="测试连接", command=self._on_test_prekey).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(row_pk_btn, text="保存配置", command=self._on_save_prekey).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(row_pk_btn, text="上传 Prekey", command=self._on_upload_prekey).pack(side=tk.LEFT)
        self.cfg_pk_status = ttk.Label(row_pk_btn, text="未连接")
        self.cfg_pk_status.pack(side=tk.LEFT, padx=12)

        frame_info = ttk.LabelFrame(main, text="系统信息", padding=10)
        frame_info.pack(fill=tk.X)
        info_text = f"版本: zhcrypt v{__version__}\nPython: {sys.version[:5]}"
        ttk.Label(frame_info, text=info_text).pack(anchor=tk.W)

    def _on_apply_params(self):
        from config import load, save
        cfg = load()
        cfg["argon2id"]["time_cost"] = self.cfg_time_var.get()
        cfg["argon2id"]["memory_cost"] = self.cfg_mem_var.get() * 1024
        cfg["argon2id"]["parallelism"] = self.cfg_par_var.get()
        save(cfg)
        self._set_status(f"参数已应用: time={cfg['argon2id']['time_cost']}, "
                         f"mem={cfg['argon2id']['memory_cost']/1024:.0f}MB, "
                         f"par={cfg['argon2id']['parallelism']}", 5000)

    def _on_test_prekey(self):
        import urllib.request, json as j, ssl as _ssl
        url = self.cfg_pk_url_var.get().rstrip("/")
        if not url:
            messagebox.showwarning("警告", "请输入 Prekey 服务器 URL")
            return
        if not url.startswith("https://") and not url.startswith("http://"):
            messagebox.showwarning("警告", "URL 格式不正确，应以 https:// 开头")
            return
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            req = urllib.request.Request(url + "/v1/health")
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                data = j.loads(resp.read())
            if data.get("status") == "ok":
                self.cfg_pk_status.config(text="已连接")
                self._set_status("Prekey 服务器连接正常", 4000)
            else:
                self.cfg_pk_status.config(text="响应异常")
        except Exception as e:
            self.cfg_pk_status.config(text="连接失败")
            messagebox.showerror("连接失败", str(e))

    def _on_save_prekey(self):
        from config import load, save, set_prekey_server
        url = self.cfg_pk_url_var.get().rstrip("/")
        if not url.startswith("https://") and not url.startswith("http://"):
            messagebox.showwarning("警告", "URL 格式不正确，应以 https:// 开头")
            return
        token = self.cfg_pk_token_var.get().strip()
        if token:
            set_prekey_server(url, token)
        else:
            set_prekey_server(url)
        self._set_status("Prekey 服务器配置已保存", 4000)

    def _refresh_hybrid_identities(self):
        try:
            identities = [id_["identity"] for id_ in self.store.list_identities()]
        except Exception:
            identities = []
        try:
            self.identity_combo["values"] = identities
            self.hybrid_receiver_combo["values"] = identities
        except Exception:
            pass
        if identities:
            if not self.hybrid_sender_var.get():
                self.hybrid_sender_var.set(identities[0])
        self._refresh_cfg_identities()

    def _on_hybrid_encrypt(self):
        sender = self.hybrid_sender_var.get()
        receiver = self.hybrid_receiver_var.get()
        if not sender or not receiver:
            messagebox.showwarning("警告", "请选择发送方和接收方身份")
            return
        plain = self.hybrid_input.get("1.0", "end-1c").strip()
        if not plain:
            messagebox.showwarning("警告", "请输入要加密的消息")
            return
        pwd = self.hybrid_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入你的私钥密码")
            return

        try:
            pub_pem = self.store.load_public_key(receiver)
            packet = encrypt_hybrid(f"--sender={sender}\n{plain}", pub_pem)
            b64 = packet_to_b64(packet)
            self.hybrid_output.delete("1.0", tk.END)
            self.hybrid_output.insert("1.0", b64)
            self._set_status(f"混合加密完成: {sender} -> {receiver}", 6000)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {e}")

    def _on_hybrid_decrypt(self):
        cipher = self.hybrid_input.get("1.0", "end-1c").strip()
        if not cipher:
            cipher = self.hybrid_output.get("1.0", "end-1c").strip()
        if not cipher:
            messagebox.showwarning("警告", "请在上方输入或粘贴密文")
            return
        sender = self.hybrid_sender_var.get()
        if not sender:
            messagebox.showwarning("警告", "请选择你的身份")
            return
        pwd = self.hybrid_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入你的私钥密码")
            return

        try:
            packet = b64_to_packet(cipher)
            private_pem = self.store.load_private_key_pem(sender, pwd)
            plain = decrypt_hybrid(packet, private_pem, pwd)
            self.hybrid_output.delete("1.0", tk.END)
            self.hybrid_output.insert("1.0", plain)
            self._set_status("混合解密成功", 6000)
        except DecryptionError as e:
            messagebox.showerror("解密失败", str(e))
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {e}")

    def _on_hybrid_copy(self):
        text = self.hybrid_output.get("1.0", "end-1c").strip()
        if text:
            self._copy_to_clipboard(text)
            self._set_status("已复制到剪贴板 (60 秒后自动清空)", 3000)

    def _on_export_bundle(self):
        identity = self.current_identity_var.get()
        if not identity:
            messagebox.showwarning("警告", "请先在顶部「我是」选择你的身份")
            return
        try:
            bundle = self.store.export_public_key_bundle(identity)
        except FileNotFoundError:
            ret = messagebox.askyesno("缺少聊天密钥",
                f"身份「{identity}」是旧版创建的，缺少聊天所需的 X25519 密钥。\n\n"
                f"是否现在自动补全？（需要输入私钥密码）")
            if not ret:
                return
            pwd = simpledialog.askstring("私钥密码", f"为 {identity} 补全 X25519 密钥\n请输入私钥密码:",
                                          show="*", parent=self.root)
            if not pwd:
                return
            try:
                self.store.ensure_kem_keys(identity, pwd)
                bundle = self.store.export_public_key_bundle(identity)
                messagebox.showinfo("成功", f"X25519 密钥已为 {identity} 补全")
            except Exception as e2:
                messagebox.showerror("错误", str(e2))
                return
        except Exception as e:
            messagebox.showerror("错误", str(e))
            return
        self._copy_to_clipboard(bundle)
        self._set_status(f"已导出并复制 {identity} 的公钥束 (含身份, 对方可自动识别)", 4000)

    def _on_import_bundle(self):
        bundle = self.import_paste_text.get("1.0", "end-1c").strip()
        if not bundle:
            messagebox.showwarning("警告", "请把对方的公钥束粘贴到输入框")
            return
        # 路由身份恒用束内 identity (聊天才能连上); 输入框只是本地备注
        bundle_identity = self.store.peek_bundle_identity(bundle)
        remark = self.import_name_entry.get().strip()
        if bundle_identity:
            routing = bundle_identity
        else:
            # 旧版束不含身份: 备注框即作为路由身份
            if not remark:
                messagebox.showwarning("警告",
                    "未能从公钥束中识别对方身份(可能是旧版格式)。\n"
                    "请在「备注」处填写对方在服务器注册的身份名。")
                return
            routing = remark
        try:
            status = self.store.import_public_key_bundle(
                bundle, routing, display_name=remark or None)
            self._refresh_identity_list()
            self._refresh_hybrid_identities()
            self._refresh_cfg_identities()
            if status == "exists_same":
                self._set_status(f"对方身份 {routing} 的公钥已存在(相同), 无需重复导入", 4000)
            else:
                self._set_status(f"已导入 {routing} 的公钥束", 4000)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ---- 问题3/4 修复：Prekey 上传唯一实现（系统配置 / 聊天内嵌 / 首次向导 统一调用）----
    def _upload_prekey_to_server(self, identity, passphrase, show_dialog=True):
        """Prekey 上传的唯一实现。

        系统配置标签、聊天内嵌、首次向导三处统一调用本方法，消除三处重复实现
        与跨 Tab 直接改写变量的耦合。返回 (ok: bool, resp: dict|None)。
        """
        import urllib.request, urllib.parse, ssl, json
        from config import get_prekey_server, get_auth_token
        url = get_prekey_server()
        token = get_auth_token()
        if not url or not token:
            if show_dialog:
                messagebox.showerror("错误", "请先在系统配置页设置服务器地址")
            return False, None
        try:
            bundle = self.store.generate_prekey_bundle(identity, passphrase, otp_count=50)
            data = json.dumps(dict(bundle, identity=identity), ensure_ascii=False).encode()
            req = urllib.request.Request(
                url + "/v1/prekey/" + urllib.parse.quote(identity, safe=''),
                data=data, method="POST")
            req.add_header("Authorization", "Bearer " + token)
            req.add_header("Content-Type", "application/json")
            ctx = ssl.create_default_context()
            resp = json.loads(urllib.request.urlopen(req, context=ctx, timeout=30).read())
        except Exception as e:
            if show_dialog:
                messagebox.showerror("错误", f"上传失败: {e}")
            return False, None
        ok = resp.get("status") == "ok"
        if show_dialog:
            if ok:
                messagebox.showinfo("成功", f"Prekey 上传成功！\nOTP: {resp.get('one_time_stored', 0)} 个")
            else:
                messagebox.showerror("错误", f"上传失败: {resp}")
        return ok, resp

    def _on_upload_prekey(self):
        identity = self.cfg_pk_identity_var.get()
        if not identity:
            messagebox.showwarning("警告", "请先在上方选择要上传的身份")
            return
        passphrase = simpledialog.askstring(
            "私钥密码", f"上传 {identity} 的 Prekey\n请输入私钥密码:", show="*", parent=self.root)
        if not passphrase:
            return
        ok, _ = self._upload_prekey_to_server(identity, passphrase)
        if ok:
            self._set_status(f"Prekey 已上传 ({identity})", 4000)

    def _build_chat_tab(self):
        main = ttk.Frame(self.tab_chat, padding=8)
        main.pack(fill=tk.BOTH, expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)

        # ---- 聊天连接前置检查条 (P1 实用性: 一眼看出还差什么) ----
        rf = ttk.LabelFrame(main, text="连接前置检查", padding=(8, 4))
        rf.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        rpill = ttk.Frame(rf)
        rpill.pack(fill=tk.X)
        self.pill_identity = tk.Label(rpill, text="身份 [待处理]", bg="#FFF6E0",
                                      fg="#8a6500", font=("Microsoft YaHei", 8),
                                      padx=8, pady=3, relief=tk.RAISED, bd=0)
        self.pill_identity.pack(side=tk.LEFT, padx=(0, 6))
        self.pill_server = tk.Label(rpill, text="服务器 [待处理]", bg="#FFF6E0",
                                     fg="#8a6500", font=("Microsoft YaHei", 8),
                                     padx=8, pady=3, relief=tk.RAISED, bd=0)
        self.pill_server.pack(side=tk.LEFT, padx=(0, 6))
        self.pill_peer = tk.Label(rpill, text="对方 [待处理]", bg="#FFF6E0",
                                   fg="#8a6500", font=("Microsoft YaHei", 8),
                                   padx=8, pady=3, relief=tk.RAISED, bd=0)
        self.pill_peer.pack(side=tk.LEFT, padx=(0, 6))
        self.pill_prekey = tk.Label(rpill, text="Prekey [待检查]", bg="#eef0f2",
                                     fg="#8e8e93", font=("Microsoft YaHei", 8),
                                     padx=8, pady=3, relief=tk.RAISED, bd=0)
        self.pill_prekey.pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(rpill, text="立即检查", command=self._refresh_readiness).pack(side=tk.LEFT, padx=(4, 0))

        # 文件传输中间状态
        self._pending_file_upload = None      # 大文件上传后待发的 [FILE] meta 信息
        self._pending_file_downloads = {}     # token -> (fname, key_b64) 等待 file_download_resp
        self._chat_file_msgs = {}             # 渲染 key -> (fname, fsize, key_b64, payload)

        # Tier 1 状态变量
        self._chat_watchdog_id = None         # 连接看门狗定时器 id
        self._ever_connected = False           # 是否曾经成功连接 (控制 REST 兜底)
        self._cached_passphrase = {}           # identity -> passphrase (会话内记住, 不落盘)
        self._remember_pwd = tk.BooleanVar(value=True)

        # ---- Header (grid) ----
        header = ttk.Frame(main)
        header.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        for i in range(7):
            if i in (1, 3):
                header.columnconfigure(i, weight=1)
            else:
                header.columnconfigure(i, weight=0)

        c = 0
        ttk.Label(header, text="对方:").grid(row=0, column=c, sticky="w", padx=(0, 2)); c += 1
        self.chat_peer_var = tk.StringVar()
        self._peer_display_map = {}  # 聊天下拉: 显示文本 -> 真实身份
        self.chat_peer_combo = ttk.Combobox(header, textvariable=self.chat_peer_var,
                                             state="normal")
        self.chat_peer_combo.grid(row=0, column=c, sticky="ew", padx=(0, 6)); c += 1
        self.chat_peer_combo.bind("<<ComboboxSelected>>", self._on_chat_select_peer)

        self.chat_connect_btn = ttk.Button(header, text="连接", command=self._on_chat_connect)
        self.chat_connect_btn.grid(row=0, column=c, sticky="w", padx=(0, 4)); c += 1

        self.chat_status_label = ttk.Label(header, text="● 未连接", foreground="#999")
        self.chat_status_label.grid(row=0, column=c, sticky="w", padx=(0, 4)); c += 1

        self.chat_safety_btn = ttk.Button(header, text="[锁]安全号",
                                           command=self._on_show_safety_number)
        self.chat_safety_btn.grid(row=0, column=c, sticky="w", padx=(0, 4)); c += 1

        self.chat_setup_btn = ttk.Button(header, text="?", command=self._on_chat_setup_guide, width=2)
        self.chat_setup_btn.grid(row=0, column=c, sticky="w"); c += 1

        # ---- Message Display ----
        msg_frame = ttk.Frame(main)
        msg_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 8))
        msg_frame.columnconfigure(0, weight=1)
        msg_frame.rowconfigure(0, weight=1)

        self.chat_msg_display = tk.Text(msg_frame, wrap=tk.WORD,
                                         font=("Microsoft YaHei", 10),
                                         state=tk.DISABLED, bg="#f5f6f8",
                                         relief=tk.FLAT, bd=0,
                                         padx=12, pady=8)
        chat_scroll = ttk.Scrollbar(msg_frame, orient=tk.VERTICAL, command=self.chat_msg_display.yview)
        self.chat_msg_display.config(yscrollcommand=chat_scroll.set)
        chat_scroll.grid(row=0, column=1, sticky="ns")
        self.chat_msg_display.grid(row=0, column=0, sticky="nsew")

        # Tags
        self.chat_msg_display.tag_configure("ts", foreground="#8e8e93", font=("Microsoft YaHei", 7))
        self.chat_msg_display.tag_configure("verified", foreground="#34c759", font=("Microsoft YaHei", 7))
        self.chat_msg_display.tag_configure("system", foreground="#8e8e93", font=("Microsoft YaHei", 8),
                                             justify=tk.CENTER)
        self.chat_msg_display.tag_configure("error", foreground="#ff3b30", font=("Microsoft YaHei", 8),
                                             justify=tk.CENTER)

        # Tags — all messages left-aligned
        self.chat_msg_display.tag_configure("p_name", foreground="#1c1c1e", font=("Microsoft YaHei", 8, "bold"),
                                             spacing1=6)
        self.chat_msg_display.tag_configure("p_bubble", foreground="#1c1c1e",
                                             background="#ffffff", lmargin1=8, spacing1=2, spacing3=4)
        self.chat_msg_display.tag_configure("p_ts", foreground="#8e8e93", font=("Microsoft YaHei", 7),
                                             lmargin1=8)

        # ---- Input Area (grid) ----
        input_frame = ttk.Frame(main)
        input_frame.grid(row=3, column=0, sticky="ew")
        input_frame.columnconfigure(0, weight=1)

        self.chat_input = tk.Text(input_frame, height=2, wrap=tk.WORD,
                                   font=("Microsoft YaHei", 10),
                                   relief=tk.FLAT, bd=0,
                                   highlightthickness=1,
                                   highlightbackground="#d1d1d6",
                                   padx=8, pady=6)
        self.chat_input.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.chat_input.bind("<Return>", self._on_chat_input_enter)
        self.chat_input.bind("<Shift-Return>", lambda e: None)

        btn_col = ttk.Frame(input_frame)
        btn_col.grid(row=0, column=1, sticky="ns")
        self.chat_send_btn = ttk.Button(btn_col, text="发送", command=self._on_chat_send)
        self.chat_send_btn.pack(fill=tk.X, pady=(0, 2))
        self.chat_emoji_btn = ttk.Button(btn_col, text="Emoji", command=self._on_emoji_picker)
        self.chat_emoji_btn.pack(fill=tk.X, pady=(0, 2))
        self.chat_file_btn = ttk.Button(btn_col, text="File", command=self._on_chat_send_file)
        self.chat_file_btn.pack(fill=tk.X)

        bottom_row = ttk.Frame(main)
        bottom_row.grid(row=4, column=0, sticky="ew", pady=(4, 0))
        self.chat_settings_btn = ttk.Button(bottom_row, text="设置", width=4,
                                             command=self._toggle_chat_settings)
        self.chat_settings_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.chat_enc_status = ttk.Label(bottom_row, text="E2E 加密中",
                                          font=("Microsoft YaHei", 7), foreground="#8e8e93")
        self.chat_enc_status.pack(side=tk.LEFT)
        self.chat_new_msg_label = ttk.Label(bottom_row, text="",
                                             font=("Microsoft YaHei", 8), foreground="#27ae60")
        self.chat_new_msg_label.pack(side=tk.LEFT, padx=(8, 0))
        self.chat_remember_chk = ttk.Checkbutton(bottom_row, text="记住密码",
                                                  variable=self._remember_pwd)
        self.chat_remember_chk.pack(side=tk.RIGHT, padx=(0, 6))
        self.chat_clear_btn = ttk.Button(bottom_row, text="清空", width=4, command=self._on_clear_chat)
        self.chat_clear_btn.pack(side=tk.RIGHT)

        # Tier 3-8: 聊天 Tab 内嵌设置折叠区 (默认折叠, 减少切 Tab 动线)
        self.chat_settings = ttk.LabelFrame(main, text="聊天设置")
        self.chat_settings.grid(row=5, column=0, sticky="ew", pady=(4, 0))
        self.chat_settings.grid_remove()
        _srow0 = ttk.Frame(self.chat_settings)
        _srow0.pack(fill=tk.X, padx=8, pady=(6, 2))
        ttk.Label(_srow0, text="服务器:").pack(side=tk.LEFT)
        self.chat_settings_url = ttk.Label(_srow0, text="—")
        self.chat_settings_url.pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(_srow0, text="系统配置", width=8,
                   command=lambda: self.notebook.select(self.tab_config)).pack(side=tk.RIGHT)
        _srow1 = ttk.Frame(self.chat_settings)
        _srow1.pack(fill=tk.X, padx=8, pady=(2, 6))
        ttk.Button(_srow1, text="上传 Prekey", width=10,
                   command=self._on_chat_upload_prekey).pack(side=tk.LEFT)
        self.chat_settings_peer = ttk.Label(_srow1, text="对方公钥: 发送时自动建立",
                                            font=("Microsoft YaHei", 8), foreground="#8e8e93")
        self.chat_settings_peer.pack(side=tk.LEFT, padx=(8, 0))

        self._refresh_chat_contacts()

    def _refresh_chat_contacts(self):
        peers = []
        try:
            import os as _os
            d = _os.path.join(_os.path.expanduser("~"), ".zhcrypt", "keys")
            if _os.path.exists(d):
                for fn in _os.listdir(d):
                    if fn.endswith(".pub") and not fn.endswith(".ed25519.pub") \
                            and not fn.endswith(".x25519.pub"):
                        ident = fn[:-4]
                        ident_self = self.chat_identity_var.get()
                        if ident and ident != ident_self:
                            peers.append(ident)
        except Exception:
            pass
        peers = sorted(set(peers))
        # 显示备注, 路由用真实身份: 建立 显示文本 -> identity 映射
        # (R6: display_name 走进程内缓存, 不再每 peer 每次刷新重读 meta)
        self._peer_display_map = {}
        values = []
        for ident in peers:
            disp = self._contact_display(ident)
            values.append(disp)
            self._peer_display_map[disp] = ident
        try:
            self.chat_peer_combo["values"] = values
        except Exception:
            self._set_status("联系人列表刷新失败", 3000)

        identities = []
        try:
            identities = [id_["identity"] for id_ in self.store.list_identities()]
        except Exception as e:
            self._set_status(f"身份列表加载失败: {e}", 3000)
        if identities:
            self.identity_combo["values"] = identities
            cur = self.chat_identity_var.get()
            if not cur or cur not in identities:
                from config import get as _cfg_get
                default_id = _cfg_get("default_identity", "default")
                if default_id in identities:
                    self.chat_identity_var.set(default_id)
                else:
                    self.chat_identity_var.set(identities[0])
        self._refresh_readiness()

    def _refresh_readiness(self):
        """聊天连接前置检查条刷新 (P1 实用性)。本地三项即时; Prekey 走 meta 端点(不消耗 OTP)。"""
        identity = self.chat_identity_var.get()
        from config import get_prekey_server
        has_identity = bool(identity)
        has_server = bool(get_prekey_server())
        has_peer = bool(self.chat_peer_var.get())
        self._set_pill(self.pill_identity, "身份", has_identity)
        self._set_pill(self.pill_server, "服务器", has_server)
        self._set_pill(self.pill_peer, "对方", has_peer)
        if has_identity and has_server:
            threading.Thread(target=self._check_prekey_on_server,
                             args=(identity,), daemon=True).start()
        else:
            self.pill_prekey.config(text="Prekey [待检查]", bg="#eef0f2", fg="#8e8e93")

    def _check_prekey_on_server(self, identity):
        """后台查询该身份是否已上传 prekey (meta 端点, 不消耗 OTP)。"""
        import urllib.request, urllib.parse, ssl, json
        from config import get_auth_token, get_prekey_server
        url = get_prekey_server(); token = get_auth_token()
        ok = False
        if url and token:
            try:
                req = urllib.request.Request(
                    url + "/v1/prekey/meta/" + urllib.parse.quote(identity, safe=''),
                    method="GET")
                req.add_header("Authorization", "Bearer " + token)
                resp = json.loads(urllib.request.urlopen(
                    req, context=ssl.create_default_context(), timeout=10).read())
                ok = resp.get("status") == "ok"
            except Exception:
                ok = False
        self.root.after(0, lambda: self._set_pill(self.pill_prekey, "Prekey", ok))

    def _toggle_chat_settings(self):
        """切换聊天设置折叠区显示/隐藏 (Tier 3-8)。"""
        if self.chat_settings.winfo_viewable():
            self.chat_settings.grid_remove()
        else:
            self._refresh_chat_settings()
            self.chat_settings.grid()

    def _refresh_chat_settings(self):
        from config import get_prekey_server
        try:
            self.chat_settings_url.config(text=get_prekey_server() or "（未设置）")
        except Exception:
            pass

    def _on_chat_upload_prekey(self):
        """聊天 Tab 内上传当前身份的 Prekey (问题4 修复：不再改写配置 Tab 的变量)。"""
        identity = self.chat_identity_var.get()
        if not identity:
            messagebox.showwarning("警告", "请先选择身份")
            return
        passphrase = simpledialog.askstring(
            "私钥密码", f"上传 {identity} 的 Prekey\n请输入私钥密码:", show="*", parent=self.root)
        if not passphrase:
            return
        ok, _ = self._upload_prekey_to_server(identity, passphrase)
        if ok:
            self._set_pill(self.pill_prekey, "Prekey", True)

    def _on_chat_select_peer(self, event=None):
        self._refresh_readiness()
        peer = self.chat_peer_var.get()
        if peer:
            self._on_chat_connect()

    # ---- 问题7 修复：聊天准备步骤单一来源（SSOT）。帮助文档/设置向导均引用此处 ----
    # 帮助文档核对清单（审计 #2）：以下任一处描述如与实现不符，以本清单为准修正。
    def _prep_steps(self):
        """聊天准备步骤的唯一定义。设置向导、准备步骤弹窗、帮助文档统一引用，杜绝口径不一。"""
        return [
            ("配置服务器", "打开「系统配置」标签，设置服务器地址：https://iweistoicqc5.top，点「测试连接」确认可达"),
            ("创建身份", "文件菜单 → 初始化身份，输入身份名和密码"),
            ("交换公钥束", "你：「密钥管理」→ 导出完整公钥束发给对方；粘贴对方公钥束 → 导入"),
            ("上传 Prekey", "打开「系统配置」标签 → 选身份 → 点「上传 Prekey」→ 输入私钥密码（对方也要做）"),
            ("开始聊天", "打开「聊天」标签 → 选身份和对方 → 点「连接」"),
        ]

    def _on_chat_setup_guide(self):
        lines = ["开始聊天前需要完成以下准备：\n"]
        for i, (title, desc) in enumerate(self._prep_steps(), 1):
            lines.append(f"▸ 步骤{i}：{title}\n   {desc}\n")
        messagebox.showinfo("聊天准备步骤", "\n".join(lines))

    def _on_show_safety_number(self):
        """查看与当前联系人的安全识别码 (带外比对, 审计 #5)。"""
        peer = self._chat_peer or self._peer_display_map.get(
            self.chat_peer_var.get(), self.chat_peer_var.get())
        if not peer:
            messagebox.showinfo("安全识别码", "请先选择对方身份")
            return
        if not self._chat_client:
            messagebox.showinfo("安全识别码", "请先连接聊天")
            return
        res = self._chat_client.get_safety_number(peer)
        if isinstance(res, dict) and "safety_number" in res:
            self._show_safety_number_dialog(peer, res["safety_number"], first=False,
                                            late_pin=res.get("late_pin"))
            return
        # 诊断：精确指出缺哪一份公钥，以及可能的身份字符串不一致
        my_ok = bool(res.get("my_sign")) if isinstance(res, dict) else False
        peer_ok = bool(res.get("peer_sign")) if isinstance(res, dict) else False
        tips = []
        if not my_ok:
            tips.append("• 我方签名公钥缺失：本机 keys 目录下 <我的身份>.ed25519.pub 不存在"
                        "（该身份的 Ed25519 密钥未生成或已丢失）。")
        if not peer_ok:
            tips.append(
                f"• 对方 TOFU 公钥缺失：keys 目录下 {peer}.tofu.ed25519.pub 不存在。\n"
                f"  常见原因：(1) 双方尚未完成一次真正的首次 X3DH 握手；"
                f"(2) 握手/收消息时存 TOFU 用的身份字符串('{peer}')与对方发来消息里的 "
                f"msg['from'] 不一致（注意大小写、@后缀、服务器规范化等）。"
            )
        detail = res.get("error") if isinstance(res, dict) else str(res)
        msg = ("无法显示安全识别码，原因如下：\n\n" + "\n".join(tips) +
               "\n\n建议：确认双方都用同一身份先互发过一条消息（触发首次握手），"
               "且身份字符串完全一致。\n\n技术细节：\n" + (detail or "未知"))
        messagebox.showwarning("安全识别码 - 诊断", msg)

    def _show_safety_number_dialog(self, peer, safety_number, first=True, late_pin=False):
        """弹窗展示安全识别码, 提示带外比对 (审计 #5 残余)。"""
        prefix = "首次与对方建立端到端加密会话!\n\n" if first else ""
        if late_pin:
            prefix += ("注意：本地无该联系人的首次握手(TOFU)记录, 本安全号基于\n"
                       "服务器当前返回的公钥计算并已固定。请务必与对方带外核对;\n"
                       "若日后提示公钥变更, 需重新确认身份。\n\n")
        msg = (prefix +
               f"与 [{peer}] 的安全识别码:\n\n"
               f"{safety_number}\n\n"
               "请通过电话 / 当面等带外方式, 与对方核对以上识别码是否完全一致。\n"
               "若不一致, 可能遭到中间人攻击, 请勿发送敏感信息!")
        messagebox.showwarning("安全识别码核对", msg)

    def _on_chat_connect(self):
        self._refresh_readiness()
        peer = self.chat_peer_var.get()
        peer = self._peer_display_map.get(peer, peer)  # 显示文本 -> 真实身份
        identity = self.chat_identity_var.get()
        if not peer:
            messagebox.showwarning("警告", "请选择对方身份")
            return
        if not identity:
            messagebox.showwarning("警告", "请选择你的身份")
            return

        if identity == peer:
            messagebox.showwarning("警告", "不能和自己聊天，请选择不同的身份")
            return

        from config import get_auth_token, get_prekey_server
        server_url = get_prekey_server()
        if not server_url:
            messagebox.showwarning("警告", "请先在系统配置页设置 Prekey 服务器")
            return

        # Tier 1-2: 允许直接输入对方 ID, 不再强制先手动导入公钥束。
        # 若对方公钥缺失, 首次发送时会通过握手自动拉取并缓存 (服务器证书固定+token 可信)。
        self._refresh_chat_contacts()

        # Tier 1-3: 会话内记住密码 (仅驻内存, 不落盘)
        if self._remember_pwd.get() and self._cached_passphrase.get(identity):
            passphrase = self._cached_passphrase[identity]
        else:
            passphrase = simpledialog.askstring("私钥密码", f"[{identity}] 请输入私钥密码:",
                                                 show="*", parent=self.root)
            if not passphrase:
                return
            passphrase = passphrase.strip()
            if not passphrase:
                messagebox.showwarning("警告", "密码不能为空")
                return
            if self._remember_pwd.get():
                self._cached_passphrase[identity] = passphrase

        if self._chat_client:
            try:
                self._chat_client.stop()
            except Exception:
                pass
        if self._chat_poll_id:
            self.root.after_cancel(self._chat_poll_id)

        from chat_client import ChatClient
        self._chat_client = ChatClient(identity, passphrase)
        client = self._chat_client
        client.start()
        self.chat_status_label.config(text="● 连接中...", foreground="#f1c40f")
        self._chat_peer = peer
        self._ever_connected = False
        if self._chat_watchdog_id:
            try:
                self.root.after_cancel(self._chat_watchdog_id)
            except Exception:
                pass
        self._chat_watchdog_id = self.root.after(10000, self._chat_connect_watchdog)

        self._append_chat_msg("system", f"正在连接到 {server_url} ...")

        # Tier 1-4: 事件驱动连接。WS 线程已通过 INBOUND 推送 status 事件,
        # 直接启动队列消费循环, 不再用 5 次硬超时轮询判定(慢握手不再被误判失败)。
        self._poll_chat()

        # Tier 1-1 + 1-2: 后台自检 (不阻塞 UI)
        #  - 自动续传自身 prekey (不足时)
        #  - 尝试预拉取对方静态公钥 (meta 端点, 不消耗 OTP)
        # 握手本身仍在首次发送时完成 (X3DH 必须伴随第一条消息, 协议语义)。
        threading.Thread(
            target=self._bg_chat_prepare,
            args=(client, identity, peer, server_url),
            daemon=True,
        ).start()

    def _chat_connect_watchdog(self):
        """单发看门狗: 连接后 10s 仍无 connected 状态, 给出明确失败原因。"""
        self._chat_watchdog_id = None
        if not self._chat_client:
            return
        if self._chat_client.connected:
            return
        self.chat_status_label.config(text="● 连接失败", foreground="#e74c3c")
        self._append_chat_msg("error",
            "连接服务器失败，可能原因：\n"
            "1. 系统配置中的服务器地址错误\n"
            "2. 网络不通 / 服务器未启动\n"
            "3. 本地 token 未配置（朋友机需在系统配置重填 token）\n\n"
            "请检查后重新点击「连接」")

    def _bg_chat_prepare(self, client, identity, peer, server_url):
        """后台自检: 自动续传自身 prekey + 预拉取对方静态公钥(不消耗 OTP)。

        在守护线程中运行, 结果通过 root.after(0) 写回 GUI, 不阻塞连接。
        握手(X3DH)仍在用户首次发送时完成, 此处只做『就绪度』准备与提示。
        """
        # 1) 自身 prekey 自动续传
        try:
            ok, msg = client.ensure_own_prekey()
        except Exception as e:
            ok, msg = False, f"异常: {e}"
        self.root.after(0, lambda: self._append_chat_msg(
            "system", ("[OK] " if ok else "[失败] ") + f"自身 prekey: {msg}"))

        # 2) 预拉取对方静态公钥 (meta 端点, 不消耗 OTP)
        try:
            meta = client.fetch_peer_meta(peer)
        except Exception as e:
            meta = {"ok": False, "missing": False, "error": str(e)}
        if meta.get("ok"):
            try:
                client.store.import_peer_static_keys(
                    peer,
                    idk_b64=meta.get("identity_key_pub"),
                    spk_b64=meta.get("signed_prekey_pub"),
                    signing_b64=meta.get("signing_public_key"),
                )
                self.root.after(0, lambda: self._append_chat_msg(
                    "system", f"已自动获取对方 {peer} 的公钥"))
                self.root.after(0, self._refresh_chat_contacts)
            except Exception as e:
                self.root.after(0, lambda: self._append_chat_msg(
                    "error", f"缓存 {peer} 公钥失败: {e}"))
        else:
            if meta.get("missing"):
                # 端点不存在(服务器未升级) 或对方尚未上传 -> 不阻断, 首次发送自动补全
                self.root.after(0, lambda: self._append_chat_msg(
                    "system",
                    f"提示: 未预取 {peer} 公钥（服务器可能未升级或对方尚未上传）。"
                    f"发起聊天时将自动完成密钥交换。"))
            else:
                self.root.after(0, lambda: self._append_chat_msg(
                    "error", f"预拉取 {peer} 公钥失败: {meta.get('error')}"))

    def _poll_chat(self):
        if not self._chat_client:
            return

        items = self._chat_client.process_inbound()
        new_count = 0
        self.chat_new_msg_label.config(text="")
        for item in items:
            try:
                if item.get("action") == "server_message":
                    data = item["data"]
                    if data.get("type") == "message":
                        result = self._chat_client.receive_chat_message(data["msg"])
                        if result and "error" not in result:
                            self._display_chat_message(result)
                            new_count += 1
                        elif result and "error" in result:
                            self._append_chat_msg("error", f"解密失败: {result['error']}")
                    elif data.get("type") == "pending":
                        for m in data.get("messages", []):
                            if isinstance(m, dict) and "from" in m:
                                r = self._chat_client.receive_chat_message(m)
                                if r and "error" not in r:
                                    self._display_chat_message(r)
                                    new_count += 1
                    elif data.get("type") == "file_upload_ack":
                        self._on_file_upload_ack(data.get("token", ""))
                    elif data.get("type") == "file_download_resp":
                        self._on_file_download_resp(data)
                elif item.get("action") == "error":
                    self._append_chat_msg("error", item["message"])
                elif item.get("action") == "status":
                    connected = item.get("connected", False)
                    if connected:
                        self._ever_connected = True
                        # 连接成功, 取消连接看门狗
                        if self._chat_watchdog_id:
                            try:
                                self.root.after_cancel(self._chat_watchdog_id)
                            except Exception:
                                pass
                            self._chat_watchdog_id = None
                        self.chat_status_label.config(text="● 已连接", foreground="#27ae60")
                    else:
                        self.chat_status_label.config(text="● 已断开", foreground="#e74c3c")
            except Exception as e:
                # 单条消息处理异常不应中断整轮轮询, 否则聊天会卡死
                self._append_chat_msg("error", f"处理消息出错: {e}")

        # Tier 1-4: REST 兜底仅在『曾连接过又断开』时启用, 避免初始连接阶段
        # 每 2s 刷一次错 (WS 还在建链时不应触发 REST 降级)。
        if not self._chat_client.connected and getattr(self, "_ever_connected", False):
            try:
                poll_results = self._chat_client.poll_messages()
                for r in poll_results:
                    if "error" not in r:
                        self._display_chat_message(r)
                        new_count += 1
            except Exception as e:
                self._set_status(f"消息轮询失败: {e}", 3000)

        if new_count:
            self.chat_new_msg_label.config(text=f"新消息: +{new_count}")

        self._chat_poll_id = self.root.after(2000, self._poll_chat)

    def _display_chat_message(self, result):
        from datetime import datetime
        ts = datetime.fromtimestamp(result["timestamp"]).strftime("%H:%M")
        date_str = datetime.fromtimestamp(result["timestamp"]).strftime("%m/%d")
        who = result["from"]
        text = result["text"]
        verified = result.get("verified", False)

        self.chat_msg_display.config(state=tk.NORMAL)
        is_me = (who == self.chat_identity_var.get())
        display_name = "你" if is_me else who

        # 自己发出的文件消息(服务器回显)不再显示下载链接, 避免与"已发送"重复
        if text.startswith("[FILE]") and is_me:
            self.chat_msg_display.config(state=tk.DISABLED)
            return

        self.chat_msg_display.insert(tk.END, f"\n{display_name}  {ts}\n", "p_name")

        if text.startswith("[FILE]"):
            # 格式: [FILE]<fname>|<fsize>|<key_b64>|<payload>
            # payload: 小文件=内联密文 base64; 大文件= tok:<token>
            try:
                body = text[len("[FILE]"):]
                fname, fsize, key_b64, payload = body.split("|", 3)
                fsize_kb = int(fsize) // 1024
            except Exception:
                self.chat_msg_display.insert(tk.END, f"{text}\n", "p_bubble")
            else:
                link_tag = f"filelink_{len(self._chat_file_msgs)}"
                self._chat_file_msgs[link_tag] = (fname, fsize, key_b64, payload)
                link_text = f"[附件] {fname} ({fsize_kb}KB)  [点击下载]"
                self.chat_msg_display.insert(tk.END, link_text + "\n", link_tag)
                self.chat_msg_display.tag_config(link_tag, foreground="#2176d4",
                                                 underline=True)
                self.chat_msg_display.tag_bind(
                    link_tag, "<Button-1>",
                    lambda e, t=link_tag: self._on_chat_download_file(t))
        else:
            self.chat_msg_display.insert(tk.END, f"{text}\n", "p_bubble")
        if verified:
            self.chat_msg_display.insert(tk.END, "签名已验证\n", "verified")

        self.chat_msg_display.config(state=tk.DISABLED)
        self.chat_msg_display.see(tk.END)

        # Desktop notification for incoming messages when minimized
        if not is_me and self.root.state() == "iconic":
            try:
                from plyer import notification as _nt
                _nt.notify(
                    title=f"{who} 发来消息",
                    message=text[:60],
                    app_name="zhcrypt",
                    timeout=4,
                )
            except Exception:
                pass

    def _append_chat_msg(self, tag, text):
        self.chat_msg_display.config(state=tk.NORMAL)
        self.chat_msg_display.insert(tk.END, f"\n{text}\n", tag)
        self.chat_msg_display.config(state=tk.DISABLED)
        self.chat_msg_display.see(tk.END)

    # ---- 文件传输: 上传 ack / 下载请求 / 下载响应 / 保存 ----

    def _on_file_upload_ack(self, token):
        """大文件上传后, 服务端返回 token, 据此把 [FILE] meta 发给接收方。"""
        if not token or not self._pending_file_upload:
            return
        info = self._pending_file_upload
        self._pending_file_upload = None
        meta = f"[FILE]{info['fname']}|{info['fsize']}|{info['key_b64']}|tok:{token}"
        result = self._chat_client.send_chat_message(self._chat_peer, meta)
        if result.get("error"):
            self._update_uploading_msg(info, failed=True, err=str(result["error"]))
            self._append_chat_msg("error", f"文件发送失败: {result['error']}")
            return
        self._update_uploading_msg(info, failed=False)
        self._set_status(f"文件已发送: {info['fname']}", 4000)

    def _update_uploading_msg(self, info, failed=False, err=""):
        """把"上传中"那条消息更新为已发送/失败, 避免旧消息永久滞留。"""
        tag = info.get("msg_tag")
        if not tag:
            return
        try:
            rng = self.chat_msg_display.tag_ranges(tag)
            if not rng:
                return
            fsize_kb = int(info.get("fsize", 0)) // 1024
            if failed:
                new_text = f"[附件] {info['fname']} ({fsize_kb}KB) ✗ 发送失败: {err}\n"
            else:
                new_text = f"[附件] {info['fname']} ({fsize_kb}KB) 已发送（对方可下载）\n"
            self.chat_msg_display.config(state=tk.NORMAL)
            self.chat_msg_display.delete(rng[0], rng[1])
            self.chat_msg_display.insert(rng[0], new_text, "p_bubble")
            self.chat_msg_display.config(state=tk.DISABLED)
            self.chat_msg_display.see(tk.END)
        except Exception:
            pass

    def _check_upload_timeout(self, tag):
        """60s 后仍在等待该条上传回执, 标记为超时失败。"""
        if self._pending_file_upload and self._pending_file_upload.get("msg_tag") == tag:
            info = self._pending_file_upload
            self._pending_file_upload = None
            self._update_uploading_msg(info, failed=True,
                                       err="上传超时（服务器无响应）")
            self._append_chat_msg("error", "大文件上传超时，请检查网络或服务器后重试")

    def _on_chat_download_file(self, tag):
        """点击聊天气泡中的 [下载] 链接: 小文件直接解密, 大文件向服务器请求。"""
        info = self._chat_file_msgs.get(tag)
        if not info:
            return
        fname, fsize, key_b64, payload = info
        if payload.startswith("tok:"):
            token = payload[len("tok:"):]
            self._pending_file_downloads[token] = (fname, key_b64)
            err = self._chat_client.request_file_download(token)
            if err:
                self._pending_file_downloads.pop(token, None)
                self._append_chat_msg("error", f"请求下载失败: {err}")
                return
            self._set_status(f"正在下载 {fname} ...", 0)
            self._append_chat_msg("system", f"正在下载 {fname} (等待服务器响应)...")
        else:
            try:
                cipher = base64.b64decode(payload)
            except Exception as e:
                self._append_chat_msg("error", f"文件解码失败: {e}")
                return
            self._decrypt_and_save(fname, key_b64, cipher)

    def _on_file_download_resp(self, data):
        """收到服务器 file_download_resp: 取出密文并解密保存。"""
        token = data.get("token", "")
        pending = self._pending_file_downloads.pop(token, None)
        if pending is None:
            return
        fname, key_b64 = pending
        file_data_b64 = data.get("file_data", "")
        try:
            cipher = base64.b64decode(file_data_b64)
        except Exception as e:
            self._append_chat_msg("error", f"文件下载失败: 数据解码错误 {e}")
            return
        self._decrypt_and_save(fname, key_b64, cipher)

    def _decrypt_and_save(self, fname, key_b64, cipher):
        """用文件密钥 AESGCM 解密, 弹出保存对话框落盘。"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            key = base64.b64decode(key_b64)
            if len(cipher) <= 12:
                raise ValueError("密文长度异常")
            nonce = cipher[:12]
            enc = cipher[12:]
            plain = AESGCM(key).decrypt(nonce, enc, None)
        except Exception as e:
            self._append_chat_msg("error", f"文件解密失败: {e}")
            return
        import tkinter.filedialog as fd
        default = os.path.basename(fname) or "download.bin"
        save_path = fd.asksaveasfilename(
            defaultextension="", initialfile=default, title="保存接收到的文件")
        if not save_path:
            return
        try:
            with open(save_path, "wb") as f:
                f.write(plain)
            self._append_chat_msg("system", f"文件已保存: {save_path}")
            self._set_status(f"文件已下载: {default}", 4000)
        except Exception as e:
            self._append_chat_msg("error", f"保存失败: {e}")

    def _on_chat_send(self):
        text = self.chat_input.get("1.0", "end-1c").strip()
        if not text:
            return
        peer = self._chat_peer or self.chat_peer_var.get()
        if not peer:
            messagebox.showwarning("警告", "请先选择对方并连接")
            return
        if not self._chat_client:
            messagebox.showwarning("警告", "请先连接")
            return

        self.chat_input.delete("1.0", tk.END)

        try:
            result = self._chat_client.send_chat_message(peer, text)
            if result.get("error"):
                self._append_chat_msg("error", f"发送失败: {result['error']}")
                return

            # 审计 #5 残余: 首次握手完成, 强制提示带外比对安全识别码
            if result.get("first_contact") and result.get("safety_number"):
                self._show_safety_number_dialog(peer, result.get("safety_number"), first=True)

            self._display_chat_message({
                "from": self.chat_identity_var.get(),
                "timestamp": time.time(),
                "text": text,
                "verified": True,
            })
            self._set_status("已发送", 3000)
        except Exception as e:
            self._append_chat_msg("error", f"发送失败: {e}")

    def _on_chat_input_enter(self, event=None):
        self._on_chat_send()
        return "break"

    def _on_emoji_picker(self):
        emojis = [
            ":)", ":D", ":(", ";)", ":P", "xD", "B)", ":o",
            "<3", "</3", "^_^", "-_-", "._.", ">_<", "O_O", "T_T",
            "+1", "-1", "OK", "NO", "Hi", "Bye", "WoW", "OMG",
            "***", "!!!", "???", "~~~", "[*]", "[!]", "[?]", "[#]",
        ]
        picker = tk.Toplevel(self.root)
        picker.title("选择 Emoji")
        picker.resizable(False, False)
        picker.transient(self.root)
        picker.grab_set()
        for i, em in enumerate(emojis):
            r, c = divmod(i, 8)
            btn = tk.Button(picker, text=em, font=("Consolas", 11),
                           width=2, relief=tk.FLAT, bd=0,
                           command=lambda e=em: self._insert_emoji(e, picker))
            btn.grid(row=r, column=c, padx=1, pady=1)
        picker.geometry("+%d+%d" % (self.root.winfo_pointerx(), self.root.winfo_pointery()))

    def _insert_emoji(self, em, picker):
        try:
            self.chat_input.insert(tk.INSERT, em)
        except tk.TclError:
            pass
        picker.destroy()

    def _on_chat_send_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="选择要发送的文件")
        if not path:
            return
        if not self._chat_client or not self._chat_peer:
            messagebox.showwarning("警告", "请先连接聊天")
            return
        import os as _os
        fsize = _os.path.getsize(path)
        fname = _os.path.basename(path)

        if fsize > 40 * 1024 * 1024:
            messagebox.showwarning("警告", "文件超过 40MB，不支持传输")
            return

        self._set_status(f"正在发送 {fname} ({fsize//1024}KB)...", 0)

        try:
            import base64, secrets
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            with open(path, "rb") as f:
                raw = f.read()
            file_key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(file_key)
            encrypted = aesgcm.encrypt(nonce, raw, None)
            payload = nonce + encrypted
            file_b64 = base64.b64encode(payload).decode("ascii")

            if fsize > 500 * 1024:
                if self._chat_client.ws_ready and self._chat_client.ws:
                    # 先上传密文到服务器, 等 file_upload_ack 拿到 token 后再发 [FILE] meta
                    err = self._chat_client.upload_file(file_b64, self._chat_peer)
                    if err:
                        messagebox.showerror("错误", f"文件上传失败: {err}")
                        return
                    self._pending_file_upload = {
                        "fname": fname,
                        "fsize": fsize,
                        "key_b64": base64.b64encode(file_key).decode("ascii"),
                    }
                    self._set_status(f"正在上传 {fname} ...", 0)
                    tag = f"uploading_{int(time.time()*1000)}"
                    self._pending_file_upload["msg_tag"] = tag
                    self.chat_msg_display.config(state=tk.NORMAL)
                    self.chat_msg_display.insert(
                        tk.END, f"\n你  {time.strftime('%H:%M')}\n", "p_name")
                    self.chat_msg_display.insert(
                        tk.END,
                        f"[附件] {fname} ({fsize//1024}KB) [上传中...]\n",
                        tag)
                    self.chat_msg_display.config(state=tk.DISABLED)
                    self.chat_msg_display.see(tk.END)
                    # 60s 超时保护: 若服务器无回执, 标记为失败, 不再永久转圈
                    self.root.after(60000, lambda t=tag: self._check_upload_timeout(t))
                    return
                else:
                    messagebox.showerror("错误", "WebSocket 未连接，无法上传大文件")
                    return
            else:
                key_b64 = base64.b64encode(file_key).decode("ascii")
                meta = f"[FILE]{fname}|{fsize}|{key_b64}|{file_b64}"

            self._display_chat_message({
                "from": self.chat_identity_var.get(),
                "timestamp": time.time(),
                "text": f"[附件] {fname} ({fsize//1024}KB) 已发送（对方可下载）",
                "verified": True,
            })
            result = self._chat_client.send_chat_message(self._chat_peer, meta)
            if result.get("error"):
                self._append_chat_msg("error", f"文件发送失败: {result['error']}")
            self._set_status(f"文件已发送: {fname}", 4000)
        except Exception as e:
            self._append_chat_msg("error", f"文件发送失败: {e}")
            self._set_status("文件发送失败", 3000)

    def _on_clear_chat(self):
        self.chat_msg_display.config(state=tk.NORMAL)
        self.chat_msg_display.delete("1.0", tk.END)
        self.chat_msg_display.config(state=tk.DISABLED)

    def _on_help_chat(self):
        messagebox.showinfo("聊天功能教程",
            "安全聊天 (E2E 端到端加密)\n"
            "========================\n\n"
            "原理是什么？\n"
            "每条消息在发送前用你的密钥加密，只有对方能解开。\n"
            "服务器只负责转发密文，完全看不懂内容。\n"
            "即使服务器被攻击，你的聊天记录也是安全的。\n\n"
            "核心技术：X3DH + Double Ratchet\n"
            "第一条消息通过三重 DH 密钥交换建立会话。\n"
            "之后每条消息都用独立的密钥（棘轮），一条密钥只用于一条消息。\n"
            "这意味着即使某条消息的密钥泄露，其他消息也无法解密。\n\n"
            "使用步骤：\n\n"
            + "".join(f"{i}. {title}：{desc}\n" for i, (title, desc) in enumerate(self._prep_steps(), 1))
            + "\n"
            "4. 消息安全标识\n"
            "   (签名已验证) = 对方身份已确认，消息未被篡改\n"
            "   (未签名) = 消息内容正确但身份未验证\n"
            "   红色错误 = 消息可能被篡改，请谨慎\n\n"
            "5. 命令行方式（备用）\n"
            "   zhcrypt chat-send -t 对方 消息内容\n"
            "   zhcrypt chat-poll    # 检查新消息\n"
            "   zhcrypt chat-history -t 对方  # 查看历史\n\n"
            "常见问题：\n"
            "Q: 连接失败？\n"
            "A: 检查服务器地址、token，确认对方已上传 prekey。\n"
            "Q: 收到消息但解密失败？\n"
            "A: 关闭 GUI 重新打开，会自动重新握手。\n"
            "Q: 能不能发文件？\n"
            "A: 支持。聊天可直接发送文件：小文件内联加密发送，大文件走服务器（阅后即焚）。\n"
            "   也可用「文件加解密」标签做口令加密后另行发送。")

    def _on_help_hybrid(self):
        messagebox.showinfo("混合加密教程",
            "混合加密 (RSA-4096 + AES-256-GCM)\n"
            "==================================\n\n"
            "原理：\n"
            "用接收方的 RSA 公钥加密一个随机 AES 密钥，\n"
            "实际内容用 AES 加密。结合了非对称加密的安全分发\n"
            "和对称加密的快速性能。\n\n"
            "使用步骤：\n"
            "1. 确保已导入对方的公钥（在「密钥管理」标签中）\n"
            "2. 打开「混合模式」标签\n"
            "3. 在上方输入框写消息\n"
            "4. 选择你的身份（发送方）和对方身份（接收方）\n"
            "5. 输入你的私钥密码\n"
            "6. 点「加密」→ 密文出现在下方\n"
            "7. 把密文通过任意渠道发给对方\n\n"
            "对方收到后：\n"
            "1. 把密文粘贴到输入框\n"
            "2. 选择自己的身份，输入自己的私钥密码\n"
            "3. 点「解密」→ 看到原文\n\n"
            "两种模式：\n"
            "RSA 模式：仅加密，无签名\n"
            "带签名模式：加密 + Ed25519 数字签名，防冒充\n\n"
            "注意：混合模式【不具备】前向安全(PFS)。\n"
            "前向安全由「聊天」标签的 Double Ratchet 提供，请按需选择。")

    def _on_help_file(self):
        messagebox.showinfo("文件加密教程",
            "文件加密 (流式分块 + AES-256-GCM)\n"
            "================================\n\n"
            "原理：\n"
            "文件被分成多个小块，每块用独立的 AES 密钥加密。\n"
            "即使文件有 10GB，内存中只占用一个块的大小。\n"
            "每块的密钥从主密钥单向派生，无法从单块密钥反推其他块。\n\n"
            "使用步骤：\n"
            "1. 打开「文件加解密」标签\n"
            "2. 点击「选择文件」选要操作的文件\n"
            "3. 输入密码\n"
            "4. 点「加密」或「解密」\n\n"
            "加密后：\n"
            "- 小于 10MB：生成 .zen 文件（全量加密）\n"
            "- 大于 10MB：生成 .zhs 文件（流式加密）\n\n"
            "解密后：\n"
            "- 自动恢复原始文件名\n"
            "- 如果输出文件已存在会提示确认覆盖\n\n"
            "安全提示：\n"
            "加密后删除原始文件前请确认解密正常。\n"
            "密码请通过不同于文件传输的渠道告知对方。")

    def _on_help_text(self):
        messagebox.showinfo("文本加密教程",
            "文本加密 (Argon2id + AES-256-GCM)\n"
            "=================================\n\n"
            "原理：\n"
            "你输入的密码通过 Argon2id 算法（256MB 内存硬化）\n"
            "派生为 256 位 AES 密钥，然后加密文本。\n"
            "每次加密使用随机盐值，相同密码每次产生不同密文。\n\n"
            "使用步骤：\n"
            "1. 打开「文本加解密」标签\n"
            "2. 在上方输入框写入或粘贴明文\n"
            "3. 输入加密密码\n"
            "4. 点「加密」→ 底部出现 Base64 密文\n"
            "5. 把密文复制发给对方\n\n"
            "密码强度条说明：\n"
            "红色 = 弱（纯数字或短密码，容易破解）\n"
            "橙色 = 中（混合字母数字）\n"
            "绿色 = 强（大写+小写+数字+符号，12位以上）\n"
            "极强 = 80 bits 以上（几乎不可能暴力破解）\n\n"
            "临时口令功能：\n"
            "点「临时口令」生成 6 个随机中文词的密码 (约 48bit)，\n"
            "只用一次就丢。适合临时分享文件。\n"
            "口令只显示一次，请立即复制。")

    def _on_help_keys(self):
        messagebox.showinfo("密钥管理教程",
            "密钥管理\n"
            "========\n\n"
            "zhcrypt 使用三套密钥体系：\n"
            "RSA-4096：用于混合加密（公钥加密 + 私钥解密）\n"
            "Ed25519：用于数字签名（验证消息来源）\n"
            "X25519： 用于前向安全密钥交换（X3DH）\n\n"
            "基本操作：\n\n"
            "1. 初始化身份\n"
            "   文件菜单 → 初始化身份\n"
            "   输入身份名和密码 → 生成三套密钥\n"
            "   密钥存储在 ~/.zhcrypt/keys/ 目录\n\n"
            "2. 导出公钥束\n"
            "   选择身份 → 点「导出完整公钥束」\n"
            "   得到 Base64 字符串，发给通信对方\n\n"
            "3. 导入对方公钥\n"
            "   收到对方的公钥束 → 点「导入公钥束」\n"
            "   粘贴 → 输入一个名字（如对方的身份名）\n\n"
            "4. 备份与恢复私钥\n"
            "   注意：Shamir 秘密分享备份/恢复目前仅命令行提供\n"
            "   （zhcrypt backup / restore），GUI 暂未集成图形按钮。\n"
            "   建议：妥善保管 ~/.zhcrypt/keys/ 下的私钥文件，切勿外传。\n\n"
            "安全提醒：\n"
            "私钥密码不要有规律，建议 16 位以上混合字符。\n"
            "公钥可以公开分享，私钥绝不外传。\n"
            "备份份额分布在至少 3 个不同地点。")

    def _on_about(self):
        messagebox.showinfo("关于 zhcrypt",
                            f"zhcrypt v{__version__} - 中文加密系统\n\n"
                            "密码学栈:\n"
                            "  Argon2id (RFC 9106) - 密钥派生\n"
                            "  AES-256-GCM - 对称加密\n"
                            "  RSA-4096-OAEP - 非对称加密\n"
                            "  Ed25519 - 数字签名\n"
                            "  X25519 X3DH - 前向安全\n\n"
                            "功能:\n"
                            "  文本/文件加密 · 数字签名\n"
                            "  前向安全(PFS) · Shamir备份\n"
                            "  可否认加密 · 密码强度检测\n"
                            "  端到端加密聊天 (Double Ratchet)\n\n"
                            "密钥存储: ~\\.zhcrypt\\keys\\")

    def _on_close(self):
        if self._chat_poll_id:
            self.root.after_cancel(self._chat_poll_id)
        if self._chat_client:
            try:
                self._chat_client.stop()
            except Exception:
                pass
        # R3: 退出时清空剪贴板与输出区, 减少敏感内容残留
        try:
            self.root.clipboard_clear()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self._refresh_hybrid_identities()
        self._maybe_first_run_wizard()
        self.root.mainloop()

    def _maybe_first_run_wizard(self):
        """Tier 3-9: 首次运行(本地无任何身份)弹出一步式引导。

        仅做『辅助』：可随时取消, 不影响手动流程; 任何一步失败都不阻断主程序。
        """
        try:
            if self.store.list_identities():
                return
        except Exception:
            return

        from tkinter import Toplevel
        from config import (set_prekey_server, set_key,
                            get_prekey_server, get_auth_token)

        win = Toplevel(self.root)
        win.title("首次设置向导")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)

        ttk.Label(win, text="欢迎使用 zhcrypt 加密聊天\n只需几步即可开始：",
                  justify=tk.LEFT, padding=(12, 12, 12, 4)).pack(anchor=tk.W)

        frm = ttk.Frame(win, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="服务器地址:").grid(row=0, column=0, sticky="w", pady=3)
        url_var = tk.StringVar(value=get_prekey_server() or "https://iweistoicqc5.top")
        ttk.Entry(frm, textvariable=url_var, width=38).grid(row=0, column=1, pady=3, padx=(6, 0))

        ttk.Label(frm, text="你的身份名:").grid(row=1, column=0, sticky="w", pady=3)
        id_var = tk.StringVar(value="default")
        ttk.Entry(frm, textvariable=id_var, width=38).grid(row=1, column=1, pady=3, padx=(6, 0))

        ttk.Label(frm, text="私钥密码:").grid(row=2, column=0, sticky="w", pady=3)
        pwd_var = tk.StringVar()
        ttk.Entry(frm, textvariable=pwd_var, show="*", width=38).grid(row=2, column=1, pady=3, padx=(6, 0))

        ttk.Label(frm, text="对方身份(可选):").grid(row=3, column=0, sticky="w", pady=3)
        peer_var = tk.StringVar()
        ttk.Entry(frm, textvariable=peer_var, width=38).grid(row=3, column=1, pady=3, padx=(6, 0))

        status = ttk.Label(frm, text="")
        status.grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

        def _finish():
            url = url_var.get().strip()
            ident = id_var.get().strip()
            pwd = pwd_var.get()
            if not url or not ident or not pwd:
                status.config(text="服务器 / 身份 / 密码 均为必填")
                return
            try:
                set_prekey_server(url)
                self.store.generate_identity(ident, pwd)
                set_key("default_identity", ident)
                # 自动上传 prekey (问题3 修复：统一调用唯一实现，顺带修掉原内联缺 json 导入的隐患)
                ok, _ = self._upload_prekey_to_server(ident, pwd, show_dialog=False)
                if not ok:
                    status.config(text="身份已建, 但上传 Prekey 失败 (可稍后在设置里重传)")
            except Exception as e:
                status.config(text="设置出错: %s" % e)
                return
            try:
                self.chat_identity_var.set(ident)
                self._refresh_chat_contacts()
                pv = peer_var.get().strip()
                if pv:
                    self.chat_peer_var.set(pv)
                    self._refresh_chat_contacts()
            except Exception:
                pass
            messagebox.showinfo("完成",
                "设置完成！现在选择对方并点击「连接」即可开始端到端加密聊天。")
            win.destroy()

        btn_row = ttk.Frame(win, padding=(12, 0, 12, 12))
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="完成", command=_finish).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(btn_row, text="稍后再说", command=win.destroy).pack(side=tk.RIGHT)

        win.wait_window()


def main():
    app = ZhCryptGUI()
    app.run()


if __name__ == "__main__":
    main()
