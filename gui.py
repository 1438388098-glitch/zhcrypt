#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt GUI - 中文加密系统图形面板
基于 Tkinter + ttk, 无需额外安装
"""

import os
import sys
import time
import tempfile
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
    DecryptionError, MAGIC,
    serialize_public_key,
)
from keys import KeyStore


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
                         background="#ffffcc", foreground="#000000",
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
        colors = ["#ddd", "#e74c3c", "#e67e22", "#f1c40f", "#2ecc71", "#27ae60"]
        widths = [0, 24, 48, 72, 96, 120]
        idx = max(0, min(score, 5))
        self.canvas.itemconfig(self._bar, fill=colors[idx], width=widths[idx])
        self.canvas.coords(self._bar, 0, 0, widths[idx], 14)
        self.canvas.itemconfig(self._label, text=label)


class ZhCryptGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("zhcrypt - 中文加密系统 v3.0")
        self.root.geometry("720x560")
        self.root.minsize(600, 440)

        try:
            self.root.iconbitmap()
        except Exception:
            pass

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.store = KeyStore()
        self._current_password = ""
        self._chat_client = None
        self._chat_peer = None
        self._chat_poll_id = None

        self._build_menu()
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
        entry = ttk.Entry(frame, width=28, show="*")
        entry.pack(side=tk.LEFT, padx=(0, 4))
        btn = ttk.Checkbutton(frame, text="显示", variable=show_var,
                              command=lambda: entry.config(
                                  show="" if show_var.get() else "*"))
        btn.pack(side=tk.LEFT)
        return frame, entry, show_var

    # ============================================================
    # Tab 1: 文本加解密
    # ============================================================
    def _build_text_tab(self):
        main = ttk.Frame(self.tab_text, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="加密文本 (支持中文/英文/数字/Emoji)",
                  font=("", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))

        ttk.Label(main, text="输入明文:").pack(anchor=tk.W)
        self.text_input = tk.Text(main, height=5, wrap=tk.WORD, font=("Consolas", 10))
        self.text_input.pack(fill=tk.BOTH, expand=True, pady=(2, 8))

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
                "密码强度实时评估。弱<30bits → 红  中30-50 → 橙\n强50-80 → 黄  极强>80 → 绿\n每次密钥派生使用 Argon2id(256MB)")

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
        self.text_output = tk.Text(main, height=4, wrap=tk.WORD, font=("Consolas", 10), bg="#f5f5f5")
        self.text_output.pack(fill=tk.BOTH, expand=True, pady=(2, 4))

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
        color_map = {"weak": "#e74c3c", "medium": "#e67e22", "strong": "#2ecc71", "very_strong": "#27ae60"}
        self.text_strength_label.config(
            text=f"{level_map.get(s['level'], '?')} ({s['entropy']:.0f} bits)",
            foreground=color_map.get(s["level"], "#000"))

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
            packet = encrypt_password_mode(plain, pwd)
            b64 = packet_to_b64(packet)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", b64)
            self.text_sig_status.config(text="")
            self._set_status(f"加密完成 (明文 {len(plain)} 字符 -> 密文 {len(b64)} 字符)", 6000)
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

            if mode == 3:
                self._decrypt_signed(packet, pwd)
            elif mode == 4:
                self.text_sig_status.config(
                    text="ℹ PFS 模式需在混合模式标签解密",
                    foreground="#e67e22")
                self.text_output.delete("1.0", tk.END)
                self.text_output.insert("1.0", "请将密文粘贴到混合模式标签解密")
            else:
                plain = decrypt_password_mode(packet, pwd)
                self.text_output.delete("1.0", tk.END)
                self.text_output.insert("1.0", plain)
                self.text_sig_status.config(text="")
                self._set_status("解密成功", 6000)
        except DecryptionError as e:
            messagebox.showerror("解密失败", str(e))
        except ValueError as e:
            messagebox.showerror("格式错误", str(e))
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {e}")

    def _decrypt_signed(self, packet, passphrase):
        from config import get
        try:
            from core import decrypt_hybrid_signed
            store_key = KeyStore()
            idents = store_key.list_identities()
            if not idents:
                raise DecryptionError("无可用身份")
            identity = idents[0]["identity"]
            priv_pem = store_key.load_private_key_pem(identity, passphrase)
            result = decrypt_hybrid_signed(packet, priv_pem, passphrase)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", result["plaintext"])
            if result["verified"]:
                self.text_sig_status.config(
                    text=f"✅ 签名验证通过 (来自: {result['sender']})",
                    foreground="#27ae60")
            else:
                self.text_sig_status.config(
                    text=f"⚠️ 签名验证失败 (来自: {result['sender']})",
                    foreground="#e67e22")
            self._set_status("解密成功", 6000)
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {e}")

    def _on_copy_output(self):
        text = self.text_output.get("1.0", "end-1c").strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._set_status("已复制到剪贴板", 3000)

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
        words = ["山茶", "东风", "白云", "松柏", "流水", "明月", "清风", "远山",
                 "晨露", "晚霞", "飞鸟", "落叶", "寒星", "暖阳", "翠竹", "幽兰"]
        chosen = [secrets.choice(words) for _ in range(4)]
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
                text="⚠ 此口令仅显示一次, 不会存储",
                foreground="#e67e22")
            self._set_status("临时口令已生成", 6000)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {e}")
        self._set_status("已清空", 2000)

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
        self.file_log = tk.Text(main, height=10, wrap=tk.WORD, font=("Consolas", 9),
                                bg="#f5f5f5", state=tk.DISABLED)
        self.file_log.pack(fill=tk.BOTH, expand=True, pady=(2, 0))

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
        try:
            src_size = os.path.getsize(path)
            use_stream = src_size > 10 * 1024 * 1024  # > 10MB use streaming
            self._file_log_append(f"[加密] {path} ({src_size:,} bytes)")
            if use_stream:
                out = encrypt_file_stream(path, pwd)
                self._file_log_append("  (使用流式分块模式)")
            else:
                out = encrypt_file_password_mode(path, pwd)
            out_size = os.path.getsize(out)
            self._file_log_append(f"  -> {out} ({out_size:,} bytes)")
            self._set_status(f"加密完成: {os.path.basename(out)}", 8000)
        except Exception as e:
            self._file_log_append(f"  [错误] {e}")
            messagebox.showerror("错误", str(e))

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
            if hdr[:4] == b"ZHCR":
                mode_byte = hdr[5:6]
                if mode_byte == bytes([5]):
                    try:
                        out = decrypt_file_stream(path, pwd, overwrite=False)
                    except FileExistsError:
                        if not messagebox.askyesno("确认覆盖", f"输出文件已存在，是否覆盖?"):
                            return
                        out = decrypt_file_stream(path, pwd, overwrite=True)
                else:
                    try:
                        out = decrypt_file_password_mode(path, pwd, overwrite=False)
                    except FileExistsError:
                        if not messagebox.askyesno("确认覆盖", f"输出文件已存在，是否覆盖?"):
                            return
                        out = decrypt_file_password_mode(path, pwd, overwrite=True)
            else:
                try:
                    out = decrypt_file_password_mode(path, pwd, overwrite=False)
                except FileExistsError:
                    if not messagebox.askyesno("确认覆盖", f"输出文件已存在，是否覆盖?"):
                        return
                    out = decrypt_file_password_mode(path, pwd, overwrite=True)

            self._file_log_append(f"  -> {out}")
            self._set_status(f"解密完成: {os.path.basename(out)}", 8000)
        except DecryptionError as e:
            self._file_log_append(f"  [错误] {e}")
            messagebox.showerror("解密失败", str(e))
        except FileExistsError as e:
            self._file_log_append(f"  [错误] {e}")
            messagebox.showerror("文件已存在", str(e))
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
        self.tree = ttk.Treeview(main, columns=columns, show="headings",
                                 selectmode="browse", height=6)
        self.tree.heading("identity", text="身份")
        self.tree.heading("fingerprint", text="指纹")
        self.tree.heading("comment", text="备注")
        self.tree.heading("created", text="创建时间")
        self.tree.column("identity", width=100)
        self.tree.column("fingerprint", width=140)
        self.tree.column("comment", width=150)
        self.tree.column("created", width=180)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        export_frame = ttk.LabelFrame(main, text="导出公钥 (分享给他人)", padding=8)
        export_frame.pack(fill=tk.X, pady=(0, 8))
        exp_row = ttk.Frame(export_frame)
        exp_row.pack(fill=tk.X)
        ttk.Button(exp_row, text="导出选中身份公钥",
                   command=self._on_export_key).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(exp_row, text="复制到剪贴板",
                   command=self._on_copy_exported_key).pack(side=tk.LEFT)
        self.exported_key_text = tk.Text(export_frame, height=3, wrap=tk.WORD,
                                         font=("Consolas", 9), bg="#f5f5f5",
                                         state=tk.DISABLED)
        self.exported_key_text.pack(fill=tk.X, pady=(6, 0))

        import_frame = ttk.LabelFrame(main, text="导入他人公钥", padding=8)
        import_frame.pack(fill=tk.X)
        imp_top = ttk.Frame(import_frame)
        imp_top.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(imp_top, text="身份名:").pack(side=tk.LEFT, padx=(0, 4))
        self.import_name_entry = ttk.Entry(imp_top, width=20)
        self.import_name_entry.pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(imp_top, text="从剪贴板导入",
                   command=self._on_import_from_clipboard).pack(side=tk.LEFT)

        bundle_frame = ttk.LabelFrame(main, text="完整公钥束 (聊天用)", padding=8)
        bundle_frame.pack(fill=tk.X, pady=(8, 0))
        bnd_top = ttk.Frame(bundle_frame)
        bnd_top.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(bnd_top, text="导出完整公钥束",
                   command=self._on_export_bundle).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(bnd_top, text="复制到剪贴板",
                   command=self._on_copy_bundle).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(bnd_top, text="导入完整公钥束",
                   command=self._on_import_bundle).pack(side=tk.LEFT)
        self.bundle_text = tk.Text(bundle_frame, height=2, wrap=tk.WORD,
                                    font=("Consolas", 8), bg="#f5f5f5")
        self.bundle_text.pack(fill=tk.X, pady=(4, 0))

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
        except Exception:
            pass

    def _refresh_cfg_identities(self):
        try:
            ids = [id_["identity"] for id_ in self.store.list_identities()]
            self.cfg_pk_identity_combo["values"] = ids
            if ids and not self.cfg_pk_identity_var.get():
                self.cfg_pk_identity_var.set(ids[0])
        except Exception:
            pass
        try:
            ids = [id_["identity"] for id_ in self.store.list_identities()]
            self.chat_identity_combo["values"] = ids
        except Exception:
            pass

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
            if len(pwd.encode("utf-8")) < 8:
                if not messagebox.askyesno("确认", "密码较短, 是否继续?", parent=dialog):
                    return
            try:
                info = self.store.generate_identity(name, pwd, comment)
                self._refresh_identity_list()
                self._refresh_hybrid_identities()
                messagebox.showinfo("成功", f"身份 '{name}' 创建成功!\n指纹: {info['fingerprint']}",
                                    parent=dialog)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("错误", str(e), parent=dialog)

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

    def _on_export_key(self):
        identity = self._get_selected_identity()
        if not identity:
            return
        try:
            b64 = self.store.export_public_key_b64(identity)
            self.exported_key_text.config(state=tk.NORMAL)
            self.exported_key_text.delete("1.0", tk.END)
            self.exported_key_text.insert("1.0", b64)
            self.exported_key_text.config(state=tk.DISABLED)
            self._set_status(f"已导出 '{identity}' 公钥", 4000)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _on_copy_exported_key(self):
        text = self.exported_key_text.get("1.0", "end-1c").strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._set_status("公钥已复制到剪贴板", 3000)

    def _on_import_from_clipboard(self):
        name = self.import_name_entry.get().strip()
        if not name:
            messagebox.showwarning("警告", "请输入身份名")
            return
        try:
            b64 = self.root.clipboard_get()
        except Exception:
            messagebox.showwarning("警告", "剪贴板为空")
            return
        try:
            self.store.import_public_key_b64(b64, name)
            self._refresh_identity_list()
            self._refresh_hybrid_identities()
            self._set_status(f"已导入公钥 '{name}'", 4000)
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
        ttk.Label(sender_frame, text="发送方 (你自己):").pack(side=tk.LEFT, padx=(0, 4))
        self.hybrid_sender_var = tk.StringVar()
        self.hybrid_sender_combo = ttk.Combobox(sender_frame,
                                                textvariable=self.hybrid_sender_var,
                                                width=18, state="readonly")
        self.hybrid_sender_combo.pack(side=tk.LEFT, padx=(0, 16))

        ttk.Label(sender_frame, text="接收方:").pack(side=tk.LEFT, padx=(0, 4))
        self.hybrid_receiver_var = tk.StringVar()
        self.hybrid_receiver_combo = ttk.Combobox(sender_frame,
                                                  textvariable=self.hybrid_receiver_var,
                                                  width=18, state="readonly")
        self.hybrid_receiver_combo.pack(side=tk.LEFT)

        ttk.Label(main, text="输入明文:").pack(anchor=tk.W)
        self.hybrid_input = tk.Text(main, height=4, wrap=tk.WORD, font=("Consolas", 10))
        self.hybrid_input.pack(fill=tk.BOTH, expand=True, pady=(2, 6))

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
        self.hybrid_output = tk.Text(main, height=4, wrap=tk.WORD, font=("Consolas", 10),
                                     bg="#f5f5f5")
        self.hybrid_output.pack(fill=tk.BOTH, expand=True, pady=(2, 0))

    # ============================================================
    # Tab 5: 系统配置 (新增)
    # ============================================================
    def _build_config_tab(self):
        from config import load as _cl
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

        row_ident = ttk.Frame(frame_prekey)
        row_ident.pack(fill=tk.X, pady=4)
        ttk.Label(row_ident, text="身份:").pack(side=tk.LEFT, padx=(0, 4))
        self.cfg_pk_identity_var = tk.StringVar()
        self.cfg_pk_identity_combo = ttk.Combobox(row_ident, textvariable=self.cfg_pk_identity_var,
                                                    state="readonly", width=20)
        self.cfg_pk_identity_combo.pack(side=tk.LEFT, padx=(0, 12))
        ToolTip(self.cfg_pk_identity_combo, "选择要上传 Prekey 的身份。\n每个身份只需上传一次，双方都要上传。")

        row_pk_btn = ttk.Frame(frame_prekey)
        row_pk_btn.pack(fill=tk.X, pady=4)
        ttk.Button(row_pk_btn, text="测试连接", command=self._on_test_prekey).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(row_pk_btn, text="保存配置", command=self._on_save_prekey).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(row_pk_btn, text="上传 Prekey", command=self._on_upload_prekey).pack(side=tk.LEFT)
        self.cfg_pk_status = ttk.Label(row_pk_btn, text="未连接", foreground="#888")
        self.cfg_pk_status.pack(side=tk.LEFT, padx=12)

        frame_info = ttk.LabelFrame(main, text="系统信息", padding=10)
        frame_info.pack(fill=tk.X)
        info_text = f"版本: zhcrypt v3.0.0\nPython: {sys.version[:5]}"
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
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            req = urllib.request.Request(url + "/v1/health")
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                data = j.loads(resp.read())
            if data.get("status") == "ok":
                self.cfg_pk_status.config(text="✅ 已连接", foreground="#27ae60")
                self._set_status("Prekey 服务器连接正常", 4000)
            else:
                self.cfg_pk_status.config(text="⚠ 响应异常", foreground="#e67e22")
        except Exception as e:
            self.cfg_pk_status.config(text=f"❌ 连接失败", foreground="#e74c3c")
            messagebox.showerror("连接失败", str(e))

    def _on_save_prekey(self):
        from config import load, save
        cfg = load()
        cfg["prekey_server"]["url"] = self.cfg_pk_url_var.get().rstrip("/")
        save(cfg)
        self._set_status("Prekey 服务器配置已保存", 4000)

    def _refresh_hybrid_identities(self):
        try:
            identities = [id_["identity"] for id_ in self.store.list_identities()]
        except Exception:
            identities = []
        try:
            self.hybrid_sender_combo["values"] = identities
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
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._set_status("已复制到剪贴板", 3000)

    def _on_export_bundle(self):
        identity = self._get_selected_identity()
        if not identity:
            return
        try:
            from keys import KeyStore
            bundle = self.store.export_public_key_bundle(identity)
            self.bundle_text.delete("1.0", tk.END)
            self.bundle_text.insert("1.0", bundle)
            self._set_status(f"已导出 {identity} 的完整公钥束", 4000)
        except FileNotFoundError as e:
            ret = messagebox.askyesno("缺少聊天密钥",
                f"身份「{identity}」是旧版创建的，缺少聊天所需的 X25519 密钥。\n\n"
                f"是否现在自动补全？（需要输入私钥密码）")
            if ret:
                pwd = simpledialog.askstring("私钥密码", f"为 {identity} 补全 X25519 密钥\n请输入私钥密码:",
                                              show="*", parent=self.root)
                if pwd:
                    try:
                        self.store.ensure_kem_keys(identity, pwd)
                        bundle = self.store.export_public_key_bundle(identity)
                        self.bundle_text.delete("1.0", tk.END)
                        self.bundle_text.insert("1.0", bundle)
                        self._set_status(f"已补全密钥并导出 {identity} 的公钥束", 4000)
                        messagebox.showinfo("成功", f"X25519 密钥已为 {identity} 补全")
                    except Exception as e2:
                        messagebox.showerror("错误", str(e2))
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _on_copy_bundle(self):
        text = self.bundle_text.get("1.0", "end-1c").strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._set_status("公钥束已复制", 3000)

    def _on_import_bundle(self):
        name = self.import_name_entry.get().strip()
        if not name:
            messagebox.showwarning("警告", "请先在上方输入身份名")
            return
        try:
            bundle = self.root.clipboard_get()
        except Exception:
            messagebox.showwarning("警告", "剪贴板为空")
            return
        try:
            self.store.import_public_key_bundle(bundle, name)
            self._refresh_identity_list()
            self._refresh_hybrid_identities()
            self._refresh_cfg_identities()
            self._refresh_chat_contacts()
            self._set_status(f"已导入 {name} 的完整公钥束", 4000)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _on_upload_prekey(self):
        identity = self.cfg_pk_identity_var.get()
        if not identity:
            messagebox.showwarning("警告", "请先在上方选择要上传的身份")
            return
        passphrase = simpledialog.askstring(
            "私钥密码", f"上传 {identity} 的 Prekey\n请输入私钥密码:", show="*", parent=self.root)
        if not passphrase:
            return
        try:
            bundle = self.store.generate_prekey_bundle(identity, passphrase, otp_count=50)
            import urllib.request, ssl, json
            from config import get_prekey_server, get_auth_token
            url = get_prekey_server()
            token = get_auth_token()
            if not url or not token:
                messagebox.showerror("错误", "请先在系统配置页设置服务器地址")
                return
            data = json.dumps(dict(bundle, identity=identity), ensure_ascii=False).encode()
            req = urllib.request.Request(url + "/v1/prekey/" + identity, data=data, method="POST")
            req.add_header("Authorization", "Bearer " + token)
            req.add_header("Content-Type", "application/json")
            ctx = ssl.create_default_context()
            resp = json.loads(urllib.request.urlopen(req, context=ctx, timeout=30).read())
            if resp.get("status") == "ok":
                self._set_status(f"Prekey 上传成功 (OTP: {resp.get('one_time_stored', 0)} 个)", 5000)
                messagebox.showinfo("成功", f"Prekey 上传成功！\nOTP: {resp.get('one_time_stored', 0)} 个")
            else:
                messagebox.showerror("错误", f"上传失败: {resp}")
        except Exception as e:
            messagebox.showerror("错误", f"上传失败: {e}")

    def _build_chat_tab(self):
        main = ttk.Frame(self.tab_chat, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        top_row = ttk.Frame(main)
        top_row.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(top_row, text="对方:").pack(side=tk.LEFT, padx=(0, 4))
        self.chat_peer_var = tk.StringVar()
        self.chat_peer_combo = ttk.Combobox(top_row, textvariable=self.chat_peer_var,
                                             state="readonly", width=20)
        self.chat_peer_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.chat_peer_combo.bind("<<ComboboxSelected>>", self._on_chat_select_peer)

        ttk.Label(top_row, text="身份:").pack(side=tk.LEFT, padx=(0, 4))
        self.chat_identity_var = tk.StringVar()
        self.chat_identity_combo = ttk.Combobox(top_row, textvariable=self.chat_identity_var,
                                                 state="readonly", width=14)
        self.chat_identity_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.chat_identity_combo.bind("<<ComboboxSelected>>", self._on_chat_identity_change)

        self.chat_connect_btn = ttk.Button(top_row, text="连接", command=self._on_chat_connect)
        self.chat_connect_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.chat_setup_btn = ttk.Button(top_row, text="? 聊天准备步骤", command=self._on_chat_setup_guide)
        self.chat_setup_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.chat_status_label = ttk.Label(top_row, text="● 未连接", foreground="#999")
        self.chat_status_label.pack(side=tk.LEFT, padx=(0, 12))

        self.chat_new_msg_label = ttk.Label(top_row, text="", foreground="#e74c3c", font=("", 9, "bold"))
        self.chat_new_msg_label.pack(side=tk.LEFT)

        msg_frame = ttk.Frame(main)
        msg_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        self.chat_msg_display = tk.Text(msg_frame, height=16, wrap=tk.WORD,
                                         font=("Microsoft YaHei", 10),
                                         state=tk.DISABLED, bg="#fafafa")
        chat_scroll = ttk.Scrollbar(msg_frame, command=self.chat_msg_display.yview)
        self.chat_msg_display.config(yscrollcommand=chat_scroll.set)
        chat_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_msg_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.chat_msg_display.tag_configure("peer", foreground="#2c3e50", font=("Microsoft YaHei", 9, "bold"))
        self.chat_msg_display.tag_configure("peer_text", foreground="#2c3e50", lmargin1=20, lmargin2=20,
                                             background="#e8e8e8", spacing1=4, spacing3=4)
        self.chat_msg_display.tag_configure("me", foreground="#1a5276", font=("Microsoft YaHei", 9, "bold"))
        self.chat_msg_display.tag_configure("me_text", foreground="#1a5276", lmargin1=20, lmargin2=20,
                                             background="#d4e6f1", spacing1=4, spacing3=4)
        self.chat_msg_display.tag_configure("verified", foreground="#27ae60", font=("Microsoft YaHei", 7))
        self.chat_msg_display.tag_configure("unverified", foreground="#e67e22", font=("Microsoft YaHei", 7))
        self.chat_msg_display.tag_configure("system", foreground="#999", font=("Microsoft YaHei", 8))
        self.chat_msg_display.tag_configure("error", foreground="#e74c3c", font=("Microsoft YaHei", 8))

        input_row = ttk.Frame(main)
        input_row.pack(fill=tk.X)

        self.chat_input = ttk.Entry(input_row, font=("Microsoft YaHei", 10))
        self.chat_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.chat_input.bind("<Return>", lambda e: self._on_chat_send())

        self.chat_send_btn = ttk.Button(input_row, text="发送", command=self._on_chat_send)
        self.chat_send_btn.pack(side=tk.LEFT)

        bottom_row = ttk.Frame(main)
        bottom_row.pack(fill=tk.X, pady=(4, 0))
        self.chat_enc_status = ttk.Label(bottom_row, text="E2E 加密中 | X3DH + Double Ratchet",
                                          font=("Microsoft YaHei", 7), foreground="#999")
        self.chat_enc_status.pack(side=tk.LEFT)

        self._refresh_chat_contacts()

    def _refresh_chat_contacts(self):
        peers = []
        try:
            import os as _os
            d = _os.path.join(_os.path.expanduser("~"), ".zhcrypt", "keys")
            if _os.path.exists(d):
                for fn in _os.listdir(d):
                    if fn.endswith(".meta"):
                        ident = fn[:-5]
                        meta_path = _os.path.join(d, fn)
                        try:
                            with open(meta_path, "r", encoding="utf-8") as f:
                                import json as _json
                                meta = _json.load(f)
                            if meta.get("type") in ("imported_public_key_bundle", "imported_public_key"):
                                peers.append(ident)
                        except Exception:
                            pass
        except Exception:
            pass
        try:
            self.chat_peer_combo["values"] = peers
        except Exception:
            pass

        identities = []
        try:
            identities = [id_["identity"] for id_ in self.store.list_identities()]
        except Exception:
            pass
        try:
            self.chat_identity_combo["values"] = identities
        except Exception:
            pass
        if identities:
            from config import get as _cfg_get
            default_id = _cfg_get("default_identity", "default")
            if default_id in identities:
                self.chat_identity_var.set(default_id)
            elif not self.chat_identity_var.get():
                self.chat_identity_var.set(identities[0])

    def _on_chat_select_peer(self, event=None):
        peer = self.chat_peer_var.get()
        if peer:
            self._on_chat_connect()

    def _on_chat_identity_change(self, event=None):
        if self._chat_client:
            try:
                self._chat_client.stop()
            except Exception:
                pass
            self._chat_client = None
        self._chat_peer = None
        self.chat_status_label.config(text="● 未连接", foreground="#999")

    def _on_chat_setup_guide(self):
        messagebox.showinfo("聊天准备步骤",
            "开始聊天前需要完成以下准备：\n\n"
            "▸ 步骤一：配置服务器\n"
            "  切换到「系统配置」标签\n"
            "  输入 URL: https://iweistoicqc5.top\n"
            "  点「测试连接」确保服务器可达\n\n"
            "▸ 步骤二：创建身份（如果还没有）\n"
            "  文件菜单 → 初始化身份\n"
            "  输入身份名和密码\n\n"
            "▸ 步骤三：交换公钥束\n"
            "  你：「密钥管理」→ 导出完整公钥束 → 发给朋友\n"
            "  朋友也导出他的公钥束发给你\n"
            "  你：粘贴朋友公钥束 → 输入身份名 → 导入完整公钥束\n\n"
            "▸ 步骤四：上传 Prekey\n"
            "  切换到「系统配置」标签\n"
            "  点「上传 Prekey」→ 输入私钥密码\n"
            "  朋友也要做这一步\n\n"
            "▸ 步骤五：开始聊天\n"
            "  回到本标签 → 选择身份和对方 → 点「连接」")

    def _on_chat_connect(self):
        peer = self.chat_peer_var.get()
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

        peer_exists = False
        try:
            self.store.load_signing_public_key(peer)
            peer_exists = True
        except Exception:
            pass

        if not peer_exists:
            ret = messagebox.askyesno("缺少对方公钥",
                f"还没有导入「{peer}」的公钥束。\n\n"
                "需要先和对方交换公钥：\n"
                f"1. 在「密钥管理」标签选中「{identity}」→ 导出完整公钥束\n"
                "2. 把公钥束复制发给对方\n"
                "3. 让对方把他的公钥束也发给你\n"
                "4. 粘贴对方公钥束 → 点「导入完整公钥束」\n\n"
                "现在去导入吗？")
            if ret:
                self.notebook.select(self.tab_keys)
            return

        import simpledialog as _sd
        passphrase = _sd.askstring("私钥密码", f"[{identity}] 请输入私钥密码:",
                                     show="*", parent=self.root)
        if not passphrase:
            return

        if self._chat_client:
            try:
                self._chat_client.stop()
            except Exception:
                pass
        if self._chat_poll_id:
            self.root.after_cancel(self._chat_poll_id)

        from chat_client import ChatClient
        self._chat_client = ChatClient(identity, passphrase)
        self._chat_client._passphrase = passphrase
        self._chat_client.start()
        self.chat_status_label.config(text="● 连接中...", foreground="#f1c40f")
        self._chat_peer = peer

        self._append_chat_msg("system", f"正在连接到 {server_url} ...")
        self.root.after(2000, self._check_chat_connected)

    def _check_chat_connected(self):
        if not self._chat_client:
            return
        if self._chat_client.connected:
            self.chat_status_label.config(text="● 已连接", foreground="#27ae60")
            self._append_chat_msg("system", "已连接到服务器")
            self._chat_poll_id = self.root.after(2000, self._poll_chat)
        else:
            self._append_chat_msg("system", "连接中...")
            self.root.after(2000, self._check_chat_connected)

        items = self._chat_client.process_inbound()
        for item in items:
            if item.get("action") == "server_message":
                data = item["data"]
                if data.get("type") == "message":
                    result = self._chat_client.receive_chat_message(data["msg"])
                    if result and "error" not in result:
                        self._display_chat_message(result)
            elif item.get("action") == "error":
                self._append_chat_msg("error", item["message"])

    def _poll_chat(self):
        if not self._chat_client:
            return

        items = self._chat_client.process_inbound()
        new_count = 0
        for item in items:
            if item.get("action") == "server_message":
                data = item["data"]
                if data.get("type") == "message":
                    result = self._chat_client.receive_chat_message(data["msg"])
                    if result and "error" not in result:
                        self._display_chat_message(result)
                        new_count += 1
                    elif result and "error" in result:
                        self._append_chat_msg("error", f"解密失败: {result['error']}")
            elif item.get("action") == "status":
                connected = item.get("connected", False)
                if connected:
                    self.chat_status_label.config(text="● 已连接", foreground="#27ae60")
                else:
                    self.chat_status_label.config(text="● 已断开", foreground="#e74c3c")

        try:
            poll_results = self._chat_client.poll_messages()
            for r in poll_results:
                if "error" not in r:
                    self._display_chat_message(r)
                    new_count += 1
        except Exception:
            pass

        if new_count:
            self.chat_new_msg_label.config(text=f"新消息: +{new_count}")

        self._chat_poll_id = self.root.after(2000, self._poll_chat)

    def _display_chat_message(self, result):
        from datetime import datetime
        ts = datetime.fromtimestamp(result["timestamp"]).strftime("%H:%M")
        who = result["from"]
        text = result["text"]
        verified = result.get("verified", False)

        self.chat_msg_display.config(state=tk.NORMAL)
        if who != self.chat_identity_var.get():
            self.chat_msg_display.insert(tk.END, f"\n{who}  {ts}\n", "peer")
            self.chat_msg_display.insert(tk.END, f"  {text}\n", "peer_text")
            if verified:
                self.chat_msg_display.insert(tk.END, "  (签名已验证)\n", "verified")
        else:
            self.chat_msg_display.insert(tk.END, f"\n你  {ts}\n", "me")
            self.chat_msg_display.insert(tk.END, f"  {text}\n", "me_text")

        self.chat_msg_display.config(state=tk.DISABLED)
        self.chat_msg_display.see(tk.END)

    def _append_chat_msg(self, tag, text):
        self.chat_msg_display.config(state=tk.NORMAL)
        self.chat_msg_display.insert(tk.END, f"[{text}]\n", tag)
        self.chat_msg_display.config(state=tk.DISABLED)
        self.chat_msg_display.see(tk.END)

    def _on_chat_send(self):
        text = self.chat_input.get().strip()
        if not text:
            return
        peer = self._chat_peer or self.chat_peer_var.get()
        if not peer:
            messagebox.showwarning("警告", "请先选择对方并连接")
            return
        if not self._chat_client:
            messagebox.showwarning("警告", "请先连接")
            return

        self.chat_input.delete(0, tk.END)

        try:
            result = self._chat_client.send_chat_message(peer, text)
            if result.get("error"):
                self._append_chat_msg("error", f"发送失败: {result['error']}")
                return

            self._display_chat_message({
                "from": self.chat_identity_var.get(),
                "timestamp": time.time(),
                "text": text,
                "verified": True,
            })
            self._set_status("消息已发送", 3000)
        except Exception as e:
            self._append_chat_msg("error", f"发送失败: {e}")

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
            "1. 前提准备（双方都要做）\n"
            "   a) 打开「系统配置」标签，设置服务器地址：https://iweistoicqc5.top\n"
            "   b) 点击「测试连接」确认服务器可达\n"
            "   c) 打开「混合模式」标签，选择你的身份，输入私钥密码\n"
            "   d) 点击「上传 Prekey」把密钥注册到服务器\n\n"
            "2. 交换公钥\n"
            "   a) 你：点击「导出完整公钥束」→ 把得到的 Base64 发给对方\n"
            "   b) 对方：点击「导入完整公钥束」→ 粘贴你的公钥\n"
            "   c) 对方也把公钥发给你，你同样导入\n\n"
            "3. 开始聊天\n"
            "   a) 打开「聊天」标签\n"
            "   b) 在「身份」下拉框选择你自己\n"
            "   c) 在「对方」下拉框选择聊天对象\n"
            "   d) 点「连接」按钮，输入你的私钥密码\n"
            "   e) 看到「已连接」绿色状态后，在输入框打字\n"
            "   f) 按回车或点「发送」\n\n"
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
            "A: v1 暂不支持文件传输，请用「文件加密」标签加密后用其他方式发送。")

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
            "三种模式：\n"
            "RSA 模式：仅加密，无签名\n"
            "带签名模式：加密 + Ed25519 数字签名，防冒充\n"
            "PFS 模式：前向安全，密钥不长期留存")

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
            "点「临时口令」生成 4 个随机中文词的密码，\n"
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
            "4. 备份私钥（Shamir 秘密分享）\n"
            "   选择身份 → 输入密码 → 点「备份私钥」\n"
            "   生成 5 份份额文件，任何一个 3 份即可恢复\n"
            "   适合分给多个信任的人保管\n\n"
            "5. 恢复私钥\n"
            "   点「恢复私钥」→ 选择 3 份份额文件 → 还原私钥\n\n"
            "安全提醒：\n"
            "私钥密码不要有规律，建议 16 位以上混合字符。\n"
            "公钥可以公开分享，私钥绝不外传。\n"
            "备份份额分布在至少 3 个不同地点。")

    def _on_about(self):
        messagebox.showinfo("关于 zhcrypt",
                            "zhcrypt v3.0 - 中文加密系统\n\n"
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
        self.root.destroy()

    def run(self):
        self._refresh_hybrid_identities()
        self.root.mainloop()


def main():
    app = ZhCryptGUI()
    app.run()


if __name__ == "__main__":
    main()
