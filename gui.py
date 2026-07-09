#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zhcrypt GUI - 中文加密系统图形面板
基于 Tkinter + ttk, 无需额外安装
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

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

        self._build_menu()
        self._build_notebook()
        self._build_status_bar()
        self._refresh_identity_list()

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
        help_menu.add_command(label="关于", command=self._on_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 0))

        self.tab_text = ttk.Frame(self.notebook)
        self.tab_file = ttk.Frame(self.notebook)
        self.tab_keys = ttk.Frame(self.notebook)
        self.tab_hybrid = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_text, text=" 文本加解密 ")
        self.notebook.add(self.tab_file, text=" 文件加解密 ")
        self.notebook.add(self.tab_keys, text=" 密钥管理 ")
        self.notebook.add(self.tab_hybrid, text=" 混合模式 ")

        self._build_text_tab()
        self._build_file_tab()
        self._build_keys_tab()
        self._build_hybrid_tab()

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

        pwd_frame, self.text_pwd_entry, _ = self._make_password_frame(
            main, "加密密码")
        pwd_frame.pack(anchor=tk.W, pady=(0, 4))

        btn_row = ttk.Frame(main)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(btn_row, text="加密", command=self._on_text_encrypt).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="解密", command=self._on_text_decrypt).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="复制密文", command=self._on_copy_output).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="清空", command=self._on_clear_text).pack(side=tk.LEFT)

        ttk.Label(main, text="输出结果:").pack(anchor=tk.W)
        self.text_output = tk.Text(main, height=5, wrap=tk.WORD, font=("Consolas", 10),
                                   bg="#f5f5f5")
        self.text_output.pack(fill=tk.BOTH, expand=True, pady=(2, 0))

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
            self._set_status(f"加密完成 (明文 {len(plain)} 字符 -> 密文 {len(b64)} 字符)", 6000)
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {e}")

    def _on_text_decrypt(self):
        cipher = self.text_input.get("1.0", "end-1c").strip()
        if not cipher:
            messagebox.showwarning("警告", "请输入密文 (Base64)")
            return
        pwd = self.text_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入解密密码")
            return
        try:
            packet = b64_to_packet(cipher)
            plain = decrypt_password_mode(packet, pwd)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", plain)
            self._set_status("解密成功", 6000)
        except DecryptionError as e:
            messagebox.showerror("解密失败", str(e))
        except ValueError as e:
            messagebox.showerror("格式错误", str(e))
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

    def _refresh_hybrid_identities(self):
        try:
            identities = [id_["identity"] for id_ in self.store.list_identities()]
        except Exception:
            identities = []
        self.hybrid_sender_combo["values"] = identities
        self.hybrid_receiver_combo["values"] = identities
        if identities:
            if not self.hybrid_sender_var.get():
                self.hybrid_sender_var.set(identities[0])

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

    def _on_about(self):
        messagebox.showinfo("关于 zhcrypt",
                            "zhcrypt v3.0 - 中文加密系统\n\n"
                            "密码学栈:\n"
                            "  Argon2id (RFC 9106) - 密钥派生\n"
                            "  AES-256-GCM - 对称加密\n"
                            "  RSA-4096-OAEP - 非对称加密\n\n"
                            "密钥存储: ~\\.zhcrypt\\keys\\")

    def _on_close(self):
        self.root.destroy()

    def run(self):
        self._refresh_hybrid_identities()
        self.root.mainloop()


def main():
    app = ZhCryptGUI()
    app.run()


if __name__ == "__main__":
    main()
