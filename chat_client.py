"""
zhchat Client v1.0
===================
WebSocket 客户端, 集成消息收发、重连、REST 降级

架构:
  后台线程 (WebSocket) ←→ queue.Queue ←→ 主线程 (Tkinter/CLI)
"""

import os
import sys
import json
import time
import queue
import threading
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import urlsafe_b64decode, urlsafe_b64encode, DecryptionError
from keys import KeyStore, compute_safety_number
from config import load, get_prekey_server, get_auth_token
from ratchet import (
    SessionState, send_message, receive_message, try_decrypt_skipped,
    x3dh_initiate_session, x3dh_complete_session,
    complete_session_first_message,
    pem_priv_to_raw, raw_to_pem_pub, _b64, _b64d, KEY_SIZE, KDF_CK,
    x3dh_reply_msg,
)
from session import save_session, load_session, list_sessions, delete_session, session_lock

INBOUND = queue.Queue()
OUTBOUND = queue.Queue()


def build_ws_sslopt(ws_url):
    """为 wss 连接构造启用证书校验的 sslopt (审计 #3/#4)。

    仅当使用 wss:// 时才要求校验 CA 链与主机名; ws:// (本地/开发) 不启用。
    返回空 dict 表示不加密 (等同于开发态)。
    """
    import ssl
    if ws_url.startswith("wss://"):
        return {"cert_reqs": ssl.CERT_REQUIRED, "check_hostname": True}
    return {}


def _friendly_conn_error(e):
    """把连接异常映射为可读中文短句 (M17: 不再把 traceback 糊给用户)。"""
    msg = str(e)
    name = type(e).__name__
    if name == "ConnectionRefusedError" or "Connection refused" in msg:
        return "无法连接服务器: 服务器未启动或地址错误"
    if name == "gaierror" or "getaddrinfo" in msg or "Name or service not known" in msg:
        return "无法解析服务器域名, 请检查网络或服务器地址"
    if name == "TimeoutError" or "timed out" in msg:
        return "连接服务器超时, 正在自动重试"
    if "SSLCertVerificationError" in msg or "certificate" in msg.lower():
        return "服务器证书校验失败, 可能被中间人劫持"
    if "AuthenticationError" in msg or "认证失败" in msg:
        return "服务器认证失败: token 可能已失效"
    if name == "ConnectionResetError" or "Connection reset" in msg:
        return "服务器连接被重置, 正在自动重连"
    return f"连接失败: {msg[:80]}"


class ChatClient:
    def __init__(self, identity, passphrase):
        self.identity = identity
        self.passphrase = passphrase
        self.store = KeyStore()
        self.ws = None
        self.ws_thread = None
        self._running = False
        self._connected = False
        self._ws_ready = False
        self._reconnect_delay = 1
        self._max_reconnect_delay = 60
        self._send_queue = queue.Queue()

        self._server_url = get_prekey_server()
        self._token = get_auth_token()

        self._ws_url = self._server_url.replace("https://", "wss://").replace("http://", "ws://")
        if not self._ws_url.endswith("/"):
            self._ws_url += "/"
        self._ws_url += "v1/chat"

    @property
    def connected(self):
        return self._connected

    @property
    def ws_ready(self):
        return self._ws_ready

    def start(self):
        if self._running:
            return
        self._running = True
        self.ws_thread = threading.Thread(target=self._ws_loop, daemon=True)
        self.ws_thread.start()

    def stop(self):
        self._running = False
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
        self._connected = False
        self._ws_ready = False

    def _http_request(self, method, path, body=None, timeout=15):
        import urllib.request
        import ssl
        import json as _json
        import urllib.parse

        base = self._server_url.rstrip("/")
        encoded_path = urllib.parse.quote(path, safe='/&=?')
        url = f"{base}{encoded_path}"

        # 审计 #18: REST 同样做证书固定 (prekey 下载是 MITM 主要目标)
        pin = self._get_cert_pin()
        if pin and self._server_url.startswith("https://"):
            self._verify_rest_cert_pin(pin)

        data = None
        if body:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Content-Type", "application/json")
        # Cloudflare 按 UA 拦截: urllib 默认 "Python-urllib/x.y" 会被 403 (1010),
        # 必须带应用 UA 才能通过 CDN
        req.add_header("User-Agent", "zhcrypt-client/3.1")

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return _json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8")[:200]
            except Exception:
                pass
            return {"error": f"HTTP {e.code}: {body_text or e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    def _host_port_from_url(self, url):
        from urllib.parse import urlparse
        p = urlparse(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        return p.hostname, port

    def _verify_rest_cert_pin(self, pin):
        """在真正发请求前, 先对服务端证书做固定校验 (审计 #18, REST 路径)。"""
        import hmac
        from certpin import fetch_cert_pin
        host, port = self._host_port_from_url(self._server_url)
        try:
            actual = fetch_cert_pin(host, port, server_name=host)
        except Exception as e:
            raise ConnectionRefusedError(f"无法获取服务端证书, 固定校验失败: {e}")
        if not hmac.compare_digest(actual, pin):
            raise ConnectionRefusedError(
                "服务端证书指纹与固定值不符, 疑似中间人攻击 (REST, 审计 #18)")

    def _ws_loop(self):
        backoff = self._reconnect_delay
        reported_error = False
        import socket as _socket
        import json as _json
        from websocket import WebSocketConnectionClosedException as _WSCE
        from websocket import WebSocketTimeoutException as _WSTE
        while self._running:
            try:
                self._connect_ws()
                backoff = self._reconnect_delay
                self._ws_ready = True
                self._connected = True
                reported_error = False
                INBOUND.put({"action": "status", "connected": True})

                # 3s socket timeout keeps connections alive while allowing
                # the send queue to be processed frequently
                try:
                    self.ws.sock.settimeout(3.0)
                except Exception:
                    pass

                while self._running:
                    try:
                        raw = self.ws.recv()
                        if raw is None:
                            break
                        try:
                            data = _json.loads(raw)
                        except _json.JSONDecodeError:
                            continue
                        INBOUND.put({"action": "server_message", "data": data})
                    except (_socket.timeout, _WSTE):
                        pass
                    except _WSCE:
                        break
                    except (_socket.error, ConnectionError, IOError):
                        break
                    except Exception:
                        break
                    # Process queued outgoing messages after every recv
                    try:
                        while True:
                            send_item = self._send_queue.get_nowait()
                            try:
                                self.ws.send(send_item)
                            except (_socket.timeout, _WSTE):
                                # 发送超时但连接还在，消息塞回队列稍后重试
                                self._send_queue.put(send_item)
                                break
                            except _WSCE:
                                self._send_queue.put(send_item)
                                break
                            except (_socket.error, ConnectionError, IOError):
                                self._send_queue.put(send_item)
                                break
                            except Exception:
                                self._send_queue.put(send_item)
                                break
                    except queue.Empty:
                        pass
                    except (_socket.timeout, _WSTE):
                        pass
                    except _WSCE:
                        break
                    except (_socket.error, ConnectionError, IOError):
                        break
                    except Exception:
                        break

            except Exception as e:
                if not reported_error:
                    # M17 修复: 常见异常映射为中文短句, 不把 traceback 糊给用户
                    INBOUND.put({"action": "error", "message": _friendly_conn_error(e)})
                    reported_error = True

            self._connected = False
            self._ws_ready = False
            INBOUND.put({"action": "status", "connected": False})

            if self._running:
                time.sleep(min(backoff, self._max_reconnect_delay))
                backoff = min(backoff * 2, self._max_reconnect_delay)

    def _connect_ws(self):
        import websocket
        # 审计 #3/#4: wss 必须校验服务端证书 (CA 链 + 主机名), 不再 sslopt={} 裸奔
        sslopt = build_ws_sslopt(self._ws_url)
        self.ws = websocket.create_connection(
            self._ws_url,
            timeout=120,
            sslopt=sslopt,
            # Cloudflare 按 UA 拦截: websocket 默认 "Python-urllib/x.y" 会被 403
            header={"User-Agent": "zhcrypt-client/3.1"},
        )
        # 审计 #18: 证书固定 (pinning) —— 即便存在 rogue CA, 不匹配固定指纹也拒连
        pin = self._get_cert_pin()
        if pin and self._ws_url.startswith("wss://"):
            self._enforce_cert_pin(pin)
        auth_msg = json.dumps({
            "type": "auth",
            "token": self._token,
            "identity": self.identity,
        })
        self.ws.send(auth_msg)
        resp = json.loads(self.ws.recv())
        if resp.get("type") != "auth_ok":
            msg = resp.get('message', 'unknown')
            self.ws.close()
            raise ConnectionRefusedError(f"认证失败: {msg}")
        self.ws.send(json.dumps({"type": "get_pending"}))

    def _get_cert_pin(self):
        try:
            from config import get_cert_pin
            return get_cert_pin()
        except Exception:
            return ""

    def _enforce_cert_pin(self, pin):
        try:
            sock = self.ws.sock
            der = sock.getpeercert(binary_form=True)
        except Exception:
            self.ws.close()
            raise ConnectionRefusedError("无法获取服务端证书, 证书固定校验失败")
        from certpin import verify_cert_pin
        if not verify_cert_pin(der, pin):
            self.ws.close()
            raise ConnectionRefusedError(
                "服务端证书指纹与固定值不符, 疑似中间人攻击 (审计 #18)")

    def send_chat_message(self, peer_identity, plaintext):
        # C1 修复 (Agent-3): 会话锁包住 load→mutate→save, 防 Binder 解密
        # 与主线程发送并发覆写 ratchet 状态
        from session import session_lock
        with session_lock(self.identity, peer_identity):
            state = load_session(self.identity, peer_identity, self.passphrase)

            if state is None or state.is_expired():
                result = self._initiate_session(peer_identity)
                if result.get("error"):
                    return result
                state = result["state"]
                result["state"] = None
                return self._send_first_message(state, result, plaintext)

            return self._send_ratchet_message(state, plaintext)

    def _initiate_session(self, peer_identity):
        from core import urlsafe_b64decode as b64d, ed25519_verify

        self.store.ensure_kem_keys(self.identity, self.passphrase)

        resp = self._http_request("GET", f"/v1/prekey/{peer_identity}")
        if resp.get("error"):
            return {"error": f"无法获取 {peer_identity} 的 prekey: {resp['error']}"}

        my_id_priv_pem = self.store.load_kem_private_key_pem(self.identity, self.passphrase)
        my_id_priv_raw = pem_priv_to_raw(my_id_priv_pem)

        # 审计 #5: 首次通信签名校验, 落地 TOFU
        spk_sig_b64 = resp.get("signed_prekey_sig", "")
        if not spk_sig_b64:
            return {"error": f"{peer_identity} 的 prekey 缺少签名，拒绝握手"}
        try:
            spk_pub_pem = b64d(resp["signed_prekey_pub"].encode())
            spk_sig = b64d(spk_sig_b64.encode())
        except Exception:
            return {"error": f"{peer_identity} 的 prekey 签名格式错误"}

        # 服务器返回的签名公钥 (新版本上传的 bundle 会携带; 旧版可能缺失)
        bundle_signing_pub_b64 = resp.get("signing_public_key", "")
        bundle_signing_pub = b64d(bundle_signing_pub_b64.encode()) if bundle_signing_pub_b64 else b""

        # 本地已记录的信任锚 (TOFU 固定值, 或带外导入的公钥)
        local_pub = b""
        try:
            local_pub = self.store.load_tofu_signing_pub(peer_identity)
        except Exception:
            try:
                local_pub = self.store.load_signing_public_key(peer_identity)
            except Exception:
                pass

        # ---- signed prekey 签名验证 (分两种情况, 避免把旧版/过期误报成 MITM) ----
        if bundle_signing_pub:
            # 情况 A: bundle 自带签名公钥 —— 以 bundle 为准做自包含验证 (强信号)
            if not ed25519_verify(bundle_signing_pub, spk_pub_pem, spk_sig):
                return {"error": f"{peer_identity} 的 signed prekey 签名验证失败：服务器返回的 bundle 自签名不一致，疑似传输中被篡改或中间人攻击。请通过带外比对安全码确认"}
            verify_key = bundle_signing_pub
            # 安全修复 (test_security_fixes #5e): 本地 TOFU/联系人公钥与 bundle 不一致时
            # 拒绝建立会话 (防 MITM 静默换钥), 而不是自动覆盖固定值。
            # 对方若确实更换了身份密钥, 需先删除本地联系人记录并重新带外导入新公钥束。
            if local_pub and local_pub != bundle_signing_pub:
                return {"error": f"{peer_identity} 的签名公钥与本地记录不一致（对方可能更换了身份密钥，或存在中间人攻击）。请与对方带外比对安全识别码，并在确认后重新导入其最新公钥束"}
        else:
            # 情况 B: 旧版上传未携带签名公钥, 只能回退本地信任锚
            if not local_pub:
                return {"error": f"{peer_identity} 的 prekey 未携带签名公钥（疑似旧版客户端上传），且本地无记录，无法验证。请让对方用最新版客户端重新『上传 Prekey』后再试"}
            verify_key = local_pub
            if not ed25519_verify(local_pub, spk_pub_pem, spk_sig):
                return {"error": f"{peer_identity} 的 signed prekey 签名验证失败：本地记录的对方签名公钥与服务器 bundle 不匹配（多为对方用旧版上传、或你本地公钥已过期）。请让对方用最新版重新『上传 Prekey』，或你重新导入对方最新公钥"}

        # 首次接触: 固定 (TOFU) 对端签名公钥
        first_contact = not local_pub
        if first_contact:
            self.store.store_tofu_signing_pub(peer_identity, verify_key)

        # Tier 1: 握手验签通过后, 将对方静态公钥缓存到本地 (覆盖写)。
        # 这样对方无需手动导出/导入公钥束即出现在联系人列表, 且安全码可离线计算。
        self._cache_peer_keys(peer_identity, resp)

        state, init_extra = x3dh_initiate_session(
            peer_identity_key_pub_pem=b64d(resp["identity_key_pub"].encode()),
            peer_signed_prekey_pub_pem=spk_pub_pem,
            peer_one_time_prekey_pub_b64=resp.get("one_time_prekey"),
            my_identity_priv_raw=my_id_priv_raw,
            my_identity=self.identity,
            peer_identity=peer_identity,
            peer_signing_pub_pem=bundle_signing_pub or verify_key,
        )

        safety_number = ""
        try:
            my_sign = self.store.load_signing_public_key(self.identity)
            peer_sign = self.store.load_tofu_signing_pub(peer_identity)
            safety_number = compute_safety_number(my_sign, peer_sign)
        except Exception:
            pass

        return {
            "state": state,
            "init_extra": init_extra,
            "is_init": True,
            "first_contact": first_contact,
            "unverified": first_contact,
            "safety_number": safety_number,
        }

    def _send_first_message(self, state, init_result, plaintext):
        init_extra = init_result["init_extra"]
        is_init = init_result.get("is_init", False)

        inner = json.dumps({
            "text": plaintext,
            "signature": "",
        }, ensure_ascii=False).encode("utf-8")

        msg = send_message(state, inner)
        msg["type"] = "x3dh_init"
        msg["payload"]["sender_identity_pub"] = init_extra["sender_identity_pub"]
        msg["payload"]["sender_ephemeral_pub"] = init_extra["sender_ephemeral_pub"]
        # 协议修复 (动态测试发现): init 消息的 signing_public_key 必须是
        # 发送方自己的 Ed25519 签名公钥 (接收方据此做 TOFU 固定与安全码计算),
        # 而不是接收方的公钥。
        try:
            msg["payload"]["signing_public_key"] = _b64(
                self.store.load_signing_public_key(self.identity))
        except Exception:
            pass
        msg["payload"]["one_time_prekey_id"] = None

        save_session(state, self.passphrase)

        if self._ws_ready:
            err = self._send_via_ws(msg)
        else:
            err = self._send_via_rest(msg)
        if err:
            return {"error": f"发送失败: {err}"}
        return {"status": "sent", "msg_id": msg["id"], "type": "x3dh_init"}

    def _send_ratchet_message(self, state, plaintext):
        try:
            signing_priv = self.store.load_signing_private_key_pem(self.identity, self.passphrase)
            # 签名体绑定消息内容, 不绑定时钟 (跨机时钟偏差不再导致验签失败)
            sig_body = f"{self.identity}{plaintext}".encode("utf-8")
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            priv = serialization.load_pem_private_key(signing_priv, password=None)
            sig = priv.sign(sig_body)
            sig_b64 = _b64(sig)
        except Exception:
            sig_b64 = ""

        inner = json.dumps({
            "text": plaintext,
            "signature": sig_b64,
        }, ensure_ascii=False).encode("utf-8")

        msg = send_message(state, inner)

        save_session(state, self.passphrase)

        if self._ws_ready:
            err = self._send_via_ws(msg)
        else:
            err = self._send_via_rest(msg)
        if err:
            return {"error": f"发送失败: {err}"}
        return {"status": "sent", "msg_id": msg["id"], "type": "message"}

    def send_friend_msg(self, peer_identity, action):
        """发送好友关系消息 (request/accept/remove), 走现有 ratchet 加密信道。

        好友消息是带语义的空文本: inner = {"text": "", "friend": {"action": ...}}。
        无会话时自动先建立会话 (X3DH 握手), 无需用户先发普通消息。
        成功: {"status":"sent","msg_id":...}   失败: {"error": str}
        """
        if action not in ("request", "accept", "remove"):
            return {"error": f"非法好友动作: {action}"}
        # C1 修复: 会话锁包住 ratchet 段
        from session import session_lock
        with session_lock(self.identity, peer_identity):
            return self._send_friend_msg_locked(peer_identity, action)

    def _send_friend_msg_locked(self, peer_identity, action):
        state = load_session(self.identity, peer_identity, self.passphrase)
        if state is None or state.is_expired():
            # 自动建立会话 (与 send_chat_message 首条消息逻辑一致)
            result = self._initiate_session(peer_identity)
            if result.get("error"):
                return result
            state = result["state"]
            init_extra = result["init_extra"]
            first_contact = result.get("first_contact", False)
            safety_number = result.get("safety_number", "")

            sig_b64 = ""
            try:
                signing_priv = self.store.load_signing_private_key_pem(
                    self.identity, self.passphrase)
                sig_body = f"{self.identity}{action}".encode("utf-8")
                from cryptography.hazmat.primitives.asymmetric import ed25519
                from cryptography.hazmat.primitives import serialization
                priv = serialization.load_pem_private_key(signing_priv, password=None)
                sig_b64 = _b64(priv.sign(sig_body))
            except Exception:
                sig_b64 = ""

            inner = json.dumps({
                "text": "",
                "signature": sig_b64,
                "friend": {"action": action},
            }, ensure_ascii=False).encode("utf-8")

            msg = send_message(state, inner)
            msg["type"] = "x3dh_init"
            msg["payload"]["sender_identity_pub"] = init_extra["sender_identity_pub"]
            msg["payload"]["sender_ephemeral_pub"] = init_extra["sender_ephemeral_pub"]
            try:
                msg["payload"]["signing_public_key"] = _b64(
                    self.store.load_signing_public_key(self.identity))
            except Exception:
                pass
            msg["payload"]["one_time_prekey_id"] = None

            save_session(state, self.passphrase)
            if self._ws_ready:
                err = self._send_via_ws(msg)
            else:
                err = self._send_via_rest(msg)
            if err:
                return {"error": f"发送失败: {err}"}
            extra = {}
            if first_contact:
                extra["first_contact"] = True
                extra["safety_number"] = safety_number
            return {"status": "sent", "msg_id": msg["id"], "type": "friend", **extra}

        sig_b64 = ""
        try:
            signing_priv = self.store.load_signing_private_key_pem(
                self.identity, self.passphrase)
            # 签名体绑定动作内容 (防重放/篡改动作)
            sig_body = f"{self.identity}{action}".encode("utf-8")
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            priv = serialization.load_pem_private_key(signing_priv, password=None)
            sig_b64 = _b64(priv.sign(sig_body))
        except Exception:
            sig_b64 = ""

        inner = json.dumps({
            "text": "",
            "signature": sig_b64,
            "friend": {"action": action},
        }, ensure_ascii=False).encode("utf-8")

        msg = send_message(state, inner)
        save_session(state, self.passphrase)

        if self._ws_ready:
            err = self._send_via_ws(msg)
        else:
            err = self._send_via_rest(msg)
        if err:
            return {"error": f"发送失败: {err}"}
        return {"status": "sent", "msg_id": msg["id"], "type": "friend"}

    def _send_via_ws(self, msg):
        try:
            self._send_queue.put_nowait(
                json.dumps({"type": "send", "msg": msg}, ensure_ascii=False))
            return None
        except Exception as e:
            return self._send_via_rest(msg)

    def _send_via_rest(self, msg):
        msg = dict(msg)
        msg["identity"] = self.identity
        # R2: 仅对 429 限流做指数退避重试 (1s/2s/4s, 最多 3 次),
        # 突发消息不再因限流直接失败; 其它错误立即返回。
        attempt = 0
        while True:
            result = self._http_request("POST", "/v1/messages/send", msg)
            err = result.get("error") or ""
            if not err:
                return None
            if "429" in err and attempt < 3:
                time.sleep(2 ** attempt)
                attempt += 1
                continue
            return err

    def upload_file(self, file_b64, recipient):
        """通过 WebSocket 上传文件密文 (大文件路径)。

        服务端落盘后返回 file_upload_ack (含 token), 由 GUI 轮询拿到 token
        后再把 [FILE]...|tok:<token> 元数据以聊天消息发出, 供接收方下载。
        """
        try:
            self._send_queue.put_nowait(json.dumps({
                "type": "file_upload",
                "file_data": file_b64,
                "recipient": recipient,
            }))
            return None
        except Exception as e:
            return str(e)

    def request_file_download(self, token):
        """请求下载大文件; 服务端返回 file_download_resp (含 file_data)。"""
        try:
            self._send_queue.put_nowait(json.dumps({
                "type": "file_download",
                "token": token,
            }))
            return None
        except Exception as e:
            return str(e)

    # ------------------------------------------------------------------
    # Tier 1 优化: 连接时自检 / 自动拉取对端公钥 (不消耗 one-time prekey)
    # ------------------------------------------------------------------
    def ensure_own_prekey(self, threshold: int = 10):
        """连接时确保自身 one-time prekey 充足; 不足则自动重新上传。

        返回 (ok: bool, msg: str)。生成 prekey 需要私钥密码(self.passphrase),
        因此仅在连接已拿到密码后调用。不抛异常。
        """
        try:
            rem = self._http_request("GET", f"/v1/prekey/remaining/{self.identity}")
        except Exception as e:
            return False, f"检查自身 prekey 异常: {e}"
        if isinstance(rem, dict) and rem.get("error"):
            return False, f"检查自身 prekey 失败: {rem['error']}"
        remaining = rem.get("remaining", 0) if isinstance(rem, dict) else 0
        if remaining >= threshold:
            return True, f"prekey 充足(剩余 {remaining})"
        try:
            bundle = self.store.generate_prekey_bundle(
                self.identity, self.passphrase, otp_count=50)
        except Exception as e:
            return False, f"生成 prekey 失败(密码错误?): {e}"
        resp = self._http_request(
            "POST", f"/v1/prekey/{self.identity}",
            body=dict(bundle, identity=self.identity))
        if isinstance(resp, dict) and resp.get("error"):
            return False, f"上传 prekey 失败: {resp['error']}"
        stored = resp.get("one_time_stored", "?") if isinstance(resp, dict) else "?"
        return True, f"已自动上传 prekey(剩余 {stored})"

    def fetch_server_identities(self):
        """拉取服务器上所有已注册的身份 (私人服务器: 好友发现来源)。

        GET /v1/identities → {"identities": [{identity, fingerprint, last_seen}]}
        返回 [{identity, fingerprint, last_seen}] 列表; 失败 {"error": str}
        """
        resp = self._http_request("GET", "/v1/identities")
        if isinstance(resp, dict) and resp.get("error"):
            return {"error": resp["error"]}
        if not isinstance(resp, dict):
            return {"error": "服务器返回格式异常"}
        return resp.get("identities", [])

    def fetch_peer_meta(self, peer_identity: str):
        """只读端点拉取对端静态公钥(不消耗 OTP)。

        返回 dict:
          {ok: True, identity_key_pub, signed_prekey_pub, signing_public_key}
          或 {ok: False, missing: bool, error: str}
        missing=True 表示端点不存在/对端未注册 -> 调用方应降级(由首次发送握手补全)。
        """
        resp = self._http_request("GET", f"/v1/prekey/meta/{peer_identity}")
        if isinstance(resp, dict) and resp.get("error"):
            err = str(resp["error"])
            missing = ("404" in err) or ("not found" in err.lower()) or ("405" in err)
            return {"ok": False, "missing": missing, "error": err}
        if not isinstance(resp, dict) or not resp.get("identity_key_pub"):
            return {"ok": False, "missing": True,
                    "error": "对方未返回公钥(meta 端点异常)"}
        return {
            "ok": True,
            "identity_key_pub": resp.get("identity_key_pub"),
            "signed_prekey_pub": resp.get("signed_prekey_pub"),
            "signing_public_key": resp.get("signing_public_key"),
        }

    def _cache_peer_keys(self, peer_identity: str, resp: dict):
        """握手成功后, 将服务器返回的静态公钥缓存到本地 (覆盖写)。

        使对端出现在联系人列表, 且安全识别码后续可离线计算。服务器证书固定
        + token 双认证, 返回公钥可信。
        """
        try:
            self.store.import_peer_static_keys(
                peer_identity,
                idk_b64=resp.get("identity_key_pub"),
                spk_b64=resp.get("signed_prekey_pub"),
                signing_b64=resp.get("signing_public_key"),
            )
        except Exception:
            pass

    def receive_chat_message(self, msg):
        # C1 修复 (Agent-3): 会话锁包住整个解密→save 段,
        # 防与发送线程并发覆写 ratchet 状态
        from session import session_lock
        peer_identity = msg["from"]
        # 防御纵深 (审计 H4): 服务端虽已校验身份名, 但本地仍拒绝非法对端身份,
        # 避免后续会话路径拼接抛异常或写越界文件。
        try:
            from schema import valid_identity
            if not valid_identity(self.identity) or not valid_identity(peer_identity):
                return {"error": f"非法对端身份: {peer_identity!r}"}
        except Exception:
            return {"error": "身份名校验失败"}
        with session_lock(self.identity, peer_identity):
            return self._receive_chat_message_locked(msg)

    def _receive_chat_message_locked(self, msg):
        peer_identity = msg["from"]
        state = load_session(self.identity, peer_identity, self.passphrase)
        import sys as _sys

        msg_type = msg.get("type", "message")

        if state is None:
            if msg_type in ("x3dh_init",):
                return self._handle_x3dh_init(msg)
            else:
                return {"error": f"收到 {peer_identity} 的消息但无会话状态",
                        "recovery": "请通知对方重新发起会话"}

        if msg_type == "x3dh_init":
            return self._handle_x3dh_init(msg)

        if msg_type == "x3dh_reply":
            # 重放去重 (审计 M8): 该分支此前缺少 seen 检查, 恶意服务器可重放
            # 已收消息造成重复解密/重复展示。
            if state._has_seen(msg.get("id", "")):
                return None
            state._mark_seen(msg.get("id", ""))
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            payload = msg["payload"]
            sender_ratchet_pub_raw = _b64d(payload["ratchet_public_key"])
            state.their_ratchet_pub = sender_ratchet_pub_raw
            hkdf_init = HKDF(hashes.SHA256(), KEY_SIZE * 4,
                salt=state.root_key, info=b"zhchat-init-chains-v1")
            cm = hkdf_init.derive(state.our_ratchet_pub)
            recv_half = cm[KEY_SIZE:KEY_SIZE * 2]
            sid = state.session_id
            if not isinstance(sid, bytes): sid = sid.encode()
            nonce = _b64d(payload["nonce"])
            ct = _b64d(payload["ciphertext"])
            CKr, MK = KDF_CK(recv_half)
            try:
                a = AESGCM(MK)
                plain = a.decrypt(nonce, ct, sid)
                state.recv_chain_key = CKr
                state.recv_msg_number += 1
                save_session(state, self.passphrase)
                return self._parse_decrypted(plain, msg)
            except Exception as e:
                return {"error": f"x3dh_reply 解密失败: {e}"}

        plain = receive_message(state, msg)
        if plain is None:
            return None

        save_session(state, self.passphrase)
        return self._parse_decrypted(plain, msg)

    def _handle_x3dh_init(self, msg):
        from core import urlsafe_b64decode as b64d
        from cryptography.hazmat.primitives import serialization

        self.store.ensure_kem_keys(self.identity, self.passphrase)

        payload = msg["payload"]

        sender_id_pub_raw = _b64d(payload["sender_identity_pub"])
        sender_eph_pub_raw = _b64d(payload["sender_ephemeral_pub"])
        sender_ratchet_pub_raw = _b64d(payload["ratchet_public_key"])
        sender_signing_pub_pem = _b64d(payload.get("signing_public_key", "")) if payload.get("signing_public_key") else b""
        sender_identity = msg["from"]
        session_id = msg.get("session_id", "")

        # 审计 #5: 响应方也做 TOFU 固定与换钥检测
        if sender_signing_pub_pem:
            try:
                existing = self.store.load_tofu_signing_pub(sender_identity)
                if existing != sender_signing_pub_pem:
                    return {"error": f"{sender_identity} 的签名公钥与历史记录不一致（疑似中间人或已更换密钥），拒绝建立会话"}
            except Exception:
                self.store.store_tofu_signing_pub(sender_identity, sender_signing_pub_pem)

        # Tier 1 对等 (协议修复): 缓存发送方静态公钥到本地联系人,
        # 使安全识别码可离线计算、消息验签无需服务器。init 消息现携带
        # 发送方自己的 signing_public_key (协议修复), 与 identity key 一并落地。
        try:
            self.store.import_peer_static_keys(
                sender_identity,
                idk_b64=payload.get("sender_identity_pub", ""),
                signing_b64=payload.get("signing_public_key", ""),
            )
        except Exception:
            pass

        my_id_priv_pem = self.store.load_kem_private_key_pem(self.identity, self.passphrase)
        my_id_priv_raw = pem_priv_to_raw(my_id_priv_pem)

        # Load SPK (signed prekey) private key — fallback to identity key if method unavailable
        try:
            spk_priv_pem = self.store.load_signed_prekey_priv_pem(self.identity, self.passphrase)
        except AttributeError:
            spk_priv_pem = None
        spk_priv_raw = pem_priv_to_raw(spk_priv_pem) if spk_priv_pem else my_id_priv_raw

        # Build trials: (spk_priv, otp_priv) pairs from most to least specific
        try:
            otp_keys = self.store.load_otp_private_keys(self.identity, self.passphrase)
        except AttributeError:
            otp_keys = []
        trials = [(spk_priv_raw, None)]  # SPK only (2DH + SPK)
        for _, obj in otp_keys:
            otp_raw = obj.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            trials.append((spk_priv_raw, otp_raw))  # SPK + OTP
        # Also try identity-only as last resort
        trials.append((my_id_priv_raw, None))

        for spk, otp_raw in trials:
            state = x3dh_complete_session(
                my_identity_priv_raw=my_id_priv_raw,
                my_signed_prekey_priv_raw=spk,
                sender_identity_pub_raw=sender_id_pub_raw,
                sender_ephemeral_pub_raw=sender_eph_pub_raw,
                sender_ratchet_pub_raw=sender_ratchet_pub_raw,
                sender_signing_pub_pem=sender_signing_pub_pem,
                my_identity=self.identity,
                sender_identity=sender_identity,
                one_time_prekey_priv_raw=otp_raw if otp_raw else None,
                session_id=bytes.fromhex(session_id) if session_id else None,
            )

            plain = complete_session_first_message(
                state, sender_ratchet_pub_raw,
                payload["nonce"], payload["ciphertext"], b"",
            )

            if plain is not None:
                save_session(state, self.passphrase)
                return self._parse_decrypted(plain, msg)

        return {"error": "X3DH 解密失败"}

    def send_x3dh_reply(self, peer_identity, plaintext):
        state = load_session(self.identity, peer_identity, self.passphrase)
        if state is None:
            return {"error": "无会话状态"}

        try:
            signing_priv = self.store.load_signing_private_key_pem(self.identity, self.passphrase)
            # 签名体绑定消息内容, 不绑定时钟
            sig_body = f"{self.identity}{plaintext}".encode("utf-8")
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            priv = serialization.load_pem_private_key(signing_priv, password=None)
            sig = priv.sign(sig_body)
            sig_b64 = _b64(sig)
        except Exception:
            sig_b64 = ""

        inner = json.dumps({
            "text": plaintext,
            "signature": sig_b64,
        }, ensure_ascii=False).encode("utf-8")

        msg = send_message(state, inner)
        msg["type"] = "x3dh_reply"
        msg["payload"]["one_time_prekey_id"] = None

        save_session(state, self.passphrase)

        if self._ws_ready:
            err = self._send_via_ws(msg)
        else:
            err = self._send_via_rest(msg)
        if err:
            return {"error": f"发送失败: {err}"}
        return {"status": "sent", "msg_id": msg["id"], "type": "x3dh_reply"}

    def _parse_decrypted(self, plain, msg):
        try:
            inner = json.loads(plain.decode("utf-8"))
            text = inner.get("text", "")
            signature = inner.get("signature", "")
            file_meta = inner.get("file")
            verified = False
            if signature:
                try:
                    peer_signing_pub = self.store.load_signing_public_key(msg["from"])
                    sig_bytes = _b64d(signature)
                    ts = int(msg.get("timestamp", 0))
                    # 新格式签名体 (内容绑定, 不绑定时钟):
                    #   文本: {from}{text}
                    #   文件: {from}{name}{size}{sha256}
                    # 旧格式 (含客户端时钟) 兜底兼容, 保证与老客户端互操作。
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    from cryptography.hazmat.primitives import serialization
                    pub = serialization.load_pem_public_key(peer_signing_pub)
                    bodies = []
                    if isinstance(file_meta, dict):
                        fname = file_meta.get("name", "")
                        fsize = file_meta.get("size", "")
                        fsha = file_meta.get("sha256", "")
                        bodies.append(
                            f"{msg['from']}{fname}{fsize}{fsha}".encode("utf-8"))
                        bodies.append(
                            f"{msg['from']}{ts}{fname}".encode("utf-8"))
                    elif isinstance(inner.get("friend"), dict):
                        faction = inner["friend"].get("action", "")
                        bodies.append(f"{msg['from']}{faction}".encode("utf-8"))
                        bodies.append(f"{msg['from']}{ts}{faction}".encode("utf-8"))
                    else:
                        bodies.append(f"{msg['from']}{text}".encode("utf-8"))
                        bodies.append(f"{msg['from']}{ts}{text}".encode("utf-8"))
                    for body in bodies:
                        try:
                            pub.verify(sig_bytes, body)
                            verified = True
                            break
                        except Exception:
                            continue
                except Exception:
                    verified = False
            return {
                "text": text,
                "from": msg["from"],
                "to": msg.get("to", ""),
                "timestamp": msg.get("timestamp", 0),
                "verified": verified,
                "signature": signature,
                "msg_id": msg["id"],
                "file": file_meta if isinstance(file_meta, dict) else None,
                "friend": inner.get("friend")
                if isinstance(inner.get("friend"), dict) else None,
            }
        except Exception as e:
            return {"error": f"解析消息失败: {e}"}

    def poll_messages(self):
        resp = self._http_request("GET", f"/v1/messages/pending?identity={self.identity}")
        messages = resp.get("messages", [])
        results = []
        for msg in messages:
            result = self.receive_chat_message(msg)
            if result and "error" not in result:
                results.append(result)
            elif result and "error" in result:
                results.append(result)
        return results

    def get_history(self, peer, before_id=None, limit=50):
        # 不预编码: _http_request 会对 path 统一 quote (safe='/&=?' 保留 & ? =),
        # 预编码会双重编码 (identity 含 @ 等字符时 %25 转义导致服务端解错)
        path = f"/v1/messages/history?identity={self.identity}&with={peer}&limit={limit}"
        if before_id:
            path += f"&before={before_id}"
        resp = self._http_request("GET", path)
        messages = resp.get("messages", [])
        results = []
        for msg in messages:
            result = self.receive_chat_message(msg)
            if result and "error" not in result:
                results.append(result)
            elif result and "error" in result:
                results.append({"error": result["error"], "msg": msg})
        return results

    def process_inbound(self):
        items = []
        while True:
            try:
                items.append(INBOUND.get_nowait())
            except queue.Empty:
                break
        return items

    def get_safety_number(self, peer_identity):
        """返回与对端的 safety number (带外比对用)。

        成功: {"safety_number": "...", "late_pin": bool}
        失败: {"my_sign": bytes|None, "peer_sign": bytes|None, "error": "诊断信息"}

        取对方签名公钥的优先级:
          1) 本地 TOFU 固定值 (首次握手时落地, 最受信任);
          2) 联系人已发布的签名公钥 load_signing_public_key(peer) —— 与消息验签
             用的是同一把密钥, 旧会话在聊天时就已经具备, 因此旧会话无需重连
             也能直接算出安全号;
          3) 会话早于 TOFU 功能建立且无联系人公钥时, 回退到服务器当前返回的
             签名公钥并固定 (late_pin=True)。
        这样无论会话何时建立, 点按钮都能出号; 且双方因使用同一把真实签名公钥
        (并经 compute_safety_number 排序归一化) 而得到一致结果。
        """
        info = {"my_sign": None, "peer_sign": None, "error": None, "late_pin": False}
        try:
            info["my_sign"] = self.store.load_signing_public_key(self.identity)
        except Exception as e:
            info["error"] = f"我方签名公钥缺失: {e}"
            return info
        # 1) 本地 TOFU 固定值
        try:
            info["peer_sign"] = self.store.load_tofu_signing_pub(peer_identity)
        except Exception:
            info["peer_sign"] = None
        # 2) 回退: 联系人已发布的签名公钥 (与消息验签同一把, 旧会话已具备)
        if not info["peer_sign"]:
            try:
                info["peer_sign"] = self.store.load_signing_public_key(peer_identity)
                if info["peer_sign"]:
                    # 顺手固定为 TOFU, 后续直接命中
                    try:
                        self.store.store_tofu_signing_pub(peer_identity, info["peer_sign"])
                    except Exception:
                        pass
            except Exception:
                info["peer_sign"] = None
        # 3) 回退: 会话早于 TOFU 功能建立, 从服务器取对方当前签名公钥并固定
        if not info["peer_sign"]:
            try:
                from core import urlsafe_b64decode as _b64d
                resp = self._http_request("GET", f"/v1/prekey/{peer_identity}")
                if isinstance(resp, dict) and resp.get("error"):
                    raise RuntimeError(resp["error"])
                b64 = resp.get("signing_public_key", "") if isinstance(resp, dict) else ""
                if not b64:
                    raise RuntimeError("服务器未返回签名公钥")
                peer_sign = _b64d(b64.encode())
                self.store.store_tofu_signing_pub(peer_identity, peer_sign)
                info["peer_sign"] = peer_sign
                info["late_pin"] = True
            except Exception as e:
                extra = f"对方 TOFU 公钥缺失且无法从服务器获取: {e}"
                info["error"] = (info["error"] + "\n" + extra) if info["error"] else extra
        if info["my_sign"] and info["peer_sign"]:
            return {
                "safety_number": compute_safety_number(info["my_sign"], info["peer_sign"]),
                "late_pin": info["late_pin"],
            }
        return info


    def send_file(self, peer_identity, file_path, progress_cb=None):
        """发送文件消息: AES-256-GCM 加密整个文件 → 上传密文拿 token →
        inner JSON 扩展 file 字段 → 走现有 ratchet 发送链路。

        成功: {"status": "sent", "msg_id": str, "type": "message"}
        失败: {"error": "人类可读中文原因"}
        """
        import secrets as _secrets
        import tempfile as _tempfile
        import hashlib as _hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from fileclient import FileClient

        if not os.path.isfile(file_path):
            return {"error": f"文件不存在: {file_path}"}
        # 先确认有可用会话, 避免白上传
        state = load_session(self.identity, peer_identity, self.passphrase)
        if state is None or state.is_expired():
            return {"error": "无可用会话, 请先发送一条普通消息建立会话"}
        try:
            with open(file_path, "rb") as f:
                plaintext = f.read()
        except OSError as e:
            return {"error": f"读取文件失败: {e}"}
        name = os.path.basename(file_path)
        size = len(plaintext)
        sha256 = _hashlib.sha256(plaintext).hexdigest()

        # a. AES-256-GCM 加密整个文件 (随机 12 字节 nonce 前置到密文)
        file_key = _secrets.token_bytes(32)
        nonce = _secrets.token_bytes(12)
        try:
            ct = AESGCM(file_key).encrypt(nonce, plaintext, None)
        except Exception as e:
            return {"error": f"加密文件失败: {e}"}
        cipher_blob = nonce + ct

        # 临时密文文件 (用完即删, 密钥与明文不落盘)
        tmp_path = None
        try:
            fd, tmp_path = _tempfile.mkstemp(prefix="zhcrypt_upload_", suffix=".bin")
            with os.fdopen(fd, "wb") as f:
                f.write(cipher_blob)
            del cipher_blob, plaintext

            # b. FileClient 分块上传密文, 拿 token
            fc = FileClient(self._server_url, self._token, self.identity)
            result = fc.upload(tmp_path, peer_identity, progress_cb)
            if result.get("error"):
                return {"error": f"上传文件失败: {result['error']}"}
            token = result["token"]

            # c. Ed25519 签名 (参照 _send_ratchet_message 的容错模式, 失败留空)
            sig_b64 = ""
            try:
                signing_priv = self.store.load_signing_private_key_pem(
                    self.identity, self.passphrase)
                # 签名体绑定文件内容指纹 (name+size+sha256), 不绑定时钟
                sig_body = f"{self.identity}{name}{size}{sha256}".encode("utf-8")
                from cryptography.hazmat.primitives.asymmetric import ed25519
                from cryptography.hazmat.primitives import serialization
                priv = serialization.load_pem_private_key(signing_priv, password=None)
                sig_b64 = _b64(priv.sign(sig_body))
            except Exception:
                sig_b64 = ""

            inner = json.dumps({
                "text": "",
                "signature": sig_b64,
                "file": {
                    "name": name,
                    "size": size,
                    "sha256": sha256,
                    "token": token,
                    "key": _b64(file_key),
                },
            }, ensure_ascii=False).encode("utf-8")

            # d. 走现有 ratchet 发送链路 (send_message → save_session → 发送)
            # R11: 与 send_chat_message 一致, load→send→save 全程持会话锁 ——
            # 上传耗时长, 期间对端消息推进 ratchet 落盘后, 旧 state 覆写会
            # 导致双方 ratchet 失步 (C1 竞态在文件路径的翻版)。
            with session_lock(self.identity, peer_identity):
                state = load_session(self.identity, peer_identity, self.passphrase)
                if state is None or state.is_expired():
                    return {"error": "上传完成但会话已失效, 文件未发送; "
                                     "请重新建立会话后再发一次"}
                msg = send_message(state, inner)
                save_session(state, self.passphrase)

            if self._ws_ready:
                err = self._send_via_ws(msg)
            else:
                err = self._send_via_rest(msg)
            if err:
                return {"error": f"发送失败: {err}"}
            # e. 成功返回
            return {"status": "sent", "msg_id": msg["id"], "type": "message"}
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def download_file(self, token, dest_dir, progress_cb=None):
        """下载文件密文到 dest_dir/<token>.bin (临时名)。

        仅负责传输, 不涉及解密与本地存储: TUI 层用 LocalStore.take_file_key
        取密钥后调用 decrypt_file 完成解密。本类刻意不依赖 localstore,
        避免模块间循环依赖。
        成功: {"status": "ok", "path": str, "token": str}   失败: {"error": str}
        """
        from fileclient import FileClient
        fc = FileClient(self._server_url, self._token, self.identity)
        result = fc.download(token, dest_dir, progress_cb)
        if result.get("error"):
            return {"error": result["error"]}
        return {"status": "ok", "path": result["path"], "token": token}

    @staticmethod
    def decrypt_file(cipher_path, key_b64, out_name, sha256):
        """解密 download_file 下载的密文 (nonce 前置的 AES-256-GCM)。

        参数: key_b64 来自文件消息 inner JSON 的 file.key (urlsafe b64);
        out_name 为明文输出文件名 (白名单 ^[\\w.\\-]+$, 防穿越);
        sha256 为原文件摘要, 校验失败则拒绝写出。
        明文写 cipher_path 同目录下。
        成功: {"status": "ok", "path": str}   失败: {"error": str}
        """
        import re as _re
        import hashlib as _hashlib
        from core import urlsafe_b64decode as _b64d
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not _re.fullmatch(r"^[\w.\-]+$", out_name or ""):
            return {"error": f"非法文件名: {out_name}"}
        try:
            key = _b64d(key_b64)
        except Exception:
            return {"error": "文件密钥格式错误"}
        if len(key) != 32:
            return {"error": "文件密钥长度错误"}
        try:
            with open(cipher_path, "rb") as f:
                blob = f.read()
        except OSError as e:
            return {"error": f"读取密文失败: {e}"}
        if len(blob) <= 12:
            return {"error": "密文过短"}
        nonce, ct = blob[:12], blob[12:]
        try:
            plain = AESGCM(key).decrypt(nonce, ct, None)
        except Exception:
            return {"error": "解密失败: 密文已损坏或密钥错误"}
        digest = _hashlib.sha256(plain).hexdigest()
        if sha256 and digest != sha256:
            return {"error": "sha256 校验失败: 文件被篡改或不完整"}
        out_path = os.path.join(
            os.path.dirname(os.path.abspath(cipher_path)), out_name)
        try:
            with open(out_path, "wb") as f:
                f.write(plain)
        except OSError as e:
            return {"error": f"写入明文失败: {e}"}
        return {"status": "ok", "path": out_path}

    def query_delivered(self, msg_ids):
        """批量查询消息送达时间戳。

        GET {server}/v1/messages/delivered?ids=a,b,c&identity=me
        响应 {"delivered": {"a": ts, "b": null}}; 仅返回与身份相关 (发送或接收) 的消息。
        返回 {msg_id: ts 或 None} 字典; 失败: {"error": str}
        """
        ids = ",".join(str(i) for i in msg_ids)
        # 不预编码 (见 get_history 注释: _http_request 统一 quote, 防双重编码)
        resp = self._http_request(
            "GET", f"/v1/messages/delivered?ids={ids}&identity={self.identity}")
        if isinstance(resp, dict) and resp.get("error"):
            return {"error": resp["error"]}
        delivered = resp.get("delivered", {}) if isinstance(resp, dict) else {}
        return {str(k): v for k, v in delivered.items()}


def init_client(identity, passphrase):
    client = ChatClient(identity, passphrase)
    client.start()
    return client
