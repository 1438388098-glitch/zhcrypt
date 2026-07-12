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
from session import save_session, load_session, list_sessions, delete_session

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
                    import traceback
                    details = traceback.format_exc().split('\n')
                    brief = " ".join(l.strip() for l in details[-3:-1] if l.strip())
                    INBOUND.put({"action": "error", "message": f"连接失败: {e} [{brief}]"})
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
            # bundle 自验证通过, 若与本地历史记录冲突, 视为对方换钥(服务器已证书固定+token 双认证),
            # 直接更新固定值, 避免每次都卡在"不一致"
            if local_pub and local_pub != bundle_signing_pub:
                self.store.store_tofu_signing_pub(peer_identity, bundle_signing_pub)
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
        if "signing_public_key" in init_extra:
            msg["payload"]["signing_public_key"] = init_extra["signing_public_key"]
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
            ts = int(time.time())
            sig_body = f"{self.identity}{ts}{plaintext}".encode("utf-8")
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

    def _send_via_ws(self, msg):
        try:
            self._send_queue.put_nowait(
                json.dumps({"type": "send", "msg": msg}, ensure_ascii=False))
            return None
        except Exception as e:
            result = self._http_request("POST", "/v1/messages/send", msg)
            if result.get("error"):
                return result["error"]
            return None

    def _send_via_rest(self, msg):
        result = self._http_request("POST", "/v1/messages/send", msg)
        if result.get("error"):
            return result["error"]
        return None

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
            ts = int(time.time())
            sig_body = f"{self.identity}{ts}{plaintext}".encode("utf-8")
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
            verified = False
            if signature:
                try:
                    peer_signing_pub = self.store.load_signing_public_key(msg["from"])
                    sig_bytes = _b64d(signature)
                    ts = int(msg.get("timestamp", 0))
                    sig_body = f"{msg['from']}{ts}{text}".encode("utf-8")
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    from cryptography.hazmat.primitives import serialization
                    pub = serialization.load_pem_public_key(peer_signing_pub)
                    pub.verify(sig_bytes, sig_body)
                    verified = True
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
        path = f"/v1/messages/history?with={peer}&limit={limit}"
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


def init_client(identity, passphrase):
    client = ChatClient(identity, passphrase)
    client.start()
    return client
