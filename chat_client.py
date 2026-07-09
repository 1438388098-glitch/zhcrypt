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
from keys import KeyStore
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

        base = self._server_url.rstrip("/")
        url = f"{base}{path}"

        data = None
        if body:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Content-Type", "application/json")

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)}

    def _ws_loop(self):
        backoff = self._reconnect_delay
        reported_error = False
        while self._running:
            try:
                self._connect_ws()
                backoff = self._reconnect_delay
                self._ws_ready = True
                self._connected = True
                reported_error = False
                INBOUND.put({"action": "status", "connected": True})

                while self._running:
                    try:
                        raw = self.ws.recv()
                        if raw is None:
                            break
                        data = json.loads(raw)
                        INBOUND.put({"action": "server_message", "data": data})
                    except Exception:
                        break

            except Exception as e:
                if not reported_error:
                    INBOUND.put({"action": "error", "message": f"连接失败: {e}"})
                    reported_error = True

            self._connected = False
            self._ws_ready = False
            INBOUND.put({"action": "status", "connected": False})

            if self._running:
                time.sleep(min(backoff, self._max_reconnect_delay))
                backoff = min(backoff * 2, self._max_reconnect_delay)

    def _connect_ws(self):
        try:
            import websocket
        except ImportError:
            INBOUND.put({"action": "error", "message": "websocket-client 未安装: pip install websocket-client"})
            self._running = False
            return

        self.ws = websocket.create_connection(
            self._ws_url,
            timeout=10,
            sslopt={"cert_reqs": 0} if "wss://" in self._ws_url else {},
        )
        auth_msg = json.dumps({
            "type": "auth",
            "token": self._token,
            "identity": self.identity,
        })
        self.ws.send(auth_msg)

        resp = json.loads(self.ws.recv())
        if resp.get("type") != "auth_ok":
            INBOUND.put({"action": "error", "message": f"认证失败: {resp.get('message', 'unknown')}"})
            self.ws.close()
            self._running = False
            return

        self.ws.send(json.dumps({"type": "get_pending"}))

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
        from core import urlsafe_b64decode as b64d

        self.store.ensure_kem_keys(self.identity, self.passphrase)

        resp = self._http_request("GET", f"/v1/prekey/{peer_identity}")
        if resp.get("error"):
            return {"error": f"无法获取 {peer_identity} 的 prekey: {resp['error']}"}

        my_id_priv_pem = self.store.load_kem_private_key_pem(self.identity, self.passphrase)
        my_id_priv_raw = pem_priv_to_raw(my_id_priv_pem)

        peer_signing_pub = b""
        try:
            peer_signing_pub = self.store.load_signing_public_key(peer_identity)
        except Exception:
            pass

        state, init_extra = x3dh_initiate_session(
            peer_identity_key_pub_pem=b64d(resp["identity_key_pub"].encode()),
            peer_signed_prekey_pub_pem=b64d(resp["signed_prekey_pub"].encode()),
            peer_one_time_prekey_pub_b64=None,
            my_identity_priv_raw=my_id_priv_raw,
            my_identity=self.identity,
            peer_identity=peer_identity,
            peer_signing_pub_pem=peer_signing_pub,
        )

        return {
            "state": state,
            "init_extra": init_extra,
            "is_init": True,
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
            self._send_via_ws(msg)
        else:
            self._send_via_rest(msg)

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
            self._send_via_ws(msg)
        else:
            self._send_via_rest(msg)

        return {"status": "sent", "msg_id": msg["id"], "type": "message"}

    def _send_via_ws(self, msg):
        try:
            self.ws.send(json.dumps({"type": "send", "msg": msg}, ensure_ascii=False))
        except Exception:
            self._http_request("POST", "/v1/messages/send", msg)

    def _send_via_rest(self, msg):
        self._http_request("POST", "/v1/messages/send", msg)

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
            send_half = cm[:KEY_SIZE]
            sid = state.session_id
            if not isinstance(sid, bytes): sid = sid.encode()
            nonce = _b64d(payload["nonce"])
            ct = _b64d(payload["ciphertext"])
            CKr, MK = KDF_CK(recv_half)
            try:
                a = AESGCM(MK)
                plain = a.decrypt(nonce, ct, sid)
                state.recv_chain_key = CKr
                state.send_chain_key = send_half
                state.recv_msg_number += 1
                save_session(state, self.passphrase)
                return self._parse_decrypted(plain, msg)
            except Exception:
                return None

        plain = receive_message(state, msg)
        if plain is None:
            return None

        save_session(state, self.passphrase)
        return self._parse_decrypted(plain, msg)

    def _handle_x3dh_init(self, msg):
        from core import urlsafe_b64decode as b64d

        self.store.ensure_kem_keys(self.identity, self.passphrase)

        payload = msg["payload"]

        sender_id_pub_raw = _b64d(payload["sender_identity_pub"])
        sender_eph_pub_raw = _b64d(payload["sender_ephemeral_pub"])
        sender_ratchet_pub_raw = _b64d(payload["ratchet_public_key"])
        sender_signing_pub_pem = _b64d(payload.get("signing_public_key", "")) if payload.get("signing_public_key") else b""
        sender_identity = msg["from"]
        session_id = msg.get("session_id", "")

        my_id_priv_pem = self.store.load_kem_private_key_pem(self.identity, self.passphrase)
        my_id_priv_raw = pem_priv_to_raw(my_id_priv_pem)

        state = x3dh_complete_session(
            my_identity_priv_raw=my_id_priv_raw,
            my_signed_prekey_priv_raw=my_id_priv_raw,
            sender_identity_pub_raw=sender_id_pub_raw,
            sender_ephemeral_pub_raw=sender_eph_pub_raw,
            sender_ratchet_pub_raw=sender_ratchet_pub_raw,
            sender_signing_pub_pem=sender_signing_pub_pem,
            my_identity=self.identity,
            sender_identity=sender_identity,
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
            self._send_via_ws(msg)
        else:
            self._send_via_rest(msg)

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


def init_client(identity, passphrase):
    client = ChatClient(identity, passphrase)
    client.start()
    return client
