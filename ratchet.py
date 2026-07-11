"""
zhchat Double Ratchet v1.0
===========================
Signal Protocol 风格的 X3DH + Double Ratchet 实现

KDF 定义:
  KDF_CK(ck) → (new_ck, mk)   HKDF-SHA256, salt=None, info="zhchat-chain-key-v1"
  KDF_RK(rk, dh) → (new_rk, ck)  HKDF-SHA256, salt=rk, info="zhchat-root-key-v1"

状态:
  RK, CKs, CKr, DHs, DHr, Ns, Nr, PN, skipped_keys, seen_message_ids
"""

import os
import sys
import json
import time
import struct
import secrets
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
MAX_SKIPPED = 100
MAX_SEEN_IDS = 1000
SESSION_EXPIRE_DAYS = 30


def _b64(data):
    return urlsafe_b64encode(data).decode("ascii")


def _b64d(s):
    return urlsafe_b64decode(s.encode("ascii"))


def KDF_CK(chain_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=None,
        info=b"zhchat-chain-key-v1",
    )
    okm = hkdf.derive(chain_key)
    return okm[:KEY_SIZE], okm[KEY_SIZE:]


def KDF_RK(root_key, dh_output):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=root_key,
        info=b"zhchat-root-key-v1",
    )
    okm = hkdf.derive(dh_output)
    return okm[:KEY_SIZE], okm[KEY_SIZE:]


def generate_x25519_keypair_raw():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


def x25519_ecdh_raw(priv_raw, pub_raw):
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_raw)
    pub = x25519.X25519PublicKey.from_public_bytes(pub_raw)
    return priv.exchange(pub)


def pub_from_raw(raw):
    return x25519.X25519PublicKey.from_public_bytes(raw)


def priv_from_raw(raw):
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def ed25519_sign_raw(signing_priv_pem, message):
    priv = serialization.load_pem_private_key(signing_priv_pem, password=None)
    return priv.sign(message)


def ed25519_verify_raw(signing_pub_pem, message, signature):
    pub = serialization.load_pem_public_key(signing_pub_pem)
    pub.verify(signature, message)
    return True


class SessionState:
    def __init__(
        self,
        session_id,
        my_identity,
        peer_identity,
        peer_signing_pub,
        root_key,
        send_chain_key,
        recv_chain_key,
        our_ratchet_priv,
        our_ratchet_pub,
        their_ratchet_pub,
        send_msg_number=0,
        recv_msg_number=0,
        prev_send_chain_len=0,
    ):
        self.session_id = session_id
        self.my_identity = my_identity
        self.peer_identity = peer_identity
        self.peer_signing_pub = peer_signing_pub
        self.root_key = root_key
        self.send_chain_key = send_chain_key
        self.recv_chain_key = recv_chain_key
        self.our_ratchet_priv = our_ratchet_priv
        self.our_ratchet_pub = our_ratchet_pub
        self.their_ratchet_pub = their_ratchet_pub
        self.send_msg_number = send_msg_number
        self.recv_msg_number = recv_msg_number
        self.prev_send_chain_len = prev_send_chain_len
        self.skipped_keys = {}
        self.seen_message_ids = []
        self.created_at = time.time()
        self.last_active = time.time()

    def is_expired(self):
        return (time.time() - self.last_active) > (SESSION_EXPIRE_DAYS * 86400)

    def touch(self):
        self.last_active = time.time()

    def _ratchet_fingerprint(self, pub_raw):
        return hashlib.sha256(pub_raw).hexdigest()[:8]

    def to_dict(self):
        sid = self.session_id
        if isinstance(sid, bytes):
            sid = sid.hex()
        d = {
            "v": 1,
            "session_id": sid,
            "my_identity": self.my_identity,
            "peer_identity": self.peer_identity,
            "peer_signing_pub": _b64(self.peer_signing_pub) if self.peer_signing_pub else "",
            "root_key": _b64(self.root_key),
            "send_chain_key": _b64(self.send_chain_key),
            "recv_chain_key": _b64(self.recv_chain_key),
            "our_ratchet_priv": _b64(self.our_ratchet_priv),
            "our_ratchet_pub": _b64(self.our_ratchet_pub),
            "their_ratchet_pub": _b64(self.their_ratchet_pub),
            "send_msg_number": self.send_msg_number,
            "recv_msg_number": self.recv_msg_number,
            "prev_send_chain_len": self.prev_send_chain_len,
            "skipped_keys": {
                fp: {str(n): _b64(mk) for n, mk in fp_dict.items()}
                for fp, fp_dict in self.skipped_keys.items()
            },
            "seen_message_ids": self.seen_message_ids[-MAX_SEEN_IDS:],
            "created_at": self.created_at,
            "last_active": self.last_active,
        }
        return d

    @classmethod
    def from_dict(cls, d):
        s = cls(
            session_id=d.get("session_id", ""),
            my_identity=d["my_identity"],
            peer_identity=d["peer_identity"],
            peer_signing_pub=_b64d(d.get("peer_signing_pub", "")) if d.get("peer_signing_pub") else b"",
            root_key=_b64d(d["root_key"]),
            send_chain_key=_b64d(d["send_chain_key"]),
            recv_chain_key=_b64d(d["recv_chain_key"]),
            our_ratchet_priv=_b64d(d["our_ratchet_priv"]),
            our_ratchet_pub=_b64d(d["our_ratchet_pub"]),
            their_ratchet_pub=_b64d(d["their_ratchet_pub"]),
            send_msg_number=d.get("send_msg_number", 0),
            recv_msg_number=d.get("recv_msg_number", 0),
            prev_send_chain_len=d.get("prev_send_chain_len", 0),
        )
        s.skipped_keys = {}
        for fp, fp_dict in d.get("skipped_keys", {}).items():
            s.skipped_keys[fp] = {int(n): _b64d(mk) for n, mk in fp_dict.items()}
        s.seen_message_ids = d.get("seen_message_ids", [])[-MAX_SEEN_IDS:]
        s.created_at = d.get("created_at", time.time())
        s.last_active = d.get("last_active", time.time())
        return s

    def _prune_skipped(self):
        total = sum(len(v) for v in self.skipped_keys.values())
        if total > MAX_SKIPPED:
            self.skipped_keys.clear()

    def _add_skipped(self, ratchet_pub_raw, msg_num, mk):
        fp = self._ratchet_fingerprint(ratchet_pub_raw)
        if fp not in self.skipped_keys:
            self.skipped_keys[fp] = {}
        self.skipped_keys[fp][msg_num] = mk
        self._prune_skipped()

    def _get_skipped(self, ratchet_pub_raw, msg_num):
        fp = self._ratchet_fingerprint(ratchet_pub_raw)
        if fp in self.skipped_keys:
            return self.skipped_keys[fp].pop(msg_num, None)
        return None

    def _has_seen(self, msg_id):
        return msg_id in self.seen_message_ids

    def _mark_seen(self, msg_id):
        self.seen_message_ids.append(msg_id)
        if len(self.seen_message_ids) > MAX_SEEN_IDS:
            self.seen_message_ids = self.seen_message_ids[-MAX_SEEN_IDS:]


def send_message(state, inner_bytes):
    CKs, MK = KDF_CK(state.send_chain_key)
    state.send_chain_key = CKs

    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(MK)
    ciphertext = aesgcm.encrypt(nonce, inner_bytes, state.session_id.encode() if isinstance(state.session_id, str) else state.session_id)

    msg_id = secrets.token_hex(16)
    msg_num = state.send_msg_number
    pn = state.prev_send_chain_len

    state.send_msg_number += 1
    state.touch()

    return {
        "id": msg_id,
        "session_id": state.session_id if isinstance(state.session_id, str) else state.session_id.hex(),
        "from": state.my_identity,
        "to": state.peer_identity,
        "timestamp": time.time(),
        "type": "message",
        "payload": {
            "ratchet_public_key": _b64(state.our_ratchet_pub),
            "message_number": msg_num,
            "previous_chain_length": pn,
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        },
    }


def receive_message(state, msg):
    if state._has_seen(msg["id"]):
        return None
    state._mark_seen(msg["id"])

    payload = msg["payload"]
    their_ratchet_pub = _b64d(payload["ratchet_public_key"])
    msg_num = payload["message_number"]

    # Skip DH ratchet for first reply (their_ratchet_pub still unset)
    if their_ratchet_pub != state.their_ratchet_pub and state.their_ratchet_pub != b"\x00" * 32:
        _dh_ratchet_step(state, their_ratchet_pub)

    return _decrypt_message_in_chain(state, payload, msg)


def _dh_ratchet_step(state, new_their_ratchet_pub):
    dh = x25519_ecdh_raw(state.our_ratchet_priv, new_their_ratchet_pub)
    state.root_key, CKr = KDF_RK(state.root_key, dh)
    state.recv_chain_key = CKr
    state.recv_msg_number = 0

    new_priv, new_pub = generate_x25519_keypair_raw()
    dh2 = x25519_ecdh_raw(new_priv, new_their_ratchet_pub)
    state.root_key, CKs = KDF_RK(state.root_key, dh2)

    state.prev_send_chain_len = state.send_msg_number
    state.send_msg_number = 0
    state.our_ratchet_priv = new_priv
    state.our_ratchet_pub = new_pub
    state.their_ratchet_pub = new_their_ratchet_pub
    state.send_chain_key = CKs

    state._prune_skipped()


def _decrypt_message_in_chain(state, payload, msg):
    msg_num = payload["message_number"]
    nonce = _b64d(payload["nonce"])
    ciphertext = _b64d(payload["ciphertext"])
    sid = state.session_id
    if isinstance(sid, str):
        sid = sid.encode()

    if state.recv_msg_number > msg_num:
        mk = state._get_skipped(state.their_ratchet_pub, msg_num)
        if mk is not None:
            try:
                aesgcm = AESGCM(mk)
                plain = aesgcm.decrypt(nonce, ciphertext, sid)
                state.touch()
                return plain
            except Exception:
                return None
        return None

    while state.recv_msg_number < msg_num:
        CKr, MK_skip = KDF_CK(state.recv_chain_key)
        state.recv_chain_key = CKr
        state._add_skipped(state.their_ratchet_pub, state.recv_msg_number, MK_skip)
        state.recv_msg_number += 1

    CKr, MK = KDF_CK(state.recv_chain_key)
    state.recv_chain_key = CKr
    state.recv_msg_number += 1

    try:
        aesgcm = AESGCM(MK)
        plain = aesgcm.decrypt(nonce, ciphertext, sid)
        state.touch()
        return plain
    except Exception:
        return None


def try_decrypt_skipped(state, their_ratchet_pub_raw, msg_num, nonce, ciphertext):
    mk = state._get_skipped(their_ratchet_pub_raw, msg_num)
    if mk is None:
        return None
    sid = state.session_id
    if isinstance(sid, str):
        sid = sid.encode()
    try:
        aesgcm = AESGCM(mk)
        return aesgcm.decrypt(nonce, ciphertext, sid)
    except Exception:
        return None


def x3dh_initiate_session(
    peer_identity_key_pub_pem,
    peer_signed_prekey_pub_pem,
    peer_one_time_prekey_pub_b64,
    my_identity_priv_raw,
    my_identity,
    peer_identity,
    peer_signing_pub_pem,
):
    peer_id_pub = deserialize_x25519_pub(peer_identity_key_pub_pem)
    peer_spk_pub = deserialize_x25519_pub(peer_signed_prekey_pub_pem)
    peer_otp_pub = None
    if peer_one_time_prekey_pub_b64:
        peer_otp_pub = deserialize_x25519_pub(_b64d(peer_one_time_prekey_pub_b64))

    eph_priv_raw, eph_pub_raw = generate_x25519_keypair_raw()
    my_id_pub = priv_from_raw(my_identity_priv_raw).public_key()
    my_id_pub_raw = my_id_pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    # 标准 X3DH: DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B) || [DH(EK_A, OPK_B)]
    dh1 = x25519_ecdh_raw(my_identity_priv_raw, _pem_pub_to_raw(peer_spk_pub))
    dh2 = x25519_ecdh_raw(eph_priv_raw, _pem_pub_to_raw(peer_id_pub))
    dh3 = x25519_ecdh_raw(eph_priv_raw, _pem_pub_to_raw(peer_spk_pub))
    dh_bytes = dh1 + dh2 + dh3

    if peer_otp_pub is not None:
        dh4 = x25519_ecdh_raw(eph_priv_raw, _pem_pub_to_raw(peer_otp_pub))
        dh_bytes += dh4

    root_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=b"zhcrypt-x3dh-v2",
        info=b"zhchat-session-root-v1",
    ).derive(dh_bytes)

    session_id = secrets.token_bytes(16)

    our_ratchet_priv, our_ratchet_pub = generate_x25519_keypair_raw()

    hkdf_init = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 4,
        salt=root_key,
        info=b"zhchat-init-chains-v1",
    )
    chain_material = hkdf_init.derive(our_ratchet_pub)
    send_chain_key = chain_material[:KEY_SIZE]
    recv_chain_key = chain_material[KEY_SIZE:KEY_SIZE * 2]

    their_ratchet_pub = b"\x00" * 32

    state = SessionState(
        session_id=session_id,
        my_identity=my_identity,
        peer_identity=peer_identity,
        peer_signing_pub=peer_signing_pub_pem,
        root_key=root_key,
        send_chain_key=send_chain_key,
        recv_chain_key=recv_chain_key,
        our_ratchet_priv=our_ratchet_priv,
        our_ratchet_pub=our_ratchet_pub,
        their_ratchet_pub=their_ratchet_pub,
    )

    init_msg_extra = {
        "sender_identity_pub": _b64(my_id_pub_raw),
        "sender_ephemeral_pub": _b64(eph_pub_raw),
        "signing_public_key": _b64(peer_signing_pub_pem) if isinstance(peer_signing_pub_pem, bytes) and b"BEGIN" not in peer_signing_pub_pem else _b64(peer_signing_pub_pem),
    }

    return state, init_msg_extra


def x3dh_complete_session(
    my_identity_priv_raw,
    my_signed_prekey_priv_raw,
    sender_identity_pub_raw,
    sender_ephemeral_pub_raw,
    sender_ratchet_pub_raw,
    sender_signing_pub_pem,
    my_identity,
    sender_identity,
    one_time_prekey_priv_raw=None,
    session_id=None,
):
    dh1 = x25519_ecdh_raw(my_signed_prekey_priv_raw, sender_identity_pub_raw)
    dh2 = x25519_ecdh_raw(my_identity_priv_raw, sender_ephemeral_pub_raw)
    dh3 = x25519_ecdh_raw(my_signed_prekey_priv_raw, sender_ephemeral_pub_raw)

    dh_bytes = dh1 + dh2 + dh3

    if one_time_prekey_priv_raw:
        dh4 = x25519_ecdh_raw(one_time_prekey_priv_raw, sender_ephemeral_pub_raw)
        dh_bytes += dh4

    root_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=b"zhcrypt-x3dh-v2",
        info=b"zhchat-session-root-v1",
    ).derive(dh_bytes)

    if session_id is None:
        session_id = secrets.token_bytes(16)

    CKr = b"\x00" * KEY_SIZE
    Nr = 0

    state = SessionState(
        session_id=session_id,
        my_identity=my_identity,
        peer_identity=sender_identity,
        peer_signing_pub=sender_signing_pub_pem,
        root_key=root_key,
        send_chain_key=b"\x00" * KEY_SIZE,
        recv_chain_key=CKr,
        our_ratchet_priv=b"\x00" * KEY_SIZE,
        our_ratchet_pub=b"\x00" * KEY_SIZE,
        their_ratchet_pub=sender_ratchet_pub_raw,
        recv_msg_number=Nr,
    )

    return state


def complete_session_first_message(state, sender_ratchet_pub_raw, nonce_b64, ciphertext_b64, inner_bytes):
    state.their_ratchet_pub = sender_ratchet_pub_raw

    our_ratchet_priv, our_ratchet_pub = generate_x25519_keypair_raw()
    state.our_ratchet_priv = our_ratchet_priv
    state.our_ratchet_pub = our_ratchet_pub

    hkdf_init = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 4,
        salt=state.root_key,
        info=b"zhchat-init-chains-v1",
    )
    chain_material = hkdf_init.derive(sender_ratchet_pub_raw)
    state.recv_chain_key = chain_material[:KEY_SIZE]
    state.send_chain_key = chain_material[KEY_SIZE:KEY_SIZE * 2]

    state.touch()

    nonce = _b64d(nonce_b64)
    ciphertext = _b64d(ciphertext_b64)
    sid = state.session_id
    if not isinstance(sid, bytes):
        sid = sid.encode()

    CKr, MK = KDF_CK(state.recv_chain_key)
    state.recv_chain_key = CKr
    state.recv_msg_number += 1

    try:
        aesgcm = AESGCM(MK)
        plain = aesgcm.decrypt(nonce, ciphertext, sid)
        return plain
    except Exception:
        return None


def deserialize_x25519_pub(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)


def _pem_pub_to_raw(pub):
    return pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def pem_priv_to_raw(pem_bytes):
    priv = serialization.load_pem_private_key(pem_bytes, password=None)
    return priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def raw_to_pem_pub(raw):
    pub = x25519.X25519PublicKey.from_public_bytes(raw)
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def x3dh_reply_msg(state, my_identity, peer_identity):
    return {
        "ratchet_public_key": _b64(state.our_ratchet_pub),
        "message_number": 0,
        "previous_chain_length": 0,
    }
