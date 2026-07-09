"""
zhchat Session Persistence v1.0
================================
会话状态存储到 ~/.zhcrypt/sessions/<my_identity>/<peer_identity>.session
用 Argon2id + AES-256-GCM 加密存储
"""

import os
import json
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

from core import SALT_SIZE, NONCE_SIZE, KEY_SIZE, derive_key

SESSIONS_DIR = os.path.join(os.path.expanduser("~"), ".zhcrypt", "sessions")
SESSION_EXPIRE_DAYS = 30


def _ensure_dir():
    os.makedirs(SESSIONS_DIR, exist_ok=True)


def _session_path(my_identity, peer_identity):
    return os.path.join(SESSIONS_DIR, my_identity, f"{peer_identity}.session")


def _peer_dir(my_identity):
    d = os.path.join(SESSIONS_DIR, my_identity)
    os.makedirs(d, exist_ok=True)
    return d


def save_session(state, passphrase):
    from ratchet import SessionState

    dir_path = _peer_dir(state.my_identity)
    file_path = _session_path(state.my_identity, state.peer_identity)

    plain = json.dumps(state.to_dict(), ensure_ascii=False).encode("utf-8")
    salt = secrets.token_bytes(SALT_SIZE)
    wrapping_key = derive_key(passphrase, salt)
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(wrapping_key)
    ciphertext = aesgcm.encrypt(nonce, plain, None)

    with open(file_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)


def load_session(my_identity, peer_identity, passphrase):
    from ratchet import SessionState

    file_path = _session_path(my_identity, peer_identity)
    if not os.path.exists(file_path):
        return None

    with open(file_path, "rb") as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    wrapping_key = derive_key(passphrase, salt)
    aesgcm = AESGCM(wrapping_key)
    try:
        plain = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return None

    d = json.loads(plain.decode("utf-8"))
    return SessionState.from_dict(d)


def delete_session(my_identity, peer_identity):
    file_path = _session_path(my_identity, peer_identity)
    if os.path.exists(file_path):
        os.remove(file_path)


def list_sessions(my_identity):
    dir_path = os.path.join(SESSIONS_DIR, my_identity)
    if not os.path.exists(dir_path):
        return []
    sessions = []
    for fname in os.listdir(dir_path):
        if fname.endswith(".session"):
            peer = fname[:-len(".session")]
            fpath = os.path.join(dir_path, fname)
            sessions.append({
                "peer": peer,
                "my_identity": my_identity,
                "path": fpath,
                "mtime": os.path.getmtime(fpath),
            })
    return sorted(sessions, key=lambda x: x["mtime"], reverse=True)


def cleanup_expired_sessions(my_identity):
    cutoff = time.time() - SESSION_EXPIRE_DAYS * 86400
    dir_path = os.path.join(SESSIONS_DIR, my_identity)
    if not os.path.exists(dir_path):
        return 0
    removed = 0
    for fname in os.listdir(dir_path):
        fpath = os.path.join(dir_path, fname)
        if fname.endswith(".session") and os.path.getmtime(fpath) < cutoff:
            os.remove(fpath)
            removed += 1
    return removed
