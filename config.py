"""
zhcrypt v3.0 - 配置管理模块
管理 ~/.zhcrypt/config.json
"""

import os
import json

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".zhcrypt")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "version": "3.0.0",
    "argon2id": {
        "time_cost": 4,
        "memory_cost": 262144,
        "parallelism": 4,
    },
    "default_identity": "default",
    "pfs_enabled": True,
    "signature_enabled": True,
    "prekey_server": {
        "url": "",
        "auth_token": "",
        "auto_upload_prekeys": True,
        "prekey_rotate_seconds": 3600,
    },
    "file_encryption": {
        "chunk_size_bytes": 65536,
        "legacy_mode": False,
    },
    "streaming": {
        "enabled": True,
        "chunk_size": 65536,
    },
    "gui": {
        "last_tab": 0,
        "window_width": 720,
        "window_height": 560,
    },
}


def ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)


def load():
    ensure_config_dir()
    if not os.path.exists(CONFIG_PATH):
        save(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        _deep_merge(merged, cfg)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save(cfg):
    ensure_config_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def get(key_path, default=None):
    cfg = load()
    keys = key_path.split(".")
    val = cfg
    for k in keys:
        if isinstance(val, dict):
            val = val.get(k)
        else:
            return default
        if val is None:
            return default
    return val


def set_key(key_path, value):
    cfg = load()
    keys = key_path.split(".")
    obj = cfg
    for k in keys[:-1]:
        if k not in obj or not isinstance(obj[k], dict):
            obj[k] = {}
        obj = obj[k]
    obj[keys[-1]] = value
    save(cfg)


def set_prekey_server(url: str, token: str = ""):
    set_key("prekey_server.url", url)
    if token:
        set_key("prekey_server.auth_token", token)


def get_prekey_server():
    return get("prekey_server.url", "")


def get_auth_token():
    return get("prekey_server.auth_token", "")


def _deep_merge(base, override):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
