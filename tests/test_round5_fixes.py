#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
R5 修复回归测试 (pytest)
========================

  - import_peer_static_keys 三重守卫 (自身拒绝/PEM 校验/TOFU 锚保护)
  - import_public_key_bundle 损坏束明确报错 (不再静默降级写垃圾)
  - _load_device_key 损坏时备份+告警 (不再静默覆盖)
  - cleanup_expired 回收已消耗 OTP
  - messages 双向索引存在
  - /v1/messages/history (before 分页) / prune / stats / prekey meta /
    admin cleanup 端点覆盖 (此前零测试)
  - health 探测 DB 且不泄露版本

运行: py -3.13 -m pytest tests/test_round5_fixes.py -q
"""
import json
import os

import pytest

TOKEN = "test-token-12345678"


@pytest.fixture
def server(monkeypatch, tmp_path):
    monkeypatch.setenv("ZHPREKEY_TOKEN", TOKEN)
    monkeypatch.setenv("ZHPREKEY_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("ZHCHAT_FILE_DIR", str(tmp_path / "files"))
    import importlib
    import server as server_mod
    importlib.reload(server_mod)
    server_mod.init_db()
    server_mod.app.config["TESTING"] = True
    return server_mod


@pytest.fixture
def client(server):
    c = server.app.test_client()
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {TOKEN}"
    return c


def _auth_headers(identity="alice", **extra):
    h = {"Authorization": f"Bearer {TOKEN}", "X-Identity": identity}
    h.update(extra)
    return h


# ----------------------------------------------------------------------
# import_peer_static_keys 三重守卫
# ----------------------------------------------------------------------

def _pub_b64(pub_key_obj):
    from cryptography.hazmat.primitives import serialization
    pem = pub_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    import base64
    return base64.urlsafe_b64encode(pem).decode("ascii")


def _gen_x25519():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.generate()


def test_import_peer_rejects_local_identity(tmp_path):
    """对端名与本地身份同名 (.key 存在) 时拒绝覆盖自身公钥。"""
    from keys import KeyStore
    ks = KeyStore(str(tmp_path))
    (tmp_path / "selfid.key").write_bytes(b"rsa-private")
    r = ks.import_peer_static_keys("selfid", idk_b64="AAAA", spk_b64="AAAA",
                                   signing_b64="AAAA")
    assert r["skipped"] and "refused" in r["skipped"][0]
    assert not (tmp_path / "selfid.x25519.pub").exists()


def test_import_peer_rejects_garbage_pem(tmp_path):
    """非 PEM 垃圾数据不得落盘。"""
    import base64
    from keys import KeyStore
    ks = KeyStore(str(tmp_path))
    r = ks.import_peer_static_keys(
        "bob",
        idk_b64=base64.urlsafe_b64encode(b"garbage").decode("ascii"))
    assert r["skipped"] and not r["updated"]
    assert not (tmp_path / "bob.x25519.pub").exists()


def test_import_peer_tofu_anchor_protects_signing_key(tmp_path):
    """已有 TOFU 锚且新签名公钥不同 -> 跳过签名公钥, 其余字段照常。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64
    from keys import KeyStore
    ks = KeyStore(str(tmp_path))

    anchor = Ed25519PrivateKey.generate()
    anchor_pem = anchor.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    ks.store_tofu_signing_pub("bob", anchor_pem)

    attacker = Ed25519PrivateKey.generate()
    idk = _gen_x25519()
    spk = _gen_x25519()
    r = ks.import_peer_static_keys(
        "bob",
        idk_b64=_pub_b64(idk.public_key()),
        spk_b64=_pub_b64(spk.public_key()),
        signing_b64=base64.urlsafe_b64encode(
            attacker.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode("ascii"))

    assert r["updated"] and not r["skipped"]          # x25519/spk 照常更新
    assert (tmp_path / "bob.x25519.pub").exists()
    # 签名公钥被跳过: 不落盘, 锚点不被替换
    assert "bob.ed25519.pub" not in r["updated"]
    assert not (tmp_path / "bob.ed25519.pub").exists()
    with open(tmp_path / "bob.tofu.ed25519.pub", "rb") as f:
        assert f.read() == anchor_pem
    # 与锚一致的签名公钥则正常写入
    r2 = ks.import_peer_static_keys(
        "bob", signing_b64=base64.urlsafe_b64encode(anchor_pem).decode("ascii"))
    assert "bob.ed25519.pub" in r2["updated"]
    with open(tmp_path / "bob.ed25519.pub", "rb") as f:
        assert f.read() == anchor_pem


# ----------------------------------------------------------------------
# import_public_key_bundle 损坏束
# ----------------------------------------------------------------------

def test_import_bundle_corrupt_raises(tmp_path):
    """带 v3 类型标记但缺字段的束必须明确报错, 不再静默降级写 .pub。"""
    import base64
    from keys import KeyStore
    ks = KeyStore(str(tmp_path))
    bad = base64.urlsafe_b64encode(
        json.dumps({"type": "zhcrypt_public_key_bundle", "version": 3}).encode()
    ).decode("ascii")
    with pytest.raises(ValueError):
        ks.import_public_key_bundle(bad, "carol")
    assert not (tmp_path / "carol.pub").exists()


# ----------------------------------------------------------------------
# device.key 损坏处理
# ----------------------------------------------------------------------

def test_device_key_corrupt_backed_up(tmp_path, monkeypatch, capsys):
    import config
    dev = tmp_path / "device.key"
    dev.write_bytes(b"short")           # 损坏: 长度 != 32
    monkeypatch.setattr(config, "DEVICE_KEY_PATH", str(dev))
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    key = config._load_device_key()
    assert len(key) == 32
    assert dev.read_bytes() == key                      # 重新生成
    assert (tmp_path / "device.key.corrupt").read_bytes() == b"short"
    err = capsys.readouterr().err
    assert "device.key 损坏" in err


# ----------------------------------------------------------------------
# 服务端清理 / 索引 / 日志
# ----------------------------------------------------------------------

def test_cleanup_expired_removes_consumed_otp(server, client):
    otp = "e" * 64
    client.post("/v1/prekey/alice", headers=_auth_headers(),
                json={"identity_key_pub": "ik", "signed_prekey_pub": "sp",
                      "signature": "sig", "fingerprint": "fp",
                      "one_time_prekeys": [otp]})
    # 消耗该 OTP
    client.get("/v1/prekey/alice", headers=_auth_headers())
    # 把 consumed_at 拨到 1 天前
    import sqlite3
    con = sqlite3.connect(server.DB_PATH)
    con.execute("UPDATE prekeys SET consumed_at = consumed_at - 90000 "
                "WHERE consumed = 1")
    con.commit()
    con.close()
    r = client.post("/v1/admin/cleanup_expired", headers=_auth_headers())
    assert r.status_code == 200
    assert r.get_json()["deleted"] >= 1
    con = sqlite3.connect(server.DB_PATH)
    n = con.execute("SELECT COUNT(*) FROM prekeys WHERE consumed = 1").fetchone()[0]
    con.close()
    assert n == 0


def test_messages_pair_index_exists(server):
    import sqlite3
    con = sqlite3.connect(server.DB_PATH)
    names = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    con.close()
    assert "idx_messages_pair" in names


def test_health_probes_db_and_hides_version(client):
    r = client.get("/v1/health")
    body = r.get_json()
    assert body["status"] == "ok"
    assert "version" not in body


# ----------------------------------------------------------------------
# 此前零覆盖的 5 个端点
# ----------------------------------------------------------------------

def test_message_history_and_pagination(server, client):
    for i in range(5):
        r = client.post("/v1/messages/send", headers=_auth_headers(),
                        json={"id": f"h{i}", "to": "bob", "identity": "alice",
                              "payload": {"i": i}})
        assert r.status_code == 200
    r = client.get("/v1/messages/history", headers=_auth_headers(),
                   query_string={"identity": "alice", "with": "bob"})
    msgs = r.get_json()["messages"]
    assert len(msgs) == 5
    assert msgs[0]["payload"]["i"] == 0          # 升序: 最旧在前
    # before 分页: 游标 = 本页最新一条 (升序末尾), 取更早的历史
    r2 = client.get("/v1/messages/history", headers=_auth_headers(),
                    query_string={"identity": "alice", "with": "bob",
                                  "before": msgs[-1]["id"]})
    older = r2.get_json()["messages"]
    assert 0 < len(older) < 5
    assert older[-1]["timestamp"] <= msgs[-1]["timestamp"]


def test_message_prune_endpoint(server, client):
    r = client.delete("/v1/messages/prune", headers=_auth_headers(),
                      query_string={"older_than_days": "0"})
    assert r.status_code == 200
    assert "deleted" in r.get_json()


def test_stats_endpoint(server, client):
    client.post("/v1/prekey/alice", headers=_auth_headers(),
                json={"identity_key_pub": "ik", "signed_prekey_pub": "sp",
                      "signature": "sig", "fingerprint": "fp"})
    r = client.get("/v1/stats", headers=_auth_headers())
    body = r.get_json()
    assert body["identities"] >= 1
    assert "prekeys_total" in body


def test_prekey_meta_does_not_consume_otp(server, client):
    otp = "f" * 64
    client.post("/v1/prekey/alice", headers=_auth_headers(),
                json={"identity_key_pub": "ik", "signed_prekey_pub": "sp",
                      "signature": "sig", "fingerprint": "fp",
                      "one_time_prekeys": [otp]})
    r1 = client.get("/v1/prekey/meta/alice", headers=_auth_headers())
    assert r1.status_code == 200
    r2 = client.get("/v1/prekey/remaining/alice", headers=_auth_headers())
    assert r2.get_json()["remaining"] == 1      # meta 不消耗 OTP
