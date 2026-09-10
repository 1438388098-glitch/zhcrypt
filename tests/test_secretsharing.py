#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Shamir 秘密分享回归测试 (R4 补齐, 此前全模块零测试)
==================================================
锁定: 3-of-5 阈值语义、尾零秘密恢复 (3.1.0 rstrip 修复)、重复序号拒绝、
份额格式解析。运行: py -3.13 -m pytest tests/test_secretsharing.py -q
"""
import os

import pytest

from secretsharing import (PRIME, BYTE_LEN, split_secret, recover_secret,
                           format_share, parse_share)


def test_roundtrip_random_secrets():
    for _ in range(20):
        secret = os.urandom(BYTE_LEN)
        shares = split_secret(secret, total=5, threshold=3)
        assert recover_secret(shares[:3]) == secret


def test_roundtrip_trailing_zero_bytes():
    """秘密尾字节为 0x00 时必须完整恢复 (rstrip 修复回归, 约 1/256 概率)。"""
    for tail in (b"\x00", b"\x00\x00", b"\x01\x00"):
        secret = os.urandom(BYTE_LEN - len(tail)) + tail
        shares = split_secret(secret)
        assert recover_secret(shares[1:4]) == secret


def test_all_zero_secret():
    secret = b"\x00" * BYTE_LEN
    shares = split_secret(secret)
    assert recover_secret(shares[:3]) == secret


def test_threshold_semantics_any_three_of_five():
    secret = os.urandom(BYTE_LEN)
    shares = split_secret(secret, total=5, threshold=3)
    # 任意 3 份组合 (C(5,3)=10) 均可恢复
    for i in range(5):
        for j in range(i + 1, 5):
            for k in range(j + 1, 5):
                assert recover_secret([shares[i], shares[j], shares[k]]) == secret


def test_two_shares_insufficient():
    secret = os.urandom(BYTE_LEN)
    shares = split_secret(secret, total=5, threshold=3)
    # 数量检查直接拒绝 2 份
    with pytest.raises(ValueError):
        recover_secret(shares[:2])


def test_duplicate_index_rejected():
    secret = os.urandom(BYTE_LEN)
    shares = split_secret(secret)
    dup = [shares[0], shares[0], shares[1]]
    with pytest.raises(ValueError):
        recover_secret(dup)


def test_insufficient_count_rejected():
    secret = os.urandom(BYTE_LEN)
    shares = split_secret(secret)
    with pytest.raises(ValueError):
        recover_secret(shares[:2])


def test_share_format_roundtrip():
    hex_data = os.urandom(BYTE_LEN).hex()
    text = format_share("alice", 3, hex_data)
    ident, idx, parsed_hex = parse_share(text)
    assert (ident, idx, parsed_hex) == ("alice", 3, hex_data)


def test_parse_share_rejects_garbage():
    for bad in ("", "hello", "other|a|1|ff", "zhcrypt|a|1"):
        with pytest.raises(ValueError):
            parse_share(bad)


def test_split_truncates_oversize_secret():
    secret = os.urandom(64)
    shares = split_secret(secret)
    assert recover_secret(shares[:3]) == secret[:BYTE_LEN]
