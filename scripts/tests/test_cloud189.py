#!/usr/bin/env python3
"""天翼云盘（cloud189）签到脚本自检与单元测试。

回归覆盖：
1. X.509 SubjectPublicKeyInfo 解析（曾因 body/off 偏移复用导致 IndexError，
   密码盲登因此崩溃 → 恶性回退到 Cookie 模式）
2. RSA PKCS#1 v1.5 加密输出格式（even-length hex，与 platformlogin.js 的
   RSAKey.encrypt 返回 hex 对齐）
3. 待补：loginSubmit 表单字段（epd 等）——依赖外网与真实账号，不在此单测覆盖。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import importlib

cloud189 = importlib.import_module("cloud189")

# 线上 encryptConf.do 返回的真实 RSA 公钥（SubjectPublicKeyInfo base64，1024 位）。
PUBKEY_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZLyV4gHNDUGJMZoOcYauxmNEsKrc0TlLeBEVVIIQNzG4WqjimceOj5R9ETwDeeSN3yejAKLGHgx83lyy2wBjvnbfm/nLObyWwQD/09CmpZdxoFYCH6rdDjRpwZOZ2nXSZpgkZXoOBkfNXNxnN74aXtho2dqBynTw3NFTWyQl8BQIDAQAB"
)


class TestCloud189(unittest.TestCase):
    def test_parse_x509_pubkey_no_indexerror(self):
        """曾因复用外层 off 当 body 偏移而 IndexError，此处验证不再崩溃且解析正确。"""
        n, e = cloud189._parse_x509_pubkey(PUBKEY_1024)
        self.assertEqual(e, 65537)
        self.assertEqual(n.bit_length(), 1024)

    def test_rsa_encrypt_format(self):
        """产出应为 128 字节（256 hex）的纯十六进制，符合 PKCS#1 v1.5。"""
        out = cloud189._rsa_encrypt_hex(PUBKEY_1024, "13800138000")
        self.assertEqual(len(out), 256)
        self.assertRegex(out, r"^[0-9a-f]{256}$")

    def test_rsa_encrypt_differs_per_call(self):
        """随机填充下相同明文两次加密结果不同（确认 PKCS#1 v1.5 盲化生效）。"""
        a = cloud189._rsa_encrypt_hex(PUBKEY_1024, "13800138000")
        b = cloud189._rsa_encrypt_hex(PUBKEY_1024, "13800138000")
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()