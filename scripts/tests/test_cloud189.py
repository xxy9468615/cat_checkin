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

    def test_cloud189_reuses_cn_proxy(self):
        """天翼云盘复用仓库已有的 SMZDM / 52POJIE 等 CN 出口代理。"""
        import os
        from unittest.mock import patch

        env = {
            "SMZDM_PROXY": "socks5://user:pass@112.64.135.45:1080#自建-上海联通",
        }
        with patch.dict(os.environ, env, clear=True):
            proxies = cloud189._get_candidate_proxies()
            self.assertTrue(len(proxies) >= 1)
            self.assertIn("自建-上海联通", proxies[0].name)
            self.assertEqual(proxies[0].protocol, "socks5")

    def test_login_network_failure_message_not_mistaken_as_credential_error(self):
        """HTTP -1（网络层失败）的报错文案不得含"密码错误/验证码"——
        候选轮换循环按这些子串中止，网络故障曾被误判成凭证错误吞掉后续候选。"""
        from unittest.mock import MagicMock, patch

        pub_key = PUBKEY_1024
        enc_resp = MagicMock(code=200)
        enc_resp.json.return_value = {"data": {"pubKey": pub_key, "pre": "{RSA}"}}
        login_page = MagicMock(
            code=200,
            text='<input name="captchaToken" value="ctk">'
                 "<script>var lt='lt123';paramId='pid9';reqId='rid7';</script>",
        )
        fail_resp = MagicMock(code=-1, text="")
        fail_resp.json.return_value = {}

        def fake_request(method, url, **_kw):
            if "encryptConf.do" in url:
                return enc_resp
            if "unifyLoginForPC" in url:
                return login_page
            return fail_resp  # loginSubmit.do → 网络层 -1

        h = MagicMock()
        h.request.side_effect = fake_request
        with patch.object(cloud189, "_resp_dict", side_effect=lambda r: r.json.return_value):
            with self.assertRaises(RuntimeError) as ctx:
                cloud189._login(h, "13800138000", "pw")
        msg = str(ctx.exception)
        self.assertIn("-1", msg)
        self.assertIn("网络层异常", msg)
        self.assertNotIn("密码错误", msg)
        self.assertNotIn("验证码", msg)

    def test_candidate_queue_continues_after_proxy_network_failure(self):
        """主出口 Errno 101 → 备用出口网络 -1 都应继续轮换到直连，而非中止队列。"""
        from unittest.mock import MagicMock, patch

        ep1 = MagicMock()
        ep1.display_name = "主出口"
        ep1.url = "socks5://127.0.0.1:1081"
        ep2 = MagicMock()
        ep2.display_name = "备用出口"
        ep2.url = "http://127.0.0.1:8888"
        created = []

        def fake_http(follow_redirects=True, proxy=""):
            h = MagicMock()
            h.url = proxy
            created.append((proxy, h))
            return h

        def fake_login(h, username, password):
            if h.url == ep1.url:
                raise RuntimeError("获取公钥失败（HTTP -1）：[Errno 101] Network is unreachable")
            if h.url == ep2.url:
                raise RuntimeError("登录失败（-1）：网络层异常，多为代理出口不可用")
            return "session-key"

        with patch.object(cloud189, "_get_candidate_proxies", return_value=[ep1, ep2]), \
             patch.object(cloud189, "Http", side_effect=fake_http), \
             patch.object(cloud189, "_login", side_effect=fake_login), \
             patch.object(cloud189, "_sign", return_value=("签到成功", True)), \
             patch.object(cloud189, "_lotteries", return_value="无"), \
             patch.object(cloud189, "_space", return_value="10G/100G"):
            ok, _summary = cloud189._run_one(1, 1, "13800138000", "pw")

        self.assertTrue(ok)
        # 直连兜底被触达（两个代理都失败后轮换到了 None 候选）
        self.assertIn("", [proxy for proxy, _ in created])

    def test_proxy_isolation_no_socket_pollution(self):
        """验证 SOCKS 代理不会污染全局 socket，直连和 HTTP 代理依然保持原生隔离。"""
        import socket
        from common import Http, _ORIG_SOCKET

        # 实例化 SOCKS 代理 Http
        h_socks = Http(proxy="socks5://user:pass@127.0.0.1:1080#测试")
        self.assertIs(socket.socket, _ORIG_SOCKET)

        # 实例化直连 Http
        h_direct = Http()
        self.assertIs(socket.socket, _ORIG_SOCKET)

        # 实例化 HTTP 代理 Http
        h_http = Http(proxy="http://127.0.0.1:8888#测试HTTP")
        self.assertIs(socket.socket, _ORIG_SOCKET)

    def test_api_url_and_endpoints(self):
        """验证 Open API 鉴权端点与 Web Portal 彻底分离，避免 cookieUserSession 错误。"""
        self.assertEqual(cloud189.API_URL, "https://api.cloud.189.cn")
        self.assertEqual(cloud189.WEB_URL, "https://cloud.189.cn")
        self.assertEqual(cloud189.AUTH_URL, "https://open.e.189.cn")


if __name__ == "__main__":
    unittest.main()