#!/usr/bin/env python3
"""agentrouter 代理解析与护栏 Cookie 域名推导单元测试（严格 Mock，不发真实请求）。"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import agentrouter


class TestPresetCookieDomain(unittest.TestCase):
    def test_default_api_url_domain(self):
        self.assertEqual(agentrouter._preset_cookie_domain("https://ps.air-outer.com"), ".air-outer.com")

    def test_alternate_domain(self):
        self.assertEqual(agentrouter._preset_cookie_domain("https://agentrouter.org"), ".agentrouter.org")

    def test_strips_path_port_and_userinfo(self):
        self.assertEqual(agentrouter._preset_cookie_domain("https://u:p@ps.air-outer.com:8443/console"), ".air-outer.com")

    def test_empty_falls_back_to_default(self):
        self.assertEqual(agentrouter._preset_cookie_domain(""), ".air-outer.com")


class TestFingerprintSessionProxyResolution(unittest.TestCase):
    def test_raises_actionable_error_without_proxy(self):
        h = MagicMock(spec=["proxy_endpoint"])
        h.proxy_endpoint = None
        env = {"AGENTROUTER_PROXY": "", "SINGBOX_SOCKS_URL": ""}
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(RuntimeError) as ctx:
                agentrouter._fingerprint_session(h)
        msg = str(ctx.exception)
        self.assertIn("Setup sing-box egress", msg)  # 指向 workflow 诊断步骤
        self.assertNotIn("未配置且无候选代理）。", msg)  # 旧误导文案已移除

    def test_singbox_socks_url_alias_fallback(self):
        h = MagicMock(spec=["proxy_endpoint"])
        h.proxy_endpoint = None
        env = {"AGENTROUTER_PROXY": "", "SINGBOX_SOCKS_URL": "socks5://127.0.0.1:1080"}
        with patch.dict(os.environ, env, clear=False):
            with patch.dict("sys.modules", {"curl_cffi": MagicMock(), "curl_cffi.requests": MagicMock()}):
                sess = agentrouter._fingerprint_session(h)
        self.assertTrue(sess)


class TestLoadAccounts(unittest.TestCase):
    def test_sequence_and_accounts_merge_dedup(self):
        env = {
            "AGENTROUTER_EMAIL_1": "a@x.com", "AGENTROUTER_PASSWORD_1": "pw1",
            "AGENTROUTER_ACCOUNTS": "a@x.com:pw1\nb@y.com:pw2",
        }
        with patch.dict(os.environ, env, clear=False):
            accounts = agentrouter._load_accounts()
        self.assertEqual(
            accounts,
            [{"username": "a@x.com", "password": "pw1"}, {"username": "b@y.com", "password": "pw2"}],
        )

    def test_unparsable_entry_skipped(self):
        env = {"AGENTROUTER_EMAIL_1": "a@x.com", "AGENTROUTER_PASSWORD_1": "pw1",
               "AGENTROUTER_ACCOUNTS": "garbage-without-colon"}
        with patch.dict(os.environ, env, clear=False):
            accounts = agentrouter._load_accounts()
        self.assertEqual(len(accounts), 1)


class TestLoginFailureHint(unittest.TestCase):
    def test_fingerprint_failure_hint_sanitized(self):
        """指纹链路失败时打印的响应片段必须经脱敏（防 Cookie/token 进公开日志）。"""
        waf_page = '<html>aliyun_waf Set-Cookie: acw_tc=secrettokenvalue123456</html>'
        fake_resp = MagicMock(status_code=403, text=waf_page, headers={})
        fake_sess = MagicMock()
        fake_sess.get.return_value = MagicMock(status_code=200, text="ok", headers={})
        fake_sess.post.return_value = fake_resp

        h = MagicMock()
        h.proxy_endpoint = None
        h.request.return_value = MagicMock(code=500, text="", headers={})
        h.request.return_value.json.return_value = {}
        env = {"AGENTROUTER_PROXY": "socks5://127.0.0.1:1080"}

        with patch.dict(os.environ, env, clear=False), \
             patch("agentrouter._browser_cookies"), \
             patch("agentrouter._warmup"), \
             patch("curl_cffi.requests.Session", return_value=fake_sess), \
             patch("builtins.print") as mock_print:
            with self.assertRaises(RuntimeError):
                agentrouter._login(h, "u", "p", "https://ps.air-outer.com")

        printed = "\n".join(str(c.args[0]) for c in mock_print.call_args_list if c.args)
        self.assertIn("指纹链路未成功", printed)
        self.assertNotIn("secrettokenvalue123456", printed)


if __name__ == "__main__":
    unittest.main()
