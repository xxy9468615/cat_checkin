#!/usr/bin/env python3
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from proxy_manager import (
    ProxyEndpoint,
    format_dead_proxy_alert,
    get_all_proxy_endpoints,
    mask_proxy_url,
    parse_proxies_text,
    parse_proxy_line,
)
from common import Http


class TestProxyManager(unittest.TestCase):
    def test_parse_uri_fragment(self):
        ep = parse_proxy_line("socks5://user:pass@1.2.3.4:1080#自建-香港-01")
        self.assertIsNotNone(ep)
        self.assertEqual(ep.name, "自建-香港-01")
        self.assertEqual(ep.url, "socks5://user:pass@1.2.3.4:1080")
        self.assertIn("1.***.***.4", ep.safe_url)
        self.assertNotIn("1080", ep.safe_url)
        self.assertTrue(ep.is_self_hosted)
        # display_name 严格仅包含名称，绝不包含 IP 和端口
        self.assertEqual(ep.display_name, "【自建-香港-01】")
        self.assertNotIn("1.2.3.4", ep.display_name)
        self.assertNotIn("1080", ep.display_name)

    def test_parse_bracket_prefix(self):
        ep1 = parse_proxy_line("[自建-美西搬瓦工] http://5.6.7.8:8080")
        self.assertIsNotNone(ep1)
        self.assertEqual(ep1.name, "自建-美西搬瓦工")
        self.assertEqual(ep1.url, "http://5.6.7.8:8080")
        self.assertTrue(ep1.is_self_hosted)
        self.assertEqual(ep1.display_name, "【自建-美西搬瓦工】")

        ep2 = parse_proxy_line("【自建-日本住宅】 socks5://9.9.9.9:1080")
        self.assertIsNotNone(ep2)
        self.assertEqual(ep2.name, "自建-日本住宅")
        self.assertEqual(ep2.url, "socks5://9.9.9.9:1080")
        self.assertEqual(ep2.display_name, "【自建-日本住宅】")

    def test_bare_ip_fallback_masking(self):
        # 裸 IP 自动降级推断名称：必须深度脱敏，且绝不显示端口
        ep = parse_proxy_line("112.64.135.45:8080")
        self.assertIsNotNone(ep)
        self.assertEqual(ep.display_name, "【代理节点-112.***.***.45】")
        self.assertNotIn("8080", ep.display_name)
        self.assertNotIn("64", ep.display_name)
        self.assertNotIn("135", ep.display_name)

    def test_parse_key_value(self):
        ep = parse_proxy_line("自建-香港02 = socks5://admin:pw@8.8.8.8:1080")
        self.assertIsNotNone(ep)
        self.assertEqual(ep.name, "自建-香港02")
        self.assertEqual(ep.url, "socks5://admin:pw@8.8.8.8:1080")
        self.assertEqual(ep.display_name, "【自建-香港02】")
        self.assertIn("8.***.***.8", ep.safe_url)
        self.assertNotIn("1080", ep.safe_url)

    def test_parse_multiline_with_comments(self):
        text = """
        # 自建-广州家宽出口
        socks5://10.0.0.1:1080
        [备用-AWS] http://11.0.0.2:3128
        # 普通注释无关于下一行
        # ------
        12.0.0.3:1080#自建-韩国
        """
        eps = parse_proxies_text(text)
        self.assertEqual(len(eps), 3)
        self.assertEqual(eps[0].name, "自建-广州家宽出口")
        self.assertEqual(eps[0].display_name, "【自建-广州家宽出口】")
        self.assertEqual(eps[1].name, "备用-AWS")
        self.assertEqual(eps[1].display_name, "【备用-AWS】")
        self.assertEqual(eps[2].name, "自建-韩国")
        self.assertEqual(eps[2].display_name, "【自建-韩国】")
        self.assertEqual(eps[2].url, "socks5://12.0.0.3:1080")

    def test_self_hosted_priority_scheduling(self):
        env = {
            "SELF_HOSTED_PROXIES": "socks5://1.1.1.1:1080#自建-主节点",
            "52POJIE_PROXY": "http://2.2.2.2:8080#业务代理",
            "AGENTROUTER_BACKUP_PROXIES": "http://3.3.3.3:8080#全局备用",
        }
        with patch.dict(os.environ, env, clear=True):
            endpoints = get_all_proxy_endpoints(task_prefix="52POJIE")
            self.assertEqual(len(endpoints), 3)
            # 自建代理排在最前
            self.assertEqual(endpoints[0].name, "自建-主节点")
            self.assertTrue(endpoints[0].is_self_hosted)
            # 其次是业务专属代理
            self.assertEqual(endpoints[1].name, "业务代理")
            # 最后是全局备用
            self.assertEqual(endpoints[2].name, "全局备用")

    def test_dead_proxy_alert_format(self):
        ep = ProxyEndpoint(
            name="自建-测试节点",
            url="socks5://1.2.3.4:1080",
            safe_url="socks5://***:***@1.***.***.4:****",
            protocol="socks5",
            host="1.2.3.4",
            port=1080,
            source="SELF_HOSTED_PROXIES",
            raw_input="socks5://1.2.3.4:1080#自建-测试节点",
            is_self_hosted=True,
        )
        alert = format_dead_proxy_alert(ep, "连接超时")
        self.assertIn("❌ 代理失效 【自建-测试节点】", alert)
        self.assertNotIn("1.2.3.4", alert)
        self.assertNotIn("1080", alert)
        self.assertIn("SELF_HOSTED_PROXIES", alert)
        self.assertIn("死代理", alert)

    def test_http_endpoint_integration(self):
        ep = ProxyEndpoint(
            name="自建-内网代理",
            url="http://127.0.0.1:8080",
            safe_url="http://127.0.0.1:8080",
            protocol="http",
            host="127.0.0.1",
            port=8080,
        )
        h = Http(proxy=ep)
        self.assertIsNotNone(h.proxy_endpoint)
        self.assertEqual(h.proxy_endpoint.name, "自建-内网代理")

        # 传入带 fragment 的字符串
        h2 = Http(proxy="http://127.0.0.1:8080#自建-HTTP代理")
        self.assertIsNotNone(h2.proxy_endpoint)
        self.assertEqual(h2.proxy_endpoint.name, "自建-HTTP代理")


if __name__ == "__main__":
    unittest.main()
