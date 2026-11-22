#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from proxy_check import (
    ProxyCheckResult,
    load_candidate_endpoints,
    result_to_dict,
    sanitize_proxy_error,
)
from proxy_manager import parse_proxy_line


class TestProxyCheckNumbering(unittest.TestCase):
    def test_unnamed_lines_get_stable_sequential_numbers(self):
        content = "\n".join(
            [
                "http://1.1.1.1:8888",
                "http://2.2.2.2:8888",
                "http://3.3.3.3:8888",
            ]
        )
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        self.assertEqual([ep.name for ep in eps], ["CN-01", "CN-02", "CN-03"])
        # 编号与输入顺序严格对应，且名称绝不夹带 IP/端口
        self.assertEqual(eps[0].host, "1.1.1.1")
        for ep in eps:
            self.assertNotIn(".", ep.display_name)
            self.assertNotIn(":", ep.display_name)

    def test_comment_lines_do_not_consume_numbers(self):
        """注释行不得占用编号，否则编号与真实行的对应关系会错位。"""
        content = "# 本轮候选\nhttp://1.1.1.1:8888\n# 另一个注释\nhttp://2.2.2.2:8888"
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        self.assertEqual([ep.name for ep in eps], ["CN-01", "CN-02"])

    def test_explicit_numbers_are_preserved(self):
        content = "[CN-07] http://7.7.7.7:8888\n[备选-家宽] http://8.8.8.8:8888"
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        self.assertEqual([ep.name for ep in eps], ["CN-07", "备选-家宽"])

    def test_empty_file_returns_empty(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n# only comments\n")
            path = fh.name
        try:
            self.assertEqual(load_candidate_endpoints(path, prefix="CN"), [])
        finally:
            Path(path).unlink()


class TestProxyCheckMasking(unittest.TestCase):
    def test_error_text_masks_host_port_and_bare_ip(self):
        ep = parse_proxy_line("[CN-01] http://112.65.132.182:3128")
        raw = (
            "Failed to perform, curl: (28) Connection timed out via "
            "http://112.65.132.182:3128 (peer 112.65.132.182)"
        )
        out = sanitize_proxy_error(raw, ep)

        self.assertNotIn("112.65.132.182", out)
        self.assertNotIn("3128", out)
        self.assertIn("112.***.***.182", out)

    def test_masks_before_truncation(self):
        """截断必须发生在脱敏之后，否则被切断的 IP 会绕过正则。"""
        ep = parse_proxy_line("[CN-02] http://9.9.9.9:8888")
        raw = "x" * 195 + " 10.20.30.40:8888"
        out = sanitize_proxy_error(raw, ep, limit=10)

        self.assertEqual(len(out), 10)
        self.assertNotIn("10.20.30.40", out)

    def test_ipv6_exit_is_masked(self):
        ep = parse_proxy_line("[CN-03] http://3.3.3.3:8888")
        out = sanitize_proxy_error("failed via 240e:3b30:2d21:9f0::12", ep)

        self.assertNotIn("240e:3b30:2d21:9f0::12", out)
        self.assertIn("***", out)


class TestProxyCheckSerialization(unittest.TestCase):
    def test_result_dict_is_safe_to_publish(self):
        ep = parse_proxy_line("[CN-04] http://4.4.4.4:8888")
        res = ProxyCheckResult(endpoint=ep, alive=True, latency_ms=812.0)
        res.exit_ip = "4.4.4.4"
        res.ip_geo = "中国 北京"
        res.site_status = {"SMZDM": "HTTP 200 OK"}

        payload = result_to_dict(res)

        self.assertEqual(payload["name"], "CN-04")
        self.assertEqual(payload["exit_ip"], "4.***.***.4")
        self.assertNotIn("8888", str(payload))
        self.assertNotIn("4.4.4.4", str(payload))

    def test_dead_result_error_is_masked(self):
        ep = parse_proxy_line("[CN-05] http://5.5.5.5:8888")
        res = ProxyCheckResult(
            endpoint=ep, alive=False, error_msg="timeout to http://5.5.5.5:8888"
        )
        payload = result_to_dict(res)

        self.assertFalse(payload["alive"])
        self.assertNotIn("5.5.5.5", payload["error"])
        self.assertNotIn("8888", payload["error"])


if __name__ == "__main__":
    unittest.main()