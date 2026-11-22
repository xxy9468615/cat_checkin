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


def _write_temp(content: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write(content)
        return fh.name


class TestProxyCheckNumbering(unittest.TestCase):
    def test_unnamed_lines_get_stable_sequential_numbers(self):
        path = _write_temp(
            "http://1.1.1.1:8888\nhttp://2.2.2.2:8888\nhttp://3.3.3.3:8888"
        )
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
        path = _write_temp(
            "# 本轮候选\nhttp://1.1.1.1:8888\n# 另一个注释\nhttp://2.2.2.2:8888"
        )
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        self.assertEqual([ep.name for ep in eps], ["CN-01", "CN-02"])

    def test_explicit_numbers_are_preserved(self):
        path = _write_temp("[CN-07] http://7.7.7.7:8888\n[备选-家宽] http://8.8.8.8:8888")
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        self.assertEqual([ep.name for ep in eps], ["CN-07", "备选-家宽"])

    def test_explicit_number_is_not_reused_by_auto_numbering(self):
        """显式 [CN-01] 必须被自动编号避开，否则会出现两个 CN-01。"""
        path = _write_temp("http://1.1.1.1:8888\n[CN-01] http://2.2.2.2:8888")
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        names = [ep.name for ep in eps]
        self.assertEqual(names, ["CN-02", "CN-01"])
        self.assertEqual(len(set(names)), 2)

    def test_explicit_name_with_dot_is_preserved(self):
        """`[HK.01]` 这类显式名称含点，不能被当成自动编号覆盖。"""
        path = _write_temp("[HK.01] http://1.1.1.1:8888")
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        self.assertEqual(eps[0].name, "HK.01")

    def test_unnamed_localhost_still_gets_numbered(self):
        """localhost 不算显式名称，必须进入编号分支（不同端口各自独立编号）。"""
        path = _write_temp("http://localhost:8080\nhttp://localhost:8081")
        try:
            eps = load_candidate_endpoints(path, prefix="CN")
        finally:
            Path(path).unlink()

        self.assertEqual([ep.name for ep in eps], ["CN-01", "CN-02"])

    def test_pii_prefix_is_redacted(self):
        """--name-prefix 会进入摘要与 JSON，邮箱形态前缀必须脱敏。"""
        path = _write_temp("http://1.1.1.1:8888")
        try:
            eps = load_candidate_endpoints(path, prefix="ops@example.com")
        finally:
            Path(path).unlink()

        self.assertNotIn("example.com", eps[0].name)

    def test_empty_file_returns_empty(self):
        path = _write_temp("\n# only comments\n")
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
        """截断必须发生在脱敏之后，否则被切断的 IP 会绕过正则。

        让代理地址正好跨过截断边界：先截断会留下 "20.30.40" 这类残片，
        先脱敏则同一位置已是 "20.***.***.40"，两种顺序的输出可区分。
        """
        ep = parse_proxy_line("[CN-02] http://9.9.9.9:8888")
        raw = "x" * 190 + " 111.222.333.444:8888"
        # 截断点落在 IP 中段：先截断会留下 "111.222.3"（三段，正则不匹配、原样泄漏），
        # 先脱敏则同一位置已是 "111.***.***"。
        out = sanitize_proxy_error(raw, ep, limit=203)

        self.assertEqual(len(out), 203)
        self.assertNotIn("222.333", out)
        self.assertNotIn(":8888", out)
        self.assertIn("111.***.***", out)

    def test_ipv6_exit_is_masked(self):
        ep = parse_proxy_line("[CN-03] http://3.3.3.3:8888")
        out = sanitize_proxy_error("failed via 240e:3b30:2d21:9f0::12", ep)

        self.assertNotIn("240e:3b30:2d21:9f0::12", out)
        self.assertIn("***", out)

    def test_bracketed_ipv6_port_is_masked(self):
        ep = parse_proxy_line("[CN-03] http://3.3.3.3:8888")
        out = sanitize_proxy_error("dial tcp [240e:3b30::12]:8888 failed", ep)

        self.assertNotIn("240e:3b30::12", out)
        self.assertNotIn("8888", out)


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