#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Http 代理推断开关（infer_proxy）测试。

2026-10-31 评审指认：出口轮换的「直连出网」候选（proxy=""）会被 Http 的任务
代理推断捡回已失败的 TELECOM/CLOUD189 代理——infer_proxy=False 必须走真直连。"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import Http  # noqa: E402


class TestHttpProxyInfer(unittest.TestCase):
    """Http(infer_proxy=...) 显式禁用任务代理推断。"""

    def _fake_endpoint(self):
        from proxy_manager import ProxyEndpoint
        return ProxyEndpoint(
            name="fake-node", url="http://127.0.0.1:7890",
            safe_url="http://***:***@127.0.0.1:7890",
            protocol="http", host="127.0.0.1", port=7890,
        )

    def test_infer_enabled_picks_task_proxy(self):
        """默认行为保持不变：task_name 命中任务代理配置时自动选用。"""
        with patch("proxy_manager.get_task_proxy_endpoints",
                   return_value=[self._fake_endpoint()]):
            h = Http(task_name="TELECOM")
        self.assertTrue(h.has_proxy)
        self.assertEqual(h.proxy_endpoint.url, "http://127.0.0.1:7890")

    def test_infer_disabled_forces_direct(self):
        """infer_proxy=False：推断被跳过，直连出网候选不再捡回任务代理。"""
        with patch("proxy_manager.get_task_proxy_endpoints",
                   return_value=[self._fake_endpoint()]) as m_infer:
            h = Http(task_name="TELECOM", proxy="", infer_proxy=False)
        self.assertFalse(h.has_proxy)
        self.assertIsNone(h.proxy_endpoint)
        m_infer.assert_not_called()

    def test_infer_disabled_no_effect_on_explicit_proxy(self):
        """infer_proxy 只关推断：显式传入的 proxy 仍正常生效。"""
        h = Http(task_name="TELECOM", proxy="http://127.0.0.1:7891",
                 infer_proxy=False)
        self.assertTrue(h.has_proxy)
        self.assertEqual(h.proxy_endpoint.url, "http://127.0.0.1:7891")

    def test_direct_mode_shields_env_proxies(self):
        """直连模式标记置位（urllib ProxyHandler({}) + curl 显式空代理的依据），
        显式代理/默认推断模式不置位。"""
        with patch("proxy_manager.get_task_proxy_endpoints",
                   return_value=[self._fake_endpoint()]):
            h_infer = Http(task_name="TELECOM")
        h_direct = Http(task_name="TELECOM", infer_proxy=False)
        h_explicit = Http(task_name="TELECOM", proxy="http://127.0.0.1:7891",
                          infer_proxy=False)
        self.assertFalse(getattr(h_infer, "direct_no_env_proxy", False))
        self.assertTrue(h_direct.direct_no_env_proxy)
        self.assertFalse(h_explicit.direct_no_env_proxy)


if __name__ == "__main__":
    unittest.main()
