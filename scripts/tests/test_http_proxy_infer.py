#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Http 代理推断开关（infer_proxy）测试。

2026-10-31 评审指认：出口轮换的「直连出网」候选（proxy=""）会被 Http 的任务
代理推断捡回已失败的 TELECOM/CLOUD189 代理——infer_proxy=False 必须走真直连。"""
import unittest
from unittest.mock import patch

from common import Http


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


if __name__ == "__main__":
    unittest.main()
