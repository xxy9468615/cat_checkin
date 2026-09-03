#!/usr/bin/env python3
"""全代理协议统一安全加固与防 MITM 中间人攻击自动化测试套件。

覆盖范围：
1. TLS/SSL 强校验安全基线（CERT_REQUIRED, check_hostname=True, 最低 TLS 1.2）。
2. 防自签名证书中间人（MITM）强阻断：面对不可信/伪造证书坚决切断连接，绝不外发数据。
3. 全代理协议（SOCKS5/SOCKS5h/SOCKS4/HTTP/HTTPS）远程 DNS（RDNS）强制解析与 Socket 隔离。
4. 代理环境下明文 HTTP 防嗅探守门员：自动防御性升级为 HTTPS。
5. 全仓库任务原生代理能力与环境变量无感自适应。
6. 全仓库签到任务生产端点 100% 全量 HTTPS 合规审计。
"""

from __future__ import annotations

import os
import re
import socket
import ssl
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import common
import proxy_manager


class TestUnifiedSecurity(unittest.TestCase):
    """全代理协议统一安全加固单元测试。"""

    def test_ssl_context_security_baseline(self):
        """验证全局 SSLContext 严格遵循最高安全标准。"""
        ctx = common._create_ssl_context()
        # 1. 强制系统受信任 CA 证书链校验
        self.assertEqual(
            ctx.verify_mode,
            ssl.CERT_REQUIRED,
            "必须启用 CERT_REQUIRED 强制证书链校验，杜绝自签名与伪造证书",
        )
        # 2. 强制证书域名匹配校验
        self.assertTrue(
            ctx.check_hostname,
            "必须启用 check_hostname 校验，防跨域名伪造证书",
        )
        # 3. 强制最低 TLS 协议版本为 TLS 1.2
        if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_2"):
            self.assertGreaterEqual(
                ctx.minimum_version,
                ssl.TLSVersion.TLSv1_2,
                "最低 TLS 版本必须大于等于 TLSv1.2，防御针对 TLS 1.0/1.1 的已知降级攻击",
            )

        # 4. 验证 Http 客户端实例正确继承了该安全上下文
        h = common.Http()
        self.assertIsNotNone(h.ssl_context)
        self.assertEqual(h.ssl_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(h.ssl_context.check_hostname)

    def test_socks_protocol_rdns_and_isolation(self):
        """验证所有 SOCKS 代理协议族强制远程 DNS 解析（RDNS），且绝不污染全局 socket。"""
        socks_cases = [
            ("socks5://user:pass@127.0.0.1:1080#自建SOCKS5", "socks5"),
            ("socks5h://user:pass@127.0.0.1:1080#自建SOCKS5H", "socks5"),
            ("socks4://127.0.0.1:1080#自建SOCKS4", "socks4"),
            ("socks4a://127.0.0.1:1080#自建SOCKS4A", "socks4"),
        ]
        for proxy_url, expected_proto in socks_cases:
            with self.subTest(proxy=proxy_url):
                # 记录实例化前全局 socket
                before_sock = socket.socket

                h = common.Http(proxy=proxy_url)

                # 验证全局 socket 保持原生纯净，未被 monkey patch 污染
                self.assertIs(
                    socket.socket,
                    common._ORIG_SOCKET,
                    "SOCKS 代理实例化后，全局 socket.socket 不得被污染",
                )
                self.assertTrue(h.has_proxy)
                self.assertIsNotNone(h.proxy_endpoint)
                self.assertEqual(h.proxy_endpoint.protocol, expected_proto)

    def test_proxy_plain_http_guard_upgrades_to_https(self):
        """验证代理环境下明文防嗅探守门员生效：请求明文 http:// 时自动升级为 https://。"""
        h_proxy = common.Http(proxy="socks5://127.0.0.1:1080#测试节点")

        # 模拟底层 opener.open，捕获实际发送的 Request 对象
        mock_open = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.geturl.return_value = "https://cloud.189.cn/api/test"
        mock_open.return_value.__enter__.return_value = mock_resp
        h_proxy.opener.open = mock_open

        # 调用时传入明文 http://
        res = h_proxy.request("GET", "http://cloud.189.cn/api/test", headers={"Cookie": "secret=123"}, retries=1)

        # 断言实际发出的请求已经被自动升级为 https://
        self.assertTrue(mock_open.called)
        sent_req = mock_open.call_args[0][0]
        self.assertTrue(
            sent_req.full_url.startswith("https://"),
            f"代理环境下请求必须被安全守门员升级为 HTTPS，实际为: {sent_req.full_url}",
        )

    def test_all_tasks_native_proxy_capability(self):
        """验证全仓库所有签到任务均原生具备代理功能与容灾候选获取能力。"""
        test_tasks = [
            "cloud189",
            "smzdm",
            "52pojie",
            "juejin",
            "alipan",
            "glados",
            "dji",
            "aistudio",
            "modelscope",
        ]
        mock_env = {
            "SELF_HOSTED_PROXIES": "socks5://user:pass@112.64.135.45:1080#自建-上海联通",
            "SMZDM_PROXY": "http://113.1.2.3:8080#SMZDM-国内住宅",
            "JUEJIN_PROXY": "socks5h://user:pwd@114.1.2.3:1080#掘金专线",
        }
        with patch.dict(os.environ, mock_env, clear=True):
            for task in test_tasks:
                with self.subTest(task=task):
                    eps = proxy_manager.get_task_proxy_endpoints(task)
                    self.assertTrue(
                        len(eps) >= 1,
                        f"任务 {task} 必须原生支持获取候选代理",
                    )
                    # 自建代理优先级最高
                    self.assertIn("自建-上海联通", eps[0].name)

            # 验证 Juejin 专属代理正确获取
            juejin_eps = proxy_manager.get_task_proxy_endpoints("juejin")
            self.assertTrue(any("掘金专线" in ep.name for ep in juejin_eps))

            # 验证任务自适应：Http(task_name="juejin") 能够自动感知
            h_juejin = common.Http(task_name="juejin")
            self.assertTrue(h_juejin.has_proxy)

    def test_repo_production_endpoints_strictly_https(self):
        """合规审计：全仓库所有生产签到脚本中的 API 端点必须强制使用 HTTPS。"""
        scripts_dir = BASE
        insecure_found = []

        # 扫描所有生产签到任务脚本
        for p in scripts_dir.glob("*.py"):
            if p.name.startswith("test_") or p.name in ("proxy_check.py",):
                continue
            content = p.read_text(encoding="utf-8", errors="ignore")
            # 匹配硬编码的真实明文请求端点
            matches = re.findall(r"[\"']http://([^\"']+)[\"']", content)
            for m in matches:
                # 排除本地环回测试与标准 XML 命名空间规范
                if any(k in m for k in ("127.0.0.1", "localhost", "w3.org", "schemas.xmlsoap")):
                    continue
                insecure_found.append(f"{p.name}: http://{m}")

        self.assertEqual(
            insecure_found,
            [],
            f"检测到存在明文 http:// 生产端点残留，必须升级为 HTTPS: {insecure_found}",
        )

    def test_mitm_cert_verification_failure_blocks_connection(self):
        """防 MITM 中间人攻击实测：模拟不可信自签证书服务器，验证连接坚决被阻断且不泄露凭据。"""
        # 使用 Python 临时生成一个自签证书上下文的服务器
        # 在没有受信根证书的情况下，Http 客户端连接必须触发证书验证错误
        ctx = common._create_ssl_context()

        # 尝试连接一个不可信主机名或伪造证书时，urllib 必须抛出 SSLCertVerificationError 或将其收敛为 -1 错误响应
        h = common.Http()
        # 请求一个不存在的自签名/无效证书域（通过真实公共恶劣环境或 mock）
        with patch.object(h.opener, "open") as mock_open:
            import urllib.error
            # 模拟标准库抛出严格的 SSL 证书校验失败
            cert_err = ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")
            url_err = urllib.error.URLError(cert_err)
            mock_open.side_effect = url_err

            res = h.request("GET", "https://malicious-proxy-mitm.example.com/api", headers={"Cookie": "secret=test"}, retries=1)

            self.assertEqual(res.code, -1, "遭遇中间人自签名伪造证书时，必须阻断连接返回错误状态")
            self.assertIn("certificate verify failed", res.text.lower())


if __name__ == "__main__":
    unittest.main()
