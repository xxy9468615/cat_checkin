#!/usr/bin/env python3
"""common.sanitize_snippet 失败诊断片段脱敏测试。

背景：must_match 等诊断路径会把服务端响应片段拼进异常消息，经 run_task 输出
进入公开 Actions 日志 / Discord 卡片 / 邮件日报，必须先抹除凭据形态内容。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import common


class TestSanitizeSnippet(unittest.TestCase):
    def test_set_cookie_masked(self):
        raw = 'HTTP/1.1 200 OK\nSet-Cookie: sessionid=abc123def456; Path=/\nServer: nginx'
        out = common.sanitize_snippet(raw)
        self.assertNotIn("abc123def456", out)
        self.assertIn("<masked>", out)
        self.assertIn("Server: nginx", out)

    def test_cookie_header_masked(self):
        out = common.sanitize_snippet("Cookie: token=secret-value-here; uid=1")
        self.assertNotIn("secret-value-here", out)

    def test_bearer_masked(self):
        out = common.sanitize_snippet("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out)
        self.assertIn("Authorization:", out)

    def test_token_keyvalue_masked(self):
        raw = '{"access_token":"aB3dEf7hIj9kLm1Np3qRs5tU","expires_in":7200}'
        out = common.sanitize_snippet(raw)
        self.assertNotIn("aB3dEf7hIj9kLm1Np3qRs5tU", out)
        self.assertIn("expires_in", out)

    def test_long_high_entropy_string_masked(self):
        out = common.sanitize_snippet("ok sig=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 done")
        self.assertNotIn("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", out)

    def test_plain_text_preserved(self):
        raw = "登录失败：用户名或密码错误 (error_code=1001)，请检查账号"
        self.assertEqual(common.sanitize_snippet(raw), raw)

    def test_truncated_to_limit(self):
        out = common.sanitize_snippet("登录失败 重试 " * 60, limit=300)
        self.assertEqual(len(out), 300)

    def test_newlines_flattened(self):
        out = common.sanitize_snippet("line1\nline2\nline3")
        self.assertNotIn("\n", out)

    def test_empty_input(self):
        self.assertEqual(common.sanitize_snippet(""), "")
        self.assertEqual(common.sanitize_snippet(None), "")


class TestMustMatchUsesSanitize(unittest.TestCase):
    def test_failure_message_is_sanitized(self):
        page = '<html>Set-Cookie: sessionid=supersecret123; Path=/</html>'
        with self.assertRaises(RuntimeError) as ctx:
            common.must_match(r'name="formhash" value="(.+?)"', page, "formhash")
        self.assertNotIn("supersecret123", str(ctx.exception))
        self.assertIn("formhash", str(ctx.exception))

    def test_success_path_unchanged(self):
        self.assertEqual(
            common.must_match(r'value="(.+?)"', 'value="abc"', "v"),
            "abc",
        )


if __name__ == "__main__":
    unittest.main()
