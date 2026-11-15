"""Regression coverage for untrusted failure lines in the alert classifier."""
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))

from alert_levels import detect_unconfigured  # noqa: E402


class UnconfiguredSecurityTests(unittest.TestCase):
    def test_keyword_order_and_spelling(self):
        for word in ("凭证", "凭据", "Cookie", "cookie", "Token", "token", "环境变量"):
            with self.subTest(word=word):
                line = f"❌ 未配置：其他信息；未配置：{word}"
                self.assertEqual(detect_unconfigured(line), line)
        for line in ("❌ Token 未配置：其他信息", "❌ 未配置：COOKIE", "⚠️ 未配置：Token"):
            with self.subTest(line=line):
                self.assertIsNone(detect_unconfigured(line))

    def test_full_line_exclusions_and_evidence_limit(self):
        line = "❌ 未配置：" + "其他信息" * 1000 + "Token"
        self.assertEqual(detect_unconfigured(line), line[:119] + "…")
        for exclusion in ("已过期", "失效"):
            with self.subTest(exclusion=exclusion):
                self.assertIsNone(detect_unconfigured(line + exclusion))

    def test_repeated_markers_finish_without_quadratic_scan(self):
        # A subprocess deadline prevents a regressed regex from hanging the suite.
        # The former expression needs minutes on this provider-shaped failure.
        code = '''
from alert_levels import classify
line = "❌ 账号 #1 签到失败: 刷新 Token 失败 [400]: " + "未配置" * 100000
assert classify("alipan.py", False, line)["level"] == "fail"
assert classify("alipan.py", False, line + "凭据")["level"] == "unconfigured"
assert classify("alipan.py", False, line + "凭据已过期")["level"] == "fail"
'''
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=SCRIPTS,
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
