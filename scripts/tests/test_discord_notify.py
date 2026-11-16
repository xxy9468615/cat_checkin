"""Account extraction compatibility and hostile-output regression tests."""
import itertools
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
import discord_notify as notify
import proxy_manager


class AccountExtractionTests(unittest.TestCase):
    def test_token_compatibility(self):
        # Preserve the previous grammar, including @ before a mask and punctuation.
        previous = re.compile(r"[A-Za-z0-9_+\-.@]*[A-Za-z0-9_+\-.]\*{2,}[A-Za-z0-9_+\-.@]*")
        for size in range(7):
            for chars in itertools.product("a@.* ", repeat=size):
                line = "".join(chars)
                match = previous.search(line)
                self.assertEqual(notify._first_masked_token(line),
                                 match.group(0) if match else "", line)

    def test_account_selection(self):
        output = "fallback z***9\n用户 a***1 UID:1***6\n账号 a***1\nemail b***2\nrefresh c***3"
        self.assertEqual(notify._extract_accounts(output), "a***1 等 2 个账号")
        self.assertEqual(notify._extract_accounts("refresh a***1"), "—")
        self.assertEqual(notify._extract_accounts("fallback .a***1-"), "a***1")
        self.assertEqual(notify._extract_accounts("a@*** x***2"), "x***2")

    def test_failed_account_paths(self):
        self.assertEqual(notify._failed_accounts("", {"fail_lines": ["账号 a***1 失败"]}), "a***1")
        self.assertEqual(notify._failed_accounts("❌ [2/3] b***2 失败"), "#2 b***2")

    def test_hostile_runs_finish(self):
        # A separate process bounds failures even if quadratic matching returns.
        code = '''import discord_notify as n
for text in ('a' * 100000, 'a@** ' * 20000, '*' * 100000):
    assert n._first_masked_token(text) == ''
assert n._first_masked_token('a' * 100000 + '**') == 'a' * 100000 + '**'
assert n._extract_accounts('a' * 100000 + '\\n用户 late***1') == 'late***1'
assert n._failed_accounts('', {'fail_lines': ['a' * 100000]})
'''
        # 不重推一次：_extract_accounts 现在保留尾部预算，超长前缀后的账号行
        # 正是要救回的证据（F2 修复），原断言的「必然读不到」语义已反转。
        subprocess.run([sys.executable, "-c", code], cwd=BASE, check=True, timeout=20)

    def test_limit_before_notification_parsing(self):
        output = "a" * notify.NOTIFY_OUTPUT_MAX + "\n用户 late***1"
        for entry, kwargs in (
            (notify.notify_task_result, {"ok": False}),
            (notify.notify_circuit_breaker, {}),
        ):
            with self.subTest(entry=entry.__name__), \
                 patch("report_fields.extract_for", return_value={}) as extract, \
                 patch.object(notify, "_post_webhook", return_value=True):
                self.assertTrue(entry(task_id="test", name="Test", script="glados.py",
                                      output=output, persist=False, **kwargs))
                self.assertEqual(extract.call_args.args[1],
                                 notify._bounded_output(output))
        with patch("alert_levels.detect_unconfigured", return_value="missing") as detect, \
             patch.object(notify, "_post_webhook", return_value=True):
            notify.notify_unconfigured("test", "Test", "glados.py", output, persist=False)
            self.assertEqual(detect.call_args.args[0], notify._bounded_output(output))

    def test_truncation_keeps_tail_failure_evidence(self):
        # 头部截断会把末尾的失败证据整体丢掉（CodeRabbit F2）。
        tail = "❌ [2/3] b***2 打卡失败: HTTP 401\n⚠️ 凭据剩余 1 天"
        output = "a" * (notify.NOTIFY_OUTPUT_MAX + 4096) + "\n" + tail
        bounded = notify._bounded_output(output)
        self.assertLessEqual(len(bounded), notify.NOTIFY_OUTPUT_MAX)
        for line in tail.splitlines():
            self.assertIn(line, bounded)
        self.assertIn("#2 b***2", notify._failed_accounts(bounded))
        items = notify._failure_items(bounded, max_items=6)
        self.assertTrue(items)
        self.assertEqual(items[0], ("#2", "b***2 打卡失败: HTTP 401"))
        self.assertIn("凭据剩余 1 天", items[1][1])

    def test_truncation_survives_oversized_last_line(self):
        # 末行本身超尾预算时，降级保留该行尾部并继续向前扫描，
        # 否则更早的失败行会被整段丢掉（F2 的降级路径）。
        long_line = "x" * (notify.NOTIFY_TAIL_KEEP + 500)
        fail = "❌ [2/3] b***2 打卡失败: HTTP 401"
        output = "a" * notify.NOTIFY_OUTPUT_MAX + "\n" + fail + "\n" + long_line
        bounded = notify._bounded_output(output)
        self.assertLessEqual(len(bounded), notify.NOTIFY_OUTPUT_MAX + 1)
        self.assertIn(fail, bounded)
        self.assertIn("#2 b***2", notify._failed_accounts(bounded))

    def test_truncation_does_not_duplicate_head_lines_into_tail(self):
        # 头部已保留的行必须被排除在尾段扫描之外，否则它们会再出现一次。
        # report_fields 的资产解析器（ex_glados）按次追加资产，重复行会让
        # 通知显示两份相同积分（CodeRabbit F3，2026-11-15）。
        head = "📧 账号: a***1\n💰 当前积分: 100 积分\n"
        output = head + "x" * 70000
        bounded = notify._bounded_output(output)
        self.assertLessEqual(len(bounded), notify.NOTIFY_OUTPUT_MAX + 1)
        self.assertEqual(bounded.count("💰 当前积分: 100 积分"), 1)
        self.assertEqual(bounded.count("📧 账号: a***1"), 1)

    def test_failure_lines_are_redacted_before_display(self):
        # 尾部保留的失败行若含裸邮箱，会经通知卡片公开（CodeRabbit round-3）。
        tail = "❌ [2/3] alice@example.com 失败 HTTP 401"
        output = "a" * (notify.NOTIFY_OUTPUT_MAX + 4096) + "\n" + tail
        bounded = notify._bounded_output(output)
        self.assertIn("alice@example.com", bounded)  # 截断层不动内容，脱敏在展示层
        items = notify._failure_items(bounded, max_items=3)
        self.assertTrue(items)
        text = items[0][1]
        self.assertNotIn("alice@example.com", text)
        self.assertIn("***lice@***", text)
        # 结构化 fail_lines 路径同样脱敏
        label = notify._failed_accounts("", {"fail_lines": [tail]})
        self.assertNotIn("alice@example.com", label)

    def test_redact_before_truncate_leaves_no_split_phone_fragment(self):
        # 反序（先截断后脱敏）会把超长条目切成「从手机号中间开始」的片段，
        # 例如残留 `8-0013-8000`：redact_pii 无法识别这段数字，标签随即露出
        # 原始数字。正序下完整号码先被遮盖，截断只会切到掩码串，无残留。
        raw = "❌ [2/3] " + "x" * 200 + " 138-0013-8000 失败"
        text = notify._failure_items(raw, max_items=3)[0][1]
        self.assertNotIn("138", text)
        self.assertNotIn("0013", text)
        # 号码的任一分组都不得作为残留片段出现（头部截断切到的是掩码前的噪音，
        # 号码本身落在 FAIL_TEXT_MAX 窗口之外，只验证「无原始数字残留」）
        self.assertNotRegex(text, r"\d{4,}")
        # 号码落在展示窗口内时必须完整遮盖，绝不保留首位数字
        near = "❌ [2/3] x 138-0013-8000 失败"
        self.assertIn("*******8000", notify._failure_items(near, max_items=3)[0][1])

    def test_fail_lines_long_entry_is_redacted_then_bounded(self):
        # fail_lines 路径同样先脱敏再截断；长条目不残留可识别的号码片段
        raw = "❌ [2/3] " + "y" * (notify.FAIL_TEXT_MAX + 50) + " 13800138000 失败"
        label = notify._failed_accounts("", {"fail_lines": [raw]})
        self.assertNotIn("13800138000", label)
        self.assertNotIn("138", label)
        self.assertNotIn("0013", label)

    def test_failure_line_sanitizes_credentials(self):
        # token/Cookie 形态内容同样不得出现在通知卡片上
        raw = "❌ [2/3] a***1 失败 Authorization: Bearer abcdef1234567890abcdef"
        text = notify._failure_items(raw, max_items=3)[0][1]
        self.assertNotIn("abcdef1234567890abcdef", text)
        self.assertIn("<masked>", text)  # 凭据被替换为占位符，而非保留原值

    def test_idn_email_and_separated_phone_labels_are_masked(self):
        # 中文域名邮箱与带分隔符的手机号此前不匹配，会明文进入日志/日报。
        url = "http://192.0.2.1:8080"
        cases = (
            ("alice@example.中国", "***lice@***"),
            ("138-0013-8000", "*******8000"),
            ("138 0013 8000", "*******8000"),
        )
        for label, expected in cases:
            for text in (f"[{label}] {url}", f"{url}#{label}"):
                with self.subTest(text=text):
                    ep = proxy_manager.parse_proxy_line(text)
                    self.assertEqual(ep.name, expected)
                    self.assertEqual(ep.display_name, f"【{expected}】")
                    self.assertNotIn(label, str(ep.to_dict()))

    def test_bounded_output_shortcuts_short_input(self):
        self.assertEqual(notify._bounded_output(""), "")
        self.assertEqual(notify._bounded_output("a\nb"), "a\nb")
        self.assertEqual(notify._bounded_output(None), "")


if __name__ == "__main__":
    unittest.main()
