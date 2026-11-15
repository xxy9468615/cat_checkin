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
assert n._extract_accounts('a' * 100000 + '\\n用户 late***1') == '—'
assert n._failed_accounts('', {'fail_lines': ['a' * 100000]})
'''
        subprocess.run([sys.executable, "-c", code], cwd=BASE, check=True, timeout=5)

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
                self.assertEqual(extract.call_args.args[1], output[:notify.NOTIFY_OUTPUT_MAX])
        with patch("alert_levels.detect_unconfigured", return_value="missing") as detect, \
             patch.object(notify, "_post_webhook", return_value=True):
            notify.notify_unconfigured("test", "Test", "glados.py", output, persist=False)
            self.assertEqual(detect.call_args.args[0], output[:notify.NOTIFY_OUTPUT_MAX])


if __name__ == "__main__":
    unittest.main()
