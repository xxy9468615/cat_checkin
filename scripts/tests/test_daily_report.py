"""Regression tests for the legacy report field parser."""
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))

from daily_report import _extract_fields


class RewardExtractionTests(unittest.TestCase):
    def test_reward_formats(self):
        for keyword in ("获得", "今日获得", "签到奖励", "新增", "领取", "奖励", "获取"):
            for separator in ("", " ", ":", "：", " \t：\t ", "\n\u3000"):
                with self.subTest(keyword=keyword, separator=separator):
                    self.assertEqual(
                        _extract_fields(f"{keyword}{separator}1,234.5 积分，结束")["reward"],
                        "1,234.5 积分",
                    )

    def test_skips_invalid_candidate_and_deduplicates(self):
        fields = _extract_fields("奖励 X\n奖励 : 2 积分\n获得 2 积分")
        self.assertEqual(fields["reward"], "2 积分")

    def test_long_remote_failure_completes(self):
        # Isolate the parser so a regression cannot hang the test runner.
        subprocess.run(
            [sys.executable, "-c", """
from daily_report import _extract_fields
for separator in ('', ':', '：'):
    output = '[1/1] 签到失败：奖励' + ' ' * 100_000 + separator + '\\t' * 100_000 + 'X'
    assert 'reward' not in _extract_fields(output)
assert _extract_fields(' ' * 200_000 + '获得 5 积分')['reward'] == '5 积分'
"""],
            cwd=SCRIPTS,
            check=True,
            timeout=10,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
