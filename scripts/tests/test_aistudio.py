#!/usr/bin/env python3
"""飞桨 AI Studio 免维护凭据归一化单元测试。

背景（2026-09-19 抓包逆向结论）：
- BDUSS 是唯一长效凭据，单独即可通过 /point/* 与 /studio/* 全部端点。
- ai-studio-ticket / BDUSS_BFESS 等为服务端按需自动铸造的短命会话票，
  携带过期值无害但无益；/studio/resource/* 另需 x-studio-token（来自
  /overview 的 bdToken，脚本运行时自动提取）。

覆盖范围：
1. 完整门户 Cookie（含短命票与埋点字段）归一化为 BDUSS-only。
2. BDUSS-only 输入恒等（剥离数为 0）。
3. 裸 BDUSS 值（无字段名）直接识别。
4. BDUSS_BFESS 不被误判为 BDUSS。
5. 无 BDUSS 的门户 Cookie 返回空（回退原串走自定义 Cookie 路径）。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from aistudio import _extract_bduss


class ExtractBdussTest(unittest.TestCase):
    FULL_COOKIE = (
        "BAIDUID=7643DC72:FG=1; BIDUPSID=7643DC72; PSTM=1789021402; "
        "BDUSS_BFESS=bfess_value_should_not_match; "
        "BDUSS=cwTWpVSVV5Y2NNalRiaFB4; "
        "ai-studio-ticket=DCA7905B3EC24FCCAFCA; lang=zh"
    )

    def test_full_cookie_normalized_to_bduss_only(self):
        val, stripped = _extract_bduss(self.FULL_COOKIE)
        self.assertEqual(val, "cwTWpVSVV5Y2NNalRiaFB4")
        # 除 BDUSS 外全部剥离（含 BDUSS_BFESS 与 ticket）
        self.assertEqual(stripped, 6)

    def test_bduss_only_is_identity(self):
        val, stripped = _extract_bduss("BDUSS=cwTWpVSVV5Y2NNalRiaFB4")
        self.assertEqual(val, "cwTWpVSVV5Y2NNalRiaFB4")
        self.assertEqual(stripped, 0)

    def test_bare_bduss_value(self):
        bare = "cwTWpVSVV5Y2NNalRiaFB4Q2ZKR2JZT0tKTm9xYjF-SlpzaT"
        val, stripped = _extract_bduss(bare)
        self.assertEqual(val, bare)
        self.assertEqual(stripped, 0)

    def test_bduss_bfess_not_mistaken_for_bduss(self):
        val, _ = _extract_bduss("BDUSS_BFESS=bfess_only; lang=zh")
        self.assertEqual(val, "")

    def test_portal_cookie_without_bduss(self):
        val, stripped = _extract_bduss("__cas__st__533=NLI; BAIDUID=3058EC:FG=1")
        self.assertEqual(val, "")
        self.assertEqual(stripped, 0)

    def test_first_bduss_wins_on_duplicates(self):
        val, stripped = _extract_bduss("BDUSS=first_val; BDUSS=second_val; lang=zh")
        self.assertEqual(val, "first_val")
        self.assertEqual(stripped, 2)


if __name__ == "__main__":
    unittest.main()
