#!/usr/bin/env python3
"""腾讯 IMA 签到与刷新令牌换票单元测试。

测试覆盖：
1. x-ima-bkn djb2 签名算法（短串手工向量 + 长串双公式交叉验证，JS 32 位回绕语义）
2. x-ima-cookie 整串解析与规范化重建（默认字段补齐、额外字段保留）
3. refresh 换票成功/失败与响应中过期时间防御性提取（秒/毫秒/垃圾值）
4. 每日签到状态机（可领取/已签到幂等/满签奖励按服务端 status 驱动领取）
5. 空 body 403 限流归一化（code=-1 不打断账号循环）
6. 双层持久化字段（refreshToken 跟随、凭据指纹、有效期证据）
7. report_fields 中 ex_ima 的报告提取逻辑验证

全部凭据均为合成 Mock，不含任何真实 token / UID。
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import ima
from report_fields import extract_for


def _synthetic_cookie() -> str:
    """构造合成 x-ima-cookie（全部字段均为 Mock 值，不指向任何真实账号）。"""
    return (
        "PLATFORM=H5; CLIENT-TYPE=256021; IMA-GUID=1111111111111111; "
        "IMA-Q36=synthetic_q36_hash; "
        "IMA-UID=abcdef0123456789; IMA-TOKEN=SYNTHETIC_LEAF_TOKEN_VALUE; "
        "IMA-REFRESH-TOKEN=SYNTHETIC_REFRESH_TOKEN_VALUE; UID-TYPE=2"
    )


def _activity_payload(today_status: int, bonus_status: int = 4) -> dict:
    """构造 get_activity_info 合成响应（周一~周日 7 格 + 满签奖励格）。"""
    infos = [
        {"button": "已领取" if today_status == 2 else "待解锁", "reward": "50算力", "status": today_status, "top": "今日"},
        {"button": "待解锁", "reward": "50算力", "status": 4, "top": "周二"},
        {"button": "待解锁", "reward": "50算力", "status": 4, "top": "周三"},
        {"button": "待解锁", "reward": "50算力", "status": 4, "top": "周四"},
        {"button": "待解锁", "reward": "50算力", "status": 4, "top": "周五"},
        {"button": "待解锁", "reward": "50算力", "status": 4, "top": "周六"},
        {"button": "待解锁", "reward": "50算力", "status": 4, "top": "周日"},
        {"button": "连续7天签到解锁", "reward": "额外随机奖励", "status": bonus_status, "top": "满签奖励"},
    ]
    return {"checkin_days": 1, "code": 0, "infos": infos, "msg": "ok", "total_reward_points": 50}


def _mock_response(payload: dict, code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.code = code
    resp.text = json.dumps(payload)
    return resp


def _mock_http(responses: dict) -> MagicMock:
    """构造按 URL 前缀路由的 Mock Http 实例。"""
    http = MagicMock()
    http.request.side_effect = lambda method, url, **kw: _mock_response(
        next((p for prefix, p in responses.items() if url.startswith(prefix)), {"code": -1, "msg": "unrouted"})
    )
    return http


class TestImaBkn(unittest.TestCase):
    def test_short_vector_hand_computed(self):
        # 手工推演：e0=5381; 'a'→177670; 'b'→5863208; 'c'→193485963（均未越过 2^31）
        self.assertEqual(ima.ima_bkn("abc"), 193485963)

    def test_long_token_int32_wraparound_semantics(self):
        # 长串强制 32 位回绕：JS 浮点累加语义与「逐次取 31 位掩码」独立公式必须逐位一致
        # （后者已对 2026-11-01 HAR 真实令牌独立验证过，两者等价性有实证背书）
        long_token = "xY3z+/=" * 40
        alt = 5381
        for ch in long_token:
            alt = (alt + ((alt << 5) & 0xFFFFFFFF) + ord(ch)) & 0x7FFFFFFF
        self.assertEqual(ima.ima_bkn(long_token), alt)

    def test_bkn_is_ten_digit_int(self):
        v = ima.ima_bkn("another_synthetic_token")
        self.assertIsInstance(v, int)
        self.assertGreaterEqual(v, 0)
        self.assertLessEqual(v, 0x7FFFFFFF)


class TestImaCookie(unittest.TestCase):
    def test_parse_and_rebuild_roundtrip(self):
        raw = _synthetic_cookie()
        items = ima.parse_ima_cookie(raw)
        self.assertEqual(items.get("IMA-UID"), "abcdef0123456789")
        self.assertEqual(items.get("IMA-REFRESH-TOKEN"), "SYNTHETIC_REFRESH_TOKEN_VALUE")

        rebuilt = ima.build_ima_cookie(items, "NEW_LEAF_TOKEN")
        self.assertIn("IMA-UID=abcdef0123456789", rebuilt)
        self.assertIn("IMA-TOKEN=NEW_LEAF_TOKEN", rebuilt)  # 叶令牌被现签值覆盖
        self.assertIn("IMA-REFRESH-TOKEN=SYNTHETIC_REFRESH_TOKEN_VALUE", rebuilt)
        self.assertIn("IMA-Q36=synthetic_q36_hash", rebuilt)  # 附加字段保留
        self.assertIn("PLATFORM=H5", rebuilt)
        self.assertIn("UID-TYPE=2", rebuilt)

    def test_rebuild_fills_defaults(self):
        rebuilt = ima.build_ima_cookie({}, "only_token")
        self.assertIn("IMA-TOKEN=only_token", rebuilt)
        self.assertIn("UID-TYPE=2", rebuilt)
        self.assertIn("PLATFORM=H5", rebuilt)

    def test_parse_tolerates_garbage(self):
        self.assertEqual(ima.parse_ima_cookie(""), {})
        self.assertEqual(ima.parse_ima_cookie("no-equals-sign;;"), {})


class TestRefreshExpiry(unittest.TestCase):
    def test_seconds_and_milliseconds(self):
        now = int(time.time())
        self.assertEqual(ima._extract_refresh_expiry({"expireTime": now + 86400}), now + 86400)
        self.assertEqual(ima._extract_refresh_expiry({"expiredTime": (now + 86400) * 1000}), now + 86400)
        # 过去时间不采纳
        self.assertEqual(ima._extract_refresh_expiry({"expireTime": now - 86400}), 0)

    def test_garbage_and_absent(self):
        self.assertEqual(ima._extract_refresh_expiry({}), 0)
        self.assertEqual(ima._extract_refresh_expiry({"expireTime": "not-a-number"}), 0)


class TestPostJsonNormalization(unittest.TestCase):
    def test_empty_body_403_normalized_as_rate_limit(self):
        http = MagicMock()
        resp = MagicMock()
        resp.code = 403
        resp.text = ""
        http.request.return_value = resp
        data = ima._post_json(http, "https://ima.qq.com/x", {}, {})
        self.assertEqual(data["code"], -1)
        self.assertIn("403", data["msg"])

    def test_non_json_body_normalized(self):
        http = MagicMock()
        resp = MagicMock()
        resp.code = 200
        resp.text = "<html>blocked</html>"
        http.request.return_value = resp
        data = ima._post_json(http, "https://ima.qq.com/x", {}, {})
        self.assertEqual(data["code"], -1)

    def test_network_exception_normalized(self):
        http = MagicMock()
        http.request.side_effect = OSError("conn reset")
        data = ima._post_json(http, "https://ima.qq.com/x", {}, {})
        self.assertEqual(data["code"], -1)
        self.assertIn("请求异常", data["msg"])


class TestMintAccessToken(unittest.TestCase):
    def test_mint_success(self):
        http = _mock_http({
            ima.REFRESH_URL: {"code": 0, "token": "NEW_LEAF", "msg": "ok"},
        })
        ok, token, msg, exp, rotated = ima.mint_access_token(http, "uid123", "rt456", "guid789")
        self.assertTrue(ok)
        self.assertEqual(token, "NEW_LEAF")
        self.assertEqual(rotated, "")  # 未轮换
        # 设备 Cookie 只带 IMA-GUID + PLATFORM，不携带旧叶令牌
        sent_headers = http.request.call_args[1]["headers"]
        self.assertIn("IMA-GUID=guid789", sent_headers["x-ima-cookie"])
        self.assertNotIn("IMA-TOKEN", sent_headers["x-ima-cookie"])
        self.assertNotIn("x-ima-bkn", sent_headers)

    def test_mint_rotated_refresh_token_returned(self):
        http = _mock_http({
            ima.REFRESH_URL: {"code": 0, "token": "NEW_LEAF", "refreshToken": "ROTATED_RT"},
        })
        ok, token, _, _, rotated = ima.mint_access_token(http, "uid123", "rt456", "guid789")
        self.assertTrue(ok)
        self.assertEqual(rotated, "ROTATED_RT")  # 轮换值来自 refresh 响应（非活动信息响应）

    def test_mint_rejected(self):
        http = _mock_http({
            ima.REFRESH_URL: {"code": 4, "msg": "refresh token invalid"},
        })
        ok, token, msg, _, rotated = ima.mint_access_token(http, "uid123", "rt456", "guid789")
        self.assertFalse(ok)
        self.assertEqual(token, "")
        self.assertEqual(rotated, "")
        self.assertIn("invalid", msg)


class TestRunAccount(unittest.TestCase):
    def _run(self, activity: dict, checkin_resps: list, state: dict = None):
        """checkin_resps 按 check_in 调用顺序消费（第 1 次日签、第 2 次满签试领）。"""
        queue = list(checkin_resps)

        with patch.object(ima, "save_kv_state") as mock_save, \
             patch.object(ima, "load_kv_state", return_value=state or {}), \
             patch.object(ima, "Http") as mock_http_cls:
            http = MagicMock()
            refresh = _mock_response({"code": 0, "token": "NEW_LEAF", "msg": "ok"})

            def route(method, url, **kw):
                if url.startswith(ima.REFRESH_URL):
                    return refresh
                if url.startswith(ima.ACTIVITY_INFO_URL):
                    return _mock_response(activity)
                if url.startswith(ima.CHECK_IN_URL):
                    return _mock_response(queue.pop(0) if queue else {"code": -1, "msg": "no stub"})
                return _mock_response({"code": -1, "msg": "unrouted"})

            http.request.side_effect = route
            mock_http_cls.return_value = http
            ok, desc = ima._run_account(_synthetic_cookie(), 1, 1)
            return ok, desc, mock_save

    def test_signable_today_claims_daily(self):
        ok, desc, mock_save = self._run(
            _activity_payload(today_status=3, bonus_status=4),
            [{"code": 0, "reward_received": 50, "msg": "ok"}],
        )
        self.assertTrue(ok)
        self.assertIn("签到成功", desc)
        saved = mock_save.call_args[0][2]
        self.assertEqual(saved.get("refresh_token"), "SYNTHETIC_REFRESH_TOKEN_VALUE")
        self.assertEqual(saved.get("uid"), "abcdef0123456789")
        self.assertTrue(saved.get("env_hash"))
        self.assertTrue(saved.get("ok_last_date"))  # mark_ok 成功日入账

    def test_already_signed_idempotent(self):
        ok, desc, _ = self._run(
            _activity_payload(today_status=2),
            [{"code": 1002, "msg": "already checked in"}],
        )
        self.assertTrue(ok)
        self.assertIn("今日已签到", desc)

    def test_weekly_bonus_claimed_when_available(self):
        ok, desc, _ = self._run(
            _activity_payload(today_status=3, bonus_status=3),
            [
                {"code": 0, "reward_received": 50, "msg": "ok"},
                {"code": 0, "reward_received": 88, "msg": "ok"},
            ],
        )
        self.assertTrue(ok)
        self.assertIn("满签奖励", desc)

    def test_weekly_bonus_not_full_week_tolerated(self):
        ok, desc, _ = self._run(
            _activity_payload(today_status=3, bonus_status=3),
            [
                {"code": 0, "reward_received": 50, "msg": "ok"},
                {"code": 1001, "msg": "week not fully claimed"},
            ],
        )
        self.assertTrue(ok)  # 未满签是正常业务态，不影响日签收益
        self.assertIn("签到成功", desc)

    def test_daily_rejected_by_1001_not_misread_as_idempotent(self):
        # 回归位：日签若真被 1001（含 "claimed" 文案）拒绝，绝不能被英文启发式吞成幂等成功
        ok, desc, _ = self._run(
            _activity_payload(today_status=3, bonus_status=4),
            [{"code": 1001, "msg": "week not fully claimed"}],
        )
        self.assertFalse(ok)
        self.assertIn("每日签到被拒", desc)

    def test_unknown_idempotent_text_without_code_fails(self):
        # 回归位：文案说"已签"但业务码非 1002 —— 协议异常必须如实判失败（防假成功）
        ok, desc, _ = self._run(
            _activity_payload(today_status=3, bonus_status=4),
            [{"code": 7, "msg": "already signed today"}],
        )
        self.assertFalse(ok)
        self.assertIn("每日签到被拒", desc)

    def test_unexpected_today_status_fails(self):
        # 「今日」格出现已过期/未解锁等协议外状态 → 判失败交熔断，绝不假成功
        ok, desc, _ = self._run(
            _activity_payload(today_status=1, bonus_status=4),
            [],
        )
        self.assertFalse(ok)
        self.assertIn("今日格状态异常", desc)
        self.assertIn("已过期", desc)

    def test_refetch_failure_keeps_pre_sign_snapshot(self):
        # 回归位：复核重拉失败必须沿用签到前快照（满签判定 + 连签统计都来自快照）
        ok_info = _activity_payload(today_status=3, bonus_status=3)
        with patch.object(ima, "save_kv_state") as mock_save, \
             patch.object(ima, "load_kv_state", return_value={}), \
             patch.object(ima, "Http") as mock_http_cls:
            http = MagicMock()
            info_calls = {"n": 0}

            def route(method, url, **kw):
                if url.startswith(ima.REFRESH_URL):
                    return _mock_response({"code": 0, "token": "NEW_LEAF", "msg": "ok"})
                if url.startswith(ima.ACTIVITY_INFO_URL):
                    info_calls["n"] += 1
                    if info_calls["n"] == 1:
                        return _mock_response(ok_info)
                    return _mock_response({"code": -1, "msg": "HTTP 403 空响应（可能被限流，稍后重试）"})
                if url.startswith(ima.CHECK_IN_URL):
                    return _mock_response({"code": 0, "reward_received": 50, "msg": "ok"})
                return _mock_response({"code": -1, "msg": "unrouted"})

            http.request.side_effect = route
            mock_http_cls.return_value = http
            ok, desc = ima._run_account(_synthetic_cookie(), 1, 1)
        self.assertTrue(ok)
        # 快照里满签格 status=3 → 试领发生（check_in 被调用两次：日签+满签）
        self.assertIn("签到成功", desc)
        self.assertIn("满签奖励", desc)
        # 连签统计来自快照而非错误响应
        self.assertIn("本周连签 1 天", desc)

    def test_server_rotated_refresh_token_persisted(self):
        with patch.object(ima, "save_kv_state") as mock_save, \
             patch.object(ima, "load_kv_state", return_value={}), \
             patch.object(ima, "Http") as mock_http_cls:
            http = _mock_http({
                ima.REFRESH_URL: {"code": 0, "token": "NEW_LEAF", "refreshToken": "ROTATED_RT"},
                ima.ACTIVITY_INFO_URL: _activity_payload(today_status=2, bonus_status=4),
            })
            mock_http_cls.return_value = http
            ok, desc = ima._run_account(_synthetic_cookie(), 1, 1)
        self.assertTrue(ok)
        saved = mock_save.call_args[0][2]
        self.assertEqual(saved.get("refresh_token"), "ROTATED_RT")

    def test_refresh_rejected_fails(self):
        with patch.object(ima, "save_kv_state") as mock_save, \
             patch.object(ima, "load_kv_state", return_value={}), \
             patch.object(ima, "Http") as mock_http_cls:
            http = _mock_http({
                ima.REFRESH_URL: {"code": 4, "msg": "token invalid"},
            })
            mock_http_cls.return_value = http
            ok, desc = ima._run_account(_synthetic_cookie(), 1, 1)
        self.assertFalse(ok)
        self.assertIn("换票失败", desc)
        self.assertIn("重新抓包", desc)
        self.assertFalse(mock_save.called)

    def test_missing_credential_fails_fast(self):
        ok, desc = ima._run_account("IMA-UID=only_uid", 1, 1)
        self.assertFalse(ok)
        self.assertIn("缺少登录凭据", desc)

    def test_activity_structure_changed_fails(self):
        with patch.object(ima, "save_kv_state"), \
             patch.object(ima, "load_kv_state", return_value={}), \
             patch.object(ima, "Http") as mock_http_cls:
            http = _mock_http({
                ima.REFRESH_URL: {"code": 0, "token": "NEW_LEAF"},
                ima.ACTIVITY_INFO_URL: {"code": 0, "infos": []},
            })
            mock_http_cls.return_value = http
            ok, desc = ima._run_account(_synthetic_cookie(), 1, 1)
        self.assertFalse(ok)
        self.assertIn("活动可能已改版", desc)


class TestReportFieldsExIma(unittest.TestCase):
    def test_extract_sign_and_assets(self):
        synthetic_output = """
==================================================
🤖 腾讯 IMA 每日登录福利签到
==================================================

[1/1] 👤 用户: ***6789
  🔑 已用长效刷新令牌现签新会话令牌（约 2 小时叶令牌，每次运行现签）
  🎉 签到成功！获得 +50 算力
  🎁 满签奖励已领取 +100 算力
  📊 本周连签 7 天 · 本周累计 +400 算力
  🔑 Cookie 剩余 30 天（2026-12-01 到期）
==================================================
🏁 执行完毕: 成功 1/1 个账号
==================================================
"""
        res = extract_for("ima.py", synthetic_output)
        self.assertTrue(any("***6789" in line for line in res["lines"]))
        self.assertTrue(any("签到成功" in line for line in res["lines"]))
        self.assertTrue(any("本周连签 7 天" in line for line in res["lines"]))
        # 本周累计是周期收益（流量）非账户余额，不进 assets
        self.assertNotIn(("算力", 400.0), res["assets"])
        self.assertIn(("算力", 50.0), res["gains"])
        self.assertIn(("算力", 100.0), res["gains"])
        self.assertIn(("reward", "签到 +50 算力"), res["badges"])
        self.assertIn(("reward", "满签奖励 +100 算力"), res["badges"])
        self.assertEqual(res["streak"], 7)

    def test_extract_numberless_success(self):
        # 服务端未下发奖励数值时状态仍需被识别（不丢签到事实）
        synthetic_output = """
[1/1] 👤 用户: ***6789
  🎉 签到成功
  📊 本周连签 2 天 · 本周累计 +100 算力
"""
        res = extract_for("ima.py", synthetic_output)
        self.assertTrue(any("签到成功" in line for line in res["lines"]))
        self.assertNotIn(("算力", 0.0), res["gains"])

    def test_extract_failure_line_before_account_block(self):
        # 缺凭据账号在 👤 行之前即失败 —— 失败行无论是否在账号块内都必须捕获
        synthetic_output = """
[1/1] 👤 用户: ***6789
  ℹ️ 今日已签到，幂等放行
[2/2] ❌ 缺少登录凭据（x-ima-cookie 须同时含 IMA-UID 与 IMA-REFRESH-TOKEN）
"""
        res = extract_for("ima.py", synthetic_output)
        self.assertTrue(any("缺少登录凭据" in line for line in res["error_lines"]))

    def test_extract_already_signed(self):
        synthetic_output = """
[1/1] 👤 用户: ***6789
  ℹ️ 今日已签到，幂等放行
  📊 本周连签 3 天 · 本周累计 +150 算力
"""
        res = extract_for("ima.py", synthetic_output)
        self.assertTrue(any("今日已签" in line for line in res["lines"]))
        self.assertEqual(res["streak"], 3)

    def test_extract_failure_lines(self):
        synthetic_output = """
[1/2] 👤 用户: ***6789
  🔑 已用长效刷新令牌现签新会话令牌
[1/2] ❌ 每日签到被拒: code=5 msg=server busy
[2/2] ❌ 换票失败（IMA-REFRESH-TOKEN 可能已失效）: token invalid
"""
        res = extract_for("ima.py", synthetic_output)
        self.assertTrue(res["fail_lines"])
        self.assertTrue(any("换票失败" in line for line in res["error_lines"]))


if __name__ == "__main__":
    unittest.main()
