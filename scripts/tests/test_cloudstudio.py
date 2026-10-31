#!/usr/bin/env python3
"""Tencent CloudStudio 凭据归一化与双路换票单元测试。

背景（2026-09-20 HAR 全链路逆向结论）：
- CSRF 双站同源算法：X-XSRF-TOKEN = Vq(cloudstudio-session)、csrfCode = Vq(skey)，
  均为 djb2 变体 t=5381; t+=(t<<5)+charCode; &0x7fffffff。
- 凭据分两层：cloudstudio 会话 Cookie（Keycloak SSO 静默续票），
  qcloud 主站登录态 skey+uin（开放平台授权链从零铸票，最小必需字段集）。
- 换票三级回退：qcloud 铸票 → Keycloak SSO 续票 → qcloud 授权链重铸。

覆盖范围（全部使用合成凭据，不含任何真实 Cookie/token）：
1. derive_xsrf / derive_csrf 哈希算法与两站同源一致性
2. extract_qcloud_credential 的三种输入形态与 uin o 前缀剥离
3. normalize_credential 的形态判定与裸值消歧（session vs skey）
4. _build_credentials 的多账号汇总优先级与分列写法
5. mint_session_from_qcloud 的逐跳换票流程（Mock Http）
6. mint_session_from_qcloud 缺参/上游失败的降级路径
7. _cookie_issue_hint 针对各形态给出可行动指引
8. report_fields.ex_tencent_cloudstudio 报告行提取
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import tencent_cloudstudio as tcs
from report_fields import extract_for

# 合成凭据（非真实值）
SYN_SKEY = "SYNTHskeyV1.0AbCdEf0123456789-_xyz"
SYN_UIN = "100000000001"
SYN_SESSION = (
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee."
    "11111111-2222-3333-4444-555555555555."
    "66666666-7777-8888-9999-000000000000"
)


class TestCsrfDerivation(unittest.TestCase):
    """1. CSRF 双站同源算法。"""

    def test_derive_xsrf_known_vector(self):
        # 合成向量：djb2 变体确定性哈希（避免任何真实凭据入库）
        self.assertEqual(tcs.derive_xsrf(SYN_SKEY), "1209899669")

    def test_derive_xsrf_empty(self):
        self.assertEqual(tcs.derive_xsrf(""), "5381")

    def test_derive_csrf_same_algorithm_as_xsrf(self):
        # 两站算法同源，仅输入不同
        for probe in ("", "abc", SYN_SKEY, SYN_SESSION):
            self.assertEqual(tcs.derive_csrf(probe), tcs.derive_xsrf(probe))

    def test_derive_xsrf_matches_synthetic_session_vector(self):
        self.assertEqual(tcs.derive_xsrf(SYN_SESSION), "1081335325")


class TestExtractQcloudCredential(unittest.TestCase):
    """2. qcloud 凭据提取。"""

    def test_full_browser_cookie(self):
        raw = f"qcloud_uid=zzz; skey={SYN_SKEY}; uin=o{SYN_UIN}; nick=x"
        skey, uin = tcs.extract_qcloud_credential(raw)
        self.assertEqual(skey, SYN_SKEY)
        self.assertEqual(uin, SYN_UIN)  # o 前缀被剥离

    def test_key_value_pair(self):
        skey, uin = tcs.extract_qcloud_credential(f"skey={SYN_SKEY}; uin={SYN_UIN}")
        self.assertEqual((skey, uin), (SYN_SKEY, SYN_UIN))

    def test_bare_skey_value(self):
        skey, uin = tcs.extract_qcloud_credential(SYN_SKEY)
        self.assertEqual(skey, SYN_SKEY)
        self.assertEqual(uin, "")

    def test_bare_uin_value(self):
        skey, uin = tcs.extract_qcloud_credential(SYN_UIN)
        self.assertEqual(skey, "")
        self.assertEqual(uin, SYN_UIN)

    def test_bare_uin_with_o_prefix(self):
        _, uin = tcs.extract_qcloud_credential(f"o{SYN_UIN}")
        self.assertEqual(uin, SYN_UIN)

    def test_empty(self):
        self.assertEqual(tcs.extract_qcloud_credential(""), ("", ""))


class TestNormalizeCredential(unittest.TestCase):
    """3. 凭据形态判定与裸值消歧。"""

    def test_full_cloudstudio_cookie(self):
        raw = f"KEYCLOAK_IDENTITY=aaa; KEYCLOAK_SESSION=cloudstudio/x/y; cloudstudio-session={SYN_SESSION}"
        self.assertEqual(tcs.normalize_credential(raw)["kind"], "cloudstudio")

    def test_explicit_session_field_trusted(self):
        # 显式字段名直接信任，无需结构判定
        info = tcs.normalize_credential("cloudstudio-session=opaque-nonstandard-value")
        self.assertEqual(info["kind"], "cloudstudio")
        self.assertEqual(info["session"], "opaque-nonstandard-value")

    def test_keycloak_only_still_cloudstudio(self):
        raw = "KEYCLOAK_IDENTITY=aaa; KEYCLOAK_SESSION=cloudstudio/x/y"
        self.assertEqual(tcs.normalize_credential(raw)["kind"], "cloudstudio")

    def test_bare_session_value(self):
        info = tcs.normalize_credential(SYN_SESSION)
        self.assertEqual(info["kind"], "cloudstudio")
        self.assertEqual(info["session"], SYN_SESSION)

    def test_old_style_s_prefix_session(self):
        self.assertEqual(tcs.normalize_credential("s:abc123deadbeef")["kind"], "cloudstudio")

    def test_qcloud_full_cookie(self):
        info = tcs.normalize_credential(f"skey={SYN_SKEY}; uin=o{SYN_UIN}")
        self.assertEqual(info["kind"], "qcloud")
        self.assertEqual(info["skey"], SYN_SKEY)
        self.assertEqual(info["uin"], SYN_UIN)

    def test_bare_skey_not_mistaken_for_session(self):
        # 关键消歧：裸 skey 无点分隔，不得被判为 cloudstudio 会话
        info = tcs.normalize_credential(SYN_SKEY)
        self.assertEqual(info["kind"], "")
        self.assertEqual(info["skey"], SYN_SKEY)

    def test_incomplete_qcloud_returns_empty_kind(self):
        info = tcs.normalize_credential(f"skey={SYN_SKEY}")
        self.assertEqual(info["kind"], "")
        self.assertTrue(info["skey"])
        self.assertEqual(info["uin"], "")


class TestBuildCredentials(unittest.TestCase):
    """4. 多账号凭据汇总。"""

    def test_cookie_sequence_takes_priority(self):
        with patch.dict("os.environ", {
            "CLOUDSTUDIO_COOKIE_1": "cloudstudio-session=a.b.c",
            "CLOUDSTUDIO_SKEY_1": SYN_SKEY,
            "CLOUDSTUDIO_UIN_1": SYN_UIN,
        }, clear=True):
            creds = tcs._build_credentials()
        self.assertEqual(creds, ["cloudstudio-session=a.b.c"])

    def test_skey_uin_split_form_synthesized(self):
        with patch.dict("os.environ", {
            "CLOUDSTUDIO_SKEY_1": SYN_SKEY,
            "CLOUDSTUDIO_UIN_1": SYN_UIN,
        }, clear=True):
            creds = tcs._build_credentials()
        self.assertEqual(len(creds), 1)
        self.assertIn(f"skey={SYN_SKEY}", creds[0])
        self.assertIn(f"uin={SYN_UIN}", creds[0])

    def test_multi_account_split_form(self):
        with patch.dict("os.environ", {
            "CLOUDSTUDIO_SKEY_1": "skeyONE",
            "CLOUDSTUDIO_UIN_1": "100000000001",
            "CLOUDSTUDIO_SKEY_2": "skeyTWO",
            "CLOUDSTUDIO_UIN_2": "100000000002",
        }, clear=True):
            creds = tcs._build_credentials()
        self.assertEqual(len(creds), 2)
        self.assertIn("skey=skeyONE", creds[0])
        self.assertIn("uin=100000000002", creds[1])

    def test_nothing_configured(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(tcs._build_credentials(), [])


class _FakeResponse:
    def __init__(self, code=200, headers=None, text="", url="", body=None):
        self.code = code
        self.headers = headers or {}
        self.text = text
        self.url = url
        self.body = body if body is not None else text.encode()
        self._json = None

    def json(self, default=None):
        try:
            return json.loads(self.text)
        except Exception:
            return default


class _FakeCookie:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _FakeHttp:
    """按预置脚本回放的 Http 替身：记录调用序列，返回预设响应。"""

    def __init__(self, script):
        self.script = list(script)
        self.jar = []
        self.calls = []

    def request(self, method, url, headers=None, json_data=None, **kw):
        self.calls.append((method, url, json_data))
        if not self.script:
            raise AssertionError(f"unexpected request: {method} {url}")
        resp = self.script.pop(0)
        # 把该跳模拟下发的 Set-Cookie 追加进 jar
        for c in resp.__dict__.get("_set_cookies", []):
            self.jar.append(_FakeCookie(c[0], c[1]))
        return resp


class TestMintSessionFromQcloud(unittest.TestCase):
    """5/6. qcloud 授权链换票流程与降级。"""

    AUTH_PAGE = (
        '<html><a class="btn" id="qcloud" '
        'data-link="/auth/realms/cloudstudio/broker/qcloud/login?client_id=cloudstudio-apiserver-club'
        '&amp;tab_id=Tab123&amp;session_code=Sc456">授权</a></html>'
    )

    def _happy_script(self):
        r1 = _FakeResponse(302, {"Location": "https://cloudstudio.net/auth/realms/cloudstudio/protocol/openid-connect/auth?client_id=x"})
        r2 = _FakeResponse(200, text=self.AUTH_PAGE)
        r3 = _FakeResponse(303, {"Location": (
            "https://cloud.tencent.com/open/authorize?scope=login&app_id=100036548734"
            "&redirect_url=...&state=ST1.Tab123.cloudstudio-apiserver-club"
        )})
        r4 = _FakeResponse(200, text=json.dumps({"code": 0, "data": {"authCode": "a" * 32, "signature": "b" * 32}, "msg": ""}))
        r5 = _FakeResponse(302, {"Location": "https://cloudstudio.net/api/public/oauth/callback?code=x"})
        r5._set_cookies = [("cloudstudio-session-team", "qcloud"), ("KEYCLOAK_IDENTITY", "kcid"), ("KEYCLOAK_SESSION", "cloudstudio/u/s")]
        r6 = _FakeResponse(302, {"Location": "https://cloudstudio.net/api/public/post-login?code=x"})
        r7 = _FakeResponse(302, {"Location": "/pages/login/index.html?idp=qcloud"})
        r7._set_cookies = [("cloudstudio-session", "new-session-value")]
        r8 = _FakeResponse(200, text="<html>ok</html>")
        return [r1, r2, r3, r4, r5, r6, r7, r8]

    def test_happy_path_mints_session(self):
        fake = _FakeHttp(self._happy_script())
        with patch.object(tcs, "Http", return_value=fake), patch.object(tcs, "_get_proxy", return_value=""):
            ok, session, merged = tcs.mint_session_from_qcloud(SYN_SKEY, f"o{SYN_UIN}")
        self.assertTrue(ok)
        self.assertEqual(session, "new-session-value")
        self.assertIn("cloudstudio-session=new-session-value", merged)
        self.assertIn("KEYCLOAK_IDENTITY=kcid", merged)

    def test_grant_url_contains_derived_csrf_and_bare_uin(self):
        fake = _FakeHttp(self._happy_script())
        with patch.object(tcs, "Http", return_value=fake), patch.object(tcs, "_get_proxy", return_value=""):
            tcs.mint_session_from_qcloud(SYN_SKEY, f"o{SYN_UIN}")
        grant_calls = [c for c in fake.calls if "open/ajax/open" in c[1]]
        self.assertEqual(len(grant_calls), 1)
        _, grant_url, _ = grant_calls[0]
        # URL 查询参数 uin 必须是裸数字（o 前缀已剥离），csrfCode 由 skey 派生
        self.assertIn(f"uin={SYN_UIN}", grant_url)
        self.assertNotIn(f"uin=o{SYN_UIN}", grant_url)
        self.assertIn(f"csrfCode={tcs.derive_csrf(SYN_SKEY)}", grant_url)

    def test_missing_inputs_returns_false(self):
        for skey, uin in (("", SYN_UIN), (SYN_SKEY, ""), ("", "")):
            ok, session, merged = tcs.mint_session_from_qcloud(skey, uin)
            self.assertFalse(ok)
            self.assertEqual(session, "")
            self.assertEqual(merged, "")

    def test_grant_failure_diagnosed(self):
        script = self._happy_script()[:3]
        script.append(_FakeResponse(200, text=json.dumps({"code": "NOT-LOGINED", "msg": "登录态验证失败", "data": None})))
        fake = _FakeHttp(script)
        with patch.object(tcs, "Http", return_value=fake), patch.object(tcs, "_get_proxy", return_value=""):
            ok, session, _ = tcs.mint_session_from_qcloud(SYN_SKEY, SYN_UIN)
        self.assertFalse(ok)
        self.assertEqual(session, "")

    def test_broker_state_missing_diagnosed(self):
        script = self._happy_script()[:2]
        script.append(_FakeResponse(303, {"Location": "https://cloud.tencent.com/open/authorize"}))  # 无 state
        fake = _FakeHttp(script)
        with patch.object(tcs, "Http", return_value=fake), patch.object(tcs, "_get_proxy", return_value=""):
            ok, session, _ = tcs.mint_session_from_qcloud(SYN_SKEY, SYN_UIN)
        self.assertFalse(ok)

    def test_callback_without_session_diagnosed(self):
        script = self._happy_script()[:6]  # 回调链缺最后一跳的 session
        script.append(_FakeResponse(200, text="<html>no session</html>"))
        fake = _FakeHttp(script)
        with patch.object(tcs, "Http", return_value=fake), patch.object(tcs, "_get_proxy", return_value=""):
            ok, session, _ = tcs.mint_session_from_qcloud(SYN_SKEY, SYN_UIN)
        self.assertFalse(ok)
        self.assertEqual(session, "")


class TestCookieIssueHint(unittest.TestCase):
    """7. 凭据形态诊断指引。"""

    def test_empty_hint_mentions_both_forms(self):
        hint = tcs._cookie_issue_hint("")
        self.assertIn("skey", hint)
        self.assertIn("KEYCLOAK_IDENTITY", hint)

    def test_half_qcloud_hint_names_missing_field(self):
        hint = tcs._cookie_issue_hint(f"skey={SYN_SKEY}")
        self.assertIn("uin", hint)
        hint2 = tcs._cookie_issue_hint(f"uin=o{SYN_UIN}")
        self.assertIn("skey", hint2)

    def test_qcloud_kind_hint_suggests_relogin(self):
        hint = tcs._cookie_issue_hint(f"skey={SYN_SKEY}; uin=o{SYN_UIN}")
        self.assertIn("重新登录", hint)

    def test_bare_session_hint_mentions_alternative(self):
        hint = tcs._cookie_issue_hint("s:legacyvalue")
        self.assertIn("skey", hint)

    def test_missing_keycloak_hint(self):
        hint = tcs._cookie_issue_hint("cloudstudio-session=" + SYN_SESSION)
        self.assertIn("KEYCLOAK_IDENTITY", hint)

    def test_no_secret_leakage(self):
        # 任何提示都不得回显原始凭据
        for raw in ("", SYN_SKEY, f"skey={SYN_SKEY}; uin=o{SYN_UIN}", SYN_SESSION, "s:abc"):
            self.assertNotIn(SYN_SKEY, tcs._cookie_issue_hint(raw))
            self.assertNotIn(SYN_SESSION, tcs._cookie_issue_hint(raw))


class TestMaskCredential(unittest.TestCase):
    """附：凭据脱敏描述。"""

    def test_masks_qcloud(self):
        desc = tcs.mask_credential(f"skey={SYN_SKEY}; uin=o{SYN_UIN}")
        self.assertNotIn(SYN_SKEY, desc)
        self.assertIn("qcloud", desc)

    def test_masks_cloudstudio(self):
        desc = tcs.mask_credential(f"cloudstudio-session={SYN_SESSION}")
        self.assertNotIn(SYN_SESSION, desc)
        self.assertIn("cloudstudio", desc)

    def test_unknown_form(self):
        self.assertIn("无法识别", tcs.mask_credential("!!!"))


class TestReportExtraction(unittest.TestCase):
    """8. 报告字段提取（含新增 qcloud 换票行）。"""

    def test_qcloud_mint_line(self):
        out = (
            "🔐 使用 qcloud 登录态（skey+uin）铸造 CloudStudio 会话...\n"
            "    🔑 qcloud 授权换票成功，新 session: 73e85d1f-2f3***\n"
            "用户 100***242 今日已签到过（本次奖励 2.00 机时）\n"
            "暂无可用资源包"
        )
        res = extract_for("tencent_cloudstudio.py", out)
        self.assertTrue(any("100***242" in ln for ln in res["lines"]))
        self.assertIn(("机时", 2.0), res["gains"])

    def test_ssO_renewal_line_still_badged(self):
        out = "🔑 SSO 主动续票成功，使用新 session: abc***\n用户 u***1 签到成功，获得 2.00 机时"
        res = extract_for("tencent_cloudstudio.py", out)
        self.assertTrue(any("SSO" in b[1] for b in res["badges"]))

    def test_resource_summary_lines(self):
        out = (
            "用户 u***1 今日已签到过\n"
            "可用资源总计：剩余 34.00 / 34.00 机时\n"
            "服务端汇总：剩余 34.00 / 34.00 机时"
        )
        res = extract_for("tencent_cloudstudio.py", out)
        self.assertTrue(any("资源" in ln for ln in res["lines"]))


if __name__ == "__main__":
    unittest.main()