#!/usr/bin/env python3
"""天翼爱音乐「AI视频创作赢话费」(imusic.py) 单元测试。

加密向量全部为合成数据（时间戳/随机串/密钥均为测试固定值，非真实凭据）；
mock Http 服务端按客户端上报的 im* 请求头密钥材料加密响应，
可同时校验「请求加密 → 头信息一致性 → 响应解密」全链路。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import imusic
from imusic import ImusicLuckClient, build_ua, run_imusic_luck
from report_fields import extract_for


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# 合成协议向量（与 telecom 侧无任何关联；生成脚本见 test 内 _derive_* 帮助函数）
VEC_TS = "1700000000000"
VEC_RAND = "abcd2345678efhijk"
VEC_KEY = "7cb852366263622ddc14c66aa5bb1ce1"
VEC_PAYLOAD = {"activityId": "ai119", "channelId": "156000008970", "portal": "45",
               "apiName": "act/LaborApi/getOperationCurrentIssueInfo"}
VEC_CT = ("d/4sSWRurs1b+3elmMfjEiCHYnWM97kPhMhgPVK/FvrusuZD4wk4wn/UD1zDOqf+"
          "y1NOxB0eBvd4KNEPWDTySjSUK6OKj5OcE48niS+NfszSLnkA/7fCIpZK207mrqx5jb"
          "TZ1Nd5Q4t8vNlmZ8a18ARTYoKmtXpXczh7fR3tWpQ=")
VEC_RESP_CT = ("POmqvO7KXKdzv7odF7jKdlq1baQhM8wa+THfHYEnYMEDQtssymAptqxNXoSghIyz"
               "+D6CLLJ7sX5dYcU/BItvEQ==")


class FakeResponse:
    def __init__(self, code: int, text: str):
        self.code = code
        self.body = text.encode()

    @property
    def text(self) -> str:
        return self.body.decode()

    def json(self, default=None):
        try:
            return json.loads(self.text)
        except Exception:
            return default


class FakeImusicServer:
    """模拟 imusic 网关：按客户端上报的 im* 头密钥材料加解密，验证全链路一致性。"""

    def __init__(self, routes: dict):
        self.routes = routes  # (method, path) -> callable(query, headers) -> (code, text)
        self.calls = []

    def request(self, method, url, *, headers=None, data=None, json_data=None,
                form=None, timeout=60):
        headers = headers or {}
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        self.calls.append((method, path, dict(query), dict(headers)))
        handler = self.routes.get(path)
        if handler is None:
            return FakeResponse(404, "{}")
        code, text = handler(query, headers)
        return FakeResponse(code, text)


def _server_decrypt_form(query, headers):
    """用请求头里的密钥材料解开 formData（服务端视角）。"""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    ts = headers["imtimestamp"]
    rand = headers["imrandomnum"]
    key = headers["imencryptkey"]
    k = _md5(_b64(rand) + _md5(ts) + key)[:16].encode()
    iv = _md5(_b64(ts) + _md5(rand) + key)[:16].encode()
    ct = urllib.parse.unquote(query["formData"][0])
    return json.loads(unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(base64.b64decode(ct)), 16))


def _server_encrypt_resp(headers, obj) -> str:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    ts = headers["imtimestamp"]
    rand = headers["imrandomnum"]
    key = headers["imencryptkey"]
    k = _md5(_b64(ts) + key + _md5(rand))[:16].encode()
    iv = _md5(_b64(rand) + key + _md5(ts))[:16].encode()
    pt = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(AES.new(k, AES.MODE_CBC, iv).encrypt(pad(pt.encode(), 16))).decode()


class TestImusicCrypto(unittest.TestCase):
    def test_key_derivation(self):
        """imencryptkey 派生公式：md5(b64(md5(ts)+rand)+rand)。"""
        self.assertEqual(_md5(_b64(_md5(VEC_TS) + VEC_RAND) + VEC_RAND), VEC_KEY)

    def test_encrypt_matches_vector(self):
        """请求加密输出与固定向量逐字节一致（AES-128-CBC Pkcs7 base64）。"""
        client = ImusicLuckClient(http=object(), ticket="0" * 256)
        client.ts, client.rand, client.key = VEC_TS, VEC_RAND, VEC_KEY
        self.assertEqual(client._enc_form(VEC_PAYLOAD), VEC_CT)

    def test_decrypt_matches_vector(self):
        """响应解密与固定向量一致。"""
        client = ImusicLuckClient(http=object(), ticket="0" * 256)
        client.ts, client.rand, client.key = VEC_TS, VEC_RAND, VEC_KEY
        self.assertEqual(
            client._dec_body(VEC_RESP_CT),
            {"code": "0000", "desc": "成功", "data": {"issueName": "第6期"}},
        )

    def test_encrypt_decrypt_separate_derivations(self):
        """请求加密与响应解密是两条独立派生链（与逆向一致）：
        请求侧用 enc 派生，响应侧用 dec 派生——各自与服务端公式互逆。"""
        client = ImusicLuckClient(http=object(), ticket="0" * 256)
        self.assertNotEqual(
            _md5(_b64(client.rand) + _md5(client.ts) + client.key)[:16],
            _md5(_b64(client.ts) + client.key + _md5(client.rand))[:16],
        )
        # 响应解密应能解开服务端（dec 派生）加密的任意 payload
        payload = {"mobile": "13800138000", "n": 20, "cn": "积分", "empty": ""}
        cipher = _server_encrypt_resp(
            {"imtimestamp": client.ts, "imrandomnum": client.rand, "imencryptkey": client.key},
            payload,
        )
        self.assertEqual(client._dec_body(cipher), payload)

    def test_build_ua(self):
        """UA 结构与 App 深链一致：b64(后6位)!#!b64(前5位)。"""
        ua = build_ua("13800138000")
        self.assertTrue(ua.startswith("CtClient;13.3.0;Android;12;PJJ110;"))
        suffix = base64.b64encode(b"138000").decode().rstrip("=")
        prefix = base64.b64encode(b"13800").decode().rstrip("=")
        self.assertEqual(ua, f"CtClient;13.3.0;Android;12;PJJ110;{suffix}!#!{prefix}")
        self.assertEqual(build_ua(""), "CtClient;13.3.0;Android;12;PJJ110")

    def test_headers_carry_key_material(self):
        """请求头携带完整 im* 密钥材料与 Bearer token。"""
        client = ImusicLuckClient(http=object(), ticket="0" * 256, phone="13800138000")
        client.token = "fake.jwt.token"
        h = client._headers()
        self.assertEqual(h["imtimestamp"], client.ts)
        self.assertEqual(h["imrandomnum"], client.rand)
        self.assertEqual(h["imencryptkey"], client.key)
        self.assertEqual(h["imencrypt"], "1")
        self.assertEqual(h["Authorization"], "Bearer fake.jwt.token")
        self.assertEqual(h["User-Agent"], build_ua("13800138000"))


def _make_server(*, token_ok=True, left_num=4, templates=2, submit_ok=True,
                 total=720, remaining=20, draw_awards=None, redeem_ok=True):
    """构造可编排的 mock 网关与点数状态机。

    total/remaining 为活动点数（total 含已消耗）；每次成功制作 +20 点；
    抽奖扣 20 点并按 draw_awards 脚本循环发奖（{"awardIndex","name","points"}）；
    兑换在 remaining>=1000 且 redeem_ok 时成功扣 1000。"""
    state = {"submits": 0, "total": total, "remaining": remaining, "draws": 0, "redeems": 0}
    draw_awards = draw_awards or [{"awardIndex": "16320106", "name": ""}]

    def login_page(query, headers):
        return 200, "<html>ok</html>"

    def sso_login(query, headers):
        if token_ok:
            return 200, json.dumps({"token": "fake.jwt.token", "returnCode": "0000",
                                    "mobile": "13800138000", "description": "Success"})
        return 200, json.dumps({"token": "", "returnCode": "1001", "description": "票据无效"})

    def en_api(query, headers):
        params = _server_decrypt_form(query, headers)
        api = params.get("apiName", "")
        if api.endswith("getOperationTotalScoreOrRemainingScore"):
            obj = {"code": "0000", "desc": "成功",
                   "data": {"totalScore": str(state["total"]), "remainingScore": str(state["remaining"])}}
        elif api.endswith("queryAiMakePkgInfo"):
            left = max(0, left_num - state["submits"])
            obj = {"code": "0000", "desc": "成功",
                   "data": {"privilegeVrbtAIVideoLeftNum": left,
                            "balanceMakeTimesTip": f"当前剩余{left}次"}}
        elif api.endswith("getOperationCurrentIssueInfo"):
            obj = {"code": "0000", "desc": "查询成功",
                   "data": {"issueName": "第6期", "issueNumber": "ai119_6", "activityId": "ai119"}}
        elif api.endswith("getEncryptDecryptMobile"):
            obj = {"code": "0000", "desc": "成功", "data": {"result": "a" * 64}}
        elif api.endswith("operationIntegralLottery"):
            state["remaining"] -= 20
            state["draws"] += 1
            award = draw_awards[(state["draws"] - 1) % len(draw_awards)]
            back = int(award.get("points") or 0)
            state["remaining"] += back
            state["total"] += back
            obj = {"code": "0000", "desc": "成功",
                   "data": {"awardIndex": award["awardIndex"], "name": award.get("name", "")}}
        elif api.endswith("operationIntegralRedeemPrize"):
            if redeem_ok and state["remaining"] >= 1000:
                state["remaining"] -= 1000
                state["redeems"] += 1
                obj = {"code": "0000", "desc": "成功", "data": {"prizeName": "10元电信话费"}}
            else:
                # 真实售罄码（H5 get10 处理："10003"→"哎呀~话费已兑换完啦"）
                obj = {"code": "10003", "desc": "话费已兑换完啦"}
        else:
            obj = {"code": "1002", "desc": f"未知接口 {api}"}
        return 200, _server_encrypt_resp(headers, obj)

    def make_api(query, headers):
        """template_make_add_v2：与 en/api 同款加解密，但 payload 无 apiName（与抓包一致）。"""
        params = _server_decrypt_form(query, headers)
        if submit_ok:
            state["submits"] += 1
            state["total"] += 20
            state["remaining"] += 20
            obj = {"code": "0000", "desc": "成功",
                   "data": {"makeId": f"vid{state['submits']}", "code": "0000",
                            "success": True, "message": "成功", "taskid": str(1000 + state["submits"])}}
        else:
            obj = {"code": "1001", "desc": "次数不足"}
        return 200, _server_encrypt_resp(headers, obj)

    def de_api(query, headers):
        api = (query.get("apiName") or [""])[0]
        if api.endswith("queryActRecommendTemplateList"):
            lst = [{"templateId": f"ve_{i}", "templateConfId": f"2T{i}",
                    "videoName": f"模板{i}",
                    "textPrompt": json.dumps([{"boxName": "", "prompt": f"提示词{i}"}],
                                             separators=(",", ":"), ensure_ascii=False)}
                   for i in range(templates)]
            obj = {"code": "0000", "desc": "成功",
                   "data": {"pageNo": 1, "totalCount": len(lst), "list": lst}}
        else:
            obj = {"code": "1002", "desc": "未知接口"}
        return 200, json.dumps(obj)

    routes = {
        "/ca/eXzv": login_page,
        "/vapi/vue_login/sso_login_v2": sso_login,
        "/hapi/en/api": en_api,
        "/hapi/diy_video/au/template_make_add_v2": make_api,
        "/hapi/de/api": de_api,
    }
    return FakeImusicServer(routes), state


class TestImusicFlow(unittest.TestCase):
    def test_run_full_success(self):
        """正常链路：登录→查点数→剩余次数内逐模板提交→点数增量正确（默认不抽奖）。"""
        server, state = _make_server(left_num=4, templates=2, total=720, remaining=20)
        with patch.object(imusic.time, "sleep", lambda *_: None):
            out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["status"], "成功")
        self.assertEqual(out["videos"], 4)
        self.assertEqual(state["submits"], 4)
        self.assertEqual(out["gain"], 80)
        self.assertEqual(out["score"], "800")
        self.assertEqual(out["issue"], "第6期")
        self.assertEqual(out["left"], 0)
        self.assertEqual(out["draws"], 0)

    def test_run_partial_success(self):
        """次数少于模板数：仅提交次数限额。"""
        server, state = _make_server(left_num=2, templates=5, total=700, remaining=0)
        with patch.object(imusic.time, "sleep", lambda *_: None):
            out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["status"], "成功")
        self.assertEqual(out["videos"], 2)
        self.assertEqual(out["gain"], 40)

    def test_run_no_left(self):
        """次数用完且未开抽奖：不提交不抽奖，如实汇报（不依赖放量周期文案）。"""
        server, state = _make_server(left_num=0, total=800, remaining=100)
        out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["status"], "无剩余次数")
        self.assertEqual(state["submits"], 0)
        self.assertEqual(out["score"], "800")
        self.assertEqual(out["draws"], 0)
        self.assertIn("免费次数已用完", out["msg"])
        self.assertNotIn("每3天", out["msg"])

    def test_run_login_fail(self):
        """票据无效：整体失败且零提交。"""
        server, state = _make_server(token_ok=False)
        out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["status"], "失败")
        self.assertEqual(out["videos"], 0)
        self.assertEqual(state["submits"], 0)

    def test_run_submit_rejected(self):
        """服务端拒绝提交：立即停止并如实汇报。"""
        server, state = _make_server(left_num=4, submit_ok=False, total=720, remaining=0)
        with patch.object(imusic.time, "sleep", lambda *_: None):
            out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["status"], "失败")
        self.assertEqual(out["videos"], 0)
        self.assertEqual(state["submits"], 0)
        self.assertEqual(out["gain"], 0)

    def test_run_draw_enabled_full_drain(self):
        """开 TELECOM_IMUSIC_DRAW=1 且储备置 0：点数全量抽到 <20，奖品按 awardIndex 归类。"""
        awards = [
            {"awardIndex": "16320106", "name": ""},                       # 谢谢参与
            {"awardIndex": "16210105", "name": "AI制作体验券×1"},           # 中奖（体验券）
            {"awardIndex": "16320101", "name": "20点数", "points": 20},    # 中奖（返点）
        ]
        server, state = _make_server(left_num=0, total=800, remaining=100, draw_awards=awards)
        env = {"TELECOM_IMUSIC_DRAW": "1", "TELECOM_IMUSIC_DRAW_RESERVE": "0"}
        with patch.dict(os.environ, env):
            with patch.object(imusic.time, "sleep", lambda *_: None):
                out = run_imusic_luck(server, "f" * 256, "13800138000")
        # 100 点 → 5 抽：-20/-20/(-20+20)/-20/-20 → 剩 20 停
        self.assertEqual(out["draws"], 5)
        self.assertEqual(state["draws"], 5)
        self.assertEqual(out["prizes"], ["谢谢参与", "AI制作体验券×1", "20点数", "谢谢参与", "AI制作体验券×1"])
        self.assertEqual(out["status"], "成功")

    def test_run_draw_keeps_reserve(self):
        """抽奖默认保留 1000 点兑换储备：只抽超出部分，储备不被破坏。"""
        server, state = _make_server(left_num=0, total=1200, remaining=1200)
        with patch.dict(os.environ, {"TELECOM_IMUSIC_DRAW": "1", "TELECOM_IMUSIC_REDEEM": "0"}):
            with patch.object(imusic.time, "sleep", lambda *_: None):
                out = run_imusic_luck(server, "f" * 256, "13800138000")
        # 1200 → 抽掉 200 超额（10 抽）→ 停在 1000 储备线
        self.assertEqual(out["draws"], 10)
        self.assertEqual(state["remaining"], 1000)

    def test_run_draw_disabled_by_default(self):
        """默认不开抽奖：剩余点数原样保留。"""
        server, state = _make_server(left_num=0, total=800, remaining=100)
        out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["draws"], 0)
        self.assertEqual(state["draws"], 0)
        self.assertEqual(state["remaining"], 100)

    def test_run_redeem_at_threshold(self):
        """≥1000 点默认自动兑换 10 元话费，只兑一次并扣点。"""
        server, state = _make_server(left_num=0, total=1200, remaining=1200)
        with patch.object(imusic.time, "sleep", lambda *_: None):
            out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["redeemed"], "10元话费")
        self.assertEqual(state["redeems"], 1)
        self.assertEqual(state["remaining"], 200)
        self.assertEqual(out["status"], "成功")

    def test_run_redeem_disabled(self):
        """关 TELECOM_IMUSIC_REDEEM：达标也不兑换。"""
        server, state = _make_server(left_num=0, total=1200, remaining=1200)
        with patch.dict(os.environ, {"TELECOM_IMUSIC_REDEEM": "0"}):
            out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["redeemed"], "")
        self.assertEqual(state["redeems"], 0)
        self.assertEqual(state["remaining"], 1200)

    def test_run_redeem_sold_out_fallback_draw(self):
        """兑换售罄（10003）：如实上报，并按默认退路抽奖——但保留 1000 点储备只抽超额。"""
        server, state = _make_server(left_num=0, total=1200, remaining=1200, redeem_ok=False)
        with patch.object(imusic.time, "sleep", lambda *_: None):
            out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["redeemed"], "")
        self.assertEqual(out["redeem_err"], "今日话费份额已被抢完")
        self.assertEqual(state["redeems"], 0)
        # 1200 → 抽掉超额 200（10 抽）→ 停在储备线 1000
        self.assertEqual(out["draws"], 10)
        self.assertEqual(state["remaining"], 1000)
        self.assertEqual(out["status"], "成功")
        self.assertIn("兑换未成", out["msg"])

    def test_run_redeem_fail_fallback_disabled(self):
        """关退路（TELECOM_IMUSIC_DRAW_ON_FAIL=0）：售罄后不抽奖。"""
        server, state = _make_server(left_num=0, total=1200, remaining=1200, redeem_ok=False)
        with patch.dict(os.environ, {"TELECOM_IMUSIC_DRAW_ON_FAIL": "0"}):
            out = run_imusic_luck(server, "f" * 256, "13800138000")
        self.assertEqual(out["draws"], 0)
        self.assertEqual(state["remaining"], 1200)
        self.assertEqual(out["status"], "无剩余次数")

    def test_prize_label_mapping(self):
        """awardIndex→奖名：谢谢参与索引集合与中奖命名。"""
        self.assertEqual(ImusicLuckClient.prize_label({"code": "0000", "data": {"awardIndex": "16320106"}}), "谢谢参与")
        self.assertEqual(ImusicLuckClient.prize_label({"code": "0000", "data": {"awardIndex": "-1"}}), "谢谢参与")
        self.assertEqual(
            ImusicLuckClient.prize_label({"code": "0000", "data": {"awardIndex": "16210105", "name": "AI制作体验券×1"}}),
            "AI制作体验券×1")
        self.assertEqual(ImusicLuckClient.prize_label({"code": "1002", "desc": "失败"}), "")

    def test_template_prompt_parsing(self):
        """textPrompt JSON 数组解析与降级。"""
        tpl = {"textPrompt": json.dumps([{"boxName": "", "prompt": "第一段"},
                                         {"boxName": "", "prompt": "第二段"}],
                                        separators=(",", ":"), ensure_ascii=False)}
        self.assertEqual(ImusicLuckClient.template_prompt(tpl), "第一段\n第二段")
        self.assertEqual(ImusicLuckClient.template_prompt({"textPrompt": "纯文本"}), "纯文本")
        self.assertEqual(ImusicLuckClient.template_prompt({}), "")

    def test_submit_payload_shape(self):
        """提交 payload 与逆向结论同构（关键固定字段与随机命名）。"""
        server, state = _make_server(left_num=1, templates=1, total=0, remaining=0)
        with patch.object(imusic.time, "sleep", lambda *_: None):
            run_imusic_luck(server, "f" * 256, "13800138000")
        method, path, query, headers = [c for c in server.calls if c[1] == "/hapi/diy_video/au/template_make_add_v2"][0]
        params = _server_decrypt_form(query, headers)
        for k in ("mobile", "templateId", "templateConfId", "userWords", "templateName",
                  "videoName", "aid", "channelId", "portal"):
            self.assertIn(k, params)
        self.assertEqual(params["aid"], "ai119")
        self.assertEqual(params["mobile"], "13800138000")
        self.assertEqual(params["userWords"], "提示词0")
        self.assertRegex(params["templateName"], r"^模板0\d{6}$")
        self.assertEqual(params["templateName"], params["videoName"])


class TestImusicReport(unittest.TestCase):
    def test_ex_telecom_imusic_line(self):
        """• 赢花费 行归一化：明细进 lines，点数进 badges+gains（供邮件今日概览）。"""
        output = (
            "👤 用户: 【138****8000】\n"
            "• 签到: 【成功】 (+10 金豆)\n"
            "• 赢花费: 【成功(提交4次生成，点数+80，总点数800，第6期)】\n"
        )
        res = extract_for("telecom.py", output)
        self.assertTrue(any("赢花费" in ln for ln in res["lines"]))
        self.assertTrue(any("点数" in b[1] for b in res["badges"]))
        self.assertIn(("点数", 80.0), res["gains"])

    def test_ex_telecom_imusic_redeem_badge(self):
        """兑换话费单独出 badge。"""
        output = (
            "👤 用户: 【138****8000】\n"
            "• 签到: 【今日已签】\n"
            "• 赢花费: 【成功(提交3次生成，点数+60，已兑10元话费，抽奖5次，总点数1060，第6期)】\n"
        )
        res = extract_for("telecom.py", output)
        self.assertTrue(any("赢花费" in ln for ln in res["lines"]))
        self.assertTrue(any("10元话费" in b[1] for b in res["badges"]))
        self.assertIn(("点数", 60.0), res["gains"])

    def test_ex_telecom_imusic_skip_ignored(self):
        """跳过行不产生展示部分。"""
        output = (
            "👤 用户: 【138****8000】\n"
            "• 签到: 【今日已签】\n"
            "• 赢花费: 【跳过(无现签ticket)】\n"
        )
        res = extract_for("telecom.py", output)
        self.assertFalse(any("赢花费" in ln for ln in res["lines"]))


if __name__ == "__main__":
    unittest.main()
