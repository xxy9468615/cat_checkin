#!/usr/bin/env python3
"""天翼爱音乐「AI视频创作赢话费」活动（ai.imusic.cn ai-luck-winnew）自动化客户端。

逆向结论（2026-10-03 电信 App HAR 抓包逐字节复现验证）：

- 入口链路：电信 App 深链 `ai.imusic.cn/ca/eXzv?ticket=<App现签SSO票据>` → 302 下发
  `imusic` / `JSESSIONID` Cookie → H5 调 `vapi/vue_login/sso_login_v2` 用同一 ticket
  换 JWT token（Authorization Bearer，3 天有效）与 `user118100cn` Cookie。
  ticket 与 `wappark.189.cn/jt-sign/ssoHomLogin` 消费的票同源同格式（256 位 hex），
  telecom.py getSingle 现签产物可直接复用，无需额外抓包。

- 业务接口两类：
  * `GET/POST /hapi/de/api?...&apiName=...`：明文 query 参数（模板列表、单个作品结果）。
  * `POST /hapi/en/api?formData=<密文>` 与 `POST /hapi/diy_video/au/template_make_add_v2?formData=<密文>`：
    全参数 JSON 经 AES-128-CBC 加密。

- 会话密钥材料（页面加载时生成一次，随 `im*` 请求头明文上报）：
    imtimestamp  = 毫秒时间戳字符串
    imrandomnum  = 16 位随机串（表 abcdefhijkmnprstwxyz2345678）
    imencryptkey = md5( b64( md5(ts) + rand ) + rand )

- 参数加密（AES-128-CBC / Pkcs7 / base64 输出）：
    key = md5( b64(rand) + md5(ts) + imencryptkey )[:16]
    iv  = md5( b64(ts)  + md5(rand) + imencryptkey )[:16]

- 响应解密（AES-128-CBC / Pkcs7 / base64 输入）：
    key = md5( b64(ts)  + imencryptkey + md5(rand) )[:16]
    iv  = md5( b64(rand) + imencryptkey + md5(ts) )[:16]

- 活动机制（activityId=ai119「AI奇遇赢Pad 2.0」，官方规则见 H5 规则弹窗原文）：
  * 活动期 2026-07-17 ~ 2027-01-12，**每 15 天为一期**（共 12 期），期结束次日 11:00 开奖。
  * 免费制作次数：每 3 天获赠 3 次、新赠时旧机会过期清零（体验券到账另计）——但自动化
    **不依赖该周期**，完全以服务端剩余计数（privilegeVrbtAIVideoLeftNum）为准，有就提交用光。
  * 点数（玩法二「AI制作赢点数」）：每成功制作 1 个作品 +20 点，每期以此方式上限 340 点；
    **20 点 = 1 次抽奖**（奖池：20/40点、AI体验券*1/*3、1元话费、谢谢参与；实测中奖概率低）；
    **1000 点 = 10 元话费兑换，每日限量、先到先得**（H5 兑换按钮红字「每日奖品有限」；
    接口 code=10003 即当日份额抢完），兑换链路前端无验证码环节，成功后次月 25 号前到账；
    未使用点数活动结束全部清零。
  * 券码（玩法一）：每制作 1 个作品得 1 券码，每期限 3 个（天翼智铃用户 2 个/作品限 6 个），
    每期抽 1 台 iPad；券码仅当期有效。
  * 自动化策略：制作次数自动检测用光 → 点数攒到 1000 优先兑话费 → 兑换失败才退回抽奖
    （保留 1000 点储备只抽超出部分）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.parse
from http.cookiejar import Cookie as JarCookie
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PREFIX = "TELECOM_"

BASE_URL = "https://ai.imusic.cn"
CHANNEL_ID = "156000008970"
PORTAL = "45"
ACTIVITY_ID = "ai119"
RAND_CHARS = "abcdefhijkmnprstwxyz2345678"

# 官方规则常量（H5 规则弹窗原文）
DRAW_COST = 20            # 20 点数 = 1 次抽奖
REDEEM_COST = 1000        # 1000 点数 = 10 元话费（限量 1000 份先到先得）
# 谢谢参与/无效的 awardIndex（页面 FlipCardLottery 判定原文）
THANK_YOU_AWARD_INDEXES = {"16320106", "16320206", "16320306", "16320401", "-1"}
# 单次运行抽奖次数上限（防御性：点数由服务端校验，这里只防异常死循环）
MAX_DRAWS_PER_RUN = 15


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def build_ua(phone: str = "") -> str:
    """构造 App 深链 UA。真机 UA 结构（HAR 逆向）：
    CtClient;13.3.0;Android;12;PJJ110;<b64(手机后6位)>!#!<b64(手机前5位)>（均去 padding）。"""
    if re.match(r"^1\d{10}$", phone or ""):
        return (
            f"CtClient;13.3.0;Android;12;PJJ110;"
            f"{_b64(phone[-6:]).rstrip('=')}!#!{_b64(phone[:5]).rstrip('=')}"
        )
    return "CtClient;13.3.0;Android;12;PJJ110"


class ImusicLuckClient:
    """ai119「AI视频创作赢话费」H5 会话：ticket 登录 + 加密业务接口 + 视频提交。"""

    def __init__(self, http: Any, ticket: str, phone: str = "") -> None:
        if not HAS_CRYPTO:
            raise RuntimeError("缺少 pycryptodome 依赖，请执行 pip install pycryptodome")
        self.http = http
        self.ticket = (ticket or "").strip()
        self.phone = (phone or "").strip()
        self.token = ""
        # 密钥材料整个 H5 会话只生成一次（页面加载时 H=$.headers(1)）
        self.ts = str(int(time.time() * 1000))
        self.rand = "".join(random.choice(RAND_CHARS) for _ in range(16))
        self.key = _md5(_b64(_md5(self.ts) + self.rand) + self.rand)
        # 渠道 Cookie：H5 由埋点 SDK 写入（cc=channelId）
        self._inject_cookie("cc", CHANNEL_ID)

    # ---------- Cookie 处理 ----------

    def _inject_cookie(self, name: str, value: str) -> None:
        """向 Http 实例的 CookieJar 注入 ai.imusic.cn 会话 Cookie。

        curl_cffi 链路每请求新建 Session 且不把响应 Set-Cookie 回写实例 Jar，
        imusic 的鉴权依赖 user118100cn 等会话 Cookie，必须手动捕获并注入。
        """
        jar = getattr(self.http, "jar", None)
        if jar is None or not value:
            return
        jar.set_cookie(JarCookie(
            version=0, name=name, value=value,
            port=None, port_specified=False,
            domain="ai.imusic.cn", domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True,
            secure=False, expires=None, discard=True,
            comment=None, comment_url=None, rest={}, rfc2109=False,
        ))

    def _capture_cookies(self, resp: Any) -> None:
        """从响应头收集 Set-Cookie 注入 Jar（兼容 urllib Message 与 curl_cffi Headers）。"""
        headers = getattr(resp, "headers", None)
        if not headers:
            return
        raw_list: List[str] = []
        try:
            if hasattr(headers, "get_all"):
                raw_list = list(headers.get_all("Set-Cookie") or [])
            elif hasattr(headers, "get_list"):
                raw_list = list(headers.get_list("set-cookie") or [])
            elif hasattr(headers, "multi_items"):
                raw_list = [v for k, v in headers.multi_items() if k.lower() == "set-cookie"]
        except Exception:
            return
        for raw in raw_list:
            try:
                sc = SimpleCookie()
                sc.load(raw)
                for name, morsel in sc.items():
                    self._inject_cookie(name, morsel.value)
            except Exception:
                continue

    # ---------- 会话与鉴权 ----------

    def login(self) -> bool:
        """App 深链落地收集 Cookie，再用 ticket 经 sso_login_v2 换 JWT token。"""
        if not self.ticket:
            return False
        res = self.http.request(
            "GET",
            f"{BASE_URL}/ca/eXzv?ticket={urllib.parse.quote(self.ticket)}&isshare=0",
            headers=self._headers({"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}),
            timeout=20,
        )
        self._capture_cookies(res)
        res = self.http.request(
            "POST",
            f"{BASE_URL}/vapi/vue_login/sso_login_v2",
            json_data={"portal": PORTAL, "channelId": CHANNEL_ID, "ticket": self.ticket},
            headers=self._headers(),
            timeout=20,
        )
        self._capture_cookies(res)
        data: Dict[str, Any] = {}
        try:
            data = res.json() or {}
        except Exception:
            pass
        token = str(data.get("token") or "")
        if res.code == 200 and data.get("returnCode") == "0000" and token:
            self.token = token
            if not self.phone and data.get("mobile"):
                self.phone = str(data.get("mobile"))
            # H5 登录成功后由前端 JS 写入的 Cookie（与抓包一致）
            self._inject_cookie("loginState", "true")
            return True
        print(f"    [imusic] sso_login 失败: http={res.code} "
              f"returnCode={data.get('returnCode')} desc={str(data.get('description'))[:60]}", flush=True)
        return False

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "User-Agent": build_ua(self.phone),
            "X-Requested-With": "com.ct.client",
            "Origin": BASE_URL,
            "Referer": f"{BASE_URL}/h5v/fusion/ai-luck-winnew?ca=eXzv&cc={CHANNEL_ID}",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        h.update({
            "imencrypt": "1",
            "imtimestamp": self.ts,
            "imrandomnum": self.rand,
            "imencryptkey": self.key,
        })
        if extra:
            h.update(extra)
        return h

    # ---------- 加解密（算法见模块 docstring，已按 HAR 逐字节验证） ----------

    def _enc_form(self, params: Dict[str, Any]) -> str:
        key = _md5(_b64(self.rand) + _md5(self.ts) + self.key)[:16].encode("utf-8")
        iv = _md5(_b64(self.ts) + _md5(self.rand) + self.key)[:16].encode("utf-8")
        plain = json.dumps(params, separators=(",", ":"), ensure_ascii=False)
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain.encode("utf-8"), AES.block_size))
        return base64.b64encode(cipher).decode("ascii")

    def _dec_body(self, cipher_b64: str) -> Dict[str, Any]:
        key = _md5(_b64(self.ts) + self.key + _md5(self.rand))[:16].encode("utf-8")
        iv = _md5(_b64(self.rand) + self.key + _md5(self.ts))[:16].encode("utf-8")
        plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(cipher_b64)), AES.block_size)
        return json.loads(plain.decode("utf-8"))

    # ---------- 接口封装 ----------

    def _post_encrypted(self, path: str, params: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        url = f"{BASE_URL}{path}?formData=" + urllib.parse.quote(self._enc_form(params), safe="")
        res = self.http.request("POST", url, headers=self._headers(), timeout=timeout)
        self._capture_cookies(res)
        if res.code != 200 or not res.text:
            return {"code": str(res.code), "desc": f"HTTP {res.code}"}
        try:
            return self._dec_body(res.text.strip())
        except Exception as e:
            return {"code": "-2", "desc": f"响应解密失败: {e}"}

    def _en_api(self, params: Dict[str, Any], api_name: str) -> Dict[str, Any]:
        payload = dict(params)
        payload["apiName"] = api_name
        return self._post_encrypted("/hapi/en/api", payload)

    def _de_api(self, params: Dict[str, Any], api_name: str, timeout: int = 30) -> Dict[str, Any]:
        """明文 query 接口（de/api），apiName 在 querystring。"""
        qs = dict(params)
        qs["apiName"] = api_name
        qs.setdefault("channelId", CHANNEL_ID)
        qs.setdefault("portal", PORTAL)
        url = f"{BASE_URL}/hapi/de/api?" + urllib.parse.urlencode(qs)
        res = self.http.request("POST", url, headers=self._headers(), timeout=timeout)
        self._capture_cookies(res)
        try:
            return res.json() or {}
        except Exception:
            return {"code": str(res.code), "desc": f"HTTP {res.code}"}

    def get_issue_info(self) -> Dict[str, Any]:
        return self._en_api(
            {"activityId": ACTIVITY_ID, "channelId": CHANNEL_ID, "portal": PORTAL},
            "act/LaborApi/getOperationCurrentIssueInfo",
        )

    def get_encrypt_mobile(self) -> Dict[str, Any]:
        return self._en_api(
            {"activityId": ACTIVITY_ID, "mobile": self.phone, "type": 1, "invitationCode": "",
             "channelId": CHANNEL_ID, "portal": PORTAL},
            "diy/DiyVideoApi/getEncryptDecryptMobile",
        )

    def get_user_area(self) -> Dict[str, Any]:
        """查询归属省/市（hma/query_info 独立路径），并把 H5 同款 Province/City Cookie 写入会话。"""
        res = self._post_encrypted(
            "/hapi/cmn/imu/hma/query_info",
            {"mobile": self.phone, "channelId": CHANNEL_ID, "portal": PORTAL},
        )
        data = res.get("data") or {}
        if data.get("province_code"):
            self._inject_cookie("Province", str(data.get("province_code")))
        if data.get("areacode"):
            self._inject_cookie("City", str(data.get("areacode")))
        return res

    def get_ai_video_left(self) -> int:
        """当前剩余免费 AI 视频生成次数（privilegeVrbtAIVideoLeftNum）。

        计数口径（官方规则）：每 3 天获赠 3 次，新赠时旧机会清零不叠加；
        抽奖获得的「AI制作体验券」到账会增加该计数。"""
        res = self._en_api(
            {"mobile": self.phone, "aid": ACTIVITY_ID, "channelId": CHANNEL_ID, "portal": PORTAL},
            "ismp/IsmpApi/queryAiMakePkgInfo",
        )
        data = res.get("data") or {}
        try:
            return int(data.get("privilegeVrbtAIVideoLeftNum") or 0)
        except (TypeError, ValueError):
            return 0

    def get_scores(self) -> Dict[str, Any]:
        """总点数/剩余可用点数（totalScore 含已消耗；remainingScore 可用于抽奖/兑换）。"""
        return self._en_api(
            {"activityId": ACTIVITY_ID, "mobile": self.phone, "channelId": CHANNEL_ID, "portal": PORTAL},
            "act/LaborApi/getOperationTotalScoreOrRemainingScore",
        )

    def draw_lottery(self) -> Dict[str, Any]:
        """点数抽奖一次（扣 20 点）。

        响应 data.awardIndex 属于 THANK_YOU_AWARD_INDEXES 时为谢谢参与/无效，
        否则中奖（20/40点数、AI体验券*1/*3、1元话费），奖名取 name/prizeName 字段。"""
        return self._en_api(
            {"activityId": ACTIVITY_ID, "mobile": self.phone, "channelId": CHANNEL_ID, "portal": PORTAL},
            "act/LaborApi/operationIntegralLottery",
        )

    def redeem_phone_bill(self) -> Dict[str, Any]:
        """1000 点数兑换 10 元话费（限量 1000 份先到先得，兑完返回售罄提示）。"""
        return self._en_api(
            {"activityId": ACTIVITY_ID, "mobile": self.phone, "channelId": CHANNEL_ID, "portal": PORTAL},
            "act/LaborApi/operationIntegralRedeemPrize",
        )

    @staticmethod
    def prize_label(res: Dict[str, Any]) -> str:
        """把抽奖响应归纳为可读奖名。"""
        if res.get("code") != "0000":
            return ""
        data = res.get("data") or {}
        idx = str(data.get("awardIndex") or "")
        if idx in THANK_YOU_AWARD_INDEXES:
            return "谢谢参与"
        name = str(data.get("name") or data.get("prizeName") or data.get("awardName") or "").strip()
        return name or (f"awardIndex={idx}" if idx else "未知奖品")

    def get_templates(self) -> List[Dict[str, Any]]:
        """活动推荐模板列表（含预置提示词），与 H5 同款 de/api 明文调用。"""
        res = self._de_api(
            {"pageNo": 1, "pageSize": 50, "activityId": ACTIVITY_ID},
            "diy/DiyVideoApi/queryActRecommendTemplateList",
        )
        data = res.get("data") or {}
        items = data.get("list") or []
        return [t for t in items if isinstance(t, dict) and t.get("templateId")]

    @staticmethod
    def template_prompt(template: Dict[str, Any]) -> str:
        """取模板预置提示词（textPrompt 为 JSON 数组字符串，逐条 prompt 拼接）。"""
        raw = template.get("textPrompt") or ""
        try:
            arr = json.loads(raw)
            prompts = [str(x.get("prompt") or "") for x in arr if isinstance(x, dict)]
            return "\n".join(p for p in prompts if p)
        except Exception:
            return str(raw)

    def submit_make(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """提交一次 AI 视频生成（提交成功即 +20 积分，生成异步进行）。"""
        base_name = str(template.get("videoName") or template.get("labelName") or "AI视频")
        suffix = f"{random.randint(0, 999999):06d}"
        payload = {
            "channelId": CHANNEL_ID,
            "portal": PORTAL,
            "mobile": self.phone,
            "openId": "",
            "makeId": "",
            "background": "",
            "userPhotos": "",
            "userWords": self.template_prompt(template),
            "templateName": f"{base_name}{suffix}",
            "videoName": f"{base_name}{suffix}",
            "templateId": str(template.get("templateId") or ""),
            "templateConfId": str(template.get("templateConfId") or ""),
            "aid": ACTIVITY_ID,
            "inviterMobile": "",
            "aiPack": 0,
            "arrangeId": "",
            "autoOrderUgc": 0,
            "aiGatewayImagMakeId": "",
            "fromType": "",
            "sessionId": "",
            "voice": "",
            "videoOwnerCode": "",
            "videoResourceCode": "",
            "workId": "",
            "imageMakeType": "",
            "songId": "",
            "imageRate": "",
            "productionType": "",
        }
        return self._post_encrypted("/hapi/diy_video/au/template_make_add_v2", payload, timeout=40)

    def query_make_result(self, make_id: str) -> Dict[str, Any]:
        return self._de_api(
            {"mobile": self.phone, "videoId": make_id},
            "diy/DiyVideoApi/querySingleDiyResult",
        )


def _env_flag(name: str, default: bool) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw not in ("0", "false", "off", "no")


def run_imusic_luck(http: Any, ticket: str, phone: str = "") -> Dict[str, Any]:
    """执行一次「AI视频创作赢话费」日常流程。

    策略（2026-10-03 按用户实测反馈定稿）：
      1. 制作次数完全以服务端剩余计数为准（自动检测，不依赖放量周期假设），
         有就提交用光——提交成功即 +20 点到账，无需等待生成完成。
      2. 点数优先兑换 10 元话费（1000 点，每日限量先到先得，code=10003=当日抢完；
         前端兑换链路无验证码）。任务每次运行到达 1000 点即发起兑换。
      3. 兑换失败（售罄/风控）才退回抽奖，且默认保留 1000 点兑换储备只抽超出部分
         （实测抽奖中奖概率低，攒兑优先）。

    开关（环境变量）：
      TELECOM_IMUSIC_REDEEM        达标 1000 点自动兑换 10 元话费，默认开
      TELECOM_IMUSIC_DRAW_ON_FAIL  兑换失败后退回抽奖，默认开
      TELECOM_IMUSIC_DRAW          无条件每日抽奖，默认关
      TELECOM_IMUSIC_DRAW_RESERVE  抽奖保留的点数储备，默认 1000（0=全量抽完）

    返回统一结构 {"status", "msg", "issue", "score", "gain", "videos", "left",
    "draws", "prizes", "redeemed", "redeem_err"}；失败不抛异常，由调用方决定是否影响主任务结果。
    """
    out: Dict[str, Any] = {"status": "跳过", "msg": "", "issue": "", "score": "", "gain": 0,
                           "videos": 0, "left": None, "draws": 0, "prizes": [], "redeemed": "", "redeem_err": ""}
    if not HAS_CRYPTO:
        out["msg"] = "缺少 pycryptodome"
        return out
    if not ticket:
        out["msg"] = "无现签 ticket"
        return out

    client = ImusicLuckClient(http, ticket, phone)
    try:
        if not client.login():
            out["status"] = "失败"
            out["msg"] = "ticket 登录失败"
            return out

        # 当前期次（开奖信息，仅展示）
        issue_res = client.get_issue_info()
        issue_data = issue_res.get("data") or {}
        out["issue"] = str(issue_data.get("issueName") or "")

        # 归属省/市（补写 H5 同款 Province/City Cookie，会话补全）
        client.get_user_area()

        def _read_scores() -> Dict[str, Any]:
            return client.get_scores().get("data") or {}

        score_before = str(_read_scores().get("totalScore") or "")
        left = client.get_ai_video_left()
        out["left"] = left

        # 1. 用光免费制作次数：完全以服务端剩余计数为准（privilegeVrbtAIVideoLeftNum），
        #    不依赖任何放量周期假设；提交成功即 +20 点到账，无需等待生成完成
        submitted = 0
        submit_err = ""
        if left > 0:
            # 仿 App 链路的加密手机号换取（提交前的活跃会话请求，非必需参数来源）
            client.get_encrypt_mobile()
            templates = client.get_templates()
            if not templates:
                submit_err = "模板列表为空"
            for i in range(left):
                if templates:
                    template = templates[i % len(templates)]
                else:
                    break
                make_res = client.submit_make(template)
                data = make_res.get("data") or {}
                if make_res.get("code") == "0000" and (data.get("success") or data.get("makeId")):
                    submitted += 1
                    print(f"    [imusic] 提交生成#{submitted}: {data.get('makeId')} ({template.get('videoName')})", flush=True)
                else:
                    submit_err = str(data.get("message") or make_res.get("desc") or "提交被拒绝")
                    print(f"    [imusic] 提交失败: {submit_err[:60]}", flush=True)
                    break
                time.sleep(1.5)
        out["videos"] = submitted

        # 2. 点数优先兑换 10 元话费（每日限量、先到先得；code=10003 即当日份额已抢完）。
        #    兑换在每次任务运行（电信任务 00:50 档）到达 1000 点即发起，无前置验证码环节；
        #    若服务端风控/验证码拦截，会以非 0000 code+desc 返回，如实上报并走抽奖退路。
        scores_now = _read_scores()
        out["score"] = str(scores_now.get("totalScore") or "")
        remaining = scores_now.get("remainingScore")
        try:
            remaining = int(remaining or 0)
        except (TypeError, ValueError):
            remaining = 0
        redeem_failed = False
        if _env_flag("TELECOM_IMUSIC_REDEEM", True) and remaining >= REDEEM_COST:
            redeem_res = client.redeem_phone_bill()
            code = str(redeem_res.get("code"))
            if code == "0000":
                remaining -= REDEEM_COST
                out["redeemed"] = "10元话费"
                print("    [imusic] 🎉 1000点已兑换10元话费（次月25日前到账）", flush=True)
            else:
                redeem_failed = True
                out["redeem_err"] = ("今日话费份额已被抢完" if code == "10003"
                                     else str(redeem_res.get("desc") or redeem_res.get("message") or f"code={code}"))
                print(f"    [imusic] 兑换失败({code}): {out['redeem_err'][:60]}", flush=True)

        # 3. 抽奖退路：仅在兑换失败（或显式常开）时进行，且默认保留 1000 点兑换储备、
        #    只抽超出部分——点数回收为体验券/小额点数，同时不破坏攒兑目标。
        draw_mode = _env_flag("TELECOM_IMUSIC_DRAW", False) or (
            redeem_failed and _env_flag("TELECOM_IMUSIC_DRAW_ON_FAIL", True))
        if draw_mode:
            try:
                reserve = int((os.getenv("TELECOM_IMUSIC_DRAW_RESERVE") or "").strip() or REDEEM_COST)
            except ValueError:
                reserve = REDEEM_COST
            while remaining - DRAW_COST >= reserve and out["draws"] < MAX_DRAWS_PER_RUN:
                draw_res = client.draw_lottery()
                if draw_res.get("code") != "0000":
                    print(f"    [imusic] 抽奖停止: {str(draw_res.get('desc'))[:60]}", flush=True)
                    break
                out["draws"] += 1
                remaining -= DRAW_COST
                label = client.prize_label(draw_res)
                out["prizes"].append(label)
                print(f"    [imusic] 抽奖#{out['draws']}: {label}", flush=True)
                time.sleep(1.2)
            # 抽奖可能中点数，重读一次实际余额
            remaining = _read_scores().get("remainingScore") or remaining

        try:
            out["gain"] = int(out["score"]) - int(score_before)
        except (TypeError, ValueError):
            out["gain"] = 0
        out["left"] = client.get_ai_video_left()
        if submitted > 0 or out["draws"] > 0 or out["redeemed"]:
            out["status"] = "成功"
        elif submit_err:
            out["status"] = "失败"
        else:
            out["status"] = "无剩余次数"
        if not out["msg"]:
            parts = []
            if submitted:
                parts.append(f"提交{submitted}次生成，点数+{out['gain']}")
            if out["redeemed"]:
                parts.append(f"已兑{out['redeemed']}")
            elif out["redeem_err"]:
                parts.append(f"兑换未成({out['redeem_err'][:20]})")
            if out["draws"]:
                parts.append(f"抽奖{out['draws']}次")
            if left <= 0 and not submitted:
                parts.append("免费次数已用完")
            out["msg"] = "；".join(parts) or (submit_err or "无可用动作")
        return out
    except Exception as e:
        out["status"] = "失败"
        out["msg"] = f"异常: {type(e).__name__}: {str(e)[:80]}"
        return out
