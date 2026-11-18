#!/usr/bin/env python3
# cron: 10 9 * * *
# new Env("GLaDOS 签到兑换")
"""GLaDOS standalone task: multi-account, multi-cookie, multi-domain check-in and auto exchange.

Environment compatibility:
  GLADOS_COOKIE_1, _2...  Multi-account cookie sequence variables (cookie auth ONLY).
  GLADOS_COOKIES          Cookies split by "&", newline, or "&&".
  GLADOS_EXCHANGE_PLAN    plan100 / plan200 / plan500, default: plan500.
  GLADOS_AUTO_EXCHANGE    true/false, default: true.
  GLADOS_VERBOSE          true/false, default: false.
  GLADOS_DOMAINS          Comma-separated domains, default: glados.cloud.
  PUSHDEER_SENDKEY        Optional PushDeer key, sends summary without extra dependency.

Auth note: the upstream has no password-login API. POST /api/authorization is a
dead endpoint that always answers {"code":1} regardless of payload, so only the
cookie (koa:sess + koa:sess.sig) flow is supported. Cookies must be pasted from
a real browser session and refreshed manually once the server-side session dies.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from common import (
    Http,
    env_seq,
    load_kv_state,
    main_guard,
    mask_str,
    sanitize_snippet,
    save_kv_state,
)
from proxy_manager import ProxyEndpoint, get_task_proxy_endpoints
import cookie_validity as cv


class Emoji:
    SUCCESS = "✅"
    FAIL = "❌"
    REPEAT = "🔄"
    WARNING = "⚠️"
    START = "🚀"
    COOKIE = "🍪"
    DOMAIN = "🌐"
    POINTS = "💰"
    EXCHANGE = "🎁"


CHECKIN_SUCCESS = 0
CHECKIN_REPEAT = 1
CHECKIN_FAILURE = -2
CHECKIN_FAILURE_DEVICE = 4
COOKIE_INVALID = -3

# 签到挑战（2026-11 上游改版）：POST /api/user/checkin 不再接受裸 {"token": domain}，
# 必须携带 GET /api/user/checkin/challenge 下发的 nonce 与客户端证明：
#   proof = hex(SHA-256(nonce + "." + "glados-observe-v1"))
# 常量取自控制台前端 checkinProof 分包的字节数组（g/l/a/d/o/s/-/o/b/s/e/r/v/e/-/v/1）。
PROOF_SALT = "glados-observe-v1"
# 前端在拿到挑战后至少等待 2500ms 才提交，服务端按首次请求耗时判定自动化，不能省。
CHALLENGE_MIN_AGE_SEC = 2.5
# Chrome TLS/JA3 指纹档位：与 DEFAULT_UA 的 Chrome/131 版本号保持一致，
# 避免 UA 与 sec-ch-ua 自相矛盾（curl_cffi 0.16.3 支持 chrome131 profile）。
IMPERSONATE = "chrome131"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# ── 真浏览器签到（Turnstile 只能由真实浏览器解出）───────────────────────────
# 2026-11-18 实测结论（家庭宽带 TW 出口 + Chrome131 JA3 也一样）：
#   纯 HTTP 客户端拿到的挑战必然带 turnstile 站点密钥，POST 恒定
#   {"code":..,"reason":"turnstile"}；headful 真 Chrome 在同一个家宽出口上
#   5 秒内自动过盾。因此签到必须交给真浏览器，HTTP 链路只做查询与兑换。
# 另外服务端把会话绑定到登录设备：设备不一致时返回
#   {"code":4,"reason":"device-mismatch","loginDevice":"Windows","currentDevice":"Linux"}
# 浏览器必须按登录设备伪装 UA/platform，否则过盾也会被判定为异地设备。
DEVICE_PROFILES: Dict[str, Dict[str, str]] = {
    "windows": {
        "ua": USER_AGENT,
        "platform": "Win32",
        "ch_platform": '"Windows"',
        "mobile": "?0",
        "locale": "en-US",
    },
    "macos": {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "platform": "MacIntel",
        "ch_platform": '"macOS"',
        "mobile": "?0",
        "locale": "en-US",
    },
    "linux": {
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "platform": "Linux x86_64",
        "ch_platform": '"Linux"',
        "mobile": "?0",
        "locale": "en-US",
    },
    "android": {
        "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "platform": "Linux armv8l",
        "ch_platform": '"Android"',
        "mobile": "?1",
        "locale": "en-US",
    },
    "ios": {
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) CriOS/131.0.0.0 Mobile/15E148 Safari/604.1",
        "platform": "iPhone",
        "ch_platform": '"iOS"',
        "mobile": "?1",
        "locale": "en-US",
    },
}
DEFAULT_DEVICE = "windows"
# 浏览器签到开关：auto（默认可用时启用）/ off（只走 HTTP，用于排查）
BROWSER_MODE_ENV = "GLADOS_BROWSER"


def resolve_device(login_device: str) -> str:
    """把服务端的 loginDevice 归一化为 DEVICE_PROFILES 键。"""
    key = (login_device or "").strip().lower()
    if key in DEVICE_PROFILES:
        return key
    if key.startswith("mac") or key.startswith("darwin"):
        return "macos"
    if "win" in key:
        return DEFAULT_DEVICE
    if "android" in key:
        return "android"
    if "ios" in key or "iphone" in key:
        return "ios"
    if "linux" in key:
        return "linux"
    return DEFAULT_DEVICE


def parse_cookie_pairs(cookie: str) -> Dict[str, str]:
    """把浏览器导出的 Cookie 串拆成 name->value（Playwright add_cookies 用）。"""
    pairs: Dict[str, str] = {}
    for part in (cookie or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name:
            pairs[name] = value
    return pairs


def coerce_code(raw: Any) -> int:
    """严格解析业务 code：只接受整数（含整值浮点/数字串），bool 与非数字一律失败。

    浏览器链路与 HTTP 链路口径必须一致；`code=0` 是成功值，不能用 `or` 兜底
    （0 是 falsy 会被吞成失败）。
    """
    if isinstance(raw, bool) or raw is None or raw == "":
        return CHECKIN_FAILURE
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return CHECKIN_FAILURE
    if value != int(value):
        return CHECKIN_FAILURE
    return int(value)

# Cookie 失效时响应中常见的登录关键词（命中即判定登录态过期）
# 注意 "没有权限"/"No permission"（code=-2）是 koa:sess 签名校验失败时服务端的
# 固定返回——不带 Cookie 请求也会得到同一结果，与越权/封号无关，必须归入
# 失效判定，否则会被当成普通签到失败白白烧掉熔断次数。
AUTH_FAILURE_KEYWORDS = ("login", "unauthorized", "请登录", "重新登录", "没有权限", "no permission")


class CookieExpiredError(RuntimeError):
    """GLaDOS 登录态（Cookie）已失效，需要重新登录更新 GLADOS_COOKIES。"""

EXCHANGE_PLANS = {
    "plan100": 100,
    "plan200": 200,
    "plan500": 500,
}


@dataclass
class Result:
    cookie_index: int
    domain: str
    account_name: str = ""
    status: str = "签到失败"
    code: int = CHECKIN_FAILURE
    points: int = 0
    days: str = "None 天"
    points_total: int = 0
    exchange: str = "未兑换"
    message: str = ""


class BrowserCheckin:
    """真浏览器签到器：headful Chrome + 家宽出口 + 登录设备指纹。

    一个浏览器实例服务全部账号（每次 new_context 隔离 Cookie），避免重复启动
    Chromium 吃掉任务超时。Playwright 缺失或无显示环境（headful 起不来）时返回
    None，由调用方退回 HTTP 链路（会拿到 reason=turnstile，如实失败）。
    """

    def __init__(self, proxy: str = "", verbose: bool = False) -> None:
        self.proxy = proxy
        self.verbose = verbose
        self._pw = None
        self._browser = None
        self._failed = False
        # 浏览器上下文的 Cookie 到期时间（expires > 0 才是真实证据；上游当前是纯会话）
        self.last_learned: Dict[str, int] = {}

    @staticmethod
    def enabled() -> bool:
        mode = (os.getenv(BROWSER_MODE_ENV) or "auto").strip().lower()
        return mode not in ("0", "false", "off", "no")

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[browser] {message}")

    def _ensure_browser(self):
        if self._browser is not None:
            return self._browser
        if self._failed:
            return None
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("⚠️ 未安装 Playwright，签到退回 HTTP 链路（Turnstile 将无法通过）")
            self._failed = True
            return None
        try:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(
                channel="chrome",
                headless=False,
                proxy={"server": self.proxy} if self.proxy else None,
                args=["--disable-blink-features=AutomationControlled"],
            )
            self._log("headful chrome ready")
        except Exception as exc:  # noqa: BLE001  无显示/无 Chrome 时退回 HTTP
            print(f"⚠️ 浏览器启动失败（需要 xvfb DISPLAY 与 Chrome）：{str(exc)[:160]}")
            self._failed = True
            try:
                if self._pw is not None:
                    self._pw.stop()
            except Exception:
                pass
            self._pw = None
            self._browser = None
            return None
        return self._browser

    def checkin(self, cookie: str, domain: str,
                device: str = DEFAULT_DEVICE) -> Optional[Tuple[str, int, int, str]]:
        """返回与 GladosAPI.checkin 相同的四元组；基础设施不可用返回 None。"""
        browser = self._ensure_browser()
        if browser is None:
            return None
        profile = DEVICE_PROFILES.get(device) or DEVICE_PROFILES[DEFAULT_DEVICE]
        base = f"https://{domain}"
        ctx = None
        try:
            ctx = browser.new_context(
                locale=profile["locale"],
                timezone_id="Asia/Shanghai",
                viewport={"width": 1366, "height": 900},
                user_agent=profile["ua"],
                extra_http_headers={
                    "sec-ch-ua": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
                    "sec-ch-ua-mobile": profile["mobile"],
                    "sec-ch-ua-platform": profile["ch_platform"],
                },
            )
            cookies = [
                {"name": name, "value": value, "domain": domain, "path": "/", "secure": True}
                for name, value in parse_cookie_pairs(cookie).items()
            ]
            if not cookies:
                return None
            ctx.add_cookies(cookies)
            # navigator.platform / userAgentData 必须与 UA 一致，否则设备指纹露馅
            ctx.add_init_script(
                "Object.defineProperty(navigator,'platform',{get:()=>%r});"
                "Object.defineProperty(navigator,'userAgentData',{get:()=>({"
                "platform:%r,brands:[{brand:'Chromium',version:'131'},"
                "{brand:'Google Chrome',version:'131'}]})});"
                % (profile["platform"], profile["ch_platform"].strip('"'))
            )
            page = ctx.new_page()
            try:
                cdp = ctx.new_cdp_session(page)
                cdp.send("Emulation.setUserAgentOverride", {
                    "userAgent": profile["ua"],
                    "acceptLanguage": "en-US,en;q=0.9",
                    "platform": profile["platform"],
                })
            except Exception:
                pass

            captured: List[Tuple[int, str]] = []

            def on_response(resp) -> None:
                try:
                    if "/api/user/checkin" in resp.url and resp.request.method == "POST" \
                            and "/challenge" not in resp.url:
                        captured.append((resp.status, resp.text()))
                except Exception:
                    pass

            page.on("response", on_response)
            page.goto(base + "/console/checkin", wait_until="domcontentloaded", timeout=45000)
            page.wait_for_timeout(4000)
            button = None
            for _ in range(6):
                for candidate in page.query_selector_all("button"):
                    text = (candidate.inner_text() or "").strip().lower()
                    if text in ("checkin", "check in") or "签到" in text:
                        button = candidate
                        break
                if button is not None:
                    break
                page.wait_for_timeout(2500)
            if button is None:
                self._log("未找到签到按钮")
                return None
            button.click()
            for _ in range(12):
                page.wait_for_timeout(5000)
                if captured:
                    break
            if not captured:
                self._log("等待签到响应超时（Turnstile 未通过）")
                return None
            status_code, body = captured[-1]
            if status_code != 200:
                # 非 200 一律不解析业务码：网关/CF 的 HTML 错误页可能恰好含 code 字样
                self._log(f"签到接口返回 HTTP {status_code}，不判定业务结果")
                return None
            data = json.loads(body)
            # 浏览器上下文是 Set-Cookie 的最权威来源；只有 expires > 0 才算证据
            try:
                for item in ctx.cookies():
                    name = str(item.get("name") or "")
                    expires = item.get("expires")
                    if name and isinstance(expires, (int, float)) and expires > 0:
                        self.last_learned[name] = int(expires)
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001  浏览器链路异常统一退回 HTTP
            self._log(f"浏览器签到异常: {str(exc)[:160]}")
            return None
        finally:
            if ctx is not None:
                try:
                    ctx.close()
                except Exception:
                    pass

        # 与 HTTP 链路共用严格解析：缺失/非整数一律失败，绝不把缺字段当成 code=0
        code = coerce_code(data.get("code"))
        message = str(data.get("message", ""))
        points = int(float(data.get("points", 0) or 0))
        reason = str(data.get("reason", "") or "")
        if code == CHECKIN_SUCCESS:
            return "签到成功", code, points, message
        if code == CHECKIN_REPEAT:
            return "重复签到", code, 0, message
        if code == CHECKIN_FAILURE_DEVICE or reason == "device-mismatch":
            login_device = str(data.get("loginDevice", "") or "")
            detail = message or "登录设备与当前设备不一致"
            return "需重新登录", CHECKIN_FAILURE, 0, (
                f"{detail} (reason=device-mismatch, loginDevice={login_device or '?'})")
        # 不回显原始响应体：可能夹带邮箱等个人信息，只保留服务端文案与 reason
        detail = message or "签到失败（响应无 message 字段）"
        if reason:
            detail += f" (reason={reason})"
        return "签到失败", CHECKIN_FAILURE, 0, detail

    def close(self) -> None:
        for closer in (getattr(self._browser, "close", None),
                       getattr(self._pw, "stop", None)):
            try:
                if closer:
                    closer()
            except Exception:
                pass
        self._browser = None
        self._pw = None


class Config:
    def __init__(self) -> None:
        self.push_key = os.getenv("PUSHDEER_SENDKEY", "").strip()
        self.cookies = self._load_cookies()
        self.domains = self._load_domains()
        self.exchange_plan = self._load_exchange_plan()
        self.auto_exchange = self._bool_env("GLADOS_AUTO_EXCHANGE", True)
        self.verbose = self._bool_env("GLADOS_VERBOSE", False)
        self.proxies = self._load_proxies()
        self.egress = self._resolve_egress()

    @staticmethod
    def _load_proxies() -> List[ProxyEndpoint]:
        """出口候选：GLADOS_PROXY(*_PROXIES/*_BACKUP_PROXIES) 优先，全部缺失才复用
        NodeSeek 的台湾家宽节点。

        上游 CF 风控按出口 IP 信誉打分，脚本自身不持有住宅出口，直接复用工作流
        统一 sing-box 入站（NodeSeek 已绑定的 TW-X1 节点），避免再维护一套节点。
        """
        endpoints = get_task_proxy_endpoints("glados")
        if not endpoints:
            endpoints = get_task_proxy_endpoints("nodeseek")
        return endpoints

    def _resolve_egress(self) -> Optional[ProxyEndpoint]:
        """确定唯一出网出口。

        依赖家宽出口的任务不应在代理缺失时静默直连（会拿到 reason=turnstile 且
        掩盖代理故障，参照 NodeSeek 的「公平失败」约定）；只有显式
        `GLADOS_ALLOW_DIRECT=1`（本机家宽排查）才允许无代理直连。
        """
        if self.proxies:
            return self.proxies[0]
        if self._bool_env("GLADOS_ALLOW_DIRECT", False):
            print("⚠️ 未配置 GLaDOS 代理出口，按 GLADOS_ALLOW_DIRECT=1 直连出网")
            return None
        raise RuntimeError(
            "未找到 GLaDOS 代理出口（GLADOS_PROXY / GLADOS_PROXIES / "
            "GLADOS_BACKUP_PROXIES，或工作流注入的 NODESEEK_PROXY）；"
            "家宽出口缺失时签到必被 Turnstile 拒绝。本机直连排查请设 GLADOS_ALLOW_DIRECT=1"
        )

    def _load_cookies(self) -> List[str]:
        # 优先扫描 COOKIE_1, COOKIE_2 序列，回退至 COOKIES / cookie (含 && 切分)
        cookies = env_seq("GLADOS_", "cookie", required=False)
        if not cookies:
            cookies = env_seq("GLADOS_", "cookies", required=False)
        return [c.strip() for c in cookies if c.strip()]

    def _load_domains(self) -> List[str]:
        raw = os.getenv("GLADOS_DOMAINS", "glados.cloud")
        domains = [x.strip().removeprefix("https://").removeprefix("http://").rstrip("/") for x in raw.split(",")]
        return [x for x in domains if x]

    def _load_exchange_plan(self) -> str:
        plan = os.getenv("GLADOS_EXCHANGE_PLAN", "plan500").strip() or "plan500"
        if plan not in EXCHANGE_PLANS:
            return "plan500"
        return plan

    @staticmethod
    def _bool_env(name: str, default: bool) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.lower() in {"1", "true", "yes", "y", "on"}


class GladosAPI:
    def __init__(self, domain: str, cookie_index: int, verbose: bool = False,
                 proxy: str = "") -> None:
        self.domain = domain
        self.cookie_index = cookie_index
        self.verbose = verbose
        # 出口走代理（CI 复用 NodeSeek 的 sing-box 台湾节点），并且必须叠加 Chrome
        # TLS/JA3 指纹：Turnstile 的风险打分是「IP 信誉 + 指纹」的联合判定，裸 urllib
        # 指纹在数据中心出口上即便换了 IP 也会被要求令牌。
        self.http = Http(
            follow_redirects=True,
            proxy=proxy,
            task_name="glados",
            impersonate=IMPERSONATE,
        )
        self.base = f"https://{domain}"
        # 本轮从 Set-Cookie 学到的 {cookie 名: 到期 epoch}，给共享有效期引擎用
        self.learned: Dict[str, int] = {}

    def _learn(self, resp) -> None:
        """从响应 Set-Cookie 学习真实到期证据（当前上游只发会话 cookie，通常为空）。"""
        try:
            self.learned = cv.merge_learned(self.learned, cv.learn_from_response(resp))
        except Exception:
            pass

    def _headers(self, cookie: str) -> Dict[str, str]:
        return {
            "Cookie": cookie,
            "Origin": self.base,
            "Referer": f"{self.base}/console/checkin",
            "User-Agent": USER_AGENT,
            # Chrome 默认 keep-alive；common.Http 的 "Connection: close" 默认值
            # 与浏览器指纹不自洽，这里显式覆盖。
            "Connection": "keep-alive",
        }

    def _log(self, message: str, force: bool = False) -> None:
        if self.verbose or force:
            print(f"[{self.domain}] {message}")

    @staticmethod
    def _safe_json(resp) -> Dict[str, Any]:
        data = resp.json({})
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _parse_code(data: Dict[str, Any]) -> int:
        """解析业务 code（与浏览器链路共用同一严格口径，见 coerce_code）。"""
        return coerce_code(data.get("code"))

    def _ensure_auth(self, resp, data: Dict[str, Any]) -> None:
        """检测 Cookie 是否已失效（HTTP 非 200 / 非 JSON / 缺 code / 命中登录关键词）。

        判定失效时抛出 CookieExpiredError 并附带响应摘要，避免事后翻日志找原因。
        """
        if resp.code != 200:
            raise CookieExpiredError(f"HTTP {resp.code}，响应: {sanitize_snippet(resp.text, 120)}")
        if not data:
            raise CookieExpiredError(
                f"响应非 JSON（可能返回了登录页），响应: {sanitize_snippet(resp.text, 120)}"
            )
        if "code" not in data:
            raise CookieExpiredError(
                f"响应缺少 code 字段，响应: {sanitize_snippet(str(data), 150)}"
            )
        message = str(data.get("message", "")).lower()
        if any(kw in message for kw in AUTH_FAILURE_KEYWORDS):
            raise CookieExpiredError(
                f"接口提示需要重新登录，响应: {sanitize_snippet(str(data), 150)}"
            )

    def status(self, cookie: str) -> Tuple[str, int]:
        resp = self.http.request("GET", self.base + "/api/user/status", headers=self._headers(cookie))
        self._learn(resp)
        data = self._safe_json(resp)
        self._ensure_auth(resp, data)
        code = self._parse_code(data)
        left_days = (data.get("data") or {}).get("leftDays")
        if left_days is None:
            self._log(f"{Emoji.FAIL} 查询剩余天数失败: {sanitize_snippet(str(data), 150)}", force=True)
            return "None 天", code
        days = int(float(left_days))
        return f"{days} 天", code

    def challenge(self, cookie: str) -> Dict[str, Any]:
        """获取签到挑战（nonce / ttl / 是否强制 Cloudflare Turnstile）。

        挑战接口抖动（5xx/网关错误/非 JSON）属于临时故障，返回空字典交由调用方
        降级处理；只有明确表明登录态失效（HTTP 200 + code=-2/登录关键词）才抛
        CookieExpiredError，避免一次 503 把整个账号判成 Cookie 过期。
        """
        resp = self.http.request(
            "GET",
            self.base + "/api/user/checkin/challenge",
            headers=self._headers(cookie),
        )
        self._learn(resp)
        data = self._safe_json(resp)
        if resp.code != 200 or not data:
            self._log(f"⚠️ 获取签到挑战失败: HTTP {resp.code}（临时故障，按无挑战处理）", force=True)
            return {}
        self._ensure_auth(resp, data)
        code = self._parse_code(data)
        if code != CHECKIN_SUCCESS:
            self._log(f"⚠️ 获取签到挑战失败: code={code}（按无挑战处理）", force=True)
            return {}
        return data

    @staticmethod
    def proof(nonce: str) -> str:
        """复刻前端 checkinProof：SHA-256(nonce + "." + PROOF_SALT) 的十六进制摘要。"""
        return hashlib.sha256(f"{nonce}.{PROOF_SALT}".encode("utf-8")).hexdigest()

    def checkin(self, cookie: str) -> Tuple[str, int, int, str]:
        started_at = time.monotonic()
        challenge = self.challenge(cookie)
        nonce = str(challenge.get("nonce") or "")
        ts_required = bool(challenge.get("turnstile"))

        payload: Dict[str, Any] = {"token": self.domain}
        if nonce:
            payload["nonce"] = nonce
            payload["proof"] = self.proof(nonce)
            # 无 Turnstile 时前端上报 "off"；有站点密钥但拿不到令牌时上报 "timeout"。
            # 脚本无法执行 Cloudflare 挑战，令牌只能由服务端按风险降级放行。
            payload["tsState"] = "timeout" if ts_required else "off"
            remaining = CHALLENGE_MIN_AGE_SEC - (time.monotonic() - started_at)
            if remaining > 0:
                time.sleep(remaining)
            if ts_required:
                self._log("⚠️ 签到挑战要求 Cloudflare Turnstile，脚本无法生成令牌，尝试无令牌提交", force=True)

        resp = self.http.request(
            "POST",
            self.base + "/api/user/checkin",
            headers=self._headers(cookie),
            json_data=payload,
        )
        self._learn(resp)
        data = self._safe_json(resp)
        self._ensure_auth(resp, data)
        code = self._parse_code(data)
        message = str(data.get("message", ""))
        reason = str(data.get("reason", "") or "")
        points = int(float(data.get("points", 0) or 0))

        if code == CHECKIN_SUCCESS:
            return "签到成功", code, points, message
        if code == CHECKIN_REPEAT:
            return "重复签到", code, 0, message
        if code == CHECKIN_FAILURE_DEVICE or reason == "device-mismatch":
            detail = message or "登录设备与当前设备不一致"
            # 归入常规失败码：summary/退出码/熔断器只认 CHECKIN_FAILURE/COOKIE_INVALID，
            # 新增码会让失败被静默吞掉（不退出、不计入标题）。
            return "需重新登录", CHECKIN_FAILURE, 0, f"{detail} (reason=device-mismatch，请在浏览器重新登录后更新 Cookie)"

        detail = message or "签到失败（响应无 message 字段）"
        if reason:
            detail += f" (reason={reason})"
        if not nonce:
            detail += " (未取到签到挑战 nonce)"
        return "签到失败", CHECKIN_FAILURE, 0, detail

    def points(self, cookie: str) -> Tuple[str, int]:
        resp = self.http.request("GET", self.base + "/api/user/points", headers=self._headers(cookie))
        self._learn(resp)
        data = self._safe_json(resp)
        self._ensure_auth(resp, data)
        value = data.get("points")
        if value is None:
            return "0 积分", 0
        pts = int(float(value))
        return f"{pts} 积分", pts

    def exchange(self, cookie: str, plan: str, required_points: int, current_points: int) -> Tuple[str, int]:
        """执行兑换逻辑：支持多轮循环兑换及距离目标积分的差距计算。
        返回 (兑换描述信息, 成功兑换次数)。
        """
        if current_points < required_points:
            diff = required_points - current_points
            return f"距离兑换目标 ({plan} / {required_points}积分) 还差 {diff} 积分", 0

        success_count = 0
        rem_points = current_points
        last_msg = ""

        while rem_points >= required_points:
            resp = self.http.request(
                "POST",
                self.base + "/api/user/exchange",
                headers=self._headers(cookie),
                json_data={"planType": plan},
            )
            self._learn(resp)
            data = self._safe_json(resp)
            self._ensure_auth(resp, data)
            code = self._parse_code(data)
            msg = str(data.get("message", ""))
            if code == 0:
                success_count += 1
                rem_points -= required_points
            else:
                last_msg = msg or str(data)
                break

        if success_count > 0:
            return f"🎁 成功兑换 {plan}" + (f" x{success_count}" if success_count > 1 else ""), success_count

        return f"兑换失败: {last_msg}", 0


class Checker:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.results: List[Result] = []
        self.devices: Dict[int, str] = {}
        # 浏览器与 HTTP 链路共用同一条住宅出口；浏览器签到是该出口上唯一能过盾的路径
        proxy_url = config.egress.url if config.egress else ""
        self.browser: Optional[BrowserCheckin] = (
            BrowserCheckin(proxy=proxy_url, verbose=config.verbose)
            if BrowserCheckin.enabled() else None
        )

    def run(self) -> None:
        print("【GLaDOS 签到兑换】")
        # 上游无密码登录接口，仅支持 Cookie 认证
        endpoint = self.config.egress
        tag = endpoint.display_name if endpoint else "直连（GLADOS_ALLOW_DIRECT=1）"
        try:
            for cookie_index, cookie in enumerate(self.config.cookies, 1):
                for domain in self.config.domains:
                    self.results.append(self._run_account(cookie, cookie_index, domain, endpoint, tag))
        finally:
            if self.browser is not None:
                self.browser.close()

    def _run_account(self, cookie: str, cookie_index: int, domain: str,
                     endpoint: Optional[ProxyEndpoint], tag: str) -> Result:
        """单账号单域名只跑一次：重试与熔断统一交给框架（规则 6），脚本内不再重跑。"""
        api = GladosAPI(domain, cookie_index, self.config.verbose,
                        proxy=endpoint.url if endpoint else "")
        try:
            return self._run_one(api, cookie, cookie_index, domain, tag)
        except CookieExpiredError as e:
            return self._cookie_invalid_result(cookie_index, domain, "", str(e))
        except Exception as e:  # noqa: BLE001  单个账号异常不中断其余账号
            print(f"❌ 账号 {cookie_index} on {domain} 执行失败: {e}")
            return Result(cookie_index=cookie_index, domain=domain, account_name="",
                          status=f"失败: {e}")

    def _checkin(self, api: GladosAPI, cookie: str, cookie_index: int,
                 domain: str) -> Tuple[str, int, int, str]:
        """真浏览器优先；设备不匹配时按服务端 loginDevice 换指纹重试一次。

        浏览器链路不可用（未装 Playwright / 无 xvfb / 启动失败）时才退回 HTTP，
        此时必然拿到 reason=turnstile，属于如实失败而不是静默假成功。
        """
        if self.browser is None:
            return api.checkin(cookie)
        device = self.devices.get(cookie_index, DEFAULT_DEVICE)
        res = self.browser.checkin(cookie, domain, device)
        if res is None:
            return api.checkin(cookie)
        mismatch = re.search(r"loginDevice=([^)\s]+)", res[3] or "")
        if mismatch:
            login_device = resolve_device(mismatch.group(1))
            if login_device != device:
                print(f"🔁 账号 {cookie_index} 登录设备为 {mismatch.group(1)}，按该设备指纹重试")
                retry = self.browser.checkin(cookie, domain, login_device)
                if retry is not None:
                    # 只有重试拿到真实业务结果才记住新设备，失败/None 保留原缓存
                    if retry[1] in (CHECKIN_SUCCESS, CHECKIN_REPEAT):
                        self.devices[cookie_index] = login_device
                    return retry
                return api.checkin(cookie)
        elif res[1] in (CHECKIN_SUCCESS, CHECKIN_REPEAT):
            # 签到成功即确认该设备指纹有效，后续域名复用
            self.devices.setdefault(cookie_index, device)
        return res

    def _cookie_invalid_result(self, cookie_index: int, domain: str, account_name: str, detail: str) -> Result:
        """生成 Cookie 失效结果并打印明确的修复指引，跳过该账号后续流程。"""
        acc_label = mask_str(account_name) if account_name else f"账号 {cookie_index}"
        print(f"📧 账号: {acc_label}")
        print(f"🍪 Cookie 已失效: 请重新登录 https://{domain} 复制 Cookie 并更新 GLADOS_COOKIES")
        print(f"   判定依据: {detail}")
        print("")
        return Result(
            cookie_index=cookie_index,
            domain=domain,
            account_name=account_name,
            status="Cookie 已失效",
            code=COOKIE_INVALID,
            message=detail,
        )

    def _run_one(self, api: GladosAPI, cookie: str, cookie_index: int, domain: str,
                 egress: str = "") -> Result:
        result = Result(cookie_index=cookie_index, domain=domain)
        result.days, _ = api.status(cookie)
        result.status, result.code, result.points, result.message = self._checkin(
            api, cookie, cookie_index, domain)
        _, points_total = api.points(cookie)
        result.points_total = points_total

        if self.config.auto_exchange:
            required = EXCHANGE_PLANS[self.config.exchange_plan]
            result.exchange, ex_count = api.exchange(cookie, self.config.exchange_plan, required, points_total)
            # 若兑换成功，刷新最新的剩余天数
            if ex_count > 0:
                result.days, _ = api.status(cookie)
        else:
            result.exchange = "未开启自动兑换"

        expiry_tag = self._expiry_tag(api, cookie, cookie_index, result.code)
        acc_label = mask_str(result.account_name) if result.account_name else f"账号 {cookie_index}"
        egress_desc = f" | 🌐 出口: {egress}" if egress else ""
        print(f"📧 账号: {acc_label}{expiry_tag}{egress_desc}")
        if result.code == CHECKIN_SUCCESS:
            print(f"✅ 签到状态: 签到成功 (+{result.points} 积分)")
        elif result.code == CHECKIN_REPEAT:
            print(f"🔄 签到状态: 今日已签到")
        else:
            print(f"❌ 签到状态: 签到失败 ({result.message})")

        print(f"📅 剩余天数: {result.days}")
        print(f"💰 当前积分: {result.points_total} 积分")
        print(f"🎯 兑换进度: {result.exchange}")
        print("")
        return result

    def _state_paths(self, cookie_index: int) -> Tuple[str, str]:
        """每账号独立的 Cookie 有效期状态（与 52pojie/cloud189 同构）。"""
        return (f"cat_checkin:state:glados_{cookie_index}",
                f".glados_state_{cookie_index}.json")

    def _expiry_tag(self, api: GladosAPI, cookie: str, cookie_index: int,
                    code: int) -> str:
        """渲染 Cookie 有效期标签（唯一实现委托共享引擎，规则 8）。

        GLaDOS 的会话 cookie 是纯会话态（无 Expires、无 _expire），拿不到真实到期
        时间时 build_tag 会输出「有效期未知（已使用 N 天）」，并在 45 天老化基线
        升级为 ⚠️ 黄卡——这是当前唯一诚实的口径，绝不编造倒计时。
        """
        try:
            redis_key, state_file = self._state_paths(cookie_index)
            state = load_kv_state(redis_key, state_file) or {}
            learned = cv.merge_learned(
                getattr(api, "learned", {}) or {},
                getattr(self.browser, "last_learned", {}) or {},
            )
            cv.update_state(state, cookie, learned)
            if code in (CHECKIN_SUCCESS, CHECKIN_REPEAT):
                cv.mark_ok(state)  # 成功运行日入账：无到期证据时按天数反推寿命
            save_kv_state(redis_key, state_file, state)
            return cv.build_tag(state, cookie_str=cookie, learned=learned)
        except Exception as exc:  # 有效期渲染绝不影响签到主流程
            print(f"⚠️ Cookie 有效期计算失败: {exc}")
            return " | 🔑 Cookie 有效期未知"

    def summary(self) -> Tuple[str, str]:
        success = sum(1 for r in self.results if r.code in (CHECKIN_SUCCESS, CHECKIN_REPEAT))
        fail = sum(1 for r in self.results if r.code == CHECKIN_FAILURE)
        expired = sum(1 for r in self.results if r.code == COOKIE_INVALID)
        title = f"GLaDOS 签到, 成功{success}, 失败{fail}, Cookie失效{expired}"
        lines = []
        for idx, r in enumerate(self.results, 1):
            name = mask_str(r.account_name) if r.account_name else f"账号{r.cookie_index}"
            if r.code == CHECKIN_SUCCESS:
                st = "签到成功"
            elif r.code == CHECKIN_REPEAT:
                st = "今日已签到"
            elif r.code == COOKIE_INVALID:
                st = "Cookie失效(需更新)"
            else:
                st = "签到失败"
            lines.append(f"#{idx} {name} | {st} | 剩余:{r.days} | 积分:{r.points_total} | {r.exchange}")
        return title, "\n".join(lines)


def pushdeer_send(push_key: str, title: str, content: str) -> None:
    if not push_key:
        return
    query = urllib.parse.urlencode({"pushkey": push_key, "text": title, "desp": content})
    resp = Http().request("GET", "https://api2.pushdeer.com/message/push?" + query)
    if resp.code == 200:
        print("✅ PushDeer 推送完成")
    else:
        print(f"⚠️ PushDeer 推送失败: HTTP {resp.code} {resp.text[:200]}")


def main() -> None:
    config = Config()
    if not config.cookies:
        raise RuntimeError("未找到 GLADOS_COOKIE_1/2/3 或 GLADOS_COOKIES（上游无密码登录，仅支持 Cookie）")

    checker = Checker(config)
    checker.run()
    title, content = checker.summary()
    pushdeer_send(config.push_key, title, content)

    if any(r.code in (CHECKIN_FAILURE, COOKIE_INVALID) for r in checker.results):
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
