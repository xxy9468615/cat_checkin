#!/usr/bin/env python3
# cron: 10 9 * * *
# new Env("GLaDOS 签到兑换")
"""GLaDOS standalone task: multi-account, multi-cookie, multi-domain check-in and auto exchange.

Environment compatibility:
  GLADOS_ACCOUNTS         Accounts format "email:password", split by newline or "&&". Preferred.
  GLADOS_email            Single account email.
  GLADOS_password         Single account password.
  GLADOS_COOKIES          Cookies split by "&", newline, or "&&".
  GLADOS_EXCHANGE_PLAN    plan100 / plan200 / plan500, default: plan500.
  GLADOS_AUTO_EXCHANGE    true/false, default: true.
  GLADOS_VERBOSE          true/false, default: false.
  GLADOS_DOMAINS          Comma-separated domains, default: glados.cloud,railgun.info.
  PUSHDEER_SENDKEY        Optional PushDeer key, sends summary without extra dependency.
"""

from __future__ import annotations

import os
import re
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from common import Http, main_guard, mask_str


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
COOKIE_INVALID = -3

# Cookie 失效时响应中常见的登录关键词（命中即判定登录态过期）
AUTH_FAILURE_KEYWORDS = ("login", "unauthorized", "请登录", "重新登录")


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


class Config:
    def __init__(self) -> None:
        self.push_key = os.getenv("PUSHDEER_SENDKEY", "").strip()
        self.accounts = self._load_accounts()
        self.cookies = self._load_cookies()
        self.domains = self._load_domains()
        self.exchange_plan = self._load_exchange_plan()
        self.auto_exchange = self._bool_env("GLADOS_AUTO_EXCHANGE", True)
        self.verbose = self._bool_env("GLADOS_VERBOSE", False)

    def _load_accounts(self) -> List[Tuple[str, str]]:
        raw = os.getenv("GLADOS_ACCOUNTS", "").strip() or os.getenv("QL_GLADOS_ACCOUNTS", "").strip()
        accounts = []
        if raw:
            for chunk in re.split(r"\n|&&", raw):
                chunk = chunk.strip()
                if ":" in chunk:
                    u, _, p = chunk.partition(":")
                    if u.strip() and p.strip():
                        accounts.append((u.strip(), p.strip()))
        email = os.getenv("GLADOS_email", "").strip() or os.getenv("QL_GLADOS_email", "").strip()
        pwd = os.getenv("GLADOS_password", "").strip() or os.getenv("QL_GLADOS_password", "").strip()
        if email and pwd and (email, pwd) not in accounts:
            accounts.append((email, pwd))
        return accounts

    def _load_cookies(self) -> List[str]:
        raw = os.getenv("GLADOS_COOKIES", "").strip()
        if not raw:
            raw = os.getenv("QL_GLADOS_cookie", "").strip()
        if not raw:
            return []
        return [x.strip() for x in re.split(r"\n|&&|(?<!;)&", raw) if x.strip()]

    def _load_domains(self) -> List[str]:
        raw = os.getenv("GLADOS_DOMAINS", "glados.cloud,railgun.info")
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
    def __init__(self, domain: str, cookie_index: int, verbose: bool = False) -> None:
        self.domain = domain
        self.cookie_index = cookie_index
        self.verbose = verbose
        self.http = Http()
        self.base = f"https://{domain}"

    def login(self, email: str, passwd: str) -> str:
        resp = self.http.request(
            "POST",
            self.base + "/api/authorization",
            headers={"Origin": self.base, "Referer": f"{self.base}/console/login"},
            json_data={"email": email, "passwd": passwd},
        )
        data = self._safe_json(resp)
        code = data.get("code")
        if code != 0:
            msg = data.get("message") or f"code={code}"
            raise RuntimeError(f"GLaDOS 登录失败 ({email}): {msg}")

        cookies = [f"{c.name}={c.value}" for c in self.http.jar]
        if not cookies:
            raise RuntimeError("GLaDOS 登录成功但未返回 Cookie")
        return "; ".join(cookies)

    def _headers(self, cookie: str) -> Dict[str, str]:
        return {
            "Cookie": cookie,
            "Origin": self.base,
            "Referer": f"{self.base}/console/checkin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
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
        """解析业务 code。注意 code=0 是成功值，不能用 `or` 兜底（0 是 falsy 会被吞掉）。"""
        raw = data.get("code")
        if raw is None or raw == "":
            return CHECKIN_FAILURE
        try:
            return int(float(raw))
        except (TypeError, ValueError):
            return CHECKIN_FAILURE

    def _ensure_auth(self, resp, data: Dict[str, Any]) -> None:
        """检测 Cookie 是否已失效（HTTP 非 200 / 非 JSON / 缺 code / 命中登录关键词）。

        判定失效时抛出 CookieExpiredError 并附带响应摘要，避免事后翻日志找原因。
        """
        if resp.code != 200:
            raise CookieExpiredError(f"HTTP {resp.code}，响应: {resp.text[:120]}")
        if not data:
            raise CookieExpiredError(f"响应非 JSON（可能返回了登录页），响应: {resp.text[:120]}")
        if "code" not in data:
            raise CookieExpiredError(f"响应缺少 code 字段，响应: {str(data)[:150]}")
        message = str(data.get("message", "")).lower()
        if any(kw in message for kw in AUTH_FAILURE_KEYWORDS):
            raise CookieExpiredError(f"接口提示需要重新登录，响应: {str(data)[:150]}")

    def status(self, cookie: str) -> Tuple[str, int]:
        resp = self.http.request("GET", self.base + "/api/user/status", headers=self._headers(cookie))
        data = self._safe_json(resp)
        self._ensure_auth(resp, data)
        code = self._parse_code(data)
        left_days = (data.get("data") or {}).get("leftDays")
        if left_days is None:
            self._log(f"{Emoji.FAIL} 查询剩余天数失败: {data}", force=True)
            return "None 天", code
        days = int(float(left_days))
        return f"{days} 天", code

    def checkin(self, cookie: str) -> Tuple[str, int, int, str]:
        resp = self.http.request(
            "POST",
            self.base + "/api/user/checkin",
            headers=self._headers(cookie),
            json_data={"token": self.domain},
        )
        data = self._safe_json(resp)
        self._ensure_auth(resp, data)
        code = self._parse_code(data)
        message = str(data.get("message", ""))
        points = int(float(data.get("points", 0) or 0))

        if code == CHECKIN_SUCCESS:
            return "签到成功", code, points, message
        if code == CHECKIN_REPEAT:
            return "重复签到", code, 0, message

        return "签到失败", CHECKIN_FAILURE, 0, message or str(data)

    def points(self, cookie: str) -> Tuple[str, int]:
        resp = self.http.request("GET", self.base + "/api/user/points", headers=self._headers(cookie))
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

    def run(self) -> None:
        print("【GLaDOS 签到兑换】")
        if self.config.accounts:
            total = len(self.config.accounts) * len(self.config.domains)
            for acc_idx, (email, pwd) in enumerate(self.config.accounts, 1):
                for domain in self.config.domains:
                    api = GladosAPI(domain, acc_idx, self.config.verbose)
                    try:
                        cookie = api.login(email, pwd)
                        res = self._run_one(api, cookie, acc_idx, domain)
                        res.account_name = email
                        self.results.append(res)
                    except CookieExpiredError as e:
                        self.results.append(self._cookie_invalid_result(acc_idx, domain, email, str(e)))
                    except Exception as e:
                        print(f"❌ 账号 {mask_str(email)} on {domain} 执行失败: {e}")
                        res = Result(cookie_index=acc_idx, domain=domain, account_name=email, status=f"失败: {e}")
                        self.results.append(res)
        elif self.config.cookies:
            for cookie_index, cookie in enumerate(self.config.cookies, 1):
                for domain in self.config.domains:
                    api = GladosAPI(domain, cookie_index, self.config.verbose)
                    try:
                        res = self._run_one(api, cookie, cookie_index, domain)
                    except CookieExpiredError as e:
                        res = self._cookie_invalid_result(cookie_index, domain, "", str(e))
                    self.results.append(res)

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

    def _run_one(self, api: GladosAPI, cookie: str, cookie_index: int, domain: str) -> Result:
        result = Result(cookie_index=cookie_index, domain=domain)
        result.days, _ = api.status(cookie)
        result.status, result.code, result.points, result.message = api.checkin(cookie)
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

        acc_label = mask_str(result.account_name) if result.account_name else f"账号 {cookie_index}"
        print(f"📧 账号: {acc_label}")
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
    if not config.accounts and not config.cookies:
        raise RuntimeError("未找到 GLADOS_ACCOUNTS (或 GLADOS_email/GLADOS_password) 或 GLADOS_COOKIES")

    checker = Checker(config)
    checker.run()
    title, content = checker.summary()
    pushdeer_send(config.push_key, title, content)

    if any(r.code in (CHECKIN_FAILURE, COOKIE_INVALID) for r in checker.results):
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
