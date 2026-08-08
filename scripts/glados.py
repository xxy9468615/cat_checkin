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

from common import Http, main_guard


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
            print(f"{Emoji.COOKIE}[{self.cookie_index}] {Emoji.DOMAIN}[{self.domain}] {message}")

    @staticmethod
    def _safe_json(resp) -> Dict[str, Any]:
        data = resp.json({})
        return data if isinstance(data, dict) else {}

    def status(self, cookie: str) -> Tuple[str, int]:
        resp = self.http.request("GET", self.base + "/api/user/status", headers=self._headers(cookie))
        data = self._safe_json(resp)
        code = int(data.get("code", CHECKIN_FAILURE) or CHECKIN_FAILURE)
        left_days = (data.get("data") or {}).get("leftDays")
        if left_days is None:
            self._log(f"{Emoji.FAIL} 查询剩余天数失败: {data}", force=True)
            return "None 天", code
        days = int(float(left_days))
        self._log(f"{Emoji.SUCCESS} 剩余 {days} 天")
        return f"{days} 天", code

    def checkin(self, cookie: str) -> Tuple[str, int, int, str]:
        resp = self.http.request(
            "POST",
            self.base + "/api/user/checkin",
            headers=self._headers(cookie),
            form={"token": self.domain},
        )
        data = self._safe_json(resp)
        code = int(data.get("code", CHECKIN_FAILURE) or CHECKIN_FAILURE)
        message = str(data.get("message", ""))
        points = int(float(data.get("points", 0) or 0))

        if code == CHECKIN_SUCCESS:
            self._log(f"{Emoji.SUCCESS} 签到成功 +{points} 积分 {message}", force=True)
            return "签到成功", code, points, message
        if code == CHECKIN_REPEAT:
            self._log(f"{Emoji.REPEAT} 重复签到 {message}", force=True)
            return "重复签到", code, 0, message

        self._log(f"{Emoji.FAIL} 签到失败 {message or data}", force=True)
        return "签到失败", CHECKIN_FAILURE, 0, message or str(data)

    def points(self, cookie: str) -> Tuple[str, int]:
        resp = self.http.request("GET", self.base + "/api/user/points", headers=self._headers(cookie))
        data = self._safe_json(resp)
        value = data.get("points")
        if value is None:
            self._log(f"{Emoji.FAIL} 查询积分失败: {data}", force=True)
            return "None 积分", 0
        points = int(float(value))
        self._log(f"{Emoji.POINTS} 总积分 {points}")
        return f"{points} 积分", points

    def exchange(self, cookie: str, plan: str, required_points: int, current_points: int) -> str:
        if current_points < required_points:
            return f"积分不足，跳过兑换({current_points}/{required_points})"

        resp = self.http.request(
            "POST",
            self.base + "/api/user/exchange",
            headers=self._headers(cookie),
            form={"planType": plan},
        )
        data = self._safe_json(resp)
        code = int(data.get("code", CHECKIN_FAILURE) or CHECKIN_FAILURE)
        message = str(data.get("message", ""))
        if code == 0:
            self._log(f"{Emoji.EXCHANGE} 兑换成功 {plan}", force=True)
            return f"兑换成功: {plan}"
        self._log(f"{Emoji.WARNING} 兑换失败: {message or data}", force=True)
        return f"兑换失败: {message or data}"


class Checker:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.results: List[Result] = []

    def run(self) -> None:
        print("【GLaDOS 签到兑换】")
        if self.config.accounts:
            total = len(self.config.accounts) * len(self.config.domains)
            print(f"共 {len(self.config.accounts)} 个账号, {len(self.config.domains)} 个域名, 共 {total} 个任务")
            task_index = 0
            for acc_idx, (email, pwd) in enumerate(self.config.accounts, 1):
                print(f"{Emoji.START} 处理账号 {acc_idx} ({email})")
                for domain in self.config.domains:
                    task_index += 1
                    api = GladosAPI(domain, acc_idx, self.config.verbose)
                    try:
                        cookie = api.login(email, pwd)
                        res = self._run_one(api, cookie, acc_idx, domain)
                        res.account_name = email
                        self.results.append(res)
                    except Exception as e:
                        print(f"❌ 账号 {email} on {domain} 执行失败: {e}")
                        res = Result(cookie_index=acc_idx, domain=domain, account_name=email, status=f"失败: {e}")
                        self.results.append(res)
        elif self.config.cookies:
            total = len(self.config.cookies) * len(self.config.domains)
            print(f"共 {len(self.config.cookies)} 个 Cookie, {len(self.config.domains)} 个域名, 共 {total} 个任务")
            task_index = 0
            for cookie_index, cookie in enumerate(self.config.cookies, 1):
                print(f"{Emoji.START} 处理 Cookie {cookie_index}")
                for domain in self.config.domains:
                    task_index += 1
                    api = GladosAPI(domain, cookie_index, self.config.verbose)
                    res = self._run_one(api, cookie, cookie_index, domain)
                    self.results.append(res)

    def _run_one(self, api: GladosAPI, cookie: str, cookie_index: int, domain: str) -> Result:
        result = Result(cookie_index=cookie_index, domain=domain)
        result.days, _status_code = api.status(cookie)
        result.status, result.code, result.points, result.message = api.checkin(cookie)
        points_total_str, points_total = api.points(cookie)
        result.points_total = points_total

        if self.config.auto_exchange:
            required = EXCHANGE_PLANS[self.config.exchange_plan]
            result.exchange = api.exchange(cookie, self.config.exchange_plan, required, points_total)
        else:
            result.exchange = "未开启自动兑换"

        print(
            f"结果: {result.status}, 获得 {result.points} 积分, "
            f"剩余 {result.days}, 总 {points_total_str}, {result.exchange}"
        )
        return result

    def summary(self) -> Tuple[str, str]:
        success = sum(1 for r in self.results if r.code == CHECKIN_SUCCESS)
        repeat = sum(1 for r in self.results if r.code == CHECKIN_REPEAT)
        fail = sum(1 for r in self.results if r.code == CHECKIN_FAILURE)
        title = f"GLaDOS 签到, 成功{success}, 失败{fail}, 重复{repeat}"
        lines = [
            f"#{idx} {r.account_name or r.domain} P:{r.points} 剩余:{r.days} 总积分:{r.points_total} | {r.status} | {r.exchange}"
            for idx, r in enumerate(self.results, 1)
        ]
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
    print("\n========== 签到总结 ==========")
    print(title)
    print(content)
    pushdeer_send(config.push_key, title, content)

    if any(r.code == CHECKIN_FAILURE for r in checker.results):
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
