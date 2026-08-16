#!/usr/bin/env python3
# cron: 9 9 * * *
# new Env("Monkeycode 签到")
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from common import Http, env, ensure, main_guard, mask_str

PREFIX = "MONKEYCODE_"
BASE = "https://monkeycode-ai.com"
ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def format_amount(val):
    points = abs(val) / 1000
    if points == int(points):
        return str(int(points))
    return f"{points:.2f}"


def format_time(ts):
    if not ts:
        return ""
    d = dt.datetime.fromtimestamp(ts, tz=dt.timezone(dt.timedelta(hours=8)))
    return d.strftime("%Y-%m-%d %H:%M:%S")


def _fnv1a(seed):
    h = 2166136261
    for ch in seed:
        h = ((h ^ ord(ch)) * 16777619) & 0xFFFFFFFF
    return h


def _prng(seed, length):
    """Cap 的 xorshift32 伪随机串生成，与前端 cap_wasm 一致。"""
    state = _fnv1a(seed)
    out = []
    while len(out) * 8 < length:
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        out.append(f"{state:08x}")
    return "".join(out)[:length]


def solve_challenge(token, challenge):
    """对每个子挑战暴力搜索 nonce，使 sha256(salt+nonce) 以 target 开头。"""
    count = int(challenge["c"])
    salt_len = int(challenge["s"])
    difficulty = int(challenge["d"])
    solutions = []
    for i in range(1, count + 1):
        salt = _prng(f"{token}{i}", salt_len).encode()
        target = _prng(f"{token}{i}d", difficulty)
        nonce = 0
        while not hashlib.sha256(salt + str(nonce).encode()).hexdigest().startswith(target):
            nonce += 1
        solutions.append(nonce)
    return solutions


def api(h, method, path, headers, **kwargs):
    """请求 API 并统一识别登录态失效。返回 (Response, 解析后的 body)。"""
    resp = h.request(method, f"{BASE}{path}", headers=headers, **kwargs)
    if resp.code in (401, 403):
        raise RuntimeError(f"🚨 Cookie 认证失败 (HTTP {resp.code})，请重新获取 cookie")
    body = resp.json(None)
    if isinstance(body, dict) and body.get("code") in (401, 403, 10001):
        raise RuntimeError(f"🚨 Cookie 认证失败 ({body.get('message')})，请重新获取 cookie")
    return resp, body


def fetch_captcha_token(h, headers):
    """走 Cap 工作量证明流程换取 captcha_token。"""
    resp, body = api(h, "POST", "/api/v1/public/captcha/challenge", headers, data=b"")
    body = body or {}
    token = body.get("token")
    challenge = body.get("challenge")
    ensure(
        bool(token) and isinstance(challenge, dict),
        f"获取验证码挑战失败 (HTTP {resp.code}): {resp.text[:200]}",
    )

    started = time.time()
    solutions = solve_challenge(token, challenge)
    if os.getenv("DEBUG"):
        print(
            f"🧩 已求解验证码 {len(solutions)} 题（难度 {challenge.get('d')}），"
            f"耗时 {time.time() - started:.1f}s"
        )

    resp, body = api(
        h,
        "POST",
        "/api/v1/public/captcha/redeem",
        headers,
        json_data={"token": token, "solutions": solutions},
    )
    body = body or {}
    ensure(
        bool(body.get("success")) and bool(body.get("token")),
        f"验证码校验未通过 (HTTP {resp.code}): {resp.text[:200]}",
    )
    return body["token"]


def jar_cookie(h):
    """把 cookie jar 里的内容拼成 Cookie 头格式。"""
    return "; ".join(f"{c.name}={c.value}" for c in h.jar)


def session_alive(h, headers):
    """探测登录态，不抛异常。返回 (alive: bool, user_name: str)。"""
    resp = h.request("GET", f"{BASE}/api/v1/users/status", headers=headers)
    body = resp.json(None)
    if isinstance(body, dict) and body.get("code") == 0:
        user = (body.get("data") or {}).get("user") or {}
        if user:
            name = user.get("name") or user.get("email") or ""
            return True, name
    return False, ""


def persist_cookie(cookie_value):
    """本地运行时把新 session 写回 .env；若 .env 存在但无 Key 则自动追加。"""
    if not cookie_value or not ENV_FILE.exists():
        return False

    possible_keys = {
        f"{PREFIX}cookie".lower(),
        f"{PREFIX}COOKIE".lower(),
        f"QL_{PREFIX}cookie".lower(),
        f"QL_{PREFIX}COOKIE".lower(),
    }

    try:
        content = ENV_FILE.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        target_line_idx = -1

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                k = stripped.split("=", 1)[0].strip().lower()
                if k in possible_keys:
                    target_line_idx = i
                    break

        if target_line_idx != -1:
            old_line = lines[target_line_idx]
            key_part = old_line.split("=", 1)[0].rstrip()
            newline = "\n" if old_line.endswith("\n") else ""
            lines[target_line_idx] = f"{key_part}={cookie_value}{newline}"
        else:
            last_has_newline = lines and lines[-1].endswith("\n")
            prefix_nl = "" if (not lines or last_has_newline) else "\n"
            lines.append(f"{prefix_nl}{PREFIX}cookie={cookie_value}\n")

        ENV_FILE.write_text("".join(lines), encoding="utf-8")
        return True
    except OSError:
        return False


def login(h, headers, email, password):
    """账密登录，成功后 session cookie 落在 h.jar 里。返回用户名。"""
    login_headers = dict(headers, Referer=f"{BASE}/login")
    captcha_token = fetch_captcha_token(h, login_headers)
    resp = h.request(
        "POST",
        f"{BASE}/api/v1/users/password-login",
        headers=login_headers,
        json_data={"email": email, "password": password, "captcha_token": captcha_token},
    )
    body = resp.json(None)
    if not isinstance(body, dict) or body.get("code") != 0:
        msg = body.get("message") if isinstance(body, dict) else resp.text[:200]
        raise RuntimeError(f"🚨 账密登录失败 (HTTP {resp.code}): {msg}")

    ensure(bool(jar_cookie(h)), "登录响应未返回 session cookie")
    user = body.get("data") or {}
    name = user.get("name") or user.get("email") or email
    return name


def build_session(cookie, email, password, is_multi=False):
    """cookie 优先；失效或缺失时用账密登录换取新 session。返回 (h, headers, user_name)。"""
    base_headers = {"Origin": BASE, "Referer": f"{BASE}/console/tasks"}
    has_credentials = bool(email and password)

    if cookie:
        h = Http()
        headers = dict(base_headers, Cookie=cookie)
        alive, user_name = session_alive(h, headers)
        if alive:
            return h, headers, user_name or "用户"
        if not has_credentials:
            raise RuntimeError("🚨 Cookie 已失效，且未配置 MONKEYCODE_email / MONKEYCODE_password，无法自动登录")
    elif not has_credentials:
        raise RuntimeError("缺少有效凭证：需提供 Cookie 或 邮箱+密码")

    # 干净的 jar，避免旧 cookie 干扰；登录后由 jar 自动携带 session
    h = Http()
    headers = dict(base_headers)
    user_name = login(h, headers, email, password)

    if not is_multi and persist_cookie(jar_cookie(h)):
        print("💾 新 Session Cookie 已成功回写保存至 .env")
    return h, headers, user_name


def get_wallet_info_lines(h, headers) -> List[str]:
    lines = []
    _, wallet = api(h, "GET", "/api/v1/users/wallet", headers)
    w_info = (wallet or {}).get("data") or {}
    if w_info:
        bal_str = format_amount(w_info.get("balance", 0))
        lines.append(f"💰 可用余额: {bal_str} 积分")
        daily_lim = w_info.get("daily_token_limit", 0)
        if daily_lim > 0:
            bal_t = w_info.get("daily_token_balance", 0)
            lines.append(f"⚡ 每日免费 Token 额度: {bal_t:,} / {daily_lim:,}")

    _, tx_body = api(h, "GET", "/api/v1/users/wallet/transaction?size=20&page=1", headers)
    transactions = ((tx_body or {}).get("data") or {}).get("transactions") or []
    if transactions:
        lines.append("📜 最近交易明细:")
        for tx in transactions[:2]:
            kind = str(tx.get("kind", ""))
            inout = str(tx.get("inout_type", ""))
            amt_str = format_amount(tx.get("amount", 0))
            sign = "-" if ("consumption" in kind or "deduct" in kind or "expense" in kind or inout == "out") else "+"
            remark = tx.get("remark", "")
            remark = remark.replace("每日签到奖励", "每日签到").replace("签到奖励", "每日签到")
            time_part = ""
            if tx.get("created_at"):
                d = dt.datetime.fromtimestamp(tx.get("created_at"), tz=dt.timezone(dt.timedelta(hours=8)))
                time_part = f" ({d.strftime('%m-%d %H:%M')})"
            lines.append(f"  • {remark}: {sign}{amt_str} 积分{time_part}")
    return lines


def _load_accounts() -> List[Dict[str, Optional[str]]]:
    """解析并汇总多账号凭证列表。"""
    raw_accounts = os.getenv(f"{PREFIX}ACCOUNTS", "") or os.getenv(f"QL_{PREFIX}ACCOUNTS", "")
    accounts: List[Dict[str, Optional[str]]] = []
    seen_keys = set()

    if raw_accounts:
        for chunk in re.split(r"\n|&&", raw_accounts):
            chunk = chunk.strip()
            if not chunk:
                continue
            if ":" in chunk:
                u, _, p = chunk.partition(":")
            elif "---" in chunk:
                u, _, p = chunk.partition("---")
            elif "," in chunk:
                u, _, p = chunk.partition(",")
            else:
                u, p = chunk, ""
            u, p = u.strip(), p.strip()
            if u:
                key = u.lower()
                if key not in seen_keys:
                    seen_keys.add(key)
                    if p:
                        accounts.append({"cookie": None, "email": u, "password": p})
                    else:
                        accounts.append({"cookie": u, "email": None, "password": None})

    raw_cookies = os.getenv(f"{PREFIX}COOKIES", "") or os.getenv(f"QL_{PREFIX}COOKIES", "")
    if raw_cookies:
        for chunk in re.split(r"\n|&&", raw_cookies):
            chunk = chunk.strip()
            if not chunk:
                continue
            key = chunk[:32]
            if key not in seen_keys:
                seen_keys.add(key)
                accounts.append({"cookie": chunk, "email": None, "password": None})

    # 兼容单账号环境变量
    single_email = (
        os.getenv(f"{PREFIX}email", "")
        or os.getenv(f"{PREFIX}EMAIL", "")
        or os.getenv(f"QL_{PREFIX}email", "")
        or os.getenv(f"QL_{PREFIX}EMAIL", "")
    ).strip()
    single_pwd = (
        os.getenv(f"{PREFIX}password", "")
        or os.getenv(f"{PREFIX}PASSWORD", "")
        or os.getenv(f"QL_{PREFIX}password", "")
        or os.getenv(f"QL_{PREFIX}PASSWORD", "")
    ).strip()
    single_cookie = (
        os.getenv(f"{PREFIX}cookie", "")
        or os.getenv(f"{PREFIX}COOKIE", "")
        or os.getenv(f"QL_{PREFIX}cookie", "")
        or os.getenv(f"QL_{PREFIX}COOKIE", "")
    ).strip()

    if single_email and single_pwd:
        if single_email.lower() not in seen_keys:
            seen_keys.add(single_email.lower())
            accounts.append({"cookie": single_cookie or None, "email": single_email, "password": single_pwd})
    elif single_cookie and single_cookie[:32] not in seen_keys:
        seen_keys.add(single_cookie[:32])
        accounts.append({"cookie": single_cookie, "email": None, "password": None})

    return accounts


def _run_one(acc: Dict[str, Optional[str]], idx: int, total: int) -> Tuple[bool, str]:
    cookie = acc.get("cookie")
    email = acc.get("email")
    password = acc.get("password")

    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    lines: List[str] = []

    h, headers, user_name = build_session(cookie, email, password, is_multi=(total > 1))
    masked_name = mask_str(user_name or email or "用户")

    resp, status = api(h, "GET", "/api/v1/users/wallet/checkin", headers)
    ensure(
        isinstance(status, dict) and status.get("code") == 0,
        f"查询签到状态失败 (HTTP {resp.code}): {resp.text[:200]}",
    )

    if (status.get("data") or {}).get("checked_in"):
        lines.append(f"{prefix_label}用户【{masked_name}】今日已签到，无需重复签到")
    else:
        captcha_token = fetch_captcha_token(h, headers)
        resp, result = api(
            h,
            "POST",
            "/api/v1/users/wallet/checkin",
            headers,
            json_data={"captcha_token": captcha_token},
        )

        if os.getenv("DEBUG"):
            print("[DEBUG] checkin response:", json.dumps(result, ensure_ascii=False))

        if not isinstance(result, dict):
            raise RuntimeError(f"响应无法解析 (HTTP {resp.code}): {resp.text[:200]}")

        code = result.get("code", -1)
        message = result.get("message", "未知错误")
        checked_in = (result.get("data") or {}).get("checked_in", False) if isinstance(result.get("data"), dict) else False

        if code == 0 and checked_in:
            lines.append(f"{prefix_label}用户【{masked_name}】签到成功，获得 100 积分")
        elif code == 0:
            raise RuntimeError("code=0 但 checked_in=false，签到未生效")
        else:
            raise RuntimeError(f"{message} (code={code})")

    wallet_lines = get_wallet_info_lines(h, headers)
    lines.extend(wallet_lines)
    return True, "\n".join(lines)


def main():
    print("【MonkeyCode 签到】")
    accounts = _load_accounts()
    if not accounts:
        raise SystemExit("缺少环境变量：需配置 MONKEYCODE_ACCOUNTS、MONKEYCODE_cookie 或 MONKEYCODE_email + MONKEYCODE_password")

    total = len(accounts)
    results: List[Tuple[bool, str]] = []

    for idx, acc in enumerate(accounts, 1):
        try:
            ok, msg = _run_one(acc, idx, total)
            print(msg)
            results.append((ok, msg))
        except Exception as e:
            name_hint = mask_str(acc.get("email") or "用户")
            prefix_label = f"[{idx}/{total}] " if total > 1 else ""
            err_msg = f"{prefix_label}用户【{name_hint}】签到失败：{e}"
            print(err_msg)
            results.append((False, err_msg))

    ok_count = sum(1 for ok, _ in results if ok)
    if total > 1:
        print(f"签到总结：成功 {ok_count}/{total}")

    if ok_count != total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
