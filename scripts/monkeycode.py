#!/usr/bin/env python3
# cron: 9 9 * * *
# new Env("Monkeycode 签到")
import datetime as dt
import os
import re
from common import Http, env, main_guard

PREFIX = "MONKEYCODE_"

def extract_cookie_value(cookie_str: str, key: str) -> str:
    m = re.search(r'(?:^|;\s*)' + re.escape(key) + r'=([^;]+)', cookie_str)
    return m.group(1) if m else ""

def format_amount(val: float | int) -> str:
    # 积分单位换算：后端数值 1000 代表 1 积分（例如 93000 = 93 积分, 100000 = 100 积分）
    points = abs(val) / 1000
    if points.is_integer():
        return str(int(points))
    return f"{points:.2f}"

def format_time(ts: int | float | None) -> str:
    if not ts:
        return ""
    d = dt.datetime.fromtimestamp(ts, tz=dt.timezone(dt.timedelta(hours=8)))
    return d.strftime("%Y-%m-%d %H:%M:%S")

def main():
    print("【MonkeyCode 签到】")
    cookie = env(PREFIX, "cookie")
    h = Http()
    headers = {
        "Cookie": cookie,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,zh-TW;q=0.5",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }

    # 1. 执行签到请求
    resp = h.request("GET", "https://monkeycode-ai.com/api/v1/users/wallet/checkin", headers=headers)

    if resp.code in (401, 403):
        raise RuntimeError("🚨 Cookie 已失效 (HTTP 401/403)，请更新 QL_MONKEYCODE_cookie 环境变量！")

    # 检查 Set-Cookie 保活续期
    set_cookie_hdr = resp.headers.get("Set-Cookie", "") if resp.headers else ""
    if set_cookie_hdr:
        new_session = extract_cookie_value(set_cookie_hdr, "monkeycode_ai_session")
        if new_session:
            print(f"🔄 Session 自动延期 (Session: {new_session[:10]}...)")

    checkin_data = resp.json({})
    code = checkin_data.get("code", 1)
    message = checkin_data.get("message", "未知错误")
    checked_in = checkin_data.get("data", {}).get("checked_in", False)

    if code == 0:
        if checked_in:
            print("✅ Monkeycode 今日已完成签到，积分已发放")
        else:
            print("✅ Monkeycode 签到成功")
    elif code in (401, 403, 10001) or "unauthorized" in str(message).lower():
        raise RuntimeError(f"🚨 Cookie 认证失败 ({message})，请重新获取 cookie")
    else:
        print(f"❌ Monkeycode 签到异常: {message} (code={code})")

    # 2. 查询钱包基本信息 (精准余额与每日 Token 额度)
    resp_wallet = h.request("GET", "https://monkeycode-ai.com/api/v1/users/wallet", headers=headers)
    wallet_data = resp_wallet.json({})
    w_info = wallet_data.get("data", {})
    if w_info:
        raw_balance = w_info.get("balance", 0)
        balance_str = format_amount(raw_balance)
        daily_bal = w_info.get("daily_token_balance", 0)
        daily_lim = w_info.get("daily_token_limit", 0)
        print(f"💰 当前可用余额: {balance_str} 积分")
        if daily_lim > 0:
            print(f"⚡ 今日免费 Token 额度: {daily_bal} / {daily_lim}")

    # 3. 查询交易明细
    resp_tx = h.request("GET", "https://monkeycode-ai.com/api/v1/users/wallet/transaction?size=20&page=1", headers=headers)
    tx_data = resp_tx.json({})
    transactions = tx_data.get("data", {}).get("transactions", [])

    if transactions:
        print("📜 最近交易明细:")
        for tx in transactions[:5]:
            kind = str(tx.get("kind", ""))
            inout = str(tx.get("inout_type", ""))
            raw_amt = tx.get("amount", 0)
            amt_str = format_amount(raw_amt)
            remark = tx.get("remark", "")
            created_at = format_time(tx.get("created_at"))

            # 正负号判断: 消费/扣除为减号 -，签到/充值/奖励为加号 +
            if "consumption" in kind or "deduct" in kind or "expense" in kind or inout == "out":
                sign_str = f"-{amt_str}"
            else:
                sign_str = f"+{amt_str}"

            time_part = f" ({created_at})" if created_at else ""
            print(f"  • {remark}{time_part}: {sign_str} 积分")

    if os.getenv("DEBUG"):
        import json
        print("\n[DEBUG] checkin:", json.dumps(checkin_data, ensure_ascii=False))
        print("[DEBUG] wallet:", json.dumps(wallet_data, ensure_ascii=False))

main_guard(main)
