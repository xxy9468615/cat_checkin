#!/usr/bin/env python3
# cron: 20 9 * * *
# new Env("Sophnet 签到")
import os
import re
import sys
from common import Http, env, main_guard, mask_str

PREFIX = "SOPHNET_"

def load_accounts():
    """支持单账号与多账号格式:
    1. 多账号: SOPHNET_TOKENS="token1|ref_token1\ntoken2|ref_token2" (或仅填 ref_token)
    2. 单账号: SOPHNET_token 与 SOPHNET_refresh_token
    """
    raw_tokens = os.getenv(f"{PREFIX}TOKENS", "").strip() or os.getenv("SOPHNET_TOKENS", "").strip()
    if raw_tokens:
        lines = [x.strip() for x in re.split(r"\n|&&", raw_tokens) if x.strip()]
        accounts = []
        for line in lines:
            if "|" in line:
                t, r = line.split("|", 1)
                accounts.append((t.strip(), r.strip()))
            else:
                accounts.append(("", line.strip()))
        return accounts

    token = (
        os.getenv(f"{PREFIX}token", "").strip()
        or os.getenv(f"{PREFIX}TOKEN", "").strip()
        or os.getenv("SOPHNET_token", "").strip()
    )
    ref_token = (
        os.getenv(f"{PREFIX}refresh_token", "").strip()
        or os.getenv(f"{PREFIX}REFRESH_TOKEN", "").strip()
        or os.getenv("SOPHNET_refresh_token", "").strip()
    )
    if token or ref_token:
        return [(token, ref_token)]
    return []

def run_account(idx: int, token: str, refresh_token: str, h: Http) -> None:
    print(f"\n--- 处理第 {idx} 个 Sophnet 账号 ---")
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    }

    def do_refresh() -> tuple[str, str]:
        nonlocal token, refresh_token
        if not refresh_token:
            raise RuntimeError(f"🚨 账号 #{idx} Token 已过期且未配置 refresh_token，无法自动续期！")

        print(f"🔄 账号 #{idx} 正在使用 Refresh Token 无感续期...")
        resp = h.request(
            "POST",
            "https://sophnet.com/api/sys/login/refresh",
            headers=headers,
            json_data={"refreshToken": refresh_token},
        )
        data = resp.json({})

        status_code = data.get("status")
        if resp.code not in (200, 201) or status_code in (10023, 10025, 1):
            msg = data.get("message") or "Refresh token 无效或已过期"
            raise RuntimeError(f"🚨 账号 #{idx} Refresh Token 续期失败 ({msg})，请从网页重新获取！")

        res = data.get("result") or data.get("data") or data
        token = res.get("token") or res.get("accessToken") or token
        new_ref = res.get("refreshToken")
        if new_ref:
            refresh_token = new_ref
        print(f"✅ 账号 #{idx} 成功刷新令牌！(新 Token: {mask_str(token)})")
        return token, refresh_token

    if not token and refresh_token:
        token, refresh_token = do_refresh()

    clean_token = token.removeprefix("Bearer ").strip()
    headers["Authorization"] = f"Bearer {clean_token}"

    # 1. 尝试签到
    resp = h.request("POST", "https://sophnet.com/api/sys/checkin/do", headers=headers, json_data={})
    data = resp.json({})

    # 若 Token 失效，自动用 refresh_token 刷 Token 后重试
    if data.get("status") in (10023, 10025) or resp.code in (401, 403):
        print(f"⚠️ 账号 #{idx} Token 已失效，自动尝试使用 Refresh Token 续期...")
        token, refresh_token = do_refresh()
        headers["Authorization"] = f"Bearer {token.removeprefix('Bearer ').strip()}"
        resp = h.request("POST", "https://sophnet.com/api/sys/checkin/do", headers=headers, json_data={})
        data = resp.json({})

    status_code = data.get("status", 0)
    msg = data.get("message", "")

    if status_code == 0:
        print(f"✅ 账号 #{idx} Sophnet 签到成功！")
    elif "已签到" in msg:
        print(f"✅ 账号 #{idx} Sophnet 今日已完成签到")
    else:
        # 签到失败必须抛出：否则脚本 exit 0，报告显示成功（假成功）
        raise RuntimeError(f"Sophnet 签到信息: {msg} (status={status_code})")

    # 2. 查询福利与账户状态
    resp_w = h.request("GET", "https://sophnet.com/api/sys/checkin/welfare", headers=headers)
    w_data = resp_w.json({})
    w_res = w_data.get("result") or {}

    checkin_info = w_res.get("checkIn") or {}
    token_summary = w_res.get("tokenSummary") or {}

    balance = token_summary.get("balance") or checkin_info.get("tokenBalance", 0)
    streak = checkin_info.get("currentContinuousDays", 0)
    total_days = checkin_info.get("totalCheckInDays", 0)

    print(f"💰 账号 #{idx} 当前 Token 余额: {balance}")
    print(f"📅 连续签到: {streak} 天 | 累计签到: {total_days} 天")

    if os.getenv("DEBUG"):
        import json
        print("\n[DEBUG] 签到响应:", json.dumps(data, ensure_ascii=False, indent=2))
        print("[DEBUG] 福利响应:", json.dumps(w_data, ensure_ascii=False, indent=2))

def main():
    accounts = load_accounts()
    if not accounts:
        raise RuntimeError("未找到 SOPHNET_TOKENS 或 SOPHNET_token / SOPHNET_refresh_token 配置")

    h = Http()
    print(f"发现 {len(accounts)} 个 Sophnet 账号，开始执行签到...")
    # 单个账号失败不能中断其余账号（refresh token 到期时服务端不会自愈，
    # 必须让其他账号照常签到，并在末尾统一汇报）
    failed = []
    for idx, (token, refresh_token) in enumerate(accounts, 1):
        try:
            run_account(idx, token, refresh_token, h)
        except Exception as e:
            print(f"❌ 账号 #{idx} 处理失败: {e}")
            failed.append(idx)

    if failed:
        ids = "、".join(f"#{i}" for i in failed)
        print(f"\n⚠️ Sophnet 签到总结：{len(accounts) - len(failed)}/{len(accounts)} 成功，账号 {ids} 失败")
        print("   Refresh Token 已过期时需从网页重新抓取 authorized-token 并更新 SOPHNET_TOKENS")
        sys.exit(1)
    print(f"\n✅ Sophnet 签到总结：{len(accounts)}/{len(accounts)} 全部成功")

if __name__ == "__main__":
    main_guard(main)
