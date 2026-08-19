#!/usr/bin/env python3
# cron: 50 16 * * *
# new Env("AI-ROUTER 签到")
"""AI-ROUTER (https://ai-router.dev) 自动化签到脚本。

平台基于自主研发的企业级 AI 网关架构，每日签到提供：
基础奖励 $1 + 昨日总用量 × 2%（单次上限 $10）。

 console.log("=== 本地存储所有数据 ===");
for (let i = 0; i < localStorage.length; i++) {
  const k = localStorage.key(i);
  console.log(`${k}:`, localStorage.getItem(k));
}

核心接口：
- 令牌续期：POST https://api.ai-router.dev/api/v1/auth/refresh
- 用户状态：GET  https://api.ai-router.dev/api/v1/auth/me
- 签到状态：GET  https://api.ai-router.dev/api/v1/user/daily-checkin
- 执行签到：POST https://api.ai-router.dev/api/v1/user/daily-checkin

支持环境变量：
  AI_ROUTER_REFRESH_TOKEN 单账号长效 Refresh Token（以 rt_ 开头，推荐，自动无感续期）
  AI_ROUTER_TOKEN         单账号短效 Access Token（JWT）
  AI_ROUTER_COOKIE        单账号 Cookie（如包含 session 或 JWT）
  AI_ROUTER_ACCOUNTS      多账号配置，换行或 && 分隔，格式为 token|refresh_token 或仅填 refresh_token
  AI_ROUTER_API_URL       接口基础地址（默认 https://api.ai-router.dev/api/v1）
"""
import json
import os
import re
import sys
from pathlib import Path
from common import Http, env, main_guard, mask_str

PREFIX = "AI_ROUTER_"
DEFAULT_API_URL = "https://api.ai-router.dev/api/v1"

# Refresh Token 轮转持久化文件（防御 RTR 模式：服务端每次刷新后作废旧 rt，签发新 rt）
# GitHub Actions 通过 actions/cache 持久化此文件，确保下次 run 使用最新 rt_
STATE_FILE = Path(os.getenv("AI_ROUTER_STATE_FILE", ".ai_router_state.json"))


def _load_state() -> dict:
    """从 state 文件加载持久化的 refresh token 映射（按 refresh_token 前缀 hash 去重）"""
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    """持久化 refresh token 映射到 state 文件"""
    try:
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"⚠️ 保存 state 失败: {e}")


def _load_accounts():
    """解析并返回账号凭据列表 [{'token': ..., 'refresh_token': ..., 'cookie': ...}, ...]"""
    raw = os.getenv(f"{PREFIX}ACCOUNTS", "").strip() or os.getenv(f"QL_{PREFIX}ACCOUNTS", "").strip() or os.getenv(f"{PREFIX}accounts", "").strip()
    accounts = []

    if raw:
        for chunk in re.split(r"\n|&&", raw):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "|" in chunk:
                part1, _, part2 = chunk.partition("|")
                p1, p2 = part1.strip(), part2.strip()
                if p1.startswith("rt_"):
                    accounts.append({"token": p2 if not p2.startswith("rt_") else "", "refresh_token": p1, "cookie": ""})
                elif p2.startswith("rt_"):
                    accounts.append({"token": p1 if not p1.startswith("rt_") else "", "refresh_token": p2, "cookie": ""})
                else:
                    accounts.append({"token": p1, "refresh_token": p2, "cookie": ""})
            else:
                if chunk.startswith("rt_"):
                    accounts.append({"token": "", "refresh_token": chunk, "cookie": ""})
                elif "eyJ" in chunk or chunk.startswith("Bearer "):
                    accounts.append({"token": chunk, "refresh_token": "", "cookie": ""})
                else:
                    accounts.append({"token": "", "refresh_token": "", "cookie": chunk})

    # 单账号兼容
    token = os.getenv(f"{PREFIX}TOKEN", "").strip() or os.getenv(f"{PREFIX}token", "").strip() or os.getenv(f"QL_{PREFIX}TOKEN", "").strip()
    ref_token = os.getenv(f"{PREFIX}REFRESH_TOKEN", "").strip() or os.getenv(f"{PREFIX}refresh_token", "").strip() or os.getenv(f"QL_{PREFIX}REFRESH_TOKEN", "").strip()
    cookie = os.getenv(f"{PREFIX}COOKIE", "").strip() or os.getenv(f"{PREFIX}cookie", "").strip() or os.getenv(f"QL_{PREFIX}COOKIE", "").strip()

    # 用持久化的轮转 refresh token 覆盖静态旧值（RTR 模式）
    state = _load_state()
    if ref_token and ref_token in state:
        ref_token = state[ref_token]
        print(f"📦 从 state 缓存恢复 Refresh Token（轮转续期）")
    elif cookie and cookie in state:
        ref_token = state[cookie]
        print(f"📦 从 state 缓存恢复 Refresh Token（cookie 映射）")

    # 处理从 cookie 里误传 token 的情况
    if cookie and cookie.startswith("rt_") and not ref_token:
        ref_token = cookie
        cookie = ""
    elif cookie and "eyJ" in cookie and not token:
        token = cookie.split("Bearer ", 1)[-1].strip()

    if (token or ref_token or cookie) and not accounts:
        accounts.append({"token": token, "refresh_token": ref_token, "cookie": cookie})
    elif (token or ref_token) and not any(a.get("refresh_token") == ref_token for a in accounts if ref_token):
        accounts.append({"token": token, "refresh_token": ref_token, "cookie": cookie})

    return accounts


def _do_refresh(h: Http, refresh_token: str, api_url: str) -> tuple[str, str]:
    """使用 Refresh Token 换取最新的 Access Token 和轮转后的 Refresh Token"""
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": "https://ai-router.dev",
        "Referer": "https://ai-router.dev/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    }
    resp = h.request("POST", f"{api_url}/auth/refresh", headers=headers, json_data={"refresh_token": refresh_token})
    data = resp.json({})

    if resp.code != 200 or not isinstance(data, dict) or data.get("code") != 0:
        err_msg = data.get("message") if isinstance(data, dict) else resp.text[:100]
        # 400/401 → Refresh Token 本身已失效，需重新登录获取
        if resp.code in (400, 401) or (isinstance(data, dict) and data.get("code") in (400, 401)):
            raise RuntimeError(
                f"Refresh Token 已失效/过期 (HTTP {resp.code}): {err_msg}\n"
                f"请登录 https://ai-router.dev 重新获取 Refresh Token 并更新 GitHub Secrets / .env 中的 "
                f"{PREFIX}REFRESH_TOKEN（rt_... 开头）后重试。"
            )
        raise RuntimeError(f"Refresh Token 续期失败 (HTTP {resp.code}): {err_msg}")

    res_data = data.get("data", {})
    new_token = res_data.get("access_token") or res_data.get("token") or ""
    new_rt = res_data.get("refresh_token") or refresh_token

    if not new_token:
        raise RuntimeError("续期响应中未包含有效 access_token")

    # RTR 防御：服务端若轮转签发新 rt（且与原 rt 不同），持久化 mapping 供下次 run 使用
    if new_rt != refresh_token:
        state = _load_state()
        state[refresh_token] = new_rt
        _save_state(state)
        print(f"🔄 Refresh Token 已轮转，new rt = {mask_str(new_rt)}")

    return new_token, new_rt


def _run_one(idx: int, total: int, account: dict, api_url: str) -> str:
    """执行单个账号的签到流程，支持 Token 过期自动无感续期"""
    h = Http()
    token = account.get("token", "").strip()
    refresh_token = account.get("refresh_token", "").strip()
    cookie = account.get("cookie", "").strip()

    # 如果没有初始 token，但有 refresh_token，直接先做一次刷新获取
    if not token and refresh_token:
        token, refresh_token = _do_refresh(h, refresh_token, api_url)

    def _make_headers(cur_token: str) -> dict:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Origin": "https://ai-router.dev",
            "Referer": "https://ai-router.dev/",
        }
        if cur_token:
            headers["Authorization"] = f"Bearer {cur_token}" if not cur_token.startswith("Bearer ") else cur_token
        if cookie:
            headers["Cookie"] = cookie
        return headers

    headers = _make_headers(token)

    # 1. 验证认证状态并获取用户信息
    me_resp = h.request("GET", f"{api_url}/auth/me", headers=headers)
    me_data = me_resp.json({})

    # 若遭遇 401 且有 refresh_token，触发无感自动续期并重试
    if (me_resp.code in (401, 403) or (isinstance(me_data, dict) and me_data.get("code") in (401, 403))) and refresh_token:
        token, refresh_token = _do_refresh(h, refresh_token, api_url)
        headers = _make_headers(token)
        me_resp = h.request("GET", f"{api_url}/auth/me", headers=headers)
        me_data = me_resp.json({})

    if me_resp.code in (401, 403) or (isinstance(me_data, dict) and me_data.get("code") in (401, 403)):
        raise RuntimeError(f"认证失败 (HTTP {me_resp.code})，Token 已过期且无法续期")

    user_info = me_data.get("data") if isinstance(me_data, dict) and "data" in me_data else me_data
    if not isinstance(user_info, dict) or not user_info.get("id"):
        raise RuntimeError(f"获取用户信息异常: {me_resp.text[:120]}")

    email = user_info.get("email") or ""
    uid = str(user_info.get("id") or "")
    balance = user_info.get("balance", 0)
    active_balance = user_info.get("active_balance", 0)
    frozen_balance = user_info.get("frozen_balance", 0)

    # 2. 查询今日签到状态
    status_resp = h.request("GET", f"{api_url}/user/daily-checkin", headers=headers)
    status_data = status_resp.json({}).get("data", {})
    checked_today = status_data.get("checked_today", False)
    reward_amount = status_data.get("reward_amount", 1)

    sign_ok = False
    sign_msg = ""
    reward_desc = ""

    if checked_today:
        sign_ok = True
        sign_msg = "今日已签到过"
    else:
        # 3. 发起每日签到 POST /user/daily-checkin
        sign_resp = h.request("POST", f"{api_url}/user/daily-checkin", headers=headers, json_data={})
        sign_res_data = sign_resp.json({})
        code = sign_res_data.get("code") if isinstance(sign_res_data, dict) else None
        reason = sign_res_data.get("reason", "")
        msg = sign_res_data.get("message") or ""

        if sign_resp.code == 200 and code == 0:
            sign_ok = True
            sign_msg = "签到成功"
            claimed_amount = sign_res_data.get("data", {}).get("reward_amount") or reward_amount
            reward_desc = f" | 🎁 奖励：${claimed_amount:.2f} USD"
            # 刷新最新资产余额
            try:
                ref_resp = h.request("GET", f"{api_url}/auth/me", headers=headers)
                ref_user = ref_resp.json({}).get("data", {})
                if isinstance(ref_user, dict) and "balance" in ref_user:
                    balance = ref_user.get("balance", balance)
                    active_balance = ref_user.get("active_balance", active_balance)
                    frozen_balance = ref_user.get("frozen_balance", frozen_balance)
            except Exception:
                pass
        elif code == 409 or reason == "DAILY_CHECKIN_CLAIMED" or "already claimed" in msg.lower():
            sign_ok = True
            sign_msg = "今日已签到过"
        else:
            sign_msg = msg or f"签到失败 (code={code})"

    # 4. 构建格式化日志输出
    user_tag = mask_str(email) if email else f"账号{idx}"
    uid_tag = f" (UID: {mask_str(uid)})" if uid else ""
    balance_desc = f" | 💰 资产：${balance} USD (可用: ${active_balance} / 冻结: ${frozen_balance})"

    line = f"[{idx}/{total}] 账号：{user_tag}{uid_tag} | {sign_msg}{reward_desc}{balance_desc}"
    print(line)

    if not sign_ok:
        raise RuntimeError(sign_msg)

    return line


def main():
    accounts = _load_accounts()
    if not accounts:
        raise RuntimeError(
            f"未配置 {PREFIX}REFRESH_TOKEN 或 {PREFIX}TOKEN / {PREFIX}ACCOUNTS"
        )

    api_url = os.getenv(f"{PREFIX}API_URL", DEFAULT_API_URL).strip().rstrip("/")

    print("【AI-ROUTER 签到】")
    print(f"共 {len(accounts)} 个账号 | API: {api_url}")

    results = []
    for idx, acc in enumerate(accounts, 1):
        try:
            line = _run_one(idx, len(accounts), acc, api_url)
            results.append((True, line))
        except Exception as e:
            line = f"[{idx}/{len(accounts)}] 签到失败：{e}"
            print(line)
            results.append((False, line))

    ok_count = sum(1 for ok, _ in results if ok)
    print(f"\n========== 签到总结 ==========\n成功 {ok_count}/{len(accounts)}")
    if ok_count != len(accounts):
        sys.exit(1)


main_guard(main)
