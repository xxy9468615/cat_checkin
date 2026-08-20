#!/usr/bin/env python3
# cron: 50 16 * * *
# new Env("AI-ROUTER 签到")
"""AI-ROUTER (https://ai-router.dev) 自动化签到脚本。

平台基于自主研发的企业级 AI 网关架构，每日签到提供：
基础奖励 $1 + 昨日总用量 × 2%（单次上限 $10）。

全自动化保活与免维护机制：
1. 账号密码自动重新登录（推荐）：
   配置 AI_ROUTER_EMAIL / AI_ROUTER_PASSWORD（或多账号 email:password），
   在 Token/Refresh Token 过期失效时自动调用 /auth/login 重新登录，实现 100% 无人值守！
2. Upstash Redis + 本地 State 双层跨 CI 持久化：
   每次 Refresh Token 轮转或重新登录后，自动同步至 Upstash Redis 和本地缓存，
   即便 GitHub Actions Cache 未命中，也能从云端 Redis 自动沿链追溯最新 Token，永不断链。
3. 智能按需刷新：
   现有 Access Token 未过期时直接使用，过期时才触发 Refresh，最大化降低 Token 消耗。

核心接口：
- 账号登录：POST https://api.ai-router.dev/api/v1/auth/login
- 令牌续期：POST https://api.ai-router.dev/api/v1/auth/refresh
- 用户状态：GET  https://api.ai-router.dev/api/v1/auth/me
- 签到状态：GET  https://api.ai-router.dev/api/v1/user/daily-checkin
- 执行签到：POST https://api.ai-router.dev/api/v1/user/daily-checkin

支持环境变量：
  AI_ROUTER_EMAIL         单账号登录邮箱（推荐，配合 PASSWORD 实现永久自动登录）
  AI_ROUTER_USERNAME      单账号登录用户名/邮箱（同上）
  AI_ROUTER_PASSWORD      单账号登录密码（推荐，配合 EMAIL 实现永久自动登录）
  AI_ROUTER_REFRESH_TOKEN 单账号长效 Refresh Token（以 rt_ 开头，自动无感续期）
  AI_ROUTER_TOKEN         单账号短效 Access Token（JWT）
  AI_ROUTER_COOKIE        单账号 Cookie
  AI_ROUTER_ACCOUNTS      多账号配置，换行或 && 分隔，支持 email:password 或 token|refresh_token 或纯 rt_...
  AI_ROUTER_API_URL       接口基础地址（默认 https://api.ai-router.dev/api/v1）
"""
import json
import os
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import Http, env, main_guard, mask_str, upstash_redis_command

PREFIX = "AI_ROUTER_"
DEFAULT_API_URL = "https://api.ai-router.dev/api/v1"

# Refresh Token 轮转持久化文件
STATE_FILE = Path(os.getenv("AI_ROUTER_STATE_FILE", ".ai_router_state.json"))
REDIS_KEY = f"{os.getenv('CAT_CHECKIN_REDIS_PREFIX', 'cat_checkin:')}ai_router:state"


def _load_state() -> dict:
    """从 Upstash Redis 与本地 state 文件双层加载持久化的 token 轮转映射"""
    state: dict = {}

    # 1. 尝试从本地 state 文件读取
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                state.update(data)
        except Exception:
            pass

    # 2. 尝试从 Upstash Redis 远程存储读取（跨 CI runner 永不丢失）
    try:
        ok, res = upstash_redis_command(["GET", REDIS_KEY])
        if ok and isinstance(res, dict):
            raw_val = res.get("result")
            if raw_val and isinstance(raw_val, str):
                remote_data = json.loads(raw_val)
                if isinstance(remote_data, dict):
                    # 远程 Redis 数据权威性高于本地临时 runner 文件
                    state.update(remote_data)
    except Exception as e:
        print(f"⚠️ 从 Redis 读取 RTR 状态异常: {e}")

    return state


def _save_state(state: dict) -> None:
    """持久化 token 映射到本地 state 文件与 Upstash Redis（双通道备份）"""
    if not isinstance(state, dict):
        return

    # 1. 保存到本地文件
    try:
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"⚠️ 保存本地 state 失败: {e}")

    # 2. 同步保存到 Upstash Redis
    try:
        ok, res = upstash_redis_command(["SET", REDIS_KEY, json.dumps(state, ensure_ascii=False)])
        if ok and isinstance(res, dict) and res.get("result") == "OK":
            print(f"☁️ Token 轮转链已实时同步至 Upstash Redis")
    except Exception as e:
        print(f"⚠️ 同步 state 到 Redis 异常: {e}")


def _resolve_rtr(refresh_token: str, state: dict) -> tuple[str, bool]:
    """沿轮转链追溯 RTR refresh token，返回 (最新 token, 是否发生过追溯)。

    state 映射为 旧rt -> 新rt。RTR 严格轮转下服务端每次刷新都作废旧 rt，
    多日运行会形成 rt_1 -> rt_2 -> rt_3 的链；静态的 rt_1 必须沿链追溯到
    最新的 rt_3，否则下一次续期必 401。visited 集合防 state 数据损坏时死循环。
    """
    if not refresh_token:
        return refresh_token or "", False
    current = refresh_token
    visited: set[str] = set()
    while current in state and current not in visited:
        visited.add(current)
        current = state[current]
    return current, current != refresh_token


def _load_accounts():
    """解析并返回账号凭据列表 [{'token': ..., 'refresh_token': ..., 'cookie': ..., 'username': ..., 'password': ...}, ...]"""
    raw = os.getenv(f"{PREFIX}ACCOUNTS", "").strip() or os.getenv(f"QL_{PREFIX}ACCOUNTS", "").strip() or os.getenv(f"{PREFIX}accounts", "").strip()
    accounts = []
    state = _load_state()

    if raw:
        for chunk in re.split(r"\n|&&", raw):
            chunk = chunk.strip()
            if not chunk:
                continue
            # 支持 email:password 或 username:password 格式
            if ":" in chunk and not chunk.startswith("http") and not chunk.startswith("rt_") and "eyJ" not in chunk:
                user_part, _, pass_part = chunk.partition(":")
                accounts.append({
                    "username": user_part.strip(),
                    "password": pass_part.strip(),
                    "token": "",
                    "refresh_token": "",
                    "cookie": "",
                })
            elif "|" in chunk:
                part1, _, part2 = chunk.partition("|")
                p1, p2 = part1.strip(), part2.strip()
                if p1.startswith("rt_"):
                    accounts.append({"token": p2 if not p2.startswith("rt_") else "", "refresh_token": p1, "cookie": "", "username": "", "password": ""})
                elif p2.startswith("rt_"):
                    accounts.append({"token": p1 if not p1.startswith("rt_") else "", "refresh_token": p2, "cookie": "", "username": "", "password": ""})
                elif ":" in p1:
                    u, _, p = p1.partition(":")
                    accounts.append({"username": u.strip(), "password": p.strip(), "token": "", "refresh_token": p2, "cookie": ""})
                else:
                    accounts.append({"token": p1, "refresh_token": p2, "cookie": "", "username": "", "password": ""})
            else:
                if chunk.startswith("rt_"):
                    accounts.append({"token": "", "refresh_token": chunk, "cookie": "", "username": "", "password": ""})
                elif "eyJ" in chunk or chunk.startswith("Bearer "):
                    accounts.append({"token": chunk, "refresh_token": "", "cookie": "", "username": "", "password": ""})
                else:
                    accounts.append({"token": "", "refresh_token": "", "cookie": chunk, "username": "", "password": ""})

    # 单账号兼容
    email = os.getenv(f"{PREFIX}EMAIL", "").strip() or os.getenv(f"{PREFIX}email", "").strip() or os.getenv(f"QL_{PREFIX}EMAIL", "").strip()
    username = os.getenv(f"{PREFIX}USERNAME", "").strip() or os.getenv(f"{PREFIX}username", "").strip() or os.getenv(f"QL_{PREFIX}USERNAME", "").strip()
    user_login = email or username
    password = os.getenv(f"{PREFIX}PASSWORD", "").strip() or os.getenv(f"{PREFIX}password", "").strip() or os.getenv(f"QL_{PREFIX}PASSWORD", "").strip()

    token = os.getenv(f"{PREFIX}TOKEN", "").strip() or os.getenv(f"{PREFIX}token", "").strip() or os.getenv(f"QL_{PREFIX}TOKEN", "").strip()
    ref_token = os.getenv(f"{PREFIX}REFRESH_TOKEN", "").strip() or os.getenv(f"{PREFIX}refresh_token", "").strip() or os.getenv(f"QL_{PREFIX}REFRESH_TOKEN", "").strip()
    cookie = os.getenv(f"{PREFIX}COOKIE", "").strip() or os.getenv(f"{PREFIX}cookie", "").strip() or os.getenv(f"QL_{PREFIX}COOKIE", "").strip()

    # 处理从 cookie 里误传 token 的情况
    if cookie and cookie.startswith("rt_") and not ref_token:
        ref_token = cookie
        cookie = ""
    elif cookie and "eyJ" in cookie and not token:
        token = cookie.split("Bearer ", 1)[-1].strip()

    if (token or ref_token or cookie or (user_login and password)) and not accounts:
        accounts.append({
            "token": token,
            "refresh_token": ref_token,
            "cookie": cookie,
            "username": user_login,
            "password": password,
        })
    elif user_login and password:
        # 若已有 accounts 但匹配到单账号用户名密码，补充凭据
        for acc in accounts:
            if not acc.get("username") and not acc.get("password"):
                acc["username"] = user_login
                acc["password"] = password

    # 对所有账号应用持久化的 RTR 链追溯与登录凭据关联恢复
    for acc in accounts:
        acc_rt = acc.get("refresh_token", "")
        acc_user = acc.get("username", "")

        # 若配了账号名，尝试从 state 恢复之前登录成功留下的最新 rt
        if acc_user and not acc_rt:
            saved_rt = state.get(f"login:{acc_user}")
            if saved_rt:
                acc_rt = saved_rt
                acc["refresh_token"] = saved_rt

        if acc_rt:
            new_rt, traced = _resolve_rtr(acc_rt, state)
            if traced:
                acc["refresh_token"] = new_rt
                print(f"📦 账号 {mask_str(acc_user or acc_rt)} 从持久化存储恢复最新 Refresh Token")
            elif state.get("_latest_rt") and acc_rt != state.get("_latest_rt"):
                acc["refresh_token"] = state.get("_latest_rt")
                print(f"📦 账号 {mask_str(acc_user or acc_rt)} 使用存储中的全局最新 Refresh Token")

    return accounts


def _do_login(h: Http, username: str, password: str, api_url: str) -> tuple[str, str]:
    """使用账号和密码登录，获取最新的 Access Token 和 Refresh Token"""
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": "https://ai-router.dev",
        "Referer": "https://ai-router.dev/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    }
    resp = h.request("POST", f"{api_url}/auth/login", headers=headers, json_data={"username": username, "password": password})
    data = resp.json({})

    if resp.code != 200 or not isinstance(data, dict) or data.get("code") != 0:
        err_msg = data.get("message") if isinstance(data, dict) else resp.text[:100]
        raise RuntimeError(f"账号密码登录失败 (HTTP {resp.code}): {err_msg}")

    res_data = data.get("data", {})
    new_token = res_data.get("access_token") or res_data.get("token") or ""
    new_rt = res_data.get("refresh_token") or ""

    if not new_token:
        raise RuntimeError("登录响应中未包含有效 access_token")

    # 保存最新凭据到 state（本地 + Upstash Redis）
    state = _load_state()
    if new_rt:
        state[f"login:{username}"] = new_rt
        state[new_rt] = new_rt
    _save_state(state)

    print(f"🔑 账号 {mask_str(username)} 密码登录成功，已自动刷新并持久化 Token")
    return new_token, new_rt


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
        raise RuntimeError(f"Refresh Token 续期失败 (HTTP {resp.code}): {err_msg}")

    res_data = data.get("data", {})
    new_token = res_data.get("access_token") or res_data.get("token") or ""
    new_rt = res_data.get("refresh_token") or refresh_token

    if not new_token:
        raise RuntimeError("续期响应中未包含有效 access_token")

    # RTR 防御：服务端若轮转签发新 rt，持久化 mapping 供下次 run 使用
    if new_rt != refresh_token:
        state = _load_state()
        state[refresh_token] = new_rt
        state["_latest_rt"] = new_rt
        _save_state(state)
        print(f"🔄 Refresh Token 已轮转，new rt = {mask_str(new_rt)}")

    return new_token, new_rt


def _run_one(idx: int, total: int, account: dict, api_url: str) -> str:
    """执行单个账号的签到流程，支持 Token 过期自动无感续期与自动重新登录"""
    h = Http()
    token = account.get("token", "").strip()
    refresh_token = account.get("refresh_token", "").strip()
    cookie = account.get("cookie", "").strip()
    username = account.get("username", "").strip()
    password = account.get("password", "").strip()

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

    # 1. 获取有效 Token（按需刷新 / 自动登录）
    # 若初始无 token 但有 refresh_token 或用户名密码，先进行凭据获取
    if not token:
        if refresh_token:
            try:
                token, refresh_token = _do_refresh(h, refresh_token, api_url)
            except Exception as e:
                if username and password:
                    print(f"⚠️ Refresh Token 续期受阻 ({e})，正在通过账号密码自动重新登录...")
                    token, refresh_token = _do_login(h, username, password, api_url)
                else:
                    raise
        elif username and password:
            token, refresh_token = _do_login(h, username, password, api_url)

    headers = _make_headers(token)

    # 2. 验证认证状态并获取用户信息
    me_resp = h.request("GET", f"{api_url}/auth/me", headers=headers)
    me_data = me_resp.json({})

    # 若遭遇 401 且有 refresh_token 或用户名密码，触发自动续期/重登
    if me_resp.code in (401, 403) or (isinstance(me_data, dict) and me_data.get("code") in (401, 403)):
        auth_recovered = False
        if refresh_token:
            try:
                token, refresh_token = _do_refresh(h, refresh_token, api_url)
                headers = _make_headers(token)
                me_resp = h.request("GET", f"{api_url}/auth/me", headers=headers)
                me_data = me_resp.json({})
                if me_resp.code == 200 and isinstance(me_data, dict) and me_data.get("code") == 0:
                    auth_recovered = True
            except Exception:
                pass

        if not auth_recovered and username and password:
            print(f"⚠️ Token/Refresh Token 失效，正在通过账号密码自动重新登录...")
            token, refresh_token = _do_login(h, username, password, api_url)
            headers = _make_headers(token)
            me_resp = h.request("GET", f"{api_url}/auth/me", headers=headers)
            me_data = me_resp.json({})
            if me_resp.code == 200 and isinstance(me_data, dict) and me_data.get("code") == 0:
                auth_recovered = True

        if not auth_recovered and (me_resp.code in (401, 403) or (isinstance(me_data, dict) and me_data.get("code") in (401, 403))):
            raise RuntimeError(
                f"认证失败 (HTTP {me_resp.code})，Token 与 Refresh Token 均已过期。\n"
                f"💡 建议配置 {PREFIX}EMAIL 与 {PREFIX}PASSWORD，脚本即可永久全自动重新登录，无需人工维护！"
            )

    user_info = me_data.get("data") if isinstance(me_data, dict) and "data" in me_data else me_data
    if not isinstance(user_info, dict) or not user_info.get("id"):
        raise RuntimeError(f"获取用户信息异常: {me_resp.text[:120]}")

    email = user_info.get("email") or username or ""
    uid = str(user_info.get("id") or "")
    balance = user_info.get("balance", 0)
    active_balance = user_info.get("active_balance", 0)
    frozen_balance = user_info.get("frozen_balance", 0)

    # 3. 直接发起每日签到 POST /user/daily-checkin
    sign_ok = False
    sign_msg = ""
    reward_desc = ""

    sign_resp = h.request("POST", f"{api_url}/user/daily-checkin", headers=headers, json_data={})
    sign_res_data = sign_resp.json({})
    code = sign_res_data.get("code") if isinstance(sign_res_data, dict) else None
    reason = sign_res_data.get("reason", "")
    msg = sign_res_data.get("message") or ""

    if sign_resp.code == 200 and code == 0:
        sign_ok = True
        sign_msg = "签到成功"
        claimed_amount = sign_res_data.get("data", {}).get("reward_amount", 1)
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
    elif sign_resp.code == 409 or code == 409 or reason == "DAILY_CHECKIN_CLAIMED" or "already claimed" in msg.lower():
        sign_ok = True
        sign_msg = "今日已签到过"
    else:
        sign_msg = msg or f"签到失败 (HTTP {sign_resp.code}, code={code})"
        print(f"   ↳ 签到原始响应: {sign_resp.text[:200]}")

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
            f"未配置凭据：请配置 {PREFIX}EMAIL 与 {PREFIX}PASSWORD（最推荐，永久自动登录），"
            f"或 {PREFIX}REFRESH_TOKEN / {PREFIX}ACCOUNTS"
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


if __name__ == "__main__":
    main_guard(main)
