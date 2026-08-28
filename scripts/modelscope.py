#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("ModelScope 社区签到")
# new Env("ModelScope 国际站 签到")
"""ModelScope 魔搭社区每日签到（国内站 + 国际站分开处理）。

机制：
1. 登录奖励（每日 200 魔粒）在用户产生活跃会话后被动发放。
2. 每日点击喜欢 20 次任务（单次 +2 魔粒，每日上限 20 次共 40 魔粒）。
3. 接口路径已变更：magic_cube → magicubes（2026-08 前后迁移）。
4. 判断方式：直查交易记录接口，`rule_key == "daily_active"` 且 `gmt_created == 今日`
   即视为已领取，无需余额增长推算或退避轮询。

多认证与长效支持（2026-08 升级）：
1. SDK 访问令牌（Access Token / API Token）直连：
   支持 MODELSCOPE_TOKEN / MODELSCOPE_TOKEN_1 等，通过 Authorization: Bearer 头鉴权，
   有效期长，无需担心 Cookie 频繁过期。
2. Cookie 滑动续期与持久化：
   对于使用 MODELSCOPE_COOKIE 的账号，自动捕获服务端 Set-Cookie 并通过 Upstash Redis
   及本地 state 进行每日滚动续期（解决 source 1 天过期问题）。
3. 会话触碰与任务执行：访问 personal overview 与模型/数据集接口触发「日活」，并自动执行 MCP Server 点赞任务。

环境变量：
  MODELSCOPE_TOKEN / MODELSCOPE_TOKEN_1, _2...：SDK 访问令牌（国内站，推荐）
  MODELSCOPE_COOKIE / MODELSCOPE_COOKIE_1, _2...：Cookie（国内站）
  MODELSCOPE_AI_TOKEN / MODELSCOPE_AI_COOKIE：国际站专用 Token / Cookie
  MODELSCOPE_HOST：国内站主机（默认 www.modelscope.cn）
  MODELSCOPE_AI_HOST：国际站主机（默认 www.modelscope.ai）
"""
from __future__ import annotations

import hashlib
import os
import random
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from common import (
    BJT,
    Http,
    env,
    env_seq,
    find,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PREFIX = "MODELSCOPE_"


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _default_host() -> str:
    return os.getenv("MODELSCOPE_HOST", "www.modelscope.cn").strip() or "www.modelscope.cn"


def _ai_host() -> str:
    return os.getenv(f"{PREFIX}AI_HOST", "www.modelscope.ai").strip() or "www.modelscope.ai"


def _merge_cookies(existing_cookie: Optional[str], jar: Any) -> str:
    """合并已有 Cookie 与 urllib CookieJar 中的最新 Set-Cookie。"""
    cookie_dict: Dict[str, str] = {}
    if existing_cookie:
        for part in existing_cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    cookie_dict[k.strip()] = v.strip()
    for c in jar:
        if getattr(c, "name", None):
            cookie_dict[c.name] = c.value
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())


def _headers(
    host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Dict[str, str]:
    """构造带浏览器上下文或 Token 鉴权的请求头，避免被风控/埋点中间件忽略。"""
    headers = {
        "Origin": f"https://{host}",
        "Referer": f"https://{host}/my/overview",
        "User-Agent": DEFAULT_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["OpenAPI-Token"] = token
        headers["X-Modelfun-Token"] = token
    if cookie:
        headers["Cookie"] = cookie
        raw_csrf = find(r"csrf_token=([^;]+)", cookie, "")
        if raw_csrf:
            headers["X-CSRF-TOKEN"] = urllib.parse.unquote(raw_csrf)
    return headers


def _touch_user(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Dict[str, Any]:
    """全链路触碰会话并验证登录态。

    1. 若有 Cookie，访问个人中心 Web 页面与首页，触发 Web 端活跃埋点中间件。
    2. 访问 magicubes 任务规则与余额端点，激活每日签到奖励系统。
    3. 访问 OpenAPI 模型与数据集轻量端点，激活用户活动。
    4. GET /openapi/v1/users/me 验证登录态并提取用户信息。
    """
    if cookie:
        web_headers = {
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"https://{host}/",
            "Cookie": cookie,
        }
        try:
            h.request("GET", f"https://{host}/my/overview", headers=web_headers, timeout=15)
            h.request("GET", f"https://{host}/", headers=web_headers, timeout=15)
            h.request("GET", f"https://{host}/home", headers=web_headers, timeout=15)
            h.request("GET", f"https://{host}/models", headers=web_headers, timeout=15)
            h.request("GET", f"https://{host}/datasets", headers=web_headers, timeout=15)
            h.request("GET", f"https://{host}/my/tasks", headers=web_headers, timeout=15)
        except Exception:
            pass

    hdrs = _headers(host, token=token, cookie=cookie)
    try:
        # 激活魔粒日常任务与余额系统
        h.request(
            "GET",
            f"https://{host}/openapi/v1/magicubes/earn/rules",
            headers=hdrs,
            timeout=15,
        )
        h.request(
            "GET",
            f"https://{host}/openapi/v1/magicubes/balance",
            headers=hdrs,
            timeout=15,
        )
        h.request(
            "GET",
            f"https://{host}/openapi/v1/models?page_number=1&page_size=10",
            headers=hdrs,
            timeout=15,
        )
        h.request(
            "GET",
            f"https://{host}/openapi/v1/datasets?page_number=1&page_size=10",
            headers=hdrs,
            timeout=15,
        )
        h.request(
            "GET",
            f"https://{host}/openapi/v1/studios?page_number=1&page_size=10",
            headers=hdrs,
            timeout=15,
        )
        h.request(
            "GET",
            f"https://{host}/openapi/v1/community/posts?page_number=1&page_size=10",
            headers=hdrs,
            timeout=15,
        )
    except Exception:
        pass

    resp = h.request(
        "GET",
        f"https://{host}/openapi/v1/users/me",
        headers=hdrs,
        timeout=20,
    )
    data = resp.json({})
    if resp.code in (401, 403) or (isinstance(data, dict) and data.get("code") in (401, 403)):
        auth_type = (
            "Token"
            if token and not cookie
            else ("Cookie" if cookie and not token else "Token / Cookie")
        )
        raise RuntimeError(
            f"{auth_type} 已失效/未登录 (HTTP {resp.code})，请重新获取 {host} 的访问凭证"
        )
    if not data or not data.get("success"):
        raise RuntimeError(f"users/me 返回异常：{resp.text[:200]}")
    user = data.get("data", {})
    if not isinstance(user, dict):
        raise RuntimeError(f"users/me 数据结构异常：{resp.text[:200]}")
    return user


def _get_today_daily_active(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """查询每日签到（daily_active）奖励交易记录或任务完成状态。返回今日记录 dict 或 None。

    双判据保障：
    1. 直查交易记录接口，`rule_key == "daily_active"` 且 `gmt_created` 日期命中今日 BJT。
       分页扫描（page_size=50，最多 3 页，扫到越过今日即止）：点赞任务每点一次各产生
       一条流水，20 次点赞会把当日 daily_active 记录挤出第 1 页，只查首页会永久误判。
    2. 若交易记录未落库，查询 earn/rules 的 `daily_active` 规则中的 `today_used > 0`。
    """
    today = datetime.now(BJT).strftime("%Y-%m-%d")
    hdrs = _headers(host, token=token, cookie=cookie)

    def _created(rec: Dict[str, Any]) -> str:
        return str(
            rec.get("gmt_created") or rec.get("gmt_create") or rec.get("created_at") or ""
        )

    # 判据 1：交易记录直查（分页扫描至越过今日）
    seen_rule_keys = set()
    resp = None
    try:
        for page in (1, 2, 3):
            resp = h.request(
                "GET",
                f"https://{host}/openapi/v1/magicubes/transactions"
                f"?type=EARN&page={page}&page_size=50",
                headers=hdrs,
                timeout=20,
            )
            if resp.code != 200:
                break
            data = resp.json({})
            if not (data and data.get("success")):
                break
            records = (data.get("data") or {}).get("records") or []
            if not records:
                break
            past_today = False
            for rec in records:
                rule_key = str(rec.get("rule_key") or "")
                if rule_key:
                    seen_rule_keys.add(rule_key)
                created_str = _created(rec)
                if rule_key == "daily_active" and (
                    created_str.startswith(today) or today in created_str
                ):
                    return rec
                # 流水按时间倒序：出现早于今日的记录说明今日记录已全部扫过
                if created_str[:10] and created_str[:10] < today:
                    past_today = True
            if past_today:
                break
    except Exception:
        pass

    # 判据 2：earn/rules 状态查询（若交易记录存在异步落库延迟，earn/rules 的 today_used 可作即时状态确认）
    resp_rules = None
    try:
        resp_rules = h.request(
            "GET",
            f"https://{host}/openapi/v1/magicubes/earn/rules",
            headers=hdrs,
            timeout=20,
        )
        if resp_rules.code == 200:
            data_rules = resp_rules.json({})
            if data_rules and data_rules.get("success"):
                for r in data_rules.get("data") or []:
                    if r.get("rule_key") == "daily_active":
                        today_used = r.get("today_used", 0)
                        if bool(today_used):
                            return {
                                "rule_key": "daily_active",
                                "total_amount": r.get("amount", 200),
                                "expire_at": "",
                                "source": "earn_rules",
                            }
                        # 诊断信息：双判据都未命中时能看到 daily_active 规则的真实字段，
                        # 便于区分「Cookie 失效」与「接口字段变更」
                        print(
                            f"  [diag] daily_active 规则未命中 today_used："
                            f"{ {k: r.get(k) for k in ('today_used', 'today_count', 'amount', 'daily_cap', 'status') if k in r} }"
                        )
    except Exception:
        pass

    if seen_rule_keys:
        print(f"  [diag] 交易记录今日可见 rule_key：{sorted(seen_rule_keys)}")
    return None


DEFAULT_MCP_TARGETS = [
    {"path": "@modelcontextprotocol", "name": "fetch"},
    {"path": "itshen", "name": "xsct-bench"},
    {"path": "@amap", "name": "amap-maps"},
    {"path": "slcatwujian", "name": "bing-cn-mcp-server"},
    {"path": "Alipay", "name": "alipay-subscription"},
    {"path": "TianYanCha", "name": "tyc-mcp"},
    {"path": "@supabase-community", "name": "supabase-mcp"},
    {"path": "yorklu", "name": "AI_Go_Hotel_MCP"},
    {"path": "zephyr", "name": "douyin-mcp-server"},
    {"path": "Launini", "name": "ChatPPT-MCP"},
    {"path": "MChina", "name": "mcd_mcp_server"},
    {"path": "@Joooook", "name": "12306-mcp"},
    {"path": "@PsychArch", "name": "Jina-AI-MCP-Tools"},
    {"path": "@ChromeDevTools", "name": "chrome-devtools-mcp"},
    {"path": "laiyelijingao", "name": "Agentic_Document_Processing_MCP"},
    {"path": "antvis", "name": "mcp-server-chart"},
    {"path": "MemTensor", "name": "MemoryOperatingSystem"},
    {"path": "@open-dingtalk", "name": "dingtalk-mcp"},
    {"path": "AgentBay", "name": "wuying-agentbay-mcp-server"},
    {"path": "@UnionPay", "name": "unionpay-mcp-server"},
    {"path": "@deckflow", "name": "gezhe-mcp-server"},
    {"path": "@regenrek", "name": "mcp-deepwiki"},
    {"path": "modelscope", "name": "ModelScope-Image-Generation-MCP"},
    {"path": "ZhipuAI", "name": "Zhipu-Web-Search"},
    {"path": "@variflight-ai", "name": "variflight-mcp"},
    {"path": "@mobvoi", "name": "mobvoi-mcp"},
    {"path": "@mem0ai", "name": "OpenMemory"},
    {"path": "@package", "name": "mcp-server-weread"},
    {"path": "@cantian-ai", "name": "Bazi-MCP"},
    {"path": "@baidu-maps", "name": "mcp"},
]


def _get_daily_like_status(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Tuple[int, int, int]:
    """查询每日点赞/喜欢任务规则与进度。

    返回 (today_used, max_count, amount_per_like)。
    """
    hdrs = _headers(host, token=token, cookie=cookie)
    try:
        resp = h.request(
            "GET",
            f"https://{host}/openapi/v1/magicubes/earn/rules",
            headers=hdrs,
            timeout=15,
        )
        if resp.code == 200:
            data = resp.json({})
            if data and data.get("success"):
                for r in data.get("data") or []:
                    rule_key = str(r.get("rule_key") or "").lower()
                    name = str(r.get("title") or r.get("name") or "").lower()
                    if (
                        rule_key == "interaction_like"
                        or "like" in rule_key
                        or "vote" in rule_key
                        or "star" in rule_key
                        or "favorite" in rule_key
                        or "点赞" in name
                        or "喜欢" in name
                    ):
                        max_cnt = int(r.get("daily_cap") or r.get("max_count") or 20)
                        used = int(r.get("today_used") or r.get("today_count") or 0)
                        amt = int(r.get("amount") or 2)
                        return used, max_cnt, amt
    except Exception:
        pass
    return 0, 20, 2


def _fetch_mcp_like_targets(
    h: Http,
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    needed: int = 20,
) -> List[Dict[str, str]]:
    """发现可点赞的 MCP Server 目标列表。

    返回 [{"path": "Alipay", "name": "alipay-subscription"}, ...]
    """
    targets: List[Dict[str, str]] = []
    seen = set()
    hdrs = _headers(host, token=token, cookie=cookie)
    hdrs["Content-Type"] = "application/json"

    for page in range(1, 3):
        if len(targets) >= needed:
            break
        try:
            resp = h.request(
                "PUT",
                f"https://{host}/api/v1/dolphin/mcpServers",
                headers=hdrs,
                json_data={
                    "PageSize": 30,
                    "PageNumber": page,
                    "Query": "",
                    "Criterion": [],
                },
                timeout=10,
            )
            if resp.code == 200:
                data = resp.json({})
                servers = (
                    ((data.get("Data") or {}).get("McpServer") or {}).get("McpServers")
                    or []
                )
                if not servers:
                    break
                for s in servers:
                    path = s.get("Path") or s.get("FromSitePath") or s.get("Namespace")
                    name = s.get("Name")
                    if path and name:
                        key = f"{path}/{name}"
                        if key not in seen:
                            seen.add(key)
                            targets.append(
                                {
                                    "path": path,
                                    "name": name,
                                    "already_star": bool(s.get("AlreadyStar", False)),
                                }
                            )
        except Exception:
            pass

    # 若动态获取数量不足，补充预设的优质热门 MCP Server
    for def_t in DEFAULT_MCP_TARGETS:
        key = f"{def_t['path']}/{def_t['name']}"
        if key not in seen:
            seen.add(key)
            targets.append(
                {
                    "path": def_t["path"],
                    "name": def_t["name"],
                    "already_star": False,
                }
            )

    targets.sort(key=lambda x: x.get("already_star", False))
    return [{"path": t["path"], "name": t["name"]} for t in targets]


def _do_daily_likes(
    h: Http,
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    count: int = 20,
    amount_per_like: int = 2,
) -> Tuple[int, int]:
    """执行每日点击喜欢 20 次任务。

    返回 (成功次数, 获得魔粒数)。
    """
    if count <= 0:
        return 0, 0

    targets = _fetch_mcp_like_targets(
        h, host, token=token, cookie=cookie, needed=count + 10
    )
    if not targets:
        return 0, 0

    success_cnt = 0
    hdrs = _headers(host, token=token, cookie=cookie)
    hdrs["Content-Type"] = "application/json"

    for t in targets:
        if success_cnt >= count:
            break
        path = t["path"]
        name = t["name"]
        req_hdrs = dict(hdrs)
        req_hdrs["Referer"] = f"https://{host}/mcp/servers/{path}/{name}"
        try:
            resp = h.request(
                "PUT",
                f"https://{host}/api/v1/mcpServers/{path}/{name}/stars",
                headers=req_hdrs,
                json_data={},
                timeout=15,
            )
            if resp.code == 200:
                res_data = resp.json({})
                if res_data.get("Success") or res_data.get("Code") == 200:
                    success_cnt += 1
        except Exception:
            pass
        time.sleep(random.uniform(0.2, 0.4))

    return success_cnt, success_cnt * amount_per_like


def _resolve_cookie(env_cookie: str, idx: int, site: str) -> Tuple[str, str, Optional[str]]:
    """解析某账号的 Cookie 配置。

    返回 (active_cookie, source_tag, fallback_env_cookie)。

    优先级与更新感知策略：
    1. 计算当前环境变量中的 env_cookie 哈希（env_hash）。
    2. 若 state 中记录的 env_hash 与当前 env_cookie 不一致，
       说明用户在 GitHub Secrets / 环境变量中更新了新凭证 → 立即优先使用 env_cookie。
    3. 若无 state_env_hash 但 env_cookie 与 state_cookie 不一致，同样优先使用 env_cookie。
    4. 若哈希一致且存在 state_cookie，优先使用带滚动 Set-Cookie 的 state_cookie，
       并将 env_cookie 留作失败回退（fallback_env_cookie）。
    5. 若无 state 则直接使用 env_cookie。
    """
    state_file = f".modelscope_{site}_state_{idx}.json"
    redis_key = f"cat_checkin:state:modelscope_{site}_{idx}"
    saved_state = load_kv_state(redis_key, state_file) or {}
    state_cookie = str(saved_state.get("cookie", "") or "").strip()
    saved_env_hash = str(saved_state.get("env_hash", "") or "").strip()

    current_env_hash = (
        hashlib.md5(env_cookie.encode("utf-8")).hexdigest() if env_cookie else ""
    )

    # 用户手动更新了 Secrets 中的 Cookie（哈希变更或旧 state 无 hash 但凭证不同），优先使用新配置
    if env_cookie:
        if (saved_env_hash and current_env_hash != saved_env_hash) or (
            not saved_env_hash and state_cookie and env_cookie != state_cookie
        ):
            return env_cookie, "env_updated", None

    if state_cookie:
        fallback = env_cookie if (env_cookie and env_cookie != state_cookie) else None
        return state_cookie, "state", fallback
    if env_cookie:
        return env_cookie, "env", None
    return "", "", None


def _load_accounts(site: str = "cn") -> List[Dict[str, Any]]:
    """加载指定站点（cn / ai）的所有账号凭证，支持 Token 与 Cookie 混合、多账号索引扫描及 Redis 滚动状态。

    凭证优先级：**Cookie 优先，Token 回退**（2026-08-25 修复）。
    实测 Bearer Token 虽能通过 OpenAPI 鉴权，但 OpenAPI 调用不计入「日活」，
    daily_active 每日魔粒不会发放；只有 Web 会话（Cookie）活动才触发奖励。
    故同时配置 Token 与 Cookie 时，一律走 Cookie（state 滚动续期版本优先）。
    """
    accounts: List[Dict[str, Any]] = []
    seen = set()

    if site == "cn":
        prefixes = [PREFIX, f"QL_{PREFIX}"]
        token_keys = ["TOKEN", "API_TOKEN", "ACCESS_TOKEN", "SDK_TOKEN"]
        cookie_keys = ["COOKIE", "COOKIES"]
    else:
        prefixes = [
            f"{PREFIX}AI_",
            f"{PREFIX}ai_",
            f"QL_{PREFIX}AI_",
            f"QL_{PREFIX}ai_",
        ]
        token_keys = ["TOKEN", "API_TOKEN", "ACCESS_TOKEN", "SDK_TOKEN"]
        cookie_keys = ["COOKIE", "COOKIES"]

    # 1. 扫描 1..20 显式序号
    for idx in range(1, 21):
        token_val = ""
        env_cookie_val = ""

        # 同时收集环境变量中的 Token 与 Cookie（不再因 Token 存在而跳过 Cookie）
        for pfx in prefixes:
            if not token_val:
                for k in token_keys:
                    token_val = (
                        os.getenv(f"{pfx}{k}_{idx}")
                        or os.getenv(f"{pfx}{k.lower()}_{idx}")
                        or ""
                    ).strip()
                    if token_val:
                        break
            if not env_cookie_val:
                for k in cookie_keys:
                    env_cookie_val = (
                        os.getenv(f"{pfx}{k}_{idx}")
                        or os.getenv(f"{pfx}{k.lower()}_{idx}")
                        or ""
                    ).strip()
                    if env_cookie_val:
                        break

        # Cookie 解析：支持 state 滚动、环境变量更新感知与回退
        cookie_val, _src, fallback_cookie = _resolve_cookie(env_cookie_val, idx, site)
        token_val = token_val.strip()
        if token_val or cookie_val:
            ident = cookie_val or token_val
            if ident not in seen:
                seen.add(ident)
                # Cookie 优先：Bearer Token 不触发 daily_active 日活奖励（见函数 docstring）
                if cookie_val:
                    accounts.append(
                        {
                            "token": None,
                            "cookie": cookie_val,
                            "fallback_cookie": fallback_cookie,
                            "env_cookie": env_cookie_val,
                            "index": idx,
                            "site": site,
                        }
                    )
                else:
                    accounts.append(
                        {
                            "token": token_val,
                            "cookie": None,
                            "fallback_cookie": None,
                            "env_cookie": None,
                            "index": idx,
                            "site": site,
                        }
                    )

    # 2. 如果未扫描到序号 1，回退扫描非序号变量
    if not accounts:
        token_val = ""
        env_cookie_val = ""

        for pfx in prefixes:
            if not token_val:
                for k in token_keys:
                    token_val = (
                        os.getenv(f"{pfx}{k}")
                        or os.getenv(f"{pfx}{k.lower()}")
                        or ""
                    ).strip()
                    if token_val:
                        break
            if not env_cookie_val:
                for k in cookie_keys:
                    env_cookie_val = (
                        os.getenv(f"{pfx}{k}")
                        or os.getenv(f"{pfx}{k.lower()}")
                        or ""
                    ).strip()
                    if env_cookie_val:
                        break

        cookie_val, _src, fallback_cookie = _resolve_cookie(env_cookie_val, 1, site)
        token_val = token_val.strip()

        # 针对单变量 && 或换行切分多账号（Cookie 优先：Token 不触发日活奖励）
        if cookie_val and ("&&" in cookie_val or "\n" in cookie_val):
            raw_cookies = [
                x.strip()
                for x in cookie_val.replace("&&", "\n").splitlines()
                if x.strip()
            ]
            for sub_idx, c_item in enumerate(raw_cookies, 1):
                accounts.append(
                    {
                        "token": None,
                        "cookie": c_item,
                        "fallback_cookie": None,
                        "env_cookie": c_item,
                        "index": sub_idx,
                        "site": site,
                    }
                )
        elif token_val and ("&&" in token_val or "\n" in token_val):
            raw_tokens = [
                x.strip()
                for x in token_val.replace("&&", "\n").splitlines()
                if x.strip()
            ]
            for sub_idx, t_item in enumerate(raw_tokens, 1):
                accounts.append(
                    {
                        "token": t_item,
                        "cookie": None,
                        "fallback_cookie": None,
                        "env_cookie": None,
                        "index": sub_idx,
                        "site": site,
                    }
                )
        elif token_val or cookie_val:
            # Cookie 优先（同序号分支注释）；Token 仅作为无 Cookie 时的回退
            accounts.append(
                {
                    "token": None if cookie_val else token_val,
                    "cookie": cookie_val or None,
                    "fallback_cookie": fallback_cookie,
                    "env_cookie": env_cookie_val or None,
                    "index": 1,
                    "site": site,
                }
            )

    return accounts


def _touch_and_check(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]], str]:
    """触碰会话、验证登录态并查询今日 daily_active 交易记录。

    返回 (credited, user_info, transaction_record, error_msg)。
    """
    try:
        user = _touch_user(h, host, token=token, cookie=cookie)
    except Exception as e:
        return False, None, None, f"登录态验证失败：{e}"

    try:
        record = _get_today_daily_active(h, host, token=token, cookie=cookie)
    except Exception as e:
        return False, user, None, f"交易记录查询失败：{e}"

    # 若尚未查到今日到账，给予服务端异步发奖队列短暂缓冲（5s / 10s / 15s）并重触碰
    if record is None and cookie and not token:
        for wait in (5, 10, 15):
            time.sleep(wait)
            try:
                _touch_user(h, host, token=token, cookie=cookie)
                record = _get_today_daily_active(h, host, token=token, cookie=cookie)
                if record is not None:
                    break
            except Exception:
                pass

    credited = record is not None
    return credited, user, record, ""


def _run_one(account: Dict[str, Any], host: str) -> Tuple[bool, str]:
    """执行单个账号的签到逻辑。返回 (成功, 描述)。"""
    token = account.get("token")
    cookie = account.get("cookie")
    fallback_cookie = account.get("fallback_cookie")
    env_cookie = account.get("env_cookie") or ""
    idx = account.get("index", 1)
    site = account.get("site", "cn")

    proxy = (
        os.getenv("MODELSCOPE_PROXY", "").strip()
        or os.getenv("HTTPS_PROXY", "").strip()
        or os.getenv("https_proxy", "").strip()
    )
    h = Http(proxy=proxy)

    active_cookie = cookie
    credited, user, record, err = _touch_and_check(
        h, host, token=token, cookie=active_cookie
    )

    # 缓存 Cookie 失效或未到账时，自动回退尝试环境变量/Secrets 中的最新 Cookie
    if not credited and fallback_cookie and fallback_cookie != active_cookie:
        print(f"  [{idx}] 🔄 缓存 Cookie 登录态失效或未到账，尝试回退使用环境变量最新配置的 Cookie...")
        h_fallback = Http(proxy=proxy)
        fb_credited, fb_user, fb_record, fb_err = _touch_and_check(
            h_fallback, host, token=token, cookie=fallback_cookie
        )
        if fb_credited or (fb_user and not user):
            active_cookie = fallback_cookie
            credited, user, record, err = fb_credited, fb_user, fb_record, fb_err
            h = h_fallback

    if not user:
        return False, err or "登录态验证失败"

    name = user.get("nickname") or user.get("username") or ""
    uid = user.get("user_id") or user.get("id")
    parts = []
    if name:
        parts.append(mask_str(str(name)))
    if uid:
        parts.append(f"UID:{mask_str(str(uid))}")
    auth_tag = "Token" if token else "Cookie"
    parts.append(f"[{auth_tag}]")
    user_tag = " ".join(parts) or "未知用户"

    amount = (record or {}).get("total_amount", 200)
    expire_at = (record or {}).get("expire_at") or ""

    # 签到成功且使用 Cookie 时，持久化并滚动更新 Cookie 到 Redis state
    if credited and active_cookie and not token:
        updated_cookie = _merge_cookies(active_cookie, h.jar)
        if updated_cookie:
            state_file = f".modelscope_{site}_state_{idx}.json"
            redis_key = f"cat_checkin:state:modelscope_{site}_{idx}"
            env_hash = (
                hashlib.md5(env_cookie.encode("utf-8")).hexdigest()
                if env_cookie
                else ""
            )
            save_kv_state(
                redis_key,
                state_file,
                {
                    "cookie": updated_cookie,
                    "env_hash": env_hash,
                    "updated_at": int(time.time()),
                    "user_tag": user_tag,
                },
            )

    # 每日点击喜欢 20 次任务（单次 +2 魔粒，每日上限 20 次共 40 魔粒）
    like_msg = ""
    if user and active_cookie:
        used_likes, max_likes, amt_per_like = _get_daily_like_status(
            h, host, token=token, cookie=active_cookie
        )
        remaining_likes = max(0, max_likes - used_likes)
        if remaining_likes > 0:
            done_likes, earned_magicubes = _do_daily_likes(
                h,
                host,
                token=token,
                cookie=active_cookie,
                count=remaining_likes,
                amount_per_like=amt_per_like,
            )
            total_done = used_likes + done_likes
            like_msg = f"，完成点赞 {total_done}/{max_likes} 次 (+{total_done * amt_per_like} 魔粒)"
        else:
            like_msg = f"，点赞已达上限 {used_likes}/{max_likes} 次"

    if credited:
        exp_desc = f"，{expire_at} 过期" if expire_at else ""
        status = f"签到成功，今日已领取 {amount} 魔粒{like_msg}{exp_desc}"
    elif token and not cookie:
        # 2026-08-25 实测：Bearer Token 能通过 OpenAPI 鉴权，但 OpenAPI 调用不计入
        # 「日活」，daily_active 奖励永不发放——红卡必须直指根因，不再猜「重置时间」
        cookie_var = f"{PREFIX}COOKIE_{idx}" if site == "cn" else f"{PREFIX}AI_COOKIE_{idx}"
        status = (
            f"交易记录无今日 daily_active："
            f"Bearer Token 不触发 daily_active 日活奖励，"
            f"请配置浏览器 Cookie 环境变量 {cookie_var}（{site} 站）"
        )
    else:
        status = f"交易记录无今日 daily_active（Cookie 可能已失效需手动刷新）{like_msg}"

    return credited, f"{user_tag} {status}"


def _run_site(
    accounts: List[Dict[str, Any]], host: str, site: str, title: str
) -> Tuple[bool, List[str]]:
    """运行单个站点的所有账号。返回 (全部成功, 各行输出)。"""
    print(f"【{title}】")
    if not accounts:
        print(f"  未提供 {title} 凭证（Token / Cookie），跳过")
        return True, []

    print(f"  {len(accounts)} 个账号 @ {host}")
    results = []
    for idx, acc in enumerate(accounts, 1):
        try:
            ok, msg = _run_one(acc, host)
            line = f"  [{idx}/{len(accounts)}] {msg}"
            print(line)
            results.append((ok, line))
        except Exception as e:
            line = f"  [{idx}/{len(accounts)}] 签到失败：{e}"
            print(line)
            results.append((False, line))

    ok_count = sum(1 for ok, _ in results if ok)
    all_ok = ok_count == len(accounts)
    print(f"  {title} 总结：成功 {ok_count}/{len(accounts)}")
    return all_ok, [line for _, line in results]


def main():
    print("【ModelScope 签到】")

    # 国内站
    cn_accounts = _load_accounts("cn")
    # 国际站
    ai_accounts = _load_accounts("ai")
    if not cn_accounts and not ai_accounts:
        raise RuntimeError(
            f"缺少环境变量：{PREFIX}TOKEN（或 {PREFIX}TOKEN_1 / {PREFIX}COOKIE_1，国内站）"
            f" 或 {PREFIX}AI_TOKEN / {PREFIX}AI_COOKIE（国际站）"
        )

    cn_host = _default_host()
    ai_host = _ai_host()

    print(
        f"共 {len(cn_accounts) + len(ai_accounts)} 个账号"
        f"（国内 {len(cn_accounts)}，国际 {len(ai_accounts)}）\n"
    )

    # 分开运行，互不影响
    cn_ok, cn_lines = _run_site(cn_accounts, cn_host, "cn", "ModelScope 国内站 签到")
    print()
    ai_ok, ai_lines = _run_site(ai_accounts, ai_host, "ai", "ModelScope 国际站 签到")

    print(f"\n国内站：{'✅ 成功' if cn_ok else '❌ 失败'}")
    print(f"国际站：{'✅ 成功' if ai_ok else '❌ 失败'}")

    # 国内站失败 → 整体失败（国际站因凭证/时区偶发问题不阻塞整体）
    if not cn_ok:
        sys.exit(1)
    # 国际站失败时，打印警告但不退出（避免误报影响整体）
    if not ai_ok:
        print("\n⚠️ 国际站签到异常（通常为凭证需手动刷新，不影响国内站）")


if __name__ == "__main__":
    main_guard(main)
