#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("ModelScope 社区签到")
# new Env("ModelScope 国际站 签到")
"""ModelScope 魔搭社区每日签到（国内站 + 国际站分开处理）。

机制：
1. 登录奖励（每日 200 魔粒）在用户产生活跃会话后被动发放。
2. ⚠️ 2026-10-27：国内站出现账号封禁，点赞 / AIGC 发布 / 信息完善等互动任务
   已全部暂停（独立开关，默认 False），仅保留每日登录签到；点赞任务频率行为
   已优化（随机目标抽样 + 4~12s 拟人间隔），后期经开关开放。
   反风控加固同步落地：每账号固定 UA（state 持久化 + 合法性校验）、请求拟人
   随机间隔、触碰端点收敛、发奖缓冲期轻量触碰、启动抖动 0~120s、多账号
   强制间隔、每账号独立代理（MODELSCOPE_PROXY_{idx}）、暂停名单机制。
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
  MODELSCOPE_PAUSED_CN_ACCOUNTS / MODELSCOPE_PAUSED_AI_ACCOUNTS：
    暂停名单（逗号分隔账号序号，如 "2,3"），命中序号不加载、不触碰、不滚动 Cookie
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import dotenv
    dotenv.load_dotenv(override=False)
except ImportError:
    pass

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
import cookie_validity as cv

PREFIX = "MODELSCOPE_"

# 2026-10-27：国内站出现账号封禁，互动类任务全部暂停，仅保留每日登录签到
# （日活触碰 + daily_active 查询 + Cookie 滚动续期）。三类动作独立开关，默认全停：
#   MODELSCOPE_ENABLE_LIKE_TASKS=1      每日点赞（频率行为已优化，后期开放）
#   MODELSCOPE_ENABLE_AIGC_PUBLISH=1    AIGC 作品发布（AI 站链路未通，暂停 indefinitely）
#   MODELSCOPE_ENABLE_PROFILE_TASKS=1   信息完善（一次性任务）
# MODELSCOPE_ENABLE_BONUS_TASKS=1 可一键打开全部（单次手动运行用，日常调度不带）。
_ENABLE_ALL = (os.getenv("MODELSCOPE_ENABLE_BONUS_TASKS") or "").strip() == "1"
ENABLE_LIKE_TASKS = _ENABLE_ALL or (os.getenv("MODELSCOPE_ENABLE_LIKE_TASKS") or "").strip() == "1"
ENABLE_AIGC_PUBLISH = _ENABLE_ALL or (os.getenv("MODELSCOPE_ENABLE_AIGC_PUBLISH") or "").strip() == "1"
ENABLE_PROFILE_TASKS = _ENABLE_ALL or (os.getenv("MODELSCOPE_ENABLE_PROFILE_TASKS") or "").strip() == "1"

# 2026-10-27：国内站账号 2 已被平台封禁，暂停其全部任务行为——不加载、不触碰、
# 不滚动 Cookie，避免封禁账号继续产生自动化流量加深风控标记。
# 环境变量 MODELSCOPE_PAUSED_CN_ACCOUNTS / MODELSCOPE_PAUSED_AI_ACCOUNTS
# （逗号分隔序号，如 "2,3"）可整体覆盖此默认值；解封或换号后清空即可。
PAUSED_CN_ACCOUNTS = {2}

# 登录会话凭据 cookie（WAF/统计类短命 cookie 不作为有效期证据）
CREDENTIAL_COOKIES = ("m_session_id",)


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# 反风控：UA 池（2026-10-27 封禁复盘）。此前所有账号/所有天共用一个写死的 Chrome 131
# UA，是最易聚类识别的指纹。现改为每账号从池中随机选定一个真实形态的完整 UA，
# 随 state 持久化后长期保持稳定（真实浏览器 UA 不会天天变）。
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
]


def _valid_ua(ua: Optional[str]) -> bool:
    """恢复的 UA 必须是完整形态（telecom 2026-09-19 先例：截断 UA 会全面 412）。"""
    return bool(ua) and all(s in ua for s in ("Mozilla/5.0", "AppleWebKit", "Safari"))


def _human_pause(lo: float, hi: float) -> None:
    """请求间拟人随机间隔，消除秒级 burst 的机器时序特征。"""
    time.sleep(random.uniform(lo, hi))


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
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    ua: Optional[str] = None,
) -> Dict[str, str]:
    """构造带浏览器上下文或 Token 鉴权的请求头，避免被风控/埋点中间件忽略。"""
    headers = {
        "Origin": f"https://{host}",
        "Referer": f"https://{host}/my/overview",
        "User-Agent": ua if _valid_ua(ua) else DEFAULT_UA,
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
    h: Http,
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    ua: Optional[str] = None,
) -> Dict[str, Any]:
    """全链路触碰会话并验证登录态。

    1. 若有 Cookie，访问个人中心 Web 页面触发 Web 端活跃埋点中间件（页面收敛为
       最小集 + 拟人间隔，2026-10-27 封禁复盘：此前 6 页面 + 5 API 秒级连发）。
    2. 访问 magicubes 任务规则与余额端点，激活每日签到奖励系统。
    3. GET /openapi/v1/users/me 验证登录态并提取用户信息。
    """
    if cookie:
        web_headers = {
            "User-Agent": ua if _valid_ua(ua) else DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "Referer": f"https://{host}/",
            "Cookie": cookie,
        }
        page_status = []
        for path in ("/my/overview", "/"):
            _human_pause(0.8, 2.0)
            try:
                r = h.request("GET", f"https://{host}{path}", headers=web_headers, timeout=15)
                page_status.append(f"{path}={r.code}")
            except Exception:
                page_status.append(f"{path}=ERR")
        # web 触碰状态码：users/me（OpenAPI）与 Web 会话可能不同寿命，用于区分
        # 「API 正常但 Web 会话已死（日活埋点收不到）」的场景
        print(f"  [diag] web 触碰[{host}]: {' '.join(page_status)}")
        print(f"  [diag] 触碰响应下发 Cookie 字段[{host}]: {sorted({c.name for c in h.jar})}")
        # 2026-08-29 HAR 抓包确认：前端每次页面加载都会调 /api/v1/users/login/info
        # （daily_active 规则即「注册并登陆，每日登录即可获取」）——补齐这一登录事件触碰；
        # 其余 binding/medal 探针已裁剪（非日活必需，只增加风控暴露面）
        for api_path in ("/api/v1/users/login/info", "/api/v1/users/authorized/check"):
            _human_pause(0.5, 1.5)
            try:
                h.request("GET", f"https://{host}{api_path}", headers=web_headers, timeout=15)
            except Exception:
                pass

    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
    try:
        # 激活魔粒日常任务与余额系统（models/datasets/studios/posts 等铺量触碰已裁剪）
        for api_path in ("/openapi/v1/magicubes/earn/rules", "/openapi/v1/magicubes/balance"):
            _human_pause(0.4, 1.2)
            h.request("GET", f"https://{host}{api_path}", headers=hdrs, timeout=15)
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


def _created(rec: Dict[str, Any]) -> str:
    return str(
        rec.get("gmt_created") or rec.get("gmt_create") or rec.get("created_at") or ""
    )


def _parse_created(s: str) -> Optional[datetime]:
    """兼容字符串日期与 epoch 秒/毫秒时间戳，返回 BJT datetime 或 None。"""
    s = s.strip()
    if not s:
        return None
    if s.isdigit():
        v = int(s)
        if v > 10**12:  # epoch 毫秒
            v //= 1000
        try:
            return datetime.fromtimestamp(v, BJT)
        except (ValueError, OverflowError, OSError):
            return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=BJT)
        except ValueError:
            continue
    try:
        dtv = datetime.fromisoformat(s)
        return dtv.replace(tzinfo=BJT) if dtv.tzinfo is None else dtv
    except ValueError:
        return None


def _get_today_daily_active(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None,
    ua: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """查询每日签到（daily_active）奖励交易记录或任务完成状态。

    返回今日记录 dict 或 None；记录 source 字段区分：
      - "transaction" / "earn_rules"：今日已真实到账
      - "cooldown"：今日未到账但 24h 冷却未过（上次到账时间见 last_created），
        Cookie 登录态正常，非故障——调用方应视为绿卡
    """
    today = datetime.now(BJT)
    today_str = today.strftime("%Y-%m-%d")
    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)

    # 判据 1：交易记录直查（分页扫描至越过今日）
    seen_rule_keys = set()
    today_record_cnt = 0
    last_da_dt: Optional[datetime] = None
    last_da_raw = ""
    recent_samples: list = []
    resp = None
    try:
        for page in (1, 2, 3):
            if page > 1:
                _human_pause(0.5, 1.2)
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
                created_str = _created(rec)
                dt_val = _parse_created(created_str)
                if dt_val is not None:
                    if dt_val.date() == today.date():
                        today_record_cnt += 1
                    elif dt_val < today:
                        past_today = True
                if rule_key:
                    seen_rule_keys.add(rule_key)
                if len(recent_samples) < 10:
                    recent_samples.append((rule_key or "?", created_str[:19], rec.get("total_amount")))
                if rule_key == "daily_active":
                    if dt_val is not None and dt_val.date() == today.date():
                        rec["source"] = "transaction"
                        return rec
                    # 流水按时间倒序：扫描中首个 daily_active 即最近一次到账
                    if last_da_dt is None:
                        last_da_dt = dt_val
                        last_da_raw = created_str
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
                        # 诊断信息：双判据都未命中时能看到 daily_active 规则的完整字段，
                        # 便于区分「Cookie 失效」与「接口字段变更/任务未领取」
                        print(
                            f"  [diag] daily_active 规则未命中 today_used，完整字段："
                            f"{ {k: str(v)[:60] for k, v in r.items()} }"
                        )
    except Exception:
        pass

    if seen_rule_keys:
        print(f"  [diag] 交易记录扫描可见 rule_key：{sorted(seen_rule_keys)}")

    # 判据 3：24h 冷却识别——今日流水存在（登录态正常）但 daily_active 今日未到账。
    # gmt_created 可能只有日期没有时刻：带时刻时按时刻精确判断（<24h 才算冷却），
    # 纯日期时放宽为「上次到账日期为昨天及以上」视为冷却中（无法确定真实时刻，
    # 宁可绿卡一次；若连续两日仍未见新到账，下次运行会因日期变旧自动回到红卡）
    if last_da_dt is not None and today_record_cnt > 0:
        elapsed_h = (today - last_da_dt).total_seconds() / 3600
        raw = (last_da_raw or "").strip()
        if len(raw) <= 10 or ":" not in raw:  # 纯日期
            in_cooldown = last_da_dt.date() >= (today - timedelta(days=1)).date()
        else:  # 带时刻
            in_cooldown = 0 <= elapsed_h < 24
        if in_cooldown:
            eta_h = max(0.0, 24 - elapsed_h) if (len(raw) > 10 and ":" in raw) else 0.0
            eta_desc = f"{eta_h:.1f}h 后可领" if eta_h > 0 else "下次运行即可领取"
            print(
                f"  [diag] daily_active 24h 冷却中：上次到账 {last_da_raw} "
                f"（{elapsed_h:.1f}h 前），{eta_desc}"
            )
            return {
                "rule_key": "daily_active",
                "total_amount": 200,
                "expire_at": "",
                "source": "cooldown",
                "last_created": last_da_raw,
                "eta_hours": round(eta_h, 1),
            }

    # 诊断信息：双判据都未命中时打印关键原始数据，便于区分「Cookie 失效」、
    # 「24h 冷却未覆盖」与「接口字段变更」
    print(
        f"  [diag] 未命中：今日流水 {today_record_cnt} 条，"
        f"最近 daily_active 到账 {last_da_raw or '扫描窗口内未见'}，"
        f"earn/rules today_used=0"
    )
    if recent_samples:
        print(f"  [diag] 最近交易记录: {recent_samples}")
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
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None,
    ua: Optional[str] = None,
) -> Tuple[int, int, int]:
    """查询每日点赞/喜欢任务规则与进度。

    返回 (today_used, max_count, amount_per_like)。
    """
    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
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
    ua: Optional[str] = None,
) -> List[Dict[str, str]]:
    """发现可点赞的 MCP Server 目标列表。

    返回 [{"path": "Alipay", "name": "alipay-subscription"}, ...]
    """
    targets: List[Dict[str, str]] = []
    seen = set()
    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
    hdrs["Content-Type"] = "application/json"

    for page in range(1, 4):
        if len(targets) >= needed:
            break
        if page > 1:
            _human_pause(0.8, 2.0)
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

    # 返回完整池（含 already_star 标记），由调用方随机抽样——不再按固定顺序消费，
    # 避免所有账号每天点同一批目标形成协同指纹
    return targets


def _do_daily_likes(
    h: Http,
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    count: int = 20,
    amount_per_like: int = 2,
    ua: Optional[str] = None,
) -> Tuple[int, int]:
    """执行每日点击喜欢任务。

    2026-10-27 频率行为优化（封禁复盘）：不再以 0.2~0.4s 固定节奏连点固定顺序的
    目标列表——目标池随机抽样、未点赞目标优先、每次点赞间隔 4~12s 拟人随机，
    打散时序与目标指纹。返回 (成功次数, 获得魔粒数)。
    """
    if count <= 0:
        return 0, 0

    targets = _fetch_mcp_like_targets(
        h, host, token=token, cookie=cookie, needed=count * 2 + 20
    )
    if not targets:
        return 0, 0

    # 未点赞目标优先（避免对已收藏目标再 PUT 造成取消收藏），同组内随机打散
    fresh = [t for t in targets if not t.get("already_star")]
    starred = [t for t in targets if t.get("already_star")]
    random.shuffle(fresh)
    random.shuffle(starred)
    pool = fresh + starred

    success_cnt = 0
    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
    hdrs["Content-Type"] = "application/json"

    for t in pool:
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
        if success_cnt < count:
            _human_pause(4, 12)

    return success_cnt, success_cnt * amount_per_like


def _fetch_all_earn_rules(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None,
    ua: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """获取所有魔粒任务规则与当前状态字典。"""
    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
    rules_map: Dict[str, Dict[str, Any]] = {}
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
                    rk = str(r.get("rule_key") or "").strip()
                    if rk:
                        rules_map[rk] = r
    except Exception:
        pass
    return rules_map


def _fetch_magicubes_balance(
    h: Http, host: str, token: Optional[str] = None, cookie: Optional[str] = None,
    ua: Optional[str] = None,
) -> Dict[str, int]:
    """获取用户魔粒账户余额。"""
    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
    try:
        resp = h.request(
            "GET",
            f"https://{host}/openapi/v1/magicubes/balance",
            headers=hdrs,
            timeout=15,
        )
        if resp.code == 200:
            data = resp.json({})
            if data and data.get("success"):
                bdata = data.get("data") or {}
                return {
                    "total_balance": int(bdata.get("total_balance") or 0),
                    "available_balance": int(bdata.get("available_balance") or 0),
                    "frozen_amount": int(bdata.get("frozen_amount") or 0),
                }
    except Exception:
        pass
    return {"total_balance": 0, "available_balance": 0, "frozen_amount": 0}


def _do_profile_complement_tasks(
    h: Http,
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    user_info: Optional[Dict[str, Any]] = None,
    rules_map: Optional[Dict[str, Dict[str, Any]]] = None,
    preferred_target_id: Optional[str] = None,
    ua: Optional[str] = None,
) -> Tuple[int, List[str]]:
    """执行一次性信息完善任务（主页置顶、个人介绍）。

    返回 (获得魔粒数, 描述信息列表)。
    """
    if not cookie:
        return 0, []

    if rules_map is None:
        rules_map = _fetch_all_earn_rules(h, host, token=token, cookie=cookie)

    earned = 0
    msgs = []
    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
    hdrs["Content-Type"] = "application/json"
    uname = (user_info or {}).get("username") or (user_info or {}).get("user_name") or ""

    # 1. 配置个人主页置顶 (infocomplement_profile_banner, +50 长期魔粒)
    banner_rule = rules_map.get("infocomplement_profile_banner")
    if banner_rule and int(banner_rule.get("total_earned") or 0) == 0:
        target_id = preferred_target_id
        hl_type = 9 if target_id else 3
        # 若外部未传入自建资产，查询用户当前 highlights 或公开资产
        if not target_id and uname:
            try:
                r_hl = h.request(
                    "GET",
                    f"https://{host}/api/v1/users/homepage/highlights/{uname}",
                    headers=hdrs,
                    timeout=15,
                )
                if r_hl.code == 200:
                    hls = (r_hl.json({}).get("Data") or {}).get("Highlights") or []
                    if hls:
                        # 已经有置顶项，任务可能处于未刷新状态
                        target_id = str(hls[0].get("TargetID") or "")
                        hl_type = int(hls[0].get("HighlightType") or 9)
            except Exception:
                pass

        if target_id:
            try:
                resp = h.request(
                    "POST",
                    f"https://{host}/api/v1/users/homepage/highlights",
                    headers=hdrs,
                    json_data={
                        "highlights": [
                            {
                                "HighlightType": hl_type,
                                "TargetID": str(target_id),
                            }
                        ]
                    },
                    timeout=15,
                )
                if resp.code == 200:
                    res_data = resp.json({})
                    if res_data.get("Success") or res_data.get("Code") == 200:
                        earned += int(banner_rule.get("amount") or 50)
                        msgs.append("主页置顶(+50)")
            except Exception:
                pass

    # 2. 编辑个人介绍 (infocomplement_profile_experience, +50 长期魔粒)
    exp_rule = rules_map.get("infocomplement_profile_experience")
    if exp_rule and int(exp_rule.get("total_earned") or 0) == 0:
        try:
            resp_info = h.request(
                "GET",
                f"https://{host}/api/v1/users/info",
                headers=hdrs,
                timeout=15,
            )
            curr_info = {}
            if resp_info.code == 200:
                curr_info = resp_info.json({}).get("Data") or {}

            curr_desc = str(curr_info.get("description") or "").strip()
            if not curr_desc or curr_desc in ("{}", '""'):
                default_desc = json.dumps(
                    {
                        "blocks": [
                            {
                                "key": "b1",
                                "text": "AI & Open Source Developer | ModelScope Community",
                                "type": "unstyled",
                                "depth": 0,
                                "inlineStyleRanges": [],
                                "entityRanges": [],
                                "data": {},
                            }
                        ],
                        "entityMap": {},
                    }
                )
                post_data = {
                    "description": default_desc,
                    "UserNickName": curr_info.get("user_nickname") or uname,
                    "ProfileTemplate": int(curr_info.get("profile_template") or 0),
                    "Experiences": "[]",
                    "SocialLinks": "[]",
                }
                resp_save = h.request(
                    "POST",
                    f"https://{host}/api/v1/users/info",
                    headers=hdrs,
                    json_data=post_data,
                    timeout=15,
                )
                if resp_save.code == 200:
                    res_data = resp_save.json({})
                    if res_data.get("Success") or res_data.get("Code") == 200:
                        earned += int(exp_rule.get("amount") or 50)
                        msgs.append("完善个人介绍(+50)")
        except Exception:
            pass

    return earned, msgs


def _do_daily_aigc_publish(
    h: Http,
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    count: int = 10,
    amount_per_publish: int = 10,
    username: Optional[str] = None,
    ua: Optional[str] = None,
) -> Tuple[int, int, Optional[str]]:
    """执行每日发布 AIGC 作品并触发有效浏览量（≥1）任务。

    返回 (成功发布次数, 获得魔粒数, 最后一个发布的作品ID)。
    """
    if count <= 0 or not cookie:
        return 0, 0, None

    hdrs = _headers(host, token=token, cookie=cookie, ua=ua)
    hdrs["Content-Type"] = "application/json"
    success_cnt = 0
    last_pic_id: Optional[str] = None

    # 合规优质示例素材图（社区公用加速资源）
    sample_img_url = (
        "https://img.alicdn.com/imgextra/i1/O1CN01yhHrHg1Pdl3UKPhGc_!!6000000001864-2-tps-88-88.png"
    )

    for i in range(count):
        try:
            # 1. 登记素材资源（后端真实路由 /api/v1/muse/image/create）
            create_resp = h.request(
                "POST",
                f"https://{host}/api/v1/muse/image/create",
                headers=hdrs,
                json_data=[
                    {
                        "height": 1024,
                        "width": 1024,
                        "index": 0,
                        "sourceType": "MUSE_UPLOAD",
                        "url": sample_img_url,
                        "mediaType": "IMAGE",
                    }
                ],
                timeout=15,
            )
            if create_resp.code != 200:
                print(f"  [aigc:{i+1}] create 失败 HTTP {create_resp.code}: {create_resp.text[:150]}")
                continue
            create_data = create_resp.json({})
            res_items = (create_data.get("Data") or {}).get("data") or create_data.get("data") or []
            if not res_items or not isinstance(res_items, list):
                print(f"  [aigc:{i+1}] create 响应无素材项: {str(create_data)[:200]}")
                continue
            item = res_items[0] or {}
            img_id = item.get("id")
            if not img_id:
                print(f"  [aigc:{i+1}] create 素材项无 id，字段: {sorted(item.keys())}")
                continue
            print(
                f"  [aigc:{i+1}] create OK id={img_id!r}({type(img_id).__name__}) "
                f"完整值: { {k: str(v)[:60] for k, v in item.items()} }"
            )
            # 立即反查该素材是否可查（upload 报「Image information query is empty」
            # 说明其内部查询查不到这条记录——区分「记录不存在」与「查询条件不同」）
            try:
                chk = h.request(
                    "GET",
                    f"https://{host}/api/v1/muse/image/get?id={img_id}",
                    headers=hdrs,
                    timeout=10,
                )
                print(f"  [aigc:{i+1}] muse/image/get 反查: HTTP {chk.code} {chk.text[:200]}")
            except Exception as exc:
                print(f"  [aigc:{i+1}] muse/image/get 反查异常: {exc}")

            # 2. 补齐生成与模型参数
            rand_code = random.randint(1000, 9999)
            upd_resp = h.request(
                "POST",
                f"https://{host}/api/v1/muse/image/updateImageGenerateInfo",
                headers=hdrs,
                json_data=[
                    {
                        "imageId": img_id,
                        "imageUrl": sample_img_url,
                        "prompt": (
                            f"Cute cyber cat in neon sci-fi wonderland #{rand_code}, "
                            "8k resolution, highly detailed"
                        ),
                        "negativePrompt": "blurry, low quality, distorted",
                        "numInferenceSteps": 20,
                        "sampler": "Euler",
                        "guidanceScale": 7.5,
                        "checkpointModelVersionId": 469191,
                    }
                ],
                timeout=15,
            )
            if upd_resp.code != 200:
                print(
                    f"  [aigc:{i+1}] updateInfo 失败 HTTP {upd_resp.code}: {upd_resp.text[:150]}"
                )

            # 3. 发布到创意广场
            muse_id = img_id
            if isinstance(muse_id, str) and muse_id.isdigit():
                muse_id = int(muse_id)
            upload_resp = h.request(
                "POST",
                f"https://{host}/api/v1/aigc/picture/upload",
                headers=hdrs,
                json_data={
                    "Title": f"Cyber Cat #{rand_code}",
                    "MuseImages": [
                        {
                            "MuseImageID": muse_id,
                            "IsCoverImage": 1,
                        }
                    ],
                    "Labels": ["photography", "dimension"],
                },
                timeout=15,
            )
            if upload_resp.code != 200:
                print(f"  [aigc:{i+1}] upload 失败 HTTP {upload_resp.code}: {upload_resp.text[:150]}")
                continue
            upload_data = upload_resp.json({})
            if not (
                upload_data.get("Success")
                or upload_data.get("Code") == 200
                or upload_data.get("Message") == "success"
            ):
                print(f"  [aigc:{i+1}] upload 业务失败: {str(upload_data)[:200]}")
                continue

            pic_id = (upload_data.get("Data") or {}).get("id") or (upload_data.get("Data") or {}).get("PictureId")
            if pic_id:
                last_pic_id = str(pic_id)

            # 4. 产生有效浏览量记录（触发「浏览量≥1」规则）：
            # 完整模拟个人主页作品列表卡片点击与分享页访问链路
            if pic_id:
                uname = username or ""
                # A. 个人主页作品卡片点击跳转作品分享页 HTML
                hdrs_share = dict(hdrs)
                if uname:
                    hdrs_share["Referer"] = f"https://{host}/profile/{uname}"
                try:
                    h.request(
                        "GET",
                        f"https://{host}/aigc/gallery/share/{pic_id}?source=InnovateSquare",
                        headers=hdrs_share,
                        timeout=10,
                    )
                except Exception:
                    pass

                # B. 作品业务详情 API 请求（带作品分享页 Referer）
                hdrs_pic = dict(hdrs)
                hdrs_pic["Referer"] = f"https://{host}/aigc/gallery/share/{pic_id}?source=InnovateSquare"
                try:
                    h.request(
                        "GET",
                        f"https://{host}/api/v1/aigc/picture/{pic_id}",
                        headers=hdrs_pic,
                        timeout=10,
                    )
                except Exception:
                    pass

                # C. 关联 Muse 图像元数据请求
                try:
                    h.request(
                        "GET",
                        f"https://{host}/api/v1/muse/image/get?id={img_id}",
                        headers=hdrs_pic,
                        timeout=10,
                    )
                except Exception:
                    pass

                # D. 个人主页作品聚合刷新触碰（触发个人主页作品卡片更新）
                if uname:
                    try:
                        h.request(
                            "PUT",
                            f"https://{host}/api/v1/dolphin/agg",
                            headers=hdrs,
                            json_data={
                                "Query": "",
                                "Target": "",
                                "Path": uname,
                                "IncludePrePublish": True,
                                "IncludeAllStatus": True,
                                "SortBy": "gmt_modified",
                            },
                            timeout=10,
                        )
                    except Exception:
                        pass

            success_cnt += 1
            time.sleep(random.uniform(0.3, 0.6))
        except Exception as exc:
            print(f"  [aigc:{i+1}] 发布链路异常: {type(exc).__name__}: {exc}")

    return success_cnt, success_cnt * amount_per_publish, last_pic_id


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


def _paused_accounts(site: str) -> set:
    """返回指定站点需要暂停的账号序号集合（环境变量优先，硬编码为默认值）。"""
    override = (os.getenv(f"{PREFIX}PAUSED_{site.upper()}_ACCOUNTS") or "").strip()
    if override:
        try:
            return {int(x) for x in override.replace("，", ",").split(",") if x.strip()}
        except ValueError:
            print(f"  ⚠️ {PREFIX}PAUSED_{site.upper()}_ACCOUNTS 格式非法（{override}），忽略")
    return set(PAUSED_CN_ACCOUNTS) if site == "cn" else set()


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

    paused = _paused_accounts(site)

    # 1. 扫描 1..20 显式序号
    for idx in range(1, 21):
        if idx in paused:
            print(f"  [pause] {site} 站账号 {idx} 处于暂停名单（封禁/风控），跳过加载")
            continue
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
                if sub_idx in paused:
                    print(f"  [pause] {site} 站账号 {sub_idx} 处于暂停名单（封禁/风控），跳过加载")
                    continue
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
                if sub_idx in paused:
                    print(f"  [pause] {site} 站账号 {sub_idx} 处于暂停名单（封禁/风控），跳过加载")
                    continue
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
            if 1 in paused:
                print(f"  [pause] {site} 站账号 1 处于暂停名单（封禁/风控），跳过加载")
            else:
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


def _light_touch(
    h: Http, host: str, ua: Optional[str] = None, cookie: Optional[str] = None
) -> None:
    """轻量日活触碰：仅 login/info 登录事件（HAR 证据显示 daily_active 由它触发）。

    用于发奖异步缓冲期的重试——不重放整轮 web 页面触碰，避免每轮 17+ 请求的
    秒级 burst 指纹。
    """
    if not cookie:
        return
    web_headers = {
        "User-Agent": ua if _valid_ua(ua) else DEFAULT_UA,
        "Accept": "application/json, text/plain, */*",
        "Referer": f"https://{host}/my/overview",
        "Cookie": cookie,
    }
    try:
        h.request("GET", f"https://{host}/api/v1/users/login/info", headers=web_headers, timeout=15)
    except Exception:
        pass


def _touch_and_check(
    h: Http,
    host: str,
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    ua: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]], str]:
    """触碰会话、验证登录态并查询今日 daily_active 交易记录。

    返回 (credited, user_info, transaction_record, error_msg)。
    """
    try:
        user = _touch_user(h, host, token=token, cookie=cookie, ua=ua)
    except Exception as e:
        return False, None, None, f"登录态验证失败：{e}"

    try:
        record = _get_today_daily_active(h, host, token=token, cookie=cookie, ua=ua)
    except Exception as e:
        return False, user, None, f"交易记录查询失败：{e}"

    # 若尚未查到今日到账，给予服务端异步发奖队列缓冲（等待抖动 ±20%），
    # 缓冲期间只做轻量触碰（login/info），不再重放整轮页面触碰
    if record is None and cookie and not token:
        for wait in (8, 16, 28):
            time.sleep(wait * random.uniform(0.85, 1.2))
            try:
                _light_touch(h, host, ua=ua, cookie=cookie)
                record = _get_today_daily_active(h, host, token=token, cookie=cookie, ua=ua)
                if record is not None:
                    break
            except Exception:
                pass

    credited = record is not None and (record or {}).get("source") != "cooldown"
    return credited, user, record, ""


def _persist_last_credit_ts(task_id: str, ts: Optional[float]) -> None:
    """把最近一次 daily_active 发放时刻写入通知状态（心跳 DUE_ONLY 调度的状态来源）。

    只允许变新（历史观测不得覆盖更新的记录）；TASK_ID 缺失（双站兼容模式）时跳过。
    """
    if not task_id or not ts:
        return
    try:
        from common import load_kv_state, save_kv_state
        prefix = (os.getenv("CAT_CHECKIN_REDIS_PREFIX") or "cat_checkin:").rstrip(":")
        state_file = f".notify_state_{task_id}.json"
        state = load_kv_state(f"{prefix}:state:notify:{task_id}", state_file)
        prev = float(state.get("last_credit_ts") or 0)
        if ts > prev:
            state["last_credit_ts"] = ts
            state["updated_at"] = int(time.time())
            save_kv_state(f"{prefix}:state:notify:{task_id}", state_file, state)
            print(f"  [sched] last_credit_ts → {datetime.fromtimestamp(ts, timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')} BJT")
    except Exception as exc:
        print(f"  ⚠️ last_credit_ts 持久化失败: {exc}")


def _run_one(account: Dict[str, Any], host: str) -> Tuple[bool, str, Optional[float]]:
    """执行单个账号的签到逻辑。返回 (成功, 描述, 最近 daily_active 发放时刻或 None)。"""
    token = account.get("token")
    cookie = account.get("cookie")
    fallback_cookie = account.get("fallback_cookie")
    env_cookie = account.get("env_cookie") or ""
    idx = account.get("index", 1)
    site = account.get("site", "cn")

    # 每账号固定 UA：从 state 恢复（telecom 先例：截断/非法 UA 一律弃用），
    # 无有效 UA 则从池中随机选定一个并在本次运行结束时随 state 持久化，
    # 此后该账号长期保持同一 UA（真实浏览器的 UA 不会每天变）
    state_file = f".modelscope_{site}_state_{idx}.json"
    redis_key = f"cat_checkin:state:modelscope_{site}_{idx}"
    acc_state = load_kv_state(redis_key, state_file) or {}
    ua = str(acc_state.get("ua") or "").strip()
    if not _valid_ua(ua):
        ua = random.choice(UA_POOL)
        # 立即固化：即使本次登录失败（后续 save 不触发），UA 也不至于每次运行都换
        acc_state["ua"] = ua
        save_kv_state(redis_key, state_file, acc_state)
        print(f"  [{idx}] [ua] 账号 UA 未初始化或非法，已选定新 UA（持久化后保持稳定）")

    # 每账号独立代理（MODELSCOPE_PROXY_{idx}）优先：多账号共机共 IP 是最直接的
    # 聚类特征，可为不同账号配置不同代理；未配置则回退任务级/全局代理
    proxy = (
        os.getenv(f"{PREFIX}PROXY_{idx}", "").strip()
        or os.getenv("MODELSCOPE_PROXY", "").strip()
        or os.getenv("HTTPS_PROXY", "").strip()
        or os.getenv("https_proxy", "").strip()
    )
    h = Http(proxy=proxy)

    active_cookie = cookie
    credited, user, record, err = _touch_and_check(
        h, host, token=token, cookie=active_cookie, ua=ua
    )

    # 缓存 Cookie 失效或未到账时，自动回退尝试环境变量/Secrets 中的最新 Cookie
    # （冷却期 cooldown 不回退：今日流水已证明登录态正常，回退无意义）
    if not credited and record is None and fallback_cookie and fallback_cookie != active_cookie:
        print(f"  [{idx}] 🔄 缓存 Cookie 登录态失效或未到账，尝试回退使用环境变量最新配置的 Cookie...")
        h_fallback = Http(proxy=proxy)
        fb_credited, fb_user, fb_record, fb_err = _touch_and_check(
            h_fallback, host, token=token, cookie=fallback_cookie, ua=ua
        )
        if fb_credited or (fb_user and not user):
            active_cookie = fallback_cookie
            credited, user, record, err = fb_credited, fb_user, fb_record, fb_err
            h = h_fallback

    # 「每日登录」事件可能记录在账号注册站（CN 站）：AI 站账号 daily_active 未到账时，
    # 用同一 Cookie 触碰 CN 站 Web 页面补登录事件，再在两个站复查 daily_active
    if site == "ai" and record is None and user and active_cookie:
        cn_host = "www.modelscope.cn"
        print(f"  [{idx}] 🧪 daily_active 未到账，尝试 CN 站跨站登录触碰（{cn_host}）...")
        cn_h = Http(proxy=proxy)
        cn_ok = True
        try:
            _touch_user(cn_h, cn_host, token=token, cookie=active_cookie, ua=ua)
        except Exception as exc:
            cn_ok = False
            print(f"  [{idx}] [diag] CN 站触碰/登录态校验失败：{exc}")
        if cn_ok:
            for check_host, check_h in ((cn_host, cn_h), (host, h)):
                try:
                    rec = _get_today_daily_active(
                        check_h, check_host, token=token, cookie=active_cookie, ua=ua
                    )
                except Exception:
                    rec = None
                if rec is not None:
                    print(f"  [{idx}] ✅ CN 站触碰后 daily_active 已在 {check_host} 查到今日记录")
                    record = rec
                    credited = rec.get("source") != "cooldown"
                    # CN 站触碰可能换发了新会话 Cookie，合并进活动 Cookie 以便滚动持久化
                    active_cookie = _merge_cookies(active_cookie, cn_h.jar) or active_cookie
                    break

    # 观测最近一次 daily_active 发放时刻（心跳 DUE_ONLY 调度的状态来源）：
    # 今日流水命中 → 发放时刻即该流水 gmt_created；earn/rules 命中（时刻未知）→
    # 取当前（偏晚安全，只会延后下次到期不会提前）；冷却中 → 上次发放时刻；
    # 完全未见 → None（不更新状态）
    credit_ts: Optional[float] = None
    if record:
        src = record.get("source")
        if src == "transaction":
            dtv = _parse_created(_created(record))
            credit_ts = dtv.timestamp() if dtv else time.time()
        elif src == "cooldown":
            dtv = _parse_created(str(record.get("last_created") or ""))
            credit_ts = dtv.timestamp() if dtv else None
        elif credited:
            credit_ts = time.time()

    if not user:
        return False, err or "登录态验证失败", None

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

    # 诊断：cookie 字段构成（只打印字段名与数量，不打印值）与用户对象字段，
    # 用于对比「发奖正常」与「未发奖」账号的 Cookie/账户差异
    cnames = [p.split("=", 1)[0].strip() for p in (active_cookie or "").split(";") if "=" in p]
    print(f"  [{idx}] [diag] cookie 字段({len(cnames)}): {cnames}")
    print(f"  [{idx}] [diag] 用户字段: {sorted(str(k) for k in user.keys())}")

    amount = (record or {}).get("total_amount", 200)
    expire_at = (record or {}).get("expire_at") or ""

    # 登录态健康（签到成功 / 24h 冷却 / daily_active 未到账）且使用 Cookie 时，
    # 都持久化并滚动更新 Cookie——确保服务端在触碰过程中下发的新 Cookie 得以积累，
    # 避免「daily_active 未到账的账号永远卡在最初的 env Cookie」而无法自愈；
    # 同时经共享引擎跟踪凭据有效期（换新 Cookie 指纹变更自动重置计时）
    validity_tag = ""
    if user and active_cookie and not token:
        updated_cookie = _merge_cookies(active_cookie, h.jar)
        if updated_cookie:
            env_hash = (
                hashlib.md5(env_cookie.encode("utf-8")).hexdigest()
                if env_cookie
                else ""
            )
            learned = cv.learn_from_jar(
                h.jar, credential_match=lambda n: n in CREDENTIAL_COOKIES
            )
            tracked = cv.update_state(
                load_kv_state(redis_key, state_file) or {}, updated_cookie, learned
            )
            validity_tag = cv.tag_for(
                updated_cookie, tracked, learned, credential_match=lambda n: n in CREDENTIAL_COOKIES
            )
            save_kv_state(
                redis_key,
                state_file,
                {
                    **tracked,
                    "cookie": updated_cookie,
                    "env_hash": env_hash,
                    "updated_at": int(time.time()),
                    "user_tag": user_tag,
                    "ua": ua,
                },
            )

    # 查询全量魔粒规则与当前配额状态
    rules_map = (
        _fetch_all_earn_rules(h, host, token=token, cookie=active_cookie, ua=ua)
        if user and active_cookie
        else {}
    )

    # 1. 每日点击喜欢任务（单次 +2 魔粒，每日上限 10 次共 20 魔粒）——默认停，见 ENABLE_LIKE_TASKS
    if user and active_cookie and ENABLE_LIKE_TASKS:
        like_rule = rules_map.get("interaction_like", {})
        max_likes = int(like_rule.get("daily_cap") or 10)
        used_likes = int(like_rule.get("today_used") or 0)
        amt_per_like = int(like_rule.get("amount") or 2)
        remaining_likes = max(0, max_likes - used_likes)
        if remaining_likes > 0:
            _do_daily_likes(
                h,
                host,
                token=token,
                cookie=active_cookie,
                count=remaining_likes,
                amount_per_like=amt_per_like,
                ua=ua,
            )

    # 2. 每日发布 AIGC 作品并触发有效浏览任务（单次 +10 魔粒，每日上限 10 次共 100 魔粒）——已暂停
    done_aigc_cnt = 0
    last_published_id = None
    if user and active_cookie and ENABLE_AIGC_PUBLISH:
        aigc_rule = rules_map.get("opensource_aigcworks_publish", {})
        max_aigc = int(aigc_rule.get("daily_cap") or 10)
        used_aigc = int(aigc_rule.get("today_used") or 0)
        amt_per_aigc = int(aigc_rule.get("amount") or 10)
        remaining_aigc = max(0, max_aigc - used_aigc)
        if remaining_aigc > 0:
            uname_val = (user or {}).get("username") or (user or {}).get("user_name") or ""
            done_aigc_cnt, _, last_published_id = _do_daily_aigc_publish(
                h,
                host,
                token=token,
                cookie=active_cookie,
                count=remaining_aigc,
                amount_per_publish=amt_per_aigc,
                username=uname_val,
                ua=ua,
            )

    # 3. 信息完善任务（主页置顶 +50 长期魔粒，完善个人介绍 +50 长期魔粒）——默认停
    if user and active_cookie and ENABLE_PROFILE_TASKS:
        _do_profile_complement_tasks(
            h,
            host,
            token=token,
            cookie=active_cookie,
            user_info=user,
            rules_map=rules_map,
            preferred_target_id=last_published_id,
            ua=ua,
        )

    # 任务动作执行完毕后，重新拉取服务端最新真实账本（确保所有魔粒到账数据与余额绝对吻合）
    latest_rules = (
        _fetch_all_earn_rules(h, host, token=token, cookie=active_cookie, ua=ua)
        if user and active_cookie
        else {}
    )

    # 1. 真实点赞状态与收益
    like_msg = ""
    if user and active_cookie:
        lr = latest_rules.get("interaction_like", {})
        l_cap = int(lr.get("daily_cap") or 10)
        l_used = int(lr.get("today_used") or 0)
        l_earned = int(lr.get("today_earned_amount") or 0)
        if l_earned > 0:
            like_msg = f"，完成点赞 {l_used}/{l_cap} 次 (+{l_earned} 魔粒)"
        elif l_used >= l_cap:
            like_msg = f"，点赞已达上限 {l_used}/{l_cap} 次"
        elif l_used > 0:
            like_msg = f"，已点赞 {l_used}/{l_cap} 次"

    # 2. 真实 AIGC 发布状态与收益（区分实时到账 vs 批处理待结算）
    aigc_msg = ""
    if user and active_cookie:
        ar = latest_rules.get("opensource_aigcworks_publish", {})
        a_cap = int(ar.get("daily_cap") or 10)
        a_used = int(ar.get("today_used") or 0)
        a_earned = int(ar.get("today_earned_amount") or 0)
        if a_earned > 0:
            aigc_msg = f"，完成AIGC发布 {a_used}/{a_cap} 次 (+{a_earned} 魔粒)"
        elif a_used >= a_cap:
            aigc_msg = f"，AIGC发布已达上限 {a_used}/{a_cap} 次"
        elif done_aigc_cnt > 0:
            aigc_msg = f"，完成AIGC发布 {done_aigc_cnt} 次(待结算)"

    # 3. 真实信息完善收益（主页置顶 +50、个人介绍 +50）
    profile_msg = ""
    if user and active_cookie:
        p_items = []
        br = latest_rules.get("infocomplement_profile_banner", {})
        if int(br.get("today_earned_amount") or 0) > 0:
            p_items.append(f"主页置顶(+{br.get('today_earned_amount')})")
        er = latest_rules.get("infocomplement_profile_experience", {})
        if int(er.get("today_earned_amount") or 0) > 0:
            p_items.append(f"完善个人介绍(+{er.get('today_earned_amount')})")
        vr = latest_rules.get("infocomplement_email_verification", {})
        if int(vr.get("today_earned_amount") or 0) > 0:
            p_items.append(f"验证邮箱(+{vr.get('today_earned_amount')})")
        if p_items:
            profile_msg = "，" + "，".join(p_items)

    # 4. 账号加成实际收益（阿里云绑定 +50、勋章 +20 等）
    extra_msgs = []
    ali_r = latest_rules.get("aliyun_bindlogin", {})
    if int(ali_r.get("today_earned_amount") or 0) > 0:
        extra_msgs.append(f"阿里云绑定(+{ali_r.get('today_earned_amount')})")
    badge_r = latest_rules.get("badge_magicube_shortterm", {})
    if int(badge_r.get("today_earned_amount") or 0) > 0:
        extra_msgs.append(f"勋章激励(+{badge_r.get('today_earned_amount')})")
    extra_msg = ("，" + "，".join(extra_msgs)) if extra_msgs else ""

    # 5. 魔粒可用余额（以服务端当前 balance 接口为准）
    bal_msg = ""
    if user and active_cookie:
        bal = _fetch_magicubes_balance(h, host, token=token, cookie=active_cookie, ua=ua)
        if bal.get("available_balance") is not None:
            bal_msg = f"，可用余额 {bal['available_balance']} 魔粒"

    task_details = f"{extra_msg}{like_msg}{aigc_msg}{profile_msg}{bal_msg}"

    if credited:
        # 「过期」主体是本次到账的魔粒奖励（流水自带 expire_at，非 Cookie 有效期）——
        # 必须写明「魔粒」，否则读者会误读成 Cookie/凭据即将过期；
        # 日报解析器按「过期$」行尾锚定提取，有效期标签须置于 exp_desc 之前
        exp_desc = f"，魔粒 {expire_at} 过期" if expire_at else ""
        status = f"签到成功，今日已领取 {amount} 魔粒{task_details}{validity_tag}{exp_desc}"
        return True, f"{user_tag} {status}", credit_ts

    # 24h 冷却期：今日流水正常（点赞/触碰均已生效），仅奖励未到账，报绿卡避免误报
    # 「Cookie 失效」红卡并触发无意义的自动重跑（冷却期内重跑多少次都不会发奖）
    if (record or {}).get("source") == "cooldown":
        eta_h = float(record.get("eta_hours") or 0)
        eta_desc = (
            f"预计 {int(eta_h)} 小时 {int(round(eta_h % 1 * 60))} 分钟后可领" if eta_h > 0 else "下次运行即可领取"
        )
        status = (
            f"今日 daily_active 未到账：24h 冷却中（上次到账 {record.get('last_created', '?')}），"
            f"Cookie 登录态正常，{eta_desc}{task_details}"
        )
        return True, f"{user_tag} {status}{validity_tag}", credit_ts

    if token and not cookie:
        # 2026-08-25 实测：Bearer Token 能通过 OpenAPI 鉴权，但 OpenAPI 调用不计入
        # 「日活」，daily_active 奖励永不发放——红卡必须直指根因，不再猜「重置时间」
        cookie_var = f"{PREFIX}COOKIE_{idx}" if site == "cn" else f"{PREFIX}AI_COOKIE_{idx}"
        status = (
            f"交易记录无今日 daily_active："
            f"Bearer Token 不触发 daily_active 日活奖励，"
            f"请配置浏览器 Cookie 环境变量 {cookie_var}（{site} 站）"
        )
    else:
        # 走到这里说明 users/me 登录态验证已通过（Cookie 未失效），但奖励未发放：
        # 多为该账号当天缺乏被服务端认可的「日活」行为或奖励规则变化
        status = (
            f"交易记录无今日 daily_active（登录态正常、Cookie 未失效；"
            f"请在浏览器实际登录使用该账号触发日活，连续多日未发放再更新 Cookie）{task_details}"
        )

    return credited, f"{user_tag} {status}{validity_tag}", credit_ts


def _run_site(
    accounts: List[Dict[str, Any]], host: str, site: str, title: str
) -> Tuple[bool, List[str], Optional[float]]:
    """运行单个站点的所有账号。返回 (全部成功, 各行输出, 最近 daily_active 发放时刻)。"""
    print(f"【{title}】")
    if not accounts:
        print(f"  未提供 {title} 凭证（Token / Cookie），跳过")
        return True, [], None

    print(f"  {len(accounts)} 个账号 @ {host}")
    results = []
    latest_ts: Optional[float] = None
    for idx, acc in enumerate(accounts, 1):
        # 多账号共 run 时强制间隔：消除「同 IP、同 UA、请求序列一致、背靠背执行」
        # 的多账号聚类特征（2026-10-27 封禁复盘：单 IP 秒级连续切换账号）
        if idx > 1:
            gap = random.uniform(20, 60)
            print(f"  ⏳ 账号间隔 {gap:.0f}s（反多账号时序聚类）")
            time.sleep(gap)
        try:
            ok, msg, credit_ts = _run_one(acc, host)
            if credit_ts and (latest_ts is None or credit_ts > latest_ts):
                latest_ts = credit_ts
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
    return all_ok, [line for _, line in results], latest_ts


def _run_single_site(site: str) -> None:
    """单站点模式（MODELSCOPE_SITE=cn/ai）：只跑指定站点，站点失败即退出非零。

    供 task_registry 拆分的两个独立任务实例调用（国内站/国际站分开调度、
    各自独立失败卡与通知状态）。
    """
    is_cn = site == "cn"
    accounts = _load_accounts("cn" if is_cn else "ai")
    if not accounts:
        var = f"{PREFIX}TOKEN（或 {PREFIX}TOKEN_1 / {PREFIX}COOKIE_1）" if is_cn \
            else f"{PREFIX}AI_TOKEN / {PREFIX}AI_COOKIE"
        raise RuntimeError(f"ModelScope {'国内' if is_cn else '国际'}站缺少环境变量：{var}")

    host = _default_host() if is_cn else _ai_host()
    title = "ModelScope 国内站 签到" if is_cn else "ModelScope 国际站 签到"
    print(f"共 {len(accounts)} 个账号 @ {host}\n")  # 站点标题由 _run_site 统一打印

    ok, _lines, latest_ts = _run_site(accounts, host, site, title)
    _persist_last_credit_ts((os.getenv("TASK_ID") or "").strip(), latest_ts)
    print(f"\n{'国内站' if is_cn else '国际站'}：{'✅ 成功' if ok else '❌ 失败'}")
    if not ok:
        sys.exit(1)


def _run_both_sites() -> None:
    """双站顺序执行（兼容青龙/本地手动场景，未设置 MODELSCOPE_SITE 时）。"""
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
    cn_ok, cn_lines, _cn_ts = _run_site(cn_accounts, cn_host, "cn", "ModelScope 国内站 签到")
    print()
    ai_ok, ai_lines, _ai_ts = _run_site(ai_accounts, ai_host, "ai", "ModelScope 国际站 签到")

    print(f"\n国内站：{'✅ 成功' if cn_ok else '❌ 失败'}")
    print(f"国际站：{'✅ 成功' if ai_ok else '❌ 失败'}")

    # 国内站失败 → 整体失败（国际站因凭证/时区偶发问题不阻塞整体）
    if not cn_ok:
        sys.exit(1)
    # 国际站失败时，打印警告但不退出（避免误报影响整体）
    if not ai_ok:
        print("\n⚠️ 国际站签到异常（通常为凭证需手动刷新，不影响国内站）")


def main():
    # 启动抖动：rolling 调度本身按 24h 状态散点，这里再加 0~120s 随机延迟，
    # 打破「误差 <1 分钟的准点周期」规律（MODELSCOPE_START_JITTER=0 可关闭，本地调试用）
    if (os.getenv("MODELSCOPE_START_JITTER") or "").strip() != "0":
        delay = random.uniform(0, 120)
        print(f"[jitter] 启动抖动 {delay:.0f}s（反准点周期规律）")
        time.sleep(delay)

    # MODELSCOPE_SITE=cn/ai：单站点独立任务模式（独立调度/失败卡/通知状态）；
    # 未设置：双站顺序执行（青龙/本地手动兼容）
    site = (os.getenv("MODELSCOPE_SITE") or "").strip().lower()
    if site in ("cn", "ai"):
        _run_single_site(site)
    else:
        _run_both_sites()


if __name__ == "__main__":
    main_guard(main)
