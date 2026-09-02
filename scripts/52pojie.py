#!/usr/bin/env python3
# cron: 15 9 * * *
# new Env("吾爱破解 签到")
"""吾爱破解（52pojie.cn）每日自动签到、吾爱币/积分资产统计与 Cookie 滚动保活。

功能：
1. 每日自动完成任务中心签到任务（两步流：apply id=2 & draw id=2）领取 2 吾爱币（CB）
2. 提取吾爱币 (CB)、积分、贡献、热心值、用户组等级等资产明细
3. 支持 curl_cffi Chrome TLS 指纹与 urllib 双引擎，有效绕过安域防护/WAF 阻断
4. 支持固定 CN 出口代理与候选代理容灾轮换（52POJIE_PROXY / WUAI_PROXY / SMZDM_PROXY / PROXY）
5. Upstash Redis + 本地 State 双层跨 CI 持久化（cat_checkin:state:52pojie_{idx}）与 Cookie 滚动保活
6. 多账号独立隔离运行与用户名/UID 智能脱敏

环境变量：
- 52POJIE_COOKIE_1, 52POJIE_COOKIE_2... (多账号序列，推荐)
- 52POJIE_COOKIE / WUAI_COOKIE / POJIE_COOKIE (单账号兼容)
- 52POJIE_PROXY / WUAI_PROXY / SMZDM_PROXY / SMZDM_BACKUP_PROXIES (代理出口，可选)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from common import (
    BJT,
    Http,
    env_seq,
    find,
    format_dead_proxy_alert,
    get_all_proxy_endpoints,
    is_already_signed,
    load_kv_state,
    main_guard,
    mask_str,
    parse_proxy_line,
    save_kv_state,
    strip_tags,
)

PREFIX = "52POJIE_"
BASE_URL = "https://www.52pojie.cn"
TASK_ID = "2"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

SUCCESS_PHRASES = ("恭喜您，任务已成功完成", "恭喜您，任务已完成", "任务已完成", "恭喜", "奖励已发放")
IDEMPOTENT_PHRASES = (
    "抱歉，本期您已申请过此任务",
    "您已申请过此任务",
    "不是进行中的任务",
    "已申请过",
    "本期任务已完成",
    "请下期再来",
)
EXPIRED_PHRASES = ("您需要先登录才能继续本操作", "请先登录", "未登录")
WAF_PHRASES = (
    "安域防护节点",
    "安全防护",
    "访问验证",
    "Just a moment",
    "cf-browser-verification",
    "SafeLine",
    "wzws-waf-cgi",
    "json2.js",
    "wzwsquestion",
    "Please enable JavaScript",
)


class _CffiResp:
    """curl_cffi Response adapter."""

    def __init__(self, r):
        self.code = r.status_code
        self.text = r.text
        self.url = str(r.url)
        self.headers = r.headers

    def json(self, default=None):
        try:
            return json.loads(self.text)
        except Exception:
            return default if default is not None else {}


def _parse_cookie_dict(cookie_str: str) -> Dict[str, str]:
    """将 cookie 字符串解析为键值对字典。"""
    res: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        res[k.strip()] = v.strip()
    return res


def _collect_resp_cookies(resp: Any) -> List[str]:
    """安全收集 HTTP 响应中的 Set-Cookie 标头。"""
    if resp is None:
        return []
    res: List[str] = []
    raw_c = getattr(resp, "_raw_cookies", None)
    if raw_c is not None:
        try:
            for k, v in raw_c.items():
                res.append(f"{k}={v}")
        except Exception:
            pass
    headers = getattr(resp, "headers", None)
    if headers:
        if hasattr(headers, "get_all"):
            res.extend(headers.get_all("Set-Cookie", []))
        elif hasattr(headers, "get_list"):
            res.extend(headers.get_list("set-cookie"))
            res.extend(headers.get_list("Set-Cookie"))
        elif isinstance(headers, dict):
            sc = headers.get("Set-Cookie") or headers.get("set-cookie")
            if isinstance(sc, list):
                res.extend(sc)
            elif isinstance(sc, str):
                res.append(sc)
    return res


def _merge_cookie_str(base_cookie: str, set_cookies: List[str]) -> str:
    """合并现有 Cookie 字符串与 HTTP 响应下发的 Set-Cookie 列表。"""
    c_dict = _parse_cookie_dict(base_cookie)
    for sc in set_cookies:
        if not sc:
            continue
        first_item = sc.split(";")[0].strip()
        if "=" in first_item:
            k, v = first_item.split("=", 1)
            c_dict[k.strip()] = v.strip()
    return "; ".join(f"{k}={v}" for k, v in c_dict.items())


def _calc_cookie_expiry(cookie_str: str, state: Dict[str, Any]) -> Optional[int]:
    """推算 Discuz Cookie 剩余有效天数（默认 30 天会话周期）。"""
    saved_ts = state.get("saved_ts")
    if saved_ts and isinstance(saved_ts, (int, float)):
        expire_ts = int(saved_ts) + 30 * 86400
        return max(0, int((expire_ts - time.time()) / 86400))
    return 30


def _load_accounts() -> List[str]:
    """加载吾爱破解 Cookie 列表，支持 52POJIE_、WUAI_、POJIE_ 前缀。"""
    raw_cookies: List[str] = []

    # 1. 优先从 52POJIE_ 前缀加载
    raw_cookies = env_seq(PREFIX, "cookie", required=False)
    if not raw_cookies:
        # 兼容旧前缀 WUAI_ / POJIE_
        raw_cookies = env_seq("WUAI_", "cookie", required=False)
    if not raw_cookies:
        raw_cookies = env_seq("POJIE_", "cookie", required=False)

    # 2. 兼容 POJIE52_ 单一变量
    if not raw_cookies:
        fallback = os.getenv("POJIE52_COOKIE") or os.getenv("POJIE_COOKIE") or os.getenv("WUAI_COOKIE") or ""
        if fallback.strip():
            raw_cookies = [c.strip() for c in fallback.replace("&&", "\n").splitlines() if c.strip()]

    return [c.strip() for c in raw_cookies if c.strip()]


def _get_candidate_proxies() -> List[str]:
    """解析候选代理列表，支持带统一识别名称与自建代理优先调度。"""
    endpoints = get_all_proxy_endpoints(task_prefix="52POJIE", include_self_hosted=True)
    if endpoints:
        return [ep.url for ep in endpoints]
    raw = (
        os.getenv("52POJIE_PROXY")
        or os.getenv("WUAI_PROXY")
        or os.getenv("POJIE_PROXY")
        or os.getenv("SMZDM_PROXY")
        or os.getenv("SMZDM_BACKUP_PROXIES")
        or os.getenv("PROXY")
        or ""
    )
    res: List[str] = []
    for line in raw.replace(",", "\n").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            res.append(line)
    return res


def _cffi_request(method: str, url: str, headers: Dict[str, str], proxy: str = ""):
    """Chrome TLS 指纹请求，绕过 WAF 阻断。"""
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return None
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = cffi_requests.request(
            method,
            url,
            headers=headers,
            proxies=proxies,
            impersonate="chrome",
            timeout=25,
            allow_redirects=True,
        )
        resp = _CffiResp(r)
        resp._raw_cookies = r.cookies
        return resp
    except Exception:
        return None


def _http_request_with_failover(
    method: str,
    url: str,
    headers: Dict[str, str],
    candidate_proxies: List[str],
) -> Tuple[Any, str, Optional[Http]]:
    """带代理候选池轮换的网络请求，首选 curl_cffi，回退 urllib Http。"""
    last_resp = None
    used_proxy = ""
    last_h = None

    for p in candidate_proxies:
        ep = parse_proxy_line(p) if p else None
        p_label = ep.display_name if ep else "【未知代理】"

        # 1. 尝试 curl_cffi
        resp = _cffi_request(method, url, headers, proxy=p)
        if resp is not None:
            # 检查是否被 WAF 阻断
            if resp.code != 403 and not any(w in resp.text for w in WAF_PHRASES):
                return resp, p_label, None
            last_resp = resp

        # 2. 回退到 common.Http (urllib)
        try:
            cur_h = Http(follow_redirects=True, proxy=p)
            resp = cur_h.request(method, url, headers=headers, timeout=20)
            if resp.code == 200 and not any(w in resp.text for w in WAF_PHRASES):
                return resp, p_label, cur_h
            last_resp = resp
            last_h = cur_h
        except Exception as exc:
            if ep:
                print(f"  {format_dead_proxy_alert(ep, str(exc))}")

        if len(candidate_proxies) > 1 and last_resp is not None:
            print(f"  ⚠️ 代理 {p_label} 响应异常 (HTTP {last_resp.code})，尝试备用出口...")

    # 若所有代理均未能正常请求且无直连，尝试直连一次
    if "" not in candidate_proxies:
        resp = _cffi_request(method, url, headers, proxy="")
        if resp is not None and resp.code != 403 and not any(w in resp.text for w in WAF_PHRASES):
            return resp, "", None
        try:
            cur_h = Http(follow_redirects=True, proxy="")
            resp = cur_h.request(method, url, headers=headers, timeout=20)
            if resp.code == 200 and not any(w in resp.text for w in WAF_PHRASES):
                return resp, "", cur_h
            last_resp = resp
            last_h = cur_h
        except Exception:
            pass

    return last_resp, used_proxy, last_h


def _clean_msg(text: str) -> str:
    """清理 HTML/JS 干扰字符。"""
    if not text:
        return ""
    # 移除 script 标签及内容
    text = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.IGNORECASE)
    # 移除 style 标签及内容
    text = re.sub(r"<style[\s\S]*?</style>", "", text, flags=re.IGNORECASE)
    # 剥离标签
    text = strip_tags(text).strip()
    # 移除多余换行与空格
    text = re.sub(r"[\r\n]+", " ", text).strip()
    return text


def _extract_task_message(html: str) -> str:
    """提取 Discuz 任务提示消息。"""
    if not html:
        return ""
    # CDATA
    m_cdata = re.search(r"<!\[CDATA\[([\s\S]+?)\]\]>", html)
    if m_cdata:
        return _clean_msg(m_cdata.group(1))
    # messagetext
    m_msg = re.search(r'<div\s+id=["\']messagetext["\'][^>]*>([\s\S]+?)</div>', html)
    if m_msg:
        return _clean_msg(m_msg.group(1))
    # alert_info
    m_alert = re.search(r'<p\s+class=["\']alert_info["\'][^>]*>([\s\S]+?)</p>', html)
    if m_alert:
        return _clean_msg(m_alert.group(1))
    # showDialog
    m_diag = re.search(r'showDialog\s*\(\s*["\']([^"\']+)["\']', html)
    if m_diag:
        return _clean_msg(m_diag.group(1))
    # 首个 p 标签文本
    m_p = re.search(r"<p>([^<]+)</p>", html)
    if m_p:
        return _clean_msg(m_p.group(1))
    return ""


def _extract_user_assets(html: str, init_uid: str = "") -> Dict[str, str]:
    """从 Discuz 个人中心/积分页面解析用户资产信息。"""
    res = {
        "username": "",
        "uid": init_uid,
        "cb": "0",
        "credit": "0",
        "contrib": "0",
        "hot": "0",
        "group": "",
    }
    if not html:
        return res

    # 用户名
    nick = (
        find(r'title=["\']访问我的空间["\']>([^<]+)</a>', html)
        or find(r'class=["\']vwmy[^"\']*["\']><a[^>]*>([^<]+)</a>', html)
        or find(r'<strong class=["\']vwmy["\']>([^<]+)</strong>', html)
        or ""
    )
    if nick:
        res["username"] = nick.strip()

    # UID
    uid = (
        find(r'home\.php\?mod=space(?:cp)?&amp;uid=(\d+)', html)
        or find(r'home\.php\?mod=space&uid=(\d+)', html)
        or find(r'space-uid-(\d+)\.html', html)
        or init_uid
    )
    if uid:
        res["uid"] = uid.strip()

    # 吾爱币 (CB)
    cb = (
        find(r'<li><em>吾爱币:?</em>\s*([\d,]+)\s*(?:CB)?</li>', html)
        or find(r'<em>\s*吾爱币\s*:\s*</em>\s*([\d,]+)', html)
        or find(r'吾爱币[:：]\s*(\d+)', html)
    )
    if cb:
        res["cb"] = cb.replace(",", "").strip()

    # 积分
    credit = (
        find(r'<li><em>积分:?</em>\s*([\d,]+)</li>', html)
        or find(r'<em>\s*积分\s*:\s*</em>\s*([\d,]+)', html)
        or find(r'积分[:：]\s*(\d+)', html)
    )
    if credit:
        res["credit"] = credit.replace(",", "").strip()

    # 贡献
    contrib = (
        find(r'<li><em>贡献:?</em>\s*([\d,]+)</li>', html)
        or find(r'<em>\s*贡献\s*:\s*</em>\s*([\d,]+)', html)
    )
    if contrib:
        res["contrib"] = contrib.replace(",", "").strip()

    # 热心值
    hot = (
        find(r'<li><em>(?:热心值|爱心):?</em>\s*([\d,]+)</li>', html)
        or find(r'<em>\s*(?:热心值|爱心)\s*:\s*</em>\s*([\d,]+)', html)
    )
    if hot:
        res["hot"] = hot.replace(",", "").strip()

    # 用户组/等级
    group = (
        find(r'用户组:?\s*<a[^>]*>([^<]+)</a>', html)
        or find(r'<li><em>用户组:?</em>\s*(?:<a[^>]*>)?([^<]+)', html)
        or find(r'class=["\']xi2["\']>([^<]+)</a>\s*\(<a[^>]*>用户组</a>\)', html)
    )
    if group:
        res["group"] = strip_tags(group).strip()

    return res


def _run_account(raw_cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    """单账号吾爱破解签到流程。"""
    raw_cookie = raw_cookie.strip()
    if not raw_cookie:
        raise RuntimeError("Cookie 为空")

    c_dict = _parse_cookie_dict(raw_cookie)
    init_uid = ""
    # 从 htVD_2132_lastcheckfeed 或 discuz_uid 提取初始 UID
    for k, v in c_dict.items():
        if "lastcheckfeed" in k:
            init_uid = v.split("%7C")[0].split("|")[0].strip()
            break
        elif "discuz_uid" in k or "uid" == k:
            init_uid = v.strip()
            break

    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest()
    redis_key = f"cat_checkin:state:52pojie_{idx}"
    state_file = f".52pojie_state_{idx}.json"

    state = load_kv_state(redis_key, state_file) or {}
    cur_cookie = raw_cookie

    # 若环境变量未变更且状态中有滚动保存的有效 cookie，则使用滚动 cookie
    if state.get("env_hash") == env_hash and state.get("cookie"):
        cur_cookie = str(state["cookie"]).strip()

    candidate_proxies = _get_candidate_proxies()
    if not candidate_proxies:
        candidate_proxies = [""]

    headers = {
        "User-Agent": DEFAULT_UA,
        "Referer": f"{BASE_URL}/",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cookie": cur_cookie,
    }

    # 1. 积分与个人信息查询（先查询以校验登录态并获取用户信息）
    credit_url = f"{BASE_URL}/home.php?mod=spacecp&ac=credit&showcredit=1"
    r_credit, used_proxy_credit, _ = _http_request_with_failover(
        "GET", credit_url, headers, candidate_proxies
    )
    credit_text = r_credit.text if (r_credit and hasattr(r_credit, "text")) else ""
    if any(e in credit_text for e in EXPIRED_PHRASES):
        raise RuntimeError("Cookie 已失效（需要先登录），请在浏览器重新登录吾爱破解并更新 Cookie")

    assets = _extract_user_assets(credit_text, init_uid)
    nickname = assets.get("username") or state.get("nickname") or ""
    uid = assets.get("uid") or init_uid or "未知"
    masked_name = mask_str(nickname, 1, 1) if nickname else f"账号 #{idx}"
    masked_uid = mask_str(uid, 2, 2) if uid != "未知" else "未知"

    remaining_days = _calc_cookie_expiry(cur_cookie, state)
    expiry_tag = ""
    if remaining_days is not None:
        if remaining_days < 7:
            expiry_tag = f" | ⚠️ Cookie 剩余 {remaining_days} 天（请尽快更新）"
        else:
            expiry_tag = f" | 🔑 Cookie 剩余 {remaining_days} 天"

    # 2. 任务申请：GET /home.php?do=apply&id=2&mod=task (多重 WAF 绕过模板)
    apply_url_variants = [
        f"{BASE_URL}/home.php?do=apply&id={TASK_ID}&mod=task",
        f"{BASE_URL}/./home.php?mod=task&do=apply&id={TASK_ID}",
        f"{BASE_URL}/home.php?id={TASK_ID}&do=apply&mod=task",
        f"{BASE_URL}/home.php?mod=task&do=apply&id={TASK_ID}",
    ]
    r_apply = None
    used_proxy_apply = ""
    for u in apply_url_variants:
        r_apply, used_proxy_apply, _ = _http_request_with_failover("GET", u, headers, candidate_proxies)
        if r_apply is not None and not any(w in getattr(r_apply, "text", "") for w in WAF_PHRASES) and r_apply.code != 403:
            break

    if r_apply is None:
        raise RuntimeError("网络请求异常：无法连接至吾爱破解服务器")

    apply_text = r_apply.text if hasattr(r_apply, "text") else ""
    if any(w in apply_text for w in WAF_PHRASES) or r_apply.code == 403:
        raise RuntimeError("触发吾爱破解安域安全防护/WAF 拦截，建议配置 CN 代理出口 (52POJIE_PROXY)")

    # 3. 任务领取：GET /home.php?do=draw&id=2&mod=task (多重 WAF 绕过模板)
    draw_url_variants = [
        f"{BASE_URL}/home.php?do=draw&id={TASK_ID}&mod=task",
        f"{BASE_URL}/./home.php?mod=task&do=draw&id={TASK_ID}",
        f"{BASE_URL}/home.php?id={TASK_ID}&do=draw&mod=task",
        f"{BASE_URL}/home.php?mod=task&do=draw&id={TASK_ID}",
    ]
    r_draw = None
    used_proxy_draw = ""
    h_draw = None
    for u in draw_url_variants:
        r_draw, used_proxy_draw, h_draw = _http_request_with_failover("GET", u, headers, candidate_proxies)
        if r_draw is not None and not any(w in getattr(r_draw, "text", "") for w in WAF_PHRASES) and r_draw.code != 403:
            break

    if r_draw is None:
        raise RuntimeError("网络请求异常：任务领取步骤请求失败")

    draw_text = r_draw.text if hasattr(r_draw, "text") else ""
    if any(w in draw_text for w in WAF_PHRASES) or r_draw.code == 403:
        raise RuntimeError("触发吾爱破解安域安全防护/WAF 拦截，建议配置 CN 代理出口 (52POJIE_PROXY)")
    msg = _extract_task_message(draw_text) or _extract_task_message(apply_text)

    # 检查登录态失效
    if any(e in draw_text for e in EXPIRED_PHRASES) or any(e in apply_text for e in EXPIRED_PHRASES):
        raise RuntimeError(f"Cookie 已失效（需要先登录）：{msg or '请在浏览器重新登录吾爱破解并更新 Cookie'}")

    used_proxy = used_proxy_draw or used_proxy_apply or used_proxy_credit
    proxy_tag = f" | 🌐 代理出口: {used_proxy}" if used_proxy else ""
    is_qq_bind = (c_dict.get("htVC_2132_connect_is_bind") == "1") or ("connect_is_bind" in raw_cookie)
    login_tag = " | 🐧 QQ 互联登录" if is_qq_bind else ""
    print(f"[{idx}/{total}] 👤 用户: 【{masked_name}】 (UID: {masked_uid}){login_tag}{expiry_tag}{proxy_tag}")

    # 4. 判定签到状态
    is_success = any(s in draw_text for s in SUCCESS_PHRASES) or any(s in apply_text for s in SUCCESS_PHRASES)
    is_already = (
        is_already_signed(msg, IDEMPOTENT_PHRASES)
        or any(p in draw_text for p in IDEMPOTENT_PHRASES)
        or any(p in apply_text for p in IDEMPOTENT_PHRASES)
    )

    if is_success:
        status_label = "成功"
        gain_desc = "(+2 吾爱币)"
        print(f"• 签到: 【{status_label}】 {gain_desc}")
    elif is_already:
        status_label = "今日已签"
        print(f"• 签到: 【{status_label}】 ({msg or '本期任务已完成'})")
    else:
        # 非明确成功/已签时抛出异常
        err_msg = msg if msg else (draw_text[:120] if draw_text else "未知响应")
        raise RuntimeError(f"任务执行非预期：{err_msg}")

    # 5. 打印资产明细
    cb_val = assets.get("cb") or "0"
    credit_val = assets.get("credit") or "0"
    contrib_val = assets.get("contrib") or "0"
    hot_val = assets.get("hot") or "0"
    group_val = assets.get("group") or ""

    asset_parts = [f"吾爱币 【{cb_val}】", f"积分 【{credit_val}】"]
    if contrib_val and contrib_val != "0":
        asset_parts.append(f"贡献 【{contrib_val}】")
    if hot_val and hot_val != "0":
        asset_parts.append(f"热心值 【{hot_val}】")
    if group_val:
        asset_parts.append(f"等级 【{group_val}】")

    print(f"• 资产: {' · '.join(asset_parts)}")

    # 6. 滚动保存状态（若有新 Set-Cookie 或首次记录）
    try:
        all_sc: List[str] = []
        all_sc.extend(_collect_resp_cookies(r_credit))
        all_sc.extend(_collect_resp_cookies(r_apply))
        all_sc.extend(_collect_resp_cookies(r_draw))
        merged_cookie = _merge_cookie_str(cur_cookie, all_sc) if all_sc else cur_cookie

        save_kv_state(
            redis_key,
            state_file,
            {
                "cookie": merged_cookie,
                "env_hash": env_hash,
                "nickname": nickname,
                "uid": uid,
                "is_qq": is_qq_bind,
                "saved_ts": int(state.get("saved_ts") or time.time()),
                "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
            },
        )
    except Exception:
        pass

    return True, status_label


def main() -> None:
    print("【吾爱破解 签到】")
    raw_cookies = _load_accounts()
    if not raw_cookies:
        raise RuntimeError("未配置 52POJIE_COOKIE_1 或 52POJIE_COOKIE（请配置 Cookie 环境变量）")

    total = len(raw_cookies)
    success_count = 0
    failures: List[Tuple[int, str]] = []

    for idx, c in enumerate(raw_cookies, 1):
        try:
            ok, _ = _run_account(c, idx, total)
            if ok:
                success_count += 1
        except Exception as e:
            print(f"[{idx}/{total}] ❌ 签到失败: {e}")
            failures.append((idx, str(e)))

    print(f"\n✅ 全部 {total} 个账号处理完成 (成功 {success_count}/{total})")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
