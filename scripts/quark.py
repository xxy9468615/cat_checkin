#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("夸克网盘 签到")
"""夸克网盘（pan.quark.cn）每日签到、成长值/连签与网盘资产统计，会话滑动保活。

功能：
1. 每日签到（移动端 growth 接口，需 App 三参数 kps/sign/vcode——Reqable 抓
   PC 客户端「签到领容量」页请求一次获得，长期有效）
2. 资产统计：会员类型/到期、总容量/已用、累计签到奖励（extend_capacity_composition）
3. __puus 24h 滑动票自动捕获 + Redis 回写（cat_checkin:state:quark_{idx}）：
   每日 API 调用即触发服务端 Set-Cookie 滑动续期，回写后长期免维护；
   主会话 __pus 为签发起 14 天硬窗口（实测），到期需扫码换票（CAS su.quark.cn）
4. 多账号隔离运行与昵称脱敏

环境变量：
- QUARK_COOKIE_1, QUARK_COOKIE_2...（网页完整 Cookie；Redis 中有更新版本时优先）
- QUARK_MPARAM_1...（可选：App 三参数，"kps=..&sign=..&vcode=.." 任意分隔符）
"""
from __future__ import annotations

import json
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from common import (
    Http,
    env_seq,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PAN_HOST = "https://pan.quark.cn"
PC_HOST = "https://drive-pc.quark.cn"
M_HOST = "https://drive-m.quark.cn"
UA_WEB = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0"
)
# 移动端 growth 接口按客户端 UA 网关放行，与 Cp0204/quark-auto-save 一致
UA_CLIENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) quark-cloud-drive/3.14.2 Chrome/112.0.5615.165 "
    "Electron/24.1.3.8 Safari/537.36 Channel/pckk_other_ch"
)

MEMBER_TYPE_MAP = {
    "NORMAL": "普通用户",
    "EXP_SVIP": "88VIP",
    "SUPER_VIP": "SVIP",
    "Z_VIP": "SVIP+",
    "VIP": "VIP",
    "MINI_VIP": "MINI VIP",
}


def _resp_dict(resp: Any) -> Dict[str, Any]:
    """resp.json() 容错：非 JSON 对象回退空 dict。"""
    try:
        j = resp.json({})
    except Exception:
        return {}
    return j if isinstance(j, dict) else {}


def _parse_mparam(raw: str) -> Dict[str, str]:
    r"""解析 App 三参数：kps/sign/vcode，任意分隔符。

    负向断言防止误匹配 cookie 里的 __kps（'_' 属于 \w）。
    """
    out: Dict[str, str] = {}
    for key in ("kps", "sign", "vcode"):
        m = re.search(rf"(?<![A-Za-z0-9_]){key}=([^;&\s]+)", raw or "")
        if m:
            out[key] = m.group(1)
    return out if len(out) == 3 else {}


def _fmt_size(num: Any) -> str:
    """字节数人性化（与夸克前端口径一致，1024 进制）。"""
    try:
        n = float(num)
    except (TypeError, ValueError):
        return "未知"
    units = ["B", "KB", "MB", "GB", "TB"]
    v = n
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f}{u}".replace(".0", "") if u != "B" else f"{int(v)}B"
        v /= 1024
    return f"{v:.1f}TB"


def _fmt_ts_ms(ts: Any) -> str:
    """毫秒时间戳 → MM-DD；无效返回空串。"""
    try:
        ts = int(ts)
        if ts <= 0:
            return ""
        from datetime import datetime, timedelta, timezone

        tz = timezone(timedelta(hours=8))
        return datetime.fromtimestamp(ts / 1000, tz).strftime("%m-%d")
    except (TypeError, ValueError):
        return ""


def _capture_puus(resp: Any) -> str:
    """从响应头捕获滑动票 __puus（服务端每次调用按 24h 滑动重签）。"""
    try:
        raws: List[str] = []
        get_all = getattr(resp.headers, "get_all", None)
        if get_all:
            raws = get_all("Set-Cookie") or []
        else:
            v = resp.headers.get("Set-Cookie") or ""
            raws = [v] if v else []
        for raw in raws:
            m = re.search(r"__puus=([^;]+)", raw)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return ""


def _account_info(h: Http, cookie: str) -> str:
    """校验会话并取昵称；会话失效抛 RuntimeError。"""
    resp = h.request(
        "GET", f"{PAN_HOST}/account/info?fr=pc&platform=pc",
        headers={"Cookie": cookie, "User-Agent": UA_WEB, "Referer": f"{PAN_HOST}/"},
    )
    data = _resp_dict(resp).get("data") or {}
    if resp.code != 200 or not data:
        raise RuntimeError(f"会话失效（HTTP {resp.code}）→ 需扫码换票后更新 Cookie")
    return str(data.get("nickname") or "用户")


def _member_overview(h: Http, cookie: str) -> Tuple[str, str, Any]:
    """会员与容量概览。返回 (会员行, 空间行, 原始响应)；失败降级为占位文案。"""
    resp = h.request(
        "GET", f"{PC_HOST}/1/clouddrive/member?pr=ucpro&fr=pc",
        headers={"Cookie": cookie, "User-Agent": UA_WEB, "Referer": f"{PAN_HOST}/"},
    )
    d = _resp_dict(resp).get("data") or {}
    if resp.code != 200 or not d:
        return "获取失败", "获取失败", resp
    mtype = MEMBER_TYPE_MAP.get(str(d.get("member_type")), str(d.get("member_type") or "未知"))
    exp = _fmt_ts_ms(d.get("vip_exp_at") or d.get("exp_at"))
    member_line = f"{mtype}（{exp} 到期）" if exp else mtype
    total = _fmt_size(d.get("total_capacity"))
    used = _fmt_size(d.get("use_capacity"))
    sign_reward = (d.get("extend_capacity_composition") or {}).get("sign_reward")
    reward_note = f"，累计签到奖励 {_fmt_size(sign_reward)}" if sign_reward else ""
    space_line = f"已用 {used} / 总量 {total}{reward_note}"
    return member_line, space_line, resp


def _growth_sign(h: Http, cookie: str, mparam: Dict[str, str]) -> Tuple[str, bool]:
    """移动端 growth 接口签到（三参数 query 鉴权，与社区实现同源）。

    返回 (文案, 是否达成签到)。
    """
    q = (
        f"pr=ucpro&fr=pc&uc_param_str="
        f"&kps={quote(mparam['kps'], safe='')}"
        f"&sign={quote(mparam['sign'], safe='')}"
        f"&vcode={quote(mparam['vcode'], safe='')}"
    )
    headers = {
        "Cookie": cookie,
        "User-Agent": UA_CLIENT,
        "Content-Type": "application/json",
        "Referer": f"{PAN_HOST}/",
    }
    resp = h.request("GET", f"{M_HOST}/1/clouddrive/capacity/growth/info?{q}", headers=headers)
    info = _resp_dict(resp)
    if resp.code != 200 or info.get("code") not in (0, None):
        return f"签到状态查询失败（HTTP {resp.code} {info.get('message', '')[:40]}），三参数可能已失效", False
    cap = (info.get("data") or {}).get("cap_sign") or {}
    if not cap:
        return "签到状态查询返回空（三参数可能已失效，请重新抓包）", False
    reward_mb = int((cap.get("sign_daily_reward") or 0) / 1024 / 1024)
    progress = cap.get("sign_progress", 0)
    target = cap.get("sign_target", 0)
    if cap.get("sign_daily"):
        return f"今日已签到（+{reward_mb}MB，连签 {progress}/{target} 天）", True
    resp = h.request(
        "POST", f"{M_HOST}/1/clouddrive/capacity/growth/sign?{q}",
        headers=headers, json_data={"sign_cyclic": True},
    )
    d = _resp_dict(resp)
    if resp.code == 200 and d.get("code") == 0 and (d.get("data") or {}):
        reward_mb = int((d["data"].get("sign_daily_reward") or 0) / 1024 / 1024)
        return f"【成功】+{reward_mb}MB（连签 {progress + 1}/{target} 天）", True
    msg = str(d.get("message") or resp.code)
    return f"签到失败（{msg[:60]}）", False


def _run_one(idx: int, total: int, cookie: str, mparam: Optional[Dict[str, str]]) -> Tuple[bool, str]:
    """单个账号完整流程。"""
    h = Http()
    prefix_redis = f"cat_checkin:state:quark_{idx}"
    state_file = f".quark_state_{idx}.json"
    state = load_kv_state(prefix_redis, state_file) or {}

    # Redis 中有滑动续期过的更新版 cookie 时优先（__puus 24h 滑动，secret 是引导票）
    saved_cookie = str(state.get("cookie") or "")
    if saved_cookie:
        cookie = saved_cookie

    nickname = _account_info(h, cookie)
    masked = mask_str(nickname)
    print(f"[{idx}/{total}] 👤 用户: 【{masked}】")

    # 捕获滑动票：服务端对每次调用做 Set-Cookie(__puus) 24h 续期
    lines: List[str] = []
    ok = True
    if mparam:
        sign_line, sign_ok = _growth_sign(h, cookie, mparam)
        lines.append(f"• 签到: {sign_line}")
        ok = ok and sign_ok
    else:
        lines.append("• 签到: ⚠️ 未配置 App 三参数（QUARK_MPARAM），本次仅完成资产统计与保活")

    member_line, space_line, member_resp = _member_overview(h, cookie)
    lines.append(f"• 空间: {space_line}")
    lines.append(f"• 会员: {member_line}")

    # 滑动票回写：member 响应带最新 __puus 时更新 Redis（远端权威，下次运行优先）
    new_puus = _capture_puus(member_resp)
    if new_puus:
        m = re.search(r"__puus=([^;]+)", cookie)
        old_puus = m.group(1) if m else ""
        if new_puus != old_puus:
            cookie = re.sub(r"__puus=[^;]*", f"__puus={new_puus}", cookie)
            if "__puus=" not in cookie:
                cookie = f"{cookie}; __puus={new_puus}"
            state["cookie"] = cookie
            state["puus_rotated_at"] = int(time.time())
            save_kv_state(prefix_redis, state_file, state)
            lines.append("• [keepalive] __puus 已滑动续期（Redis 回写）")

    for ln in lines:
        print(ln)
    return ok, "；".join(lines)


def main() -> None:
    cookies = env_seq("QUARK_", "cookie", required=True)
    mparams = env_seq("QUARK_", "mparam", required=False, default=[])
    total = len(cookies)
    print(f"【夸克网盘 签到】共 {total} 个账号")
    failed = 0
    done = 0
    for idx, cookie in enumerate(cookies, start=1):
        if not cookie.strip():
            continue
        done += 1
        mparam = _parse_mparam(mparams[idx - 1]) if idx <= len(mparams) else {}
        try:
            ok, _ = _run_one(idx, total, cookie.strip(), mparam or None)
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"❌ 账号 {idx} 处理失败: {exc}")
        if not ok:
            failed += 1
    print(f"✅ 全部 {done} 个账号处理完成 (成功 {done - failed}/{done})")
    if failed:
        print(f"❌ {failed} 个账号未达成签到")
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
