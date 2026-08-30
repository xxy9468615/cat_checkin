#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("飞桨 AI Studio 签到")
"""飞桨 AI Studio（aistudio.baidu.com）每日签到、算力卡领取与资产统计。

功能：
1. 社区每日签到（POST /point/sign，工作日 +1 积分，周末 +3 积分）
2. 每日算力卡领取（POST /studio/user/center/resource/receive，每日获赠 GPU 算力卡）
3. 积分与连签天数查询（GET /point/user/info）
4. 算力卡总余额查询（POST /studio/resource/user/summary，单位：点）
5. 大模型 Token 余额查询（GET /studio/trade/token/my/balance）
6. 百度 Passport 凭证（BDUSS/STOKEN）多账号支持与智能脱敏

环境变量：
- AISTUDIO_COOKIE_1, AISTUDIO_COOKIE_2... (多账号序列，推荐)
- AISTUDIO_COOKIE / AISTUDIO_cookie (单账号兼容)
"""

import json
import re
import sys
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from common import (
    BJT,
    Http,
    env_seq,
    is_already_signed,
    main_guard,
    mask_str,
)

PREFIX = "AISTUDIO_"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _check_passport_cookie(cookie_str: str) -> bool:
    """检查 Cookie 中是否包含核心百度 Passport 凭证。"""
    return "BDUSS" in cookie_str or "BDUSS_BFESS" in cookie_str


def _format_token_num(num: int) -> str:
    """格式化 Token 数量（如 2000000 -> 2,000,000 (2.00M)）。"""
    if num >= 1_000_000:
        return f"{num:,} ({num / 1_000_000:.2f}M)"
    if num >= 1_000:
        return f"{num:,} ({num / 1_000:.1f}k)"
    return f"{num:,}"


def _format_compute_card(mins: int) -> str:
    """将算力卡分钟数格式化为点数（如 480 分钟 -> 8.0 点）。"""
    points = mins / 60.0
    if points == int(points):
        return f"{int(points)}点"
    return f"{points:.1f}点"


def _run_account(cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    """单账号签到与算力卡领取执行流程。"""
    if not cookie.strip():
        raise RuntimeError("Cookie 为空")

    has_passport = _check_passport_cookie(cookie)
    cert_status = "🔑 百度 Passport 凭证有效" if has_passport else "🔑 自定义 Cookie"

    h = Http(follow_redirects=True)
    base_headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Cookie": cookie.strip(),
    }

    # 1. 访问 /overview 初始化会话并提取用户基础信息与 bdToken
    username = ""
    uid = ""
    bd_token = ""

    r_overview = h.request("GET", "https://aistudio.baidu.com/overview", headers=base_headers)
    if r_overview.code == 200 and r_overview.text:
        m = re.search(r"userInfo\s*:\s*(\{[^{}]+\})", r_overview.text)
        if m:
            try:
                uinfo = json.loads(m.group(1))
                username = str(uinfo.get("userName") or uinfo.get("nickname") or "")
                uid = str(uinfo.get("id") or "")
            except Exception:
                pass
        m_token = re.search(r"bdToken\s*:\s*\"([A-Fa-f0-9]+)\"", r_overview.text)
        if m_token:
            bd_token = m_token.group(1)

    if not bd_token:
        # 兜底：从 /deploy/mine 尝试提取 bdToken
        r_mine = h.request("GET", "https://aistudio.baidu.com/deploy/mine", headers=base_headers)
        if r_mine.code == 200 and r_mine.text:
            m_token = re.search(r"bdToken\s*:\s*\"([A-Fa-f0-9]+)\"", r_mine.text)
            if m_token:
                bd_token = m_token.group(1)

    if not username and not uid:
        # 兜底：从 Cookie 尝试提取
        m_bd = re.search(r"bce-user-info=\"[^\"]*\|([a-f0-9]+)\"", cookie)
        if m_bd:
            uid = m_bd.group(1)

    user_label = mask_str(username) if username else (f"UID: {mask_str(uid)}" if uid else f"账号 #{idx}")
    uid_label = f" (UID: {mask_str(uid)})" if uid and username else ""

    print(f"[{idx}/{total}] 👤 用户: 【{user_label}】{uid_label} | {cert_status}")

    api_headers = {
        "User-Agent": UA,
        "Origin": "https://aistudio.baidu.com",
        "Referer": "https://aistudio.baidu.com/overview",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/plain, */*",
    }
    if bd_token:
        api_headers["x-studio-token"] = bd_token

    # 2. 核心社区签到：直接 POST /point/sign（服务端幂等）
    r_sign = h.request("POST", "https://aistudio.baidu.com/point/sign", headers=api_headers)
    sign_data: Dict[str, Any] = r_sign.json({})

    sign_status = "成功"
    gain_points = 0
    now_bjt = datetime.now(BJT)
    # 周末 +3 积分，工作日 +1 积分
    default_gain = 3 if now_bjt.weekday() >= 5 else 1

    if r_sign.code == 200 and sign_data.get("errorCode") == 0:
        res = sign_data.get("result") or {}
        if isinstance(res, dict) and (res.get("finish") == 1 or res.get("isFinishSign") == 1):
            sign_status = "今日已签"
        else:
            sign_status = "成功"
            gain_points = default_gain
    else:
        err_msg = sign_data.get("errorMsg") or r_sign.text[:100]
        if is_already_signed(err_msg, extra_phrases=("已完成签到", "今日已签", "已经签到", "repeat")):
            sign_status = "今日已签"
        elif sign_data.get("errorCode") in (401, 403, 10001) or "未登录" in err_msg or "没有权限" in err_msg:
            raise RuntimeError(f"百度登录态已失效或未授权：{err_msg}")
        else:
            raise RuntimeError(f"签到请求异常 [{r_sign.code}]：{err_msg}")

    # 3. 每日算力卡领取（POST /studio/user/center/resource/receive?isInfoComplete=1）
    card_receive_msg = ""
    try:
        r_rec = h.request("POST", "https://aistudio.baidu.com/studio/user/center/resource/receive?isInfoComplete=1", headers=api_headers)
        rec_data: Dict[str, Any] = r_rec.json({})
        if r_rec.code == 200 and rec_data.get("errorCode") == 0:
            rec_res = rec_data.get("result")
            if isinstance(rec_res, dict) and rec_res.get("received"):
                card_receive_msg = "领取成功"
            elif isinstance(rec_res, (int, float)) and rec_res > 0:
                card_receive_msg = f"+{_format_compute_card(int(rec_res))}"
            else:
                card_receive_msg = "已领取"
        elif is_already_signed(rec_data.get("errorMsg", ""), extra_phrases=("已领取", "已完成", "今日已")):
            card_receive_msg = "今日已领取"
    except Exception:
        pass

    # 4. 积分与连签天数查询
    r_info = h.request("GET", "https://aistudio.baidu.com/point/user/info", headers=api_headers)
    info_data: Dict[str, Any] = r_info.json({})
    total_points: Optional[int] = None
    streak_days = 0

    if r_info.code == 200 and info_data.get("errorCode") == 0:
        info_res = info_data.get("result") or {}
        if isinstance(info_res, dict):
            total_points = info_res.get("totalPoint")
            streak_days = int(info_res.get("continuousSingCount") or 0)

    # 5. 算力卡总额与资源汇总（POST /studio/resource/user/summary）
    compute_points: Optional[str] = None
    try:
        r_res = h.request("POST", "https://aistudio.baidu.com/studio/resource/user/summary", headers=api_headers)
        res_data: Dict[str, Any] = r_res.json({})
        if r_res.code == 200 and res_data.get("errorCode") == 0:
            sum_res = res_data.get("result") or {}
            if isinstance(sum_res, dict):
                res_total = sum_res.get("resourceTotal")
                if res_total is not None and isinstance(res_total, (int, float)):
                    compute_points = _format_compute_card(int(res_total))
    except Exception:
        pass

    # 6. 大模型 Token 余额查询
    r_token = h.request("GET", "https://aistudio.baidu.com/studio/trade/token/my/balance", headers=api_headers)
    token_data: Dict[str, Any] = r_token.json({})
    token_balance: Optional[int] = None

    if r_token.code == 200 and token_data.get("errorCode") == 0:
        token_res = token_data.get("result")
        if isinstance(token_res, (int, float)):
            token_balance = int(token_res)

    # 7. 输出格式化结果
    sign_desc = f"• 签到: 【{sign_status}】"
    if streak_days > 0:
        sign_desc += f" 连签天数: 【{streak_days}】天"
    if sign_status == "成功" and gain_points > 0:
        sign_desc += f" +{gain_points} 积分"
    print(sign_desc)

    if card_receive_msg:
        print(f"• 算力卡: 【{card_receive_msg}】")

    asset_parts = []
    if total_points is not None:
        asset_parts.append(f"积分 【{total_points}】")
    if compute_points is not None:
        asset_parts.append(f"算力卡 【{compute_points}】")
    if token_balance is not None:
        asset_parts.append(f"大模型 Token 【{_format_token_num(token_balance)}】")

    if asset_parts:
        print(f"• 资产: {' | '.join(asset_parts)}")

    return True, sign_status


def main() -> None:
    print("【飞桨 AI Studio 签到】")
    cookies = env_seq(PREFIX, "cookie")
    total = len(cookies)
    success_count = 0
    errors = []

    for i, cookie in enumerate(cookies, 1):
        try:
            ok, _ = _run_account(cookie, i, total)
            if ok:
                success_count += 1
        except Exception as e:
            errors.append(f"账号 #{i} 失败：{e}")
            print(f"❌ 账号 #{i} 签到失败: {e}")

    print(f"\n✅ 全部 {total} 个账号处理完成 (成功 {success_count}/{total})")

    if errors:
        raise RuntimeError("; ".join(errors))


if __name__ == "__main__":
    main_guard(main)
