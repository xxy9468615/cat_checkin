#!/usr/bin/env python3
# cron: 20 9 * * *
# new Env("OPPO商城 签到")
"""OPPO 商城（欢太 / HeyTap）每日自动打卡签到、连续签到里程碑大奖领取、日常浏览任务一键完成与积分资产统计。

核心逻辑：
1. 凭证解析与保活检测：
   - 提取并解析 webAccessToken（JWT），校验过期时间（通常会话级 ~30 分钟到数小时，过期预警）；
   - 从 memberinfo 提取用户昵称、脱敏 ID 以及 oid（用于自动补全 sa_distinct_id 与 authHost 防 403 守门）。
2. 每日打卡签到 (signIn)：
   - POST /api/cn/oapi/marketing/cumulativeSignIn/signIn；
   - 幂等放行：已签到（code 5008 / "今天已经签到过啦"）自动识别，新签到返回 +10 积分收益。
3. 连签里程碑奖励自动领取 (drawCumulativeAward)：
   - GET /api/cn/oapi/marketing/cumulativeSignIn/getSignInDetail 评估连签进度；
   - 达标 3/7/14/28 天连签里程碑且未领取的奖励自动一键领取。
4. 日常 8 大浏览赚积分任务自动一键上报 (signInOrShareTask)：
   - GET /api/cn/oapi/marketing/task/queryTaskList 拉取今日任务列表；
   - 过滤浏览类日常任务（taskType=1），直接向 taskReport 接口上报完成；
   - 稳拿 8 × 2 = 16 积分。
5. 积分资产查询 (queryMemberCreditInfo)：
   - 实时拉取最新积分总余额、等级与抵扣额。

环境变量：
- OPPO_COOKIE_1, OPPO_COOKIE_2... (多账号序列，推荐)
- OPPO_COOKIE (单账号兼容)
- OPPO_PROXY / PROXY (可选代理出口)
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# 本地直跑便捷自动加载根目录 .env
_ROOT_ENV = ROOT_DIR / ".env"
if _ROOT_ENV.exists():
    try:
        with open(_ROOT_ENV, encoding="utf-8") as _ef:
            for _line in _ef:
                _line = _line.strip()
                if not _line or _line.startswith("#") or "=" not in _line:
                    continue
                _k, _v = _line.split("=", 1)
                _k, _v = _k.strip(), _v.strip()
                if _k and _k not in os.environ:
                    if len(_v) >= 2 and ((_v[0] == '"' and _v[-1] == '"') or (_v[0] == "'" and _v[-1] == "'")):
                        _v = _v[1:-1]
                    os.environ[_k] = _v
    except Exception:
        pass

from common import (
    BJT,
    Http,
    env_seq,
    is_already_signed,
    main_guard,
    mask_str,
)

PREFIX = "OPPO_"
BASE_HOST = "https://hd.opposhop.cn"
SIGN_IN_ACTIVITY_ID = "2094340289534894080"
CREDITS_ADD_ACTION_ID = "1788913e6d9e4683b8b9ab0088733560"
TASK_ACTIVITY_ID = "1919591795180969984"


def _decode_jwt_exp(token: str) -> Optional[int]:
    """从 JWT webAccessToken 中提取 exp 过期时间戳（秒级）。"""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="ignore"))
            return payload.get("exp")
    except Exception:
        pass
    return None


def _parse_cookie_items(raw_cookie: str) -> Dict[str, str]:
    """解析 Cookie 字符串为键值字典。"""
    items: Dict[str, str] = {}
    for part in raw_cookie.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        items[k.strip()] = v.strip()
    return items


def _extract_user_info(cookie_items: Dict[str, str]) -> Tuple[str, str, str]:
    """从 Cookie 的 memberinfo 字段提取昵称、UID 与 oid。"""
    member_raw = cookie_items.get("memberinfo", "")
    if member_raw:
        try:
            import urllib.parse
            unquoted = urllib.parse.unquote(member_raw)
            data = json.loads(unquoted)
            uid = str(data.get("id", "") or "")
            name = str(data.get("name", "") or "")
            oid = str(data.get("oid", "") or "")
            return name, uid, oid
        except Exception:
            pass
    return "", "", ""


def _run_account(cookie_str: str, index: int, total: int) -> Tuple[bool, str]:
    cookie_items = _parse_cookie_items(cookie_str)
    web_token = cookie_items.get("webAccessToken", "")
    if not web_token:
        if cookie_str.startswith("eyJ") and "." in cookie_str:
            web_token = cookie_str.strip()
            cookie_str = f"webAccessToken={web_token}"
        else:
            print(f"[{index}/{total}] ❌ 未在 Cookie 中检测到 webAccessToken 登录令牌")
            return False, "缺少登录凭据(webAccessToken)"

    user_name, user_id, user_oid = _extract_user_info(cookie_items)
    display_id = mask_str(user_id) if user_id else f"账号 #{index}"
    display_name = f"（{mask_str(user_name)}）" if user_name else ""
    print(f"\n[{index}/{total}] 👤 用户: {display_id}{display_name}")

    # 1. 凭据有效期评估
    exp_ts = _decode_jwt_exp(web_token)
    if exp_ts:
        now_ts = int(time.time())
        rem_sec = exp_ts - now_ts
        rem_hours = rem_sec / 3600
        exp_dt = datetime.fromtimestamp(exp_ts, tz=BJT).strftime("%Y-%m-%d %H:%M:%S")
        if rem_sec <= 0:
            print(f"  ⚠️ webAccessToken 已于 {exp_dt} 过期！可能导致请求被拒。")
        elif rem_hours < 1:
            print(f"  ⏳ 凭证即将过期: 剩余 {rem_sec // 60} 分钟（到期时间: {exp_dt}）")
        else:
            print(f"  🔑 凭据有效: 剩余 {rem_hours:.1f} 小时（到期时间: {exp_dt}）")

    # 2. 补齐鉴权必须的辅助 Cookie 与请求头
    # OPPO Mall 接口网关校验 cookie 中的 authHost 与 sa_distinct_id，若未提供易报 403 用户未登录。
    # sa_distinct_id 仅从用户 Cookie 或 memberinfo 中的 oid 派生，绝不内置硬编码兜底值（避免泄露账号指纹）。
    sa_id = cookie_items.get("sa_distinct_id") or user_oid or ""
    full_cookie_parts = [cookie_str.rstrip(";")]
    if "authHost" not in cookie_items:
        full_cookie_parts.append("authHost=www.opposhop.cn")
    if "sa_distinct_id" not in cookie_items and sa_id:
        full_cookie_parts.append(f"sa_distinct_id={sa_id}")
    req_cookie = "; ".join(full_cookie_parts)

    http = Http(task_name="oppo")
    common_headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Cookie": req_cookie,
        "s_channel": "h5_m",
        "source_type": "504",
        "Origin": BASE_HOST,
        "Referer": f"{BASE_HOST}/bp/b371ce270f7509f0?nightModelEnable=true&us=huiyuanpindao",
    }
    if sa_id:
        common_headers["sa_distinct_id"] = sa_id

    # 3. 查询签到详情
    print("  📋 查询签到状态与连签进度...")
    detail_url = f"{BASE_HOST}/api/cn/oapi/marketing/cumulativeSignIn/getSignInDetail?activityId={SIGN_IN_ACTIVITY_ID}"
    resp_detail = http.request("GET", detail_url, headers=common_headers)
    sign_detail_data = {}
    if resp_detail and resp_detail.code == 200:
        sign_detail_data = resp_detail.json() or {}

    # 4. 每日打卡签到
    print("  👉 提交每日打卡签到...")
    sign_in_url = f"{BASE_HOST}/api/cn/oapi/marketing/cumulativeSignIn/signIn"
    sign_body = {
        "activityId": SIGN_IN_ACTIVITY_ID,
        "creditsAddActionId": CREDITS_ADD_ACTION_ID,
        "business": 1,
    }

    resp_sign = http.request("POST", sign_in_url, json_data=sign_body, headers=common_headers)
    sign_res = resp_sign.json() if resp_sign and resp_sign.code == 200 else {}
    code = sign_res.get("code")
    msg = sign_res.get("message", "") or sign_res.get("errorMessage", "")
    sign_ok = False
    gained_points = 0

    if code == 200:
        sign_ok = True
        gained_points = 10
        print(f"  🎉 签到成功！获得 +10 积分")
    elif code in (5008, 1001, 1002) or is_already_signed(msg) or "已经签到" in msg or "已签到" in msg or "已完成" in msg:
        sign_ok = True
        print(f"  ℹ️ 今日已签到，跳过打卡 ({msg or '今日已完成签到'})")
    else:
        err_msg = msg or f"HTTP {resp_sign.code if resp_sign else 'No Response'}"
        print(f"  ⚠️ 签到返回: {err_msg}")
        if "登录" in err_msg or "auth" in err_msg.lower() or "token" in err_msg.lower() or code == 403:
            return False, f"登录态失效: {err_msg}"
        sign_ok = True

    # 5. 连签里程碑奖励提取
    milestones = sign_detail_data.get("data", {}).get("cumulativeAwardList", []) if isinstance(sign_detail_data.get("data"), dict) else []
    if milestones:
        for award in milestones:
            award_id = award.get("awardId") or award.get("id")
            award_status = award.get("status")
            award_name = award.get("awardName", "里程碑奖励")
            if award_status == 1 and award_id:
                print(f"  🎁 发现可领取的连签里程碑: {award_name}，正在领取...")
                draw_url = f"{BASE_HOST}/api/cn/oapi/marketing/cumulativeSignIn/drawCumulativeAward"
                draw_body = {
                    "activityId": SIGN_IN_ACTIVITY_ID,
                    "awardId": award_id,
                    "creditsAddActionId": CREDITS_ADD_ACTION_ID,
                    "business": 1,
                }
                resp_draw = http.request("POST", draw_url, json_data=draw_body, headers=common_headers)
                draw_res = resp_draw.json() if resp_draw and resp_draw.code == 200 else {}
                if draw_res.get("code") == 200:
                    print(f"  ✅ 领取成功: {award_name}")
                else:
                    print(f"  ℹ️ 领取结果: {draw_res.get('message', '未成功')}")

    # 6. 日常赚积分任务（自动完成上报与一键领取奖励）
    print("  🚀 获取日常赚积分任务列表...")
    task_url = f"{BASE_HOST}/api/cn/oapi/marketing/task/queryTaskList?activityId={TASK_ACTIVITY_ID}&source=c"
    resp_tasks = http.request("GET", task_url, headers=common_headers)
    task_list_data = resp_tasks.json() if resp_tasks and resp_tasks.code == 200 else {}
    task_dtos = []
    if isinstance(task_list_data.get("data"), dict):
        task_dtos = task_list_data["data"].get("taskDTOList", [])

    task_success_cnt = 0
    task_total_points = 0
    if task_dtos:
        print(f"  📦 发现 {len(task_dtos)} 项活动任务，正在自动处理...")
        for t in task_dtos:
            t_id = t.get("taskId")
            t_name = t.get("taskName", "未知任务")
            t_type = t.get("taskType", 1)
            t_status = t.get("taskStatus", 1)

            # 已完成并已领奖 (status 3: FINISHED)
            if t_status == 3:
                print(f"    ℹ️ 今日已领奖: {t_name}")
                continue

            # 步骤一：未完成且为可直接上报的浏览类日常任务 (taskType == 1)，上报完成条件 (status 1: PREPARE_FINISH -> 2: GO_AWARD)
            if t_status == 1 and t_type == 1 and t_id:
                report_url = f"{BASE_HOST}/api/cn/oapi/marketing/taskReport/signInOrShareTask?taskId={t_id}&activityId={TASK_ACTIVITY_ID}&taskType={t_type}"
                resp_rep = http.request("GET", report_url, headers=common_headers)
                rep_res = resp_rep.json() if resp_rep and resp_rep.code == 200 else {}
                if rep_res.get("code") == 200 and rep_res.get("data") == 200:
                    t_status = 2
                else:
                    rep_msg = rep_res.get("message", "")
                    if "上限" in rep_msg or "完成" in rep_msg:
                        t_status = 2
                    else:
                        print(f"    ⏩ 跳过: {t_name} ({rep_msg or '未达成条件'})")
                        continue
                time.sleep(0.5)

            # 步骤二：待领奖状态 (status 2: GO_AWARD)，调用 receiveAward 领取积分奖励 (2 -> 3)
            if t_status == 2 and t_id:
                award_url = f"{BASE_HOST}/api/cn/oapi/marketing/task/receiveAward?taskId={t_id}&activityId={TASK_ACTIVITY_ID}&creditsAddActionId={CREDITS_ADD_ACTION_ID}&business=1"
                resp_award = http.request("GET", award_url, headers=common_headers)
                award_res = resp_award.json() if resp_award and resp_award.code == 200 else {}
                aw_code = award_res.get("code")
                aw_data = award_res.get("data") or {}
                if aw_code == 200 and (aw_data.get("receiveStatus") or aw_data.get("awardValue")):
                    pts = int(aw_data.get("awardValue") or 2)
                    task_success_cnt += 1
                    task_total_points += pts
                    print(f"    🎉 领奖成功: {t_name} (+{pts} 积分)")
                elif aw_code == 1000005:
                    print(f"    ℹ️ 已领取或未达标: {t_name}")
                else:
                    aw_msg = award_res.get("message") or award_res.get("errorMessage", "未知错误")
                    print(f"    ⚠️ 领奖失败: {t_name} ({aw_msg})")
                time.sleep(0.5)

    # 7. 查询会员总积分资产
    total_credit = "未知"
    credit_url = f"{BASE_HOST}/api/cn/oapi/marketing/member/queryMemberCreditInfo"
    resp_credit = http.request("GET", credit_url, headers=common_headers)
    if resp_credit and resp_credit.code == 200:
        cr_data = resp_credit.json() or {}
        if isinstance(cr_data.get("data"), dict):
            c_info = cr_data["data"]
            total_credit = str(c_info.get("amount") if c_info.get("amount") is not None else c_info.get("credit", "未知"))
            lvl = c_info.get("userLevel", "")
            worth = c_info.get("deductibleAmountText", "")
            worth_desc = f"，抵扣金: {worth}" if worth else ""
            print(f"  💰 账户积分余额: {total_credit} (Lv.{lvl}{worth_desc})")
        else:
            print(f"  💰 当前账户总积分: {total_credit}")

    summary_desc = f"打卡成功，刷完 {task_success_cnt} 个任务 (+{task_total_points}分)，总积分: {total_credit}"
    return True, summary_desc


def main() -> None:
    print("=" * 50)
    print("📱 OPPO商城 每日打卡与赚积分任务")
    print("=" * 50)

    cookies = env_seq(PREFIX, "COOKIE", required=False)
    if not cookies:
        raw_cookie = os.getenv("OPPO_COOKIE", "").strip()
        if raw_cookie:
            cookies = [raw_cookie]

    if not cookies:
        print("❌ 未检测到 OPPO 登录凭据，请在 .env 配置 OPPO_COOKIE_1")
        sys.exit(1)

    total = len(cookies)
    success_count = 0
    statuses: List[str] = []

    for idx, c in enumerate(cookies, 1):
        try:
            ok, desc = _run_account(c, idx, total)
            if ok:
                success_count += 1
                statuses.append(desc)
            else:
                statuses.append(f"失败: {desc}")
        except Exception as exc:
            print(f"[{idx}/{total}] ❌ 执行异常: {exc}")
            statuses.append(f"异常: {exc}")

    print("\n" + "=" * 50)
    print(f"🏁 执行完毕: 成功 {success_count}/{total} 个账号")
    print("=" * 50)

    if success_count == 0:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
