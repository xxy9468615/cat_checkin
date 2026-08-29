#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("掘金 签到")
import hashlib
import json
import re
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from common import (
    BJT,
    Http,
    env_seq,
    is_already_signed,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PREFIX = "JUEJIN_"
BASE_URL = "https://api.juejin.cn"
DEFAULT_AID = "2608"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _merge_cookie_str(base: str, jar: Any) -> str:
    """合并已有 Cookie 串与 urllib CookieJar 中的最新 Set-Cookie（同名覆盖）。"""
    cookie_dict: Dict[str, str] = {}
    if base:
        for part in base.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    cookie_dict[k.strip()] = v.strip()
    for c in jar or ():
        if getattr(c, "name", None) and getattr(c, "value", None):
            cookie_dict[c.name] = c.value
    return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())


def _parse_cookie_tokens(cookie_str: str) -> Tuple[str, str]:
    """从 Cookie 串中提取 aid 与 uuid（从 __tea_cookie_tokens_2608 等解析）。"""
    aid = DEFAULT_AID
    uuid = ""
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip()
        m = re.match(r"^__tea_cookie_tokens_(\d+)$", k)
        if m:
            aid = m.group(1)
            try:
                raw_json = urllib.parse.unquote(urllib.parse.unquote(v))
                t_obj = json.loads(raw_json)
                uuid = str(t_obj.get("user_unique_id") or t_obj.get("web_id") or "")
            except Exception:
                pass
    if not uuid:
        # 尝试从 uuid_tt 或 odin_tt 降级获取
        m_uid = re.search(r"uid_tt=([a-f0-9]+)", cookie_str)
        if m_uid:
            uuid = m_uid.group(1)
    return aid, uuid


def _parse_cookie_expiry(cookie_str: str) -> Tuple[Optional[int], Optional[int]]:
    """解析 sid_guard 中的签发时间戳与 TTL，返回 (expire_ts, remaining_days)。"""
    unquoted = urllib.parse.unquote(cookie_str)
    m = re.search(r"sid_guard=[^|;]+\|(\d+)\|(\d+)", unquoted)
    if m:
        try:
            issue_ts = int(m.group(1))
            ttl_sec = int(m.group(2))
            expire_ts = issue_ts + ttl_sec
            remaining_days = max(0, int((expire_ts - time.time()) / 86400))
            return expire_ts, remaining_days
        except Exception:
            pass
    return None, None


def _run_one(raw_cookie: str, idx: int, total: int) -> Tuple[bool, str]:
    state_file = f".juejin_state_{idx}.json"
    redis_key = f"cat_checkin:state:juejin_{idx}"
    saved_state = load_kv_state(redis_key, state_file) or {}
    saved_cookie = str(saved_state.get("cookie") or "").strip()
    saved_env_hash = str(saved_state.get("env_hash") or "").strip()

    raw_cookie = raw_cookie.strip()
    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest() if raw_cookie else ""

    # 起始 Cookie：env 更新感知（用户更新了 Secrets → 新 env 优先）；否则滚动 state 优先
    if raw_cookie and env_hash and env_hash != saved_env_hash:
        base_cookie = raw_cookie
    else:
        base_cookie = saved_cookie or raw_cookie

    if not base_cookie:
        raise RuntimeError("未配置 JUEJIN_cookie，请配置掘金登录凭证")

    # 提取 aid 与 uuid
    aid, uuid = _parse_cookie_tokens(base_cookie)

    # 解析 sid_guard 有效期
    _, remaining_days = _parse_cookie_expiry(base_cookie)
    expiry_desc = (
        f"Cookie 剩余 {remaining_days} 天"
        if remaining_days is not None
        else "Cookie 有效期未知"
    )

    headers = {
        "User-Agent": DEFAULT_UA,
        "Referer": "https://juejin.cn/",
        "Origin": "https://juejin.cn",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Cookie": base_cookie,
    }
    h = Http()

    # === 1. 用户信息获取（非阻断） ===
    user_name = "掘金用户"
    user_id = ""
    try:
        u_resp = h.request(
            "GET",
            f"{BASE_URL}/user_api/v1/user/get?aid={aid}&uuid={uuid}",
            headers=headers,
            timeout=20,
        )
        if u_resp.code == 200:
            u_json = u_resp.json({}) or {}
            if u_json.get("err_no") == 0:
                udata = u_json.get("data") or {}
                user_name = str(udata.get("user_name") or "掘金用户")
                user_id = str(udata.get("user_id") or "")
    except Exception:
        pass

    masked_user = mask_str(user_name)
    masked_uid = mask_str(user_id) if user_id else ""
    user_info_str = (
        f"用户：【{masked_user}】 (UID: {masked_uid})"
        if masked_uid
        else f"用户：【{masked_user}】"
    )

    # === 2. 核心签到（直接 POST，服务端响应判定成败与幂等） ===
    sign_resp = h.request(
        "POST",
        f"{BASE_URL}/growth_api/v1/check_in?aid={aid}&uuid={uuid}&spider=0",
        headers=headers,
        json_data={},
        timeout=30,
    )

    sign_data = sign_resp.json({}) or {}
    err_no = sign_data.get("err_no")
    err_msg = str(sign_data.get("err_msg") or "")
    incr_point = 0
    signed_status = ""

    if err_no == 0:
        sdata = sign_data.get("data")
        if isinstance(sdata, dict):
            incr_point = int(sdata.get("incr_point", 0))
            signed_status = "成功"
        else:
            signed_status = "成功"
    elif err_no == 15001 or is_already_signed(err_msg, extra_phrases=("重复签到", "已经签到")):
        signed_status = "今日已签"
    elif sign_resp.code == 200 and not sign_data:
        # HTTP 200 但响应体为空，通过 get_today_status 辅助校验
        try:
            st_resp = h.request(
                "GET",
                f"{BASE_URL}/growth_api/v2/get_today_status?aid={aid}&uuid={uuid}",
                headers=headers,
                timeout=15,
            )
            if st_resp.code == 200 and ((st_resp.json({}) or {}).get("data") or {}).get("check_in_done"):
                signed_status = "今日已签"
            else:
                signed_status = "成功"
        except Exception:
            signed_status = "成功"
    else:
        # 签到接口报错
        raise RuntimeError(f"签到失败: {err_msg} (err_no={err_no})")

    # === 3. 连签天数查询 ===
    cont_count = 0
    sum_count = 0
    try:
        c_resp = h.request(
            "GET",
            f"{BASE_URL}/growth_api/v1/get_counts?aid={aid}&uuid={uuid}",
            headers=headers,
            timeout=20,
        )
        if c_resp.code == 200:
            c_json = c_resp.json({}) or {}
            if c_json.get("err_no") == 0:
                cdata = c_json.get("data") or {}
                cont_count = int(cdata.get("cont_count", 0))
                sum_count = int(cdata.get("sum_count", 0))
    except Exception:
        pass

    # === 4. 免费抽奖（1 次免费机会） ===
    lottery_msg = "今日已抽"
    draw_gain_ore = 0
    try:
        cfg_resp = h.request(
            "GET",
            f"{BASE_URL}/growth_api/v1/lottery_config/get?aid={aid}&uuid={uuid}",
            headers=headers,
            timeout=20,
        )
        if cfg_resp.code == 200:
            cfg_json = cfg_resp.json({}) or {}
            free_count = int(((cfg_json.get("data") or {}).get("free_count") or 0))
            if free_count > 0:
                draw_resp = h.request(
                    "POST",
                    f"{BASE_URL}/growth_api/v1/lottery/draw?aid={aid}&uuid={uuid}&spider=0",
                    headers=headers,
                    json_data={},
                    timeout=30,
                )
                if draw_resp.code == 200:
                    draw_json = draw_resp.json({}) or {}
                    if draw_json.get("err_no") == 0:
                        lottery_name = str((draw_json.get("data") or {}).get("lottery_name") or "未知奖品")
                        lottery_msg = f"抽中 {lottery_name}"
                        # 若抽中矿石，提取数额
                        m_ore = re.search(r"(\d+)\s*矿石", lottery_name)
                        if m_ore:
                            draw_gain_ore = int(m_ore.group(1))
                    else:
                        lottery_msg = f"抽奖失败: {draw_json.get('err_msg')}"
    except Exception as e:
        lottery_msg = f"抽奖异常: {e}"

    # === 5. 沾喜气（每日 1 次免费机会） ===
    dip_msg = "今日已沾"
    gain_lucky = 0
    total_lucky = 0
    try:
        hist_resp = h.request(
            "POST",
            f"{BASE_URL}/growth_api/v1/lottery_history/global_big?aid={aid}&uuid={uuid}",
            headers=headers,
            json_data={"page_no": 1, "page_size": 5},
            timeout=20,
        )
        history_id = None
        if hist_resp.code == 200:
            h_json = hist_resp.json({}) or {}
            h_data = h_json.get("data") or {}
            h_list = []
            if isinstance(h_data, dict):
                h_list = h_data.get("lotteries") or h_data.get("lottery_history_list") or []
            elif isinstance(h_data, list):
                h_list = h_data
            if isinstance(h_list, list) and h_list:
                history_id = h_list[0].get("history_id") or h_list[0].get("lottery_id")

        if history_id:
            dip_resp = h.request(
                "POST",
                f"{BASE_URL}/growth_api/v1/lottery_lucky/dip_lucky?aid={aid}&uuid={uuid}",
                headers=headers,
                json_data={"lottery_history_id": str(history_id)},
                timeout=20,
            )
            if dip_resp.code == 200:
                d_json = dip_resp.json({}) or {}
                if d_json.get("err_no") == 0:
                    d_data = d_json.get("data") or {}
                    has_dip = bool(d_data.get("has_dip"))
                    gain_lucky = int(d_data.get("dip_value", 0))
                    total_lucky = int(d_data.get("total_value", 0))
                    if gain_lucky > 0:
                        dip_msg = f"成功 +{gain_lucky} 幸运值"
                    elif has_dip:
                        dip_msg = "今日已沾"
                    else:
                        dip_msg = f"已沾（当前幸运值 {total_lucky}）"
                else:
                    dip_msg = "今日已沾"
    except Exception as e:
        dip_msg = f"沾喜气异常: {e}"

    # === 6. 矿石资产查询 ===
    cur_point = 0
    try:
        p_resp = h.request(
            "GET",
            f"{BASE_URL}/growth_api/v1/get_cur_point?aid={aid}&uuid={uuid}",
            headers=headers,
            timeout=20,
        )
        if p_resp.code == 200:
            p_json = p_resp.json({}) or {}
            if p_json.get("err_no") == 0:
                cur_point = int(p_json.get("data", 0))
    except Exception:
        pass

    # === 7. 保存滚动 Cookie 状态 ===
    merged_cookie = _merge_cookie_str(base_cookie, h.jar)
    save_kv_state(
        redis_key,
        state_file,
        {
            "cookie": merged_cookie,
            "env_hash": env_hash,
            "aid": aid,
            "uuid": uuid,
            "remaining_days": remaining_days,
            "updated_at": int(time.time()),
        },
    )

    # === 8. 组装格式化输出 ===
    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    sign_gain_str = f" +{incr_point} 矿石" if incr_point > 0 else ""
    streak_str = f" 连签天数：【{cont_count}】天" if cont_count > 0 else ""
    sum_str = f" (累计 {sum_count} 天)" if sum_count > 0 else ""
    lucky_tail = f" 当前累计幸运值：【{total_lucky}】" if total_lucky > 0 else ""

    lines = [
        f"{prefix_label}👤 {user_info_str} | 🔑 {expiry_desc}",
        f"• 签到：【{signed_status}】{streak_str}{sum_str}{sign_gain_str}",
        f"• 免费抽奖：【{lottery_msg}】",
        f"• 沾喜气：【{dip_msg}】{lucky_tail}",
        f"• 资产：矿石 【{cur_point:,}】",
    ]

    if remaining_days is not None and remaining_days < 30:
        lines.append(f"⚠️ Cookie 剩余有效期不足 30 天（剩余 {remaining_days} 天），请及时更新")

    return True, "\n".join(lines)


def main():
    print("【掘金 签到】")
    cookies = env_seq(PREFIX, "cookie")
    total = len(cookies)
    results: List[Tuple[bool, str]] = []

    for idx, c in enumerate(cookies, 1):
        c = c.strip()
        if not c:
            continue
        try:
            ok, msg = _run_one(c, idx, total)
            print(msg)
            results.append((ok, msg))
        except Exception as e:
            prefix_label = f"[{idx}/{total}] " if total > 1 else ""
            err_msg = f"{prefix_label}签到失败：{e}"
            print(err_msg)
            results.append((False, err_msg))

    ok_count = sum(1 for ok, _ in results if ok)
    if total > 1:
        print(f"\n========== 签到总结 ==========\n成功 {ok_count}/{total}")

    if ok_count != total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
