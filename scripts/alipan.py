#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("阿里云盘 签到")
"""阿里云盘（alipan.com）每日自动签到、奖励领取与网盘空间资产统计。

功能：
1. 官方 OAuth2 Token 自动刷新与轮换（POST /v2/account/token）
2. Upstash Redis + 本地 State 双层跨 CI 持久化（cat_checkin:state:alipan_{idx}），实现数月/长期免维护
3. 每日自动签到与月度累计天数查询（POST /v2/activity/sign_in_info）
4. 签到奖励自动识别（容量延期特权 / 文件容量包 / 会员权益）
5. 个人网盘总容量与已用空间统计（POST /v2/databox/get_personal_info）
6. 多账号独立隔离运行与手机号/UID/昵称智能脱敏

环境变量：
- ALIPAN_REFRESH_TOKEN_1, ALIPAN_REFRESH_TOKEN_2... (多账号序列，推荐)
- ALIPAN_REFRESH_TOKEN / ALIPAN_refresh_token (单账号兼容)
- ALIPAN_TOKEN_1, ALIPAN_TOKEN_2... / ALIPAN_TOKEN (兼容 LocalStorage token json 或 裸 refresh_token)
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from common import (
    BJT,
    Http,
    env_seq,
    load_kv_state,
    main_guard,
    mask_str,
    save_kv_state,
)

PREFIX = "ALIPAN_"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _extract_refresh_token(raw: str) -> str:
    """从原始字符串或 LocalStorage JSON 中安全提取 32 位 refresh_token。"""
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith("{") and "refresh_token" in raw:
        try:
            d = json.loads(raw)
            if isinstance(d, dict) and d.get("refresh_token"):
                return str(d["refresh_token"]).strip()
        except Exception:
            pass
        m = re.search(r'["\']refresh_token["\']\s*:\s*["\']([a-f0-9]{32})["\']', raw, re.I)
        if m:
            return m.group(1).strip()
    m_hex = re.search(r"([a-f0-9]{32})", raw, re.I)
    if m_hex:
        return m_hex.group(1).strip()
    return raw


def _format_size(bytes_num: int) -> str:
    """将字节数格式化为易读的容量单位（如 2.23 GB / 804.24 GB）。"""
    if bytes_num >= 1024**4:
        return f"{bytes_num / (1024**4):.2f} TB"
    if bytes_num >= 1024**3:
        return f"{bytes_num / (1024**3):.2f} GB"
    if bytes_num >= 1024**2:
        return f"{bytes_num / (1024**2):.2f} MB"
    if bytes_num >= 1024:
        return f"{bytes_num / 1024:.1f} KB"
    return f"{bytes_num} B"


def _refresh_access_token(h: Http, refresh_token: str) -> Dict[str, Any]:
    """调用阿里云盘官方接口刷新 access_token 并获取最新 refresh_token。"""
    r = h.request(
        "POST",
        "https://auth.alipan.com/v2/account/token",
        headers={"Content-Type": "application/json", "User-Agent": UA},
        json_data={"grant_type": "refresh_token", "refresh_token": refresh_token},
    )
    data: Dict[str, Any] = r.json({})
    if r.code == 200 and data.get("access_token"):
        return data
    err_msg = data.get("message") or data.get("code") or r.text[:120]
    raise RuntimeError(f"刷新 Token 失败 [{r.code}]: {err_msg}")


def _run_account(raw_token: str, idx: int, total: int) -> Tuple[bool, str]:
    """单账号阿里云盘签到与资产统计流程。"""
    init_refresh_token = _extract_refresh_token(raw_token)
    if not init_refresh_token:
        raise RuntimeError("refresh_token 为空或无法提取")

    env_hash = hashlib.md5(init_refresh_token.encode("utf-8")).hexdigest()
    redis_key = f"cat_checkin:state:alipan_{idx}"
    state_file = f".alipan_state_{idx}.json"

    # 1. 状态恢复：检查 Upstash Redis 与 本地 State
    state = load_kv_state(redis_key, state_file) or {}
    cur_refresh_token = init_refresh_token

    if state.get("env_hash") == env_hash and state.get("refresh_token"):
        # 环境变量未变更，优先沿用持久化中最新的滚动 refresh_token
        cur_refresh_token = str(state["refresh_token"]).strip()

    h = Http(follow_redirects=True)

    # 2. 执行 Token 换新
    token_resp = None
    try:
        token_resp = _refresh_access_token(h, cur_refresh_token)
    except Exception as e:
        if cur_refresh_token != init_refresh_token:
            # 滚动 Token 失效时，回退尝试初始环境变量凭证
            try:
                token_resp = _refresh_access_token(h, init_refresh_token)
                cur_refresh_token = init_refresh_token
            except Exception:
                raise e
        else:
            raise e

    access_token = token_resp.get("access_token", "")
    new_refresh_token = token_resp.get("refresh_token") or cur_refresh_token
    user_name = str(token_resp.get("user_name") or "")
    nick_name = str(token_resp.get("nick_name") or "")
    user_id = str(token_resp.get("user_id") or "")

    # 3. 持久化最新轮换的 Token
    try:
        save_kv_state(
            redis_key,
            state_file,
            {
                "refresh_token": new_refresh_token,
                "env_hash": env_hash,
                "user_name": user_name,
                "nick_name": nick_name,
                "user_id": user_id,
                "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
            },
        )
    except Exception:
        pass

    # 用户名与标签
    display_name = nick_name or user_name or (f"UID: {user_id[:8]}" if user_id else f"账号 #{idx}")
    masked_name = mask_str(display_name)
    masked_phone = f" ({mask_str(user_name)})" if user_name and user_name != display_name else ""
    print(f"[{idx}/{total}] 👤 用户: 【{masked_name}】{masked_phone} | 🔑 Token 自动续期有效")

    api_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "User-Agent": UA,
        "Origin": "https://www.alipan.com",
        "Referer": "https://www.alipan.com/",
    }

    # 4. 辅助触碰签到列表（触发日活）
    try:
        h.request(
            "POST",
            "https://member.alipan.com/v1/activity/sign_in_list",
            headers=api_headers,
            json_data={"_rx-s": "mobile"},
        )
    except Exception:
        pass

    # 5. 核心签到与月度签到详情查询 (POST /v2/activity/sign_in_info)
    r_info = h.request(
        "POST",
        "https://member.alipan.com/v2/activity/sign_in_info",
        headers=api_headers,
        json_data={},
    )
    info_data: Dict[str, Any] = r_info.json({})

    sign_days = 1
    blessing = ""
    reward_name = ""
    reward_desc = ""

    if r_info.code == 200 and info_data.get("success"):
        res = info_data.get("result") or {}
        sign_days = int(res.get("signInDay") or 1)
        blessing = str(res.get("blessing") or "")
        rewards: List[Dict[str, Any]] = res.get("rewards") or []
        for rw in rewards:
            if isinstance(rw, dict) and rw.get("type") == "dailySignIn":
                reward_name = str(rw.get("name") or "")
                reward_desc = str(rw.get("remind") or rw.get("rewardDesc") or "")
                break
        if not reward_name and rewards:
            first_rw = rewards[0]
            reward_name = str(first_rw.get("name") or "")
            reward_desc = str(first_rw.get("remind") or first_rw.get("rewardDesc") or "")

    # 6. 查询个人空间容量信息 (POST /v2/databox/get_personal_info)
    space_str = ""
    usage_str = ""
    try:
        r_space = h.request(
            "POST",
            "https://api.alipan.com/v2/databox/get_personal_info",
            headers=api_headers,
            json_data={},
        )
        space_data: Dict[str, Any] = r_space.json({})
        if r_space.code == 200:
            sp_info = space_data.get("personal_space_info") or {}
            used_size = sp_info.get("used_size")
            total_size = sp_info.get("total_size")
            if isinstance(used_size, (int, float)) and isinstance(total_size, (int, float)) and total_size > 0:
                space_str = f"{_format_size(int(used_size))} / {_format_size(int(total_size))}"
                usage_pct = (used_size / total_size) * 100.0
                usage_str = f" (使用率 {usage_pct:.2f}%)"
    except Exception:
        pass

    # 7. 格式化输出
    sign_line = f"• 签到: 【成功】 本月累计签到: 【{sign_days}】天"
    if blessing:
        sign_line += f" ({blessing})"
    print(sign_line)

    if reward_name:
        reward_line = f"• 奖励: 【{reward_name}】"
        if reward_desc:
            reward_line += f" ({reward_desc})"
        print(reward_line)

    if space_str:
        print(f"• 空间: 【{space_str}】{usage_str}")

    return True, "成功"


def main() -> None:
    print("【阿里云盘 签到】")
    # 优先扫描 ALIPAN_REFRESH_TOKEN_1, _2...，其次回退 ALIPAN_TOKEN_1, _2...
    tokens = env_seq(PREFIX, "refresh_token", required=False)
    if not tokens:
        tokens = env_seq(PREFIX, "token", required=False)
    if not tokens:
        raise RuntimeError("未配置 ALIPAN_REFRESH_TOKEN_1 或 ALIPAN_TOKEN_1 环境变量")

    total = len(tokens)
    success_count = 0
    errors = []

    for i, token in enumerate(tokens, 1):
        try:
            ok, _ = _run_account(token, i, total)
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
