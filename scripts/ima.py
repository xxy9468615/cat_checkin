#!/usr/bin/env python3
# cron: 30 8 * * *
# new Env("腾讯 IMA 签到")
"""腾讯 IMA（ima.copilot 知识工作台）每日登录福利自动签到与满签奖励领取。

核心逻辑（接口逆向自 ima PC 客户端 H5 签到页 /copilot-token-daily-checkin/pc，
2026-11-01 HAR 抓包对齐）：
1. 凭证模型（两级：长效根凭据 + 短命叶令牌）：
   - 用户配置 IMA_COOKIE_<n> = 任意 ima.qq.com 请求的 x-ima-cookie 请求头整串；
     根凭据为其中的 IMA-REFRESH-TOKEN（不透明长令牌，寿命以周/月计），
     IMA-TOKEN 为约 2 小时的叶会话令牌（仅当次有效，永不落盘信任）；
   - Fresh-Mint-First（telecom 先例）：每次运行先用根凭据向
     /cgi-bin/auth_login/refresh 现签新 IMA-TOKEN（body: userId/refreshToken/tokenType=-1，
     设备 Cookie 仅 IMA-GUID + PLATFORM=H5），缓存令牌回退已无意义（2h < 调度间隔 24h）；
   - 服务端若在 refresh 响应中轮换 refreshToken 则同步持久化（实测不轮换，防御性兼容）。
2. x-ima-bkn 签名可推导，绝不让用户手抄（cloudstudio 先例）：
   bkn = djb2(IMA-TOKEN)，JS 语义为 32 位有符号回绕：result += int32(int32(result) << 5) + ord(ch)，
   最终 int32(result) & 0x7FFFFFFF。已对 HAR 真实令牌验证逐位吻合（1964361404）。
3. 每日签到（/cgi-bin/daily_login_activity/get_activity_info + check_in）：
   - get_activity_info 返回本周 7 格 + 满签奖励格，status 枚举：1=已过期 2=已领取 3=可领取 4=未解锁；
   - 今日格 status=3 时提交 check_in {type:1}（日签，+50 算力），status=2 幂等放行；
   - 满签奖励（连续 7 天解锁，周一开始周日结算）：按服务端 status 驱动而非日历锚定——
     status=3 即提交 check_in {type:2}，code 1001（未满签）/1002（当日已签）按业务态放行；
     日签成功后重拉一次活动信息，保证第 7 天同请求解锁的满签奖励当轮即领；
   - 服务端对同一接口短时间多次拒绝会回 HTTP 403 + 空 body，统一归一化为 code=-1
     限流态交由外层熔断重试，绝不让异常打断账号循环。
4. 双层持久化（Upstash Redis cat_checkin:state:ima_<n> + 本地 .ima_state_<n>.json）：
   - 状态含最新 refreshToken（轮换跟随）、凭据指纹（用户换 Secret 时重置有效期证据）；
   - 凭据无内嵌可解析有效期（不透明串），有效期经共享引擎 cookie_validity 按成功运行
     日反推老化信号，refresh 响应若携带过期时间字段则作为硬证据采纳。

环境变量：
- IMA_COOKIE_1, IMA_COOKIE_2...（多账号序列，x-ima-cookie 整串）
- IMA_COOKIE（单账号兼容）
- IMA_PROXY（可选代理出口；腾讯 CDN 直连可达，缺省不走代理）
"""
from __future__ import annotations

import hashlib
import json
import os
import re
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
    load_kv_state,
    main_guard,
    mask_email,
    mask_phone,
    mask_str,
    sanitize_snippet,
    save_kv_state,
)
import cookie_validity as cv

PREFIX = "IMA_"
BASE_URL = "https://ima.qq.com"
REFRESH_URL = f"{BASE_URL}/cgi-bin/auth_login/refresh"
ACTIVITY_INFO_URL = f"{BASE_URL}/cgi-bin/daily_login_activity/get_activity_info"
CHECK_IN_URL = f"{BASE_URL}/cgi-bin/daily_login_activity/check_in"

# ima PC 客户端内嵌浏览器 H5 页请求的规范 UA（HAR 2026-11-01 逐字节对齐；
# 电信先例：UA 必须保持完整规范形态，禁止截断/陈旧值）
UA_IMA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 IMA/150.0.7871.5469"
)

# 服务端状态枚举（来自签到页 JS）：1=已过期 2=已领取 3=可领取 4=未解锁
STATUS_CLAIMED = 2
STATUS_AVAILABLE = 3
STATUS_TEXT = {0: "未知", 1: "已过期", 2: "已领取", 3: "可领取", 4: "未解锁"}

CHECKIN_TYPE_DAILY = 1
CHECKIN_TYPE_WEEKLY_BONUS = 2

# 服务端业务码（社区实测 + HAR 对齐）：
#   0    = 成功
#   1001 = 本周未满签（满签奖励试领被拒，属正常业务态）
#   1002 = 今日已签到（幂等放行）
CODE_OK = 0
CODE_NOT_FULL_WEEK = 1001
CODE_ALREADY_CHECKED_IN = 1002

# 满签奖励格标题（活动改版时经 find_item 兜底，找不到则跳过试领）
BONUS_TITLE = "满签奖励"
_COOKIE_OPTIONAL_ORDER = (
    "IMA-GUID",
    "UID-TYPE",
    "PLATFORM",
    "CLIENT-TYPE",
    "IMA-Q36",
    "IMA-IUA",
)


def _to_int32(value: int) -> int:
    """Python int → JS 32 位有符号整数（回绕）。"""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def ima_bkn(token: str) -> int:
    """复刻 ima 页面 JS 的 djb2 签名算法，输出 x-ima-bkn 请求头。

    语义：result += int32(int32(result) << 5) + ord(ch)，最终 int32(result) & 0x7FFFFFFF。
    已对 2026-11-01 HAR 真实 IMA-TOKEN 验证：输出与抓包 x-ima-bkn 逐位一致。
    """
    result = 5381
    for ch in token or "":
        result += _to_int32(_to_int32(result) << 5) + ord(ch)
    return _to_int32(result) & 0x7FFFFFFF


def parse_ima_cookie(raw: str) -> Dict[str, str]:
    """解析 x-ima-cookie 整串（k=v; k=v）为字段字典。"""
    items: Dict[str, str] = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if k:
            items[k] = v
    return items


def build_ima_cookie(items: Dict[str, str], token: str) -> str:
    """构造规范 x-ima-cookie：必备字段 + 固定 PLATFORM=H5 + 保留用户附带字段。

    顺序对齐 H5 页抓包形态（IMA-UID → IMA-TOKEN → IMA-REFRESH-TOKEN → 设备字段），
    缺失的固定项（UID-TYPE=2 / PLATFORM=H5）自动补默认值。
    """
    merged: Dict[str, str] = {}
    for k in ("IMA-UID", "IMA-TOKEN", "IMA-REFRESH-TOKEN"):
        if items.get(k):
            merged[k] = items[k]
    if token:
        merged["IMA-TOKEN"] = token
    for k in _COOKIE_OPTIONAL_ORDER:
        if items.get(k):
            merged.setdefault(k, items[k])
    merged.setdefault("UID-TYPE", "2")
    merged.setdefault("PLATFORM", "H5")
    return "; ".join(f"{k}={v}" for k, v in merged.items())


def _base_headers() -> Dict[str, str]:
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "from_browser_ima": "1",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/copilot-token-daily-checkin/pc",
        "User-Agent": UA_IMA,
    }


def _mask_pii(text: str) -> str:
    """对服务端文案中的裸号码/邮箱脱敏（sanitize_snippet 不覆盖裸 PII，规则 4）。

    - 11 位独立数字段（大陆手机号与其他 11 位号码形态均覆盖）→ mask_phone 只留末 4；
      前后邻接数字时不命中，13 位毫秒时间戳 / 16 位 IMA-GUID / 长 docid 不受影响；
    - 邮箱 → mask_email（前缀末 4 + 域名全脱）。
    """
    text = re.sub(r"(?<!\d)\d{11}(?!\d)", lambda m: mask_phone(m.group(0)), text)
    return re.sub(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        lambda m: mask_email(m.group(0)),
        text,
    )


def _post_json(http: Http, url: str, body: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    """POST JSON 并归一化响应：空 body（限流 403）/ 非 JSON / 网络异常 → code=-1 结构。

    服务端被连续拒绝后直接回 HTTP 403 + 空 body，必须接住归一化，
    不能让异常冒出去打断账号循环（社区实测行为）。
    """
    try:
        resp = http.request("POST", url, json_data=body, headers=headers)
    except Exception as exc:
        return {"code": -1, "msg": f"请求异常: {exc}", "http_status": -1}
    if not resp:
        return {"code": -1, "msg": "无响应", "http_status": -1}
    raw = (resp.text or "").strip()
    status = resp.code
    if not raw:
        return {
            "code": -1,
            "msg": f"HTTP {status} 空响应（可能被限流，稍后重试）",
            "http_status": status,
        }
    try:
        data = json.loads(raw)
    except ValueError:
        return {
            "code": -1,
            # 非 JSON 响应（拦截页/网关错误页）与 dict 分支同级对待：先脱裸 PII
            # 再过 sanitize_snippet，才允许进入公开日志
            "msg": f"HTTP {status} 非 JSON 响应: {sanitize_snippet(_mask_pii(raw))}",
            "http_status": status,
        }
    if isinstance(data, dict):
        data.setdefault("http_status", status)
        msg = data.get("msg")
        if isinstance(msg, str) and msg:
            # 服务端原始响应文案：先脱裸 PII（手机号/邮箱），再过 sanitize_snippet
            # （抹 Cookie/token 形态）后才进 stdout（公开 Actions 日志 / 日报）
            data["msg"] = sanitize_snippet(_mask_pii(msg))
        return data
    return {"code": -1, "msg": f"HTTP {status} 异常响应结构", "http_status": status}


def _headers_with_cookie(cookie_str: str, token: str) -> Dict[str, str]:
    headers = _base_headers()
    headers["x-ima-cookie"] = cookie_str
    headers["x-ima-bkn"] = str(ima_bkn(token))
    return headers


def _extract_refresh_expiry(data: Dict[str, Any]) -> int:
    """从 refresh 响应中防御性提取凭据过期时间（秒级时间戳；无证据返回 0）。

    ima 客户端会展示 refreshTokenExpiredTime，但字段命名未定——扫描常见
    epoch 字段（秒/毫秒自动判别，取最大未来值）作为 cookie_validity 硬证据。
    """
    best = 0
    now = time.time()
    for key in (
        "expire_time", "expireTime", "expired_time", "expiredTime",
        "tokenExpiredTime", "refreshTokenExpiredTime", "expire_at", "expireAt",
    ):
        v = data.get(key)
        if isinstance(v, dict):
            v = v.get("refreshToken") or v.get("token") or ""
        try:
            ts = float(str(v).strip())
        except (TypeError, ValueError):
            continue
        if ts > 1e12:  # 毫秒级归一化
            ts /= 1000.0
        if ts > now and ts > best:
            best = int(ts)
    return best


def mint_access_token(
    http: Http, uid: str, refresh_token: str, guid: str
) -> Tuple[bool, str, str, int, str]:
    """用长效 refreshToken 现签约 2 小时叶会话 IMA-TOKEN。

    返回 (ok, token|"", msg, refresh_exp, rotated_refresh_token|"")。
    设备 Cookie 仅 IMA-GUID + PLATFORM=H5（对齐 ima 内置浏览器刷新链路），
    不携带旧 IMA-TOKEN（telecom 先例：死会话前置有害）；refresh 响应若轮换
    下发新 refreshToken 则透传给调用方持久化（实测不轮换，防御性兼容）。
    """
    device_cookie = f"IMA-GUID={guid}; PLATFORM=H5"
    headers = _base_headers()
    headers["x-ima-cookie"] = device_cookie
    body = {"userId": uid, "refreshToken": refresh_token, "tokenType": -1}
    data = _post_json(http, REFRESH_URL, body, headers)
    token = str(data.get("token") or "")
    if data.get("code") == CODE_OK and token:
        rotated = str(data.get("refreshToken") or data.get("refresh_token") or "")
        return True, token, "换票成功", _extract_refresh_expiry(data), rotated
    msg = str(data.get("msg") or f"HTTP {data.get('http_status')}")
    return False, "", msg, 0, ""


def find_item(info: Dict[str, Any], top: str) -> Optional[Dict[str, Any]]:
    """在活动信息 infos 数组中按 top 标题查找格子（今日 / 周二 / 满签奖励）。"""
    for item in info.get("infos") or []:
        if item.get("top") == top:
            return item
    return None


def _reward_of(resp: Dict[str, Any]) -> str:
    """签到接口奖励字段（snake/camel 双兼容），归一化为纯数字串（如 "50"）。"""
    got = resp.get("reward_received", resp.get("rewardReceived"))
    if got in (None, ""):
        return ""
    m = re.match(r"(\d+)", str(got).strip())
    return m.group(1) if m else str(got)


def _run_account(raw_cookie: str, index: int, total: int) -> Tuple[bool, str]:
    raw_cookie = (raw_cookie or "").strip()
    env_hash = hashlib.md5(raw_cookie.encode("utf-8")).hexdigest()
    redis_key = f"cat_checkin:state:ima_{index}"
    state_file = f".ima_state_{index}.json"

    items = parse_ima_cookie(raw_cookie)
    uid = items.get("IMA-UID", "")
    guid = items.get("IMA-GUID", "")
    refresh_token = items.get("IMA-REFRESH-TOKEN", "")
    if not uid or not refresh_token:
        return False, (
            "缺少登录凭据（x-ima-cookie 须同时含 IMA-UID 与 IMA-REFRESH-TOKEN，"
            f"缺失: {[k for k in ('IMA-UID', 'IMA-REFRESH-TOKEN') if not items.get(k)]}）"
        )

    # 1. 加载双层持久化状态（Upstash Redis + 本地 State）
    state = load_kv_state(redis_key, state_file) or {}
    # 根凭据以 Env 为准（状态里的 refreshToken 仅作服务端轮换后的最新值）
    if state.get("refresh_token") and state.get("env_hash") == env_hash:
        # 服务端轮换链未断时优先用轮换值，断链（用户换 Secret）则回退 Env 原值
        refresh_token = str(state["refresh_token"])

    http = Http(task_name="ima")

    # 2. Fresh-Mint-First：每次现签新 IMA-TOKEN（约 2h 叶令牌，缓存无意义）
    print(f"\n[{index}/{total}] 👤 用户: {mask_str(uid) if uid else f'账号 #{index}'}")
    ok_mint, token, mint_msg, refresh_exp, rotated = mint_access_token(http, uid, refresh_token, guid)
    if not ok_mint:
        return False, f"换票失败（IMA-REFRESH-TOKEN 可能已失效，请重新抓包更新 IMA_COOKIE_{index}）: {mint_msg}"
    print("  🔑 已用长效刷新令牌现签新会话令牌（约 2 小时叶令牌，每次运行现签）")
    # 服务端若轮换 refreshToken 则跟随最新值（实测不轮换，防御性兼容）：
    # 轮换发生时立即先持久化一次，消除「本次运行中途崩溃丢失新令牌」窗口；
    # 持久化沿用 save_kv_state 双通道「失败仅警告」契约（与全仓库一致），
    # 提示在保存动作之后输出，成功与否经其自身的 ☁️/⚠️ 行可观测
    if rotated and rotated != refresh_token:
        refresh_token = rotated
        save_kv_state(
            redis_key,
            state_file,
            {
                **state,
                "refresh_token": refresh_token,
                "uid": uid,
                "guid": guid,
                "env_hash": env_hash,
                "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
            },
        )
        print("  🔄 服务端已轮换 refreshToken，已同步持久化最新值")

    cookie_str = build_ima_cookie(items, token)
    headers = _headers_with_cookie(cookie_str, token)

    # 3. 查询本周签到活动信息
    info = _post_json(http, ACTIVITY_INFO_URL, {}, headers)
    if info.get("code") != CODE_OK:
        return False, f"查询活动信息失败: code={info.get('code')} msg={info.get('msg')}"

    # 4. 每日签到（今日格 status=3 可领取 → check_in type=1；status=2 幂等放行）
    today = find_item(info, "今日")
    if today is None:
        return False, "未找到「今日」条目，活动可能已改版，请人工核查"
    today_status = today.get("status")
    summary_parts: List[str] = []
    daily_newly_signed = False  # 本次运行真实提交了日签（非幂等放行）
    if today_status == STATUS_AVAILABLE:
        resp = _post_json(http, CHECK_IN_URL, {"type": CHECKIN_TYPE_DAILY}, headers)
        code = resp.get("code")
        if code == CODE_OK:
            daily_newly_signed = True
            got = _reward_of(resp)
            print(f"  🎉 签到成功！获得 +{got} 算力" if got else "  🎉 签到成功")
            summary_parts.append("签到成功" + (f" +{got} 算力" if got else ""))
        elif code == CODE_ALREADY_CHECKED_IN:
            # 幂等判定只认协议业务码：文案启发式会把真实拒绝误判成假成功
            print("  ℹ️ 今日已签到，幂等放行")
            summary_parts.append("今日已签到")
        else:
            return False, f"每日签到被拒: code={code} msg={resp.get('msg')}"
    elif today_status == STATUS_CLAIMED:
        print("  ℹ️ 今日已签到，幂等放行")
        summary_parts.append("今日已签到")
    else:
        # 协议外状态（已过期/未解锁出现在「今日」格）说明服务端状态机异常，
        # 如实判失败交外层重试与熔断，绝不当作成功吞掉
        return False, f"今日格状态异常（status={today_status} {STATUS_TEXT.get(today_status, '未知')}），请人工核查"

    # 5. 满签奖励：连续 7 天解锁（周一挂起、周日结算），按服务端 status 驱动
    #    （非日历锚定——status=3 即可领，日签成功后重拉信息确保第 7 天当轮即领）
    refetch_failed = False
    info_refetch = _post_json(http, ACTIVITY_INFO_URL, {}, headers)
    if info_refetch.get("code") == CODE_OK:
        info = info_refetch
    else:
        # 重拉失败时沿用签到前快照继续判定；是否致命由退出段裁决——
        # 若日签刚提交且快照显示满签奖励未入账，第 7 天同请求解锁的奖励
        # 可能被本次重拉失败吞掉 → 账号判失败交框架重试（下轮日签幂等放行）。
        # 警告行只打 code 不回显 msg：msg 常含「失败/403」等错误关键词，
        # 会被报告兜底降噪扫描误捞进 error_lines
        refetch_failed = True
        print(f"  ⚠️ 复核活动信息未成功（沿用签到前快照）: code={info_refetch.get('code')}")
    bonus = find_item(info, BONUS_TITLE) if isinstance(info, dict) else None
    bonus_secured = False       # 满签奖励已确定入账（本次领取成功 / 服务端已领取）
    bonus_pending_fail = False  # 试领被未知码拒绝 → 需要重试
    if bonus is not None and bonus.get("status") == STATUS_AVAILABLE:
        resp = _post_json(http, CHECK_IN_URL, {"type": CHECKIN_TYPE_WEEKLY_BONUS}, headers)
        code = resp.get("code")
        if code == CODE_OK:
            bonus_secured = True
            got = _reward_of(resp)
            print(f"  🎁 满签奖励已领取 +{got} 算力" if got else "  🎁 满签奖励已领取")
            summary_parts.append("满签奖励" + (f" +{got} 算力" if got else ""))
        elif code == CODE_NOT_FULL_WEEK:
            print("  ℹ️ 满签奖励未达条件（本周未签满）")
        elif code == CODE_ALREADY_CHECKED_IN:
            bonus_secured = True
            print("  ℹ️ 满签奖励本期已领取")
        else:
            # 未知拒绝（含限流 -1）：拒绝 ≠ 核实不可领，绝不当作成功吞掉——
            # 账号判失败交框架重试（日签收益已入账，重试只补试领）；
            # 警告行只打 code，防 msg 关键词被报告兜底扫描误捞
            bonus_pending_fail = True
            print(f"  ⚠️ 满签奖励试领未成功: code={code}")

    # 6. 结算展示 + 凭据有效期（共享引擎：无内嵌证据按成功运行日反推老化信号）
    days = info.get("checkin_days") if isinstance(info, dict) else None
    points = info.get("total_reward_points") if isinstance(info, dict) else None
    if days is not None and points is not None:
        print(f"  📊 本周连签 {days} 天 · 本周累计 +{points} 算力")

    final_refresh = refresh_token  # 轮换跟随已在换票步处理（取自 refresh 响应）

    final_cookie = build_ima_cookie({**items, "IMA-REFRESH-TOKEN": final_refresh}, token)
    learned = {"IMA-REFRESH-TOKEN": refresh_exp} if refresh_exp else {}
    tracked = cv.update_state(dict(state), final_cookie, learned)
    cv.mark_ok(tracked)  # 成功运行日入账（无解析有效期凭据按执行天数反推寿命）
    tag = cv.tag_for(
        final_cookie,
        tracked,
        learned,
        credential_match=lambda n: "IMA-REFRESH-TOKEN" in n or "IMA-TOKEN" in n,
    )
    if tag:
        print(f"  {tag.lstrip(' |')}")

    save_kv_state(
        redis_key,
        state_file,
        {
            **tracked,
            "refresh_token": final_refresh,
            "uid": uid,
            "guid": guid,
            "exp": refresh_exp or 0,
            "env_hash": env_hash,
            "updated_at": datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S"),
        },
    )

    summary_desc = "；".join(summary_parts) or "无动作"
    if days is not None:
        summary_desc += f"，本周连签 {days} 天"

    # 退出裁决：满签奖励存在「未入账且可能可领」的风险时如实判失败交框架
    # 重试（日签收益已入账且已在 summary 中保留，状态/轮换令牌也已持久化）；
    # 下轮日签幂等放行，只补试领，无重复收益风险
    if bonus_pending_fail:
        return False, f"{summary_desc}；满签奖励试领未成功（日签收益已入账），交由框架重试"
    if (
        refetch_failed
        and daily_newly_signed
        and bonus is not None
        and not (bonus_secured or bonus.get("status") == STATUS_CLAIMED)
    ):
        return False, f"{summary_desc}；复核活动信息未成功且满签奖励可能已解锁待领，交由框架重试"
    return True, summary_desc


def main() -> None:
    print("=" * 50)
    print("🤖 腾讯 IMA 每日登录福利签到")
    print("=" * 50)

    cookies = env_seq(PREFIX, "COOKIE", required=False)
    if not cookies:
        raw_cookie = os.getenv("IMA_COOKIE", "").strip()
        if raw_cookie:
            cookies = [raw_cookie]

    if not cookies:
        print("❌ 未检测到 IMA 登录凭据，请在 .env 配置 IMA_COOKIE_1（x-ima-cookie 请求头整串）")
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
                # 失败明细必须落到 stdout：unified_report / alert_levels 只认任务原始输出；
                # desc 拍平换行，防止服务端 msg 续行被报告解析器拆成独立行误判
                flat_desc = " ".join(str(desc).split())
                print(f"[{idx}/{total}] ❌ {flat_desc}")
                statuses.append(f"失败: {desc}")
        except Exception as exc:
            print(f"[{idx}/{total}] ❌ 执行异常: {exc}")
            statuses.append(f"异常: {exc}")

    print("\n" + "=" * 50)
    print(f"🏁 执行完毕: 成功 {success_count}/{total} 个账号")
    print("=" * 50)

    # 任一账号失败即非零退出（cloud189 同款语义）：外层熔断/重试按任务粒度接管，
    # 已成功账号次日重跑时走幂等放行，无重复收益风险
    if success_count < total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
