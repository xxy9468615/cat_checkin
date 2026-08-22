#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("Latvi 每日奖励及服务器自动续期")
import json
import os
import random
import re
import time
from datetime import datetime
from pathlib import Path
from common import BJT, Http, env, env_bool, is_already_signed, must_match, find, main_guard, schedule_repo_dispatch, upstash_redis_command

# Latvi 是 24 小时冷却制，不是每天固定时间刷新。
# 需要记录上次成功签到时间，下次在 +24h 之后才能再签。
# 状态持久化：优先 Upstash Redis（cat_checkin:state:latvi），本地 /data/latvi_state.json 或 .latvi_state.json 兜底备份。
#
# 单 run 全内联（2026-08-22 起）：由 daily_orchestrator 按 last_sign_ts+24h 动态推算
# 当日窗口并提前 ~2min 进场，脚本侧仅原地等待 + 冷却重试循环精确收尾（LATVI_NO_RELAY=1）。
# 旧 QStash 延时接力（+24h+3~5min dispatch latvi_next_sign / 18:00 cron 兜底锚点）
# 已退役，仅在未设 LATVI_NO_RELAY 时保留兼容。

PREFIX = "LATVI_"
STATE_FILE = Path(os.getenv("LATVI_STATE_FILE", "/data/latvi_state.json"))
LATVI_REDIS_KEY = f"{os.getenv('CAT_CHECKIN_REDIS_PREFIX', 'cat_checkin:').rstrip(':')}:state:latvi"

def _is_no_relay() -> bool:
    return env_bool("LATVI_NO_RELAY")


# QStash 接力调度的事件名（latvi.yml 的 repository_dispatch 类型）
DISPATCH_EVENT = "latvi_next_sign"
# 冷却后的随机余量（分钟）：避免每天同一秒请求；3~5 分钟同时控制链式顺延速度
MARGIN_MIN, MARGIN_MAX = 3, 5
# 等待不超过该秒数时原地短睡；更远则交给 QStash 延时接力（不阻塞 Runner）
INLINE_WAIT_MAX = 240


def _get_last_sign_time() -> datetime | None:
    """读取上次成功签到时间（优先 Upstash Redis，本地文件兜底）"""
    # 1. 优先从 Upstash Redis 远程读取
    url = os.getenv("UPSTASH_REDIS_REST_URL", "")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
    if url and token:
        try:
            ok, res = upstash_redis_command(["GET", LATVI_REDIS_KEY])
            if ok and isinstance(res, dict):
                raw = res.get("result")
                if raw:
                    data = json.loads(raw) if isinstance(raw, str) else raw
                    if isinstance(data, dict):
                        ts = data.get("last_sign_ts")
                        if ts:
                            return datetime.fromtimestamp(float(ts), tz=BJT)
        except Exception as e:
            print(f"⚠️ 从 Redis 读取 Latvi 状态异常: {e}")

    # 2. 本地文件兜底
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            ts = data.get("last_sign_ts")
            if ts:
                return datetime.fromtimestamp(float(ts), tz=BJT)
        except Exception:
            pass
    return None


def _set_last_sign_time(ts: datetime) -> None:
    """写入成功签到时间（本地文件 + Upstash Redis 同步持久化）"""
    state_data = {
        "last_sign_ts": ts.timestamp(),
        "last_sign_time": ts.isoformat(),
    }
    # 1. 保存本地文件
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state_data, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"⚠️ 保存 Latvi 本地状态失败: {e}")

    # 2. 同步保存至 Upstash Redis
    url = os.getenv("UPSTASH_REDIS_REST_URL", "")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
    if url and token:
        try:
            ok, res = upstash_redis_command(["SET", LATVI_REDIS_KEY, json.dumps(state_data, ensure_ascii=False)])
            if ok:
                print(f"☁️ Latvi 冷却状态已同步至 Upstash Redis ({LATVI_REDIS_KEY})")
            else:
                print(f"⚠️ Latvi 状态同步 Redis 失败: {res}")
        except Exception as e:
            print(f"⚠️ Latvi 状态同步 Redis 异常: {e}")


def _calc_wait_seconds() -> int:
    """计算需要等待的秒数：上次签到 + 24h + 随机 3~5 分钟余量。

    余量与接力调度用同一分布（MARGIN_MIN~MARGIN_MAX）：dispatch 按上次的余量触发后，
    此处新算的余量至多比它晚 2 分钟，落在原地短睡阈值（INLINE_WAIT_MAX）内。
    """
    last = _get_last_sign_time()
    if last is None:
        print("ℹ️ 无历史签到记录，直接尝试签到")
        return 0

    now = datetime.now(BJT)
    # 目标时间 = 上次 + 24小时 + 随机余量（避免每天同一秒请求）
    target = last + timedelta(hours=24, minutes=random.randint(MARGIN_MIN, MARGIN_MAX))
    wait = (target - now).total_seconds()

    print(f"📅 上次签到：{last.strftime('%Y-%m-%d %H:%M:%S')} | 目标时间：{target.strftime('%Y-%m-%d %H:%M:%S')}")
    return max(0, int(wait))


def _schedule_next_sign(delay_seconds: int) -> None:
    """调度下一次接力签到；失败不影响本次结果，由每日 18:00 定时任务兜底重锚。

    内联模式（LATVI_NO_RELAY=1）下仅打印明日窗口预期，不调度接力。
    """
    if _is_no_relay():
        eta = datetime.now(BJT) + timedelta(seconds=delay_seconds)
        # last_sign 在签到成功后写入；此处打印以当前时刻推算的明日窗口
        # 实际窗口以脚本输出的今日签到时刻 + 24h 为准
        print(f"📅 明日窗口预计开启于 {eta.strftime('%Y-%m-%d %H:%M:%S')} BJT（内联模式，无接力调度）")
        return
    ok, detail = schedule_repo_dispatch(DISPATCH_EVENT, delay_seconds)
    if ok:
        eta = datetime.now(BJT) + timedelta(seconds=delay_seconds)
        print(f"🔗 已调度下一轮签到：{eta.strftime('%Y-%m-%d %H:%M')}（QStash 延时接力）")
    else:
        print(f"⚠️ 下一轮延时调度失败（{detail}），将由每日 18:00 定时任务兜底重锚")


def main():
    email = env(PREFIX, "email")
    password = env(PREFIX, "password")

    # 幂等闸门：今日已签到（接力链重复触发 / cron 与 dispatch 重叠）时直接退出，
    # 不重复签到也不重复调度——下一轮已由当日签到时调度好
    last = _get_last_sign_time()
    now = datetime.now(BJT)
    if last and last.date() == now.date():
        print(f"✅ 今日已于 {last.strftime('%H:%M:%S')} 签到过，无需重复执行")
        return

    # 计算等待时间（24h 冷却 + 随机余量）
    wait_sec = _calc_wait_seconds()
    if _is_no_relay():
        # 内联模式：orchestrator 已按 last_sign+24h 精确排布进场时刻（提前 ~2min），
        # 此处 wait 通常 ≤ 130s，直接原地等待让冷却重试循环精确收尾
        if wait_sec > INLINE_WAIT_MAX:
            hh, rem = divmod(wait_sec, 3600)
            mm, ss = divmod(rem, 60)
            print(f"ℹ️ 内联模式：距窗口尚有 {hh}小时{mm}分{ss}秒，原地等待（不调度接力）")
    elif wait_sec > INLINE_WAIT_MAX:
        # 旧接力/兜底模式：距窗口尚远不阻塞 Runner，调度 QStash 接力
        schedule_delay = wait_sec + 60
        ok, detail = schedule_repo_dispatch(DISPATCH_EVENT, schedule_delay)
        if ok:
            eta = datetime.now(BJT) + timedelta(seconds=schedule_delay)
            hh, rem = divmod(wait_sec, 3600)
            mm, ss = divmod(rem, 60)
            print(f"🔔 距签到窗口尚有 {hh}小时{mm}分{ss}秒，已调度 {eta.strftime('%H:%M')} 接力签到（本次运行结束）")
            return
        print(f"⚠️ 延时调度失败（{detail}），回退为原地等待签到窗口")

    if wait_sec > 0:
        h, rem = divmod(wait_sec, 3600)
        m, s = divmod(rem, 60)
        print(f"⏳ 等待 {h}小时{m}分{s}秒 到达签到窗口...")
        time.sleep(wait_sec)

    h = Http(follow_redirects=True)
    ua = {"Referer": "https://dash.latvi.space/login"}

    # 1. 登录
    r = h.request("GET", "https://dash.latvi.space/login", headers=ua)
    csrf = must_match(r'name="csrf-token"\s+content="([^"]+)"', r.text, "csrf_token")
    h.request("POST", "https://dash.latvi.space/login", headers=ua, form={"_token": csrf, "email": email, "password": password})

    # 2. 访问主页获取最新 CSRF 和余额
    home = h.request("GET", "https://dash.latvi.space/home", headers={"Referer": "https://dash.latvi.space/home"})
    csrf = find(r'name="csrf-token"\s+content="([^"]+)"', home.text, csrf)
    before = find(r'info-box-text">Credits</span>\s*<span class="info-box-number">([\d,.]+)', home.text, "?")

    print("【Latvi 每日奖励及服务器自动续期】")

    # 3. 每日签到领奖励（冷却期内自动重试）
    claim_headers = {
        "X-CSRF-TOKEN": csrf,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://dash.latvi.space/home",
    }
    max_retries = 60
    sign_success = False
    for attempt in range(1, max_retries + 1):
        claim = h.request(
            "POST",
            "https://dash.latvi.space/daily-rewards/claim",
            headers=claim_headers,
            json_data={},
        )
        data = claim.json({})
        if data.get("success"):
            now = datetime.now(BJT)
            _set_last_sign_time(now)
            print(f"✅ 签到成功 +{data.get('reward')}（连续{data.get('new_streak')}天），余额 {data.get('new_balance')}")
            sign_success = True
            # 接力链：本次 + 24h + 3~5 分钟后由 QStash dispatch 下一轮签到
            _schedule_next_sign(24 * 3600 + random.randint(MARGIN_MIN, MARGIN_MAX) * 60)
            break

        # 解析冷却时间（中英文都支持）
        msg = data.get("error") or data.get("message") or ""
        cooldown_sec = 0
        # 中文: X小时 Y分钟 Z秒
        m = re.search(r'(\d+)\s*(?:小时|hours?|hour)', msg)
        if m:
            cooldown_sec += int(m.group(1)) * 3600
        m = re.search(r'(\d+)\s*(?:分钟|minutes?|minute)', msg)
        if m:
            cooldown_sec += int(m.group(1)) * 60
        m = re.search(r'(\d+)\s*(?:秒|seconds?|second)', msg)
        if m:
            cooldown_sec += int(m.group(1))

        if cooldown_sec > 0:
            cooldown_sec += 1  # 安全余量
            print(f"⏳ 第{attempt}次：{msg}，等待 {cooldown_sec} 秒后重试...")
            time.sleep(cooldown_sec)
        else:
            # 无冷却消息：可能为「今日已签到」（状态缓存丢失后的重复触发），也可能是真实错误。
            # 匹配词必须精确到 ≥2 字词组：单字符「已」会命中「账户已被封禁」等错误 → 假成功 + 状态污染，
            # 错误状态写盘会导致次日真实跳过签到（宁可红卡、由次日重锚恢复，不可假绿）
            if is_already_signed(msg):
                now = datetime.now(BJT)
                _set_last_sign_time(now)
                sign_success = True
                print(f"ℹ️ 今日已签到（服务端：{msg}），已回写状态")
                _schedule_next_sign(24 * 3600 + random.randint(MARGIN_MIN, MARGIN_MAX) * 60)
            else:
                print(f"ℹ️ 签到结果：{msg}（当前余额 {before}）——未识别为已签到，不回写状态")
            break
    else:
        print(f"❌ 签到失败：超过最大重试次数，当前余额 {before}")

    # 4. 服务器自动延长/续期逻辑 (Server Renewal)
    servers_page = h.request("GET", "https://dash.latvi.space/servers", headers={"Referer": "https://dash.latvi.space/home"})
    combined_html = home.text + "\n" + servers_page.text

    # 寻找所有的 renew 动作 URL (如 /servers/renew/123 或 /servers/123/renew)
    renew_urls = set(re.findall(r'(?:action|href)="([^"]*/servers/(?:renew/\d+|\d+/renew|extend/\d+))"', combined_html))

    # 若未匹配到显式按钮 URL，尝试根据服务器 ID 拼装
    if not renew_urls:
        server_ids = set(re.findall(r'/servers/(\d+)', combined_html))
        for sid in server_ids:
            renew_urls.add(f"https://dash.latvi.space/servers/renew/{sid}")

    if renew_urls:
        for renew_url in sorted(renew_urls):
            if not renew_url.startswith("http"):
                renew_url = "https://dash.latvi.space" + (renew_url if renew_url.startswith('/') else '/' + renew_url)

            server_target = renew_url.rstrip('/').split('/')[-1]
            renew_resp = h.request(
                "POST",
                renew_url,
                headers={"Referer": "https://dash.latvi.space/servers", "X-CSRF-TOKEN": csrf},
                form={"_token": csrf},
            )

            # 提取 alert 提示信息
            alert_msg = find(r'<div class="alert alert-[^"]*">(.*?)</div>', renew_resp.text, "")
            if alert_msg:
                clean_msg = re.sub(r'<[^>]+>', '', alert_msg).strip()
                print(f"🔄 服务器自动延长 (#{server_target}): {clean_msg}")
            elif "success" in renew_resp.text.lower() or renew_resp.code in (200, 302):
                print(f"🔄 服务器自动延长 (#{server_target}): 已发送续期请求 (HTTP {renew_resp.code})")
            else:
                print(f"ℹ️ 服务器自动延长 (#{server_target}): 响应 Code {renew_resp.code}")
    else:
        print("ℹ️ 未在账号下检测到服务器续期链接")

    # 签到未达成时显式失败（exit 1 → 结果卡片标红）；接力链不续，由次日 18:00 cron 重锚
    if not sign_success:
        raise RuntimeError(f"签到失败：未能完成每日签到（当前余额 {before}）")

if __name__ == "__main__":
    main_guard(main)
