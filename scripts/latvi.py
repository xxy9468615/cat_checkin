#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("Latvi 每日奖励及服务器自动续期")
import json
import os
import random
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from common import Http, env, must_match, find, main_guard

# Latvi 是 24 小时冷却制，不是每天固定时间刷新。
# 需要记录上次成功签到时间，下次在 +24h 之后才能再签。
# 状态持久化：本地 /data/latvi_state.json（app_runner 环境），GitHub Actions 用 cache（.latvi_state.json）。

PREFIX = "LATVI_"
BJT = timezone(timedelta(hours=8))
STATE_FILE = Path(os.getenv("LATVI_STATE_FILE", "/data/latvi_state.json"))


def _get_last_sign_time() -> datetime | None:
    """读取上次成功签到时间"""
    if not STATE_FILE.exists():
        return None
    try:
        data = json.loads(STATE_FILE.read_text())
        ts = data.get("last_sign_ts")
        if ts:
            return datetime.fromtimestamp(ts, tz=BJT)
    except Exception:
        pass
    return None


def _set_last_sign_time(ts: datetime) -> None:
    """写入成功签到时间"""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"last_sign_ts": ts.timestamp()}, ensure_ascii=False))


def _calc_wait_seconds() -> int:
    """计算需要等待的秒数：上次签到 + 24h + 随机 0-10 分钟偏移"""
    last = _get_last_sign_time()
    if last is None:
        print("ℹ️ 无历史签到记录，直接尝试签到")
        return 0

    now = datetime.now(BJT)
    # 目标时间 = 上次 + 24小时 + 随机偏移（避免每天同一秒请求）
    target = last + timedelta(hours=24, minutes=random.randint(0, 10))
    wait = (target - now).total_seconds()

    print(f"📅 上次签到：{last.strftime('%Y-%m-%d %H:%M:%S')} | 目标时间：{target.strftime('%Y-%m-%d %H:%M:%S')}")
    return max(0, int(wait))


def main():
    email = env(PREFIX, "email")
    password = env(PREFIX, "password")

    # 计算等待时间（24h 冷却 + 随机偏移）
    wait_sec = _calc_wait_seconds()
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
            break

        # 解析冷却时间
        msg = data.get("error") or data.get("message") or ""
        cooldown_sec = 0
        m = re.search(r'(\d+)\s*小时', msg)
        if m:
            cooldown_sec += int(m.group(1)) * 3600
        m = re.search(r'(\d+)\s*分钟', msg)
        if m:
            cooldown_sec += int(m.group(1)) * 60
        m = re.search(r'(\d+)\s*秒', msg)
        if m:
            cooldown_sec += int(m.group(1))

        cooldown_sec += 1  # 安全余量

        if cooldown_sec > 0:
            print(f"⏳ 第{attempt}次：{msg}，等待 {cooldown_sec} 秒后重试...")
            time.sleep(cooldown_sec)
        else:
            print(f"ℹ️ 签到结果：{msg}（当前余额 {before}）")
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

main_guard(main)
