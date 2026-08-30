#!/usr/bin/env python3
# cron: 50 16 * * *
# new Env("NodeSeek 签到")
"""NodeSeek (https://www.nodeseek.com) 每日自动签到领鸡腿脚本。

核心逻辑：
1. 从 Cookie 中提取 pjwt（JWT Payload）解码用户 ID、用户名，并计算 30 天有效期与剩余天数（<7 天告警）。
2. 直接调用签到 API：POST https://www.nodeseek.com/api/attendance?random=true（支持代理出口）。
3. 服务端响应判定：
   - success=true: 提取 gain（获得鸡腿数）与 current（当前鸡腿总资产）。
   - success=false 且含「今天已完成签到/请勿重复操作」：幂等放行。
   - 其他错误抛出异常触发失败卡。

环境变量：
  NODESEEK_COOKIE / NODESEEK_COOKIE_1, _2... : 多账号 Cookie 字符串
  NODESEEK_PROXY : 代理出口（如 http://127.0.0.1:3066 或 socks5://127.0.0.1:1080）
  NODESEEK_RANDOM : 是否随机鸡腿（默认 true）
"""
import base64
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common import Http, env, env_bool, env_seq, is_already_signed, main_guard, mask_str

PREFIX = "NODESEEK_"
DEFAULT_API = "https://www.nodeseek.com"
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _parse_cookie_info(cookie_str: str) -> Tuple[str, str, Optional[int]]:
    """从 Cookie 中解析用户名、UID 以及剩余有效期（天）。"""
    username = ""
    uid = ""
    remaining_days = None

    m = re.search(r"pjwt=([^;]+)", cookie_str)
    if m:
        raw_jwt = m.group(1).strip()
        parts = raw_jwt.split(".")
        if parts:
            try:
                b64_payload = parts[0]
                # 补全 base64 padding
                b64_payload += "=" * ((4 - len(b64_payload) % 4) % 4)
                decoded = base64.b64decode(b64_payload).decode("utf-8")
                payload = json.loads(decoded)
                if isinstance(payload, dict):
                    username = str(payload.get("name", ""))
                    uid = str(payload.get("id", ""))
                    ts = payload.get("ts")
                    if ts and isinstance(ts, (int, float)):
                        # NodeSeek Session 默认有效期 30 天 (2592000s)
                        expire_ts = int(ts) + 30 * 86400
                        remaining_days = max(0, int((expire_ts - time.time()) / 86400))
            except Exception:
                pass

    return username, uid, remaining_days


class _CffiResp:
    """与 common.Http.Response 对齐的最小接口（.code/.text/.json(default)）。"""

    def __init__(self, r):
        self.code = r.status_code
        self.text = r.text

    def json(self, default=None):
        try:
            return json.loads(self.text)
        except Exception:
            return default if default is not None else {}


def _request_attendance(h, url: str, headers: Dict[str, str], proxy: str):
    """优先 curl_cffi Chrome TLS 指纹：NodeSeek 的 CF 风控按 IP 信誉+TLS 指纹打分，
    urllib/requests 的 Python 指纹在数据中心出口上稳定吃 managed challenge（403）。
    Chrome 指纹不改 UA 语义，仅抹平 JA3 差异；未安装 curl_cffi 时回退原 Http。
    （实验记录 2026-08-31：干净住宅 IP 上 urllib 也能过 → 指纹只在可疑 IP 上成为
    压死稻草；TW-X1-1 出口 urllib 连续两轮 403，curl_cffi 是最小代价的对策。）"""
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return h.request("POST", url, headers=headers, json_data={})
    proxies = {"http": proxy, "https": proxy} if proxy else None
    r = cffi_requests.post(
        url, headers=headers, json={}, proxies=proxies,
        impersonate="chrome", timeout=60, allow_redirects=False,
    )
    return _CffiResp(r)


def _run_account(idx: int, total: int, cookie: str, proxy: str, random_bonus: bool) -> None:
    username, uid, remaining_days = _parse_cookie_info(cookie)
    masked_user = mask_str(username, 1, 1) if username else f"账号 #{idx}"
    masked_uid = mask_str(uid, 2, 1) if uid else "未知"

    expiry_tag = ""
    if remaining_days is not None:
        if remaining_days < 7:
            expiry_tag = f" | ⚠️ Cookie 剩余 {remaining_days} 天（请尽快更新）"
        else:
            expiry_tag = f" | 🔑 Cookie 剩余 {remaining_days} 天"

    print(f"[{idx}/{total}] 👤 用户: 【{masked_user}】 (UID: {masked_uid}){expiry_tag}")

    h = Http(follow_redirects=True, proxy=proxy)
    headers = {
        "User-Agent": _UA,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": DEFAULT_API,
        "Referer": f"{DEFAULT_API}/board",
        "Cookie": cookie,
    }

    url = f"{DEFAULT_API}/api/attendance?random={'true' if random_bonus else 'false'}"
    resp = _request_attendance(h, url, headers, proxy)

    if resp.code == 200:
        data = resp.json({})
        if data.get("success"):
            gain = data.get("gain", 0)
            current = data.get("current")
            msg = data.get("message", "签到成功")
            print(f"• 签到: 【成功】 获得 🍗 +{gain} 鸡腿 ({msg})")
            if current is not None:
                print(f"• 资产: 鸡腿 【{current}】")
            return
        else:
            msg = data.get("message", "")
            if is_already_signed(msg, extra_phrases=("今天已完成签到", "已完成签到", "请勿重复操作", "已经签到")):
                print("• 签到: 【今日已签】")
                current = data.get("current")
                if current is not None:
                    print(f"• 资产: 鸡腿 【{current}】")
                return
            raise RuntimeError(f"NodeSeek 签到失败: {msg or resp.text}")

    # 服务端返回非 200（例如 500 包含今天已签到）
    try:
        err_data = json.loads(resp.text)
        err_msg = err_data.get("message", "")
    except Exception:
        err_data = {}
        err_msg = resp.text

    if is_already_signed(err_msg, extra_phrases=("今天已完成签到", "已完成签到", "请勿重复操作", "已经签到")):
        print("• 签到: 【今日已签】")
        return

    if resp.code in (401, 403) or "USER NOT FOUND" in err_msg or "Just a moment" in err_msg:
        raise RuntimeError(f"NodeSeek 鉴权或风控失败 (HTTP {resp.code}): {err_msg[:120]}")

    raise RuntimeError(f"NodeSeek 请求异常 (HTTP {resp.code}): {err_msg[:120]}")


def main() -> None:
    print("【NodeSeek 签到】")
    cookies = env_seq(PREFIX, "cookie")

    # 代理优先级：NODESEEK_PROXY -> AGENTROUTER_PROXY -> 空
    proxy = os.getenv("NODESEEK_PROXY") or os.getenv("AGENTROUTER_PROXY") or ""
    random_bonus = env_bool("NODESEEK_RANDOM", default=True)

    errors = []
    total = len(cookies)
    for i, cookie in enumerate(cookies, 1):
        try:
            _run_account(i, total, cookie, proxy, random_bonus)
        except Exception as e:
            errors.append(f"账号 #{i} 失败: {e}")
            print(f"❌ 账号 #{i} 签到失败: {e}")

    if errors:
        print(f"\n❌ 共有 {len(errors)}/{total} 个账号签到失败")
        sys.exit(1)
    else:
        print(f"\n✅ 全部 {total} 个账号处理完成")


if __name__ == "__main__":
    main_guard(main)
