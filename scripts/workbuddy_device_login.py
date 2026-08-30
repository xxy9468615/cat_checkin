#!/usr/bin/env python3
"""WorkBuddy/CodeBuddy 插件 OAuth 设备码登录助手（一次性跑在本地，勿进 CI）。

背景：workbuddy.cn 的浏览器会话 cookie 是 7 天硬上限、无法脚本侧续期（实测
ONEID authorize prompt=login + failCode=10074 双重堵死）。但插件 OAuth 流
（copilot.tencent.com /v2/plugin/auth/*）会签发可滚动的 refresh_token：
首次浏览器登录后，凭 X-Refresh-Token 头即可反复换新 token 对。社区实现
（wb2api / workbuddy-switch）证实唯一失效方式是「闲置数天未刷新」被服务端
清理（12153 invalid_grant）——每天刷一次即可永久续命。

用法（本地终端，两步）：
  python3 scripts/workbuddy_device_login.py url    # 打印登录 URL，浏览器打开并登录
  python3 scripts/workbuddy_device_login.py poll   # 登录完成后执行，输出凭据 JSON

把 poll 输出的 JSON 原样交给维护者写入 GitHub Secrets（值不入库不入日志）。
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from common import Http  # noqa: E402

UPSTREAM = "https://copilot.tencent.com"
EP_AUTH_STATE = f"{UPSTREAM}/v2/plugin/auth/state?platform=CLI"
EP_AUTH_TOKEN = f"{UPSTREAM}/v2/plugin/auth/token?state="
EP_LOGIN_ACCT = f"{UPSTREAM}/v2/plugin/login/account?state="
STATE_FILE = Path(tempfile.gettempdir()) / "workbuddy_login_state.json"

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": "https://www.codebuddy.cn",
    "Referer": "https://www.codebuddy.cn/",
    "User-Agent": "CLI/2.63.2 CodeBuddy/2.63.2",
}


def _envelope_data(resp):
    j = resp.json()
    if j.get("code") != 0:
        raise SystemExit(f"upstream code={j.get('code')} msg={j.get('msg')}")
    return j.get("data") or {}


def cmd_url() -> None:
    h = Http()
    data = _envelope_data(h.request("POST", EP_AUTH_STATE, headers=HEADERS, data=b"{}", timeout=30))
    state, auth_url = data.get("state") or "", data.get("authUrl") or ""
    if not (state and auth_url):
        raise SystemExit(f"auth state 缺字段: {list(data.keys())}")
    STATE_FILE.write_text(json.dumps({"state": state}), encoding="utf-8")
    print(f"state 已暂存 {STATE_FILE}")
    print("\n请在浏览器打开以下链接并完成登录：\n")
    print(f"  {auth_url}\n")
    print("登录完成后运行: python3 scripts/workbuddy_device_login.py poll")


def cmd_poll() -> None:
    if not STATE_FILE.exists():
        raise SystemExit("未找到 state（先运行 url 子命令）")
    state = (json.loads(STATE_FILE.read_text(encoding="utf-8"))).get("state") or ""
    h = Http()
    r = h.request("GET", EP_AUTH_TOKEN + state, headers=HEADERS, timeout=30)
    j = r.json()
    if j.get("code") != 0:
        raise SystemExit(f"登录未完成或已过期（code={j.get('code')} msg={j.get('msg')}）。重新 url → 登录 → poll")
    tok = j.get("data") or {}
    if not tok.get("accessToken") or not tok.get("refreshToken"):
        raise SystemExit(f"token 响应缺字段: {list(tok.keys())}")
    bundle = {
        "access_token": tok.get("accessToken"),
        "refresh_token": tok.get("refreshToken"),
        "expires_in": tok.get("expiresIn"),
        "domain": tok.get("domain") or "",
    }
    # 拉账号信息（失败不阻塞，uid 仅用于命名 secret）
    r2 = h.request(
        "GET", EP_LOGIN_ACCT + state,
        headers={**HEADERS, "Authorization": f"Bearer {tok.get('accessToken')}"},
        timeout=30,
    )
    try:
        acct = (r2.json().get("data") or {})
        bundle["uid"] = acct.get("uid") or ""
        bundle["nickname"] = acct.get("nickname") or ""
        bundle["enterprise_id"] = acct.get("enterpriseId") or ""
    except Exception:
        pass
    STATE_FILE.unlink(missing_ok=True)
    print(json.dumps(bundle, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "url":
        cmd_url()
    elif cmd == "poll":
        cmd_poll()
    else:
        print(__doc__)
        raise SystemExit(1)
