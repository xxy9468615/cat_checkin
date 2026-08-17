#!/usr/bin/env python3
# new Env("HW 开发者 登入引导")
"""HW 开发者门户一次性本地引导：有头浏览器手动登入，导出 storage_state 与 Cookie。

背景：门户会话 Cookie 约 24h 失效且无续期接口，但 SSO 会话有效期长得多。
本脚本把"已登入的完整浏览器状态"（含 SSO + 门户 Cookie）存为 HW_DEV_STATE，
之后 CI 中的签到脚本会在会话过期时用它静默重登自愈（见 hw_dev.py 的 L3 自愈）。

凭证存储（Redis 为主、Secrets 兜底）：
  - 主：写入 Upstash Redis（hw:cookie / hw:state），CI 优先读取。
  - 兜底：gh secret set 写 GitHub Secrets（HW_DEV_COOKIE / HW_DEV_STATE）。
    未配置 Redis 或 gh 不可用时仍可走 Secrets 路径。

用法（本机执行，需要图形界面；引导完成后无需重复，直到 SSO 也失效）：
  pip install -r requirements.txt
  python -m playwright install chromium
  python3 scripts/hw_login.py                    # 登入后写 Redis + Secrets
  python3 scripts/hw_login.py --no-push         # 仅写 Redis（若配置），不动 Secrets

写入的 Secrets（本机已 gh auth login 时自动完成，值经 stdin 传入不回显）：
  HW_DEV_COOKIE             浏览器同源 Cookie 串（L1 快路径用）
  HW_DEV_STATE              storage_state JSON（L3 自愈用）
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

from common import Browser, Http, mask_str

from cred_store import set_hw_cred, set_meta

from hw_dev import (
    BASE_HEADERS,
    BASE_URL,
    HEAL_DIR,
    PORTAL_URL,
    _export_cookie_string,
    _extract_csrf_eco,
    _get_personal_info,
    _write_heal_outputs,
)

DEFAULT_REPO = "xxy9468615/cat_checkin"
DEFAULT_TIMEOUT = 300  # 手动登入（含滑块/短信验证）的最长等待


SSO_MARKERS = ("oauth", "/cas/", "id1.cloud", "passport", "loginAuth", "ticket=")


def _attach_sso_tracker(browser: Browser) -> list:
    """记录登入过程中的 SSO 跳转链（供未来固化自愈触发 URL）。"""
    chain: list = []
    try:
        page = browser.page
        if page is not None:

            def on_request(req):
                url = req.url
                if any(m in url.lower() for m in SSO_MARKERS) and url not in chain:
                    chain.append(url)

            page.on("request", on_request)
    except Exception:
        pass
    return chain


def _wait_manual_login(browser: Browser, timeout: int) -> None:
    """轮询 get-ainfo 直到门户会话建立（200 + csrf 头）。"""
    headers = {
        "Origin": "https://developer.huaweicloud.com",
        "Referer": "https://developer.huaweicloud.com/",
        "Content-Type": "text/plain",
    }
    deadline = time.time() + timeout
    next_hint = 0.0
    while time.time() < deadline:
        resp = browser.request("GET", f"{BASE_URL}/api/get-ainfo", headers=headers, timeout=15)
        if resp.code == 200 and (resp.headers or {}).get("csrf"):
            return
        if time.time() >= next_hint:
            remaining = int(deadline - time.time())
            print(f"… 等待登入完成（剩余 {remaining // 60}m{remaining % 60:02d}s），当前页面: {browser.current_url[:100]}")
            next_hint = time.time() + 30
        time.sleep(3)
    raise RuntimeError(f"等待登入超时（{timeout}s），请重跑本脚本")


def _gh_available() -> bool:
    return shutil.which("gh") is not None


def _gh_secret_set(repo: str, name: str, value: str) -> bool:
    """gh secret set（stdin 传值，不进 argv、不回显）。"""
    proc = subprocess.run(
        ["gh", "secret", "set", name, "-R", repo],
        input=value.encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f"⚠️ 写入 Secret {name} 失败: {proc.stderr.decode('utf-8', 'replace')[:200]}")
        return False
    print(f"✅ Secret 已更新: {name}")
    return True


def _write_redis_only(cookie_str: str, state: dict) -> None:
    """把凭证推送到 Upstash Redis（主存储）。best-effort，未配置/失败仅警告。"""
    try:
        ok_c = set_hw_cred("cookie", cookie_str, source="login-script")
        ok_s = set_hw_cred("state", json.dumps(state, ensure_ascii=False), source="login-script")
        if ok_c and ok_s:
            print("✅ 凭证已推送到 Upstash Redis（CI 下次将优先读取）")
            set_meta({"source": "login-script", "cookie_len": len(cookie_str)})
        elif ok_c or ok_s:
            print(f"⚠️ 部分凭证推送 Redis 失败（cookie={ok_c}, state={ok_s}）")
        else:
            print("ℹ️ 未配置 Upstash Redis（UPSTASH_REDIS_REST_URL/TOKEN），跳过 Redis 推送")
    except Exception as e:
        print(f"⚠️ 推送 Upstash Redis 异常（已忽略）: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="HW 开发者门户登入引导（一次性）")
    parser.add_argument("--repo", default=DEFAULT_REPO, help=f"GitHub 仓库（默认 {DEFAULT_REPO}）")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="等待手动登入的超时秒数")
    parser.add_argument("--no-push", action="store_true", help="仅导出本地文件，不写 GitHub Secrets")
    args = parser.parse_args()

    print("【HW 开发者 登入引导】")
    print(f"即将打开浏览器：{PORTAL_URL}")
    print("请在弹出的浏览器中手动登入（密码 + 可能的滑块/短信验证）。脚本会自动检测登入状态…\n")

    browser = Browser(headless=False, user_agent=BASE_HEADERS["User-Agent"])
    try:
        browser.goto(PORTAL_URL, timeout=90)
        sso_chain = _attach_sso_tracker(browser)
        _wait_manual_login(browser, args.timeout)

        cookie_str = _export_cookie_string(browser)
        if "csrf-eco=" not in cookie_str:
            raise RuntimeError("导出的 Cookie 缺少 csrf-eco，请确认已完整登入后重试")
        state = browser.export_storage_state()
        _write_heal_outputs(cookie_str, state)

        # 用导出的 Cookie 走一遍 L1 快路径探测，确认对纯 HTTP 请求同样可用
        h = Http(follow_redirects=True)
        alias, name = _get_personal_info(h, cookie_str, _extract_csrf_eco(cookie_str))
        print(f"✅ 登入成功：用户【{mask_str(name)}】（{mask_str(alias)}）")
        print(f"✅ 已导出: {HEAL_DIR}/cookie.txt（{len(cookie_str)} 字符）与 {HEAL_DIR}/state.json")

        if sso_chain:
            with open(os.path.join(HEAL_DIR, "sso_chain.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(sso_chain))
            print(f"📝 已记录 SSO 跳转链 {len(sso_chain)} 步（{HEAL_DIR}/sso_chain.txt），前 3 步：")
            for u in sso_chain[:3]:
                print(f"   {u[:130]}")

        if args.no_push:
            # --no-push 模式：仍尝试写 Redis（若配置了 env），仅跳过 gh
            _write_redis_only(cookie_str, state)
            print("\n--no-push 模式：已尝试写 Upstash Redis；如未配置 Redis，请手动设置以下 GitHub Secrets：")
            print("  HW_DEV_COOKIE <- .heal/cookie.txt")
            print("  HW_DEV_STATE  <- .heal/state.json")
            return

        # 先写 Upstash Redis（主，CI 下次优先读取），再 gh secret set（兜底）
        _write_redis_only(cookie_str, state)

        if not _gh_available():
            print("\n⚠️ 未找到 gh 命令，请手动设置 Secrets（或安装并 gh auth login 后重跑）：")
            print(f"  gh secret set HW_DEV_COOKIE -R {args.repo} < {HEAL_DIR}/cookie.txt")
            print(f"  gh secret set HW_DEV_STATE  -R {args.repo} < {HEAL_DIR}/state.json")
            return

        ok1 = _gh_secret_set(args.repo, "HW_DEV_COOKIE", cookie_str)
        ok2 = _gh_secret_set(args.repo, "HW_DEV_STATE", json.dumps(state, ensure_ascii=False))
        if not (ok1 and ok2):
            sys.exit(1)
        print("\n🎉 引导完成。CI 签到将优先使用 Cookie，过期时自动用 STATE 静默重登。")
    finally:
        browser.close()


if __name__ == "__main__":
    main()
