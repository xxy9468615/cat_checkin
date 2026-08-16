#!/usr/bin/env python3
# cron: 0 */5 * * *
# new Env("HW Cookie 保活探测")
"""HW 门户会话保活探测（L2）：由 hw-keepalive workflow 每 5 小时调用。

- 会话存活：记录状态与 Set-Cookie 轮换观测（用于判断会话 TTL 语义：滑动/绝对），不做事
- 会话失效：复用 hw_dev 的 L3 自愈（Playwright 静默重登），导出 .heal/ 供回写
退出码：0 = 存活或已自愈；1 = 失效且无法自愈
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional, Tuple

from common import Http, main_guard, mask_str

from hw_dev import (
    BASE_HEADERS,
    BASE_URL,
    SessionExpiredError,
    _autoheal_enabled,
    _extract_csrf_eco,
    _get_csrf_token,
    _parse_cookies,
    _self_heal,
)

PERSONAL_INFO_URL = (
    f"{BASE_URL}/rest/developer/fwdu/rest/developer/user/"
    "hdcommunityservice/v1/member/get-personal-info"
)


def _probe(h: Http, cookie: str) -> Tuple[int, Optional[Dict[str, Any]], str]:
    """GET get-personal-info，返回 (HTTP code, JSON, Set-Cookie 名称列表)。"""
    headers = dict(BASE_HEADERS)
    headers.update({"Cookie": cookie, "csrf": _extract_csrf_eco(cookie) or "x"})
    resp = h.request("GET", PERSONAL_INFO_URL, headers=headers)
    data = resp.json({}) if resp.code == 200 else None
    try:
        rotated = ", ".join(
            sorted({c.split("=", 1)[0] for c in resp.headers.get_all("Set-Cookie") or []})
        ) or "无"
    except Exception:
        rotated = "未知"
    return resp.code, data if isinstance(data, dict) else None, rotated


def main() -> None:
    print("【HW Cookie 保活探测】")
    cookies = _parse_cookies(os.getenv("HW_DEV_COOKIE", "") or os.getenv("HW_DEV_cookie", ""))
    if not cookies:
        raise RuntimeError("未配置 HW_DEV_COOKIE，无法探测")

    cookie = cookies[0]
    h = Http(follow_redirects=True)
    try:
        _get_csrf_token(h, cookie)  # 确保 csrf-eco 存在（缺失会抛出指引性错误）
        code, data, rotated = _probe(h, cookie)
    except SessionExpiredError as e:
        code, data, rotated = 403, None, "-"
        print(f"❌ 会话已失效: {e}")
    else:
        if code == 200 and data:
            who = mask_str(str(data.get("memName") or data.get("account_name") or "?"))
            print(f"✅ 会话存活（用户 {who}），Set-Cookie 轮换: {rotated}，无需干预")
            return
        print(f"❌ 探测异常: HTTP {code}（非 200 响应），按会话失效处理")

    if not _autoheal_enabled(total=1):
        sys.exit(1)
    browser = None
    try:
        browser, new_cookie = _self_heal()
        code2, data2, _ = _probe(h, new_cookie)
        if code2 == 200 and data2:
            who = mask_str(str(data2.get("memName") or data2.get("account_name") or "?"))
            print(f"✅ 自愈后验证通过（用户 {who}），.heal/ 已导出待回写")
        else:
            print(f"⚠️ 自愈后探测仍异常: HTTP {code2}，请检查日志")
            sys.exit(1)
    except Exception as e:
        print(f"❌ 自愈失败: {e}")
        sys.exit(1)
    finally:
        if browser is not None:
            browser.close()


if __name__ == "__main__":
    main_guard(main)
