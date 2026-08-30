#!/usr/bin/env python3
"""提示/警告分级引擎（daily_report / discord_notify / unified_report 共用）。

三级模型（优先级 fail > warn > ok）：
  🔴 fail  任务失败（退出非 0 / 超时 / 异常）——红色预警，走既有失败卡链路
  🟡 warn  任务成功但需要关注——黄色预警（提示级），两个来源：
            1) 无感续期任务（auto-renew）续期失败：本次签到仍成功，但滚动续期
               链路断了，凭据将在当前余量耗尽后失效 → 提示「续期失败请检查」
            2) 无法续期任务凭据即将过期：Cookie 剩余有效期 <= 1 天
               → 提前 1 天提示「请尽快更新」
  🟢 ok    一切正常

设计原则：
- 站点续期语义集中在本模块注册表（script 文件名 → 模式），report_fields 只管
  展示字段、不掺和级别判断；
- 无感续期任务的「剩余 N 天」不参与过期提示（滚动续期会自动续，报了反而误导读者，
  modelscope 的「魔粒 X 过期」同理，那是奖励有效期不是凭据有效期）；
- fail 恒压过 warn：失败卡已覆盖一切，黄色提示不重复打扰；
- 判定纯函数化（无 IO），便于自测与复用。

用法：
    from alert_levels import classify
    cls = classify("tencent_cloudstudio.py", ok=True, output="...")
    cls["level"] ∈ {"ok", "warn", "fail"}；cls["warns"] 为提示文本列表
"""
from __future__ import annotations

import re
from typing import Dict, List

# ---------------------------------------------------------------------------
# 站点续期语义注册表（key = 脚本文件名，与 report_fields.SCRIPT_EXTRACTORS 同键位）
# ---------------------------------------------------------------------------

# 无感续期任务：凭据可自动滚动/换新。其「剩余 N 天」是滚动窗口而非死线，
# 不做「即将过期」提示；续期失败（仍能签到的场景）才值得黄色提示。
AUTO_RENEW_SCRIPTS = {
    "tencent_cloudstudio.py",  # Keycloak SSO 长期票静默换 session
    "2libra.py",               # refresh_token 换新 access_token
    "alipan.py",               # OAuth2 refresh_token 官方轮换
    "sophnet.py",              # refresh_token 换新
    "latvi.py",                # 服务器自动延长
    "smzdm.py",                # Set-Cookie 滚动保活
    "modelscope.py",           # Set-Cookie 滑动续期（国内/国际共用脚本）
}

# 续期失败信号（按行匹配；任务整体 ok=True 时命中 → 黄色「续期失败请检查」。
# 各模式只锚定本站脚本的专属措辞，不会误伤其他站点）
_RENEWAL_FAIL_PATTERNS: Dict[str, tuple] = {
    "tencent_cloudstudio.py": (
        r"SSO 未取到新 session",
        r"KEYCLOAK 长期票据",
        r"AUTH_EXPIRED",
        r"自动续票失败",
    ),
    "2libra.py": (
        r"token 换新失败",
    ),
    "alipan.py": (
        r"刷新 Token 失败",
    ),
    "sophnet.py": (
        r"无法自动续期",
        r"[Rr]efresh [Tt]oken (?:无效|已过期)",
    ),
    "latvi.py": (
        # 延长结果行不含「HTTP 200 / 成功」即视为失败（与 ex_latvi 的 ✓ 判定同源）
        r"服务器自动延长 \(#\d+\): (?!.*(HTTP 200|成功))",
    ),
}

# 续期失败提示语（提示读者该做什么，而不是只抛日志原文）
_RENEWAL_HINTS: Dict[str, str] = {
    "tencent_cloudstudio.py": "SSO 静默换票失败（KEYCLOAK 长期票据可能被吊销或要求交互登录），本次用旧票签成，请检查/准备更新 Cookie",
    "2libra.py": "refresh_token 换新失败，当前 access_token 到期前仍可签到，请尽快重新登录更新 Cookie",
    "alipan.py": "refresh_token 轮换异常，请检查凭据",
    "sophnet.py": "refresh_token 续期失败，请检查凭据",
    "latvi.py": "服务器自动延长失败，请检查站点",
}

# 无法续期任务：凭据剩余有效期提前 1 天提示（用户指定阈值）
EXPIRY_WARN_DAYS = 1
_COOKIE_DAYS_RE = re.compile(r"Cookie 剩余 (\d+) 天")

_LEVELS = ("ok", "warn", "fail")


def _clean(text: str, limit: int = 60) -> str:
    text = re.sub(r"\s+", " ", (text or "").strip())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def classify(script: str, ok: bool, output: str) -> Dict[str, object]:
    """按脚本名 + 执行结果 + 原始输出判定预警级别。

    返回 {"level": "ok"|"warn"|"fail", "warns": [str, ...]}，warns 已去重。
    """
    script = (script or "").strip()
    warns: List[str] = []
    for raw in (output or "").splitlines():
        ln = raw.strip()
        if not ln:
            continue
        # 1) 无感续期任务：续期失败（本次签到仍成功）
        for pat in _RENEWAL_FAIL_PATTERNS.get(script, ()):  # type: ignore[arg-type]
            if re.search(pat, ln):
                hint = _RENEWAL_HINTS.get(script, "自动续期失败，请检查凭据")
                warns.append(f"{hint}｜证据: {_clean(ln)}")
                break
        # 2) 无法续期任务：凭据剩余有效期 <= 1 天，提前 1 天提示
        if script not in AUTO_RENEW_SCRIPTS:
            m = _COOKIE_DAYS_RE.search(ln)
            if m and int(m.group(1)) <= EXPIRY_WARN_DAYS:
                warns.append(f"Cookie 仅剩 {int(m.group(1))} 天，无法自动续期，请尽快更新凭据")
    # 去重保序，上限 5 条防刷屏
    seen: set = set()
    warns = [w for w in warns if not (w in seen or seen.add(w))][:5]
    if not ok:
        level = "fail"
    elif warns:
        level = "warn"
    else:
        level = "ok"
    return {"level": level if level in _LEVELS else "ok", "warns": warns}


def warn_count(script: str, ok: bool, output: str) -> int:
    return len(classify(script, ok, output)["warns"])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 自测：python3 scripts/tests/test_alert_levels.py 亦可运行完整用例
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    cases = [
        # (说明, script, ok, output, 期望 level, 期望 warns 片段)
        ("cloudstudio 续期失败但签到成功 → 黄色",
         "tencent_cloudstudio.py", True,
         "[diag] SSO 未取到新 session（HTTP 200）——KEYCLOAK 长期票据可能已失效\n✅ 签到成功",
         "warn", "换票失败"),
        ("cloudstudio 一切正常 → 绿色",
         "tencent_cloudstudio.py", True, "🔑 SSO 主动续票成功\n✅ 签到成功", "ok", None),
        ("cloudstudio 签到失败 → 红色（压过黄色）",
         "tencent_cloudstudio.py", False,
         "[diag] SSO 未取到新 session\n签到失败：Cookie 已失效", "fail", None),
        ("2libra 换新失败但 token 仍可用 → 黄色",
         "2libra.py", True,
         "[keepalive] ⚠️ token 换新失败（HTTP 400）——当前 access_token 到期前仍可签到\n签到成功",
         "warn", "换新失败"),
        ("glados 无法续期且剩余 1 天 → 黄色提前提示",
         "glados.py", True, "🔑 Cookie 剩余 1 天\n签到成功", "warn", "仅剩 1 天"),
        ("glados 剩余 30 天 → 绿色",
         "glados.py", True, "🔑 Cookie 剩余 30 天\n签到成功", "ok", None),
        ("modelscope 魔粒过期不算凭据过期 → 绿色",
         "modelscope.py", True,
         "[1/1] j***r [Cookie] 签到成功，今日已领取 200 魔粒，2026-08-31 00:14:39 过期",
         "ok", None),
        ("smzdm 无感续期：剩余天数不提示 → 绿色",
         "smzdm.py", True, "🔑 Cookie 剩余 2 天\n签到成功", "ok", None),
    ]
    failed = 0
    for desc, sc, ok, out, want_level, want_frag in cases:
        got = classify(sc, ok, out)
        good = got["level"] == want_level and (
            want_frag is None or any(want_frag in w for w in got["warns"])
        )
        print(f"[{'PASS' if good else 'FAIL'}] {desc} → {got['level']} {got['warns']}")
        failed += 0 if good else 1
    raise SystemExit(1 if failed else 0)
