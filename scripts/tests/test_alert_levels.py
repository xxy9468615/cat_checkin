#!/usr/bin/env python3
"""alert_levels 自检：三级分级（🟢ok / 🟡warn / 🔴fail）判定用例 + 与
report_fields/daily_report 联动的端到端渲染检查。

用法：python3 scripts/tests/test_alert_levels.py
"""
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent  # scripts/
sys.path.insert(0, str(BASE))

from alert_levels import classify, detect_unconfigured, EXPIRY_WARN_DAYS  # noqa: E402

# 每条用例：(说明, script, ok, output, 期望 level, 期望 warns 命中片段或 None)
CASES = [
    # --- ⚪ unconfigured：凭据未配置（非故障），按跳过处理 ---
    ("smzdm 未配置 Secret → unconfigured", "smzdm.py", False,
     "【什么值得买 签到】\n签到失败： 缺少环境变量：SMZDM_cookie_1 或 SMZDM_cookie",
     "unconfigured", "SMZDM_cookie_1"),
    ("alipan 未配置 refresh_token → unconfigured", "alipan.py", False,
     "【阿里云盘 签到】\n签到失败： 未配置 ALIPAN_REFRESH_TOKEN_1 或 ALIPAN_TOKEN_1 环境变量",
     "unconfigured", "ALIPAN_REFRESH_TOKEN_1"),
    ("52pojie 未配置 Secret → unconfigured", "52pojie.py", False,
     "【吾爱破解 签到】\n签到失败： 未配置 52POJIE_COOKIE_1 或 52POJIE_COOKIE（请配置 Cookie 环境变量）",
     "unconfigured", "52POJIE_COOKIE_1"),
    ("modelscope 未配置 Cookie → unconfigured", "modelscope.py", False,
     "签到失败： ModelScope 国际站缺少环境变量：MODELSCOPE_AI_TOKEN / MODELSCOPE_AI_COOKIE",
     "unconfigured", "缺少环境变量"),
    ("orchestrator spawn 报 workbuddy 缺 Cookie → unconfigured", "workbuddy.py", False,
     "failed to spawn: workbuddy 账号 2 缺少 WORKBUDDY_COOKIE_2（secret 未配置或为空），"
     "拒绝继承其他账号的 cookie", "unconfigured", "WORKBUDDY_COOKIE_2"),
    ("2libra 未配置 cookie → unconfigured", "2libra.py", False,
     "签到失败： 未配置 2LIBRA_COOKIES 或 2LIBRA_cookie", "unconfigured", None),

    # --- 🔴 红色：真故障不得被误判为未配置（回归护栏） ---
    ("sophnet Token 已过期 ≠ 未配置（凭据死了是真故障）", "sophnet.py", False,
     "🚨 账号 #1 Token 已过期且未配置 refresh_token，无法自动续期！", "fail", None),
    ("u1s1 手机号 403（Cookie 已失效）≠ 未配置", "u1s1.py", False,
     "❌ 账号 eyJ***FFI 打卡失败: HTTP 403, msg: 请先绑定并验证手机号 (Session Cookie 已失效)",
     "fail", None),
    ("cloudstudio Cookie 死亡 ≠ 未配置", "tencent_cloudstudio.py", False,
     "签到失败：Cookie 已失效且自动续票失败。KEYCLOAK 长期票据已无法静默换票", "fail", None),
    ("非致命 state 告警行不触发 unconfigured 判定", "glados.py", False,
     "☁️ state 同步失败： 未配置 UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN\n"
     "签到失败：HTTP 500 服务端错误", "fail", None),
    ("失败压过续期失败信号", "tencent_cloudstudio.py", False,
     "[diag] SSO 未取到新 session（HTTP 200）\n签到失败：Cookie 已失效", "fail", None),
    ("普通失败", "juejin.py", False, "❌ 账号 #1 签到失败: HTTP 401", "fail", None),

    # --- 🟡 黄色：无感续期任务续期失败（本次签到仍成功） ---
    ("cloudstudio SSO 换票失败但旧票签成", "tencent_cloudstudio.py", True,
     "[diag] SSO 未取到新 session（HTTP 200，最终 URL: https://cloudstudio.net/...）"
     "——KEYCLOAK 长期票据可能已失效或被要求交互式重新登录\n✅ 签到成功",
     "warn", "换票失败"),
    ("cloudstudio AUTH_EXPIRED 回退后签成", "tencent_cloudstudio.py", True,
     "🔄 session 失效（AUTH_EXPIRED_401），回退使用环境变量中的 session...\n✅ 签到成功",
     "warn", "AUTH_EXPIRED"),
    ("2libra token 换新失败但旧 token 仍可签到", "2libra.py", True,
     "[keepalive] ⚠️ token 换新失败（HTTP 400）——当前 access_token 到期前仍可签到\n签到成功 +300金币",
     "warn", "refresh_token 换新失败"),
    ("sophnet refresh_token 续期异常但本次成功", "sophnet.py", True,
     "Refresh token 无效或已过期（回退旧 token 签到成功）", "warn", "refresh_token 续期失败"),
    ("latvi 服务器自动延长失败", "latvi.py", True,
     "🔄 服务器自动延长 (#1): HTTP 503 Service Unavailable\n✅ 签到成功 +5",
     "warn", "自动延长失败"),

    # --- 🟢 绿色：无感续期任务不报「剩余天数」也不报奖励有效期 ---
    ("cloudstudio 续票成功", "tencent_cloudstudio.py", True,
     "🔑 SSO 主动续票成功，使用新 session: abcd***\n✅ 签到成功", "ok", None),
    ("2libra 换新成功", "2libra.py", True,
     "[keepalive] ✅ token 已换新并持久化，新 access_token 到期 2026-10-28 BJT\n签到成功",
     "ok", None),
    ("latvi 延长成功（HTTP 200）", "latvi.py", True,
     "🔄 服务器自动延长 (#1): HTTP 200 OK\n✅ 签到成功", "ok", None),
    ("smzdm 滚动续期：剩余 2 天不提示（滚动窗口非死线）", "smzdm.py", True,
     "签到成功 +5积分 | 🔑 Cookie 剩余 2 天", "ok", None),
    ("modelscope 魔粒奖励有效期不误报为凭据过期", "modelscope.py", True,
     "[1/1] j***r [Cookie] 签到成功，今日已领取 200 魔粒，点赞已达上限 20/20 次，"
     "魔粒 2026-08-31 00:14:39 过期", "ok", None),

    # --- 🟡 黄色：无法续期任务提前 1 天提示 ---
    ("glados 剩余 1 天 → 提示", "glados.py", True,
     "📅 剩余天数: 1\n🔑 Cookie 剩余 1 天\n签到成功", "warn", "仅剩 1 天"),
    ("juejin 剩余 0 天 → 提示", "juejin.py", True,
     "🔑 Cookie 剩余 0 天\n签到成功", "warn", "仅剩 0 天"),
    ("railgun 剩余 2 天 → 不提示（阈值 1 天）", "railgun.py", True,
     f"🔑 Cookie 剩余 {EXPIRY_WARN_DAYS + 1} 天\n签到成功", "ok", None),

    # --- 边界 ---
    ("未知脚本默认绿色", "new_site.py", True, "签到成功", "ok", None),
    ("空输出", "glados.py", True, "", "ok", None),
    ("warns 去重：同文案只留一条", "2libra.py", True,
     "[keepalive] ⚠️ token 换新失败（HTTP 400）\n[keepalive] ⚠️ token 换新失败（HTTP 400）",
     "warn", None),
]


def main() -> None:
    failures = []
    for desc, script, ok, output, want_level, want_frag in CASES:
        got = classify(script, ok, output)
        good = got["level"] == want_level and (
            want_frag is None or any(want_frag in w for w in got["warns"])
        )
        if not good:
            failures.append(f"{desc}: 期望 {want_level}/{want_frag}，实际 {got['level']}/{got['warns']}")
        print(f"[{'PASS' if good else 'FAIL'}] {desc} → {got['level']} ({len(got['warns'])} 提示)")

    # 去重上限：warns 去重后应只有 1 条
    got = classify("2libra.py", True,
                   "[keepalive] ⚠️ token 换新失败（HTTP 400）\n[keepalive] ⚠️ token 换新失败（HTTP 400）")
    if len(got["warns"]) != 1:
        failures.append(f"去重失效：期望 1 条，实际 {len(got['warns'])}")

    # 端到端：与 report_fields 联动 —— fixture 真实输出 + 模拟续期失败行
    try:
        from report_fields import extract_for
        fixture = (BASE / "tests" / "fixtures" / "modelscope_ai.txt").read_text(encoding="utf-8")
        info = extract_for("modelscope.py", fixture)
        cls = classify("modelscope.py", True, fixture)
        ok = (
            cls["level"] == "ok"
            and info["lines"]
            and "魔粒 2026-08-30 01:47:28 过期" in info["lines"][0]
        )
        if not ok:
            failures.append(f"modelscope 端到端：cls={cls}，line0={info['lines'][0] if info['lines'] else '空'}")
        print(f"[{'PASS' if ok else 'FAIL'}] 端到端 modelscope：绿色 + 魔粒过期展示正确")
    except Exception as exc:
        failures.append(f"端到端联动异常: {exc}")

    # 端到端：daily_report.build_report 头部与行级黄色标注 + ⚪ 未配置不计失败
    try:
        from daily_report import build_report
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as fh:
            fh.write("# glados stub")
            stub = Path(fh.name)
        warn_out = "🔑 Cookie 剩余 1 天\n签到成功"
        ok_out = "签到成功 +5"
        unconf_out = "签到失败： 缺少环境变量：SMZDM_cookie_1 或 SMZDM_cookie"
        fail_out = "签到失败：HTTP 500 服务端错误"
        rows = [
            (True, stub, warn_out, 1.0, "GLaDOS 签到"),
            (True, stub, ok_out, 1.0, "GLaDOS 签到2"),
            (False, stub, unconf_out, 0.1, "SMZDM 签到"),
            (False, stub, fail_out, 1.0, "坏站点"),
        ]
        header, text, fail_n = build_report(rows)
        stub.unlink()
        good = (
            fail_n == 1  # 只有真故障计入失败
            and "[🟡 1项注意]" in header
            and "[⚪ 1项未配置]" in header
            and "🟡 GLaDOS 签到" in text
            and "⚠️ Cookie 仅剩 1 天" in text
            and "✅ GLaDOS 签到2" in text
            and "⚪ SMZDM 签到 (未配置凭据，跳过)" in text
            and "❌ 坏站点" in text
        )
        if not good:
            failures.append(f"build_report 端到端：header={header!r} fail_n={fail_n}")
        print(f"[{'PASS' if good else 'FAIL'}] 端到端 build_report：🟡/⚠️ + ⚪ 不计失败 + ❌ 真故障")
    except Exception as exc:
        failures.append(f"build_report 端到端异常: {exc}")

    # orchestrator 多轮结果合并：True > False > "unconfigured"
    try:
        from daily_orchestrator import _merge_result
        merge_cases = [
            (None, False, True, "unconfigured"),   # 首轮未配置
            (None, False, False, False),           # 首轮真失败
            (None, True, False, True),             # 首轮成功
            ("unconfigured", True, False, True),   # 先未配置后成功 → 成功
            ("unconfigured", False, False, False), # 先未配置后真失败 → 失败
            (True, False, True, True),             # 成功过一次，后续未配置 → 成功
            (False, False, True, False),           # 失败过一次，后续未配置 → 失败
        ]
        good = True
        for prev, ok, unconf, want in merge_cases:
            got = _merge_result(prev, ok, unconf)
            if got != want:
                good = False
                failures.append(f"_merge_result({prev!r}, {ok}, {unconf}) = {got!r}，期望 {want!r}")
        print(f"[{'PASS' if good else 'FAIL'}] orchestrator _merge_result 三态合并（7 用例）")
    except Exception as exc:
        failures.append(f"_merge_result 测试异常: {exc}")

    print(f"\n{'❌ ' + str(len(failures)) + ' 项失败' if failures else '✅ 全部通过'}")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
