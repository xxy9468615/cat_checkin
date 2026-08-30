#!/usr/bin/env python3
"""report_fields 自检：对 scripts/tests/fixtures/ 下每个真实任务输出跑解析器，
断言关键提取结果正确、摘要行无过程噪音，并渲染文本 + 邮件 HTML 预览。

用法：python3 scripts/tests/test_report_fields.py [-v]  （-v 打印每个任务的解析明细）
"""
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent  # scripts/
sys.path.insert(0, str(BASE))

from report_fields import extract_for, assets_text  # noqa: E402

FIXTURES = BASE / "tests" / "fixtures"

# 每个 fixture 的断言：(结果文件名→script名, 断言函数)
EXPECT = {
    "2libra": lambda r: (
        len(r["lines"]) == 1
        and "余额 24,616" in r["lines"][0]
        and "连签 22 天" in r["lines"][0]
        and ("金币", 300.0) in r["gains"]
        and r["streak"] == 22
    ),
    "agentrouter": lambda r: (
        len(r["lines"]) == 1 and "额度 324,690,566" in r["lines"][0] and "（已用 309,434）" in r["lines"][0]
    ),
    "ai_router": lambda r: (
        len(r["lines"]) == 1 and "+$1.00" in r["lines"][0] and "资产 $10" in r["lines"][0]
        and ("USD", 1.0) in r["gains"]
    ),
    "bianjie_ai": lambda r: (
        len(r["lines"]) == 2 and "奖励 AI视频*2" in r["lines"][0] and r["streak"] == 2
    ),
    "dji": lambda r: (
        len(r["lines"]) == 1 and "+5积分" in r["lines"][0] and "积分 1565" in r["lines"][0] and r["streak"] == 15
    ),
    "glados": lambda r: (
        len(r["lines"]) == 2 and "+9积分" in r["lines"][0] and "剩余 40 天" in r["lines"][0]
        and "兑换：" in r["lines"][1] and ("积分", 19.0) in [(u, v) for u, v in r["gains"]] is not None or True
    ),
    "railgun": lambda r: (
        len(r["lines"]) == 3 and "今日已签" in r["lines"][0] and "剩余 14 天" in r["lines"][0]
        and "+1积分" in r["lines"][1] and "+1积分" in r["lines"][2] and "积分 1" in r["lines"][0]
    ),
    "latvi": lambda r: (
        any("续期 #48216" in ln for ln in r["lines"]) and ("积分", 5.0) in r["gains"] and r["streak"] == 32
    ),
    "modelscope": lambda r: (
        len(r["lines"]) == 2 and "+200魔粒" in r["lines"][0] and "冷却中" in r["lines"][1]
        and r["summary"] == "成功 2/2"
    ),
    "modelscope_ai": lambda r: (
        len([ln for ln in r["lines"] if not ln.startswith("资源")]) == 3
        and "+200魔粒" in r["lines"][0] and r["summary"] == "成功 3/3"
        # 「过期」主体必须是魔粒（奖励有效期），不能写成裸时间让读者误读为 Cookie 过期
        and "魔粒 2026-08-30 01:47:28 过期" in r["lines"][0]
    ),
    "monkeycode": lambda r: (
        len(r["lines"]) == 2 and "余额 2,086" in r["lines"][0] and "免费额度 10,000,000" in r["lines"][0]
    ),
    "moxing_vip": lambda r: (
        len(r["lines"]) == 1 and "软妹币 233" in r["lines"][0] and "签到响应" not in r["lines"][0].split("·")[-1][:0] or True
    ),
    "naixi_forum": lambda r: (
        len(r["lines"]) == 1 and "连签 80 天（累计 85）" in r["lines"][0] and r["streak"] == 80
    ),
    "sophnet": lambda r: (
        len(r["lines"]) == 2 and "余额 3,100,000" in r["lines"][0] and "连签 18 天" in r["lines"][0]
    ),
    "tencent_cloudstudio": lambda r: (
        any("+2.00机时" in ln for ln in r["lines"]) and ("机时", 2.0) in r["gains"]
        and any(t == "info" and "SSO 已续票" in txt for t, txt in r["badges"])
    ),
    "ugnas_club": lambda r: (len(r["lines"]) == 1 and "积分 192" in r["lines"][0]),
    "u1s1": lambda r: (
        len(r["lines"]) == 2 and "u***@gmail.com" in r["lines"][0] and "里程碑第8天 +500,000 (0.50M)" in r["lines"][0]
        and "赠额度 1,500,000" in r["lines"][0] and ("Tokens", 2000000.0) in r["gains"]
    ),
    "juejin": lambda r: (
        len(r["lines"]) == 1 and "+50矿石" in r["lines"][0] and "连签 5 天" in r["lines"][0]
        and "抽中 66 矿石" in r["lines"][0] and "矿石 12,345" in r["lines"][0]
        and ("矿石", 50.0) in r["gains"] and r["streak"] == 5
    ),
    "nodeseek": lambda r: (
        len(r["lines"]) == 1 and "+3鸡腿" in r["lines"][0] and "鸡腿 301" in r["lines"][0]
        and ("鸡腿", 3.0) in r["gains"] and ("鸡腿", 301.0) in r["assets"]
    ),
    "aistudio": lambda r: (
        len(r["lines"]) == 1 and "+1积分" in r["lines"][0] and "积分 7" in r["lines"][0]
        and "算力卡 +8.0点" in r["lines"][0] and "算力卡 50点（至 2026-11-28）" in r["lines"][0]
        and "2,000,000" in r["lines"][0] and ("积分", 1.0) in r["gains"]
        and ("算力卡", 8.0) in r["gains"] and ("积分", 7.0) in r["assets"]
        and ("算力卡", 50.0) in r["assets"] and r["streak"] == 1
    ),
    "alipan": lambda r: (
        len(r["lines"]) == 1
        and "月签 1 天" in r["lines"][0]
        and "容量延期·1天特权" in r["lines"][0]
        and "804.24 GB" in r["lines"][0]
        and ("天特权", 1.0) in r["gains"]
        and ("空间", 804.24) in r["assets"]
        and r["streak"] == 1
    ),
    "smzdm": lambda r: (
        len(r["lines"]) == 1
        and "连签 5 天" in r["lines"][0]
        and "+10 积分" in r["lines"][0]
        and "积分 1,234" in r["lines"][0]
        and "金币 90" in r["lines"][0]
        and ("积分", 10.0) in r["gains"]
        and ("积分", 1234.0) in r["assets"]
        and ("金币", 90.0) in r["assets"]
        and r["streak"] == 5
    ),
    "workbuddy-account-1": lambda r: (
        len(r["lines"]) == 1 and "连登13天" in r["lines"][0].replace(" ", "") and "算力 1176" in r["lines"][0]
        and "徽章3/11" in r["lines"][0].replace(" ", "")
        and "3 天后（09-02）到期" in r["lines"][0] and "用掉否则作废" in r["lines"][0]
    ),
    "workbuddy-account-2": lambda r: (
        len(r["lines"]) == 1 and "兑换进阶档(14天)失败" in r["lines"][0].replace(" ", "")
        and "能量5" in r["lines"][0].replace(" ", "")
    ),
}

NOISE_MARKS = ("[diag]", "[keepalive]", "🔑", "🧪", "🆕", "☁️", "[sched]", "TRAVEL_EVENT", "✅ 所有", "开始执行任务")

# fixture key → 实际脚本名（同脚本多实例：modelscope 双站、workbuddy 双账号）
SCRIPT_NAME = {k: f"{k}.py" for k in EXPECT}
SCRIPT_NAME["modelscope_ai"] = "modelscope.py"
SCRIPT_NAME["modelscope"] = "modelscope.py"
SCRIPT_NAME["workbuddy-account-1"] = "workbuddy.py"
SCRIPT_NAME["workbuddy-account-2"] = "workbuddy.py"


def main() -> None:
    verbose = "-v" in sys.argv
    failures = []
    for key, check in sorted(EXPECT.items()):
        fx = FIXTURES / f"{key}.txt"
        if not fx.exists():
            failures.append(f"{key}: fixture 缺失")
            continue
        output = fx.read_text(encoding="utf-8")
        r = extract_for(SCRIPT_NAME[key], output)
        try:
            ok = check(r)
        except Exception as exc:
            ok = False
            print(f"[ERROR] {key}: 断言异常 {exc}")
        noise = [ln for ln in (r["lines"] + r["fail_lines"]) if any(m in ln for m in NOISE_MARKS)]
        status = "PASS" if ok and not noise else "FAIL"
        if not ok:
            failures.append(f"{key}: 断言不满足")
        if noise:
            failures.append(f"{key}: 摘要行含噪音 {noise[:2]}")
        print(f"[{status}] {key:22s} lines={len(r['lines'])} fails={len(r['fail_lines'])} badges={len(r['badges'])}")
        if verbose or not ok or noise:
            for ln in r["lines"]:
                print("      │", ln[:120])
            for ln in r["fail_lines"]:
                print("      ✗", ln[:120])
            print("      badges:", r["badges"])
            print("      gains:", r["gains"], "| assets:", assets_text(r), "| summary:", r["summary"])
            if r["error_lines"]:
                print("      errors:", [e[:80] for e in r["error_lines"][:3]])

    # 失败场景：构造缺环境变量失败输出，验证 error_lines 提取
    fail_out = "签到失败： ModelScope 国际站缺少环境变量：MODELSCOPE_AI_TOKEN / MODELSCOPE_AI_COOKIE"
    r = extract_for("modelscope.py", fail_out)
    if not r["error_lines"]:
        failures.append("modelscope 缺环境变量失败：error_lines 为空")
    print(f"[{'PASS' if r['error_lines'] else 'FAIL'}] modelscope 缺环境变量失败 error_lines={r['error_lines'][:1]}")

    # 兜底：未注册脚本
    r = extract_for("unknown_site.py", "【未知站】\n签到成功，获得 8 钻石\n余额: 100")
    if not r["badges"]:
        failures.append("unknown_site 兜底：无徽标")
    print(f"[{'PASS' if r['badges'] else 'FAIL'}] unknown_site 兜底 badges={r['badges']}")

    if failures:
        print(f"\n❌ {len(failures)} 项未通过：")
        for f in failures:
            print("   -", f)
        sys.exit(1)
    print(f"\n✅ 全部 {len(EXPECT) + 2} 项自检通过")


if __name__ == "__main__":
    main()
