#!/usr/bin/env python3
"""unified_report 回归测试（在仓库根目录运行：python3 scripts/tests/test_unified_report.py）。

历史事故：_emit_failed_sites 曾写成 sorted({...}) - set(unconf_sites)——
sorted() 返回 list，list - set 直接 TypeError，12:24 起所有带未配置站点的
报告步骤必崩（任务全绿 run 也被标红）。
"""
import datetime as dt
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import unified_report
from unified_report import _daily_report_window_blocks, _emit_failed_sites

BJT = dt.timezone(dt.timedelta(hours=8))


def _site(script: str, ok: bool, output: str = "", pending: bool = False) -> dict:
    return {
        "script": script,
        "ok": ok,
        "output": output,
        "is_pending": pending,
        "status": "pending" if pending else ("success" if ok else "failure"),
    }


def _run(collected):
    buf = io.StringIO()
    with redirect_stdout(buf):
        with mock.patch.dict("os.environ", {"GITHUB_OUTPUT": ""}):
            failed_matrix = _emit_failed_sites(collected)
    return failed_matrix, buf.getvalue()


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


@case
def test_no_typeerror_with_unconf_and_fail():
    """回归主案：未配置 + 真实失败混合时不再 TypeError，且未配置不计入失败。"""
    collected = {
        "workbuddy-account-2": _site(
            "workbuddy.py", False, "签到失败：缺少 WORKBUDDY_REFRESH_TOKEN_2（secret 未配置或为空）"
        ),
        "smzdm": _site("smzdm.py", False, "签到失败：Cookie 已失效"),
        "alipan": _site("alipan.py", True, "✅ ok"),
    }
    matrix, out = _run(collected)
    assert "workbuddy.py" not in out.split("真实失败站点")[-1].splitlines()[0], out
    assert "smzdm.py" in out, out
    assert "smzdm.py" in matrix


@case
def test_pending_and_unconf_never_trigger_rerun():
    collected = {
        "a": _site("nodeseek.py", False, "签到失败：缺少 NODESEEK_COOKIE_1（secret 未配置或为空）"),
        "b": _site("smzdm.py", True, "", pending=True),
    }
    matrix, out = _run(collected)
    assert matrix == [], (matrix, out)
    assert "无真实失败站点" in out, out


@case
def test_all_fail_no_unconf():
    collected = {
        "x": _site("smzdm.py", False, "签到失败：HTTP 403"),
        "y": _site("alipan.py", False, "签到失败：HTTP 403"),
    }
    matrix, out = _run(collected)
    assert set(matrix) == {"smzdm.py", "alipan.py"}, (matrix, out)


@case
def test_empty_collected():
    matrix, out = _run({})
    assert matrix == [] and "无真实失败站点" in out, (matrix, out)


# ── 日报发信时间窗守卫（凌晨误发回归）─────────────────────────────
# 历史事故：GitHub schedule 严重不准时——本应 20:00 BJT 送达的 "0 12 * * *"
# 日报 cron 屡次延迟约 5~6.7 小时，直到次日 00:59 / 01:16 / 02:44 BJT 才落地
# （实测 run 34873705030 于 2026-09-14T17:16:04Z 启动 = 晚 5h16m）。运行时才
# 计算 TODAY，于是发出「成功 4、待执行 25」的空日报并写下新一天的 sent marker，
# 把当天真正的 20:00 主发幂等秒退——用户每天凌晨收报。
# 严格窗口（DAILY_REPORT_ALLOW_LATE=False）：仅 19:00~23:59 BJT 放行，
# 凌晨 00:00~05:59 与被拦的 06:00~18:59 一并禁止——凌晨发信正是故障现象本身。


def _at(hh: int, mm: int) -> dt.datetime:
    return dt.datetime(2026, 9, 15, hh, mm, tzinfo=BJT)


@case
def test_fallback_blocked_outside_window():
    """19:00 前一律禁止 fallback 发信，含实测事故时刻 01:16 与晨间批次 07:00。"""
    for hh, mm in [(0, 5), (0, 59), (1, 3), (1, 16), (5, 59),
                   (6, 0), (7, 0), (9, 30), (12, 34), (18, 0), (18, 59)]:
        assert _daily_report_window_blocks(_at(hh, mm), True), f"{hh:02d}:{mm:02d} 应被拦截"


@case
def test_fallback_allowed_in_report_window():
    """19:00~23:59 BJT 放行：覆盖 20:00 主发与 21:30 补发。"""
    for hh, mm in [(19, 0), (20, 0), (21, 30), (22, 0), (23, 59)]:
        assert not _daily_report_window_blocks(_at(hh, mm), True), f"{hh:02d}:{mm:02d} 应被放行"


@case
def test_non_fallback_never_time_blocked():
    """重跑补充邮件等非 fallback 通道不受时间窗约束。"""
    for hh in range(0, 24):
        assert not _daily_report_window_blocks(_at(hh, 0), False), f"{hh:02d}:00 非 fallback 不应被拦截"


def main() -> int:
    failed = []
    for fn in CASES:
        try:
            fn()
            print(f"  ✅ {fn.__name__}")
        except AssertionError as exc:
            failed.append(fn.__name__)
            print(f"  ❌ {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed.append(fn.__name__)
            print(f"  💥 {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{'ALL GREEN' if not failed else 'FAILED'}: {len(CASES) - len(failed)}/{len(CASES)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
