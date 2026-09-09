#!/usr/bin/env python3
"""unified_report 回归测试（在仓库根目录运行：python3 scripts/tests/test_unified_report.py）。

历史事故：_emit_failed_sites 曾写成 sorted({...}) - set(unconf_sites)——
sorted() 返回 list，list - set 直接 TypeError，12:24 起所有带未配置站点的
报告步骤必崩（任务全绿 run 也被标红）。
"""
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import unified_report
from unified_report import _emit_failed_sites


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
