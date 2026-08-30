#!/usr/bin/env python3
"""daily_orchestrator 回归测试（在仓库根目录运行：python3 scripts/tests/test_daily_orchestrator.py）。

历史事故：显式任务模式（手动 dispatch/自动重跑）hard_deadline=+24h，
猫咪放风回程若在数小时后，orchestrator 会原地 sleep 干等（曾 4h），
把同一并发组的后续 run 全部堵在队列里。
修复：显式模式下回访等待 > EXPLICIT_CLAIM_MAX_WAIT_SEC 时顺延到下一次 run。
"""
import io
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from daily_orchestrator import EXPLICIT_CLAIM_MAX_WAIT_SEC, Orchestrator

CFG = {"id": "workbuddy-account-1", "name": "WorkBuddy 账号1", "script": "workbuddy.py"}


def _travel_event(delay_sec: float) -> str:
    return f"TRAVEL_EVENT state=traveling arrive_at={int(time.time() + delay_sec)}"


def _run(claim_max_wait, out):
    # 显式模式真实场景：hard_deadline = now + 24h（cutoff 极远，旧逻辑拦不住远回程）
    orch = Orchestrator(hard_deadline=time.time() + 86400, claim_max_wait=claim_max_wait)
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            orch._on_task_done(CFG, True, out)
        return orch, buf.getvalue()
    finally:
        orch.executor.shutdown(wait=False, cancel_futures=True)


def main() -> int:
    failures = []

    def check(name, cond, detail=""):
        print(f"  {'✅' if cond else '❌'} {name}" + ("" if cond else f" — {detail}"))
        if not cond:
            failures.append(name)

    # 1) 显式模式 + 回程 2h 后：超出 30min 上限 → 顺延，不排回访
    orch, out = _run(EXPLICIT_CLAIM_MAX_WAIT_SEC, _travel_event(2 * 3600))
    check("显式模式远回程→顺延", len(orch.heap) == 0, f"heap={orch.heap}")
    check("顺延日志", "wait cap" in out, out[-200:])

    # 2) 显式模式 + 回程 10min 后：在窗口内 → 照常排回访
    orch, out = _run(EXPLICIT_CLAIM_MAX_WAIT_SEC, _travel_event(10 * 60))
    check("显式模式近回程→照常排队", len(orch.heap) == 1, f"heap={orch.heap}")
    check("排队日志", "enqueued claim round 1" in out, out[-200:])

    # 3) 默认模式（claim_max_wait=None，每日 scheduled）+ 远回程：保持原行为排队
    orch, out = _run(None, _travel_event(2 * 3600))
    check("默认模式不受影响", len(orch.heap) == 1, f"heap={orch.heap}")

    # 4) 回程已过（claim_fire 在过去）：显式模式立即排回访，不受上限影响
    orch, out = _run(EXPLICIT_CLAIM_MAX_WAIT_SEC, _travel_event(-60))
    check("回程已过→立即回访", len(orch.heap) == 1, f"heap={orch.heap}")

    print(f"\n{'ALL GREEN' if not failures else 'FAILED'}: {4 - len(failures)}/4 passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
