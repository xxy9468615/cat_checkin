#!/usr/bin/env python3
# new Env("Daily Unified Orchestrator")
"""Single-run inline daily check-in orchestrator."""
from __future__ import annotations
import argparse, heapq, json, os, re, signal, subprocess, sys, time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait as wait_futures
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from common import upstash_redis_command
from task_registry import TASKS, resolve_execution_queue
BJT = timezone(timedelta(hours=8))
TRAVEL_EVENT_RE = re.compile(r"TRAVEL_EVENT\s+state=(\w+)\s+arrive_at=(\d+)")
MAX_CLAIM_ROUNDS, CLAIM_MARGIN_SEC, LATVI_ENTER_EARLY_SEC = 3, 15*60, 120
def bjt_now() -> datetime:
    return datetime.now(BJT)
def _hm_today_ts(hm: str) -> float:
    h, m = (int(x) for x in hm.split(":"))
    d = bjt_now().replace(hour=h, minute=m, second=0, microsecond=0)
    return d.timestamp()
def _fmt_bjt(ts: float) -> str:
    return datetime.fromtimestamp(ts, BJT).strftime("%H:%M:%S")
def _read_latvi_last_sign() -> Optional[float]:
    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    try:
        ok, res = upstash_redis_command(["GET", f"{prefix}:state:latvi"])
        if ok and isinstance(res, dict):
            raw = res.get("result")
            if raw:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict) and data.get("last_sign_ts"):
                    return float(data["last_sign_ts"])
    except Exception as e:
        print(f"WARN: read Latvi Redis state failed: {e}", file=sys.stderr)
    state_file = Path(os.getenv("LATVI_STATE_FILE", str(ROOT_DIR / ".latvi_state.json")))
    if not state_file.is_absolute():
        state_file = ROOT_DIR / state_file
    if state_file.exists():
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            if data.get("last_sign_ts"):
                return float(data["last_sign_ts"])
        except Exception:
            pass
    return None
def latvi_plan() -> Dict[str, Any]:
    fit_deadline = _hm_today_ts(os.getenv("LATVI_FIT_DEADLINE", "19:30"))
    last = _read_latvi_last_sign()
    if last is None:
        return {"mode": "immediate", "window_open": None, "fire_at": time.time() + 5}
    window_open = last + 86400
    if window_open > fit_deadline:
        return {"mode": "skip", "window_open": window_open, "fire_at": None}
    fire_at = max(time.time() + 30, window_open - LATVI_ENTER_EARLY_SEC)
    return {"mode": "scheduled", "window_open": window_open, "fire_at": fire_at}
def build_task_env(cfg: Dict[str, Any]) -> Dict[str, str]:
    env = os.environ.copy()
    env.setdefault("TZ", "Asia/Shanghai")
    env.setdefault("TASK_OUTPUT_DIR", ".task_results")
    env["TASK_TIMEOUT"] = str(cfg["timeout"])
    if cfg.get("account"):
        n = cfg["account"]
        if n != "1":
            cookie = os.getenv(f"WORKBUDDY_COOKIE_{n}", "")
            if cookie:
                env["WORKBUDDY_COOKIE"] = cookie
        env["WORKBUDDY_WAIT_TRAVEL"] = "true"
        env["WORKBUDDY_NO_RELAY"] = "1"
        env["TASK_RESULT_NAME"] = cfg["result"]
    if cfg["id"] == "latvi":
        env["LATVI_NO_RELAY"] = "1"
        env.setdefault("LATVI_STATE_FILE", ".latvi_state.json")
    return env
def run_task_subprocess(cfg: Dict[str, Any]) -> Tuple[bool, str]:
    env = build_task_env(cfg)
    cmd = [sys.executable, str(BASE_DIR / "run_task.py"), cfg["script"]]
    cap = cfg["timeout"] + 120
    try:
        proc = subprocess.Popen(cmd, cwd=str(ROOT_DIR), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    except Exception as exc:
        return False, f"failed to spawn: {exc}"
    try:
        out, _ = proc.communicate(timeout=cap)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            out, _ = proc.communicate(timeout=10)
        except Exception:
            out = ""
        out = f"[orchestrator kill >{cap}s]\n{(out or '')}"
    return proc.returncode == 0, (out or "").strip()
class Orchestrator:
    def __init__(self, hard_deadline: float) -> None:
        self.hard_deadline = hard_deadline
        self.heap: List[Tuple[float, int, str, Optional[Dict[str, Any]]]] = []
        self.seq = 0
        self.results: Dict[str, bool] = {}
        self.claim_rounds: Dict[str, int] = {}
        self.executor = ThreadPoolExecutor(max_workers=int(os.getenv("BATCH_PARALLEL", "4")))
        self.futures: Dict[Future, Tuple[str, Optional[Dict[str, Any]]]] = {}
        self.latvi_fire_at: Optional[float] = None
    def push(self, fire_at: float, kind: str, cfg: Optional[Dict[str, Any]] = None) -> None:
        heapq.heappush(self.heap, (fire_at, self.seq, kind, cfg))
        self.seq += 1
    def _label(self, kind: str, cfg: Optional[Dict[str, Any]]) -> str:
        return cfg["id"] if cfg else kind
    def _submit(self, kind: str, cfg: Optional[Dict[str, Any]]) -> None:
        fut = self.executor.submit(run_task_subprocess, cfg or {})
        self.futures[fut] = (kind, cfg)
    def _claim_cutoff(self) -> float:
        anchor = self.latvi_fire_at if self.latvi_fire_at else self.hard_deadline - 300
        margin = CLAIM_MARGIN_SEC if self.latvi_fire_at else 20*60
        return anchor - margin
    def _on_task_done(self, cfg: Dict[str, Any], ok: bool, out: str) -> None:
        tid = cfg["id"]
        prev = self.results.get(tid)
        self.results[tid] = ok if prev is None else (prev and ok)
        tag = "OK" if ok else "FAIL"
        print(f"\n{'='*60}\n[{tag}] [{tid}] done (ok={ok})\n{'-'*60}")
        if out:
            print(out)
        print(f"{'='*60}")
        matches = TRAVEL_EVENT_RE.findall(out or "")
        if matches:
            state, arrive_raw = matches[-1]
            arrive_at = int(arrive_raw)
            rounds = self.claim_rounds.get(tid, 0)
            cutoff = self._claim_cutoff()
            claim_fire = arrive_at + 60
            if state == "traveling" and rounds < MAX_CLAIM_ROUNDS:
                if claim_fire <= cutoff:
                    self.push(claim_fire, "task", cfg)
                    self.claim_rounds[tid] = rounds + 1
                    print(f"  -> enqueued claim round {rounds+1} @ {_fmt_bjt(claim_fire)} (cutoff {_fmt_bjt(cutoff)})")
                else:
                    print(f"  -> claim @ {_fmt_bjt(claim_fire)} past cutoff {_fmt_bjt(cutoff)}, deferred to next run")
    def run(self) -> int:
        while self.heap or self.futures:
            now = time.time()
            while self.heap and self.heap[0][0] <= now:
                fire, _, kind, cfg = heapq.heappop(self.heap)
                if fire > self.hard_deadline:
                    print(f"dropping event [{self._label(kind, cfg)}] past hard wall")
                    continue
                self._submit(kind, cfg)
            if not self.heap and not self.futures:
                break
            timeout: Optional[float] = None
            if self.heap and self.heap[0][0] <= self.hard_deadline:
                timeout = max(0.0, self.heap[0][0] - time.time())
            done, _ = wait_futures(list(self.futures), timeout=timeout, return_when=FIRST_COMPLETED)
            for fut in done:
                kind, cfg = self.futures.pop(fut)
                try:
                    ok, out = fut.result()
                except Exception as exc:
                    ok, out = False, f"orchestrator error: {exc}"
                if cfg:
                    self._on_task_done(cfg, ok, out)
        print(f"\n{'#'*60}\nOrchestrator done: {len(self.results)} task instances")
        failed = [k for k, v in self.results.items() if not v]
        for tid, ok in self.results.items():
            print(f"  {'OK' if ok else 'FAIL'} {tid}")
        if failed:
            print(f"failed: {', '.join(failed)}")
            return 1
        return 0
def build_default_timeline(orch: Orchestrator) -> None:
    now = time.time()
    stage_a = [t for t in TASKS.values() if "matrix" in t["tags"] or "workbuddy" in t["tags"]]
    for cfg in stage_a:
        orch.push(now, "task", cfg)
    ms_cfg = TASKS["modelscope"]
    ms_fire = max(now, _hm_today_ts("09:10"))
    orch.push(ms_fire, "task", ms_cfg)
    plan = latvi_plan()
    latvi_cfg = TASKS["latvi"]
    if plan["mode"] == "skip":
        print(f"Latvi window {_fmt_bjt(plan['window_open'])} past fit deadline {os.getenv('LATVI_FIT_DEADLINE','19:30')}, skipping today; next run will re-anchor")
    else:
        orch.latvi_fire_at = plan["fire_at"]
        orch.push(plan["fire_at"], "task", latvi_cfg)
    print("Timeline:")
    print(f"  immediate ({len(stage_a)} tasks, concurrency {os.getenv('BATCH_PARALLEL','4')}): " + ", ".join(t["id"] for t in stage_a))
    print(f"  modelscope @ {_fmt_bjt(ms_fire)} (gate 09:10)")
    if plan["mode"] == "skip":
        print(f"  latvi: skipped (window {_fmt_bjt(plan['window_open'])} past deadline)")
    else:
        wo = plan.get("window_open")
        basis = f"last {datetime.fromtimestamp(wo - 86400, BJT).strftime('%m-%d %H:%M:%S')} +24h" if wo else "no history"
        print(f"  latvi @ {_fmt_bjt(plan['fire_at'])} (basis: {basis}{', window '+_fmt_bjt(wo) if wo else ''})")
        if wo:
            print(f"  next window estimate: {datetime.fromtimestamp(wo + 86400, BJT).strftime('%m-%d %H:%M:%S')}")
def build_explicit_timeline(orch: Orchestrator, raw: str) -> None:
    queue = resolve_execution_queue(input_tasks=raw)
    now = time.time()
    ids = []
    for cfg in queue:
        orch.push(now, "task", cfg)
        if cfg["id"] == "latvi":
            orch.latvi_fire_at = now
        ids.append(cfg["id"])
    print(f"Explicit tasks: {', '.join(ids)}")
def main() -> None:
    parser = argparse.ArgumentParser(description="Daily Unified Orchestrator")
    parser.add_argument("--tasks", type=str, default="", help="comma-separated task list (explicit mode)")
    args = parser.parse_args()
    print(f"Daily orchestrator start @ {bjt_now().strftime('%Y-%m-%d %H:%M:%S')} BJT")
    hard_deadline = _hm_today_ts(os.getenv("ORCH_HARD_DEADLINE", "19:55"))
    orch = Orchestrator(hard_deadline)
    if args.tasks.strip():
        build_explicit_timeline(orch, args.tasks)
    else:
        build_default_timeline(orch)
    print(f"Hard wall: {os.getenv('ORCH_HARD_DEADLINE','19:55')} BJT\n")
    sys.exit(orch.run())
if __name__ == "__main__":
    main()
