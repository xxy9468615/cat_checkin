# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

cat_checkin is a lightweight automated sign-in system. It runs sign-in scripts for various websites on a daily GitHub Actions schedule and sends a Telegram summary report. No server required.

## Project Layout

```
.
├── .github/workflows/
│   ├── checkin.yml          → Main daily sign-in workflow (all sites except latvi)
│   └── latvi.yml            → Latvi independent workflow (24h cooldown tracking)
├── scripts/
│   ├── common.py            → Shared stdlib HTTP client + helpers
│   ├── daily_report.py      → Discovers & runs all sign-in scripts sequentially
│   ├── glados.py, 2libra.py, ... → Per-site sign-in modules
├── .env.example             → Environment variable template (local reference only)
├── requirements.txt         → Python dependencies
└── README.md
```

**No persistent storage** — Telegram notification is the only "log". No SQLite, no R2 backup.

## Syntax Check (No Test Suite)

```bash
python3 -m py_compile scripts/*.py
```

## Architecture

```
GitHub Actions (cron)    →  python3 scripts/daily_report.py
                              ├─ discovers & runs scripts/*.py sequentially
                              ├─ parses `# new Env("...")` metadata for Telegram report
                              └─ builds report, pushes to Telegram

Latvi (independent)      →  python3 scripts/latvi.py
                              ├─ reads last sign time from .latvi_state.json (cache)
                              ├─ waits until last + 24h + random 0-10min offset
                              ├─ attempts sign-in, retries on cooldown
                              └─ writes new timestamp on success
```

**Execution model**: Each sign-in script runs as an independent subprocess. Scripts are isolated — one crash doesn't affect others.

**Task discovery** (`daily_report.py → discover_tasks()`): Globs `scripts/*.py`, excludes names starting with `_`, plus the hardcoded set `{common.py, daily_report.py}`. Override with `DAILY_TASKS` (comma-separated whitelist) or `DAILY_EXCLUDE` env vars. `DAILY_TIMEOUT` (default 180s) bounds each task execution, `DAILY_MAX_TASK_OUTPUT` (default 1500) caps per-task report size.

**Report formatting** (`daily_report.py`): The Telegram sender chunks by task-title lines (regex `^[✅❌]\s*【`) rather than blank lines — script output (e.g. Sophnet multi-account) often contains blank lines internally. Keep the first output line as `【站点名称 签到】` so tasks stay intact across chunks.

**No persistent storage** — Telegram notification is the only "log". No SQLite, no R2 backup.

## Daily Report Script

`scripts/daily_report.py` — the main entry point. Runs all sign-in scripts sequentially, parses `# new Env("...")` metadata for report headers, collects stdout, builds a combined report, and pushes to Telegram via `TG_BOT_TOKEN` / `TG_CHAT_ID`.

## Adding a New Sign-in Script

Place in `scripts/`, follow this structure:

```python
#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("站点名称 签到")
import os
from common import Http, env, main_guard

PREFIX = "SITENAME_"

def main():
    print("【站点名称 签到】")
    cookie = env(PREFIX, "cookie")
    h = Http()
    # ... sign-in logic, print results ...

main_guard(main)
```

**Conventions**:
- Always use `from common import Http, env, main_guard` and wrap entry point with `main_guard(main)`
- Environment variable prefixes omit `QL_`. `env()` in `common.py` automatically checks both `<PREFIX><NAME>` and `QL_<PREFIX><NAME>` for backwards compatibility
- Multi-account: `&&` or newline separators
- Print `【站点名称 签到】` as the first line for consistent report formatting
- **Verify success, don't fake it**: check HTTP status codes and parse the response body for actual success signals. Never report success based on a 200 alone — the page may return a login redirect (302) or an error body (e.g. `{"code":400}`) that the script would otherwise swallow.
- **Multi-account isolation**: one account's failure should not stop the others — wrap per-account work in try/except, collect failures, and `sys.exit(1)` at the end if any failed. (See `sophnet.py`, `bianjie_ai.py`.)

## `scripts/common.py` API

Pure-stdlib HTTP client. Key exports:

| Function | Usage |
|----------|-------|
| `Http(follow_redirects=False)` | Cookie-jar HTTP client. Sanitizes non-latin-1 header chars |
| `h.request(method, url, *, headers=None, form=None, json_data=None, data=None, timeout=60)` | Returns `Response`. `form={}` = urlencoded, `json_data={}` = JSON. Network errors surface as a synthetic `Response` with `code=-1`, not an exception |
| `Response.text` | Auto-decodes gzip/deflate, tries utf-8 → gb18030 → latin-1 |
| `Response.json(default)` | Safe JSON parse |
| `env(prefix, name)` | Multi-key lookup, raises `SystemExit` if missing |
| `find(pattern, text, default)` | Regex search → group(1) or default |
| `must_match(pattern, text, label)` | Like `find` but raises `RuntimeError` on miss |
| `findall(pattern, text)` | Regex findall → group(1) list |
| `strip_tags(s)` | Strip HTML tags and unescape entities |
| `ensure(ok, msg)` | Assert helper, raises `RuntimeError` on false |
| `bj_time_from_iso_z(value)` | Parse ISO 8601 Z-time → (date, time) in Beijing tz |
| `main_guard(fn)` | Wraps main(), catches exceptions, prints error, exits 1 |
| `retry(times=2, backoff=3.0)` | Decorator for transient network retries |

## GitHub Actions Workflows

### Main Workflow (`.github/workflows/checkin.yml`)

- **Trigger**: UTC 02:25 (Beijing 10:25) daily + manual
- **Excludes**: `birdiesearch.py` (site down), `latvi.py` (has own workflow)
- **Secrets**: All site credentials via Repository Secrets (uppercase names)
- **Note**: `2LIBRA_COOKIES` maps to secret `TWO_LIBRA_COOKIES` (can't start with digit)

### Latvi Workflow (`.github/workflows/latvi.yml`)

- **Trigger**: Same time as main, but independent
- **Why separate**: Latvi uses 24h cooldown (not daily reset). Script waits internally.
- **State persistence**: `.latvi_state.json` via `actions/cache` (fixed key, overwritten each run)
- **Timeout**: 120 minutes (may wait hours for cooldown)
- **State file content**: `{"last_sign_ts": 1722933046.0}` — Unix timestamp of last successful sign

## Environment Variables

All config via env vars. `.env` is manually parsed (no python-dotenv). 

**Parser quirk**: The manual parser does **not** strip inline comments — `KEY=value # comment` yields `value # comment`. Don't put trailing `#` comments on secret lines.

Site credentials follow the pattern `<SITE>_cookie` / `<SITE>_username` / `<SITE>_password` / `<SITE>_token`. Multi-account: `&&` or newline separators.

## Sign-in Script Notes

**GLaDOS** (`glados.py`): Uses `GLADOS_COOKIES` (`&&` separated). Parses with `re.split(r"\n|&&|(?<!;)&", raw)` — the lookbehind prevents splitting on `;` within cookie attributes. If cookie count is wrong, check `&&` delimiters.

**Latvi** (`latvi.py`): **24-hour cooldown system**, not daily reset. Workflow triggers at 10:25 Beijing time, but the script internally:
1. Reads last successful sign time from state
2. Calculates target = last + 24h + random 0-10min offset
3. Sleeps until target time
4. Attempts sign-in; if cooldown message returned, parses wait time and retries
5. On success, writes new timestamp

This means the actual sign-in happens ~24h after the previous success, regardless of when GitHub Actions triggers.
