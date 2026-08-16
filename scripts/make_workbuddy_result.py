#!/usr/bin/env python3
"""从 workbuddy_output.txt 生成 .workbuddy_result.json，供 report.yml 收集。

在 workbuddy.yml 的 "Write workbuddy result JSON" 步骤中被调用。
"""
import json
import os
from pathlib import Path


def main() -> None:
    out_file = Path(os.getenv("WORKBUDDY_OUTPUT_FILE", "workbuddy_output.txt"))
    result_file = Path(os.getenv("WORKBUDDY_RESULT_FILE", ".workbuddy_result.json"))

    ok = False
    output = "无输出"
    if out_file.exists():
        text = out_file.read_text(encoding="utf-8", errors="replace").strip()
        output = text
        ok = "签到成功" in text

    import datetime as dt
    tz = dt.timezone(dt.timedelta(hours=8))
    bj_date = dt.datetime.now(tz).strftime("%Y-%m-%d")
    result = {
        "ok": ok,
        "script": "workbuddy.py",
        "output": output,
        "elapsed": 0.0,
        "date": bj_date,
    }
    result_file.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    print(f"workbuddy result: ok={ok}")


if __name__ == "__main__":
    main()
