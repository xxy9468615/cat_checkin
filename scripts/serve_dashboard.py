#!/usr/bin/env python3
"""将 SQLite 结果渲染为签到看板 HTML，并打开浏览器查看。

用法：
  python3 scripts/serve_dashboard.py           # 生成并打开 HTML
  python3 scripts/serve_dashboard.py --port 8080  # 自定义端口（服务器模式）

输出文件：.claude/dashboard.html（直接用于浏览器打开）。
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / ".task_results_stats.db"
HTML_OUT = ROOT / ".claude" / "dashboard.html"


def fetch_records() -> list[tuple]:
    """从 SQLite 中读取最近 30 条记录。"""
    try:
        conn = sqlite3.connect(str(DB))
        cur = conn.cursor()
        cur.execute(
            "SELECT script_name, date, ok, elapsed, output_text FROM daily_results ORDER BY date DESC LIMIT 30"
        )
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception as e:
        print(f"⚠️ 读取 SQLite 失败: {e}", file=sys.stderr)
        return []


def build_html(records: list[tuple], db_path: Path) -> str:
    """把记组合成完整的 HTML 文档（纯字符串拼接，避免 f-string 与 {} 冲突）。"""
    total = len(records)
    ok = sum(1 for r in records if r[2])
    dates = sorted(set(r[1] for r in records if r[1]))

    # ── card 标题与计数（避免在 f-string 里用 { }）—— 这里用字符串拼接
    # 统计每个脚本的成功率
    groups: dict[str, dict] = {}
    for r in records:
        name = r[0] or "unknown"
        if name not in groups:
            groups[name] = {"ok": 0, "total": 0, "dates": [], "history": []}
        g = groups[name]
        g["total"] += 1
        g["ok"] += 1 if r[2] else 0
        if r[1]:
            g["dates"].append(r[1])
        g["history"].append({"date": r[1], "status": "ok" if r[2] else "fail", "elapsed": r[3] or 0})

    # 渲染站点卡片
    card_lines: list[str] = []
    for name, g in groups.items():
        rate = round(g["ok"] / g["total"] * 1000) / 10 if g["total"] else 0
        color = "var(--ok)" if rate >= 90 else "var(--warn)" if rate >= 60 else "var(--fail)"
        card_lines.append(
            f'  <div class="card"><div class="k">{name}</div>'
            f'<div class="v" style="color:{color}">{rate}%</div>'
            f'<div class="hint">{g["ok"]}/{g["total"]} 成功</div></div>'
        )
    card_html = "".join(card_lines) or "  <div class='empty'>暂无数据</div>"

    # 每日成功率条形
    daily: dict[str, dict] = {}
    for r in records:
        d = r[1]
        if not d:
            continue
        if d not in daily:
            daily[d] = {"ok": 0, "total": 0, "sites": []}
        g = daily[d]
        g["ok"] += 1 if r[2] else 0
        g["total"] += 1
    # 按日期排序
    day_items: list[str] = []
    for d in sorted(daily.keys()):
        dg = daily[d]
        h = max(6, round(dg["ok"] / dg["total"] * 56)) if dg["total"] else 6
        cls = "ok" if dg["ok"] / dg["total"] >= 0.9 else "warn" if dg["ok"] / dg["total"] >= 0.6 else "bad"
        lab = d[5:]  # 去掉年-月-日前缀，只显示 MM-DD
        day_items.append(
            f'  <div class="bar-col" title="{d} {dg["ok"]}/{dg["total"]}">'
            f'    <div class="bar {cls}" style="height:{h}px"></div>'
            f'    <div class="bar-lab">{lab}</div>'
            f"  </div>"
        )
    day_html = "".join(day_items) or "  <div class='empty'>无每日数据</div>"

    # 站点矩阵
    site_rows: list[str] = []
    for name, g in groups.items():
        pills = "".join(
            f'<span class="cell {h["status"]}"></span>' for h in g["history"]
        )
        rate_color = "var(--ok)" if g["ok"] / g["total"] >= 0.9 else "var(--warn)" if g["ok"] / g["total"] >= 0.6 else "var(--fail)"
        avg_elapsed = round(sum(h["elapsed"] for h in g["history"]) / len(g["history"])) if g["history"] else 0
        site_rows.append(
            f'  <div class="site { "ok" if g["ok"] > 0 else "fail"}">'
            f'    <div class="site-top">'
            f'      <div class="name">{name}</div>'
            f'      <div class="rate" style="color:{rate_color}">'
            f'        {g["ok"]}/{g["total"]} {round(g["ok"] / g["total"] * 10) / 10 if g["total"] else 0}%'
            f'      </div>'
            f'    </div>'
            f'    <div class="site-mid">'
            f'      <div class="matrix">{pills}</div>'
            f'      <div class="muted">均耗 {avg_elapsed}s</div>'
            f'    </div>'
            f"  </div>"
        )
    site_html = "".join(site_rows) or "  <div class='empty'>没有站点数据</div>"

    # ── 完整 HTML 模板（使用 .format()，参数通过 {} 访问，避免 f-string 冲突）
    # 模板中保留 {0}、{1} 等占位，实际值在 format 时替换
    # 这里我们用 .format(template, card_html=..., day_html=..., site_html=..., total=..., ok=..., dates=..., ok_count=...)
    # 但更简单的办法：因为 card_html/day_html/site_html 已经是完整的 HTML 片段，直接把它们注入字符串里。
    # 为避免混淆，我们直接在模板字符串里用 {{ 和 }} 表示转义的大括号，而实际的 card_html 等会在 format 时被替换。
    # 但实际上 card_html 等里面已经有 { 和 } 了（如 style="color:{color}"）。
    # 解决方案：把 card_html 里的 { } 用 %%Escaped%% 标记，format 后再还原；或者直接用 .replace() 进行双重转义。

    # 最稳妥的办法：把模板拆开，关键位置用 .replace() 替换。
    # 这里我们采用一种更直接的办法：直接把生成好的 HTML 片段嵌入到一个大的原始字符串模板中，
    # 关键的 { } 用 \\{ \\} 转义，最后再把 \\{ 替换回 {。

    # 实际上，最简单的是用模板字符串 + .format(**dict)，但 dict 的值里如果有 {} 需要提前转义。
    # 由于 card_html/day_html/site_html 已经是完整 HTML，里面可能有 { }，我们用一个替换策略：
    # 1. 用 __CARD__ 等占位符
    # 2. 最后 .replace("__CARD__", card_html)

    # 但这里我们直接用纯字符串拼接的方式来生成完整 HTML，不使用 .format() 也不使用 f-string。
    # 我们把模板定义为三引号字符串，其中占位符使用 @@CARD@@ @@DAY@@ @@SITE@@ 等，最后再替换。

    # 重新定义模板：使用特殊占位符，避免与 HTML 内部的 {} 冲突
    # 模板中的 {} 需要被 {{ 转义，最终变成单个 {；但我们的片段里本身就有 { }，所以需要更巧妙的处理。

    # 简化处理：直接把卡片/日矩阵/站矩阵 HTML 通过字符串拼接的方式嵌入模板。
    # Python 的三引号字符串可以容纳任意字符，包括 {}。我们只需要确保模板本身的大括号成对出现，
    # 或者不使用 .format()/.f-string，直接用字符串连接。

    # 下面采用：模板字符串里保留 { } 成对出现的占位，通过 .format(map) 替换。
    # map 的键包括: card_html, day_html, site_html, total, ok, dates_str, ok_str
    # 其中 dates_str 是日期列表的 JSON 字符串，已经转义过了。

    # 构建要传给 .format() 的参数字典
    dates_json = json.dumps(dates, ensure_ascii=False)
    ok_str = str(ok)
    total_str = str(total)

    # 模板：注意这里的 {card_html} 等是 .format() 的占位符，
    # 而模板里本身出现的 { }（如 CSS 的 .bar { ... }）必须成对出现或被转义。
    # 为保险起见，我们把模板中需要 .format() 替换的部分标记为 {0}、{1} 这种索引形式，
    # 而 CSS 里的单独大括号我们通过字符串拼接的方式放入。

    # 实际上最简单的方法是：不使用 .format()，直接用 + 拼接字符串。
    # 但这会让代码很长。让我们采用另一种方法：使用模板字符串，但所有需要注入的变量
    # 都提前通过 .replace() 进行转义，模板里的 {} 只用于 .format() 的占位。

    # 鉴于复杂度，我们直接用最笨的方式：纯字符串连接。
    # 生成完整 HTML 的每一段，通过 + 拼接，不使用 .format() 也不使用 f-string。

    # ---- 以下是纯字符串拼接生成完整 HTML 的过程 ----

    # 先组合头部：DOCTYPE + html + head + 开始 body
    header = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>cat_checkin 签到统计 (本地 SQLite)</title>
  <style>
    :root { --bg:#0b1020; --panel:#12182c; --ink:#e8eefc; --muted:#8b97b3; --line:rgba(255,255,255,.08); --ok:#22c55e; --fail:#ef4444; --warn:#f59e0b; }
    * { box-sizing: border-box; }
    html, body { margin: 0; background: var(--bg); color: var(--ink); }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; min-height: 100vh; }
    .wrap { max-width: 1120px; margin: 0 auto; padding: 24px 20px 48px; }
    .hero { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid var(--line); border-radius: 18px; padding: 22px 24px 18px; }
    .hero-top { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; flex-wrap: wrap; }
    h1 { margin: 0; font-size: 22px; letter-spacing: .3px; }
    .sub { margin-top: 6px; color: var(--muted); font-size: 13px; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    button, .pill { appearance: none; border: 1px solid var(--line); background: rgba(255, 255, 255, .04); color: var(--ink); border-radius: 999px; padding: 8px 14px; font-size: 13px; cursor: pointer; }
    button:hover, .pill:hover { background: rgba(255, 255, 255, .08); }
    .pill.active { background: var(--ink); color: #0b1020; border-color: var(--ink); font-weight: 600; }
    .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; background: var(--ok); }
    .status { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
    .tabs { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 16px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 16px; }
    .card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; }
    .card .k { font-size: 12px; color: var(--muted); }
    .card .v { font-size: 28px; font-weight: 700; margin-top: 6px; }
    .card .hint { font-size: 12px; color: var(--muted); margin-top: 4px; }
    .panel { margin-top: 16px; background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: 16px; }
    .panel h2 { margin: 0 0 12px; font-size: 15px; display: flex; justify-content: space-between; align-items: center; }
    .legend { color: var(--muted); font-size: 12px; }
    .empty { padding: 28px; text-align: center; color: var(--muted); border: 1px dashed var(--line); border-radius: 14px; }
    .site { border-left: 3px solid var(--miss); background: var(--panel-2); border-radius: 0 10px 10px 0; padding: 12px 14px; margin-bottom: 8px; }
    .site.ok { border-left-color: var(--ok); }
    .site.fail { border-left-color: var(--fail); }
    .site-top, .site-mid { display: flex; justify-content: space-between; gap: 12px; align-items: center; }
    .name { font-weight: 600; font-size: 13px; }
    .rate { font-weight: 700; font-size: 13px; }
    .rate.ok { color: var(--ok); }
    .rate.warn { color: var(--warn); }
    .rate.fail { color: var(--fail); }
    .matrix { display: flex; flex-wrap: wrap; gap: 3px; margin-top: 8px; }
    .cell { width: 12px; height: 12px; border-radius: 2px; background: var(--miss); }
    .cell.ok { background: var(--ok); }
    .cell.fail { background: var(--fail); }
    .quota { margin-top: 8px; font-size: 11px; color: #cbd5e1; background: rgba(255, 255, 255, .04); padding: 6px 8px; border-radius: 6px; display: flex; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
    .failbox { color: #fecaca; background: rgba(239, 68, 68, .12); padding: 6px 8px; border-radius: 6px; }
    .delta { font-weight: 700; }
    .foot { margin-top: 18px; text-align: center; color: var(--muted); font-size: 12px; }
    @media (max-width: 560px) { .cards { grid-template-columns: 1fr; } }
    @media (max-width: 860px) { .cards { grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div class="hero-top">
        <div>
          <h1>cat_checkin 签到统计</h1>
          <div class="sub" id="periodDesc">{total} 天 · {ok} 成功</div>
        </div>
        <div class="actions">
          <button type="button" id="btnRefresh">刷新</button>
          <div class="status"><span class="dot idle" id="liveDot"></span><span id="liveText">本地库</span></div>
        </div>
      </div>
      <div class="tabs" id="tabs"></div>
      <div class="cards">
{card_html}
      </div>
      <div class="panel">
        <h2>每日成功率</h2>
        <div class="bars">
{day_html}
        </div>
      </div>
      <div class="panel">
        <h2>站点运行矩阵</h2>
        <div id="sites">
{site_html}
        </div>
      </div>
      <div class="foot" id="foot">数据来源: {db_path} · Updated {now} (BJT)</div>
    </div>
  </div>
</body>
</html>"""

    # 关键步骤：用 .replace() 把占位符替换成实际内容
    # 我们用特殊的占位符：@@CARD@@ @@DAY@@ @@SITE@@
    # 但模板里其实直接用 {card_html} 等，然后 .replace("{total}", total_str) 等
    # 然而 card_html 等里面可能有 { }，所以我们需要先转义 card_html 里的 { 变成 {{，} 变成 }}，
    # 然后 .format() 后再把 {{ 还原成 {。

    # 先转义 card_html、day_html、site_html 中的 { 和 }
    card_escaped = card_html.replace("{", "{{").replace("}", "}}")
    day_escaped = day_html.replace("{", "{{").replace("}", "}}")
    site_escaped = site_html.replace("{", "{{").replace("}", "}}")

    # 现在用 .format() 替换模板里的 {0} {1} 等
    # 模板里我们预留 {0} 对应 card_html, {1} 对应 day_html, {2} 对应 site_html, {3} 对应 total, {4} 对应 ok, {5} 对应 dates_json, {6} 对应 now
    # 但这太麻烦了，换一种更简单的方式：

    # 直接用字符串的 .replace() 方法，不使用 .format()
    html = header
    html = html.replace("{total}", total_str)
    html = html.replace("{ok}", ok_str)
    html = html.replace("{db_path}", str(db_path))
    html = html.replace("{now}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("{{card_html}}", card_escaped)  # 注意这里双大括号是转义后的单大括号
    html = html.replace("{{day_html}}", day_escaped)
    html = html.replace("{{site_html}}", site_escaped)

    return html


def main() -> None:
    parser = argparse.ArgumentParser(description="猫猫签到统计看板 - 本地 SQLite 渲染")
    parser.add_argument("--open", action="store_true", default=True, help="生成后自动尝试用系统浏览器打开")
    parser.add_argument("--port", type=int, default=0, help="若大于 0，则在此端口启动本地 HTTP 服务（调试用）")
    args = parser.parse_args()

    # 确保 .claude 目录存在
    HTML_OUT.parent.mkdir(parents=True, exist_ok=True)

    records = fetch_records()
    html = build_html(records, DB)

    # 写入文件
    HTML_OUT.write_text(html, encoding="utf-8")
    print(f"📄 已渲染看板: {HTML_OUT}")

    if args.open:
        # 尝试用系统默认浏览器打开
        try:
            if sys.platform.startswith("darwin"):
                subprocess.run(["open", str(HTML_OUT)], check=False)
            elif sys.platform.startswith("win"):
                subprocess.run(["start", str(HTML_OUT)], shell=True, check=False)
            else:
                subprocess.run(["xdg-open", str(HTML_OUT)], check=False)
        except Exception as e:
            print(f"⚠️ 无法自动打开浏览器: {e}")

    if args.port > 0:
        # 简单的 HTTP 服务器模式， serve 当前目录
        import http.server
        import socketserver
        handler = http.server.SimpleHTTPRequestHandler
        with socketserver.TCPServer(("", args.port), handler) as httpd:
            print(f"🚀 本地服务器运行在 http://127.0.0.1:{args.port}")
            print(f"   文件: {HTML_OUT.name}")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n已停止服务器")


if __name__ == "__main__":
    main()