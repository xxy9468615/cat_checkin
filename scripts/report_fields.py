#!/usr/bin/env python3
"""按任务定制的报告字段解析器（unified_report / daily_report / discord_notify 共用）。

背景：此前统一报告用一套全局启发式（daily_report._extract_fields）解析所有脚本输出，
站点字段大量失配（2libra 余额、CloudStudio 机时、agentrouter 余额额度、ai_router USD、
dji 积分变化、workbuddy 算力/能量等），且近期脚本新增的 [diag]/[keepalive]/🔑 SSO 续票/
🧪 跨站触碰/☁️ state 同步等过程行混进卡片正文，信息混乱。

本模块为每个任务注册专属解析器（锚定各自脚本当前的输出格式），统一产出：

    {
      "lines":      [str]        每账号一行紧凑摘要（成功 / 幂等 / 冷却等正常态）
      "fail_lines": [str]        失败账号行（名字 + 原因）
      "error_lines":[str]        错误相关原始行（失败卡正文；无则回退 fail_lines）
      "badges":     [(group, text)]   group ∈ reward/asset/streak/info/summary
      "gains":      [(unit, float)]   数值化奖励（「今日概览」按单位聚合）
      "assets":     [(label, float)]  数值化资产（「今日概览」与昨日归档对比）
      "streak":     int               最高连签天数
      "summary":    str               多账号「成功 X/Y」
    }

未注册脚本回退 fallback_extract()（启发式 + 过程噪音过滤），保证新增站点不炸报告。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

# 数字：容忍千分位/小数
NUM = r"\d[\d,]*(?:\.\d+)?"
_NUM_RE = re.compile(NUM)


def _f(text: str) -> float:
    """'12,345.6' → 12345.6；解析失败返回 0.0。"""
    m = _NUM_RE.search(text or "")
    if not m:
        return 0.0
    try:
        return float(m.group().replace(",", ""))
    except ValueError:
        return 0.0


def _d(text: str) -> str:
    """保留千分位原样的展示值。"""
    m = _NUM_RE.search(text or "")
    return m.group() if m else (text or "").strip()


def _clean(text: str, limit: int = 46) -> str:
    """截短过长的状态描述（兑换进度 / 猫咪来信等），压平空白。"""
    text = re.sub(r"\s+", " ", (text or "").strip())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _int(text: str) -> str:
    """去千分位后按千分位重新格式化（展示统一）。"""
    return f"{int(_f(text)):,}" if _f(text) else _d(text)


# 过程噪音行（兜底过滤用；各专属解析器只认结果行，天然不命中）
_NOISE_RE = re.compile(
    r"^\s*(?:"
    r"\[(?:diag|sched|keepalive|DEBUG|workbuddy)\]"
    r"|▶️|💾|📡|☁️|🔖|🧪|🆕|🔑|📦|🧩"
    r"|TRAVEL_EVENT"
    r"|🔄 (?:Refresh Token|账号|服务器自动延长|缓存)"
    r"|✅ 账号 #\d+ 成功刷新令牌"
    r"|📜 最近交易明细"
    r"|⚠️ .*持久化失败"
    r")"
)

# 错误关键词（失败卡正文筛选 + 兜底扫描）
_ERROR_KW = ("失败", "失效", "异常", "错误", "401", "403", "超时", "无法", "Traceback")


def _new_result() -> Dict[str, Any]:
    return {
        "lines": [],
        "fail_lines": [],
        "error_lines": [],
        "badges": [],
        "gains": [],
        "assets": [],
        "streak": 0,
        "summary": "",
    }


class _Block:
    """多账号块式输出的累积器（extractor 结束时统一落成字符串行）。"""

    def __init__(self, name: str):
        self.name = name
        self.parts: List[str] = []

    def flush(self, res: Dict[str, Any]) -> None:
        if self.parts:
            res["lines"].append(_acc_line(self.name, self.parts))


def _acc_line(name: str, parts: List[str]) -> str:
    segs = [p for p in (s.strip() for s in parts) if p]
    return (f"{name}  " if name else "") + " · ".join(segs)


def _finalize(res: Dict[str, Any]) -> None:
    """兜底：既没有账号摘要行也没有错误行时，做一次降噪错误扫描。"""
    if not res["error_lines"] and not res["fail_lines"]:
        for raw in (res.get("_output") or "").splitlines():
            ln = raw.strip()
            if ln and not _NOISE_RE.match(ln) and any(kw in ln for kw in _ERROR_KW):
                res["error_lines"].append(ln)
    res.pop("_output", None)


def _add_summary(res: Dict[str, Any], output: str) -> None:
    m = re.findall(r"成功\s+(\d+)\s*/\s*(\d+)", output)
    if m:
        ok, total = m[-1]
        if int(total) > 1:
            res["summary"] = f"成功 {ok}/{total}"
            res["badges"].append(("summary", f"✅ {ok}/{total}"))


# =====================================================================
# 各任务解析器（锚定 scripts/<task>.py 当前 print 格式）
# =====================================================================

def ex_2libra(output: str, res: Dict[str, Any]) -> None:
    """【2Libra 签到】：[i/N] 名字（第 N 号会员）+ 3 行详情；失败为 [i/N] 签到失败：...。"""
    cur: Any = None
    for raw in output.splitlines():
        s = raw.strip()
        m = re.match(r"\[(\d+)/(\d+)\] (\S+?)（第 (\d+) 号会员）", s)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(m.group(3))
            continue
        if "签到失败" in s and s.startswith("["):
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(s))
            res["error_lines"].append(s)
            continue
        if cur is None:
            continue
        mm = re.search(r"本次签到获得 (\d+) 金币", s)
        if mm:
            cur.parts.append(f"+{mm.group(1)}金币")
            res["gains"].append(("金币", _f(mm.group(1))))
            res["badges"].append(("reward", f"+{mm.group(1)} 金币"))
            continue
        mm = re.search(r"当前金币总数为 (\d+) 个，已累计签到 (\d+) 天", s)
        if mm:
            cur.parts.append(f"余额 {int(mm.group(1)):,}")
            cur.parts.append(f"连签 {mm.group(2)} 天")
            res["assets"].append(("金币", _f(mm.group(1))))
            res["streak"] = max(res["streak"], int(mm.group(2)))
            res["badges"].append(("streak", f"连签 {mm.group(2)} 天"))
            continue
        mm = re.search(r"当前用户等级为 (\d+) 级，经验值为 (\d+) 点", s)
        if mm:
            cur.parts.append(f"Lv{mm.group(1)}（{mm.group(2)}点）")
            continue
        if "已经签到" in s and "签到时间为：" in s:
            cur.parts.append("今日已签（幂等）")
    if cur:
        cur.flush(res)
    _keepalive_badge(output, res)
    _add_summary(res, output)


def _keepalive_badge(output: str, res: Dict[str, Any]) -> None:
    if "[keepalive] ✅" in output:
        m = re.search(r"\[keepalive\] ✅ token 已换新并持久化，新 access_token 到期 ([\d-]+)", output)
        res["badges"].append(("info", f"Token已换新{('，到期 ' + m.group(1)) if m else ''}"))
    elif "[keepalive] ⚠️" in output:
        res["badges"].append(("info", "Token换新失败"))


def ex_glados(output: str, res: Dict[str, Any]) -> None:
    """【GLaDOS / Railgun 签到兑换】：📧 账号 块。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.match(r"📧 账号:\s*(.+)", ln)
        if m:
            if cur:
                cur.flush(res)
            acc_name = m.group(1).split(" | ")[0].strip()
            cur = _Block(acc_name)
            continue
        if cur is None:
            continue
        mm = re.search(r"签到状态: 签到成功 \(\+(\d+) 积分\)", ln)
        if mm:
            cur.parts.append(f"+{mm.group(1)}积分")
            res["gains"].append(("积分", _f(mm.group(1))))
            res["badges"].append(("reward", f"+{mm.group(1)} 积分"))
            continue
        if ln.startswith("🔄 签到状态: 今日已签到"):
            cur.parts.append("今日已签")
            continue
        mm = re.search(r"❌ 签到状态: 签到失败 \((.+)\)", ln)
        if mm:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_acc_line("", [f"签到失败：{_clean(mm.group(1))}"]))
            res["error_lines"].append(ln)
            continue
        mm = re.search(r"📅 剩余天数: (.+)", ln)
        if mm:
            cur.parts.append(f"剩余 {_clean(mm.group(1), 20)}")
            continue
        mm = re.search(r"💰 当前积分: (\d+) 积分", ln)
        if mm:
            cur.parts.append(f"积分 {int(mm.group(1)):,}")
            res["assets"].append(("积分", _f(mm.group(1))))
            continue
        mm = re.search(r"🎯 兑换进度: (.+)", ln)
        if mm:
            cur.parts.append(f"兑换：{_clean(mm.group(1), 40)}")
            res["badges"].append(("info", _clean(mm.group(1), 40)))
    if cur:
        cur.flush(res)
    _add_summary(res, output)


ex_railgun = ex_glados


def ex_bianjie_ai(output: str, res: Dict[str, Any]) -> None:
    """【边界 AI 签到】：[i/N] 用户名：xx，签到成功，已连续签到N天，奖励：X，累计积分：Y。"""
    for raw in output.splitlines():
        m = re.match(r"\[(\d+)/(\d+)\] 用户名：(\S+?)，(.+)$", raw.strip())
        if not m:
            continue
        name, body = m.group(3), m.group(4)
        if "签到失败" in body:
            res["fail_lines"].append(_acc_line(name, [_clean(body)]))
            res["error_lines"].append(raw.strip())
            continue
        parts = []
        mm = re.search(r"已连续签到(\d+)天", body)
        if mm:
            parts.append(f"连签 {mm.group(1)} 天")
            res["streak"] = max(res["streak"], int(mm.group(1)))
            res["badges"].append(("streak", f"连签 {mm.group(1)} 天"))
        if "今日已签到" in body:
            parts.append("今日已签")
        mm = re.search(r"奖励：([^，。]+)", body)
        if mm:
            parts.append(f"奖励 {mm.group(1)}")
            res["badges"].append(("reward", f"+{mm.group(1)}"))
        mm = re.search(r"累计积分：(\d+)", body)
        if mm:
            parts.append(f"积分 {int(mm.group(1)):,}")
            res["assets"].append(("积分", _f(mm.group(1))))
        res["lines"].append(_acc_line(name, parts))
    _add_summary(res, output)


def ex_dji(output: str, res: Dict[str, Any]) -> None:
    """【DJI 大疆社区签到】：【个人信息】块。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.search(r"【个人信息】用户：【(.+?)】 UID：【(.+?)】", ln)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(m.group(1))
            cur.parts.append(f"UID {m.group(2)}")
            continue
        if cur is None:
            continue
        mm = re.search(r"连签天数：【(\d+)】", ln)
        if mm:
            cur.parts.append(f"连签 {mm.group(1)} 天")
            res["streak"] = max(res["streak"], int(mm.group(1)))
            res["badges"].append(("streak", f"连签 {mm.group(1)} 天"))
            continue
        if "签到失败" in ln:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
            continue
        mm = re.search(r"签到：【成功】\s*\+(\d+)", ln)
        if mm:
            cur.parts.append(f"+{mm.group(1)}积分")
            res["gains"].append(("积分", _f(mm.group(1))))
            res["badges"].append(("reward", f"+{mm.group(1)} 积分"))
        elif "签到：【已签到】" in ln:
            cur.parts.append("今日已签")
        mm = re.search(r"他人空间：【成功(\d+)次】", ln)
        if mm:
            cur.parts.append(f"浏览 {mm.group(1)} 篇")
        mm = re.search(r"积分变化：【([^】]*) -> ([^】]*)】", ln)
        if mm:
            cur.parts.append(f"积分 {_d(mm.group(2))}")
            res["assets"].append(("积分", _f(mm.group(2))))
    if cur:
        cur.flush(res)
    _add_summary(res, output)


def ex_monkeycode(output: str, res: Dict[str, Any]) -> None:
    """【MonKeyCode 签到】：[i/N] 用户【xx】签到成功，获得 100 积分 + 💰/⚡ 行（📜 明细跳过）。"""
    cur: Any = None
    in_tx = False
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.match(r"(?:\[(\d+)/(\d+)\] )?用户【(.+?)】(.+)$", ln)
        if m:
            in_tx = False
            if cur:
                cur.flush(res)
            name, body = m.group(3), m.group(4)
            if "签到失败" in body:
                res["fail_lines"].append(_acc_line(name, [_clean(body)]))
                res["error_lines"].append(ln)
                cur = None
                continue
            cur = _Block(name)
            mm = re.search(r"获得 (\d+) 积分", body)
            if mm:
                cur.parts.append(f"+{mm.group(1)}积分")
                res["gains"].append(("积分", _f(mm.group(1))))
                res["badges"].append(("reward", f"+{mm.group(1)} 积分"))
            elif "今日已签到" in body:
                cur.parts.append("今日已签")
            continue
        if cur is None:
            continue
        if ln.startswith("📜"):
            in_tx = True
            continue
        if in_tx:
            continue
        mm = re.search(r"💰 可用余额: ([\d,]+) 积分", ln)
        if mm:
            cur.parts.append(f"余额 {int(mm.group(1).replace(',', '')):,}")
            res["assets"].append(("积分", _f(mm.group(1))))
            continue
        mm = re.search(r"⚡ 每日免费 Token 额度: ([\d,]+) /", ln)
        if mm:
            cur.parts.append(f"免费额度 {_d(mm.group(1))}")
    if cur:
        cur.flush(res)
    _add_summary(res, output)


def ex_moxing_vip(output: str, res: Dict[str, Any]) -> None:
    """【moxing.vip 签到】：单行 用户名：xx 威望: N 软妹币: N ... 签到响应：xxx。"""
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.search(r"用户名：(\S+)", ln)
        if not m:
            continue
        name = m.group(1)
        if "签到失败" in ln:
            res["fail_lines"].append(_acc_line(name, [_clean(ln)]))
            res["error_lines"].append(ln)
            continue
        parts = []
        for label, key in (("软妹币", "软妹币"), ("威望", "威望"), ("交易魔币", "魔币")):
            mm = re.search(label + r"[::]\s*(" + NUM + ")", ln)
            if mm and _f(mm.group(1)) > 0:
                parts.append(f"{key} {_d(mm.group(1))}")
                res["assets"].append((label, _f(mm.group(1))))
        mm = re.search(r"签到响应：(.+)$", ln)
        if mm:
            parts.append(_clean(mm.group(1), 40))
        res["lines"].append(_acc_line(name, parts))
    _add_summary(res, output)


def ex_naixi_forum(output: str, res: Dict[str, Any]) -> None:
    """【奶昔论坛 签到】：[i/N] 用户名：xx | 状态 | 连续签到：N天（累计M天） | 点数：a，经验：b，积分：c。"""
    for raw in output.splitlines():
        m = re.match(r"\[(\d+)/(\d+)\] 用户名：(\S+?) \| (.+)$", raw.strip())
        if not m:
            continue
        name, body = m.group(3), m.group(4)
        if "签到失败" in body:
            res["fail_lines"].append(_acc_line(name, [_clean(body)]))
            res["error_lines"].append(raw.strip())
            continue
        parts = []
        mm = re.search(r"连续签到：(\d+)天（累计(\d+)天）", body)
        if mm:
            parts.append(f"连签 {mm.group(1)} 天（累计 {mm.group(2)}）")
            res["streak"] = max(res["streak"], int(mm.group(1)))
            res["badges"].append(("streak", f"连签 {mm.group(1)} 天"))
        if "签到成功：" in body:
            parts.append("签到成功")
        elif "已签到" in body:
            parts.append("今日已签")
        mm = re.search(r"点数：(\S+)，经验：(\S+)，积分：(\S+)", body)
        if mm:
            parts.append(f"点数 {mm.group(1)} · 经验 {mm.group(2)} · 积分 {mm.group(3)}")
            res["assets"].append(("积分", _f(mm.group(3))))
        res["lines"].append(_acc_line(name, parts))
    _add_summary(res, output)


def ex_sophnet(output: str, res: Dict[str, Any]) -> None:
    """Sophnet：--- 处理第 N 个 --- 块（✅ 状态 / 💰 余额 / 📅 连签行）。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.match(r"--- 处理第 (\d+) 个 Sophnet 账号 ---", ln)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(f"账号#{m.group(1)}")
            continue
        if cur is None:
            continue
        mm = re.search(r"账号 #\d+ Sophnet 签到成功！", ln)
        if mm:
            cur.parts.append("签到成功")
            continue
        mm = re.search(r"账号 #\d+ Sophnet 今日已完成签到", ln)
        if mm:
            cur.parts.append("今日已签")
            continue
        if "处理失败" in ln:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
            continue
        mm = re.search(r"账号 #\d+ 当前 Token 余额: ([\d,]+)", ln)
        if mm:
            cur.parts.append(f"余额 {int(mm.group(1).replace(',', '')):,}")
            res["assets"].append(("Token", _f(mm.group(1))))
            continue
        mm = re.search(r"连续签到: (\d+) 天 \| 累计签到: (\d+) 天", ln)
        if mm:
            cur.parts.append(f"连签 {mm.group(1)} 天（累计 {mm.group(2)}）")
            res["streak"] = max(res["streak"], int(mm.group(1)))
            res["badges"].append(("streak", f"连签 {mm.group(1)} 天"))
    if cur:
        cur.flush(res)
    mm = re.search(r"签到总结[：:]\s*(\d+)/(\d+) 成功", output) or re.search(
        r"签到总结[：:]\s*(\d+)/(\d+) 全部成功", output
    )
    if mm and int(mm.group(2)) > 1:
        res["summary"] = f"成功 {mm.group(1)}/{mm.group(2)}"
        res["badges"].append(("summary", f"✅ {mm.group(1)}/{mm.group(2)}"))


def ex_tencent_cloudstudio(output: str, res: Dict[str, Any]) -> None:
    """Tencent CloudStudio：用户 x {状态} + 机时资源行 + 🔑 SSO 续票行。"""
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.match(
            r"用户 (\S+) (签到成功，获得 " + NUM + r" 机时"
            r"|今日已签到过（本次奖励 " + NUM + r" 机时）"
            r"|今日已签到过)$",
            ln,
        )
        if m:
            name, status = m.group(1), m.group(2)
            parts = []
            mm = re.search(r"(?:获得|本次奖励) (" + NUM + r") 机时", status)
            if mm:
                parts.append(f"+{_d(mm.group(1))}机时")
                res["gains"].append(("机时", _f(mm.group(1))))
                res["badges"].append(("reward", f"+{_d(mm.group(1))} 机时"))
            else:
                parts.append("今日已签")
            res["lines"].append(_acc_line(name, parts))
            continue
        mm = re.search(r"可用资源总计：剩余 (" + NUM + r") / (" + NUM + r") 机时", ln)
        if mm:
            res["lines"].append(f"资源  剩余 {_d(mm.group(1))} / {_d(mm.group(2))} 机时")
            res["assets"].append(("机时", _f(mm.group(1))))
            res["badges"].append(("asset", f"机时 {_d(mm.group(1))}/{_d(mm.group(2))}"))
            continue
        mm = re.match(
            r"• (.+?) \((\d+)个包\): 剩余 (" + NUM + r")/(" + NUM + r") 机时(?:，(\d{4}-\d{2}-\d{2}) 到期)?$",
            ln,
        )
        if mm:
            exp = f"，{mm.group(5)} 到期" if mm.group(5) else ""
            res["lines"].append(f"资源  {mm.group(1)}（{mm.group(2)}包）{_d(mm.group(3))}/{_d(mm.group(4))} 机时{exp}")
            continue
        if ln == "暂无可用资源包":
            res["lines"].append("资源  暂无可用资源包")
            continue
        if "🔑 SSO 主动续票成功" in ln or "🔑 SSO 换票成功" in ln or "🔑 SSO 续期成功" in ln:
            res["badges"].append(("info", "SSO 已续票"))
        elif "🆕 检测到环境变量 Cookie 已更新" in ln:
            res["badges"].append(("info", "Cookie已更新"))
        if any(kw in ln for kw in _ERROR_KW) and not ln.startswith(("✅", "🔔")):
            res["error_lines"].append(ln)
    _add_summary(res, output)


def ex_ugnas_club(output: str, res: Dict[str, Any]) -> None:
    """绿联私有云：积分: N。"""
    for raw in output.splitlines():
        ln = raw.strip()
        if "签到失败" in ln:
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
            continue
        m = re.search(r"积分[::]\s*(" + NUM + ")", ln)
        if m:
            res["lines"].append(_acc_line("账号", [f"积分 {_d(m.group(1))}"]))
            res["assets"].append(("积分", _f(m.group(1))))
    _add_summary(res, output)


def ex_ai_router(output: str, res: Dict[str, Any]) -> None:
    """AI-ROUTER：[i/N] 账号：xx | 签到成功 | 🎁 奖励：$X USD | 💰 资产：$Y USD (可用: $A / 冻结: $F)。"""
    for raw in output.splitlines():
        m = re.match(r"\[(\d+)/(\d+)\] 账号：(.+)$", raw.strip())
        if not m:
            continue
        body = m.group(3)
        name = re.split(r"\s*\|", body)[0].strip()
        if "签到失败" in body:
            res["fail_lines"].append(_acc_line(name, [_clean(body)]))
            res["error_lines"].append(raw.strip())
            continue
        parts = []
        if "签到成功" in body:
            parts.append("签到成功")
        elif "今日已签到过" in body:
            parts.append("今日已签")
        mm = re.search(r"🎁 奖励：\$(" + NUM + r") USD", body)
        if mm:
            parts.append(f"+${_d(mm.group(1))}")
            res["gains"].append(("USD", _f(mm.group(1))))
            res["badges"].append(("reward", f"+${_d(mm.group(1))}"))
        mm = re.search(
            r"💰 资产：\$(" + NUM + r") USD \(可用: \$(" + NUM + r") / 冻结: \$(" + NUM + r")\)", body
        )
        if mm:
            parts.append(f"资产 ${_d(mm.group(1))}（可用{_d(mm.group(2))}）")
            res["assets"].append(("USD", _f(mm.group(1))))
        res["lines"].append(_acc_line(name, parts))
    _add_summary(res, output)


def ex_agentrouter(output: str, res: Dict[str, Any]) -> None:
    """AgentRouter：[i/N] 账号：xx | 签到成功 | 💰 余额额度：N（已用 M）。"""
    for raw in output.splitlines():
        m = re.match(r"\[(\d+)/(\d+)\] 账号：(.+)$", raw.strip())
        if not m:
            continue
        body = m.group(3)
        name = re.split(r"\s*\|", body)[0].strip()
        if "签到失败" in body:
            res["fail_lines"].append(_acc_line(name, [_clean(body)]))
            res["error_lines"].append(raw.strip())
            continue
        parts = []
        if "签到成功" in body:
            parts.append("签到成功")
        elif "今日已签到过" in body:
            parts.append("今日已签")
        mm = re.search(r"余额额度：(" + NUM + r")（已用 (" + NUM + r")）", body)
        if mm:
            parts.append(f"额度 {int(_f(mm.group(1))):,}（已用 {int(_f(mm.group(2))):,}）")
            res["assets"].append(("额度", _f(mm.group(1))))
        res["lines"].append(_acc_line(name, parts))
    _add_summary(res, output)


def ex_u1s1(output: str, res: Dict[str, Any]) -> None:
    """u1s1.io：🎉 账号 [i/N] 打卡成功（用户名在下一行 👤 用户信息）+ 📅/🎁 附加行。"""
    pending: Any = None  # (tag, parts) 等待 👤 用户信息补名字

    def _flush() -> None:
        nonlocal pending
        if pending:
            tag, parts = pending
            digits = re.search(r"(\d+)", tag or "")
            res["lines"].append(_acc_line(f"账号{digits.group(1)}" if digits else "账号", parts))
            pending = None

    for raw in output.splitlines():
        ln = raw.strip()
        m = re.search(r"🎉 账号 ([\[\]0-9/]*)\s*打卡成功！今日获得: (.+?) Tokens，连续 (\d+) 天", ln)
        if m:
            _flush()
            parts = [f"+{m.group(2)} Tokens", f"连签 {m.group(3)} 天"]
            mm = re.search(r"达成第 (\d+) 天里程碑额外 \+(.+)\)$", ln)
            if mm:
                parts.append(f"里程碑第{mm.group(1)}天 +{mm.group(2)}")
            pending = (m.group(1), parts)
            res["streak"] = max(res["streak"], int(m.group(3)))
            res["gains"].append(("Tokens", _f(m.group(2))))
            res["badges"].append(("reward", f"+{_d(m.group(2))} Tokens"))
            continue
        m = re.search(r"👤 用户信息: (\S+)", ln)
        if m and pending:
            tag, parts = pending
            res["lines"].append(_acc_line(m.group(1), parts))
            pending = None
            continue
        m = re.search(r"ℹ️ 账号 ([\[\]0-9/]*)\s*今日已完成打卡", ln)
        if m:
            _flush()
            pending = (m.group(1), ["今日已签"])
            continue
        m = re.search(r"❌ 账号 ([\[\]0-9/]*)\s*\S*\s*打卡失败: (.+)$", ln)
        if m:
            _flush()
            dm = re.search(r"(\d+)", m.group(1) or "")
            label = f"账号{dm.group(1)}" if dm else "账号"
            res["fail_lines"].append(f"{label}  打卡失败：{_clean(m.group(2))}")
            res["error_lines"].append(ln)
            continue
        m = re.search(r"📅 连签进度: 连续 (\d+) 天", ln)
        if m:
            res["streak"] = max(res["streak"], int(m.group(1)))
            continue
        m = re.search(r"🎁 打卡赠送额度: (.+?) Tokens \(有效期至 (.+?)\)", ln)
        if m and res["lines"]:
            res["lines"][-1] += f" · 赠额度 {m.group(1)}（至 {m.group(2)}）"
    _flush()
    for raw in output.splitlines():
        if re.search(r"共有 \d+ 个账号打卡失败", raw):
            res["error_lines"].append(raw.strip())
    _add_summary(res, output)


def ex_juejin(output: str, res: Dict[str, Any]) -> None:
    """掘金社区：👤 用户：【xx】 (UID: xx) + • 签到 / 抽奖 / 沾喜气 / 资产 行。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.search(r"👤 用户：【(.+?)】(?:\s*\(UID:\s*(\S+)\))?", ln)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(m.group(1))
            continue
        if "签到失败" in ln:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
            continue
        if cur is None:
            continue
        mm = re.search(r"• 签到：【(.+?)】(?:\s*连签天数：【(\d+)】天)?(?:\s*\(累计 (\d+) 天\))?(?:\s*\+(\d+)\s*矿石)?", ln)
        if mm:
            status, cont_d, sum_d, gain_ore = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
            if status == "成功":
                if gain_ore:
                    cur.parts.append(f"+{gain_ore}矿石")
                    res["gains"].append(("矿石", _f(gain_ore)))
                    res["badges"].append(("reward", f"+{gain_ore} 矿石"))
                else:
                    cur.parts.append("签到成功")
            elif "已签" in status:
                cur.parts.append("今日已签")
            if cont_d:
                cur.parts.append(f"连签 {cont_d} 天")
                res["streak"] = max(res["streak"], int(cont_d))
                res["badges"].append(("streak", f"连签 {cont_d} 天"))
            continue
        mm = re.search(r"• 免费抽奖：【(.+?)】", ln)
        if mm:
            draw_res = mm.group(1)
            if "抽中" in draw_res:
                cur.parts.append(draw_res)
                m_ore = re.search(r"(\d+)\s*矿石", draw_res)
                if m_ore:
                    res["gains"].append(("矿石", _f(m_ore.group(1))))
                    res["badges"].append(("reward", f"抽奖+{m_ore.group(1)} 矿石"))
            elif "已抽" in draw_res:
                pass
            else:
                cur.parts.append(_clean(draw_res, 20))
            continue
        mm = re.search(r"• 沾喜气：【(.+?)】(?:\s*当前累计幸运值：【(\d+)】)?", ln)
        if mm:
            dip_res, total_l = mm.group(1), mm.group(2)
            if "成功" in dip_res or "+" in dip_res:
                cur.parts.append(dip_res)
            if total_l:
                cur.parts.append(f"幸运值 {total_l}")
            continue
        mm = re.search(r"• 资产：矿石 【(" + NUM + r")】", ln)
        if mm:
            cur.parts.append(f"矿石 {_d(mm.group(1))}")
            res["assets"].append(("矿石", _f(mm.group(1))))
            continue
    if cur:
        cur.flush(res)
    _add_summary(res, output)


def ex_nodeseek(output: str, res: Dict[str, Any]) -> None:
    """NodeSeek：👤 用户: 【xx】 (UID: xx) + • 签到 / 资产 行。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.search(r"👤 用户:\s*【(.+?)】(?:\s*\(UID:\s*(\S+)\))?", ln)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(m.group(1))
            continue
        if "签到失败" in ln:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
            continue
        if cur is None:
            continue
        mm = re.search(r"• 签到:\s*【(.+?)】(?:\s*获得\s*🍗?\s*\+(\d+)\s*鸡腿)?", ln)
        if mm:
            status, gain = mm.group(1), mm.group(2)
            if status == "成功" or gain:
                if gain:
                    cur.parts.append(f"+{gain}鸡腿")
                    res["gains"].append(("鸡腿", _f(gain)))
                    res["badges"].append(("reward", f"+{gain} 鸡腿"))
                else:
                    cur.parts.append("签到成功")
            elif "已签" in status:
                cur.parts.append("今日已签")
            continue
        mm = re.search(r"• 资产:\s*鸡腿\s*【(" + NUM + r")】", ln)
        if mm:
            cur.parts.append(f"鸡腿 {_d(mm.group(1))}")
            res["assets"].append(("鸡腿", _f(mm.group(1))))
            continue
    if cur:
        cur.flush(res)
    _add_summary(res, output)


def ex_aistudio(output: str, res: Dict[str, Any]) -> None:
    """飞桨 AI Studio：👤 用户: 【xx】 (UID: xx) + • 签到 / 算力卡 / 资产 行。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.search(r"👤 用户:\s*【(.+?)】(?:\s*\(UID:\s*(\S+)\))?", ln)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(m.group(1))
            continue
        if "签到失败" in ln or "失败：" in ln:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
            continue
        if cur is None:
            continue
        mm = re.search(r"• 签到:\s*【(.+?)】(?:\s*连签天数:\s*【(\d+)】天)?(?:\s*\+(\d+)\s*积分)?", ln)
        if mm:
            status, streak_d, gain_p = mm.group(1), mm.group(2), mm.group(3)
            if status == "成功":
                if gain_p:
                    cur.parts.append(f"+{gain_p}积分")
                    res["gains"].append(("积分", _f(gain_p)))
                    res["badges"].append(("reward", f"+{gain_p} 积分"))
                else:
                    cur.parts.append("签到成功")
            elif "已签" in status:
                cur.parts.append("今日已签")
            if streak_d:
                cur.parts.append(f"连签 {streak_d} 天")
                res["streak"] = max(res["streak"], int(streak_d))
                res["badges"].append(("streak", f"连签 {streak_d} 天"))
            continue
        mm = re.search(r"• 算力卡:\s*【(.+?)】", ln)
        if mm:
            card_stat = mm.group(1)
            if "+" in card_stat:
                cur.parts.append(f"算力卡 {card_stat}")
                c_gain = re.search(r"\+([\d.]+)", card_stat)
                if c_gain:
                    res["gains"].append(("算力卡", _f(c_gain.group(1))))
                    res["badges"].append(("reward", f"+{c_gain.group(1)}点算力"))
            elif "已" in card_stat or "成功" in card_stat:
                cur.parts.append(f"算力卡 {card_stat}")
            continue
        if ln.startswith("• 资产:"):
            m_pt = re.search(r"积分\s*【(" + NUM + r")】", ln)
            if m_pt:
                cur.parts.append(f"积分 {_d(m_pt.group(1))}")
                res["assets"].append(("积分", _f(m_pt.group(1))))
            m_card = re.search(r"算力卡\s*【([^】]+)】(?:\s*\(([^)]+)\))?", ln)
            if m_card:
                card_val, card_extra = m_card.group(1), m_card.group(2)
                if card_extra:
                    if "⚠️" in card_extra:
                        cur.parts.append(f"算力卡 {card_val}（{card_extra}）")
                        res["badges"].append(("warn", "算力卡即将过期"))
                    else:
                        m_exp = re.search(r"(\d{4}-\d{2}-\d{2})", card_extra)
                        exp_date = m_exp.group(1) if m_exp else card_extra
                        cur.parts.append(f"算力卡 {card_val}（至 {exp_date}）")
                else:
                    cur.parts.append(f"算力卡 {card_val}")
                c_num = re.search(r"([\d.]+)", card_val)
                if c_num:
                    res["assets"].append(("算力卡", _f(c_num.group(1))))
            m_tk = re.search(r"大模型 Token\s*【([^】]+)】", ln)
            if m_tk:
                cur.parts.append(f"Token {m_tk.group(1)}")
                t_num = re.search(r"([\d,]+)", m_tk.group(1))
                if t_num:
                    res["assets"].append(("Tokens", _f(t_num.group(1))))
            continue
    if cur:
        cur.flush(res)
    _add_summary(res, output)


def ex_alipan(output: str, res: Dict[str, Any]) -> None:
    """阿里云盘：👤 用户: 【xx】 (177***109) + • 签到 / 奖励 / 空间 行。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.search(r"👤 用户:\s*【(.+?)】(?:\s*\(([^)]+)\))?", ln)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(m.group(1))
            continue
        if "签到失败" in ln:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
            continue
        if cur is None:
            continue
        mm = re.search(r"• 签到:\s*【(.+?)】(?:\s*本月累计签到:\s*【(\d+)】天)?(?:\s*\((.+?)\))?", ln)
        if mm:
            status, days, blessing = mm.group(1), mm.group(2), mm.group(3)
            if days:
                cur.parts.append(f"月签 {days} 天")
                res["streak"] = max(res["streak"], int(days))
                res["badges"].append(("streak", f"月签 {days} 天"))
            if status == "成功":
                cur.parts.append("签到成功")
            elif "已签" in status:
                cur.parts.append("今日已签")
            if blessing:
                cur.parts.append(blessing)
            continue
        mm = re.search(r"• 奖励:\s*【(.+?)】(?:\s*\((.+?)\))?", ln)
        if mm:
            rw_name = mm.group(1)
            if rw_name:
                cur.parts.append(f"奖励 {rw_name}")
                res["badges"].append(("reward", rw_name))
                m_gain_days = re.search(r"(\d+)天", rw_name)
                m_gain_mb = re.search(r"(\d+)\s*(?:M|MB|G|GB)", rw_name, re.I)
                if m_gain_days:
                    res["gains"].append(("天特权", _f(m_gain_days.group(1))))
                elif m_gain_mb:
                    res["gains"].append(("容量", _f(m_gain_mb.group(1))))
            continue
        mm = re.search(r"• 空间:\s*【([^】]+)】(?:\s*\(使用率\s*([^)]+)\))?", ln)
        if mm:
            space_val = mm.group(1)
            cur.parts.append(f"空间 {space_val}")
            m_total = re.search(r"/\s*([\d.]+)\s*(GB|TB|MB)", space_val)
            if m_total:
                res["assets"].append(("空间", _f(m_total.group(1))))
            continue
    if cur:
        cur.flush(res)
    _add_summary(res, output)


def ex_workbuddy(output: str, res: Dict[str, Any]) -> None:
    """WorkBuddy：用户【xx】（UID: xx）+ • 八项 bullets。"""
    cur: Any = None
    for raw in output.splitlines():
        ln = raw.strip()
        m = re.match(r"(?:\[(\d+)/(\d+)\] )?用户【(.+?)】（UID: (.+?)）", ln)
        if m:
            if cur:
                cur.flush(res)
            cur = _Block(m.group(3))
            continue
        if cur is None:
            continue
        mm = re.search(r"• AI对话签到：(.+)$", ln)
        if mm:
            body = mm.group(1)
            sm = re.search(r"签到成功 \(\+(\d+) 算力，连签 (\d+) 天", body)
            if sm:
                cur.parts.append(f"+{sm.group(1)}算力 · 连签 {sm.group(2)} 天")
                res["gains"].append(("算力", _f(sm.group(1))))
                res["streak"] = max(res["streak"], int(sm.group(2)))
                res["badges"].append(("reward", f"+{sm.group(1)} 算力"))
                res["badges"].append(("streak", f"连签 {sm.group(2)} 天"))
            elif "今日已签到" in body:
                cur.parts.append("今日已签")
            elif "失败" in body:
                cur.parts.append(f"⚠️ {_clean(body, 40)}")
                res["error_lines"].append(ln)
            continue
        mm = re.search(r"• 成长等级：(.+)$", ln)
        if mm:
            tm = re.search(r"(.+?)\s*\(任务 (\d+)/(\d+)\)", mm.group(1))
            if tm:
                cur.parts.append(f"{_clean(tm.group(1), 12)} 任务{tm.group(2)}/{tm.group(3)}")
            else:
                cur.parts.append(_clean(mm.group(1), 14))
            continue
        mm = re.search(r"• 连登兑换：(.+)$", ln)
        if mm:
            body = mm.group(1)
            dm = re.search(r"当月连登 (\d+) 天", body)
            if dm:
                cur.parts.append(f"连登{dm.group(1)}天")
            dm = re.search(r"兑换【(.+?)】失败", body)
            if dm:
                cur.parts.append(f"⚠️ 兑换{dm.group(1)}失败")
                res["error_lines"].append(ln)
            else:
                dm = re.search(r"兑换【(.+?)】", body)
                if dm:
                    cur.parts.append(f"已兑{dm.group(1)}")
                elif "已兑:" in body:
                    dm = re.search(r"已兑: (.+?)\)", body)
                    cur.parts.append(f"已兑{dm.group(1)})" if dm else "已兑档位")
            continue
        mm = re.search(r"• 抽奖活动：完成 (\d+)/(\d+) 次抽奖", ln)
        if mm:
            cur.parts.append(f"抽奖{mm.group(1)}/{mm.group(2)}")
            continue
        if re.search(r"• 抽奖活动：抽奖机会 0 次", ln):
            cur.parts.append("抽奖0次")
            continue
        mm = re.search(r"• 猫咪放风：(.+)$", ln)
        if mm:
            body = mm.group(1)
            sm = re.search(r"已领取【(.+?)】放风奖励（\+(\d+) 积分", body)
            if sm:
                cur.parts.append(f"放风+{sm.group(2)}积分")
                res["gains"].append(("积分", _f(sm.group(2))))
            elif "派遣猫咪出发" in body:
                sm = re.search(r"【(.+?)】，预计时长 (\d+)小时", body)
                cur.parts.append(f"放风中({sm.group(1)},{sm.group(2)}h)" if sm else "放风中")
            else:
                cur.parts.append(_clean(body, 24))
            continue
        mm = re.search(r"• 积分\(算力\)余额 (" + NUM + r")", ln)
        if mm:
            cur.parts.append(f"算力 {_d(mm.group(1))}")
            res["assets"].append(("算力", _f(mm.group(1))))
            continue
        mm = re.search(r"• 资产：能量 (\d+) \| 猫咪配额 (\d+) \| 徽章 (\d+)/(\d+)", ln)
        if mm:
            cur.parts.append(f"能量{mm.group(1)} · 配额{mm.group(2)} · 徽章{mm.group(3)}/{mm.group(4)}")
            res["assets"].append(("能量", _f(mm.group(1))))
            continue
        if "签到失败" in ln:
            if cur:
                cur.flush(res)
                cur = None
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
    if cur:
        cur.flush(res)
    _add_summary(res, output)


def ex_modelscope(output: str, res: Dict[str, Any]) -> None:
    """ModelScope（国内/国际共用）：[i/N] tag 状态行；[diag]/🧪/☁️ 过程行全部忽略。"""
    for raw in output.splitlines():
        m = re.match(r"\s*\[(\d+)/(\d+)\] (.+)$", raw)
        if not m:
            continue
        body = m.group(3).strip()
        if "[diag]" in body:
            continue
        nm = re.match(r"(\S+) \[(Cookie|Token)\]", body)
        name = nm.group(1) if nm else ""
        if "签到失败" in body:
            res["fail_lines"].append(_clean(body))
            res["error_lines"].append(body)
            continue
        parts = []
        mm = re.search(r"今日已领取 (\d+) 魔粒", body)
        if mm:
            parts.append(f"+{mm.group(1)}魔粒")
            res["gains"].append(("魔粒", _f(mm.group(1))))
            res["badges"].append(("reward", f"+{mm.group(1)} 魔粒"))
        mm = re.search(r"完成点赞 (\d+)/(\d+) 次 \(\+(\d+) 魔粒\)", body)
        if mm:
            parts.append(f"点赞 {mm.group(1)}/{mm.group(2)}(+{mm.group(3)})")
            res["gains"].append(("魔粒", _f(mm.group(3))))
        else:
            mm2 = re.search(r"点赞已达上限 (\d+)/(\d+)", body)
            if mm2:
                parts.append(f"点赞 {mm2.group(1)}/{mm2.group(2)}")
        mm = re.search(r"24h 冷却中（上次到账 ([^）]+)）", body)
        if mm:
            em = re.search(r"预计 (\d+) 小时 (\d+) 分钟后可领", body)
            eta_txt = f"约{em.group(1)}h{em.group(2)}m后领" if em else "下次运行可领"
            parts.append(f"冷却中（上次 {mm.group(1)}，{eta_txt}）")
            res["badges"].append(("info", "24h 冷却中，登录态正常"))
        mm = re.search(r"，([\d-]+ [\d:]+) 过期$", body)
        if mm:
            parts.append(f"{mm.group(1)} 过期")
        if "交易记录无今日 daily_active" in body:
            res["fail_lines"].append(_acc_line(name, [_clean(body)]))
            res["error_lines"].append(body)
            continue
        res["lines"].append(_acc_line(name + (" [Token]" if "[Token]" in body else ""), parts))
    mm = re.search(r"总结：成功 (\d+)/(\d+)", output)
    if mm and int(mm.group(2)) > 1:
        res["summary"] = f"成功 {mm.group(1)}/{mm.group(2)}"
        res["badges"].append(("summary", f"✅ {mm.group(1)}/{mm.group(2)}"))


def ex_latvi(output: str, res: Dict[str, Any]) -> None:
    """Latvi：✅ 签到成功 +N（连续N天），余额 N + 🔄 服务器自动延长。"""
    for raw in output.splitlines():
        ln = raw.strip()
        mm = re.search(r"签到成功 \+(\S+)（连续(\d+)天），余额 (\S+)", ln)
        if mm:
            res["lines"].append(_acc_line("账号", [f"+{mm.group(1)}", f"连签 {mm.group(2)} 天", f"余额 {mm.group(3)}"]))
            res["gains"].append(("积分", _f(mm.group(1))))
            res["assets"].append(("积分", _f(mm.group(3))))
            res["streak"] = max(res["streak"], int(mm.group(2)))
            res["badges"].append(("reward", f"+{mm.group(1)}"))
            res["badges"].append(("streak", f"连签 {mm.group(2)} 天"))
            continue
        mm = re.search(r"今日已于 (\S+) 签到过，无需重复执行", ln)
        if mm:
            res["lines"].append(_acc_line("账号", [f"今日已于 {mm.group(1)} 签到过"]))
            continue
        mm = re.search(r"服务器自动延长 \(#(\d+)\): (.+)$", ln)
        if mm:
            state = "✓" if ("HTTP 200" in mm.group(2) or "成功" in mm.group(2)) else _clean(mm.group(2), 18)
            res["lines"].append(f"续期 #{mm.group(1)}  {state}")
            continue
        if "签到失败" in ln:
            res["fail_lines"].append(_clean(ln))
            res["error_lines"].append(ln)
    _add_summary(res, output)


# 注册表：key = 脚本文件名（task_registry 的 script 字段 / 结果 JSON 的 script 字段）
SCRIPT_EXTRACTORS = {
    "2libra.py": ex_2libra,
    "glados.py": ex_glados,
    "railgun.py": ex_railgun,
    "bianjie_ai.py": ex_bianjie_ai,
    "dji.py": ex_dji,
    "monkeycode.py": ex_monkeycode,
    "moxing_vip.py": ex_moxing_vip,
    "naixi_forum.py": ex_naixi_forum,
    "sophnet.py": ex_sophnet,
    "tencent_cloudstudio.py": ex_tencent_cloudstudio,
    "ugnas_club.py": ex_ugnas_club,
    "ai_router.py": ex_ai_router,
    "agentrouter.py": ex_agentrouter,
    "u1s1.py": ex_u1s1,
    "juejin.py": ex_juejin,
    "nodeseek.py": ex_nodeseek,
    "aistudio.py": ex_aistudio,
    "alipan.py": ex_alipan,
    "workbuddy.py": ex_workbuddy,
    "modelscope.py": ex_modelscope,
    "latvi.py": ex_latvi,
}


def fallback_extract(output: str, res: Dict[str, Any]) -> None:
    """未注册脚本的兜底：启发式 _extract_fields 徽标 + 过程噪音过滤后的原文行。"""
    from daily_report import _extract_fields  # 局部导入避免循环依赖

    fields = _extract_fields(output or "")
    for part in (fields.get("reward") or "").split(" | "):
        if part:
            res["badges"].append(("reward", f"获得 {part}"))
    for part in (fields.get("assets") or "").split(" | "):
        if part:
            res["badges"].append(("asset", part))
            mm = re.match(r"\s*(\S+)\s+(" + NUM + r")\s*$", part)
            if mm:
                res["assets"].append((mm.group(1), _f(mm.group(2))))
    if fields.get("streak"):
        res["badges"].append(("streak", f"连签 {fields['streak']}"))
        m = re.search(r"(\d+)", fields["streak"])
        if m:
            res["streak"] = int(m.group(1))
    if fields.get("exchange"):
        res["badges"].append(("info", fields["exchange"]))
    if fields.get("summary"):
        res["summary"] = fields["summary"]
        res["badges"].append(("summary", fields["summary"]))
    for raw in (output or "").splitlines():
        ln = raw.strip()
        if not ln or _NOISE_RE.match(ln):
            continue
        if any(kw in ln for kw in _ERROR_KW):
            res["error_lines"].append(ln)
        else:
            res["lines"].append(_clean(ln, 120))


def extract_for(script: str, output: str) -> Dict[str, Any]:
    """按脚本名解析输出；未注册脚本走兜底。script 传文件名（如 'modelscope.py'）。"""
    res = _new_result()
    res["_output"] = output or ""
    fn = SCRIPT_EXTRACTORS.get(script or "")
    try:
        if fn is not None:
            fn(output or "", res)
        else:
            fallback_extract(output or "", res)
    except Exception:
        # 解析器自身异常时保底：至少给降噪后的原文，绝不炸报告链路
        res = _new_result()
        res["_output"] = output or ""
        fallback_extract(output or "", res)
        res["badges"].append(("info", "（字段解析降级）"))
    _finalize(res)
    return res


def assets_text(res: Dict[str, Any]) -> str:
    """[(label, float)] → '金币 24,616 | 积分 349'（兼容旧 _parse_asset_pairs 的展示串）。"""
    parts = []
    for label, val in res.get("assets") or []:
        if isinstance(val, float):
            v = int(val) if abs(val - round(val)) < 0.01 else round(val, 2)
            parts.append(f"{label} {v:,}")
        else:
            parts.append(f"{label} {val}")
    return " | ".join(parts)


def assets_pairs(res: Dict[str, Any]) -> Dict[str, float]:
    """同标签资产求和（多账号各自提报时聚合），供「今日概览」与归档对比。"""
    pairs: Dict[str, float] = {}
    for label, val in res.get("assets") or []:
        if isinstance(val, (int, float)):
            pairs[label] = pairs.get(label, 0.0) + float(val)
    return pairs


def assets_pairs_text(res: Dict[str, Any]) -> str:
    """求和后的资产展示串（归档用，'积分 658 | 魔粒 240'）。"""
    return " | ".join(f"{label} {v:,.2f}".rstrip("0").rstrip(".") if v % 1 else f"{label} {int(v):,}"
                      for label, v in assets_pairs(res).items())
