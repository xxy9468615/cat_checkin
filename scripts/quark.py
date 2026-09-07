#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("夸克网盘 签到")
"""夸克网盘（pan.quark.cn）每日签到领容量。

鉴权（2026-09-07 实测定型）：growth 签到接口凭 **App 抓包设备签名串独立鉴权**，
无需任何会话 Cookie（kps_wg/sign_wg 设备绑定、长期有效，整串重放即可）。
历史网页会话票方案（__pus 14 天窗口 + __puus 滑动续期 + 容量/会员到期统计）
已随 QUARK_COOKIE_1 退役，如需恢复见 git 历史 d2249b6。

环境变量：
- QUARK_MPARAM_1...（App 抓包串整串粘贴：Android 网关变体
  kps_wg/sign_wg/vcode/_ts/_nonce/_sign 原样重放，或经典 "kps=..&sign=..&vcode=.."）
"""
from __future__ import annotations

import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from common import Http, env_seq, main_guard

PAN_HOST = "https://pan.quark.cn"
M_HOST = "https://drive-m.quark.cn"
# 移动端 growth 接口按客户端 UA 网关放行，与 Cp0204/quark-auto-save 一致
UA_CLIENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) quark-cloud-drive/3.14.2 Chrome/112.0.5615.165 "
    "Electron/24.1.3.8 Safari/537.36 Channel/pckk_other_ch"
)


def _resp_dict(resp: Any) -> Dict[str, Any]:
    """resp.json() 容错：非 JSON 对象回退空 dict。"""
    try:
        j = resp.json({})
    except Exception:
        return {}
    return j if isinstance(j, dict) else {}


def _parse_mparam(raw: str) -> Dict[str, str]:
    r"""解析经典 App 三参数：kps/sign/vcode（vcode 可选），任意分隔符。

    负向断言防止误匹配 cookie 里的 __kps（'_' 属于 \w）。
    """
    out: Dict[str, str] = {}
    for key in ("kps", "sign", "vcode"):
        m = re.search(rf"(?<![A-Za-z0-9_]){key}=([^;&\s]+)", raw or "")
        if m:
            out[key] = m.group(1)
    return out if len(out) >= 2 else {}


def _mparam_candidates(raw: str) -> List[str]:
    r"""把用户抓包串转换为 growth 接口的候选 query 列表（按保真度排序）。

    1. Android 抓包（kps_wg/sign_wg + _ts/_nonce/_sign 网关签名）：首选整串
       原样重放（值已含 URL 编码，勿再 quote）；降级为剔除时敏参数并重命名
       kps_wg→kps、sign_wg→sign 的经典形态。
    2. PC 抓包（kps/sign/vcode）：重拼标准前缀。含 % 的值视为已编码不再 quote。
    """
    raw = (raw or "").strip().lstrip("?").strip()
    if not raw:
        return []
    if "kps_wg=" in raw:
        out = [raw]
        pairs = []
        for kv in raw.split("&"):
            if "=" not in kv:
                continue
            k, _, v = kv.partition("=")
            if k in ("_ts", "_nonce", "_sign", "salt"):
                continue
            if k == "kps_wg":
                k = "kps"
            elif k == "sign_wg":
                k = "sign"
            pairs.append(f"{k}={v}")
        out.append("&".join(pairs))
        return out

    p = _parse_mparam(raw)
    if "kps" not in p or "sign" not in p:
        return [raw] if "=" in raw else []

    def _q(v: str) -> str:
        return v if "%" in v else quote(v, safe="")

    q = f"pr=ucpro&fr=pc&uc_param_str=&kps={_q(p['kps'])}&sign={_q(p['sign'])}"
    if p.get("vcode"):
        q += f"&vcode={_q(p['vcode'])}"
    return [q]


def _growth_sign(h: Http, mparam_raw: str) -> Tuple[str, bool]:
    """移动端 growth 接口签到（设备签名串独立鉴权，无会话态）。

    mparam_raw 候选按保真度依次尝试（最多 2 种形态，属业务级降级而非失败重试）。
    返回 (文案, 是否达成签到)。
    """
    headers = {
        "User-Agent": UA_CLIENT,
        "Content-Type": "application/json",
        "Referer": f"{PAN_HOST}/",
    }
    info: Dict[str, Any] = {}
    used_q = ""
    last_note = ""
    for q in _mparam_candidates(mparam_raw):
        resp = h.request("GET", f"{M_HOST}/1/clouddrive/capacity/growth/info?{q}", headers=headers)
        info = _resp_dict(resp)
        if resp.code == 200 and info.get("code") in (0, None) \
                and (info.get("data") or {}).get("cap_sign"):
            used_q = q
            break
        last_note = f"HTTP {resp.code} {str(info.get('message', ''))[:40]}"
    if not used_q:
        return f"签到状态查询失败（{last_note}），设备签名串可能已失效，请重新抓包", False

    cap = (info.get("data") or {}).get("cap_sign") or {}
    reward_mb = int((cap.get("sign_daily_reward") or 0) / 1024 / 1024)
    progress = cap.get("sign_progress", 0)
    target = cap.get("sign_target", 0)
    if cap.get("sign_daily"):
        return f"今日已签到（+{reward_mb}MB，连签 {progress}/{target} 天）", True
    resp = h.request(
        "POST", f"{M_HOST}/1/clouddrive/capacity/growth/sign?{used_q}",
        headers=headers, json_data={"sign_cyclic": True},
    )
    d = _resp_dict(resp)
    if resp.code == 200 and d.get("code") == 0 and (d.get("data") or {}):
        reward_mb = int((d["data"].get("sign_daily_reward") or 0) / 1024 / 1024)
        return f"【成功】+{reward_mb}MB（连签 {progress + 1}/{target} 天）", True
    msg = str(d.get("message") or resp.code)
    return f"签到失败（{msg[:60]}）", False


def _run_one(idx: int, total: int, mparam_raw: str) -> bool:
    """单个账号签到流程（纯 App 设备票，无会话态）。"""
    h = Http()
    print(f"[{idx}/{total}] 👤 用户: 【APP设备票·账号{idx}】")
    sign_line, ok = _growth_sign(h, mparam_raw)
    print(f"• 签到: {sign_line}")
    return ok


def main() -> None:
    mparams = env_seq("QUARK_", "mparam", required=True)
    total = len(mparams)
    print(f"【夸克网盘 签到】共 {total} 个账号")
    failed = 0
    done = 0
    for idx in range(1, total + 1):
        mparam = mparams[idx - 1].strip()
        if not mparam:
            continue
        done += 1
        try:
            ok = _run_one(idx, total, mparam)
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"❌ 账号 {idx} 处理失败: {exc}")
        if not ok:
            failed += 1
    print(f"✅ 全部 {done} 个账号处理完成 (成功 {done - failed}/{done})")
    if failed:
        print(f"❌ {failed} 个账号未达成签到")
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
