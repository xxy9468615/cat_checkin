#!/usr/bin/env python3
"""凭据年龄预警：对「无法自动续期、只有硬寿命上限」的凭据做提前预警。

原理：GitHub Secrets 只能经 API 读到 updated_at（值本身永不回显），而用户
「浏览器重新登录 → 拷贝 Cookie → gh secret set」的动作间隔通常只有几分钟，
因此 updated_at ≈ 登录时刻，可当作寿命起点。剩余寿命 ≤1 天时产出 🟡 提示，
把「第 7 天突然红卡」变成「提前一天的定时重登提醒」。

范围约定：
- 只登记已证实有硬寿命上限、且脚本侧无法自动续期的凭据（WorkBuddy 登录会话
  7 天硬上限，HAR 逆向结论：二进制 opaque 票据、无滑动续期、无 refresh 端点）；
- 自动续期型凭据（alipan/2libra/modelscope/cloudstudio 等）的续期失败提示由
  alert_levels 覆盖，不在此重复登记；
- 无 token / API 失败 / 本地运行 → 静默返回 []，绝不影响主流程。
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# secret 名 → (展示名, 硬寿命上限天数)；新凭据按实测寿命在此登记
CREDENTIAL_LIFETIMES: Dict[str, Any] = {
    "WORKBUDDY_COOKIE_1": ("WorkBuddy 账号1", 7),
    "WORKBUDDY_COOKIE_2": ("WorkBuddy 账号2", 7),
}
WARN_REMAINING_DAYS = 1.0  # 剩余 ≤1 天时提示（与分级制「提前一天提示」一致）


def _token() -> str:
    return (os.getenv("GH_PAT") or os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN") or "").strip()


def _repo() -> str:
    return (os.getenv("GITHUB_REPO") or os.getenv("GITHUB_REPOSITORY") or "").strip()


def fetch_secret_updated_at() -> Dict[str, str]:
    """返回 {secret 名: updated_at ISO 串}；无 token / 任何异常静默返回 {}。"""
    token, repo = _token(), _repo()
    if not (token and repo):
        return {}
    try:
        from common import Http

        resp = Http().request(
            "GET",
            f"https://api.github.com/repos/{repo}/actions/secrets?per_page=100",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )
        if resp.code != 200:
            return {}
        data = resp.json()
        return {
            s["name"]: s.get("updated_at") or ""
            for s in (data.get("secrets") or [])
            if s.get("name")
        }
    except Exception:
        return {}


def compute_warns(updated: Dict[str, str], now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """纯函数（便于测试）：根据 updated_at 映射产出预警条目。

    每条：{"title", "secret", "remaining_days", "lifetime_days", "expired"}，
    按 remaining 升序（最紧急在前）。缺少/无法解析的 secret 直接跳过。
    """
    now = now or datetime.now(timezone.utc)
    entries: List[Dict[str, Any]] = []
    for secret, (title, lifetime) in CREDENTIAL_LIFETIMES.items():
        raw = (updated.get(secret) or "").strip()
        if not raw:
            continue
        try:
            ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        remaining = lifetime - (now - ts).total_seconds() / 86400
        entries.append(
            {
                "title": title,
                "secret": secret,
                "remaining_days": remaining,
                "lifetime_days": lifetime,
                "expired": remaining <= 0,
            }
        )
    entries.sort(key=lambda e: e["remaining_days"])
    return [e for e in entries if e["expired"] or e["remaining_days"] <= WARN_REMAINING_DAYS]


def format_warn(entry: Dict[str, Any]) -> str:
    """预警条目 → 日报正文文案。"""
    life = entry["lifetime_days"]
    if entry["expired"]:
        return (
            f"{entry['title']} 凭据已到 {life:g} 天硬上限（大概率已失效）"
            f"——请重新登录并更新 {entry['secret']}"
        )
    rem = max(entry["remaining_days"], 0.0)
    rem_txt = "不足半天" if rem < 0.5 else f"约 {rem:.0f} 天"
    return (
        f"{entry['title']} 凭据剩{rem_txt}（{life:g} 天硬上限，无法自动续期）"
        f"——请尽快重新登录并更新 {entry['secret']}"
    )


def format_chip(entry: Dict[str, Any]) -> str:
    """预警条目 → 邮件概览短徽标文案。"""
    life = entry["lifetime_days"]
    if entry["expired"]:
        return f"{entry['title']} 凭据已到期（{life:g}天上限）"
    rem = max(entry["remaining_days"], 0.0)
    rem_txt = "≤半天" if rem < 0.5 else "≤1 天"
    return f"{entry['title']} 凭据剩 {rem_txt}"


def credential_age_warns() -> List[Dict[str, Any]]:
    """入口：读 API + 计算；无 token / 失败 → []。"""
    return compute_warns(fetch_secret_updated_at())
