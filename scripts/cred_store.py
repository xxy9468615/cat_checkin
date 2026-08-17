#!/usr/bin/env python3
"""HW 凭证存储：Upstash Redis REST 封装。

凭证流向（Redis 为主、GitHub Secrets 兜底）：
  - 读侧：CI 优先从 Redis 取 HW_DEV_COOKIE / HW_DEV_STATE，未配置或 miss 时回退 env。
  - 写侧：hw_login.py 本机重登、hw_dev._self_heal() CI 自愈成功后推送到 Redis；
    失败不中断，由调用方回退到 .heal/ 文件 + gh secret set 回写。

环境变量：
  - UPSTASH_REDIS_REST_URL    形如 https://xxx.upstash.io
  - UPSTASH_REDIS_REST_TOKEN  Redis REST API Bearer Token
未配置时 _configured() 返回 False，所有读返回 None，所有写返回 False。

实现说明：
  - 用 Upstash Redis REST 的命令端点：POST {url}/{command}/{key}[/{arg}]
    value 取 base64（urlsafe 编码，避免 state JSON 里的 '/' 破坏路径段）。
  - 写用 SETEX 一步完成 key+value+EXPIRE；读用 GET。
  - 仅依赖标准库 + common.Http，无新依赖。
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
from typing import Any, Dict, Optional

from common import Http

PREFIX = "hw:"
COOKIE_KEY = PREFIX + "cookie"
STATE_KEY = PREFIX + "state"
META_KEY = PREFIX + "meta"

# TTL（秒）：cookie 30 天、state 90 天，覆盖一次 SSO 生命周期
COOKIE_TTL = 30 * 86400
STATE_TTL = 90 * 86400

_TTL_DAYS = {"cookie": COOKIE_TTL, "state": STATE_TTL}


def _creds() -> tuple[Optional[str], Optional[str]]:
    url = os.getenv("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()
    if not url or not token:
        return None, None
    return url, token


def _configured() -> bool:
    return _creds()[0] is not None


def _cmd(path: str, *, token: str) -> Optional[str]:
    """发一条 Redis REST 命令（HTTP GET，命令名已在 path 里），返回 result 字符串；失败返回 None。

    Upstash REST 响应：{"result": <value or null>}。非 200 视为失败。
    """
    h = Http()
    resp = h.request(
        "GET",
        path,
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    if resp.code != 200:
        return None
    data = resp.json()
    if not isinstance(data, dict):
        return None
    result = data.get("result")
    if result is None:
        return None
    return str(result)


def get_hw_cred(name: str) -> Optional[str]:
    """读取凭证：name ∈ {'cookie','state'}。未配置/miss/故障返回 None。"""
    url, token = _creds()
    if not url or not token:
        return None
    key = COOKIE_KEY if name == "cookie" else STATE_KEY
    raw = _cmd(f"{url}/get/{key}", token=token)
    if raw is None:
        return None
    try:
        return base64.urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8")
    except Exception:
        return None


def set_hw_cred(name: str, value: str, source: str = "manual") -> bool:
    """写入凭证并设 TTL：name ∈ {'cookie','state'}。返回是否成功。

    source 记入 hw:meta 便于诊断（manual / selfheal / login-script）。
    """
    url, token = _creds()
    if not url or not token:
        return False
    key = COOKIE_KEY if name == "cookie" else STATE_KEY
    ttl = _TTL_DAYS.get(name, COOKIE_TTL)
    b64 = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
    # SETEX key ttl value：路径段为 /setex/{key}/{ttl}/{value}
    if _cmd(f"{url}/setex/{key}/{ttl}/{b64}", token=token) is None:
        return False
    # 更新 meta（best-effort，不阻塞成功路径）
    try:
        set_meta({"last_updated": _now_iso(), "source": source,
                   "cookie_len": len(value) if name == "cookie" else None})
    except Exception:
        pass
    return True


def set_meta(meta: Dict[str, Any]) -> bool:
    """合并写入 hw:meta（last_updated / source / last_probe / status …）。"""
    url, token = _creds()
    if not url or not token:
        return False
    cur = get_meta() or {}
    cur.update(meta)
    cur.setdefault("last_updated", _now_iso())
    cur["last_updated"] = _now_iso()
    b64 = base64.urlsafe_b64encode(json.dumps(cur, ensure_ascii=False).encode("utf-8")).decode("ascii")
    return _cmd(f"{url}/setex/{META_KEY}/{STATE_TTL}/{b64}", token=token) is not None


def get_meta() -> Optional[Dict[str, Any]]:
    url, token = _creds()
    if not url or not token:
        return None
    raw = _cmd(f"{url}/get/{META_KEY}", token=token)
    if raw is None:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8"))
    except Exception:
        return None


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
