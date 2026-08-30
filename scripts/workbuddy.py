#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("WorkBuddy 签到与成长中心")
"""WorkBuddy (https://www.workbuddy.cn) 每日算力中心签到、成长中心连登兑换、抽奖与猫咪放风自动化。

核心特性：
1. 算力中心每日签到与专享礼包：
   - 每日调用 `POST /billing/meter/daily-checkin` 领取每日算力与累计连签天数。
   - 自动检测并领取 `POST /billing/meter/check-gift-claimed` 专享算力礼包（如 +1500 算力）。
2. 动态放风跟踪与回程领奖：
   - 不依赖硬编码的 4 小时，完全基于服务端返回的真实 `arrive_at` 与 `server_now` 动态计算。
   - 单 run 全内联（2026-08-22 起）：放风进行中时打印 `TRAVEL_EVENT` 机器行，由
     `daily_orchestrator` 在 `arrive_at+60s` 定时回访领奖（受 Latvi 进场截止线约束，超线
     留次日领）；旧 QStash 延时接力（`workbuddy_travel_claim`）已退役，未设
     `WORKBUDDY_NO_RELAY` 时仍兼容旧行为。
3. 连登兑换与抽奖追踪：
   - 自动核算当月连登天数，符合 7d/14d/28d 档位时自动兑换奖励与抽奖机会。
   - 追踪当前剩余抽奖次数，>0 时自动循环抽奖并统计获得的奖品。
4. 严格单号独立与隐私脱敏：
   - 支持多账号（换行或 && 分隔），每个账号独立完成全套流程与放风回访。
   - 所有用户名、昵称和 UID 均通过 `mask_str()` 严格脱敏。
5. 积分（算力）余额查询：
   - 调用 `POST /billing/meter/get-user-resource` 汇总各有效资源包剩余算力与本月周期剩余，
     放风领取的积分计入对应资源包后此处会同步反映最新余额。

环境变量：
  - WORKBUDDY_REFRESH_TOKEN / WORKBUDDY_REFRESH_TOKEN_1/2…：插件 OAuth refresh_token（优先凭据）。
    每次运行先换新 access_token（60 天）再签到，轮换出的新 refresh_token（90 天）经 gh 回写
    Secret 滚动保活；换取方式见 scripts/workbuddy_device_login.py
  - WORKBUDDY_COOKIE / WORKBUDDY_cookie：浏览器会话 Cookie（兜底凭据，7 天硬上限）
  - WORKBUDDY_WAIT_TRAVEL：是否开启放风动态等待并自动回访领奖（默认 true，如设为 false 则仅输出当前倒计时）
  - QSTASH_URL / QSTASH_TOKEN：QStash 延时发布服务凭证（放风时通过延时 Webhook 触发下一轮接力）
  - GH_PAT：GitHub Personal Access Token with Actions: write，用于 repository_dispatch（未配置时脚本静默跳过）
  - WORKBUDDY_DEBUG：设为 1 时实时打印过程调试日志（默认缓冲，仅账号失败时随错误输出）
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
from typing import Any, Dict, List, Optional, Tuple

from common import Http, env, env_bool, env_seq, is_already_signed, main_guard, mask_str, schedule_repo_dispatch, upstash_redis_command

PREFIX = "WORKBUDDY_"
BASE_URL = "https://www.workbuddy.cn"
# 插件 OAuth（realm=copilot）：refresh_token 换新端点。社区逆向（wb2api /
# workbuddy-switch）证实：X-Refresh-Token 头换新、响应轮换新 refresh_token；
# 唯一失效方式是闲置数天被服务端清理（12153 invalid_grant）→ 每次签到即刷新保活。
PLUGIN_REFRESH_URL = "https://www.codebuddy.cn/v2/plugin/auth/token/refresh"
PLUGIN_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": "https://www.codebuddy.cn",
    "Referer": "https://www.codebuddy.cn/",
    "User-Agent": "CLI/2.63.2 CodeBuddy/2.63.2",
}

BASE_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Origin": "https://www.workbuddy.cn",
    "Referer": "https://www.workbuddy.cn/profile/growth-center",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
    "x-client-platform": "web",
}


def _is_access_token(cred: str) -> bool:
    """凭据是插件 OAuth access_token（JWT）还是浏览器会话 Cookie。"""
    return cred.startswith("eyJ") and cred.count(".") == 2


def _base_auth_headers(cred: str, referer: str = f"{BASE_URL}/profile/growth-center") -> Dict[str, str]:
    """构造鉴权请求头：token 模式用 Bearer，cookie 模式用 Cookie。"""
    headers = dict(BASE_HEADERS)
    headers["Referer"] = referer
    if _is_access_token(cred):
        headers["Authorization"] = f"Bearer {cred}"
    else:
        headers["Cookie"] = cred
    return headers


def _resp_dict(resp: Any) -> Dict[str, Any]:
    """resp.json() 容错：响应非 JSON 对象（JSON 字符串/数组/null、WAF 拦截页）时回退空 dict。

    CI 实弹（#33319485658）踩坑：端点在代理/风控下可能返回非对象 JSON，
    裸 .get() 会炸 'str' object has no attribute 'get' 且无堆栈难定位。
    """
    try:
        j = resp.json({})
    except Exception:
        return {}
    return j if isinstance(j, dict) else {}


def _data_dict(data: Any, key: str = "data") -> Dict[str, Any]:
    """data[key] 容错取 dict：值缺失或为字符串/列表等非 dict 类型时回退空 dict。"""
    v = data.get(key) if isinstance(data, dict) else None
    return v if isinstance(v, dict) else {}


def _refresh_access_token(h: Http, refresh_token: str) -> Tuple[str, str]:
    """用 refresh_token 换新凭据，返回 (access_token, 轮换后的新 refresh_token)。

    实测（2026-08-30）：access_token 60 天、refresh_token 90 天，每次刷新轮换；
    401/12153 invalid_grant = refresh 会话被清理或失效，需重跑设备码登录。
    """
    resp = h.request(
        "POST",
        PLUGIN_REFRESH_URL,
        headers={**PLUGIN_HEADERS, "X-Refresh-Token": refresh_token, "X-Auth-Refresh-Source": "workbuddy"},
        json_data={},
    )
    j = _resp_dict(resp)
    if not j:
        raise RuntimeError(f"refresh_token 换新异常（HTTP {resp.code}，响应非 JSON 对象）")
    data = _data_dict(j)
    if j.get("code") != 0 or not data.get("accessToken"):
        msg = str(j.get("msg") or resp.code)
        raise RuntimeError(
            f"refresh_token 续期失败（code={j.get('code')} msg={msg}）。"
            "refresh 会话可能闲置被清理或已失效，请重新运行 scripts/workbuddy_device_login.py 换取新凭据"
        )
    return str(data["accessToken"]), str(data.get("refreshToken") or refresh_token)


def _redis_refresh_key(idx: int) -> str:
    """Redis 滚动票键。per-account dispatch（orchestrator 注入 WORKBUDDY_ACCOUNT_IDX）
    时子进程内账号重编号为 1，键必须映射真实账号号，否则两个账号的独立 dispatch
    会共用 _1 键互相覆盖、串用对方票据（张冠李戴）。
    v2：首版 _1 键在修复前已被账号2 的 dispatch 写入过，直接作废改用 v2 命名，
    免清理；新键带 14 天 TTL，链路长期停摆时自动过期回退 Secret 票。"""
    real = (os.getenv("WORKBUDDY_ACCOUNT_IDX") or "").strip()
    if real.isdigit():
        idx = int(real)
    prefix = os.getenv("CAT_CHECKIN_REDIS_PREFIX", "cat_checkin:").rstrip(":")
    return f"{prefix}:state:workbuddy_refresh_token_v2_{idx}"


def _load_refresh_token_redis(idx: int) -> str:
    """从 Upstash Redis 读滚动 refresh_token（数据库为准，env secret 可能滞后）。"""
    try:
        ok, res = upstash_redis_command(["GET", _redis_refresh_key(idx)])
        if ok and isinstance(res, dict):
            raw = res.get("result")
            data = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(data, dict):
                return str(data.get("refresh_token") or "")
    except Exception:  # noqa: BLE001
        pass
    return ""


def _save_refresh_token_redis(idx: int, new_token: str) -> bool:
    """滚动票写入 Upstash Redis（数据库回写主通道，免 GH_PAT 权限）。"""
    try:
        payload = json.dumps({"refresh_token": new_token, "rotated_at": time.time()}, ensure_ascii=False)
        ok, _res = upstash_redis_command(
            ["SET", _redis_refresh_key(idx), payload, "EX", str(14 * 86400)]
        )
        return bool(ok)
    except Exception:  # noqa: BLE001
        return False


def _persist_refresh_token(idx: int, new_token: str) -> str:
    """滚动回写 refresh_token：Upstash Redis 为主，GitHub Secret 为辅（best-effort）。

    数据库回写不依赖 GH_PAT 权限（CI 内 gh secret set 曾被 403 拒）；
    Secret 回写仅当 GH_PAT 具备 Secrets 写权限时生效，失败只进调试日志。
    Keycloak offline token 默认允许重复使用，回写失败不致命（旧票 90 天内仍可刷），
    但长期不回写会让滚动链退化为同一张票刷到死，由 secret_age 凭据年龄预警兜底。
    """
    if new_token == _load_refresh_token_redis(idx) and new_token == (env(PREFIX, "refresh_token", required=False) or ""):
        return ""
    if _save_refresh_token_redis(idx, new_token):
        note = f"☁️🔑 refresh_token 已滚动回写（Redis {_redis_refresh_key(idx)}"
        if _persist_refresh_token_secret(idx, new_token):
            note += " + Secret"
        return note + "）"
    if _persist_refresh_token_secret(idx, new_token):
        return f"🔑 refresh_token 已滚动回写 Secret（Redis 不可用，WORKBUDDY_REFRESH_TOKEN_{idx}）"
    return "⚠️ refresh_token 滚动回写失败（Redis 与 Secret 均不可用，靠 Keycloak 票据可重复使用维持）"


def _persist_refresh_token_secret(idx: int, new_token: str) -> bool:
    """GitHub Secret 回写（best-effort，需 GH_PAT 有 Secrets 写权限）。"""
    repo = os.getenv("GITHUB_REPO") or os.getenv("GITHUB_REPOSITORY") or ""
    pat = os.getenv("GH_PAT") or os.getenv("GH_TOKEN") or ""
    if not (repo and pat and shutil.which("gh")):
        return False
    try:
        run_env = dict(os.environ)
        run_env["GH_TOKEN"] = pat
        proc = subprocess.run(
            ["gh", "secret", "set", f"WORKBUDDY_REFRESH_TOKEN_{idx}", "--body", new_token, "--repo", repo],
            env=run_env, capture_output=True, text=True, timeout=90,
        )
        if proc.returncode != 0:
            _dbg(f"[workbuddy] Secret 回写失败（不影响 Redis 主通道）：{(proc.stderr or '').strip()[:120]}")
        return proc.returncode == 0
    except Exception as exc:  # noqa: BLE001
        _dbg(f"[workbuddy] Secret 回写异常（不影响 Redis 主通道）：{exc}")
        return False


def _parse_cookies(raw: str) -> List[str]:
    """解析多账号 Cookie，支持序列变量、换行或 && 分隔。"""
    if not raw:
        return []
    return [x.strip() for x in raw.replace("&&", "\n").splitlines() if x.strip()]


# 过程日志治理：stdout 会原样进入每日邮件卡片，请求头 dump / 轮询心跳等
# 调试信息默认只缓冲不输出（成功时丢弃），账号失败时才随错误一起输出便于排查；
# WORKBUDDY_DEBUG=1 可恢复实时打印（本地调试用）。
_DEBUG = env_bool("WORKBUDDY_DEBUG")
_DEBUG_LINES: List[str] = []


def _dbg(msg: str) -> None:
    if _DEBUG:
        print(msg, flush=True)
    else:
        _DEBUG_LINES.append(msg)


def _flush_dbg() -> None:
    if _DEBUG_LINES:
        print("\n".join(_DEBUG_LINES))
        _DEBUG_LINES.clear()


def _format_countdown(seconds: int) -> str:
    """将秒数格式化为 HH:MM:SS。"""
    if seconds <= 0:
        return "00:00:00"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def _format_beijing_time(ts: int) -> str:
    """将时间戳格式化为北京时间 HH:MM:SS。"""
    if ts <= 0:
        return "--:--:--"
    tz = dt.timezone(dt.timedelta(hours=8))
    return dt.datetime.fromtimestamp(ts, tz=tz).strftime("%H:%M:%S")


def _safe_session_dump(session_data: Dict[str, Any]) -> str:
    """脱敏打印 session 配置，避免泄露 token/secret。"""
    sensitive = ("cookie", "token", "accesstoken", "access_token", "secret", "authorization", "apikey", "api_key", "password")
    redacted = {}
    for k, v in session_data.items():
        if any(s in k.lower() for s in sensitive):
            redacted[k] = "<redacted>"
        else:
            redacted[k] = v
    return json.dumps(redacted, ensure_ascii=False)


def _get_account_info(h: Http, cred: str) -> Tuple[str, str]:
    """获取用户信息，返回 (uid, nickname)。"""
    headers = _base_auth_headers(cred)
    # 调试日志脱敏：绝不打印 Cookie/Authorization 等敏感头
    safe_headers = {k: ("<redacted>" if k.lower() in ("cookie", "authorization", "x-api-key") else v)
                    for k, v in headers.items()}
    _dbg(f"[workbuddy] _get_account_info 请求头: {json.dumps(safe_headers, ensure_ascii=False, indent=2)}")
    resp = h.request("GET", f"{BASE_URL}/console/accounts", headers=headers)
    if resp.code in (401, 403):
        raise RuntimeError(f"鉴权已失效（HTTP {resp.code}），请重新登录更新 Cookie 或重跑 workbuddy_device_login.py")
    if resp.code in (301, 302, 303, 307, 308):
        # 补重定向目标(仅路径,去 query 防泄露 token),便于确认是被导向登录页而非其他异常端点
        loc = (resp.headers.get("Location", "?") or "?").split("?")[0]
        raise RuntimeError(f"鉴权已失效（HTTP {resp.code} 重定向至 {loc}），请重新登录更新凭据")
    if resp.code != 200:
        raise RuntimeError(f"获取账号信息失败：HTTP {resp.code}")

    data = _resp_dict(resp)
    if data.get("code") not in (0, None):
        raise RuntimeError(f"获取账号信息失败：接口返回 {data.get('code')} ({data.get('msg', '未知')})")
    accounts = _data_dict(data).get("accounts", [])
    if accounts and isinstance(accounts, list):
        acc = accounts[0]
        uid = str(acc.get("uid") or acc.get("uin") or "")
        nickname = str(acc.get("nickname") or acc.get("mobile") or "用户")
        return uid, nickname
    return "", "用户"


def _init_conversations_headers(cred: str) -> Dict[str, str]:
    """对话任务专用请求头。"""
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Content-Type": "application/json",
        "Origin": "https://www.workbuddy.cn",
        "Referer": "https://www.workbuddy.cn/console/agents",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
        "x-client-platform": "web",
    }
    if _is_access_token(cred):
        headers["Authorization"] = f"Bearer {cred}"
    else:
        headers["Cookie"] = cred
    return headers


def _create_conversation(h: Http, cred: str) -> Dict[str, Any]:
    """创建 AI 对话任务，返回 conversation 数据。

    POST /console/as/conversations/
    Body: {"prompt":"hi","model":"auto","plugins":[{"name":"weixinpay","marketplace":"codebuddy-builtin"}]}
    """
    headers = _init_conversations_headers(cred)
    resp = h.request(
        "POST",
        f"{BASE_URL}/console/as/conversations/",
        headers=headers,
        json_data={"prompt": "hi", "model": "auto", "plugins": [{"name": "weixinpay", "marketplace": "codebuddy-builtin"}]},
    )
    if resp.code != 200:
        return {}
    data = _resp_dict(resp)
    if data.get("code") != 0:
        return {}
    return _data_dict(data)






def _get_conversation_session(h: Http, cred: str, conversation_id: str) -> Dict[str, Any]:
    """获取对话的 session 配置（包含 e2bEndpoint 等）。

    GET /console/as/conversations/{conversation_id}/session
    """
    headers = _init_conversations_headers(cred)
    resp = h.request("GET", f"{BASE_URL}/console/as/conversations/{conversation_id}/session", headers=headers)
    if resp.code != 200:
        return {}
    data = _resp_dict(resp)
    if data.get("code") != 0:
        return {}
    return _data_dict(data)


def _acp_headers(token: str, *, conn_id: str = "", with_auth: bool = False, is_post: bool = False) -> Dict[str, str]:
    """构造与浏览器一致的 ACP 请求头。

    HAR 抓取显示：浏览器对 sandbox 直连 /acp 的 GET/POST 均无需显式 Authorization
    （不可猜的 URL 即凭证），且带了完整的 CORS / 浏览器指纹头
    （sec-fetch-*、accept-encoding、accept-language 等）。网关（CloudStudio Gateway）
    会对缺少这些头的“非浏览器”请求返回 401，因此这里尽量还原浏览器头。
    若仍 401，则回退追加 Authorization: Bearer <token> 重试。
    """
    headers: Dict[str, str] = {
        "Accept": "text/event-stream" if not is_post else "application/json, text/event-stream",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Origin": "https://www.workbuddy.cn",
        "Referer": "https://www.workbuddy.cn/",
        "User-Agent": BASE_HEADERS["User-Agent"],
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "sec-ch-ua": '"Not=A?Brand";v="99", "Microsoft Edge";v="151", "Chromium";v="151"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "priority": "u=1, i",
    }
    if is_post:
        headers["Content-Type"] = "application/json"
    if conn_id:
        headers["Acp-Connection-Id"] = conn_id
    if with_auth and token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _acp_connect(h: Http, acp_url: str, stop_event: "threading.Event", token: str = "") -> Tuple[str, "threading.Thread", list]:
    """建立 ACP 连接：GET {acp_url}(SSE)。

    服务端在响应头返回 acp-connection-id；该 GET 连接即 SSE 通道，
    必须保持打开（后台线程持续读取），后续 POST 复用同一 acp-connection-id。
    返回 (acp_connection_id, sse_thread, sse_events)。
    若首轮带浏览器头仍 401，则追加 Authorization: Bearer <token> 重试。
    """
    import urllib.request as _urllib_req
    import urllib.error as _urllib_err

    # bj* 集群的 sandbox 网关要求 Bearer token；优先带 token，失败再回退无鉴权。
    auth_attempts = [True, False] if token else [False]
    last_exc: Any = None
    for with_auth in auth_attempts:
        headers = _acp_headers(token, with_auth=with_auth)
        req = _urllib_req.Request(acp_url, headers=headers, method="GET")
        try:
            resp = h.opener.open(req, timeout=30)  # type: ignore[attr-defined]  # 网关 SYN 黑洞时防主线程长期挂起
        except _urllib_err.HTTPError as e:
            last_exc = e
            if e.code == 401 and with_auth is True and token:
                _dbg(f"[workbuddy] ACP GET /acp 401（带 Bearer token），尝试无鉴权重试...")
                continue
            _dbg(f"[workbuddy] ACP GET /acp 连接失败: HTTP {e.code}")
            return "", None, []
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            _dbg(f"[workbuddy] ACP GET /acp 连接失败: {exc}")
            return "", None, []

        conn_id = resp.headers.get("acp-connection-id", "")
        if not conn_id:
            try:
                resp.close()
            except Exception:
                pass
            last_exc = "响应未返回 acp-connection-id"
            if with_auth is True and token:
                continue
            _dbg(f"[workbuddy] ACP GET /acp 连接失败: {last_exc}")
            return "", None, []

        sse_events: list = []

        def _drain():
            try:
                for raw in resp:
                    if stop_event.is_set():
                        break
                    sse_events.append(raw.decode("utf-8", "ignore"))
            except Exception:
                pass
            finally:
                try:
                    resp.close()
                except Exception:
                    pass

        t = threading.Thread(target=_drain, daemon=True)
        t.start()
        return conn_id, t, sse_events

    _dbg(f"[workbuddy] ACP GET /acp 连接失败: {last_exc}")
    return "", None, []


def _acp_call(h: Http, acp_url: str, conn_id: str, method: str, params: Dict[str, Any], rpc_id: int, token: str = "") -> int:
    """向 ACP endpoint 发送一次 JSON-RPC POST（initialize/session/load/session/prompt 等）。

    ACP endpoint 是 sandbox 直连地址；HAR 显示无需显式 Authorization（不可猜的 URL 即凭证），
    但需带完整浏览器头。若遇 401 则回退追加 Authorization: Bearer <token>。
    POST 返回 202(空)/200(SSE)，结果经 SSE 通道推送，这里只关心 HTTP 状态码。
    """
    import urllib.request as _urllib_req
    import urllib.error as _urllib_err
    payload = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = _acp_headers(token, conn_id=conn_id, is_post=True, with_auth=bool(token))
    req = _urllib_req.Request(acp_url, data=data, headers=headers, method="POST")

    def _drain_resp(r):
        try:
            while True:
                chunk = r.read(4096)
                if not chunk:
                    break
        except Exception:
            pass
        finally:
            try:
                r.close()
            except Exception:
                pass

    def _open():
        try:
            r = h.opener.open(req, timeout=30)  # type: ignore[attr-defined]  # 防挂起
            status = r.status
            # prompt 返回 200 SSE，会持续推送；放后台排空，避免阻塞主流程
            threading.Thread(target=_drain_resp, args=(r,), daemon=True).start()
            return status
        except _urllib_err.HTTPError as e:
            return e.code
        except Exception as exc:  # noqa: BLE001
            _dbg(f"[workbuddy] ACP {method} 调用异常: {exc}")
            return -1

    # 同步拿到状态码即可（响应体后台排空）
    return _open()


def _daily_meter_checkin(h: Http, cred: str) -> Tuple[str, bool]:
    """算力中心每日签到（确定性主逻辑，直接调用 API，不依赖 AI 对话）。

    早期版本即采用此方式：POST /billing/meter/daily-checkin 自包含地领取每日算力与连签天数。
    AI 对话仅作为辅助激活，真正的签到以本调用为准。
    返回 (描述文案, 是否签到成功)。
    """
    headers = _base_auth_headers(cred, referer=f"{BASE_URL}/profile/plans-usage")
    resp = h.request("POST", f"{BASE_URL}/billing/meter/daily-checkin", headers=headers, json_data={})
    data = _resp_dict(resp) if resp.code in (200, 400) else {}
    code = data.get("code")
    msg = data.get("msg", "")
    if resp.code == 200 and code == 0:
        d = _data_dict(data)
        credit = d.get("credit", 100)
        streak = d.get("streak_days", 1)
        return f"签到成功(+{credit}算力，连签{streak}天)", True
    if "已签到" in msg or code == 10001:
        return "今日已签到", True
    if resp.code != 200:
        return f"签到返回 HTTP {resp.code}", False
    return f"签到返回：{msg or '未知'}", False


def _run_conversation_and_wait(h: Http, cred: str, timeout_seconds: int = 240) -> Tuple[str, bool]:
    """创建对话任务 -> 通过 ACP 发送 prompt -> 等待 AI 完成 -> 轮询签到状态。

    返回 (描述文字, 是否签到成功)。
    """
    # 1. 创建 conversation
    conv = _create_conversation(h, cred)
    conv_id = conv.get("id")
    if not conv_id:
        _dbg("[workbuddy] 创建对话任务失败，无法激活签到面板")
        return "创建对话任务失败，无法激活签到面板", False

    _dbg(f"[workbuddy] 对话任务已创建，conversation_id={conv_id}")

    # 2. 获取 session 信息
    session_data = _get_conversation_session(h, cred, conv_id)
    e2b_endpoint = session_data.get("e2bEndpoint", "")
    session_id = session_data.get("sessionId", conv_id)
    if not e2b_endpoint:
        _dbg(f"[workbuddy] conversation_id={conv_id} 但无法获取 ACP endpoint，签到面板可能无法激活")
        return f"对话已创建 (ID:{conv_id}) 但无法获取 ACP endpoint，签到面板可能无法激活", False

    _dbg(f"[workbuddy] ACP endpoint: {e2b_endpoint}，session_id: {session_id}")
    _dbg(f"[workbuddy] session 配置(脱敏): {_safe_session_dump(session_data)}")

    # ACP 实际地址优先用 link（sandbox 直连 /acp），回退到 e2bEndpoint+/acp；
    # link 已含 /acp 后缀，无需再拼。
    acp_url = session_data.get("link") or f"{e2b_endpoint}/acp"
    if acp_url.endswith("/acp/acp"):
        acp_url = acp_url[:-4]  # 防止重复拼接
    token = session_data.get("token", "")

    # 1) 建立 ACP 连接：GET /acp(SSE)，服务端在响应头返回 acp-connection-id；
    #    该连接即 SSE 通道，需保持打开，后台线程持续读取。
    stop_event = threading.Event()
    conn_id, sse_thread, sse_events = _acp_connect(h, acp_url, stop_event, token)
    if not conn_id:
        return "ACP 连接建立失败（未返回 acp-connection-id）", False
    _dbg(f"[workbuddy] ACP 连接已建立 acp-connection-id={conn_id}")

    # 2) 依次发送 ACP JSON-RPC：initialize -> session/load -> session/prompt
    init_status = _acp_call(h, acp_url, conn_id, "initialize", {
        "protocolVersion": 1,
        "clientCapabilities": {
            "_meta": {"codebuddy.ai": {"cwd": "/workspace"}},
            "fs": {"readTextFile": False, "writeTextFile": False},
        },
    }, 0, token)
    _dbg(f"[workbuddy] initialize 状态码: {init_status}")

    load_status = _acp_call(h, acp_url, conn_id, "session/load", {
        "sessionId": conv_id,
        "cwd": "/workspace",
        "mcpServers": [],
    }, 1, token)
    _dbg(f"[workbuddy] session/load 状态码: {load_status}")

    prompt_payload = {
        "sessionId": conv_id,
        "prompt": [
            {"type": "text", "text": "hi", "_meta": {"codebuddy.ai": {"mode": "bypassPermissions"}}}
        ],
        "_meta": {
            "codebuddy.ai": {
                "mode": "bypassPermissions",
                "userMessageId": f"{conv_id}-user-{int(time.time() * 1000)}",
                "telemetryClientInfo": {"ideType": "WorkBuddy_Web", "ideName": "web_agents"},
            }
        },
    }
    prompt_status = _acp_call(h, acp_url, conn_id, "session/prompt", prompt_payload, 2, token)
    _dbg(f"[workbuddy] session/prompt 状态码: {prompt_status}")

    acp_codes = [init_status, load_status, prompt_status]
    if not all(c in (200, 202) for c in acp_codes):
        _dbg(f"[workbuddy] ACP 调用状态码异常: {acp_codes}")
        stop_event.set()
        return f"ACP 调用异常 (状态码 {acp_codes})，签到可能无法完成", False

    # 3) 保持 SSE 连接打开，等待 AI 完成；随后轮询签到状态
    _dbg(f"[workbuddy] 对话任务已创建并发送 prompt (conversation ID: {conv_id})，等待 AI 完成...")

    # 5. 轮询签到状态
    headers = _init_conversations_headers(cred)
    headers["Referer"] = f"{BASE_URL}/app/task/{conv_id}"

    start = time.time()
    last_status = None
    last_msg = f"对话任务已创建 (ID:{conv_id})，等待签到激活..."

    while time.time() - start < timeout_seconds:
        elapsed = time.time() - start
        _dbg(f"[workbuddy] [{elapsed:.0f}s] 轮询签到状态...")
        resp = h.request("POST", f"{BASE_URL}/billing/meter/checkin-status", headers=headers, json_data={})
        if resp.code != 200:
            last_msg = f"查询签到状态失败 (HTTP {resp.code})"
            _dbg(f"[workbuddy] 查询签到状态失败 (HTTP {resp.code})")
            time.sleep(5)
            continue

        data = _resp_dict(resp)
        if data.get("code") != 0:
            last_msg = f"签到状态异常：{data.get('msg', '未知')}"
            _dbg(f"[workbuddy] 签到状态异常：{data.get('msg', '未知')}")
            time.sleep(5)
            continue

        cd = _data_dict(data)
        active = cd.get("active", False)
        today_checked_in = cd.get("today_checked_in", False)
        streak_days = cd.get("streak_days", 0)
        daily_credit = cd.get("daily_credit", 0)
        is_streak_day = cd.get("is_streak_day", False)

        last_status = (active, today_checked_in)
        last_msg = (
            f"签到面板 active={active}, today_checked_in={today_checked_in}, "
            f"streak={streak_days}天"
        )

        _dbg(f"[workbuddy] [{elapsed:.0f}s] active={active}, today_checked_in={today_checked_in}, streak={streak_days}天, credit={daily_credit}")

        if today_checked_in:
            if is_streak_day:
                _dbg(f"[workbuddy] 签到成功 (+{daily_credit} 算力，连签 {streak_days} 天，连续签到日)")
                return (
                    f"签到成功 (+{daily_credit} 算力，连签 {streak_days} 天，连续签到日)",
                    True,
                )
            _dbg(f"[workbuddy] 签到成功 (+{daily_credit} 算力，连签 {streak_days} 天)")
            return f"签到成功 (+{daily_credit} 算力，连签 {streak_days} 天)", True

        if not active:
            last_msg = f"签到活动尚未激活 (active=False)，等待对话任务完成..."
        else:
            last_msg = (
                f"签到面板已激活，今日尚未签到 (today_checked_in=False)，等待任务完成..."
            )

        time.sleep(5)

    # 超时：关闭 ACP SSE 连接
    stop_event.set()
    if last_status:
        # checked_in 为真时轮询循环内已提前 return，这里只会是「未签」状态
        active, _checked_in = last_status
        if active:
            _dbg(f"[workbuddy] 对话任务已激活但 {timeout_seconds}s 内未完成签到")
            return f"对话任务已激活但 {timeout_seconds}s 内未完成签到", False
        _dbg(f"[workbuddy] 对话任务未激活签到面板，{timeout_seconds}s 超时")
        return f"对话任务未激活签到面板，{timeout_seconds}s 超时", False
    _dbg(f"[workbuddy] 轮询超时 ({timeout_seconds}s)，无法获知签到状态")
    return f"轮询超时 ({timeout_seconds}s)，无法获知签到状态", False


def _get_growth_profile(h: Http, cred: str) -> Dict[str, Any]:
    """获取成长等级与任务进度。"""
    headers = _base_auth_headers(cred)
    resp = h.request("GET", f"{BASE_URL}/v2/activity/growth/profile", headers=headers)
    if resp.code != 200:
        return {}
    data = _resp_dict(resp)
    return _data_dict(data) if data.get("code") == 0 else {}


def _redeem_rewards(h: Http, cred: str) -> Tuple[str, int]:
    """活动一：检查连登档位并执行兑换。

    返回: (描述文字, 新增抽奖机会数)
    """
    headers = _base_auth_headers(cred)

    resp = h.request("GET", f"{BASE_URL}/activity/growth/streak", headers=headers)
    if resp.code != 200:
        return "查询连登状态失败", 0

    data = _resp_dict(resp)
    if data.get("code") != 0:
        return "连登数据异常", 0

    streak_data = _data_dict(data)
    streak = _data_dict(streak_data, "streak")
    month_days = streak.get("month_total_days", 0)
    redemption_status = _data_dict(streak_data, "redemption_status")

    tiers_config = [
        ("7d", "入门档(7天)", 7),
        ("14d", "进阶档(14天)", 14),
        ("28d", "巅峰档(28天)", 28),
    ]

    redeemed_msgs: List[str] = []
    total_chances_gained = 0

    for tier_code, tier_name, min_days in tiers_config:
        status = redemption_status.get(f"tier_{tier_code}_status")
        count = redemption_status.get(f"tier_{tier_code}_count", 0)

        # 可兑换条件：状态为 claimable，或者未兑换且当月天数达标
        if status == "claimable" or (count == 0 and month_days >= min_days):
            client_token = f"redeem-{tier_code}-{uuid.uuid4()}"
            redeem_resp = h.request(
                "POST",
                f"{BASE_URL}/activity/growth/redeem",
                headers=headers,
                json_data={"tier": tier_code, "client_token": client_token},
            )
            if redeem_resp.code == 200:
                r_json = _resp_dict(redeem_resp)
                if r_json.get("code") == 0:
                    r_data = _data_dict(r_json)
                    energy = r_data.get("energy_granted", 0)
                    cards = r_data.get("cards_granted", 0)
                    credit = r_data.get("credit_granted", 0)
                    chances = r_data.get("chances_granted", 0)
                    total_chances_gained += chances
                    reward_parts = []
                    if energy:
                        reward_parts.append(f"能量+{energy}")
                    if cards:
                        reward_parts.append(f"补登卡+{cards}")
                    if credit:
                        reward_parts.append(f"积分+{credit}")
                    if chances:
                        reward_parts.append(f"抽奖+{chances}")
                    redeemed_msgs.append(f"兑换【{tier_name}】({', '.join(reward_parts)})")
                else:
                    redeemed_msgs.append(f"兑换【{tier_name}】失败({r_json.get('msg', '未知')})")
            else:
                # 非 200（含网络错误 -1）：显式记录，不再静默掉落
                redeemed_msgs.append(f"兑换【{tier_name}】失败(HTTP {redeem_resp.code})")

    # 统计已兑换和未达标状态
    claimed_tiers = [t_name for t_code, t_name, _ in tiers_config if redemption_status.get(f"tier_{t_code}_status") == "claimed"]
    streak_desc = f"当月连登 {month_days} 天"

    if redeemed_msgs:
        return f"{streak_desc} | " + "，".join(redeemed_msgs), total_chances_gained
    elif claimed_tiers:
        return f"{streak_desc} (已兑: {', '.join(claimed_tiers)})", 0
    else:
        return f"{streak_desc} (未到兑换档位)", 0


def _draw_lottery(h: Http, cred: str) -> str:
    """活动一：查询抽奖剩余次数，并自动执行抽奖（次数为 0 时跳过）。"""
    headers = _base_auth_headers(cred)

    # 查询剩余抽奖次数（chances/summary 双接口兜底）
    resp = h.request("GET", f"{BASE_URL}/activity/growth/lottery/chances", headers=headers)
    chances = None
    if resp.code == 200:
        chances = _data_dict(_resp_dict(resp)).get("balance")
    if chances is None:
        sum_resp = h.request("GET", f"{BASE_URL}/activity/growth/lottery/summary", headers=headers)
        if sum_resp.code == 200:
            chances = _data_dict(_resp_dict(sum_resp)).get("chances")

    if chances is None:
        # 查询失败不能伪装成「0 次（无需抽奖）」——当日抽奖机会会被静默浪费
        return "抽奖次数查询失败（今日抽奖未执行，请排查）"

    if chances <= 0:
        return "抽奖机会 0 次（无需抽奖）"

    prizes: List[str] = []
    success_draws = 0

    # 上限 20 次防服务端异常大值把任务拖到超时
    for i in range(min(chances, 20)):
        client_token = f"draw-{uuid.uuid4()}"
        draw_resp = h.request(
            "POST",
            f"{BASE_URL}/activity/growth/lottery/draw",
            headers=headers,
            json_data={"client_token": client_token},
        )
        if draw_resp.code == 200:
            d_json = _resp_dict(draw_resp)
            if d_json.get("code") == 0:
                p_data = _data_dict(d_json)
                p_name = p_data.get("prize_name") or f"{p_data.get('credit_amount', 0)}积分"
                prizes.append(p_name)
                success_draws += 1
            else:
                prizes.append(f"失败({d_json.get('msg', '错误')})")
        else:
            prizes.append(f"HTTP {draw_resp.code}")
        time.sleep(0.5)

    return f"完成 {success_draws}/{chances} 次抽奖：{', '.join(prizes)}"


def _claim_travel_reward(h: Http, headers: Dict[str, str], travel_data: Dict[str, Any], loc_name: str) -> Tuple[bool, str]:
    """回访领取放风奖励，返回 (是否领取成功/已领取, 可读的结果文案)。

    礼物 = 猫咪带回的 letter（来信，含 guide_text） + reward_credit 积分。
    处理幂等：若服务端判定已领取，按“已领取”处理而非报错（计为成功）。
    """
    claim_resp = h.request("POST", f"{BASE_URL}/activity/growth/buddy/travel/claim", headers=headers, json_data={})
    if claim_resp.code != 200:
        return False, f"回访领奖失败（HTTP {claim_resp.code}）"
    cj = _resp_dict(claim_resp)
    if cj.get("code") != 0:
        msg = str(cj.get("msg", ""))
        # 匹配词必须精确：单字符「已」/裸「重复」会命中「今日次数已达上限」等错误 → 假成功、奖励静默丢失
        if is_already_signed(msg, ("已经领取", "重复领取", "已领过")):
            return True, "放风奖励（已领取，无需重复领取）"
        return False, f"回访领奖失败：{msg or cj.get('code')}"
    c_data = _data_dict(cj)
    credit = c_data.get("reward_credit") or 0
    # letter 优先取领取响应，回退到状态里的（arrived 态状态里已带 letter）
    letter = c_data.get("letter") or travel_data.get("letter")
    letter_info = ""
    if letter:
        guide = letter.get("guide_text") or ""
        if guide:
            letter_info = f"，收到来信《{guide}》"
        else:
            letter_info = "，收到来信"
    return True, f"已领取【{loc_name}】放风奖励（+{credit} 积分{letter_info}）"


def _is_no_relay() -> bool:
    return env_bool("WORKBUDDY_NO_RELAY")


def _schedule_travel_claim(remaining_seconds: int) -> str:
    """通过 QStash 延时 Webhook 触发 repository_dispatch，调度下一轮工作流接力领取放风奖励。

    不在本地阻塞等待放风时长——改为提取剩余秒数后通过 QStash 延时发布，
    由下一轮 workbuddy.yml 接力发现 arrived 状态后自动领奖，避免长时间占用 Runner。
    （QStash publish URL 拼接 / 鉴权透传统一在 common.schedule_repo_dispatch）

    内联模式（WORKBUDDY_NO_RELAY=1，orchestrator 注入）：不再调度接力，改为打印
    TRAVEL_EVENT 机器行供 orchestrator 解析后排入回程领奖事件。
    """
    if _is_no_relay():
        # orchestrator 解析此行后按 arrive_at+60s 排入 claim 事件
        arrive_at = int(time.time()) + remaining_seconds
        print(f"TRAVEL_EVENT state=traveling arrive_at={arrive_at}")
        return "已记录放风回程（内联模式，等待 orchestrator 定时回访）"
    delay = remaining_seconds + 300  # 5 分钟缓冲，防止时钟/接口延迟导致提前到达
    ok, detail = schedule_repo_dispatch("workbuddy_travel_claim", delay)
    if ok:
        eta = int(time.time()) + delay
        return f"已调度下一轮领奖（{delay}秒后，约 {_format_beijing_time(eta)}）"
    if detail.startswith("未配置"):
        return f"{detail}，将等待下次定时触发"
    return f"⚠️ 延时调度失败（{detail}）"


def _handle_traveling(h: Http, headers: Dict[str, str], travel_data: Dict[str, Any], loc_name: str, wait_travel: bool) -> str:
    """处理「放风中」状态：若已到达则立即领奖，否则调度 QStash 延时触发下一轮领取。

    不再在本地阻塞等待放风时长——改为提取剩余时间后通过 QStash 延时 Webhook
    触发 repository_dispatch，由下一轮工作流接力领奖，避免长时间占用 Runner。
    """
    arrive_at = travel_data.get("arrive_at", 0)
    server_now = travel_data.get("server_now", int(time.time()))
    remaining_seconds = max(0, arrive_at - server_now)

    if remaining_seconds == 0:
        print(f"🔔 放风已完成，正在自动回访【{loc_name}】领取奖励...")
        claim_ok, claim_msg = _claim_travel_reward(h, headers, travel_data, loc_name)
        if not claim_ok:
            time.sleep(3)
            claim_ok, claim_msg = _claim_travel_reward(h, headers, travel_data, loc_name)
        if not claim_ok:
            # 领取失败：调度 5 分钟后的接力 run 重试，奖励不静默丢到次日
            return f"{claim_msg}；{_schedule_travel_claim(0)}"
        return claim_msg

    if wait_travel:
        schedule_msg = _schedule_travel_claim(remaining_seconds)
    else:
        schedule_msg = "不调度延时领取（WORKBUDDY_WAIT_TRAVEL=false）"
    return (
        f"放风中（【{loc_name}】，剩余 {_format_countdown(remaining_seconds)}，"
        f"预计 {_format_beijing_time(arrive_at)} 返回）| {schedule_msg}"
    )


def _process_travel(h: Http, cred: str, wait_travel: bool = True) -> str:
    """活动二：动态跟踪放风并自动回访领取礼物（含猫咪来信）。

    同一天内若放风额度未用完（daily_limit_reached=False），领取上一场礼物后会继续派遣下一场，
    形成「领取 → 再出发 →（下个 CI run 领取）」的链路，直到当天放风次数达上限，当天任务即完成。
    不依赖硬编码时长，完全基于接口返回的 (arrive_at - server_now) 动态等待并回访。
    """
    headers = _base_auth_headers(cred)

    actions: List[str] = []
    # 同一场次（一次到达）的奖励只领取一次，避免接口在领取后仍未清掉 arrived 态时重复领奖
    claimed_this_arrival = False

    # 单 run 内最多处理几场：受放风时长（通常数小时）限制，一场往往已占满等待窗口，
    # 多轮主要用于「领取上一场 → 派遣下一场」的衔接；上限防止异常时死循环。
    MAX_ROUNDS = 3
    for _ in range(MAX_ROUNDS):
        resp = h.request("GET", f"{BASE_URL}/activity/growth/buddy/travel/status", headers=headers)
        if resp.code != 200:
            actions.append(f"查询放风状态失败（HTTP {resp.code}）")
            break
        data = _resp_dict(resp)
        if data.get("code") != 0:
            actions.append(f"查询放风状态异常：{data.get('msg', '未知错误')}")
            break

        travel_data = _data_dict(data)
        state = travel_data.get("state", "idle")
        daily_limit_reached = travel_data.get("daily_limit_reached", False)
        loc = travel_data.get("location", {}) or {}
        loc_name = loc.get("name", "放风地点")

        # 1) 已返回 -> 领取礼物（含来信），每场次仅领一次
        if state == "arrived":
            if claimed_this_arrival:
                # 领取后接口仍未清掉 arrived 态：不再重复领奖，避免重复发放
                if daily_limit_reached:
                    actions.append("今日放风次数已达上限，今日任务已完成")
                    break
                actions.append("放风奖励已领取，等待状态刷新")
                break
            claim_ok, claim_msg = _claim_travel_reward(h, headers, travel_data, loc_name)
            if not claim_ok:
                time.sleep(3)
                claim_ok, claim_msg = _claim_travel_reward(h, headers, travel_data, loc_name)
            if not claim_ok:
                # 领取失败不置已领标记（否则本场永不重试）：调度 5 分钟后接力重领，
                # 奖励不再因一次 5xx/网络抖动静默丢到次日 00:50
                actions.append(f"{claim_msg}；{_schedule_travel_claim(0)}")
                break
            actions.append(claim_msg)
            claimed_this_arrival = True
            if daily_limit_reached:
                actions.append("今日放风次数已达上限，今日任务已完成")
                break
            # 当天还能继续放风 -> 下一轮重新查询，若已转为 idle 则派遣下一场
            continue

        # 进入新场次（空闲/放风中）后，重置领取标记
        claimed_this_arrival = False

        # 2) 空闲 -> 检查额度并派遣出发
        if state == "idle":
            if daily_limit_reached:
                actions.append("今日放风次数已达上限，今日任务已完成")
                break
            depart_resp = h.request(
                "POST",
                f"{BASE_URL}/activity/growth/buddy/travel/depart",
                headers=headers,
                json_data={"location_id": 1},
            )
            if depart_resp.code == 200 and _resp_dict(depart_resp).get("code") == 0:
                depart_data = _data_dict(_resp_dict(depart_resp))
                travel_data = depart_data
                state = "traveling"
                loc = depart_data.get("location", {}) or {}
                loc_name = loc.get("name", "放风地点")
                dur = loc.get("duration_hours") or depart_data.get("duration_hours") or "?"
                actions.append(f"派遣猫咪出发放风（【{loc_name}】，预计时长 {dur}小时）")
            else:
                err_msg = _resp_dict(depart_resp).get("msg") or f"HTTP {depart_resp.code}"
                actions.append(f"派遣出发失败（{err_msg}）")
                break

        # 3) 放风中 -> 动态等待并在返回后领取（受窗口限制，通常本场处理完即结束）
        if state == "traveling":
            actions.append(_handle_traveling(h, headers, travel_data, loc_name, wait_travel))
            break

    return " | ".join(actions) if actions else "状态：idle"


def _get_energy(h: Http, cred: str) -> Dict[str, Any]:
    """获取能量数据。"""
    headers = _base_auth_headers(cred)
    resp = h.request("GET", f"{BASE_URL}/activity/growth/energy", headers=headers)
    if resp.code != 200:
        return {}
    data = _resp_dict(resp)
    return _data_dict(data) if data.get("code") == 0 else {}


def _get_buddy_quota(h: Http, cred: str) -> Dict[str, Any]:
    """获取猫咪开启配额。"""
    headers = _base_auth_headers(cred)
    resp = h.request("GET", f"{BASE_URL}/activity/growth/buddy/quota", headers=headers)
    if resp.code != 200:
        return {}
    data = _resp_dict(resp)
    return _data_dict(data) if data.get("code") == 0 else {}


def _get_badges(h: Http, cred: str) -> Tuple[int, int]:
    """获取徽章数量，返回 (已获得数, 总数)。"""
    headers = _base_auth_headers(cred)
    resp = h.request("GET", f"{BASE_URL}/v2/activity/growth/badges", headers=headers)
    if resp.code != 200:
        return 0, 0
    data = _resp_dict(resp)
    badges = _data_dict(_data_dict(data)).get("badges", [])
    if not isinstance(badges, list):
        return 0, 0
    earned_count = sum(1 for b in badges if isinstance(b, dict) and b.get("earned"))
    return earned_count, len(badges)


def _now_beijing_str() -> str:
    """返回北京时间（Asia/Shanghai）字符串，用于资源包查询的到期时间区间起点。"""
    try:
        import datetime as _dt
        return _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def _get_user_resource(h: Http, cred: str) -> Dict[str, Any]:
    """获取账号算力（积分）余额。

    直接用服务端在响应里算好的 `TotalDosage` 作为余额，不做本地累加。
    前端余额口径会排除「个人体验版」等非周期额度资源包（CapacityType==4），
    因此这里先列出全部资源包、剔除该类型后，再用其 PackageCode 二次查询，
    取服务端返回的 TotalDosage 作为真实可用余额。
    """
    headers = _base_auth_headers(cred)
    base_body = {
        "PageNumber": 1,
        "PageSize": 200,
        "ProductCode": "p_tcaca",
        "Status": [0],
        "OrderBy": "endTime",
        "SortBy": "desc",
    }
    try:
        resp = h.request(
            "POST",
            f"{BASE_URL}/billing/meter/get-user-resource",
            headers=headers,
            json_data=base_body,
        )
        if resp.code != 200:
            return {}
        data = _resp_dict(resp)
        if data.get("code") != 0:
            return {}
        inner = (data.get("data", {}) or {}).get("Response", {}).get("Data", {}) or {}

        # 剔除「个人体验版」(CapacityType==4) 等非周期额度包，仅保留计入余额的资源包
        codes = [
            a.get("PackageCode")
            for a in (inner.get("Accounts") or [])
            if isinstance(a, dict) and a.get("PackageCode")
            and int(a.get("CapacityType", 0) or 0) != 4
        ]
        if not codes:
            return inner

        # 用筛选后的 PackageCode 二次查询，取服务端算好的 TotalDosage 作为余额
        body2 = dict(base_body)
        body2["PackageCodes"] = codes
        body2["PackageEndTimeRangeBegin"] = _now_beijing_str()
        body2["PackageEndTimeRangeEnd"] = "2127-08-16 05:05:17"
        resp2 = h.request(
            "POST",
            f"{BASE_URL}/billing/meter/get-user-resource",
            headers=headers,
            json_data=body2,
        )
        if resp2.code == 200:
            d2 = resp2.json({})
            if d2.get("code") == 0:
                return (d2.get("data", {}) or {}).get("Response", {}).get("Data", {}) or {}
        return inner
    except Exception:
        return {}


def _parse_ts_bjt(v: Any) -> Optional[float]:
    """时间戳容错解析：秒/毫秒 epoch 数字或 'YYYY-MM-DD HH:MM:SS' 字符串 → epoch 秒。

    移植自 workbuddy-switch credits.rs 的 parse_timestamp_ms（资源包到期字段
    有秒/毫秒/日期字符串多种形态）。
    """
    if v is None:
        return None
    if isinstance(v, (int, float)):
        ts = float(v)
        return ts / 1000.0 if ts > 1e12 else ts
    s = str(v).strip()
    if not s:
        return None
    if s.replace(".", "", 1).isdigit():
        n = float(s)
        return n / 1000.0 if n > 1e12 else n
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return dt.datetime.strptime(s[:19], fmt).replace(
                tzinfo=dt.timezone(dt.timedelta(hours=8))
            ).timestamp()
        except ValueError:
            continue
    return None


def _get_credit_expiry(h: Http, cred: str, soon_days: int = 7) -> str:
    """算力到期监控（移植自 workbuddy-switch credits.rs，EXPIRING_SOON_DAYS=7）。

    列出活跃资源包（剔除「个人体验版」CapacityType==4），7 天内到期的剩余算力
    提醒「用掉否则作废」；无临期包时返回空串，不进卡片。
    """
    headers = _base_auth_headers(cred, referer=f"{BASE_URL}/profile/plans-usage")
    try:
        resp = h.request(
            "POST",
            f"{BASE_URL}/billing/meter/get-user-resource",
            headers=headers,
            json_data={
                "PageNumber": 1, "PageSize": 200, "ProductCode": "p_tcaca",
                "Status": [0], "OrderBy": "endTime", "SortBy": "asc",
            },
        )
        if resp.code != 200:
            return ""
        data = _resp_dict(resp)
        if data.get("code") != 0:
            return ""
        inner = (data.get("data", {}) or {}).get("Response", {}).get("Data", {}) or {}
    except Exception:  # noqa: BLE001
        return ""

    now = time.time()
    soon: List[Tuple[float, float, str]] = []
    for a in inner.get("Accounts") or []:
        if not isinstance(a, dict) or int(a.get("CapacityType", 0) or 0) == 4:
            continue

        def _first_num(*keys: str) -> float:
            # 闭包直接读当前迭代变量 a（isinstance 守卫保证是 dict，且定义后立即调用）；
            # 不要用默认参数绑定 a——位置调用会把第一个 key 填进 acc 导致 'str' has no 'get'
            for k in keys:
                v = a.get(k)
                if v is None:
                    continue
                try:
                    return float(str(v).replace(",", ""))
                except (TypeError, ValueError):
                    continue
            return 0.0

        remaining = _first_num(
            "CycleCapacityRemainPrecise", "CycleCapacityRemain",
            "CapacityRemainPrecise", "CapacityRemain",
        )
        expire_ts = None
        for k in ("DeductionEndTime", "expiredTime", "CycleEndTime"):
            expire_ts = _parse_ts_bjt(a.get(k))
            if expire_ts:
                break
        if expire_ts and now < expire_ts <= now + soon_days * 86400 and remaining > 0:
            soon.append((expire_ts, remaining, str(a.get("PackageName") or "资源包")))
    if not soon:
        return ""
    soon.sort()
    ts, rem, name = soon[0]
    days = (ts - now) / 86400
    date_str = dt.datetime.fromtimestamp(ts, tz=dt.timezone(dt.timedelta(hours=8))).strftime("%m-%d")
    extra = f"（另有 {len(soon) - 1} 包）" if len(soon) > 1 else ""
    return f"{rem:g} 算力 {days:.0f} 天后（{date_str}）到期——用掉否则作废{extra}"


def _run_one(cred: str, idx: int, total: int, wait_travel: bool) -> Tuple[bool, str]:
    """执行单个账号的完整独立流程。"""
    h = Http()

    # 1. 用户信息与成长等级
    uid, nickname = _get_account_info(h, cred)
    profile = _get_growth_profile(h, cred)
    level_name = profile.get("level_name") or f"LV.{profile.get('level', 1)}"
    completed = profile.get("completed", 0)
    total_tasks = profile.get("total", 0)
    task_progress = f"任务 {completed}/{total_tasks}" if total_tasks else ""

    # 2. 算力中心每日签到（确定性主逻辑：直接调用 API）
    daily_msg, daily_ok = _daily_meter_checkin(h, cred)

    # 3. AI 对话任务（辅助激活签到面板，尽力而为，不阻塞主流程）
    # 主 API 签到已成功时缩短轮询：辅助通道价值有限，省时间给兑换/抽奖/放风链路
    conv_timeout = 45 if daily_ok else 120
    conv_msg, conv_ok = _run_conversation_and_wait(h, cred, timeout_seconds=conv_timeout)
    checkin_ok = daily_ok or conv_ok
    # AI 对话是辅助通道：主 API 签到已成功时不把辅助通道的超时噪音带进摘要
    #（避免「签到成功｜超时」这种读起来像报错的组合），仅主通道失败时附详情排查
    checkin_msg = daily_msg if daily_ok else f"{daily_msg}｜AI对话：{conv_msg}"

    # 3. 活动一：连登兑换与抽奖追踪（取决于签到是否达成）
    redeem_msg, _ = _redeem_rewards(h, cred)
    lottery_msg = _draw_lottery(h, cred)

    # 4. 活动二：动态跟踪放风时间与自动回访领奖
    travel_msg = _process_travel(h, cred, wait_travel=wait_travel)

    # 5. 资产统计
    energy = _get_energy(h, cred)
    energy_bal = energy.get("balance", 0)
    quota = _get_buddy_quota(h, cred)
    quota_bal = quota.get("balance", 0)
    earned_badges, total_badges = _get_badges(h, cred)
    badge_str = f"{earned_badges}/{total_badges}" if total_badges else str(earned_badges)

    # 6. 积分（算力）余额
    # 直接取服务端在响应里算好的 TotalDosage（已按前端口径剔除「个人体验版」等非周期额度包），即为真实可用余额
    expiry_msg = _get_credit_expiry(h, cred)

    resource = _get_user_resource(h, cred)
    total_dosage = resource.get("TotalDosage")
    if total_dosage is not None:
        try:
            credit_str = f"积分(算力)余额 {float(total_dosage):g}"
        except (TypeError, ValueError):
            credit_str = "积分(算力)余额：获取失败"
    else:
        credit_str = "积分(算力)余额：获取失败"

    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    masked_name = mask_str(nickname)
    masked_uid = mask_str(uid)

    lines = [
        f"{prefix_label}用户【{masked_name}】（UID: {masked_uid}）",
        f"• AI对话签到：{checkin_msg}",
        f"• 成长等级：{level_name}" + (f" ({task_progress})" if task_progress else ""),
        f"• 连登兑换：{redeem_msg}",
        f"• 抽奖活动：{lottery_msg}",
        f"• 猫咪放风：{travel_msg}",
        f"• {credit_str}",
        *(  # 无临期包时该行整体省略，保持卡片干净
            [f"• 算力到期：{expiry_msg}"] if expiry_msg else []
        ),
        f"• 资产：能量 {energy_bal} | 猫咪配额 {quota_bal} | 徽章 {badge_str}",
    ]
    return checkin_ok, "\n".join(lines)


def _resolve_credential(h: Http, idx: int, refresh_token: str, cookie: str) -> Tuple[str, List[str]]:
    """解析单账号凭据：refresh_token 优先（Redis 滚动票 > env secret，换新+数据库回写），Cookie 兜底。

    返回 (cred, notes)。refresh 续期失败但配置了 Cookie 时回退（不中断签到），
    续期错误文案进入 notes（alert_levels 据此判黄色「续期失败请检查」）。
    """
    notes: List[str] = []
    redis_rt = _load_refresh_token_redis(idx)
    candidates: List[str] = []
    if redis_rt and redis_rt != refresh_token:
        candidates.append(redis_rt)  # 数据库里的票更新（Secret 回写可能被 403 挡住）
    if refresh_token:
        candidates.append(refresh_token)
    for cand in candidates:
        try:
            cred, new_rt = _refresh_access_token(h, cand)
            persist_note = _persist_refresh_token(idx, new_rt)
            if persist_note:
                notes.append(persist_note)
            return cred, notes
        except Exception as exc:  # noqa: BLE001
            notes.append(f"⚠️ {exc}")
    if candidates:
        if not cookie:
            raise RuntimeError(notes[-1].removeprefix("⚠️ ") if notes else "refresh_token 续期失败")
        notes.append("已回退 Cookie 凭据（7 天硬上限，请尽快重跑 workbuddy_device_login.py）")
    if not cookie:
        raise RuntimeError(
            f"缺少 {PREFIX}REFRESH_TOKEN_{idx}/{PREFIX}COOKIE_{idx}（secret 未配置或为空），"
            "请运行 scripts/workbuddy_device_login.py 获取 refresh_token 或粘贴浏览器 Cookie"
        )
    return cookie, notes


def main():
    print("【WorkBuddy 签到与成长中心】")
    cookies = env_seq(PREFIX, "cookie", required=False)
    refresh_tokens = env_seq(PREFIX, "refresh_token", required=False)
    if not cookies and not refresh_tokens:
        raise RuntimeError(
            f"缺少 {PREFIX}REFRESH_TOKEN_1/{PREFIX}COOKIE_1（secret 未配置或为空），"
            "请运行 scripts/workbuddy_device_login.py 获取 refresh_token 或粘贴浏览器 Cookie"
        )

    # 默认开启动态放风跟踪与自动回访领奖
    wait_travel = os.getenv("WORKBUDDY_WAIT_TRAVEL", "true").lower() in ("true", "1", "yes")

    total = max(len(refresh_tokens), len(cookies))
    if total > 1:
        print(f"共发现 {total} 个账号，开始依次独立执行与动态回访...")

    results = []
    for idx in range(1, total + 1):
        refresh_token = refresh_tokens[idx - 1] if idx <= len(refresh_tokens) else ""
        cookie = cookies[idx - 1] if idx <= len(cookies) else ""
        try:
            h = Http()
            cred, notes = _resolve_credential(h, idx, refresh_token, cookie)
            for note in notes:
                print(f"[{idx}/{total}] {note}" if total > 1 else note)
            ok, msg = _run_one(cred, idx, total, wait_travel=wait_travel)
            if ok:
                _DEBUG_LINES.clear()  # 成功：丢弃过程日志，保持邮件卡片干净
            else:
                _flush_dbg()          # 失败：附带调试轨迹便于排查
            print(msg)
            results.append((ok, msg))
        except Exception as e:
            _dbg("[workbuddy] " + traceback.format_exc().replace("\n", "\n[workbuddy] "))
            _flush_dbg()
            err_msg = f"[{idx}/{total}] 签到失败：{e}" if total > 1 else f"签到失败：{e}"
            print(err_msg)
            results.append((False, err_msg))

    ok_count = sum(1 for ok, _ in results if ok)
    if total > 1:
        print(f"签到总结：成功 {ok_count}/{total}")

    if ok_count != total:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
