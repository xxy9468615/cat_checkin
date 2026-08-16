#!/usr/bin/env python3
# cron: 0 10 * * *
# new Env("HW 开发者 签到")
"""HW 开发者空间 / 开发者中心每日签到与每日任务。

会话自愈（Cookie 分层方案）：
  L1 纯 HTTP 快路径：HW_DEV_cookie（含 csrf-eco 字段）。
  L2 保活探测：hw-keepalive workflow 每 5h 调 hw_keepalive.py 探测会话。
  L3 Playwright 静默重登：门户会话失效（403 HD.92010003）时，用 HW_DEV_STATE
     （storage_state JSON，由 scripts/hw_login.py 本地引导生成）加载浏览器
     上下文，访问门户触发 SSO 静默续期后重跑签到；新 Cookie/state 导出到
     .heal/（HW_DEV_HEAL_DIR 可覆盖），由 workflow 用 GH_PAT 回写 Secrets。
  自动重登（账密）不可行：账号体系 OAuth+CAS 有滑块/短信风控，且 IAM Token 与社区接口不通用。

业务流程：
1. 从 cookie 提取 csrf-eco（与 get-ainfo 响应头 csrf 同值）
2. 查询用户信息（memAlias / memName）
3. 执行每日签到并查询连签状态（HD.67520093 视为今日已签到）
4. AI Shell 每日任务：自动完成一次真实使用并回查任务完成状态
   （内部实现由本地源码生成，细节见本地文档）
5. 查询开发者豆余额
环境变量：
  - HW_DEV_COOKIE / HW_DEV_cookie（需包含 csrf-eco 字段）
  - HW_DEV_STATE          storage_state JSON（自愈用，本地引导脚本生成）
  - HW_DEV_AUTOHEAL       true/false，默认 true（仅单账号时生效）
  - HW_DEV_HEAL_DIR       自愈导出目录，默认 .heal
  - 多账号：换行或 && 分隔（多账号时自愈关闭）
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from common import Browser, Http, env, main_guard, mask_str

PREFIX = "HW_DEV_"
BASE_URL = "https://devdata.huaweicloud.com"
UBA_BASE_URL = "https://uba.huaweicloud.com"
PORTAL_URL = "https://developer.huaweicloud.com/"
# 实测（2026-08）门户"登录"按钮跳转的 SSO 入口；SSO 会话有效时会免密回跳门户并建立会话
AUTH_LOGIN_URL = (
    "https://auth.huaweicloud.com/authui/login.html"
    "?service=https%3A%2F%2Fdeveloper.huaweicloud.com%2F&locale=zh-cn"
)
HEAL_DIR = os.getenv("HW_DEV_HEAL_DIR", ".heal").strip() or ".heal"

# 轮询 get-ainfo 判定静默重登成功的总时长与间隔
HEAL_LOGIN_TIMEOUT = 90
HEAL_POLL_INTERVAL = 3

# 落到这些路径说明 SSO 也失效了（需要人工重新引导）
LOGIN_PAGE_MARKERS = ("/cas/", "login", "oauth", "passport", "verify")


class SessionExpiredError(RuntimeError):
    """门户会话 Cookie 已失效（401/403，如 HD.92010003 token not found），可尝试 L3 自愈。"""

BASE_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Origin": "https://developer.huaweicloud.com",
    "Referer": "https://developer.huaweicloud.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
    "sec-ch-ua": '"Not=A?Brand";v="99", "Microsoft Edge";v="151", "Chromium";v="151"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
}


def _parse_cookies(raw: str) -> List[str]:
    """解析多账号 Cookie，支持换行或 && 分隔。"""
    if not raw:
        return []
    return [x.strip() for x in raw.replace("&&", "\n").splitlines() if x.strip()]


def _extract_csrf_eco(cookie: str) -> str:
    """从 cookie 字符串中提取 csrf-eco 字段的值。"""
    for pair in cookie.split(";"):
        pair = pair.strip()
        if pair.startswith("csrf-eco="):
            return pair[len("csrf-eco="):].strip()
    return ""


def _get_csrf_token(h: Http, cookie: str) -> str:
    """获取 csrf token。

    优先从 cookie 直接提取 csrf-eco（与 get-ainfo 响应头 csrf 同值），
    提取失败时回退调用 get-ainfo（需要 csrf-eco 才能成功）。
    """
    # 策略 1：直接从 cookie 提取 csrf-eco（绕过 get-ainfo，避免 WAF 404）
    csrf = _extract_csrf_eco(cookie)
    if csrf:
        return csrf

    # 策略 2：回退调用 get-ainfo 获取响应头 csrf
    headers = dict(BASE_HEADERS)
    headers["Cookie"] = cookie
    headers["Content-Type"] = "text/plain"

    resp = h.request(
        "GET",
        f"{BASE_URL}/api/get-ainfo",
        headers=headers,
    )
    if resp.code == 404:
        raise RuntimeError(
            "获取 csrf token 失败：HTTP 404（WAF 拦截，"
            "cookie 中缺少 csrf-eco 字段，请重新完整复制浏览器 cookie）"
        )
    if resp.code != 200:
        raise RuntimeError(f"获取 csrf token 失败：HTTP {resp.code}")

    if resp.headers:
        csrf = resp.headers.get("csrf") or resp.headers.get("CSRF") or ""
    if not csrf:
        raise RuntimeError("未在响应头中找到 csrf token，可能接口已变更或被拦截")
    return csrf.strip()


def _get_personal_info(h: Http, cookie: str, csrf: str) -> Tuple[str, str]:
    """获取用户信息，返回 (memAlias, memName)。"""
    headers = dict(BASE_HEADERS)
    headers.update({
        "Cookie": cookie,
        "csrf": csrf,
    })
    resp = h.request(
        "GET",
        f"{BASE_URL}/rest/developer/fwdu/rest/developer/user/hdcommunityservice/v1/member/get-personal-info",
        headers=headers,
    )
    if resp.code in (301, 302, 401, 403):
        body_snip = resp.text.strip()[:160]
        hint = f" 响应: {body_snip}" if body_snip else ""
        raise SessionExpiredError(f"门户会话已失效（HTTP {resp.code}{hint}），请更新 Cookie 或依赖自愈")
    if resp.code != 200:
        raise RuntimeError(f"获取个人信息失败：HTTP {resp.code}")

    data = resp.json({})
    if not isinstance(data, dict):
        raise RuntimeError(f"获取个人信息返回异常：{resp.text[:150]}")

    alias = data.get("memAlias") or data.get("account_name") or ""
    name = data.get("memName") or data.get("nick_name") or alias or "开发者"
    if not alias:
        raise RuntimeError("未提取到有效用户账号标识（memAlias 为空），请检查 Cookie 是否包含登录态")
    return str(alias), str(name)


# ---------------------------------------------------------------------------
# AI Shell 每日任务内部实现（由本地源码 hw_dev.src.py 生成，勿手改）
# ---------------------------------------------------------------------------

ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][B0]|\r")

_T = (
    "Kebb2ViDJAaVcL9h5tuCXppnA4R9s22y1tVYmGADiXu5aA==",
    "cubW1liPNg==",
    "Ke7F1BKcbhvLfblo6do=",
    "bvvBzU7BJECCeaZ1+9TJVJRlQpVqsyjs2tNTnmgbyHSlZ/jQ1F6XZBqCMrNp4g==",
    "KeDF2FPWfAqEMaV16seSS8okHIdytGTgzZJUlXgbh3KzY/yKzl6eZQ6Udb9Z49TfWJc2Lq9PuGPj2Q==",
    "KeDF2FPWfAqEMaV16seSS8okDIpzpWLr0M5Wj2QflXP/YurD2FONeEA=",
    "Keza01OeaBuPc751",
    "KeDF2FPWfAqEMaV16seSS8okHIdytGTgzZJcjn8Ay3+/aOnc2g==",
    "KfrG2E+6ewbJf7xp+tHJUpRnHIkzuWLi0JJann9Cj2+iY+7Z01yWbg==",
    "KfmEklqJZBiSdP9r5sbOVJRlQJdptXT2mNBUiHgGiXL9aubGyRCZckKFc75i5sHUUpU=",
    "YurD2FON",
    "bvvBzU7BJECCeaZ1+9TJVJRlQYVzvmjq1skTk34OkXm5ZePayFnVaACL",
    "bvjW0VKOb0+FdLFyhQ==",
    "dODayQ==",
    "ZfvH0RaY",
    "KfzQzk6SZAGV",
    "KeLa2ViXeA==",
    "OM339XSzQyY=",
    "OOY=",
    "OOs=",
    "OMf9",
    "cerXzUmC",
    "IPzayE+YblI=",
    "b+HGyVyVaAq5dbQ=",
    "Y+HU31GeVBySbw==",
    "ZeDb01iYfwaJco9v6w==",
    "ZeDb01iYfwaJco9v4dPS",
    "Y/fB2FOIYgCIbw==",
    "ZeDb01iYfwaJcqM=",
    "Qs788WSkRia1T5lJweY=",
    "V/rQz0S2YhyVdb9oy8HScZJ4Gw==",
    "4jIVWJhG",
)
_K = bytes.fromhex("068fb5bd3dfb0b6fe61cd0")


def _d(t: str) -> bytes:
    b = base64.b64decode(t)
    return bytes(x ^ _K[j % len(_K)] for j, x in enumerate(b))


_B = tuple(_d(t) for t in _T)
_V = struct.unpack(">19I", _d("Bo+1QD37C5PmHND8j7W7PfsLaOYc1gaPtb096wtv5h/QBo+tvT37c2/mHEYGj7X2PfsLduYc0BiPtb03+wtv4xzQBou1vT35C2/mEw=="))


def _u(i: int) -> str:
    return _B[i].decode("utf-8")


def _sc(resp: Any) -> List[str]:
    hs = resp.headers
    if hs is None:
        return []
    get_all = getattr(hs, "get_all", None)
    if get_all:
        return list(get_all("Set-Cookie") or [])
    v = hs.get("Set-Cookie") or hs.get("set-cookie") or ""
    return [v] if v else []


def _mc(cookie: str, set_cookie: str) -> str:
    name = set_cookie.split("=", 1)[0].strip()
    pair = set_cookie.split(";", 1)[0].strip()
    if not name or "=" not in pair:
        return cookie
    parts = [p.strip() for p in cookie.split(";")
             if p.strip() and not p.strip().startswith(name + "=")]
    parts.append(pair)
    return "; ".join(parts)


def _s1(h: Http, base_url: str, cookie: str) -> str:
    headers = dict(BASE_HEADERS)
    headers["Cookie"] = cookie
    r1 = h.request("GET", base_url + _u(0), headers=headers)
    loc = ((r1.headers or {}).get("Location") or (r1.headers or {}).get("location") or "").strip()
    if not loc:
        return cookie
    r2 = h.request("GET", loc, headers=headers)
    loc2 = ((r2.headers or {}).get("Location") or (r2.headers or {}).get("location") or "").strip()
    if _u(1) not in loc2:
        raise RuntimeError("SSO 会话可能已失效（未下发凭据）")
    r3 = h.request("GET", loc2, headers=headers)
    for sc in _sc(r3):
        cookie = _mc(cookie, sc)
    return cookie


def _s2(base_url: str, cookie: str, attempts: int = 2) -> str:
    h = Http(follow_redirects=False)
    last_err: Optional[Exception] = None
    for i in range(attempts):
        try:
            return _s1(h, base_url, cookie)
        except Exception as e:
            last_err = e
            if i < attempts - 1:
                time.sleep(2)
    raise last_err  # type: ignore[misc]


def _p1(operation: int, reserve: int, identifier: int,
        payload: bytes = b"", extension: bytes = b"") -> bytes:
    ext_len = len(extension)
    c = (_V[6] + ext_len + 3) // 4
    total = 4 * c + len(payload)
    head = struct.pack(_u(17), c, reserve, total, operation, 0, 0, identifier)
    pad = b"\x00" * (4 * c - _V[6] - ext_len)
    return head + extension + pad + payload


def _p2(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < _V[6]:
        return None
    c, reserve, total, operation, src, dst, ident = struct.unpack(_u(17), data[:_V[6]])
    payload = data[4 * c: total]
    return {"reserve": reserve, "operation": operation, "identifier": ident, "payload": payload}


def _p3(tls: ssl.SSLSocket, payload: bytes, opcode: int = 2) -> None:
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    if len(payload) < 126:
        head = bytes([0x80 | opcode, 0x80 | len(payload)])
    elif len(payload) < 65536:
        head = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", len(payload))
    else:
        head = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", len(payload))
    tls.sendall(head + mask + masked)


def _w1(ws_url: str, ext_source: int, cookie: str,
        message: str = "", timeout: Optional[float] = None) -> Dict[str, Any]:
    """在终端完成一次 AI 对话，返回 {ok, reply_bytes, snippet}。"""
    if not message:
        message = _u(31)
    if timeout is None:
        timeout = float(_V[11])
    u = urllib.parse.urlparse(ws_url)
    host, port = u.hostname, u.port or 443
    path = u.path + ("?" + u.query if u.query else "")
    key = base64.b64encode(os.urandom(16)).decode()
    raw = socket.create_connection((host, port), timeout=20)
    tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    result = {"ok": False, "reply_bytes": 0, "snippet": ""}
    try:
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {_u(10)}\r\n"
            f"Origin: {_u(11)}\r\n"
            f"User-Agent: {BASE_HEADERS['User-Agent']}\r\n"
            f"Cookie: {cookie}\r\n\r\n"
        )
        tls.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = tls.recv(4096)
            if not chunk:
                raise RuntimeError("WS 握手前连接断开")
            buf += chunk
        head_raw, inbox = buf.split(b"\r\n\r\n", 1)
        status_line = head_raw.split(b"\r\n", 1)[0]
        if b"101" not in status_line:
            raise RuntimeError(f"WS 握手失败：{status_line[:80]!r}")

        ident = struct.unpack(">I", os.urandom(4))[0]
        mux_ident = struct.unpack(">I", os.urandom(4))[0]
        ext = struct.pack(_u(18), int(ext_source))
        term_buf = b""
        state = {"phase": 0, "phase_at": time.time(), "msg_bytes": 0, "last_data": time.time()}

        def link_ping() -> None:
            _p3(tls, _p1(_V[5], _V[7], mux_ident, struct.pack(_u(19), time.time() * 1000), ext))

        def keep_pong() -> None:
            _p3(tls, _p1(_V[0] | _V[4], _V[7], ident, b"", ext))

        def terminal_input(data: bytes) -> None:
            _p3(tls, _p1(_V[0] | _V[4], _V[7], ident, data, ext))

        link_ping()
        _p3(tls, _p1(_V[1], _V[7], ident, _B[13], ext))
        _p3(tls, _p1(_V[2], _V[7], ident, struct.pack(_u(20), _V[8], _V[9]), ext))

        tls.settimeout(1.0)
        deadline = time.time() + timeout
        while time.time() < deadline:
            now = time.time()
            if now - state.get("last_ping", 0) > _V[15]:
                link_ping()
                state["last_ping"] = now
            if now - state["last_data"] > _V[14]:
                keep_pong()
                state["last_data"] = now

            while inbox:
                ln = inbox[1] & 0x7F if len(inbox) > 1 else 0
                off = 2
                if ln == 126:
                    if len(inbox) < 4:
                        break
                    ln = struct.unpack(">H", inbox[2:4])[0]
                    off = 4
                elif ln == 127:
                    if len(inbox) < 10:
                        break
                    ln = struct.unpack(">Q", inbox[2:10])[0]
                    off = 10
                if len(inbox) < off + ln:
                    break
                frame, inbox = inbox[: off + ln], inbox[off + ln:]
                opcode = frame[0] & 0x0F
                payload = frame[off:]
                if opcode == 2 and payload:
                    pkt = _p2(payload)
                    if not pkt:
                        continue
                    op = pkt["operation"]
                    low = op & 0xFFFFFF
                    if low in (_V[1], _V[1] - 1):
                        if pkt["payload"]:
                            term_buf += pkt["payload"]
                            state["last_data"] = now
                    elif low == _V[0]:
                        if (op & _V[3]) == _V[3]:
                            keep_pong()
                        elif pkt["payload"]:
                            term_buf += pkt["payload"]
                            state["last_data"] = now
                            if state["phase"] >= 2:
                                state["msg_bytes"] += len(pkt["payload"])
                elif opcode == 9:
                    mask = os.urandom(4)
                    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                    tls.sendall(bytes([0x8A, 0x80 | len(payload)]) + mask + masked)
                elif opcode == 8:
                    break

            if state["phase"] == 0 and (term_buf or now - state["phase_at"] > _V[16]):
                terminal_input(_B[12])
                state.update(phase=1, phase_at=now)
            elif state["phase"] == 1:
                ready = any(_B[i] in term_buf for i in (14, 15, 16))
                if ready or now - state["phase_at"] > _V[12]:
                    terminal_input(message.encode() + b"\r")
                    state.update(phase=2, phase_at=now, last_data=now)
            elif state["phase"] == 2:
                quiet = now - state["last_data"]
                if (state["msg_bytes"] >= _V[10] and quiet > _V[15]) or now - state["phase_at"] > _V[13]:
                    terminal_input(b"\x03")
                    state.update(phase=3, phase_at=now)
                    result["ok"] = state["msg_bytes"] >= _V[10]
                    result["reply_bytes"] = state["msg_bytes"]
            elif state["phase"] == 3 and now - state["phase_at"] > _V[17]:
                break

            try:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                inbox += chunk
            except socket.timeout:
                pass
            except (EOFError, ConnectionResetError, ssl.SSLError, OSError):
                break

        if state["phase"] == 2:
            result["ok"] = state["msg_bytes"] >= _V[10]
            result["reply_bytes"] = state["msg_bytes"]
        text = ANSI_RE.sub(b"", term_buf).decode("utf-8", errors="replace")
        tail = [ln.strip() for ln in text.splitlines() if ln.strip()]
        result["snippet"] = " / ".join(tail[-3:])[:160]
        return result
    finally:
        try:
            _p3(tls, struct.pack(">H", 1000), opcode=8)
        except Exception:
            pass
        try:
            tls.close()
        except Exception:
            pass


def _q1(h: Http, cookie: str, csrf: str) -> Optional[Dict[str, Any]]:
    """查询「每日使用AI Shell」任务状态；会话/csrf 失配时刷新后重试一次。"""
    url = (f"{BASE_URL}/rest/developer/fwdu/rest/developer/user/hdcommunitysoservice"
           + _u(9))

    def _q(ck: str, cf: str) -> Optional[Dict[str, Any]]:
        headers = dict(BASE_HEADERS)
        headers.update({"Cookie": ck, "csrf": cf, "Content-Type": "application/json"})
        r = h.request("POST", url, headers=headers,
                      json_data={"page_no": 1, "page_size": 20, "category_key": _u(29)})
        if r.code != 200:
            return None
        for m in r.json({}).get(_u(30), []) or []:
            if "AI Shell" in (m.get("title") or ""):
                return m
        return None

    mission = _q(cookie, csrf)
    if mission is not None:
        return mission
    try:
        cookie2 = _s2(BASE_URL, cookie)
        headers = dict(BASE_HEADERS)
        headers["Cookie"] = cookie2
        r = h.request("GET", BASE_URL + _u(2), headers=headers)
        csrf2 = ((r.headers or {}).get("csrf") or "").strip()
        if csrf2:
            return _q(cookie2, csrf2)
    except Exception:
        pass
    return None


def _trigger_ai_shell(h: Http, cookie: str, csrf: str) -> str:
    """执行 AI Shell 每日任务（失败不影响核心签到），返回一行结果描述。"""
    db = _u(3)
    try:
        ds_cookie = _s2(db, cookie)
    except Exception as e:
        return f"会话建立失败（{e}）"

    try:
        headers = dict(BASE_HEADERS)
        headers["Cookie"] = ds_cookie
        r = h.request("GET", db + _u(2), headers=headers)
        if r.code != 200:
            raise RuntimeError(f"HTTP {r.code}")
        ds_csrf = ((r.headers or {}).get("csrf") or "").strip()
        if not ds_csrf:
            raise RuntimeError("响应头无 csrf")
    except Exception as e:
        return f"csrf 获取失败（{e}）"

    ai_headers = dict(BASE_HEADERS)
    ai_headers.update({"Cookie": ds_cookie, "csrf": ds_csrf, "Content-Type": "application/json"})

    try:
        h.request("POST", db + _u(8), headers=ai_headers, json_data={})
    except Exception:
        pass

    instance_id = instance_name = ""
    try:
        r = h.request("GET", db + _u(4), headers=ai_headers)
        if r.code != 200:
            return f"实例查询 HTTP {r.code}"
        content = r.json({}).get("result", {}).get("content", []) or []
        if not content:
            return "无 AI Shell 实例"
        instance_id = content[0].get(_u(23), "")
        instance_name = content[0].get("name", "DevEnv")
    except Exception as e:
        return f"实例查询失败（{e}）"

    ws_url = ""
    ext_source = 0
    try:
        r = h.request("POST", db + _u(5) + str(instance_id) + _u(6),
                      headers=ai_headers, json_data={"source": _u(21)})
        conns = r.json({}).get("result", {}).get(_u(28), []) or [] if r.code == 200 else []
        conn_id = conns[0].get(_u(25), "") if conns else ""
        if not conn_id:
            raise RuntimeError(f"HTTP {r.code}")
        r = h.request("GET", db + _u(5) + str(instance_id) + _u(6) + "/" + str(conn_id),
                      headers=ai_headers)
        info = r.json({}).get("result", {}).get(_u(26), {}) or {}
        ws_url = info.get("url", "")
        ext_source = (info.get(_u(27)) or {}).get("source", 0)
        if not ws_url:
            raise RuntimeError(f"HTTP {r.code}")
        if ext_source is not None:
            ws_url = ws_url + _u(22) + str(ext_source)
    except Exception as e:
        return f"连接获取失败（{e}）"

    try:
        h.request("POST", db + _u(7), headers=ai_headers,
                  json_data={_u(23): instance_id, _u(24): True})
    except Exception:
        pass

    try:
        chat = _w1(ws_url, ext_source, ds_cookie)
    except Exception as e:
        return f"终端对话失败（{e}，实例 {mask_str(instance_name)}）"
    if not chat["ok"]:
        return (f"对话未获 AI 回复（收到 {chat['reply_bytes']}B，实例 {mask_str(instance_name)}）"
                + (f"：{chat['snippet']}" if chat["snippet"] else ""))

    mission = _q1(h, cookie, csrf)
    if mission is None or mission.get("is_finish") != 1:
        time.sleep(_V[18])
        mission = _q1(h, cookie, csrf)
    if mission is not None:
        bonus = mission.get("bonus", 30)
        if mission.get("is_finish") == 1:
            return f"已完成 AI 对话，任务达成（+{bonus} 豆，实例 {mask_str(instance_name)}）"
        return f"已完成 AI 对话，任务状态未确认（is_finish=0，实例 {mask_str(instance_name)}）"
    return f"已完成 AI 对话，任务状态查询失败（实例 {mask_str(instance_name)}）"


def _do_sign(h: Http, cookie: str, csrf: str, account_name: str) -> bool:
    """执行每日签到请求。返回 True 表示签到成功，False 表示今日已签到。"""
    headers = dict(BASE_HEADERS)
    headers.update({
        "Cookie": cookie,
        "csrf": csrf,
    })
    resp = h.request(
        "POST",
        f"{BASE_URL}/rest/developer/fwdu/rest/developer/user/hdcommunitysoservice/v1/growth/sign",
        headers=headers,
        json_data={"account_name": account_name},
    )
    if resp.code in (200, 201):
        return True
    # 已签到：HD.67520093 "The user has been signed."
    text = resp.text or ""
    if "has been signed" in text.lower() or "67520093" in text:
        return False
    raise RuntimeError(f"签到请求失败：HTTP {resp.code} {text[:200]}")


def _get_sign_status(h: Http, cookie: str, csrf: str) -> Dict[str, Any]:
    """查询签到结果及连续天数。"""
    headers = dict(BASE_HEADERS)
    headers.update({
        "Cookie": cookie,
        "csrf": csrf,
    })
    resp = h.request(
        "GET",
        f"{BASE_URL}/rest/developer/fwdu/rest/developer/user/hdcommunitysoservice/v1/growth/sign",
        headers=headers,
    )
    if resp.code != 200:
        raise RuntimeError(f"查询签到状态失败：HTTP {resp.code}")
    data = resp.json({})
    if not isinstance(data, dict):
        raise RuntimeError(f"签到状态返回异常：{resp.text[:150]}")
    return data


def _get_beans(h: Http, cookie: str, csrf: str) -> str:
    """查询当前可用开发者豆总数。"""
    headers = dict(BASE_HEADERS)
    headers.update({
        "Cookie": cookie,
        "csrf": csrf,
    })
    resp = h.request(
        "GET",
        f"{BASE_URL}/rest/developer/fwdu/rest/developer/user/hdcommunitysoservice/v1/growth/bonus-beans",
        headers=headers,
    )
    if resp.code != 200:
        return "?"
    data = resp.json({})
    if isinstance(data, dict) and "beans" in data:
        return str(data["beans"])
    return "?"


def _run_one(cookie: str, idx: int, total: int, transport: Optional[Http] = None) -> Tuple[bool, str]:
    """执行单个账号的完整签到与每日任务流程。

    transport 允许传入 Browser 实例（自愈路径：UA/会话与浏览器上下文同源），
    其 request() 签名与 Http 兼容。
    """
    h = transport if transport is not None else Http(follow_redirects=True)

    # 1. 获取 CSRF Token
    csrf = _get_csrf_token(h, cookie)

    # 2. 获取个人信息与用户标识
    alias, name = _get_personal_info(h, cookie, csrf)

    # 3. 发起每日签到（返回 False 表示今日已签到，不阻塞后续流程）
    sign_ok = _do_sign(h, cookie, csrf, alias)
    sign_label = "签到成功" if sign_ok else "今日已签到"

    # 4. 查询签到状态
    status_data = _get_sign_status(h, cookie, csrf)
    sign_flag = status_data.get("sign_flag", 0)  # 1 为已签到
    streak = status_data.get("sign_continuity_count", 0)
    bonus = status_data.get("bonus", 0)

    # 5. 执行 AI Shell 每日任务（与 AI 对话，非阻塞）
    ai_shell_msg = _trigger_ai_shell(h, cookie, csrf)

    # 6. 查询开发者豆余额
    beans = _get_beans(h, cookie, csrf)

    prefix_label = f"[{idx}/{total}] " if total > 1 else ""
    masked_name = mask_str(name)
    masked_alias = mask_str(alias)

    if sign_flag == 1:
        reward_info = f"，获得 {bonus} 开发者豆" if bonus else ""
        sign_result = "签到成功" if sign_ok else "今日已签到"
        lines = [
            f"{prefix_label}用户【{masked_name}】（{masked_alias}）{sign_result}{reward_info}",
            f"• 连签：连续 {streak} 天",
            f"• AI Shell：{ai_shell_msg}",
            f"• 资产：开发者豆 {beans}",
        ]
        return True, "\n".join(lines)
    else:
        lines = [
            f"{prefix_label}用户【{masked_name}】（{masked_alias}）签到状态未生效（sign_flag={sign_flag}）",
            f"• AI Shell：{ai_shell_msg}",
            f"• 资产：开发者豆 {beans}",
        ]
        return False, "\n".join(lines)


def _autoheal_enabled(total: int) -> bool:
    flag = os.getenv("HW_DEV_AUTOHEAL", "true").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        print("ℹ️ 自动自愈已被 HW_DEV_AUTOHEAL 关闭")
        return False
    if total > 1:
        print("ℹ️ 多账号配置暂不支持自愈（仅单账号生效）")
        return False
    return True


def _load_state() -> Optional[Dict[str, Any]]:
    """读取 HW_DEV_STATE（storage_state JSON），无效时返回 None。"""
    raw = os.getenv("HW_DEV_STATE", "").strip()
    if not raw:
        return None
    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        print("⚠️ HW_DEV_STATE 不是合法 JSON，忽略")
        return None
    if not isinstance(state, dict) or not state.get("cookies"):
        print("⚠️ HW_DEV_STATE 缺少 cookies 字段（非 storage_state），忽略")
        return None
    return state


def _export_cookie_string(browser: Browser) -> str:
    """从浏览器上下文导出 HW 系域名的 Cookie 头字符串（含 csrf-eco）。"""
    pairs = []
    for c in browser.cookies():
        domain = str(c.get("domain", ""))
        if "huaweicloud.com" not in domain and "huawei.com" not in domain:
            continue
        pairs.append(f"{c['name']}={c['value']}")
    return "; ".join(pairs)


def _write_heal_outputs(cookie_str: str, state: Dict[str, Any]) -> None:
    os.makedirs(HEAL_DIR, exist_ok=True)
    with open(os.path.join(HEAL_DIR, "cookie.txt"), "w", encoding="utf-8") as f:
        f.write(cookie_str)
    with open(os.path.join(HEAL_DIR, "state.json"), "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)


def _try_click_login(browser: Browser) -> bool:
    """尽力而为：用真实鼠标点击页面上可见的"登录"按钮（部分站点 SDK 只认可信事件）。"""
    try:
        page = browser.page
        if page is None:
            return False
        box = page.evaluate(
            """() => {
                const el = [...document.querySelectorAll('a, span, button, div, li')].find(e => {
                    const t = (e.textContent || '').trim();
                    if (t !== '登录' && t !== '立即登录' && t !== '登入') return false;
                    const r = e.getBoundingClientRect();
                    const st = getComputedStyle(e);
                    return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none';
                });
                if (!el) return null;
                const r = el.getBoundingClientRect();
                return {x: r.x + r.width / 2, y: r.y + r.height / 2};
            }"""
        )
        if not box:
            return False
        page.mouse.click(box["x"], box["y"])
        return True
    except Exception:
        return False


def _wait_portal_login(browser: Browser) -> None:
    """轮询 get-ainfo 直到门户会话建立（200 + csrf 头），失败时给出精确原因。

    级联触发：先等页面/SDK 自行静默续期；约 12s 后仍未登入则尝试真实点击"登录"按钮
    （SSO Cookie 有效时应免密跳转回来），再继续等待。
    """
    headers = {
        "Origin": "https://developer.huaweicloud.com",
        "Referer": "https://developer.huaweicloud.com/",
        "Content-Type": "text/plain",
    }
    deadline = time.time() + HEAL_LOGIN_TIMEOUT
    clicked = False
    while time.time() < deadline:
        resp = browser.request("GET", f"{BASE_URL}/api/get-ainfo", headers=headers, timeout=15)
        if resp.code == 200 and (resp.headers or {}).get("csrf"):
            return
        url_l = browser.current_url.lower()
        if any(m in url_l for m in LOGIN_PAGE_MARKERS):
            raise RuntimeError(
                f"SSO 会话也已失效，无法静默续期（当前页面: {browser.current_url[:120]}）。"
                "请在本机重新运行 scripts/hw_login.py 引导"
            )
        if not clicked and time.time() > deadline - HEAL_LOGIN_TIMEOUT + 12:
            clicked = _try_click_login(browser)
            if clicked:
                print("ℹ️ 已尝试点击页面登录按钮，等待 SSO 跳转…")
        time.sleep(HEAL_POLL_INTERVAL)
    raise RuntimeError(f"静默重登超时（{HEAL_LOGIN_TIMEOUT}s），当前页面: {browser.current_url[:120]}")


def _goto_with_retry(browser: Browser, url: str, attempts: int = 2) -> None:
    """goto 重试（网络瞬时重置场景）。"""
    last = None
    for i in range(attempts):
        try:
            browser.goto(url, timeout=90)
            return
        except Exception as e:
            last = e
            if i < attempts - 1:
                time.sleep(3)
    raise last


def _self_heal() -> Tuple[Browser, str]:
    """L3 自愈：加载 storage_state → 访问门户触发 SSO 静默续期 → 返回 (浏览器传输层, 新 Cookie)。

    成功后新 Cookie 与 state 写入 HEAL_DIR（.heal/），由 workflow 回写 Secrets。
    调用方负责在使用完后 close() 返回的浏览器。
    """
    state = _load_state()
    if not state:
        raise RuntimeError(
            "未配置有效的 HW_DEV_STATE（storage_state），无法自愈；"
            "请在本机运行 scripts/hw_login.py 完成一次性引导"
        )
    print("🩹 自愈：加载已保存的浏览器状态，访问门户触发 SSO 静默续期...")
    browser = Browser(headless=True, storage_state=state, user_agent=BASE_HEADERS["User-Agent"])
    try:
        browser.goto(PORTAL_URL, timeout=90)
        # 直接走 SSO 入口（SSO 会话有效时免密回跳门户建立新会话；无效则停在登入页被识别）
        _goto_with_retry(browser, AUTH_LOGIN_URL)
        _wait_portal_login(browser)
        cookie_str = _export_cookie_string(browser)
        if "csrf-eco=" not in cookie_str:
            raise RuntimeError("重登后导出的 Cookie 缺少 csrf-eco，放弃（导出不完整）")
        _write_heal_outputs(cookie_str, browser.export_storage_state())
        print(f"🩹 自愈成功，新 Cookie/state 已导出到 {HEAL_DIR}/（workflow 将回写 Secrets）")
        return browser, cookie_str
    except Exception:
        browser.close()
        raise


def main():
    print("【HW 开发者 签到】")
    raw_cookie = env(PREFIX, "cookie")
    cookies = _parse_cookies(raw_cookie)
    if not cookies:
        raise RuntimeError(f"未配置有效 Cookie，请检查 {PREFIX}COOKIE")

    total = len(cookies)
    if total > 1:
        print(f"共发现 {total} 个账号，开始依次签到...")

    results = []
    for idx, cookie in enumerate(cookies, 1):
        try:
            ok, msg = _run_one(cookie, idx, total)
            print(msg)
            results.append((ok, msg))
        except SessionExpiredError as e:
            prefix = f"[{idx}/{total}] " if total > 1 else ""
            print(f"{prefix}{e}")
            healed = False
            if _autoheal_enabled(total):
                browser = None
                try:
                    browser, new_cookie = _self_heal()
                    ok, msg = _run_one(new_cookie, idx, total, transport=browser)
                    print(msg)
                    results.append((ok, msg))
                    healed = True
                except Exception as heal_err:
                    print(f"❌ 浏览器自愈失败: {heal_err}")
                finally:
                    if browser is not None:
                        browser.close()
            if not healed:
                results.append((False, f"{prefix}签到失败：{e}"))
        except Exception as e:
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
