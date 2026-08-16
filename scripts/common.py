#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import gzip
import html
import json
import functools
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from http.cookiejar import CookieJar
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_UA = (
    os.getenv("UA")
    or os.getenv("QL_UA")
    or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class Response:
    def __init__(self, code: int, headers: Any, body: bytes, url: str):
        self.code = code
        self.headers = headers
        self.body = body
        self.url = url
    @property
    def text(self) -> str:
        body = self.body
        enc = (self.headers.get("Content-Encoding", "") if self.headers else "").lower()
        try:
            if "gzip" in enc:
                body = gzip.decompress(body)
            elif "deflate" in enc:
                body = zlib.decompress(body)
        except Exception:
            pass
        for codec in ("utf-8", "gb18030", "latin-1"):
            try:
                return body.decode(codec)
            except UnicodeDecodeError:
                continue
        return body.decode("utf-8", errors="replace")
    def json(self, default: Any = None) -> Any:
        try:
            return json.loads(self.text)
        except Exception:
            return default

def retry(times: int = 2, backoff: float = 3.0, retry_codes: tuple = (-1, 429, 500, 502, 503, 504)):
    """Retry decorator for network calls.

    - times: total number of attempts (1 = no retry).
    - backoff: seconds between attempts.
    - retry_codes: Response.code values that should trigger a retry.

    Only decorates callables whose return value exposes a `.code` attribute
    (i.e. ql_common.Response). Other return types are returned without retry.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last = None
            for attempt in range(1, max(1, times) + 1):
                last = fn(*args, **kwargs)
                code = getattr(last, "code", None)
                if code is None or code not in retry_codes:
                    return last
                if attempt < max(1, times):
                    time.sleep(backoff)
            return last
        return wrapper
    return decorator

class Http:
    def __init__(self, follow_redirects: bool = False):
        self.jar = CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if not follow_redirects:
            handlers.insert(0, NoRedirectHandler())
        self.opener = urllib.request.build_opener(*handlers)
    @retry()
    def request(self, method: str, url: str, *, headers: Optional[Dict[str,str]]=None,
                data: Any=None, json_data: Any=None, form: Optional[Dict[str,Any]]=None,
                timeout: int=60) -> Response:
        headers = dict(headers or {})
        headers.setdefault("User-Agent", DEFAULT_UA)
        headers.setdefault("Accept", "application/json, text/plain, */*")

        # Clean non-latin-1 characters in header values to prevent urllib encoding errors
        for k, v in list(headers.items()):
            if isinstance(v, str):
                headers[k] = v.encode("latin-1", errors="ignore").decode("latin-1")

        body = None
        if json_data is not None:
            body = json.dumps(json_data, ensure_ascii=False, separators=(",", ":")).encode()
            headers.setdefault("Content-Type", "application/json")
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif data is not None:
            body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return Response(r.status, r.headers, r.read(), r.geturl())
        except urllib.error.HTTPError as exc:
            return Response(exc.code, exc.headers, exc.read(), url)
        except urllib.error.URLError as exc:
            # DNS failure / TLS error / connection-phase timeout escape as URLError.
            # Surface as a synthetic error response so callers get a usable .text/.json()
            # instead of an unhandled exception (which main_guard would flag as failure).
            return Response(-1, None, str(getattr(exc, "reason", exc)).encode("utf-8", "replace"), url)
        except OSError as exc:
            # 读超时（socket.timeout=TimeoutError）与读到一半的连接重置（ConnectionError、
            # RemoteDisconnected）不会被 urllib 包装成 URLError，会直接穿透 except 与
            # @retry —— 同样收敛为合成 -1 响应，让 retry 对慢 CDN / 连接抖动真正生效
            #（urllib.error.URLError 本身是 OSError 子类，放最后只兜住非 URLError 的网络异常）。
            return Response(-1, None, str(exc).encode("utf-8", "replace"), url)

class Browser:
    """Playwright-based browser client for WAF-protected sites and session-bound APIs.

    Drop-in for Http: `.request(method, url, *, headers, json_data, form)` returns a
    `Response`-like object with `.code`, `.headers`, `.text`, `.json()`.

    Requests go through the context's API client: context cookies are attached
    automatically, redirects are followed (unless follow_redirects=False), and real
    status/headers/body come back without CORS limits — suitable for driving
    authenticated JSON APIs from a browser session.

    Session keep-alive flows (e.g. hw_dev self-heal) can seed a saved
    `storage_state` (cookies + localStorage), drive the page with `goto()` so the
    site's own silent-SSO redirect chain runs, then export `cookies()` /
    `export_storage_state()` for persistence.
    """

    def __init__(self, follow_redirects: bool = True, headless: bool = True,
                 storage_state: Optional[Dict[str, Any]] = None,
                 user_agent: Optional[str] = None):
        self.follow_redirects = follow_redirects
        self.headless = headless
        self.storage_state = storage_state
        self.user_agent = user_agent
        self._sync = None
        self._browser = None
        self._context = None
        self._page = None

    def _ensure(self):
        if self._page is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError(
                "需要 Playwright。请在本地执行 pip install -r requirements.txt "
                "（CI 中 workflow 已自动安装）"
            )
        self._sync = sync_playwright().start()
        self._browser = self._sync.chromium.launch(headless=self.headless)
        context_kwargs = {
            "user_agent": self.user_agent or DEFAULT_UA,
            "locale": "zh-CN",
        }
        if self.storage_state:
            context_kwargs["storage_state"] = self.storage_state
        self._context = self._browser.new_context(**context_kwargs)
        self._page = self._context.new_page()

    def request(self, method: str, url: str, *, headers: Optional[Dict[str,str]]=None,
                data: Any=None, json_data: Any=None, form: Optional[Dict[str,Any]]=None,
                timeout: int=60) -> "Response":
        self._ensure()
        req_headers = {k: v for k, v in (headers or {}).items() if isinstance(v, str)}
        kwargs: Dict[str, Any] = {"headers": req_headers, "timeout": timeout * 1000}
        if not self.follow_redirects:
            kwargs["max_redirects"] = 0
        body = None
        if json_data is not None:
            body = json.dumps(json_data, ensure_ascii=False, separators=(",", ":"))
            req_headers.setdefault("Content-Type", "application/json")
        elif form is not None:
            body = urllib.parse.urlencode(form)
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif data is not None:
            body = data if isinstance(data, str) else data.decode("utf-8", "replace")
        if body is not None:
            kwargs["data"] = body
        try:
            method_upper = method.upper()
            fn = {
                "GET": self._context.request.get,
                "POST": self._context.request.post,
                "PUT": self._context.request.put,
                "PATCH": self._context.request.patch,
                "DELETE": self._context.request.delete,
                "HEAD": self._context.request.head,
            }.get(method_upper)
            if fn is not None:
                resp = fn(url, **kwargs)
            else:
                resp = self._context.request.fetch(url, method=method_upper, **kwargs)
            return Response(resp.status, dict(resp.headers), resp.body(), url)
        except Exception as exc:
            return Response(-1, {}, str(exc).encode("utf-8", "replace"), url)

    def goto(self, url: str, timeout: int = 60):
        """Open url in the page context (runs site JS / triggers SSO redirect chains)."""
        self._ensure()
        return self._page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)

    @property
    def current_url(self) -> str:
        return self._page.url if self._page is not None else ""

    @property
    def page(self):
        """底层 Playwright Page（已 _ensure 后可用），供需要真实交互的场景（如点击登入）。"""
        return self._page

    def cookies(self) -> List[Dict[str, Any]]:
        self._ensure()
        return self._context.cookies()

    def export_storage_state(self) -> Dict[str, Any]:
        self._ensure()
        return self._context.storage_state()

    def content(self) -> str:
        self._ensure()
        return self._page.content()

    def close(self):
        if self._page is not None:
            self._page.close()
            self._page = None
        if self._context is not None:
            self._context.close()
            self._context = None
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._sync is not None:
            self._sync.stop()
            self._sync = None


def schedule_repo_dispatch(event_type: str, delay_seconds: int) -> tuple[bool, str]:
    """通过 QStash 延时 Webhook 触发 GitHub repository_dispatch（跨 run 接力调度）。

    供 workbuddy 放风领奖接力、latvi 24h 冷却签到接力等场景共用：不在本地阻塞
    等待，由 QStash 在 delay_seconds 后回调 repository_dispatch API 触发下一个
    工作流。QStash 免费版延时上限 7 天，覆盖 24h 级接力。

    环境变量：QSTASH_URL / QSTASH_TOKEN / GH_PAT（需 Actions: write）/ GITHUB_REPO。
    返回 (是否已成功调度, 说明)；未配置依赖或发布失败时返回 False，调用方自行回退
    （workbuddy 回退为等下次定时触发，latvi 回退为原地等待）。
    """
    qstash_url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL")
    qstash_token = os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN")
    gh_pat = os.getenv("GH_PAT") or os.getenv("WORKFLOW_TOKEN")
    repo = os.getenv("GITHUB_REPO", "")

    missing = [
        key
        for key, value in (
            ("QSTASH_URL", qstash_url),
            ("QSTASH_TOKEN", qstash_token),
            ("GH_PAT", gh_pat),
            ("GITHUB_REPO", repo),
        )
        if not value
    ]
    if missing:
        return False, f"未配置延时调度依赖({', '.join(missing)})"

    # GitHub repository_dispatch API 目标地址；QStash publish 的 topic 是目标 URL（需编码为路径片段）
    dispatch_api = f"https://api.github.com/repos/{repo}/dispatches"
    topic = urllib.parse.quote(dispatch_api, safe="")

    # 拼接 publish URL：无论 QSTASH_URL 配的是裸域名还是已带 /v2/publish[/<旧topic>]
    # （含无尾斜杠的写法），都先剥掉 publish 路径再统一拼，避免双重前缀导致
    # QStash 把目的地解析成 "v2/publish/https://…" 而报 invalid scheme
    base = qstash_url.split("/v2/publish", 1)[0].rstrip("/")
    publish_url = f"{base}/v2/publish/{topic}"

    # QStash `…/v2/publish/{目标URL}` 会把请求体原样转发给目标，Body 必须是 GitHub
    # dispatches API 要求的原始 JSON（{"event_type": …}）。
    # GitHub 所需的鉴权/接受头通过 QStash 的 Upstash-Forward-* 前缀透传——
    # QStash 收到带该前缀的头时，会把前缀剥离后原样转发（Upstash → GitHub）。
    body = json.dumps({"event_type": event_type}, ensure_ascii=False)
    headers = {
        "Authorization": f"Bearer {qstash_token}",
        "Content-Type": "application/json",
        "Upstash-Delay": str(int(delay_seconds)),
        "Upstash-Forward-Authorization": f"Bearer {gh_pat}",
        "Upstash-Forward-Accept": "application/vnd.github+json",
        "Upstash-Forward-X-GitHub-Api-Version": "2022-11-28",
    }

    resp = Http().request("POST", publish_url, headers=headers, data=body)
    if resp.code == 200:
        return True, str(int(delay_seconds))
    detail = resp.text[:200] if resp.text else ""
    return False, f"HTTP {resp.code}{': ' + detail if detail else ''}"


def env(prefix: str, name: str, default: str = "", required: bool = True) -> str:
    clean_prefix = prefix.removeprefix("QL_")
    keys = [
        f"{clean_prefix}{name}",
        f"{clean_prefix}{name.upper()}",
        f"QL_{clean_prefix}{name}",
        f"QL_{clean_prefix}{name.upper()}",
        f"{prefix}{name}",
        f"{prefix}{name.upper()}",
        name,
        name.upper(),
    ]
    seen = set()
    ordered_keys = [k for k in keys if not (k in seen or seen.add(k))]
    for key in ordered_keys:
        value = os.getenv(key)
        if value not in (None, ""):
            return value
    if required and default == "":
        raise SystemExit(f"缺少环境变量：{clean_prefix}{name}")
    return default

def must_match(pattern: str, text: str, label: str, flags: int = 0) -> str:
    m = re.search(pattern, text, flags)
    if not m:
        raise RuntimeError(f"未提取到 {label}")
    return m.group(1) if m.groups() else m.group(0)

def find(pattern: str, text: str, default: str = "", flags: int = 0) -> str:
    m = re.search(pattern, text, flags)
    return (m.group(1) if m.groups() else m.group(0)) if m else default

def findall(pattern: str, text: str, flags: int = 0) -> list[str]:
    out=[]
    for m in re.findall(pattern, text, flags):
        out.append(m[0] if isinstance(m, tuple) else m)
    return out

def strip_tags(s: Any) -> str:
    return html.unescape(re.sub(r"<[^>]*>", "", str(s))).strip()

def mask_str(value: Any, keep_start: int | None = None, keep_end: int | None = None, mask_char: str = "*") -> str:
    """智能脱敏字符串（用户名、手机号、邮箱、账号 ID 等）。

    脱敏规则：
    - 邮箱：对 @ 前缀进行脱敏，保留完整域名，如 user123@gmail.com -> u***3@gmail.com
    - 手机号（11位纯数字）：保留前3后4，如 13812345678 -> 138****5678
    - 自定义 keep_start / keep_end：按指定保留字符数脱敏
    - 默认智能策略（首尾可见、中间掩码，便于本人识别同时防止公开泄露）：
      * 长度 <= 1: 返回 "*"
      * 长度 == 2: 保留首位，如 "张三" -> "张*"
      * 长度 3~9:  保留首1尾1，如 "hun8461" -> "h***1", "admin" -> "a***n"
      * 长度 >= 10: 保留首3尾3，如 "yd_219491735" -> "yd_***735"
    """
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""

    # 邮箱处理
    if "@" in s and not (s.startswith("@") or s.endswith("@")):
        user_part, domain_part = s.split("@", 1)
        masked_user = mask_str(user_part, keep_start=keep_start, keep_end=keep_end, mask_char=mask_char)
        return f"{masked_user}@{domain_part}"

    # 手机号处理 (11位纯数字)
    if len(s) == 11 and s.isdigit() and keep_start is None and keep_end is None:
        return f"{s[:3]}****{s[-4:]}"

    n = len(s)
    if n <= 1:
        return mask_char
    if n == 2:
        return f"{s[0]}{mask_char}"

    if keep_start is not None and keep_end is not None:
        ks = max(0, min(keep_start, n))
        ke = max(0, min(keep_end, n - ks))
        if ks == 0 and ke == 0:
            return mask_char * 3
        return f"{s[:ks]}***{s[n - ke:] if ke > 0 else ''}"

    if n < 10:
        return f"{s[0]}***{s[-1]}"
    return f"{s[:3]}***{s[-3:]}"

def bj_time_from_iso_z(value: str) -> tuple[str,str]:
    if not value:
        return "", ""
    value = value.replace("Z", "+00:00")
    d = dt.datetime.fromisoformat(value)
    bj = d.astimezone(dt.timezone(dt.timedelta(hours=8)))
    return bj.strftime("%Y-%m-%d"), bj.strftime("%H:%M:%S")

def ensure(ok: bool, msg: str) -> None:
    if not ok:
        raise RuntimeError(msg)

def main_guard(fn):
    try:
        fn()
    except Exception as e:
        print("签到失败：", e)
        if os.getenv("DEBUG"):
            import traceback; traceback.print_exc()
        sys.exit(1)
