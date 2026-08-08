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
from typing import Any, Dict, Iterable, Optional

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
            # DNS failure / TLS error / connection reset / timeout escape as URLError.
            # Surface as a synthetic error response so callers get a usable .text/.json()
            # instead of an unhandled exception (which main_guard would flag as failure).
            return Response(-1, None, str(getattr(exc, "reason", exc)).encode("utf-8", "replace"), url)

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
