#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import gzip
import html
import json
import functools
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from http.cookiejar import Cookie, CookieJar
from typing import Any, Dict, Iterable, List, Optional, Union

# 保存原生未被猴子补丁污染的 socket，用于跨代理/直连切换时彻底隔离与还原
_ORIG_SOCKET = getattr(socket, "_orig_socket", socket.socket)

try:
    from proxy_manager import (
        ProxyEndpoint,
        format_dead_proxy_alert,
        get_all_proxy_endpoints,
        get_task_proxy_endpoints,
        mask_proxy_url,
        parse_proxies_text,
        parse_proxy_line,
    )
except ImportError:
    try:
        from scripts.proxy_manager import (  # type: ignore
            ProxyEndpoint,
            format_dead_proxy_alert,
            get_all_proxy_endpoints,
            get_task_proxy_endpoints,
            mask_proxy_url,
            parse_proxies_text,
            parse_proxy_line,
        )
    except ImportError:
        from .proxy_manager import (  # type: ignore
            ProxyEndpoint,
            format_dead_proxy_alert,
            get_all_proxy_endpoints,
            get_task_proxy_endpoints,
            mask_proxy_url,
            parse_proxies_text,
            parse_proxy_line,
        )

DEFAULT_UA = (
    os.getenv("UA")
    or os.getenv("QL_UA")
    or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# 北京时间统一常量（此前 7+ 个脚本各自定义 timezone(timedelta(hours=8))）
BJT = dt.timezone(dt.timedelta(hours=8))


def env_bool(name: str, default: bool = False) -> bool:
    """解析布尔型环境变量（"1"/"true"/"yes" 为真，其余为假）。"""
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes")


def is_already_signed(msg: str, extra_phrases: tuple = ()) -> bool:
    """「今日已签到」幂等判定：只认明确词组，杜绝单字符「已」类假成功。

    默认词组覆盖中文「已签到/已领取/已经签到/今日已签」与英文 already/claimed/signed；
    站点有专属文案时经 extra_phrases 追加（词长必须 ≥2，防误报）。
    """
    if not msg:
        return False
    phrases = ("已签到", "已领取", "已经签到", "今日已签") + tuple(extra_phrases)
    if any(p in msg for p in phrases if len(p) >= 2):
        return True
    low = msg.lower()
    return "already" in low or "claimed" in low


def load_kv_state(redis_key: str, state_file: str | os.PathLike) -> dict:
    """本地 JSON + Upstash Redis 双层加载 KV 状态（远端权威性高于本地）。

    ai_router / agentrouter 的 token 链与 session 状态共用此模式；
    任一层缺失/损坏都静默降级为空 dict，由调用方走重登兜底。
    """
    state: dict = {}
    try:
        if os.path.exists(state_file):
            with open(state_file, encoding="utf-8") as f:
                data = json.loads(f.read())
            if isinstance(data, dict):
                state.update(data)
    except Exception as e:
        print(f"⚠️ 读取本地 state 失败（{state_file}）: {e}")
    try:
        ok, res = upstash_redis_command(["GET", redis_key])
        if ok and isinstance(res, dict):
            raw_val = res.get("result")
            if raw_val and isinstance(raw_val, str):
                remote = json.loads(raw_val)
                if isinstance(remote, dict):
                    state.update(remote)
    except Exception as e:
        print(f"⚠️ 从 Redis 读取 state 异常: {e}")
    return state


def save_kv_state(redis_key: str, state_file: str | os.PathLike, state: dict) -> None:
    """持久化 KV 状态到本地文件与 Upstash Redis（双通道，失败仅警告）。"""
    if not isinstance(state, dict):
        return
    try:
        with open(state_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(state, ensure_ascii=False))
    except Exception as e:
        print(f"⚠️ 保存本地 state 失败: {e}")
    try:
        ok, res = upstash_redis_command(["SET", redis_key, json.dumps(state, ensure_ascii=False)])
        if ok and isinstance(res, dict) and res.get("result") == "OK":
            print(f"☁️ state 已实时同步至 Upstash Redis（{redis_key}）")
    except Exception as e:
        print(f"⚠️ 同步 state 到 Redis 异常: {e}")

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

def _create_ssl_context() -> ssl.SSLContext:
    """构建严格且健壮的 SSLContext，强制实施系统根证书链校验与主机名一致性验证，最低 TLS 1.2。"""
    ctx = ssl.create_default_context()
    # 显式强制验证模式与主机名匹配，杜绝任何外部上下文或环境篡改风险
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    # 强制最低 TLS 协议版本为 TLSv1.2，防御针对 TLS 1.0/1.1 的 POODLE/BEAST 等降级攻击
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_2"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    return ctx


def retry(times: int = 3, backoff: float = 3.0, retry_codes: tuple = (-1, 429, 500, 502, 503, 504)):
    """Retry decorator for network calls.

    - times: total number of attempts (1 = no retry).
    - backoff: seconds between attempts.
    - retry_codes: Response.code values that should trigger a retry.

    Only decorates callables whose return value exposes a `.code` attribute
    (i.e. ql_common.Response). Other return types are returned without retry.
    调用方可通过传递 retries=1 显式指定单次尝试次数（如候选代理快速探测/故障切换）。
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            attempt_times = kwargs.pop("retries", None)
            if attempt_times is None:
                attempt_times = times
            last = None
            for attempt in range(1, max(1, attempt_times) + 1):
                last = fn(*args, **kwargs)
                code = getattr(last, "code", None)
                if code is None or code not in retry_codes:
                    return last
                if attempt < max(1, attempt_times):
                    # 指数退避：backoff, 2*backoff, 4*backoff...（上限 60s，防长退避横跨兜底核查点）
                    time.sleep(min(backoff * (2 ** (attempt - 1)), 60.0))
            return last
        return wrapper
    return decorator

class Http:
    def __init__(
        self,
        follow_redirects: bool = False,
        proxy: Union[str, ProxyEndpoint] = "",
        task_name: str = "",
        impersonate: str = "",
        infer_proxy: bool = True,
    ):
        # 浏览器 TLS/HTTP2 指纹模拟（如 "chrome124"），走 curl_cffi 发起请求，
        # 绕过 Aliyun WAF 等对 urllib 裸 TLS 指纹的识别。空串 = 保持纯 urllib 链路。
        self.impersonate = impersonate or ""
        if self.impersonate:
            try:
                import curl_cffi  # noqa: F401   # 缺失时回退 urllib 而不致命
            except Exception:
                self.impersonate = ""
                print(f"⚠️ curl_cffi 不可用，Http(impersonate=...) 回退到 urllib")
        self.jar = CookieJar()
        self.proxy_endpoint: Optional[ProxyEndpoint] = None
        self.has_proxy: bool = False
        ssl_ctx = _create_ssl_context()
        self.ssl_context = ssl_ctx
        handlers = [
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ssl_ctx),
        ]
        if not follow_redirects:
            handlers.insert(0, NoRedirectHandler())

        # 原生任务代理能力自适应：若未显式传 proxy，自动探测任务环境配置。
        # infer_proxy=False 显式禁用推断——出口轮换的「直连出网」候选必须走真直连，
        # 否则推断会把已失败的任务代理捡回来（2026-10-31 场次首战复盘 + 评审修正）。
        # 直连模式同时屏蔽环境变量代理（HTTPS_PROXY 等）：urllib 默认 ProxyHandler
        # 读环境、curl_cffi/libcurl 未显式指定代理时同样回退环境变量——「直连」必须
        # 两端都掐掉环境代理，否则环境代理一死直连兜底跟着死（评审指认）。
        self.direct_no_env_proxy = bool(not proxy and not infer_proxy)
        if self.direct_no_env_proxy:
            handlers.insert(0, urllib.request.ProxyHandler({}))
        if not proxy and infer_proxy:
            inferred_task = task_name
            if not inferred_task and sys.argv and sys.argv[0]:
                stem = Path(sys.argv[0]).stem
                if stem and stem not in ("run_task", "daily_orchestrator", "unittest", "pytest", "daily_report"):
                    inferred_task = stem
            if inferred_task:
                try:
                    # 动态延迟导入以防循环依赖
                    from proxy_manager import get_task_proxy_endpoints
                    candidate_eps = get_task_proxy_endpoints(inferred_task)
                    if candidate_eps:
                        proxy = candidate_eps[0]
                except Exception:
                    pass

        if proxy:
            # 代理出口：支持字符串 URL (含 [名称] / #名称 识别标签) 或 ProxyEndpoint 对象
            proxy_str = ""
            if isinstance(proxy, ProxyEndpoint):
                self.proxy_endpoint = proxy
                proxy_str = proxy.url
            else:
                raw_p = str(proxy).strip()
                parsed_ep = parse_proxy_line(raw_p)
                if parsed_ep:
                    self.proxy_endpoint = parsed_ep
                    proxy_str = parsed_ep.url
                else:
                    proxy_str = raw_p

            if proxy_str:
                self.has_proxy = True
                # curl_cffi 链路需要代理 URL 本体；parse_proxy_line 失败时 endpoint
                # 对象为 None，此处记录原始 URL 供其使用，避免静默假设默认端口
                self.proxy_url: str = proxy_str
                # - http(s):// 走 urllib 原生 ProxyHandler（HTTPS 经 CONNECT 隧道，隧道内走端到端 TLS）
                # - socks5(h)://, socks4(a):// 使用 sockshandler.SocksiPyHandler
                #   （强制 rdns=True 远程 DNS，隔离全局 socket）
                if proxy_str.lower().startswith(("http://", "https://")):
                    socket.socket = _ORIG_SOCKET
                    handlers.append(
                        urllib.request.ProxyHandler({"http": proxy_str, "https": proxy_str})
                    )
                else:
                    try:
                        import socks
                    except ImportError:
                        raise RuntimeError(
                            "检测到 SOCKS 代理但缺少 pysocks 依赖，请 pip install pysocks"
                        )
                    u = urllib.parse.urlparse(
                        proxy_str if "://" in proxy_str else f"socks5://{proxy_str}"
                    )
                    # sockshandler 随 pysocks 一并提供；不再回退 pysocks 全局
                    # set_default_proxy monkey-patch（进程级 socket 污染会波及
                    # 同进程其他请求路径——2026-09-06 代理收敛清理），失败即显式报错
                    import sockshandler
                    scheme_lower = u.scheme.lower()
                    ptype = (
                        sockshandler.socks.SOCKS4
                        if scheme_lower.startswith("socks4")
                        else sockshandler.socks.SOCKS5
                    )
                    handlers.append(
                        sockshandler.SocksiPyHandler(
                            ptype,
                            u.hostname or "",
                            u.port or 1080,
                            True,  # rdns=True: 强制远程 DNS 解析，彻底杜绝本地 DNS 劫持与域名泄露
                            urllib.parse.unquote(u.username) if u.username else None,
                            urllib.parse.unquote(u.password) if u.password else None,
                        )
                    )
                    socket.socket = _ORIG_SOCKET
            else:
                socket.socket = _ORIG_SOCKET
        else:
            socket.socket = _ORIG_SOCKET
        self.opener = urllib.request.build_opener(*handlers)

    @retry()
    def request(self, method: str, url: str, *, headers: Optional[Dict[str,str]]=None,
                data: Any=None, json_data: Any=None, form: Optional[Dict[str,Any]]=None,
                timeout: int=60) -> Response:
        headers = dict(headers or {})
        headers.setdefault("User-Agent", DEFAULT_UA)
        headers.setdefault("Accept", "application/json, text/plain, */*")
        headers.setdefault("Connection", "close")

        # 浏览器 TLS/HTTP2 指纹链路：配置了 impersonate 时优先走 curl_cffi，
        # 复用本实例的 CookieJar 与代理配置，突破 Aliyun WAF/Cloudflare 的指纹识别。
        if self.impersonate:
            try:
                return self._request_impersonated(
                    method, url, headers=headers, data=data,
                    json_data=json_data, form=form, timeout=timeout,
                )
            except Exception as exc:
                # 捕获 curl_cffi 的网络级异常（DNS/连接/TLS握手/超时）并返回 -1 合成响应，让 @retry 生效
                is_net_err = False
                try:
                    from curl_cffi.requests.errors import RequestsError
                    if isinstance(exc, RequestsError):
                        is_net_err = True
                except Exception:
                    pass
                if is_net_err or "curl_cffi" in getattr(type(exc), "__module__", ""):
                    return Response(-1, None, f"curl_cffi network error: {exc}".encode(), url)
                # 配置或解析级异常：绝不吞掉业务失败，但也不占用重试次数——直接透传
                raise

        # 代理模式安全守门员：当通过任何代理（HTTP / SOCKS）传输时，严禁明文 HTTP 裸奔传输
        if (getattr(self, "proxy_endpoint", None) or getattr(self, "has_proxy", False)) and url.lower().startswith("http://"):
            # 自动防御性升级为安全 HTTPS，确保流量强制受 TLS 端到端强校验保护，中间人无法嗅探
            url = "https://" + url[7:]

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

    def _request_impersonated(self, method: str, url: str, *, headers: dict,
                              data: Any = None, json_data: Any = None,
                              form: Optional[Dict[str, Any]] = None,
                              timeout: int = 60) -> Response:
        """curl_cffi 指纹链路：以浏览器的 TLS/HTTP2/JA3 指纹发出请求。

        复用本实例的 CookieJar（含预置护栏 Cookie）、代理出口与代理安全守门员逻辑。
        返回统一 Response(code/text/json)，与 urllib 链路完全兼容。
        """
        # 代理模式安全守门员：同上，明文 HTTP 一律升级为 HTTPS
        if (getattr(self, "proxy_endpoint", None) or getattr(self, "has_proxy", False)) and url.lower().startswith("http://"):
            url = "https://" + url[7:]

        from curl_cffi import requests as cr
        sess_kwargs = {"impersonate": self.impersonate, "timeout": timeout}
        # 直连模式：显式空代理串 = libcurl CURLOPT_PROXY ""，掐掉环境变量代理
        if getattr(self, "direct_no_env_proxy", False):
            sess_kwargs["proxies"] = {"http": "", "https": ""}
        # 代理出口：优先走具体的 ProxyEndpoint（含 socks5/http），与 urllib 链路一致
        elif getattr(self, "proxy_endpoint", None):
            sess_kwargs["proxies"] = {
                "http": self.proxy_endpoint.url,
                "https": self.proxy_endpoint.url,
            }
        elif getattr(self, "has_proxy", False):
            # 仅有代理标记但无 endpoint 对象（sockshandler 全局 patch 类）——curl_cffi 原生
            # 支持 socks5:// 地址。优先用实例记录的原始代理 URL；信息缺失时才回退
            # SINGBOX_SOCKS_URL（缺省为本机 sing-box inbound），并显式告警
            inst_url = getattr(self, "proxy_url", "")
            if inst_url:
                proxy_url = inst_url
            else:
                proxy_url = os.getenv("SINGBOX_SOCKS_URL", "socks5://127.0.0.1:1080")
                print(
                    f"⚠️ curl_cffi 链路未拿到显式代理 endpoint，使用兜底代理出口 "
                    f"[{mask_str(proxy_url)}]（可经 SINGBOX_SOCKS_URL 覆盖）",
                    file=sys.stderr,
                )
            sess_kwargs["proxies"] = {
                "http": proxy_url,
                "https": proxy_url,
            }

        sess = cr.Session(**sess_kwargs)
        try:
            # 清空会话级 cookie，仅从本实例 CookieJar 迁移到 curl_cffi，保证预置护栏 cookie 生效
            sess.cookies.clear()
            for c in self.jar:
                if not isinstance(c, Cookie):
                    continue
                try:
                    sess.cookies.set(
                        c.name, c.value or "",
                        domain=c.domain, path=getattr(c, "path", "/"),
                        secure=bool(getattr(c, "secure", True)),
                    )
                except Exception:
                    continue
            body = None
            if json_data is not None:
                body = json.dumps(json_data, ensure_ascii=False, separators=(",", ":")).encode()
                headers.setdefault("Content-Type", "application/json")
            elif form is not None:
                body = urllib.parse.urlencode(form).encode()
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif data is not None:
                body = data.encode() if isinstance(data, str) else data
            kw = {"headers": headers}
            if body is not None:
                kw["data"] = body
            resp = sess.request(method.upper(), url, **kw)
            return Response(resp.status_code, resp.headers, resp.content, str(resp.url))
        finally:
            sess.close()


def qstash_publish(
    destination: str,
    body: str,
    *,
    forward_headers: Optional[Dict[str, str]] = None,
    delay_seconds: int = 0,
    retries: Optional[int] = None,
    content_dedup: bool = False,
) -> tuple[bool, str]:
    """发布消息到 QStash，由其持久化投递到 destination（自动重试/退避/DLQ）。

    环境变量：QSTASH_URL / QSTASH_TOKEN（兼容 WORKBUDDY_QSTASH_* 旧名）。
    - destination: 目标 API 的完整 URL
    - forward_headers: 透传给目标 API 的请求头——QStash 收到 Upstash-Forward-* 前缀
      的头时会把前缀剥离后原样转发（如 Resend/GitHub 的 Authorization）
    - delay_seconds: >0 时延时投递（Upstash-Delay，Go duration 语法须带单位；
      免费版上限 7 天）
    - retries: 显式重试上限（None = QStash 默认 3 次；任何非 2xx 都重试，
      退避 e^(2.5n)≈12s/2m28s/30m8s，耗尽入 DLQ）
    - content_dedup: 开 10 分钟内容级去重（同 destination+body+headers 的重复
      publish 返回 202 + 原 messageId，防 ack 丢失重发导致目标收双份）

    返回 (是否发布成功, messageId 或失败说明)；200/201/202 均视为成功
    （201 Created 带 messageId；202 = 内容去重命中重复）。
    """
    qstash_url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL")
    qstash_token = os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN")
    if not qstash_url or not qstash_token:
        return False, "未配置 QStash(QSTASH_URL, QSTASH_TOKEN)"

    # 拼接 publish URL：无论 QSTASH_URL 配的是裸域名还是已带 /v2/publish[/<旧topic>]
    # （含无尾斜杠的写法），都先剥掉 publish 路径再统一拼，避免双重前缀。
    # destination 用字面量 URL 而非百分号编码：区域端点（如 qstash-us-east-1）
    # 不解码路径 topic，编码后的 https%3A%2F%2F… 会被判 "endpoint has invalid scheme"
    base = qstash_url.split("/v2/publish", 1)[0].rstrip("/")
    publish_url = f"{base}/v2/publish/{destination}"

    # publish 请求体原样转发给目标，body 必须是目标 API 要求的原始 JSON 文本。
    headers: Dict[str, str] = {
        "Authorization": f"Bearer {qstash_token}",
        "Content-Type": "application/json",
    }
    if delay_seconds > 0:
        # Upstash-Delay 必须带单位（Go duration 语法），纯数字会报
        # "time: missing unit in duration"
        headers["Upstash-Delay"] = f"{int(delay_seconds)}s"
    for name, value in (forward_headers or {}).items():
        headers[f"Upstash-Forward-{name}"] = value
    if retries is not None:
        headers["Upstash-Retries"] = str(int(retries))
    if content_dedup:
        headers["Upstash-Content-Based-Deduplication"] = "true"

    # QStash 发布是控制面调用，必须直连：proxy="" 语义为「禁用任务代理」，
    # 但 infer_proxy 默认开启会在 stdin/异常 argv 场景推断出空前缀 →
    # get_all_proxy_endpoints 扫描全部站点代理 → 捡起 NODESEEK_PROXY(SOCKS)，
    # 空转 run 未装 pysocks 时直接 ModuleNotFoundError 崩溃（2026-11-05 复盘）。
    resp = Http(proxy="", infer_proxy=False).request("POST", publish_url, headers=headers, data=body, timeout=15)
    if resp.code in (200, 201, 202):
        data = resp.json()
        msg_id = str(data.get("messageId", "") or "") if isinstance(data, dict) else ""
        return True, msg_id
    detail = resp.text[:200] if resp.text else ""
    return False, f"HTTP {resp.code}{': ' + detail if detail else ''}"


def create_qstash_schedule(
    destination: str,
    cron: str,
    body: str,
    *,
    method: str = "POST",
    forward_headers: Optional[Dict[str, str]] = None,
    schedule_id: str = "",
    retries: Optional[int] = None,
    timezone_name: str = "",
) -> tuple[bool, str]:
    """创建/覆盖一条 QStash Cron 定时投递（幂等：同 schedule_id 即 update）。

    用途：GitHub Actions 的 schedule 事件只承诺「大致按时」，实测可漂移数小时
    甚至整体丢投（本仓库 4 条 cron 一天只落地约 9 次而非约 52 次）。日报这类
    「必须在固定时刻送达」的任务改用 QStash 精确定时，cron 仅保留为兜底。

    - destination: 目标 API 完整 URL
    - cron: POSIX cron（UTC）；timezone_name 非空时以 CRON_TZ 前缀注入
    - schedule_id: 自定义 ID；已存在则原地更新，避免重复排程
    返回 (是否成功, scheduleId 或失败说明)。
    """
    qstash_url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL")
    qstash_token = os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN")
    if not qstash_url or not qstash_token:
        return False, "未配置 QStash(QSTASH_URL, QSTASH_TOKEN)"

    base = qstash_url.split("/v2/publish", 1)[0].rstrip("/")
    url = f"{base}/v2/schedules/{destination}"

    headers: Dict[str, str] = {
        "Authorization": f"Bearer {qstash_token}",
        "Content-Type": "application/json",
        "Upstash-Cron": f"CRON_TZ={timezone_name} {cron}" if timezone_name else cron,
        "Upstash-Method": method,
    }
    if schedule_id:
        headers["Upstash-Schedule-Id"] = schedule_id
    if retries is not None:
        headers["Upstash-Retries"] = str(int(retries))
    for name, value in (forward_headers or {}).items():
        headers[f"Upstash-Forward-{name}"] = value

    # 控制面调用强制直连（同 qstash_publish，禁用任务代理推断）
    resp = Http(proxy="", infer_proxy=False).request("POST", url, headers=headers, data=body, timeout=15)
    if resp.code in (200, 201, 202):
        data = resp.json()
        sid = str(data.get("scheduleId", "") or "") if isinstance(data, dict) else ""
        return True, sid
    detail = resp.text[:200] if resp.text else ""
    return False, f"HTTP {resp.code}{': ' + detail if detail else ''}"


def schedule_repo_dispatch(event_type: str, delay_seconds: int) -> tuple[bool, str]:
    """通过 QStash 延时 Webhook 触发 GitHub repository_dispatch（跨 run 接力调度）。

    供 workbuddy 放风领奖接力等跨 run 接力场景共用：不在本地阻塞
    等待，由 QStash 在 delay_seconds 后回调 repository_dispatch API 触发下一个
    工作流。QStash 免费版延时上限 7 天，覆盖 24h 级接力。

    环境变量：QSTASH_URL / QSTASH_TOKEN / GH_PAT（需 contents: write —— dispatches API 要求）/ GITHUB_REPO。
    返回 (是否已成功调度, 延时秒数或失败说明)；未配置依赖或发布失败时返回 False，
    调用方自行回退（workbuddy 回退为等下次定时触发）。
    """
    qstash_url = os.getenv("QSTASH_URL") or os.getenv("WORKBUDDY_QSTASH_URL")
    qstash_token = os.getenv("QSTASH_TOKEN") or os.getenv("WORKBUDDY_QSTASH_TOKEN")
    gh_pat = os.getenv("GH_PAT") or os.getenv("GH_TOKEN") or os.getenv("WORKFLOW_TOKEN")
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

    # GitHub 所需的鉴权/接受头通过 Upstash-Forward-* 透传（见 qstash_publish）
    ok, detail = qstash_publish(
        f"https://api.github.com/repos/{repo}/dispatches",
        json.dumps({"event_type": event_type}, ensure_ascii=False),
        forward_headers={
            "Authorization": f"Bearer {gh_pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        delay_seconds=delay_seconds,
    )
    return (True, str(int(delay_seconds))) if ok else (False, detail)


def _upstash_redis_env() -> tuple[str, str]:
    """读取 Upstash Redis REST 凭据（URL 去尾斜杠）。"""
    url = (os.getenv("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN") or ""
    return url, token


def _upstash_redis_request(url: str, token: str, body: str) -> tuple[bool, Any]:
    """POST 一条/多头 Redis 命令到 Upstash REST API。Http 自带 @retry 重试网络抖动。"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    # 控制面调用强制直连（同 qstash_publish，禁用任务代理推断）
    resp = Http(proxy="", infer_proxy=False).request("POST", url, headers=headers, data=body, timeout=15)
    if resp.code == 200:
        return True, resp.json()
    return False, f"HTTP {resp.code}: {resp.text[:200]}"


def upstash_redis_command(command: list) -> tuple[bool, Any]:
    """执行单条 Upstash Redis 命令（REST，免驱动）。

    环境变量：UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN。
    返回 (成功?, 命令结果 或 失败说明)；未配置凭据时返回 False。
    """
    url, token = _upstash_redis_env()
    if not url or not token:
        return False, "未配置 UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN"
    return _upstash_redis_request(url, token, json.dumps(command, ensure_ascii=False))


def upstash_redis_pipeline(commands: list) -> tuple[bool, Any]:
    """管道批量执行多条 Upstash Redis 命令（POST /pipeline，一次 RTT 原子提交）。

    commands 形如 [["SET", "k", "v"], ["HSET", "h", "f", "v"], ...]。
    返回 (成功?, 各命令结果数组 或 失败说明)。
    """
    url, token = _upstash_redis_env()
    if not url or not token:
        return False, "未配置 UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN"
    return _upstash_redis_request(f"{url}/pipeline", token, json.dumps(commands, ensure_ascii=False))


def env(prefix: str, name: str, default: str = "", required: bool = True) -> str:
    clean_prefix = prefix.removeprefix("QL_")
    keys = [
        f"{clean_prefix}{name}",
        f"{clean_prefix}{name.upper()}",
        f"{clean_prefix.upper()}{name}",
        f"{clean_prefix.upper()}{name.upper()}",
        f"{clean_prefix.lower()}{name}",
        f"{clean_prefix.lower()}{name.upper()}",
        f"QL_{clean_prefix}{name}",
        f"QL_{clean_prefix}{name.upper()}",
        f"QL_{clean_prefix.upper()}{name.upper()}",
        f"{prefix}{name}",
        f"{prefix}{name.upper()}",
        f"{clean_prefix}{name}_1",
        f"{clean_prefix}{name.upper()}_1",
        f"{clean_prefix.upper()}{name}_1",
        f"{clean_prefix.upper()}{name.upper()}_1",
        f"{clean_prefix.lower()}{name}_1",
        f"{clean_prefix.lower()}{name.upper()}_1",
        f"QL_{clean_prefix}{name}_1",
        f"QL_{clean_prefix}{name.upper()}_1",
        f"{prefix}{name}_1",
        f"{prefix}{name.upper()}_1",
    ]
    # 不回退裸 {name}/{NAME}：任何同名的全局环境变量都会静默劫持站点配置（凭证串 env 风险）
    seen = set()
    ordered_keys = [k for k in keys if not (k in seen or seen.add(k))]
    for key in ordered_keys:
        value = os.getenv(key)
        if value not in (None, ""):
            return value
    if required and default == "":
        # RuntimeError（而非 SystemExit）：main_guard 的 except Exception 能统一格式化输出
        raise RuntimeError(f"缺少环境变量：{clean_prefix}{name}")
    return default


def env_seq(prefix: str, name: str, default: list[str] | None = None, required: bool = True) -> list[str]:
    """获取多账号序列环境变量（统一支持 <PREFIX>_<NAME>_1, <PREFIX>_<NAME>_2 序列）。

    检索策略：
    1. 优先扫描序号序列：依次查找 <prefix><name>_1, <prefix><name>_2, ...
       （通过 env() 的变体查找规则），直到遇到第一个不存在的序号停止。
       若元素中包含 && 或换行（例如 Secret 回退链注入），自动切分展平。
    2. 若未配置序号（未找到 _1），回退探测未编号的单变量 <prefix><name>：
       - 若单变量存在且包含 && 或换行（兼容过渡期残留），则自动切分。
       - 否则作为单元素列表返回。
    3. 若均未找到：
       - 当 required=True 且 default 为 None 时，抛出 RuntimeError。
       - 否则返回 default if default is not None else []。
    """
    clean_prefix = prefix.removeprefix("QL_")
    results = []
    idx = 1
    while True:
        # 直接查找精确的 _idx 序号变量
        exact_keys = [
            f"{clean_prefix}{name}_{idx}",
            f"{clean_prefix}{name.upper()}_{idx}",
            f"{clean_prefix.upper()}{name}_{idx}",
            f"{clean_prefix.upper()}{name.upper()}_{idx}",
            f"{clean_prefix.lower()}{name}_{idx}",
            f"{clean_prefix.lower()}{name.upper()}_{idx}",
            f"QL_{clean_prefix}{name}_{idx}",
            f"QL_{clean_prefix}{name.upper()}_{idx}",
            f"QL_{clean_prefix.upper()}{name.upper()}_{idx}",
            f"{prefix}{name}_{idx}",
            f"{prefix}{name.upper()}_{idx}",
        ]
        seen = set()
        ordered_keys = [k for k in exact_keys if not (k in seen or seen.add(k))]
        found = ""
        for k in ordered_keys:
            val = os.getenv(k)
            if val not in (None, ""):
                found = val
                break
        if found:
            for piece in re.split(r"\n|&&", found):
                p = piece.strip()
                if p:
                    results.append(p)
            idx += 1
        else:
            break

    if results:
        return results

    # 回退探测未编号单变量
    fallback_val = env(prefix, name, default="", required=False)
    if fallback_val:
        parts = [x.strip() for x in re.split(r"\n|&&", fallback_val) if x.strip()]
        if parts:
            return parts

    if required and default is None:
        raise RuntimeError(f"缺少环境变量：{clean_prefix}{name}_1 或 {clean_prefix}{name}")
    return default if default is not None else []

_AUTH_HEADER_RE = re.compile(r"(?i)authorization[ \t]*:[ \t]*")
_AUTH_STATUS_AT_RE = re.compile(r"HTTP[ \t]?\d{3}")


def _mask_authorization_values(text: str) -> str:
    """遮盖 Authorization 头的字段值：整行到字段边界，同行末尾的 HTTP 状态码保留。

    为什么单独成函数而不写成正则：状态码边界前瞻（`[ \\t]*HTTP`）会在每个候选
    起点重新扫描其后的整段空白，空格串上呈平方级回溯——8k 空格实测 0.26s，
    通知脱敏又走 `limit=None`，长度上限帮不上忙（CodeRabbit round-10）。

    改为单次左到右扫描，每个字符只走一遍；同时跟踪引号状态，避免把
    `response="HTTP 401 …"` 这类**引号内**的文本误判成字段终点而让
    `nonce="n"` 之类的后续参数裸奔（同轮 finding）。

    字段值本身的取舍（round-8/9 累积）：只吃一个 `\\S+` 会把方案关键字当成
    凭据值；按方案白名单取下一个 token 又漏掉自定义方案与 Digest 的逗号参数
    列表。行尾即字段边界，整段遮盖是唯一同时覆盖三种形态的做法。
    """
    if not text:
        return text
    parts: List[str] = []
    pos = 0
    for m in _AUTH_HEADER_RE.finditer(text):
        if m.start() < pos:
            continue
        value_start = m.end()
        line_end = len(text)
        for sep in ("\r", "\n"):
            idx = text.find(sep, value_start)
            if idx != -1 and idx < line_end:
                line_end = idx
        if value_start >= line_end:
            # 空值：不插入占位符，也不跨越到下一行
            continue
        cut = line_end
        in_quote = False
        i = value_start
        while i < line_end:
            ch = text[i]
            if ch == '"':
                in_quote = not in_quote
            elif not in_quote and ch in "Hh" and text[i:i + 4].lower() == "http":
                sm = _AUTH_STATUS_AT_RE.match(text, i, line_end)
                # 状态码必须独占字段尾部，否则只是值的一部分，不能据此截断
                if sm is not None and not text[sm.end():line_end].strip():
                    cut = i
                    while cut > value_start and text[cut - 1] in " \t":
                        cut -= 1
                    break
            i += 1
        parts.append(text[pos:value_start])
        parts.append("<masked>")
        pos = cut
    parts.append(text[pos:])
    return "".join(parts)


_SNIPPET_SENSITIVE_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    # Set-Cookie / Cookie 头：响应回显中最直接的凭据载体
    (re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n;]+"), r"\1<masked>"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"), r"\1<masked>"),
    # 上下文兜底：无字段名时 `Basic <base64>` 仍以裸凭据形态出现（响应体回显、
    # 诊断片段）。要求 `Basic` 为独立单词且其后至少 4 位 base64 字符，避免把
    # 「Basic 认证」之类叙述误杀；该模式线性、无回溯风险（实测 2.5M 字符 0.05s）。
    (re.compile(r"(?i)\bbasic\s+[A-Za-z0-9_\-+/=.]{4,}"), "<masked>"),
    # token/apikey 类键值对（JSON 或 query 形态）。键名一旦出现即视为凭据载体，
    # 值不设最小长度：短值同样可能是有效凭据（短 session id / 一次性 code），
    # 且键名后紧跟的值在诊断片段里没有保留价值。要求值非空且以键名字符类开头，
    # 避免把 `token` 这类普通单词后接冒号的叙述文本整段吃掉。
    (re.compile(
        r"(?i)((?:access[_-]?token|refresh[_-]?token|api[_-]?key|session[_-]?id|"
        r"csrf[_-]?token|token|sign(?:ature)?)['\"]?\s*[:=]\s*['\"]?)"
        r"[A-Za-z0-9_\-+/=.]+"
    ), r"\1<masked>"),
    # 兜底：>=20 位且含数字的高熵串（hex/base64 形态，大概率是 token/签名/密文；
    # 要求含数字以避免误杀普通长单词/URL 路径）
    (re.compile(r"\b(?=[A-Za-z0-9+/=_\-]*\d)[A-Za-z0-9+/=_\-]{20,}\b"), "<masked>"),
)

def sanitize_snippet(text: str, limit: Optional[int] = 300) -> str:
    """失败诊断片段脱敏：抹除 Cookie/token 形态内容后去换行截断。

    异常消息会经 run_task 输出进入公开 Actions 日志、Discord 卡片与邮件日报，
    任何携带服务端原始响应的文本必须先过这里。

    `limit=None` 关闭截断：脱敏是扩张替换（值 → 定长占位符），按原文长度设上限
    会在替换后把尾部内容切掉。调用方若需要「未截断的安全全文」应显式传 None，
    自行承担长度责任（CodeRabbit round-8）。
    """
    s = text or ""
    # Authorization 需要按行扫描（引号状态 + 状态码边界），放在正则链之前
    s = _mask_authorization_values(s)
    for pat, repl in _SNIPPET_SENSITIVE_PATTERNS:
        s = pat.sub(repl, s)
    s = s.replace("\n", " ")
    if limit is None:
        return s
    return s[:limit]

# 裸 PII 形态（不依赖字段名）：
# - 邮箱：本地部分按 RFC 5322 atext（含 .!#$%&'*+-/=?^_`{|}~），域名要求至少
#   一个点 + >=2 位 TLD；标签内允许非 ASCII（中文域名如 例子.中国、拼音域名），
#   但排除空白与 @，避免把自然语言里的 @ 当成邮箱起点而过度遮盖。
#   引号等 atext 之外字符包裹的本地部分走兜底规则整段遮盖。
# - 手机号：11 位孤立数字段；带空格/连字符分隔的常见写法（138-0013-8000 /
#   138 0013 8000）单独识别，只保留末 4 位；带国家码形态（+86xxxxxxxxxxx）
#   单独识别。前后邻接数字的 11 位段不命中（避免误伤 13 位毫秒时间戳 /
#   16 位 GUID / 长 docid），因此不是无差别替换。
# 本地部分必须限长（1~64），并在其前加 `(?=[\s\S]{0,64}@)` 前瞻：无 `@` 的
# 长串上，引擎本会在每个起点重试「本地部分 + 域名重复」，100k 字符实测 ~11s/次
# （无界回溯）；前瞻把起点收敛到 `@` 前 64 字符内，同样的输入降到 ~0.04s。
# 域名标签仍排除 `.`：否则连续点号可被切成多种标签组合，匹配失败时逐一枚举，
# `"x@" + "a." * 20 + "!"` 实测 0.1s、28 组 3s 未返回，会直接卡死通知路径。
_PII_DOMAIN_LABEL = r"[^\s@.]+"
_PII_EMAIL_LOCAL_MAX = 64
_PII_EMAIL_RE = re.compile(
    rf"(?=[\s\S]{{0,{_PII_EMAIL_LOCAL_MAX}}}@)"
    rf"[A-Za-z0-9.!#$%&'*+/=?^_`{{|}}~-]{{1,{_PII_EMAIL_LOCAL_MAX}}}@"
    rf"(?:{_PII_DOMAIN_LABEL}\.)+[A-Za-z0-9一-鿿]{{2,}}"
)
_PII_EMAIL_FALLBACK_RE = re.compile(
    rf"[^\s@]{{1,{_PII_EMAIL_LOCAL_MAX}}}@"
    rf"(?:{_PII_DOMAIN_LABEL}\.)+[A-Za-z0-9一-鿿]{{2,}}"
)
_PII_INTL_PHONE_RE = re.compile(r"(?<![\d+])(\+(?:86)?)(\d{11})(?!\d)")
# 带国家码且带分隔符的国际号码（`+1 202-555-0123` / `+44 20 7946 0958`）。原规则
# 只认 `+86` + 连续 11 位，其余国家码与分隔写法整条漏过（CodeRabbit round-9）。
# 要求国家码后至少 9 位数字：`+1 2020-01-01`（8 位）这类日期写法因此不命中。
# 重复次数有界（E.164 最长 15 位），避免在超长数字串上无界回溯。
_PII_INTL_SEP_PHONE_RE = re.compile(r"(?<![\d+])(\+\d{1,3})((?:[ -]?\d){9,20})(?!\d)")
# 日期/时间写法不是号码：`+1 2020-01-01 12:00` 的位数足以落入上面的重复范围，
# 必须显式排除，否则报告里的版本号+时间戳会被整段打码，诊断信息全丢。
# 只有**完整**日期且边界干净时才放行：`2020-01-0188` 这类「日期前缀 + 多余数字」
# 与号码存在歧义，必须按号码遮盖（CodeRabbit round-10）。
_PII_DATE_LIKE_RE = re.compile(
    r"^[ \t-]*\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?!\d)(?=$|[\s,:])"
)
# 分隔符写法必须让分隔符两侧都是数字，且整段恰好 11 位——否则版本号、端口、
# 日期区间这类带连字符/空格的数字串会被误判成手机号。
_PII_SEP_PHONE_RE = re.compile(r"(?<!\d)(\d{3})[- ](\d{4})[- ](\d{4})(?!\d)")
_PII_PHONE_RE = re.compile(r"(?<!\d)\d{11}(?!\d)")


def _mask_intl_sep_phone(m: "re.Match", mask_char: str = "*") -> str:
    """带国家码的分隔号码脱敏；日期/时间形态整段放行，避免误伤时间戳。"""
    body = m.group(2)
    if _PII_DATE_LIKE_RE.match(body):
        return m.group(0)
    return m.group(1) + _mask_digits_keep_last4(body, mask_char=mask_char)


def _mask_digits_keep_last4(text: str, mask_char: str = "*") -> str:
    """保留末 4 位数字，其余数字逐位替换为掩码符，分隔符与结构原样保留。

    用于 `+1 202-555-0123` 这类带国家码的分隔写法：整段抹掉会丢失号码形态，
    只留末 4 位既符合仓库脱敏口径，又保持可读的 `+cc ***-***-0123` 结构。
    """
    idx = [i for i, ch in enumerate(text) if ch.isdecimal()]
    drop = len(idx) - 4
    if drop <= 0:
        return text
    cut = set(idx[:drop])
    return "".join(mask_char if i in cut else ch for i, ch in enumerate(text))


def redact_pii(text: Any, mask_char: str = "*") -> str:
    """对任意文本中的裸手机号/邮箱脱敏（保留原文结构与其余内容）。

    与 sanitize_snippet 的区别：本函数按「出现形态」而非字段名匹配，专治
    服务端原始文案里不带 key 的裸 PII。典型泄漏面是代理标签——用户把节点命名成
    自己的邮箱时，该标签会经 display_name/to_dict 明文流到公开仓库的 Actions
    日志与日报，进而成为钓鱼邮件的目标（用户明确反馈过这一危害）。

    顺序是硬要求：先邮箱后手机号。反序会把 `user13800138000@example.com` 的
    本地部分当成手机号打码，破坏邮箱形态后域名就不再被识别，反而裸奔。
    邮箱兜底规则覆盖 atext 之外的引号包裹本地部分（如 `"user"@example.com`），
    此时整段保守遮盖，不留可识别前缀。
    """
    s = str(text or "")
    if not s:
        return s
    s = _PII_EMAIL_RE.sub(lambda m: mask_email(m.group(0), mask_char=mask_char), s)
    s = _PII_EMAIL_FALLBACK_RE.sub(
        lambda m: f"{mask_char * 3}@{mask_char * 3}", s
    )
    s = _PII_INTL_PHONE_RE.sub(
        lambda m: m.group(1) + mask_phone(m.group(2), mask_char=mask_char), s
    )
    # 带国家码的分隔写法紧随其后：`+86 138 0013 8000` 由上一条的连续写法匹配不到，
    # 必须在这里补上；只留末 4 位数字、分隔符原样保留（CodeRabbit round-9）。
    s = _PII_INTL_SEP_PHONE_RE.sub(
        lambda m: _mask_intl_sep_phone(m, mask_char=mask_char), s
    )
    # 分隔符写法先于裸号处理：否则 138-0013-8000 里的 00138000 等子串会被裸号规则命中，
    # 产生不符合「只留末 4」的残留。号码拼接后统一交 mask_phone，绝不保留首位数字；
    # 仅在遮盖完成后重新插入原分隔符，保持可读结构而不泄漏分组内容。
    s = _PII_SEP_PHONE_RE.sub(
        lambda m: mask_phone(m.group(1) + m.group(2) + m.group(3), mask_char=mask_char),
        s,
    )
    return _PII_PHONE_RE.sub(lambda m: mask_phone(m.group(0), mask_char=mask_char), s)

def must_match(pattern: str, text: str, label: str, flags: int = 0) -> str:
    m = re.search(pattern, text, flags)
    if not m:
        # 失败时附脱敏后的响应片段,便于诊断服务端返回了什么(重定向/风控/模板变更)
        if text:
            raise RuntimeError(f"未提取到 {label}（响应片段: {sanitize_snippet(text)}）")
        raise RuntimeError(f"未提取到 {label}（空响应）")
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
    s = str(s)
    # 移除 CDATA 标记，保留内容
    s = re.sub(r"<!\[CDATA\[|\]\]>", "", s)
    # 提取 <img> 的 alt/title 文本后再移除标签（否则 alt="今日已签" 会跟着标签一起消失）
    s = re.sub(r"<img\b[^>]*\balt=[\"']([^\"']*)[\"'][^>]*>", r"\1", s, flags=re.I)
    s = re.sub(r"<img\b[^>]*\btitle=[\"']([^\"']*)[\"'][^>]*>", r"\1", s, flags=re.I)
    return html.unescape(re.sub(r"<[^>]*>", "", s)).strip()


def mask_phone(value: Any, mask_char: str = "*") -> str:
    """手机号脱敏：只保留末 4 位，其余全部掩码（2026-10-31 脱敏增强，用户指令）。

    11 位手机号 13812345678 -> *******5678（7 个掩码符 + 末 4 位）；
    8~15 位纯数字串同规则；其余形态回退 mask_str 通用规则。"""
    s = str(value or "").strip()
    if len(s) == 11 and s.isdigit():
        return mask_char * (len(s) - 4) + s[-4:]
    if 8 <= len(s) <= 15 and s.isdigit():
        return mask_char * (len(s) - 4) + s[-4:]
    return mask_str(s, mask_char=mask_char)


def mask_nickname(value: Any, mask_char: str = "*") -> str:
    """昵称/用户名脱敏：只保留末 3 位字符，前缀用定长 *** 防长度泄漏。

    「张小三」(3 位) -> ***（≤4 位全脱，防短名反推）；「王小虎要加油」-> ***加油。"""
    s = str(value or "").strip()
    if len(s) <= 4:
        return mask_char * 3
    return mask_char * 3 + s[-3:]


def mask_email(value: Any, mask_char: str = "*") -> str:
    """邮箱脱敏：前缀只保留末 4 位，域名（尾缀）全额脱敏（用户指令）。

    user123@gmail.com -> ***r123@***。前缀用定长 *** 防长度泄漏，
    域名不再保留首字符/TLD（欧美信息保护法数据最小化口径）。"""
    s = str(value or "").strip()
    if "@" not in s or s.startswith("@") or s.endswith("@"):
        return mask_str(s, mask_char=mask_char)
    user_part, _domain = s.split("@", 1)
    if len(user_part) <= 4:
        return f"{mask_char * 3}@{mask_char * 3}"
    return f"{mask_char * 3}{user_part[-4:]}@{mask_char * 3}"


def mask_str(value: Any, keep_start: int | None = None, keep_end: int | None = None, mask_char: str = "*") -> str:
    """智能脱敏字符串（用户名、手机号、邮箱、账号 ID 等）。

    脱敏规则（2026-10-31 增强：手机号只留末4、昵称/通用只留末尾、邮箱域名全脱）：
    - 邮箱：mask_email（前缀末4 + 域名全额脱敏），user123@gmail.com -> ***r123@***
    - 手机号/纯数字 ID（8~15位）：mask_phone（只留末4），13812345678 -> *******5678
    - 自定义 keep_start / keep_end：按指定保留字符数脱敏（调用方显式决策）
    - 默认通用策略（欧美信息保护法数据最小化：不露头部字符，定长掩码防长度泄漏）：
      * 长度 <= 4: 全脱 "***"
      * 长度 >= 5: 定长 "***" + 末 3 位，如 "hun8461" -> "***461", "yd_219491735" -> "***735"
    """
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""

    # 邮箱处理：前缀末4 + 域名全额脱敏
    if "@" in s and not (s.startswith("@") or s.endswith("@")):
        return mask_email(s, mask_char=mask_char)

    # 手机号/纯数字 ID 处理（8~15 位，显式 keep 参数优先）
    if keep_start is None and keep_end is None and 8 <= len(s) <= 15 and s.isdigit():
        return mask_phone(s, mask_char=mask_char)

    n = len(s)
    if n <= 1:
        return mask_char
    if keep_start is not None and keep_end is not None:
        ks = max(0, min(keep_start, n))
        ke = max(0, min(keep_end, n - ks))
        if ks == 0 and ke == 0:
            return mask_char * 3
        return f"{s[:ks]}***{s[n - ke:] if ke > 0 else ''}"

    # 默认通用策略：定长掩码 + 只露尾部（防头部重识别 + 防长度泄漏）
    if n <= 4:
        return mask_char * 3
    return f"{mask_char * 3}{s[-3:]}"

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
