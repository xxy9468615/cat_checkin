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
        get_candidate_proxy_urls,
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
            get_candidate_proxy_urls,
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
            get_candidate_proxy_urls,
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
            data = json.loads(open(state_file, encoding="utf-8").read())
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

        # 原生任务代理能力自适应：若未显式传 proxy，自动探测任务环境配置
        if not proxy:
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
                # - http(s):// 走 urllib 原生 ProxyHandler（HTTPS 经 CONNECT 隧道，隧道内走端到端 TLS）
                # - socks5(h)://, socks4(a):// 优先使用 sockshandler.SocksiPyHandler（强制 rdns=True 远程 DNS，隔离全局 socket）
                #   兜底回退为 pysocks 全局 monkey-patch socket，并在后续/直连时及时还原
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
                    used_handler = False
                    try:
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
                        used_handler = True
                    except Exception:
                        pass

                    if not used_handler:
                        socks.set_default_proxy(
                            socks.SOCKS5,
                            u.hostname or "",
                            u.port or 1080,
                            rdns=True,  # 强制远程 DNS
                            username=urllib.parse.unquote(u.username) if u.username else None,
                            password=urllib.parse.unquote(u.password) if u.password else None,
                        )
                        socket.socket = socks.socksocket
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
            except curl_cffi.RequestsError:
                # 网络级失败（DNS/连接/TLS 握手/超时）收敛为合成 -1 响应，让 @retry 生效
                return Response(-1, None, "curl_cffi network error".encode(), url)
            except Exception:
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
        # 代理出口：优先走具体的 ProxyEndpoint（含 socks5/http），与 urllib 链路一致
        if getattr(self, "proxy_endpoint", None):
            sess_kwargs["proxies"] = {
                "http": self.proxy_endpoint.url,
                "https": self.proxy_endpoint.url,
            }
        elif getattr(self, "has_proxy", False):
            # 仅有代理标记但无 endpoint 对象（sockshandler 全局 patch 类）——curl_cffi 原生
            # 支持 socks5:// 地址，直接用代理 URL 等价表达
            sess_kwargs["proxies"] = {
                "http": "socks5://127.0.0.1:1080",
                "https": "socks5://127.0.0.1:1080",
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

    resp = Http().request("POST", publish_url, headers=headers, data=body)
    if resp.code in (200, 201, 202):
        data = resp.json()
        msg_id = str(data.get("messageId", "") or "") if isinstance(data, dict) else ""
        return True, msg_id
    detail = resp.text[:200] if resp.text else ""
    return False, f"HTTP {resp.code}{': ' + detail if detail else ''}"


def schedule_repo_dispatch(event_type: str, delay_seconds: int) -> tuple[bool, str]:
    """通过 QStash 延时 Webhook 触发 GitHub repository_dispatch（跨 run 接力调度）。

    供 workbuddy 放风领奖接力、latvi 24h 冷却签到接力等场景共用：不在本地阻塞
    等待，由 QStash 在 delay_seconds 后回调 repository_dispatch API 触发下一个
    工作流。QStash 免费版延时上限 7 天，覆盖 24h 级接力。

    环境变量：QSTASH_URL / QSTASH_TOKEN / GH_PAT（需 contents: write —— dispatches API 要求）/ GITHUB_REPO。
    返回 (是否已成功调度, 延时秒数或失败说明)；未配置依赖或发布失败时返回 False，
    调用方自行回退（workbuddy 回退为等下次定时触发，latvi 回退为原地等待）。
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
    resp = Http().request("POST", url, headers=headers, data=body)
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

def must_match(pattern: str, text: str, label: str, flags: int = 0) -> str:
    m = re.search(pattern, text, flags)
    if not m:
        # 失败时附响应片段(截断 300 字、去换行),便于诊断服务端返回了什么(重定向/风控/模板变更)
        snippet = (text or "").replace("\n", " ")[:300]
        if text:
            raise RuntimeError(f"未提取到 {label}（响应片段: {snippet}）")
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

def _mask_domain(domain: str, mask_char: str = "*") -> str:
    """邮箱域名脱敏：保留首字符与尾部后缀，其余掩码。

    - aifre.cyou   -> a***.cyou
    - gmail.com    -> g***.com
    - mail.foo.co.uk -> m***.co.uk（co/com/net/org/gov/edu/ac + 国家码的二级后缀整段保留）
    - localhost    -> l***
    - 极短/异常域  -> ***（掩码兜底，绝不原样返回）
    """
    domain = (domain or "").strip().rstrip(".")
    if not domain:
        return mask_char * 3
    labels = domain.split(".")
    if len(labels) == 1:
        return f"{domain[0]}{mask_char * 3}" if len(domain) > 1 else mask_char * 3
    second_level = {"co", "com", "net", "org", "gov", "edu", "ac"}
    keep_labels = 2 if len(labels) >= 3 and labels[-2].lower() in second_level else 1
    tail = ".".join(labels[-keep_labels:])
    return f"{domain[0]}{mask_char * 3}.{tail}"


def mask_str(value: Any, keep_start: int | None = None, keep_end: int | None = None, mask_char: str = "*") -> str:
    """智能脱敏字符串（用户名、手机号、邮箱、账号 ID 等）。

    脱敏规则：
    - 邮箱：@ 前缀与域名都脱敏，仅保留域名 TLD（co.uk/com.cn 等二级后缀整段保留），
      如 user123@gmail.com -> u***3@g***.com，abc@aifre.cyou -> a***b@a***.cyou
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

    # 邮箱处理：本地部分常规脱敏；域名保留首字符 + TLD，其余掩码
    if "@" in s and not (s.startswith("@") or s.endswith("@")):
        user_part, domain_part = s.split("@", 1)
        masked_user = mask_str(user_part, keep_start=keep_start, keep_end=keep_end, mask_char=mask_char)
        return f"{masked_user}@{_mask_domain(domain_part)}"

    # 手机号处理 (11位纯数字)
    if len(s) == 11 and s.isdigit() and keep_start is None and keep_end is None:
        return f"{s[:3]}****{s[-4:]}"

    n = len(s)
    if n <= 1:
        return mask_char
    if keep_start is not None and keep_end is not None:
        ks = max(0, min(keep_start, n))
        ke = max(0, min(keep_end, n - ks))
        if ks == 0 and ke == 0:
            return mask_char * 3
        return f"{s[:ks]}***{s[n - ke:] if ke > 0 else ''}"
    if n == 2:
        return f"{s[0]}{mask_char}"

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
