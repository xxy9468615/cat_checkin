#!/usr/bin/env python3
"""代理节点健康自检与死代理诊断工具。

功能说明：
1. 自动收集环境变量（或 .env / 命令行）配置的全部自建代理与业务代理。
2. 并发探测连通性、出口落地 IP、归属地理位置、延迟及主流业务站点（NodeSeek、52Pojie、AgentRouter等）可达性。
3. 对死代理（不可达、握手超时、证书报错、WAF封禁）生成统一识别名称的精准替换建议报告。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from proxy_manager import (
    ProxyEndpoint,
    format_dead_proxy_alert,
    get_all_proxy_endpoints,
    mask_proxy_url,
    parse_proxies_text,
    parse_proxy_line,
)


@dataclass
class ProxyCheckResult:
    endpoint: ProxyEndpoint
    alive: bool = False
    latency_ms: float = 0.0
    exit_ip: str = ""
    ip_geo: str = ""
    ip_isp: str = ""
    error_msg: str = ""
    site_status: Dict[str, str] = field(default_factory=dict)

    @property
    def status_icon(self) -> str:
        if not self.alive:
            return "❌ 死代理"
        if self.latency_ms > 2500 or any("403" in s or "50" in s for s in self.site_status.values()):
            return "⚠️ 告警/迟钝"
        return "✅ 正常"


def _check_tcp_ping(host: str, port: int, timeout: float = 5.0) -> Tuple[bool, float, str]:
    """测试 TCP 端口可达性与延迟（ms）。"""
    t0 = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        latency = (time.perf_counter() - t0) * 1000.0
        sock.close()
        return True, round(latency, 1), ""
    except Exception as exc:
        sock.close()
        return False, 0.0, f"TCP连接失败: {exc}"


def _get_urllib_opener(endpoint: ProxyEndpoint, timeout: float = 8.0) -> urllib.request.OpenerDirector:
    """构建针对指定代理的 urllib opener。"""
    handlers = []
    proxy_url = endpoint.url
    if endpoint.protocol in ("http", "https"):
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        # socks5
        try:
            import socks
        except ImportError:
            raise RuntimeError("缺少 pysocks 依赖，无法测试 socks5 代理")
        u = urllib.parse.urlparse(proxy_url)
        # 建立独立 socket handler
        socks_handler = urllib.request.ProxyHandler({})
        # 为了隔离多线程，利用 pysocks 创建单独的连接 opener
        handlers.append(socks_handler)
    return urllib.request.build_opener(*handlers)


def _probe_via_curl_or_urllib(
    endpoint: ProxyEndpoint,
    url: str,
    timeout: float = 8.0,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, float]:
    """通过代理请求目标 URL，首选 curl_cffi，回退 urllib/subprocess curl。"""
    headers = headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    t0 = time.perf_counter()

    # 1. 尝试使用 curl-cffi（支持 Chrome TLS 指纹与直接 socks5 代理）
    try:
        from curl_cffi import requests as cffi_requests

        proxies = {"http": endpoint.url, "https": endpoint.url}
        resp = cffi_requests.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            impersonate="chrome",
            allow_redirects=True,
        )
        latency = (time.perf_counter() - t0) * 1000.0
        return resp.status_code, resp.text, round(latency, 1)
    except ImportError:
        pass
    except Exception as exc:
        # curl_cffi 发生网络错误
        latency = (time.perf_counter() - t0) * 1000.0
        return 0, str(exc), round(latency, 1)

    # 2. 降级尝试 subprocess curl 命令（系统原生支持 socks5:// 与 http://）
    import subprocess

    cmd = [
        "curl",
        "-sS",
        "-x",
        endpoint.url,
        "-m",
        str(int(timeout)),
        "-w",
        "\n%{http_code}\n%{time_total}",
        url,
    ]
    for k, v in headers.items():
        cmd.extend(["-H", f"{k}: {v}"])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        lines = res.stdout.rsplit("\n", 2)
        if len(lines) >= 2 and lines[-2].isdigit():
            http_code = int(lines[-2])
            body = lines[0] if len(lines) > 2 else ""
            latency = (time.perf_counter() - t0) * 1000.0
            return http_code, body, round(latency, 1)
        err = res.stderr.strip() or "curl 未知错误"
        return 0, err, (time.perf_counter() - t0) * 1000.0
    except Exception as e:
        return 0, str(e), (time.perf_counter() - t0) * 1000.0


def _query_ip_geo(ip: str) -> Tuple[str, str]:
    """查询出口 IP 的地理位置与 ISP 归属（优先 ip-api.com / 备用静态推断）。"""
    if not ip or ip.startswith(("127.", "10.", "192.168.")):
        return "本地环回/私有网络", "局域网"
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as",
            headers={"User-Agent": "curl/7.68.0"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            country = data.get("country", "")
            city = data.get("city", "")
            isp = data.get("isp") or data.get("org", "")
            geo = f"{country} {city}".strip()
            return geo or "未知地理位置", isp or "未知运营商"
    except Exception:
        return "公网", "未知"


def check_single_proxy(
    endpoint: ProxyEndpoint,
    test_sites: bool = True,
    timeout: float = 8.0,
) -> ProxyCheckResult:
    """全面体检单个代理节点。"""
    res = ProxyCheckResult(endpoint=endpoint)

    # 1. 基础连接探测与延迟测试（通过出口探测接口测出真出口 IP）
    # 尝试访问 api.ipify.org
    code, body, lat = _probe_via_curl_or_urllib(endpoint, "https://api.ipify.org", timeout=timeout)
    if code != 200 or not body:
        # 尝试备用接口 httpbin.org/ip
        code, body, lat = _probe_via_curl_or_urllib(
            endpoint, "https://httpbin.org/ip", timeout=timeout
        )
        if code == 200 and "origin" in body:
            try:
                res.exit_ip = json.loads(body).get("origin", "").split(",")[0].strip()
            except Exception:
                pass
    else:
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)
        if ip_match:
            res.exit_ip = ip_match.group(0)

    if not res.exit_ip:
        # 代理完全不可达，标记为死代理
        res.alive = False
        res.error_msg = body[:100] if body else "连接超时或代理拒绝连接"
        return res

    res.alive = True
    res.latency_ms = lat
    res.ip_geo, res.ip_isp = _query_ip_geo(res.exit_ip)

    # 2. 关键业务目标站点可达性探测
    if test_sites:
        targets = [
            ("AgentRouter", "https://ps.air-outer.com"),
            ("NodeSeek", "https://www.nodeseek.com"),
            ("52Pojie", "https://www.52pojie.cn/index.php"),
            ("SMZDM", "https://user-api.smzdm.com/checkin"),
        ]
        for name, url in targets:
            scode, sbody, _ = _probe_via_curl_or_urllib(
                endpoint, url, timeout=max(5.0, timeout - 2)
            )
            if scode in (200, 204, 301, 302):
                res.site_status[name] = f"HTTP {scode} OK"
            elif scode == 403 and "Just a moment" in sbody:
                res.site_status[name] = "CF 5秒盾阻断"
            elif scode == 403 and ("安域" in sbody or "WAF" in sbody or "防黑客" in sbody):
                res.site_status[name] = "安域 WAF 拦截"
            elif scode == 0:
                res.site_status[name] = "连接超时/被拒"
            else:
                res.site_status[name] = f"HTTP {scode}"

    return res


def run_proxy_healthcheck(
    custom_proxies: Optional[List[ProxyEndpoint]] = None,
    test_sites: bool = True,
    timeout: float = 8.0,
    max_workers: int = 5,
) -> Tuple[List[ProxyCheckResult], List[ProxyCheckResult]]:
    """批量并发检测所有代理节点，返回 (存活列表, 死代理列表)。"""
    if custom_proxies:
        endpoints = custom_proxies
    else:
        endpoints = get_all_proxy_endpoints(include_self_hosted=True, include_backups=True)

    if not endpoints:
        print("ℹ️ 未发现任何配置的代理节点（已扫描 SELF_HOSTED_PROXIES, 业务专属 PROXY 等）。")
        return [], []

    print(f"🚀 开始并发代理健康体检 (共 {len(endpoints)} 个节点, 并发线程: {max_workers})...\n")

    alive_list: List[ProxyCheckResult] = []
    dead_list: List[ProxyCheckResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(check_single_proxy, ep, test_sites, timeout): ep for ep in endpoints
        }
        for future in concurrent.futures.as_completed(future_map):
            try:
                result = future.result()
                if result.alive:
                    alive_list.append(result)
                else:
                    dead_list.append(result)
            except Exception as e:
                ep = future_map[future]
                dead_list.append(ProxyCheckResult(endpoint=ep, alive=False, error_msg=str(e)))

    # 结果按识别名称排序
    alive_list.sort(key=lambda r: (not r.endpoint.is_self_hosted, r.endpoint.name))
    dead_list.sort(key=lambda r: (not r.endpoint.is_self_hosted, r.endpoint.name))

    return alive_list, dead_list


def print_healthcheck_report(alive_list: List[ProxyCheckResult], dead_list: List[ProxyCheckResult]) -> None:
    """以终端格式化表格与卡片输出自检诊断报告。"""
    total = len(alive_list) + len(dead_list)
    print("=" * 80)
    print(f"📊 代理出口健康自检报告 | 总计: {total} | 存活: {len(alive_list)} | 死代理: {len(dead_list)}")
    print("=" * 80)

    # 1. 打印存活代理详细信息
    if alive_list:
        print("\n【✅ 存活就绪代理清单】")
        for idx, res in enumerate(alive_list, 1):
            ep = res.endpoint
            tag = " [自建]" if ep.is_self_hosted else ""
            src = f" ({ep.source})" if ep.source else ""
            print(f"[{idx}] {res.status_icon} {ep.display_name}{tag}{src}")
            print(f"    • 连接地址: {ep.safe_url}")
            print(f"    • 出口 IP: {res.exit_ip} | 延迟: {res.latency_ms}ms")
            print(f"    • 归属信息: {res.ip_geo} ({res.ip_isp})")
            if res.site_status:
                site_line = " | ".join(f"{k}: {v}" for k, v in res.site_status.items())
                print(f"    • 站点连通: {site_line}")
            print("-" * 70)

    # 2. 打印死代理清单与替换指引
    if dead_list:
        print("\n" + "=" * 80)
        print("🚨 【死代理 / 不可用节点替换清单（请及时更新）】")
        print("=" * 80)
        for idx, res in enumerate(dead_list, 1):
            ep = res.endpoint
            tag = " [自建]" if ep.is_self_hosted else ""
            src_str = ep.source or "环境变量"
            print(f"\n👉 [{idx}] {ep.display_name}{tag}")
            print(f"   • 来源配置: {src_str}")
            print(f"   • 代理地址: {ep.safe_url}")
            print(f"   • 失效原因: {res.error_msg or '连接超时/拒绝连接/无网络响应'}")
            print(f"   • 原始定义: {ep.raw_input}")
            print(f"   💡 替换处置建议: 该节点已彻底失效(死代理)，请登录对应服务商后台排查，")
            print(f"      并在 GitHub Secrets 的 [{src_str}] 中将其替换为有效的新代理节点！")
        print("=" * 80)
    else:
        print("\n🎉 恭喜！当前所有配置的代理节点均连通良好，无死代理！")


def main() -> None:
    parser = argparse.ArgumentParser(description="代理自建与多渠道节点健康自检工具")
    parser.add_argument("proxies", nargs="*", help="可选命令行传入代理串，如 'socks5://1.2.3.4:1080#自建-HK'")
    parser.add_argument("--no-sites", action="store_true", help="跳过目标业务站点(NodeSeek/52Pojie等)的探测")
    parser.add_argument("--timeout", type=float, default=8.0, help="单节点超时时间(秒，默认 8.0)")
    parser.add_argument("--workers", type=int, default=6, help="并发线程数(默认 6)")
    parser.add_argument("--env-file", default=".env", help="本地 .env 路径")
    parser.add_argument("--strict", action="store_true", help="严格模式: 若存在死代理则以退出码 1 结束")

    args = parser.parse_args()

    # 尝试加载 .env
    env_path = Path(args.env_file)
    if env_path.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path)
        except ImportError:
            # 简单纯文本加载
            for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k not in os.environ:
                        os.environ[k] = v

    custom_eps: Optional[List[ProxyEndpoint]] = None
    if args.proxies:
        custom_eps = []
        for p in args.proxies:
            eps = parse_proxies_text(p, default_name_prefix="命令行输入")
            custom_eps.extend(eps)

    alive, dead = run_proxy_healthcheck(
        custom_proxies=custom_eps,
        test_sites=not args.no_sites,
        timeout=args.timeout,
        max_workers=args.workers,
    )

    print_healthcheck_report(alive, dead)

    if args.strict and dead:
        sys.exit(1)


if __name__ == "__main__":
    main()
