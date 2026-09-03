#!/usr/bin/env python3
"""统一代理管理、自建代理解析与健康检测模块。

功能特性：
1. 统一识别名称解析（支持 URI Fragment #名称、[名称] 前缀、键值对等多种语法规范）。
2. 自建代理（Self-hosted Proxy）逻辑支持与优先级调度（SELF_HOSTED_PROXIES > 业务代理 > 全局备用代理）。
3. 敏感凭据自动脱敏（打印日志绝不泄漏账号密码）。
4. 候选代理列表解析与去重。
5. 死代理诊断与替换指引生成。
"""

from __future__ import annotations

import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class ProxyEndpoint:
    """代理节点描述结构。"""

    name: str  # 统一识别名称，如 "自建-香港-01"
    url: str  # 完整可用代理连接串，如 "socks5://user:pass@1.2.3.4:1080"
    safe_url: str  # 脱敏后的安全连接串，如 "socks5://***:***@1.***.***.4:****"
    protocol: str  # "socks5", "http", "https"
    host: str  # "1.2.3.4"
    port: int  # 1080
    raw_input: str = ""  # 原始输入行
    source: str = ""  # 来源环境变量名
    is_self_hosted: bool = False  # 是否标记为自建代理

    @property
    def host_port(self) -> str:
        """返回 host:port 组合（仅供内部网络传输，严禁直接打印在日志）。"""
        return f"{self.host}:{self.port}"

    @property
    def display_name(self) -> str:
        """友好的安全显示名称：严格仅显示节点名称，绝不附带真实 IP 与端口。"""
        clean = self.name.strip()
        if (clean.startswith("【") and clean.endswith("】")) or (
            clean.startswith("[") and clean.endswith("]")
        ):
            return clean
        return f"【{clean}】"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.safe_url,
            "protocol": self.protocol,
            "display_name": self.display_name,
            "source": self.source,
            "is_self_hosted": self.is_self_hosted,
        }

    def __str__(self) -> str:
        return self.display_name


def mask_host(host: str) -> str:
    """对 IP 地址或域名进行安全脱敏（首尾可见、中间掩码，防止在公开日志中暴露资产）。

    示例:
    112.64.135.45 -> 112.***.***.45
    hk01.myvps.net -> h***1.myvps.net
    127.0.0.1 / localhost -> 原样保留
    """
    if not host:
        return "***"
    if host in ("127.0.0.1", "localhost", "0.0.0.0"):
        return host
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.***.***.{parts[3]}"
    if "." in host:
        sub, rest = host.split(".", 1)
        masked_sub = f"{sub[0]}***{sub[-1]}" if len(sub) > 2 else "***"
        return f"{masked_sub}.{rest}"
    if len(host) > 4:
        return f"{host[:2]}***{host[-2:]}"
    return "***"


def mask_proxy_url(url: str) -> str:
    """对代理 URL 进行严格多层脱敏处理（隐去密码、掩码主机、隐去敏感端口）。

    示例:
    socks5://admin:secret123@1.2.3.4:1080 -> socks5://***:***@1.***.***.4:****
    http://5.6.7.8:8080 -> http://5.***.***.8:****
    """
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme or "socks5"
        masked_h = mask_host(parsed.hostname or "")
        return f"{scheme}://***:***@{masked_h}:****"
    except Exception:
        return "proxy://***:***@***:****"


def parse_proxy_line(
    raw_line: str,
    default_name_prefix: str = "",
    explicit_name: str = "",
    source_env: str = "",
    is_self_hosted: bool = False,
) -> Optional[ProxyEndpoint]:
    """解析单行代理配置，提取统一识别名称与连接 URL。

    支持语法规范：
    1. URI Fragment 格式（推荐，标准 URL 规范）：
       socks5://user:pass@1.2.3.4:1080#自建-香港-01
       http://5.6.7.8:8080#自建-美西-02
    2. 中括号 / 尖括号前缀语法：
       [自建-HK-01] socks5://user:pass@1.2.3.4:1080
       【自建-日本住宅】 http://1.2.3.4:8080
    3. 键值对语法：
       自建-HK-01 = socks5://user:pass@1.2.3.4:1080
       自建-US: socks5://user:pass@1.2.3.4:1080
    4. 裸 URL / host:port 降级（自动推导规范名称）：
       socks5://user:pass@1.2.3.4:1080 -> 名称: [自建节点-1.2.3.4:1080]
       1.2.3.4:1080 -> 默认 socks5://1.2.3.4:1080

    返回 ProxyEndpoint 对象，解析失败或为空行返回 None。
    """
    line = raw_line.strip()
    if not line or line.startswith(("#", "//", ";")):
        return None

    extracted_name = ""
    proxy_part = line

    # 1. 语法匹配：前缀中括号 [名称] 或 【名称】
    bracket_match = re.match(r"^\[([^\]]+)\]\s*(.+)$", line) or re.match(
        r"^【([^】]+)】\s*(.+)$", line
    )
    if bracket_match:
        extracted_name = bracket_match.group(1).strip()
        proxy_part = bracket_match.group(2).strip()
    else:
        # 2. 语法匹配：键值对 "名称 = url" 或 "名称: url"
        # 必须满足: 等号连接，或者冒号连接但值必须包含协议头或斜杠，避免把 1.2.3.4:1080 误判为键值对
        if "=" in line:
            parts = line.split("=", 1)
            extracted_name = parts[0].strip()
            proxy_part = parts[1].strip()
        elif ":" in line:
            m = re.match(r"^([a-zA-Z0-9_一-龥\-\s]+)\s*:\s*(.+)$", line)
            if m:
                k_candidate = m.group(1).strip()
                v_candidate = m.group(2).strip()
                # 排除协议头本身（如 http:, socks5:）以及纯数字端口 host:port
                if (
                    k_candidate.lower() not in ("http", "https", "socks", "socks4", "socks5", "socks5h")
                    and not re.match(r"^\d+$", v_candidate)
                    and ("://" in v_candidate or " " in line or "@" in v_candidate)
                ):
                    extracted_name = k_candidate
                    proxy_part = v_candidate

    # 3. 语法匹配：URI Fragment (例如 url#名称，行内自带优先级高于上一行注释)
    clean_proxy_url = proxy_part
    if "#" in proxy_part:
        p_url, frag = proxy_part.split("#", 1)
        p_url = p_url.strip()
        frag = frag.strip()
        if frag:
            extracted_name = frag
        clean_proxy_url = p_url

    # 4. 若行内未提供名称，则借用上文注释 explicit_name
    if not extracted_name and explicit_name.strip():
        extracted_name = explicit_name.strip()

    # 去除多余的行尾注释 (例如空格后跟随 // 或 ;)
    clean_proxy_url = re.split(r"\s+[;/]", clean_proxy_url)[0].strip()
    if not clean_proxy_url:
        return None

    # 4. 规范化 URL scheme
    if "://" not in clean_proxy_url:
        # 裸 host:port，默认按 socks5 处理
        clean_proxy_url = f"socks5://{clean_proxy_url}"

    try:
        parsed = urllib.parse.urlsplit(clean_proxy_url)
    except Exception:
        return None

    protocol = (parsed.scheme or "socks5").lower()
    if protocol in ("socks", "socks5h"):
        protocol = "socks5"
    elif protocol in ("socks4a",):
        protocol = "socks4"

    host = parsed.hostname or ""
    try:
        port = parsed.port or (1080 if "socks" in protocol else 8080)
    except ValueError:
        return None

    if not host:
        return None

    # 5. 自动推断识别名称（若配置中未指明名称，必须严格对 IP 进行掩码，且坚决不暴露端口）
    if not extracted_name:
        prefix = default_name_prefix or ("自建节点" if is_self_hosted else "代理节点")
        masked_h = mask_host(host)
        extracted_name = f"{prefix}-{masked_h}"

    # 判断是否为自建代理（根据名称关键字、配置来源或显式标记）
    self_hosted_mark = (
        is_self_hosted
        or "自建" in extracted_name.lower()
        or "self" in extracted_name.lower()
        or "custom" in extracted_name.lower()
        or "vps" in extracted_name.lower()
        or "home" in extracted_name.lower()
        or "家宽" in extracted_name.lower()
        or "host" in source_env.lower()
    )

    # 还原不含 fragment 的标准 URL
    std_netloc = parsed.netloc
    std_url = urllib.parse.urlunsplit((protocol, std_netloc, parsed.path, parsed.query, ""))
    safe_url = mask_proxy_url(std_url)

    return ProxyEndpoint(
        name=extracted_name,
        url=std_url,
        safe_url=safe_url,
        protocol=protocol,
        host=host,
        port=port,
        raw_input=line,
        source=source_env,
        is_self_hosted=self_hosted_mark,
    )


def parse_proxies_text(
    raw_text: str,
    default_name_prefix: str = "自建节点",
    source_env: str = "",
    is_self_hosted: bool = False,
) -> List[ProxyEndpoint]:
    """解析多行文本中的所有代理配置，支持 # 连续注释提取名称。

    示例多行输入：
    # 自建香港CN2
    socks5://admin:123@1.1.1.1:1080
    [自建-美西] http://2.2.2.2:8080
    socks5://3.3.3.3:1080#自建-日本住宅
    4.4.4.4:1080
    """
    if not raw_text:
        return []

    results: List[ProxyEndpoint] = []
    lines = raw_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    last_comment_name = ""

    for line in lines:
        stripped = line.strip()
        if not stripped:
            last_comment_name = ""
            continue

        # 如果是单独的注释行，暂存为下一个节点的潜在名称
        if stripped.startswith(("#", "//", ";")):
            comment_content = stripped.lstrip("#/;").strip()
            # 排除非描述性的纯字符分割线（如 "------" 或 "====="）
            if comment_content and not re.match(r"^[-=_*~]{3,}$", comment_content):
                last_comment_name = comment_content
            continue

        # 支持一行内逗号分隔的多个代理
        sub_items = stripped.split(",") if "," in stripped and "#" not in stripped else [stripped]
        for item in sub_items:
            item = item.strip()
            if not item:
                continue
            endpoint = parse_proxy_line(
                item,
                default_name_prefix=default_name_prefix,
                explicit_name=last_comment_name,
                source_env=source_env,
                is_self_hosted=is_self_hosted,
            )
            if endpoint:
                # 若使用了上一行的注释名称，则消费掉
                last_comment_name = ""
                results.append(endpoint)

    return results


def get_all_proxy_endpoints(
    task_prefix: str = "",
    include_self_hosted: bool = True,
    include_backups: bool = True,
) -> List[ProxyEndpoint]:
    """获取指定任务前缀或全局的所有候选代理列表（自建代理优先排序并去重）。

    优先级顺序：
    1. SELF_HOSTED_PROXIES / SELF_HOSTED_PROXY / CUSTOM_PROXIES (自建代理，最高优先级)
    2. {task_prefix}_PROXY / {task_prefix}_PROXIES (站点专属主代理)
    3. {task_prefix}_BACKUP_PROXIES (站点专属备用代理池)
    4. AGENTROUTER_BACKUP_PROXIES (CI 级高可用代理池)
    5. 全局 PROXY / BACKUP_PROXIES
    """
    task_prefix = task_prefix.strip().upper().rstrip("_")
    candidates: List[ProxyEndpoint] = []
    seen_urls = set()

    def _collect(env_names: List[str], is_self: bool, default_prefix: str) -> None:
        for name in env_names:
            val = os.getenv(name, "").strip()
            if not val:
                continue
            endpoints = parse_proxies_text(
                val,
                default_name_prefix=default_prefix,
                source_env=name,
                is_self_hosted=is_self,
            )
            for ep in endpoints:
                if ep.url not in seen_urls:
                    seen_urls.add(ep.url)
                    candidates.append(ep)

    # 1. 自建代理配置池 (自建优先级最高)
    if include_self_hosted:
        _collect(
            ["SELF_HOSTED_PROXIES", "SELF_HOSTED_PROXY", "CUSTOM_PROXIES", "CUSTOM_PROXY"],
            is_self=True,
            default_prefix="自建节点",
        )

    # 2. 站点专属代理
    if task_prefix:
        task_specific_keys = [
            f"{task_prefix}_PROXY",
            f"{task_prefix}_PROXIES",
            f"{task_prefix}_BACKUP_PROXIES",
        ]
        # 特殊兼容映射（国内服务复用仓库 CN 代理出口：SMZDM / 52POJIE 等）
        if task_prefix in ("52POJIE", "WUAI", "POJIE"):
            task_specific_keys.extend(["WUAI_PROXY", "POJIE_PROXY", "SMZDM_PROXY", "SMZDM_BACKUP_PROXIES"])
        elif task_prefix == "CLOUD189":
            task_specific_keys.extend(["52POJIE_PROXY", "WUAI_PROXY", "POJIE_PROXY", "SMZDM_PROXY", "SMZDM_BACKUP_PROXIES"])
        _collect(
            task_specific_keys,
            is_self=False,
            default_prefix=f"{task_prefix}代理",
        )
    else:
        # 全局扫描：找出所有站点特定的 PROXY 环境变量
        site_proxy_keys = []
        known_global = {
            "SELF_HOSTED_PROXIES", "SELF_HOSTED_PROXY", "CUSTOM_PROXIES", "CUSTOM_PROXY",
            "AGENTROUTER_BACKUP_PROXIES", "SMZDM_BACKUP_PROXIES", "BACKUP_PROXIES", "PROXY",
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        }
        for k in sorted(os.environ.keys()):
            if "PROXY" in k.upper() and k not in known_global and not k.startswith(("_", "npm_")):
                site_proxy_keys.append(k)
        if site_proxy_keys:
            _collect(site_proxy_keys, is_self=False, default_prefix="业务代理")

    # 3. 全局高可用备用代理池
    if include_backups:
        _collect(
            [
                "AGENTROUTER_BACKUP_PROXIES",
                "SMZDM_BACKUP_PROXIES",
                "BACKUP_PROXIES",
                "PROXY",
            ],
            is_self=False,
            default_prefix="备用节点",
        )

    return candidates


def get_task_proxy_endpoints(
    task_name: str,
    include_self_hosted: bool = True,
    include_backups: bool = True,
) -> List[ProxyEndpoint]:
    """为全仓库任意签到任务获取合规、全协议正规化且安全隔离的候选代理列表。

    支持全代理协议：HTTP, HTTPS, SOCKS5, SOCKS5h, SOCKS4, SOCKS4a。
    调度特性：
    1. 自动正规化任务名（如 "juejin" -> "JUEJIN", "cloud189" -> "CLOUD189", "52pojie" -> "52POJIE"）
    2. 自建代理优先调度（SELF_HOSTED_PROXIES / CUSTOM_PROXIES）
    3. 任务专属代理（{TASK}_PROXY, {TASK}_BACKUP_PROXIES）
    4. 国内站点（如 52POJIE, CLOUD189, SMZDM）智能复用仓库共享 CN 代理出口
    5. 全局高可用备用代理池安全回退
    6. 节点敏感 IP、端口与密码统一脱敏
    """
    clean_task = re.sub(r"[^a-zA-Z0-9_]", "", task_name).upper()
    return get_all_proxy_endpoints(
        task_prefix=clean_task,
        include_self_hosted=include_self_hosted,
        include_backups=include_backups,
    )


def get_candidate_proxy_urls(task_prefix: str = "") -> List[str]:
    """返回所有可用代理的纯 URL 字符串列表（向后兼容纯 URL 消费代码）。"""
    return [ep.url for ep in get_all_proxy_endpoints(task_prefix=task_prefix)]


def format_dead_proxy_alert(endpoint: ProxyEndpoint, error_msg: str = "") -> str:
    """生成死代理告警与更新替换提示文本。"""
    err_desc = f"：{error_msg}" if error_msg else ""
    src_info = f" [来源: {endpoint.source}]" if endpoint.source else ""
    return (
        f"❌ 代理失效 {endpoint.display_name}{src_info}{err_desc}\n"
        f"   💡 该代理已不可达(死代理)，请及时在 GitHub Secrets 或环境变量中更新替换！"
    )


def probe_first_working_proxy(
    label: str, raw_text: str, state_file: str = "/tmp/proxy_active.json"
) -> bool:
    """在 CI 环境下探测一组候选代理，选取首个连通节点写入 GITHUB_ENV。"""
    import subprocess
    import json

    endpoints = parse_proxies_text(raw_text, default_name_prefix=f"{label}节点")
    if not endpoints:
        return False

    print(f"🔍 开始探测 {label} 代理池 (共 {len(endpoints)} 个节点)...")
    github_env = os.getenv("GITHUB_ENV", "")

    for ep in endpoints:
        print(f"  ⏳ 正在探测 {ep.display_name}...")
        cmd_ip = ["curl", "-sS", "-x", ep.url, "-m", "8", "https://api.ipify.org"]
        try:
            r_ip = subprocess.run(cmd_ip, capture_output=True, text=True, timeout=10)
            exit_ip = r_ip.stdout.strip()
        except Exception:
            exit_ip = ""

        if not exit_ip:
            print(f"  {format_dead_proxy_alert(ep, '公网出口超时或无法连接')}")
            continue

        cmd_api = [
            "curl",
            "-sS",
            "-x",
            ep.url,
            "-m",
            "10",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://ps.air-outer.com",
        ]
        try:
            r_api = subprocess.run(cmd_api, capture_output=True, text=True, timeout=12)
            api_code = r_api.stdout.strip()
        except Exception:
            api_code = "000"

        print(
            f"  ✅ {label}代理存活就绪: {ep.display_name} (API HTTP {api_code})"
        )

        if github_env and os.path.exists(github_env):
            with open(github_env, "a", encoding="utf-8") as f:
                f.write(f"AGENTROUTER_PROXY={ep.url}\n")
                f.write(f"NODESEEK_PROXY={ep.url}\n")
                f.write(f"2LIBRA_PROXY={ep.url}\n")
                f.write(f"CLOUDSTUDIO_PROXY={ep.url}\n")

        try:
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "mode": f"{label}代理",
                        "node": ep.name,
                        "exit_ip": mask_host(exit_ip),
                        "probe": api_code,
                    },
                    f,
                )
        except Exception:
            pass

        return True

    print(f"❌ {label}代理池全部不可达 (死代理)")
    return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 4 and sys.argv[1] == "probe":
        _label = sys.argv[2]
        _raw = sys.argv[3]
        _ok = probe_first_working_proxy(_label, _raw)
        sys.exit(0 if _ok else 1)

