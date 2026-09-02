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
    safe_url: str  # 脱敏后的安全连接串，如 "socks5://***:***@1.2.3.4:1080"
    protocol: str  # "socks5", "http", "https"
    host: str  # "1.2.3.4"
    port: int  # 1080
    raw_input: str = ""  # 原始输入行，便于提示用户替换哪一行
    source: str = ""  # 来源环境变量名
    is_self_hosted: bool = False  # 是否标记为自建代理

    @property
    def host_port(self) -> str:
        """返回 host:port 组合。"""
        return f"{self.host}:{self.port}"

    @property
    def display_name(self) -> str:
        """友好的显示名称，例如: 【自建-香港-01】(1.2.3.4:1080)。"""
        return f"【{self.name}】({self.host_port})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.safe_url,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "display_name": self.display_name,
            "source": self.source,
            "is_self_hosted": self.is_self_hosted,
        }

    def __str__(self) -> str:
        return self.display_name


def mask_proxy_url(url: str) -> str:
    """对代理 URL 中的用户名密码进行脱敏处理。

    示例:
    socks5://admin:secret123@1.2.3.4:1080 -> socks5://***:***@1.2.3.4:1080
    http://5.6.7.8:8080 -> http://5.6.7.8:8080
    """
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.username or parsed.password:
            masked_netloc = f"***:***@{parsed.hostname}"
            if parsed.port:
                masked_netloc += f":{parsed.port}"
            return urllib.parse.urlunsplit(
                (parsed.scheme, masked_netloc, parsed.path, parsed.query, parsed.fragment)
            )
        return url
    except Exception:
        # 正则降级
        return re.sub(r"://([^:@]+):([^@]+)@", r"://***:***@", url)


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

    host = parsed.hostname or ""
    try:
        port = parsed.port or (1080 if "socks" in protocol else 8080)
    except ValueError:
        return None

    if not host:
        return None

    # 5. 自动推断识别名称（若配置中未指明）
    if not extracted_name:
        prefix = default_name_prefix or ("自建节点" if is_self_hosted else "代理节点")
        extracted_name = f"{prefix}-{host}:{port}"

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
        # 特殊兼容映射
        if task_prefix == "52POJIE":
            task_specific_keys.extend(["WUAI_PROXY", "POJIE_PROXY"])
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
