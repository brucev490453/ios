#!/usr/bin/env python3
"""
iOS 网络安全威胁监测工具

面向企业 SOC / 移动安全团队的防御性监测脚本，用于：
  1. 检测网络日志中与已知 iOS 利用工具包（DarkSword / Coruna）相关的 IOC
  2. 检查 iOS 设备版本是否处于已知受影响范围
  3. 分析 DNS 查询日志中的可疑模式
  4. 生成中文安全监测报告

用法：
  python ios_network_security_monitor.py                     # 交互式演示
  python ios_network_security_monitor.py --dns-log dns.txt   # 分析 DNS 日志
  python ios_network_security_monitor.py --check-version 17.2.1
  python ios_network_security_monitor.py --scan-network net_log.csv
  python ios_network_security_monitor.py --report            # 生成完整监测报告

本工具不包含漏洞利用代码、PoC 或攻击载荷，仅用于防御性检测与响应。

咨询ios系统请咨询  telegram：@DZHT333333
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import NamedTuple

# ---------------------------------------------------------------------------
# 1. IOC 数据库 —— 来自公开威胁情报，仅用于防御检测
# ---------------------------------------------------------------------------

DARKSWORD_DOMAINS = frozenset({
    "cdncounter.net",
    "static.cdncounter.net",
    "sqwas.shapelie.com",
    "snapshare.chat",
})

COMPROMISED_WATERING_HOLES = frozenset({
    "novosti.dn.ua",
    "7aac.gov.ua",
})

DARKSWORD_IPS = frozenset({
    "141.105.130.237",
    "62.72.21.10",
})

SUSPICIOUS_PORTS = frozenset({8881, 8882})

CRYPTO_LURE_KEYWORDS = re.compile(
    r"(backup[_\-\s]?phrase|seed[_\-\s]?phrase|mnemonic|"
    r"wallet[_\-\s]?recover|airdrop[_\-\s]?claim|"
    r"metamask|bitkeep|bitcoin[_\-\s]?bonus|"
    r"crypto[_\-\s]?invest|free[_\-\s]?token)",
    re.IGNORECASE,
)

GAMBLING_LURE_KEYWORDS = re.compile(
    r"(online[_\-\s]?casino|slot[_\-\s]?machine|bet[_\-\s]?now|"
    r"jackpot[_\-\s]?win|lucky[_\-\s]?spin)",
    re.IGNORECASE,
)

IOS_USERAGENT_PATTERN = re.compile(
    r"iPhone\s+OS\s+(\d+)[_.](\d+)(?:[_.](\d+))?", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# 2. 版本合规检查
# ---------------------------------------------------------------------------

class VersionRange(NamedTuple):
    name: str
    min_major: int
    min_minor: int
    max_major: int
    max_minor: int
    max_patch: int
    severity: str
    description: str


VULNERABLE_RANGES = [
    VersionRange(
        name="Coruna",
        min_major=13, min_minor=0,
        max_major=17, max_minor=2, max_patch=1,
        severity="严重",
        description="Coruna 工具包适配范围 — 5 条完整利用链、23 个利用模块",
    ),
    VersionRange(
        name="DarkSword",
        min_major=18, min_minor=4,
        max_major=18, max_minor=7, max_patch=2,
        severity="严重",
        description="DarkSword 工具包适配范围（iOS 18 分支）",
    ),
    VersionRange(
        name="DarkSword (26.x)",
        min_major=26, min_minor=0,
        max_major=26, max_minor=2, max_patch=99,
        severity="严重",
        description="DarkSword 工具包适配范围（iOS 26 分支，26.3 修复）",
    ),
    VersionRange(
        name="USB Restricted Mode 绕过",
        min_major=11, min_minor=4,
        max_major=18, max_minor=3, max_patch=0,
        severity="高",
        description="CVE-2025-24200 — 物理接触攻击可禁用 USB 限制",
    ),
]

SAFE_VERSIONS = {
    "26.x": "26.6",
    "18.x": "18.7.3+",
    "17.x 及更早": "尽快升级至 26.x 或 18.7.3+",
}


def parse_version(version_str: str) -> tuple[int, int, int]:
    parts = re.split(r"[._]", version_str.strip())
    major = int(parts[0]) if len(parts) > 0 else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return major, minor, patch


def check_version(version_str: str) -> list[dict]:
    major, minor, patch = parse_version(version_str)
    findings = []

    for vr in VULNERABLE_RANGES:
        ver_tuple = (major, minor, patch)
        range_min = (vr.min_major, vr.min_minor, 0)
        range_max = (vr.max_major, vr.max_minor, vr.max_patch)

        if range_min <= ver_tuple <= range_max:
            findings.append({
                "threat": vr.name,
                "severity": vr.severity,
                "description": vr.description,
                "version_checked": version_str,
                "recommendation": "立即升级至安全版本",
            })

    if not findings:
        findings.append({
            "threat": "无已知匹配",
            "severity": "信息",
            "description": f"iOS {version_str} 不在已知工具包公开适配范围内",
            "version_checked": version_str,
            "recommendation": "仍建议保持最新版本",
        })

    return findings


# ---------------------------------------------------------------------------
# 3. 网络日志分析
# ---------------------------------------------------------------------------

class Alert:
    def __init__(self, level: str, category: str, detail: str,
                 indicator: str, source_line: str = ""):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.level = level
        self.category = category
        self.detail = detail
        self.indicator = indicator
        self.source_line = source_line

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "category": self.category,
            "detail": self.detail,
            "indicator": self.indicator,
        }

    def __str__(self) -> str:
        return f"[{self.level}] {self.category}: {self.detail} (indicator={self.indicator})"


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def check_domain(domain: str) -> list[Alert]:
    alerts = []
    normalized = _normalize_domain(domain)

    if normalized in DARKSWORD_DOMAINS:
        alerts.append(Alert(
            level="严重",
            category="IOC 域名匹配",
            detail=f"域名 {domain} 匹配 DarkSword 已知 C2/投递基础设施",
            indicator=normalized,
        ))

    if normalized in COMPROMISED_WATERING_HOLES:
        alerts.append(Alert(
            level="高",
            category="水坑站点访问",
            detail=f"域名 {domain} 为已知被入侵的合法站点（水坑），建议监控告警而非封禁",
            indicator=normalized,
        ))

    for parent in DARKSWORD_DOMAINS | COMPROMISED_WATERING_HOLES:
        if normalized.endswith("." + parent) and normalized != parent:
            alerts.append(Alert(
                level="高",
                category="IOC 子域名匹配",
                detail=f"域名 {domain} 是已知 IOC 域名 {parent} 的子域",
                indicator=normalized,
            ))

    if CRYPTO_LURE_KEYWORDS.search(domain):
        alerts.append(Alert(
            level="中",
            category="加密资产诱饵域名",
            detail=f"域名 {domain} 包含加密资产诱饵关键词",
            indicator=normalized,
        ))

    if GAMBLING_LURE_KEYWORDS.search(domain):
        alerts.append(Alert(
            level="中",
            category="博彩诱饵域名",
            detail=f"域名 {domain} 包含博彩诱饵关键词（Coruna 活动常见投递载体）",
            indicator=normalized,
        ))

    return alerts


def check_ip(ip_str: str) -> list[Alert]:
    alerts = []
    normalized = ip_str.strip()

    if normalized in DARKSWORD_IPS:
        alerts.append(Alert(
            level="严重",
            category="IOC IP 匹配",
            detail=f"IP {ip_str} 匹配 DarkSword 已知基础设施",
            indicator=normalized,
        ))

    return alerts


def check_port(port: int, dest_domain: str = "") -> list[Alert]:
    alerts = []
    if port in SUSPICIOUS_PORTS:
        alerts.append(Alert(
            level="高",
            category="可疑端口",
            detail=f"目标端口 {port} 匹配 DarkSword 已知通信端口"
                   + (f"（目标: {dest_domain}）" if dest_domain else ""),
            indicator=str(port),
        ))
    return alerts


def check_useragent(ua: str) -> list[Alert]:
    alerts = []
    match = IOS_USERAGENT_PATTERN.search(ua)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        version_str = f"{major}.{minor}.{patch}"
        version_findings = check_version(version_str)
        for finding in version_findings:
            if finding["severity"] != "信息":
                alerts.append(Alert(
                    level=finding["severity"],
                    category="脆弱版本 User-Agent",
                    detail=f"检测到 iOS {version_str} — {finding['description']}",
                    indicator=version_str,
                ))
    return alerts


# ---------------------------------------------------------------------------
# 4. DNS 日志分析
# ---------------------------------------------------------------------------

def analyze_dns_log(log_path: str) -> list[Alert]:
    alerts = []
    domain_counts = defaultdict(int)

    path = Path(log_path)
    if not path.exists():
        print(f"错误：DNS 日志文件不存在 — {log_path}", file=sys.stderr)
        return alerts

    with open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            domains = re.findall(
                r"(?:query|QUERY|dns)[:\s]+([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})",
                line,
            )
            if not domains:
                domains = re.findall(
                    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
                    r"\.[a-zA-Z]{2,})\b",
                    line,
                )

            for domain in domains:
                domain_counts[_normalize_domain(domain)] += 1
                for alert in check_domain(domain):
                    alert.source_line = f"行 {line_no}: {line[:120]}"
                    alerts.append(alert)

            ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
            for ip in ips:
                try:
                    ipaddress.IPv4Address(ip)
                except ValueError:
                    continue
                for alert in check_ip(ip):
                    alert.source_line = f"行 {line_no}: {line[:120]}"
                    alerts.append(alert)

    high_freq_threshold = 50
    for domain, count in domain_counts.items():
        if count >= high_freq_threshold:
            alerts.append(Alert(
                level="低",
                category="高频查询",
                detail=f"域名 {domain} 在日志中出现 {count} 次（阈值 {high_freq_threshold}），"
                       "可能为正常业务或 C2 心跳",
                indicator=domain,
            ))

    return alerts


# ---------------------------------------------------------------------------
# 5. 网络连接日志分析（CSV 格式）
# ---------------------------------------------------------------------------

def analyze_network_log(log_path: str) -> list[Alert]:
    """分析 CSV 格式的网络连接日志。

    期望列（顺序不限，按列名匹配）：
      timestamp, src_ip, src_port, dst_ip, dst_port, domain, user_agent, bytes_out
    """
    alerts = []
    path = Path(log_path)
    if not path.exists():
        print(f"错误：网络日志文件不存在 — {log_path}", file=sys.stderr)
        return alerts

    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row_no, row in enumerate(reader, 2):
            domain = row.get("domain", "").strip()
            dst_ip = row.get("dst_ip", "").strip()
            dst_port_str = row.get("dst_port", "").strip()
            user_agent = row.get("user_agent", "").strip()
            bytes_out_str = row.get("bytes_out", "0").strip()

            line_ref = f"行 {row_no}"

            if domain:
                for alert in check_domain(domain):
                    alert.source_line = line_ref
                    alerts.append(alert)

            if dst_ip:
                for alert in check_ip(dst_ip):
                    alert.source_line = line_ref
                    alerts.append(alert)

            if dst_port_str.isdigit():
                for alert in check_port(int(dst_port_str), domain):
                    alert.source_line = line_ref
                    alerts.append(alert)

            if user_agent:
                for alert in check_useragent(user_agent):
                    alert.source_line = line_ref
                    alerts.append(alert)

            try:
                bytes_out = int(bytes_out_str)
            except ValueError:
                bytes_out = 0
            if bytes_out > 5_000_000:
                alerts.append(Alert(
                    level="中",
                    category="大流量出站",
                    detail=f"单次连接出站 {bytes_out:,} 字节"
                           f"（目标: {domain or dst_ip}），可能为数据外传",
                    indicator=f"{bytes_out} bytes → {domain or dst_ip}",
                    source_line=line_ref,
                ))

    return alerts


# ---------------------------------------------------------------------------
# 6. 报告生成
# ---------------------------------------------------------------------------

def generate_report(
    alerts: list[Alert],
    versions_checked: list[str] | None = None,
    output_path: str | None = None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    severity_order = {"严重": 0, "高": 1, "中": 2, "低": 3, "信息": 4}
    sorted_alerts = sorted(alerts, key=lambda a: severity_order.get(a.level, 5))

    stats = defaultdict(int)
    for a in alerts:
        stats[a.level] += 1

    lines = [
        "# iOS 网络安全威胁监测报告",
        "",
        f"| 项目 | 内容 |",
        f"|---|---|",
        f"| 生成时间 | {now} |",
        f"| 告警总数 | {len(alerts)} |",
        f"| 严重 | {stats.get('严重', 0)} |",
        f"| 高 | {stats.get('高', 0)} |",
        f"| 中 | {stats.get('中', 0)} |",
        f"| 低 | {stats.get('低', 0)} |",
        "",
        "> 本报告由 iOS 网络安全威胁监测工具自动生成，仅用于防御性安全检测。",
        ">",
        "> IOC 数据来源：Google Threat Intelligence、iVerify、Zimperium、Apple 安全公告。",
        "",
        "---",
        "",
    ]

    if versions_checked:
        lines.append("## 设备版本合规检查")
        lines.append("")
        lines.append("| iOS 版本 | 风险 | 严重度 | 建议 |")
        lines.append("|---|---|---|---|")
        for v in versions_checked:
            findings = check_version(v)
            for f in findings:
                lines.append(
                    f"| {f['version_checked']} | {f['threat']} | "
                    f"{f['severity']} | {f['recommendation']} |"
                )
        lines.append("")
        lines.append("**安全版本参考：**")
        for branch, safe in SAFE_VERSIONS.items():
            lines.append(f"- {branch}：{safe}")
        lines.append("")
        lines.append("---")
        lines.append("")

    if sorted_alerts:
        lines.append("## 告警详情")
        lines.append("")
        lines.append("| # | 严重度 | 类别 | 详情 | 指标 |")
        lines.append("|---|---|---|---|---|")
        for i, alert in enumerate(sorted_alerts, 1):
            detail_escaped = alert.detail.replace("|", "\\|")
            lines.append(
                f"| {i} | **{alert.level}** | {alert.category} | "
                f"{detail_escaped} | `{alert.indicator}` |"
            )
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.extend([
        "## 已知 IOC 参考（截至 2026-10-04）",
        "",
        "### DarkSword C2 / 投递域名",
        "",
    ])
    for d in sorted(DARKSWORD_DOMAINS):
        lines.append(f"- `{d}`")
    lines.append("")
    lines.append("### 被入侵的合法水坑站点（监控告警，勿直接封禁）")
    lines.append("")
    for d in sorted(COMPROMISED_WATERING_HOLES):
        lines.append(f"- `{d}`")
    lines.append("")
    lines.append("### DarkSword 已知 IP")
    lines.append("")
    for ip in sorted(DARKSWORD_IPS):
        lines.append(f"- `{ip}`")
    lines.append("")
    lines.append("### 可疑端口")
    lines.append("")
    for p in sorted(SUSPICIOUS_PORTS):
        lines.append(f"- `{p}`")

    lines.extend([
        "",
        "---",
        "",
        "## 响应建议",
        "",
        "1. **严重告警**：立即隔离相关设备，启动事件响应流程，采集 sysdiagnose。",
        "2. **高告警**：在 4 小时内完成调查，确认是否为误报。",
        "3. **中告警**：纳入日常威胁狩猎，24 小时内关联其他信号。",
        "4. **低告警**：记录并在下次复核周期评估趋势。",
        "5. **水坑站点**：通知站点所有方，监控而非封禁，以避免阻断正常业务。",
        "6. **版本不合规设备**：72 小时内完成升级或退出敏感业务。",
        "",
        "---",
        "",
        "## 参考来源",
        "",
        "- [Google Threat Intelligence — DarkSword](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)",
        "- [Google Threat Intelligence — Coruna](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)",
        "- [iVerify — Inside DarkSword](https://www.iverify.com/blog/darksword-ios-exploit-kit-explained)",
        "- [Zimperium — DarkSword](https://zimperium.com/blog/darksword-the-hit-and-run-successor-to-the-coruna-ios-exploit-kit)",
        "- [Apple Security Releases](https://support.apple.com/en-us/100100)",
        "- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
        "",
        "---",
        "",
        "*IOC 时效性较短，建议每 90 天复核并同步最新厂商情报。*",
        "",
        "咨询ios系统请咨询  telegram：@DZHT333333",
        "",
    ])

    report = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        print(f"监测报告已生成：{output_path}")

    return report


# ---------------------------------------------------------------------------
# 7. 交互式演示
# ---------------------------------------------------------------------------

def run_demo():
    print("=" * 60)
    print("  iOS 网络安全威胁监测工具 — 演示模式")
    print("=" * 60)
    print()

    all_alerts: list[Alert] = []

    # 演示：版本检查
    print("[1/4] 设备版本合规检查")
    print("-" * 40)
    demo_versions = ["15.6.1", "17.2.1", "18.5", "18.7.3", "26.2", "26.6"]
    for v in demo_versions:
        findings = check_version(v)
        for f in findings:
            status = "!!" if f["severity"] in ("严重", "高") else "OK" if f["severity"] == "信息" else "??"
            print(f"  [{status}] iOS {v:10s} → {f['threat']:25s} ({f['severity']})")
    print()

    # 演示：域名检测
    print("[2/4] 域名 IOC 检测")
    print("-" * 40)
    demo_domains = [
        "static.cdncounter.net",
        "sqwas.shapelie.com",
        "novosti.dn.ua",
        "wallet-recovery-free-tokens.xyz",
        "www.apple.com",
    ]
    for d in demo_domains:
        alerts = check_domain(d)
        if alerts:
            for a in alerts:
                print(f"  [{a.level}] {d} → {a.category}")
                all_alerts.append(a)
        else:
            print(f"  [安全] {d} → 未匹配已知 IOC")
    print()

    # 演示：IP 检测
    print("[3/4] IP 地址 IOC 检测")
    print("-" * 40)
    demo_ips = ["141.105.130.237", "62.72.21.10", "8.8.8.8"]
    for ip in demo_ips:
        alerts = check_ip(ip)
        if alerts:
            for a in alerts:
                print(f"  [{a.level}] {ip} → {a.category}")
                all_alerts.append(a)
        else:
            print(f"  [安全] {ip} → 未匹配已知 IOC")
    print()

    # 演示：User-Agent 检测
    print("[4/4] User-Agent 版本检测")
    print("-" * 40)
    demo_uas = [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) Safari/605.1",
    ]
    for ua in demo_uas:
        alerts = check_useragent(ua)
        short_ua = ua[:70] + "..."
        if alerts:
            for a in alerts:
                print(f"  [{a.level}] {short_ua}")
                print(f"          → {a.detail}")
                all_alerts.append(a)
        else:
            print(f"  [安全] {short_ua}")
    print()

    # 生成演示报告
    print("=" * 60)
    report_path = "iOS网络安全威胁监测报告_demo.md"
    generate_report(all_alerts, versions_checked=demo_versions, output_path=report_path)
    print(f"共检测到 {len(all_alerts)} 条告警")
    print()
    print("咨询ios系统请咨询  telegram：@DZHT333333")


# ---------------------------------------------------------------------------
# 8. CLI 入口
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="iOS 网络安全威胁监测工具",
        epilog="咨询ios系统请咨询  telegram：@DZHT333333",
    )
    parser.add_argument(
        "--dns-log",
        help="DNS 查询日志文件路径（纯文本，每行一条记录）",
    )
    parser.add_argument(
        "--scan-network",
        help="网络连接日志文件路径（CSV，含 dst_ip/domain/dst_port/user_agent 列）",
    )
    parser.add_argument(
        "--check-version",
        nargs="+",
        help="检查一个或多个 iOS 版本号（如 17.2.1 18.5 26.6）",
    )
    parser.add_argument(
        "--check-domain",
        nargs="+",
        help="检查一个或多个域名是否匹配已知 IOC",
    )
    parser.add_argument(
        "--check-ip",
        nargs="+",
        help="检查一个或多个 IP 地址是否匹配已知 IOC",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="生成完整 Markdown 监测报告",
    )
    parser.add_argument(
        "--output", "-o",
        default="iOS网络安全威胁监测报告.md",
        help="报告输出路径（默认: iOS网络安全威胁监测报告.md）",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出告警（用于 SIEM 集成）",
    )

    args = parser.parse_args()

    if len(sys.argv) == 1:
        run_demo()
        return

    all_alerts: list[Alert] = []
    versions_checked: list[str] = []

    if args.check_version:
        versions_checked = args.check_version
        for v in args.check_version:
            findings = check_version(v)
            for f in findings:
                print(f"[{f['severity']}] iOS {v} — {f['threat']}: {f['description']}")

    if args.check_domain:
        for domain in args.check_domain:
            alerts = check_domain(domain)
            all_alerts.extend(alerts)
            if alerts:
                for a in alerts:
                    print(a)
            else:
                print(f"[安全] {domain} — 未匹配已知 IOC")

    if args.check_ip:
        for ip in args.check_ip:
            alerts = check_ip(ip)
            all_alerts.extend(alerts)
            if alerts:
                for a in alerts:
                    print(a)
            else:
                print(f"[安全] {ip} — 未匹配已知 IOC")

    if args.dns_log:
        print(f"正在分析 DNS 日志：{args.dns_log}")
        dns_alerts = analyze_dns_log(args.dns_log)
        all_alerts.extend(dns_alerts)
        print(f"DNS 日志分析完成，发现 {len(dns_alerts)} 条告警")

    if args.scan_network:
        print(f"正在分析网络日志：{args.scan_network}")
        net_alerts = analyze_network_log(args.scan_network)
        all_alerts.extend(net_alerts)
        print(f"网络日志分析完成，发现 {len(net_alerts)} 条告警")

    if args.json:
        output = [a.to_dict() for a in all_alerts]
        print(json.dumps(output, ensure_ascii=False, indent=2))

    if args.report or all_alerts:
        generate_report(all_alerts, versions_checked=versions_checked or None,
                        output_path=args.output)


if __name__ == "__main__":
    main()
