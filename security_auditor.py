#!/usr/bin/env python3
"""
System Security Auditor v2.0
A modern, cross-platform local security posture assessment tool.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------

VERSION = "2.0.0"
HIGH_RISK_PORTS = {22, 23, 3389, 5900, 445, 139, 135}          # Remote access / SMB
MEDIUM_RISK_PORTS = {80, 443, 8080, 8443, 8888, 3306, 5432, 27017}
TIMEOUT = 12  # seconds for external commands


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ANSI colors (disabled automatically when not a TTY)
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

    @classmethod
    def disable(cls) -> None:
        for attr in ("RESET", "BOLD", "RED", "GREEN", "YELLOW", "BLUE", "CYAN", "GRAY"):
            setattr(cls, attr, "")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class PortEntry:
    protocol: str
    local_address: str
    remote_address: str
    state: str
    pid: str
    port: int | None
    process: str = ""
    risk: str = "low"


@dataclass
class Finding:
    title: str
    severity: RiskLevel
    description: str
    recommendation: str = ""


@dataclass
class SecurityReport:
    timestamp: str
    host: str
    user: str
    os_name: str
    os_version: str
    architecture: str
    accounts: list[str] = field(default_factory=list)
    listening_ports: list[PortEntry] = field(default_factory=list)
    installed_software_count: int = 0
    pending_updates: list[str] = field(default_factory=list)
    running_processes: list[str] = field(default_factory=list)
    firewall_status: list[str] = field(default_factory=list)
    suid_binaries: list[str] = field(default_factory=list)
    world_writable: list[str] = field(default_factory=list)
    failed_logins: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    recommendations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def safe_run(cmd: list[str] | str, timeout: int = TIMEOUT, shell: bool = False) -> str | None:
    """Run a command safely. Returns stdout or None on any failure."""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
        if result.stderr:
            logging.debug("Command %s stderr: %s", cmd, result.stderr[:200])
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logging.debug("Command failed: %s → %s", cmd, exc)
        return None


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

class SystemCollector:
    def __init__(self) -> None:
        self.os_name = platform.system()
        self.is_linux = self.os_name == "Linux"
        self.is_windows = self.os_name == "Windows"
        self.is_macos = self.os_name == "Darwin"

    def get_basic_info(self) -> dict[str, str]:
        return {
            "host": socket.gethostname(),
            "user": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
            "os_name": self.os_name,
            "os_version": f"{platform.system()} {platform.release()} ({platform.version()})",
            "architecture": platform.machine(),
        }

    def get_accounts(self) -> list[str]:
        if self.is_linux or self.is_macos:
            out = safe_run(["getent", "passwd"]) or safe_run(["cat", "/etc/passwd"])
            if out:
                return [line.split(":")[0] for line in out.splitlines() if ":" in line][:40]
        elif self.is_windows:
            out = safe_run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-LocalUser | Select-Object -ExpandProperty Name"]
            )
            if out:
                return [line.strip() for line in out.splitlines() if line.strip()][:40]
        return []

    def get_listening_ports(self) -> list[PortEntry]:
        entries: list[PortEntry] = []

        if self.is_linux:
            # Prefer ss (modern)
            out = safe_run(["ss", "-tulnp"]) or safe_run(["netstat", "-tulnp"])
            if out:
                entries = self._parse_ss_or_netstat(out)
        elif self.is_macos:
            out = safe_run(["netstat", "-anv"]) or safe_run(["lsof", "-i", "-P", "-n"])
            if out:
                entries = self._parse_macos_netstat(out)
        elif self.is_windows:
            out = safe_run(["netstat", "-ano"])
            if out:
                entries = self._parse_windows_netstat(out)

        # Enrich with process names where possible
        for entry in entries:
            if entry.pid and entry.pid.isdigit():
                entry.process = self._get_process_name(int(entry.pid))
            entry.risk = self._classify_port(entry.port)

        return entries[:50]

    def _classify_port(self, port: int | None) -> str:
        if port is None:
            return "unknown"
        if port in HIGH_RISK_PORTS:
            return "high"
        if port in MEDIUM_RISK_PORTS:
            return "medium"
        return "low"

    def _get_process_name(self, pid: int) -> str:
        if self.is_linux or self.is_macos:
            out = safe_run(["ps", "-p", str(pid), "-o", "comm="])
            return out or ""
        if self.is_windows:
            out = safe_run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"]
            )
            return out or ""
        return ""

    def _parse_ss_or_netstat(self, output: str) -> list[PortEntry]:
        entries = []
        for line in output.splitlines():
            if not re.search(r"\b(LISTEN|ESTAB|TIME-WAIT|CLOSE-WAIT)\b", line, re.I):
                continue
            # ss format examples vary; keep it resilient
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[4] if "ss" in (which("ss") or "") else parts[3]
            state = "LISTENING" if "LISTEN" in line.upper() else parts[1] if len(parts) > 1 else "UNKNOWN"
            pid = ""
            m = re.search(r"pid=(\d+)", line)
            if m:
                pid = m.group(1)
            else:
                m = re.search(r"\s(\d+)/", line)
                if m:
                    pid = m.group(1)

            host, port_str = (local.rsplit(":", 1) if ":" in local else (local, ""))
            try:
                port = int(port_str) if port_str.isdigit() else None
            except ValueError:
                port = None

            entries.append(PortEntry(
                protocol=proto,
                local_address=local,
                remote_address="*",
                state=state,
                pid=pid,
                port=port,
            ))
        return entries

    def _parse_windows_netstat(self, output: str) -> list[PortEntry]:
        entries = []
        for line in output.splitlines():
            if not re.search(r"\b(LISTENING|ESTABLISHED|TIME_WAIT|CLOSE_WAIT)\b", line):
                continue
            match = re.match(
                r"^\s*(\w+)\s+([^\s]+)\s+([^\s]+)\s+(LISTENING|ESTABLISHED|TIME_WAIT|CLOSE_WAIT)\s+(\d+)?",
                line,
            )
            if not match:
                continue
            proto, local, remote, state, pid = match.groups()
            host, port_str = (local.rsplit(":", 1) if ":" in local else (local, ""))
            port = int(port_str) if port_str and port_str.isdigit() else None
            entries.append(PortEntry(
                protocol=proto,
                local_address=local,
                remote_address=remote,
                state=state,
                pid=pid or "",
                port=port,
            ))
        return entries

    def _parse_macos_netstat(self, output: str) -> list[PortEntry]:
        # Simplified for brevity – real parser would be more complete
        entries = []
        for line in output.splitlines():
            if "LISTEN" not in line.upper():
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            host, port_str = (local.rsplit(".", 1) if "." in local else (local, ""))
            port = int(port_str) if port_str.isdigit() else None
            entries.append(PortEntry(
                protocol=parts[0],
                local_address=local,
                remote_address="*",
                state="LISTENING",
                pid="",
                port=port,
            ))
        return entries

    def get_installed_software_count(self) -> int:
        if self.is_linux:
            if which("dpkg"):
                out = safe_run(["dpkg", "-l"])
                return len([l for l in (out or "").splitlines() if l.startswith("ii")])
            if which("rpm"):
                out = safe_run(["rpm", "-qa"])
                return len((out or "").splitlines())
        elif self.is_macos:
            out = safe_run(["ls", "/Applications"])
            return len((out or "").splitlines())
        elif self.is_windows:
            out = safe_run([
                "powershell", "-NoProfile", "-Command",
                r"(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | "
                r"Where-Object { $_.DisplayName }).Count"
            ])
            try:
                return int(out or "0")
            except ValueError:
                return 0
        return 0

    def get_pending_updates(self) -> list[str]:
        if self.is_linux:
            if which("apt"):
                out = safe_run(["apt", "list", "--upgradable"])
                if out:
                    return [l for l in out.splitlines()
                            if l.strip() and not l.startswith("Listing") and not l.startswith("WARNING")]
            if which("dnf"):
                out = safe_run(["dnf", "check-update", "--quiet"])
                return (out or "").splitlines()[:30]
        elif self.is_macos:
            out = safe_run(["softwareupdate", "-l"])
            return [l for l in (out or "").splitlines() if "Label:" in l][:20]
        elif self.is_windows:
            # Lightweight check – full Windows Update query is heavy
            out = safe_run([
                "powershell", "-NoProfile", "-Command",
                "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 8 "
                "HotFixID,InstalledOn | Format-Table -AutoSize | Out-String"
            ])
            return [l.strip() for l in (out or "").splitlines() if l.strip()][:15]
        return []

    def get_top_processes(self, limit: int = 12) -> list[str]:
        if self.is_windows:
            out = safe_run([
                "powershell", "-NoProfile", "-Command",
                f"Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First {limit} "
                "ProcessName,Id,@{N='Mem(MB)';E={[math]::Round($_.WorkingSet64/1MB,1)}} | "
                "Format-Table -AutoSize | Out-String"
            ])
        else:
            out = safe_run(["ps", "aux", "--sort=-%mem"])
        if not out:
            return []
        lines = [l for l in out.splitlines() if l.strip()]
        return lines[:limit + 1]  # keep header if present

    def get_firewall_status(self) -> list[str]:
        if self.is_linux:
            if which("ufw"):
                out = safe_run(["ufw", "status", "verbose"])
                return (out or "").splitlines()[:12]
            if which("firewall-cmd"):
                out = safe_run(["firewall-cmd", "--state"])
                return [out] if out else []
            out = safe_run(["iptables", "-S"])
            return (out or "").splitlines()[:10]
        elif self.is_macos:
            out = safe_run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
            return [out] if out else []
        elif self.is_windows:
            out = safe_run([
                "powershell", "-NoProfile", "-Command",
                "Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table -AutoSize | Out-String"
            ])
            return [l for l in (out or "").splitlines() if l.strip()]
        return []

    def get_suid_binaries(self) -> list[str]:
        if not (self.is_linux or self.is_macos):
            return []
        # Limit scope for performance and safety
        out = safe_run(
            ["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
             "-perm", "-4000", "-type", "f", "-print"],
            timeout=20
        )
        return (out or "").splitlines()[:40]

    def get_world_writable(self) -> list[str]:
        if not (self.is_linux or self.is_macos):
            return []
        out = safe_run(
            ["find", "/tmp", "/var/tmp", "/dev/shm",
             "-type", "f", "-perm", "-0002", "-print"],
            timeout=15
        )
        return (out or "").splitlines()[:25]

    def get_failed_logins(self) -> list[str]:
        if self.is_linux:
            out = safe_run(["lastb", "-n", "15"]) or safe_run(["grep", "Failed password", "/var/log/auth.log"])
            return (out or "").splitlines()[:15]
        if self.is_macos:
            out = safe_run(["log", "show", "--predicate", 'eventMessage contains "Failed"', "--last", "1d"])
            return (out or "").splitlines()[:10]
        return []

    def get_notable_services(self) -> list[str]:
        if self.is_linux:
            out = safe_run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
            return [l.split()[0] for l in (out or "").splitlines() if l.strip()][:25]
        if self.is_macos:
            out = safe_run(["launchctl", "list"])
            return (out or "").splitlines()[:20]
        if self.is_windows:
            out = safe_run([
                "powershell", "-NoProfile", "-Command",
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                "Select-Object -First 20 Name,DisplayName | Format-Table -AutoSize | Out-String"
            ])
            return [l for l in (out or "").splitlines() if l.strip()][:20]
        return []


# ---------------------------------------------------------------------------
# Risk Engine
# ---------------------------------------------------------------------------

class RiskEngine:
    def analyze(self, report: SecurityReport) -> None:
        score = 0
        findings: list[Finding] = []

        # High-risk listening ports
        for p in report.listening_ports:
            if p.port in HIGH_RISK_PORTS and p.state == "LISTENING":
                score += 4
                findings.append(Finding(
                    title=f"High-risk port {p.port} listening",
                    severity=RiskLevel.HIGH,
                    description=f"{p.protocol} {p.local_address} (PID {p.pid} / {p.process})",
                    recommendation="Close or restrict access with firewall rules if not required.",
                ))
            elif p.port in MEDIUM_RISK_PORTS and p.state == "LISTENING":
                score += 2
                findings.append(Finding(
                    title=f"Web/DB port {p.port} listening",
                    severity=RiskLevel.MEDIUM,
                    description=f"{p.local_address}",
                    recommendation="Ensure only necessary services are exposed.",
                ))

        # Pending updates
        if report.pending_updates:
            score += 3
            findings.append(Finding(
                title=f"{len(report.pending_updates)} pending updates",
                severity=RiskLevel.MEDIUM,
                description="Security patches may be missing.",
                recommendation="Install updates as soon as possible.",
            ))

        # Firewall
        fw_text = " ".join(report.firewall_status).lower()
        if "inactive" in fw_text or "disabled" in fw_text or "false" in fw_text:
            score += 5
            findings.append(Finding(
                title="Firewall appears disabled or inactive",
                severity=RiskLevel.HIGH,
                description="Host-based firewall is not protecting inbound traffic.",
                recommendation="Enable and configure the host firewall immediately.",
            ))

        # SUID binaries (informational + slight risk)
        if len(report.suid_binaries) > 25:
            score += 1
            findings.append(Finding(
                title="Large number of SUID binaries",
                severity=RiskLevel.LOW,
                description=f"{len(report.suid_binaries)} SUID files found in common paths.",
                recommendation="Review and remove unnecessary SUID bits.",
            ))

        # World-writable files
        if report.world_writable:
            score += 2
            findings.append(Finding(
                title=f"{len(report.world_writable)} world-writable files in temp areas",
                severity=RiskLevel.MEDIUM,
                description="Potential privilege escalation or data leakage vector.",
                recommendation="Remove write permissions for others where possible.",
            ))

        # Many installed packages
        if report.installed_software_count > 80:
            score += 1
            findings.append(Finding(
                title="Large software inventory",
                severity=RiskLevel.LOW,
                description=f"{report.installed_software_count} packages/apps detected.",
                recommendation="Remove unused software to reduce attack surface.",
            ))

        # Failed logins
        if len(report.failed_logins) > 5:
            score += 2
            findings.append(Finding(
                title="Multiple failed login attempts",
                severity=RiskLevel.MEDIUM,
                description="Possible brute-force activity.",
                recommendation="Review logs and consider fail2ban / account lockout policies.",
            ))

        # Determine overall level
        if score >= 12:
            level = RiskLevel.CRITICAL
        elif score >= 7:
            level = RiskLevel.HIGH
        elif score >= 3:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        report.risk_score = score
        report.risk_level = level
        report.findings = findings
        report.recommendations = self._build_recommendations(report)

    def _build_recommendations(self, report: SecurityReport) -> list[str]:
        recs = []
        if any(f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) for f in report.findings):
            recs.append("Address all High and Critical findings immediately.")
        if report.pending_updates:
            recs.append("Apply pending security updates without delay.")
        if any("firewall" in f.title.lower() for f in report.findings):
            recs.append("Enable and harden the host firewall (default-deny inbound).")
        recs.extend([
            "Use least-privilege accounts; avoid daily use of root/Administrator.",
            "Enable multi-factor authentication on all remote access and important services.",
            "Keep an up-to-date inventory of installed software and remove unused packages.",
            "Regularly review listening services and close anything not required.",
            "Implement automated backups and test restore procedures.",
            "Consider endpoint detection (EDR) or at least a reputable antivirus solution.",
        ])
        return recs


# ---------------------------------------------------------------------------
# Report Formatters
# ---------------------------------------------------------------------------

class ReportFormatter:
    def __init__(self, use_color: bool = True):
        if not use_color or not sys.stdout.isatty():
            Color.disable()

    def to_text(self, report: SecurityReport) -> str:
        c = Color
        lines: list[str] = []

        lines.append(f"{c.BOLD}{c.CYAN}System Security Auditor v{VERSION}{c.RESET}")
        lines.append("=" * 80)
        lines.append(f"Timestamp   : {report.timestamp}")
        lines.append(f"Host        : {report.host}")
        lines.append(f"User        : {report.user}")
        lines.append(f"OS          : {report.os_version}")
        lines.append(f"Architecture: {report.architecture}")
        lines.append("")

        # Risk banner
        level_color = {
            RiskLevel.LOW: c.GREEN,
            RiskLevel.MEDIUM: c.YELLOW,
            RiskLevel.HIGH: c.RED,
            RiskLevel.CRITICAL: c.RED + c.BOLD,
        }.get(report.risk_level, c.RESET)

        lines.append(f"{c.BOLD}Overall Risk: {level_color}{report.risk_level.value} "
                     f"({report.risk_score} points){c.RESET}")
        lines.append("")

        if report.findings:
            lines.append(f"{c.BOLD}Findings{c.RESET}")
            lines.append("-" * 80)
            for f in report.findings:
                sev_col = {
                    RiskLevel.LOW: c.GREEN,
                    RiskLevel.MEDIUM: c.YELLOW,
                    RiskLevel.HIGH: c.RED,
                    RiskLevel.CRITICAL: c.RED + c.BOLD,
                }.get(f.severity, "")
                lines.append(f"  [{sev_col}{f.severity.value:8}{c.RESET}] {f.title}")
                lines.append(f"             {c.GRAY}{f.description}{c.RESET}")
                if f.recommendation:
                    lines.append(f"             → {f.recommendation}")
            lines.append("")

        # Sections
        self._section(lines, "User Accounts", report.accounts)
        self._section_ports(lines, report.listening_ports)
        lines.append(f"{c.BOLD}Installed Software{c.RESET}")
        lines.append("-" * 80)
        lines.append(f"  {report.installed_software_count} packages / applications detected")
        lines.append("")

        self._section(lines, "Pending Updates", report.pending_updates or ["None detected"])
        self._section(lines, "Top Processes", report.running_processes)
        self._section(lines, "Firewall Status", report.firewall_status or ["No information available"])
        self._section(lines, "SUID Binaries (sample)", report.suid_binaries)
        self._section(lines, "World-writable files (temp)", report.world_writable)
        self._section(lines, "Failed Logins (recent)", report.failed_logins)
        self._section(lines, "Notable Running Services", report.services)

        lines.append(f"{c.BOLD}Recommended Actions{c.RESET}")
        lines.append("-" * 80)
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"  {i}. {rec}")

        lines.append("")
        lines.append(f"{c.GRAY}Scan completed at {report.timestamp}{c.RESET}")
        return "\n".join(lines)

    def _section(self, lines: list[str], title: str, items: list[str]) -> None:
        lines.append(f"{Color.BOLD}{title}{Color.RESET}")
        lines.append("-" * 80)
        if not items:
            lines.append("  (none)")
        else:
            for item in items[:25]:
                lines.append(f"  • {item}")
            if len(items) > 25:
                lines.append(f"  … and {len(items) - 25} more")
        lines.append("")

    def _section_ports(self, lines: list[str], ports: list[PortEntry]) -> None:
        lines.append(f"{Color.BOLD}Listening Ports{Color.RESET}")
        lines.append("-" * 80)
        if not ports:
            lines.append("  (none detected)")
        else:
            for p in ports:
                risk_col = {
                    "high": Color.RED,
                    "medium": Color.YELLOW,
                    "low": Color.GREEN,
                }.get(p.risk, "")
                proc = f" ({p.process})" if p.process else ""
                lines.append(
                    f"  {p.protocol:6} {p.local_address:25}  "
                    f"PID={p.pid or '-':6}  "
                    f"[{risk_col}{p.risk:6}{Color.RESET}]{proc}"
                )
        lines.append("")

    def to_json(self, report: SecurityReport) -> str:
        def default(o: Any) -> Any:
            if isinstance(o, Enum):
                return o.value
            if isinstance(o, PortEntry):
                return asdict(o)
            if isinstance(o, Finding):
                return asdict(o)
            raise TypeError(f"Object of type {type(o)} is not JSON serializable")

        return json.dumps(asdict(report), indent=2, default=default)

    def to_html(self, report: SecurityReport) -> str:
        # Minimal clean HTML report
        risk_color = {
            RiskLevel.LOW: "#28a745",
            RiskLevel.MEDIUM: "#ffc107",
            RiskLevel.HIGH: "#dc3545",
            RiskLevel.CRITICAL: "#721c24",
        }.get(report.risk_level, "#6c757d")

        findings_html = "".join(
            f"<tr><td><span class='badge {f.severity.value.lower()}'>{f.severity.value}</span></td>"
            f"<td>{f.title}</td><td>{f.description}</td></tr>"
            for f in report.findings
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Report – {report.host}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }}
  h1 {{ color: #333; }}
  .risk {{ font-size: 1.4rem; font-weight: bold; color: {risk_color}; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
  th {{ background: #f5f5f5; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.85em; }}
  .badge.high, .badge.critical {{ background: #dc3545; }}
  .badge.medium {{ background: #ffc107; color: #333; }}
  .badge.low {{ background: #28a745; }}
  .meta {{ color: #666; font-size: 0.9rem; }}
</style>
</head>
<body>
  <h1>System Security Report</h1>
  <p class="meta">
    Host: <strong>{report.host}</strong> · User: {report.user}<br>
    OS: {report.os_version} · {report.architecture}<br>
    Generated: {report.timestamp}
  </p>
  <p class="risk">Overall Risk: {report.risk_level.value} ({report.risk_score} points)</p>

  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Details</th></tr>
    {findings_html or "<tr><td colspan='3'>No significant findings</td></tr>"}
  </table>

  <h2>Listening Ports</h2>
  <ul>
    {"".join(f"<li>{p.protocol} {p.local_address} (PID {p.pid}) – risk: {p.risk}</li>" for p in report.listening_ports)
     or "<li>None detected</li>"}
  </ul>

  <h2>Recommendations</h2>
  <ol>
    {"".join(f"<li>{r}</li>" for r in report.recommendations)}
  </ol>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def build_report(collector: SystemCollector) -> SecurityReport:
    info = collector.get_basic_info()
    report = SecurityReport(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        host=info["host"],
        user=info["user"],
        os_name=info["os_name"],
        os_version=info["os_version"],
        architecture=info["architecture"],
    )

    logging.info("Collecting accounts…")
    report.accounts = collector.get_accounts()

    logging.info("Scanning listening ports…")
    report.listening_ports = collector.get_listening_ports()

    logging.info("Counting installed software…")
    report.installed_software_count = collector.get_installed_software_count()

    logging.info("Checking for updates…")
    report.pending_updates = collector.get_pending_updates()

    logging.info("Gathering processes…")
    report.running_processes = collector.get_top_processes()

    logging.info("Checking firewall…")
    report.firewall_status = collector.get_firewall_status()

    logging.info("Looking for SUID binaries…")
    report.suid_binaries = collector.get_suid_binaries()

    logging.info("Scanning world-writable files…")
    report.world_writable = collector.get_world_writable()

    logging.info("Checking failed logins…")
    report.failed_logins = collector.get_failed_logins()

    logging.info("Listing notable services…")
    report.services = collector.get_notable_services()

    # Risk analysis
    engine = RiskEngine()
    engine.analyze(report)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Modern cross-platform system security auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s\n"
               "  %(prog)s --json\n"
               "  %(prog)s --html -o report.html\n"
               "  %(prog)s --verbose --quiet",
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--html", action="store_true", help="Output HTML report")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write report to file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)

    collector = SystemCollector()
    report = build_report(collector)

    formatter = ReportFormatter(use_color=not args.no_color and not args.json and not args.html)

    if args.json:
        content = formatter.to_json(report)
    elif args.html:
        content = formatter.to_html(report)
    else:
        content = formatter.to_text(report)

    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
        if not args.quiet:
            print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(content)


if __name__ == "__main__":
    main()
