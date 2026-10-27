"""Platform detection, capability probing and permission gate.

Every collector and analyzer is built on this module: it answers the question
"what can this OS let us see, and has the user granted it?" before any socket
table is read.
"""

from __future__ import annotations

import getpass
import os
import platform as _platform
import shutil
import socket
import subprocess
import sys
from typing import Dict, List, Optional

from .models import PermissionCheck, PlatformReport

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

OS_LABEL = "windows" if IS_WINDOWS else "macos" if IS_MACOS else "linux" if IS_LINUX else "unknown"


def is_admin() -> bool:
    """True when the process has elevated rights on the current OS."""

    try:
        if IS_WINDOWS:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return False


def which(name: str) -> bool:
    return shutil.which(name) is not None


def run(cmd: List[str], timeout: float = 8.0) -> subprocess.CompletedProcess:
    """Run a command without a shell and never raise on non-zero exit."""

    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(cmd, 1, "", "")


def has_module(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def probe_os_version() -> str:
    if IS_MACOS:
        out = run(["sw_vers", "-productVersion"]).stdout.strip()
        return out or _platform.mac_ver()[0]
    if IS_LINUX:
        try:
            with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return _platform.release()
    if IS_WINDOWS:
        return f"{_platform.system()} {_platform.release()} {_platform.version()}"
    return _platform.platform()


# ---------------------------------------------------------------------------
# Permission probes
# ---------------------------------------------------------------------------


def check_socket_table_access() -> PermissionCheck:
    """Can we enumerate the process -> socket mapping?

    On macOS this needs root for *other* users' sockets, but the current
    user's own sockets are always visible. On Linux /proc/net + /proc/<pid>/fd
    need root for sockets owned by other users. On Windows GetExtendedTcpTable
    is readable by a normal user, but process image paths may be restricted.
    """

    detail = ""
    granted = True
    try:
        if IS_MACOS:
            proc = run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-a", "-u", getpass.getuser()])
            if proc.returncode != 0 and not proc.stdout.strip():
                granted = False
                detail = proc.stderr.strip() or "lsof returned no data"
            else:
                detail = f"lsof readable for user {getpass.getuser()}"
            if not is_admin():
                detail += " - only this user's sockets visible (run elevated for system-wide)"
        elif IS_LINUX:
            if not os.access("/proc/net/tcp", os.R_OK):
                granted = False
                detail = "/proc/net/tcp not readable"
            else:
                detail = "/proc/net readable"
                if not is_admin():
                    detail += " - other users' sockets require root"
        elif IS_WINDOWS:
            if has_module("psutil"):
                detail = "psutil available; Windows IP Helper table readable"
            else:
                detail = "falling back to netstat (no psutil)"
    except Exception as exc:  # pragma: no cover - defensive
        granted = False
        detail = f"probe failed: {exc}"

    return PermissionCheck(
        key="socket_table",
        title="Socket / connection table access",
        required=True,
        granted=granted,
        detail=detail,
        remediation=(
            "Run NetWatch elevated (sudo on macOS/Linux, Administrator on Windows) "
            "to see every process on the machine."
        ),
    )


def check_process_inspection() -> PermissionCheck:
    """Can we resolve PIDs to executable paths / command lines?"""

    granted = True
    detail = ""
    try:
        pid = os.getpid()
        if IS_LINUX:
            granted = os.path.exists(f"/proc/{pid}/cmdline")
            detail = f"/proc/{pid}/cmdline {"readable" if granted else "missing"}"
        elif IS_MACOS:
            # ``ps`` is frequently blocked by endpoint security and sandboxing,
            # so probe lsof, which is also what the macOS collector relies on.
            proc = run(["/usr/sbin/lsof", "-a", "-p", str(pid), "-d", "txt", "-Fn"])
            granted = proc.returncode == 0 and "n" in proc.stdout
            detail = "lsof can resolve pid -> executable" if granted else "lsof could not resolve pid"
        elif IS_WINDOWS:
            granted = has_module("psutil") or which("wmic") or which("tasklist")
            detail = "psutil/tasklist available" if granted else "no process backend"
    except Exception as exc:  # pragma: no cover
        granted = False
        detail = f"probe failed: {exc}"

    return PermissionCheck(
        key="process_inspection",
        title="Application / process identification",
        required=True,
        granted=granted,
        detail=detail,
        remediation="Needed to show which application owns each connection.",
    )


def check_dns_resolution() -> PermissionCheck:
    """Can we reverse-resolve remote IPs to hostnames?"""

    try:
        socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        return PermissionCheck(
            key="dns",
            title="DNS resolution",
            required=False,
            granted=True,
            detail="outbound DNS/53 or system resolver reachable",
        )
    except Exception as exc:
        return PermissionCheck(
            key="dns",
            title="DNS resolution",
            required=False,
            granted=False,
            detail=f"resolution failed: {exc}",
            remediation="Hostnames and domain reputation will be unavailable; IP-level analysis still works.",
        )


def check_tls_probe() -> PermissionCheck:
    """Can we open outbound TLS connections to inspect certificates?"""

    try:
        import ssl

        ctx = ssl.create_default_context()
        with socket.create_connection(("example.com", 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="example.com") as tls:
                tls.version()
        return PermissionCheck(
            key="tls",
            title="TLS certificate inspection",
            required=False,
            granted=True,
            detail="TLS handshake successful; certificate chain can be graded",
        )
    except Exception as exc:
        return PermissionCheck(
            key="tls",
            title="TLS certificate inspection",
            required=False,
            granted=False,
            detail=f"TLS probe failed: {exc}",
            remediation="HTTPS connections will be graded on port/SNI only, not certificate trust.",
        )


def check_packet_capture() -> PermissionCheck:
    """Optional deep-inspection capability (scapy / pcap)."""

    if has_module("scapy"):
        if IS_LINUX and not is_admin():
            return PermissionCheck(
                key="pcap",
                title="Packet capture (deep inspection)",
                required=False,
                granted=False,
                detail="scapy installed but CAP_NET_RAW/root missing",
                remediation="Grant CAP_NET_RAW (setcap) or run elevated to enable payload-level checks.",
            )
        return PermissionCheck(
            key="pcap",
            title="Packet capture (deep inspection)",
            required=False,
            granted=True,
            detail="scapy available",
        )
    return PermissionCheck(
        key="pcap",
        title="Packet capture (deep inspection)",
        required=False,
        granted=False,
        detail="scapy not installed",
        remediation="Optional: pip install scapy for packet-level analysis.",
    )


def _macos_firewall_state() -> str:
    proc = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    return proc.stdout.strip() or "unknown"


def _linux_firewall_state() -> str:
    if which("ufw"):
        proc = run(["ufw", "status"])
        return (proc.stdout.strip().splitlines() or ["unknown"])[0]
    if which("firewall-cmd"):
        proc = run(["firewall-cmd", "--state"])
        return proc.stdout.strip() or "unknown"
    if which("nft"):
        proc = run(["nft", "list", "ruleset"])
        return "nftables present" if proc.returncode == 0 else "unknown"
    return "not detected"


def _windows_firewall_state() -> str:
    if which("netsh"):
        proc = run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        return "netsh advfirewall readable" if proc.returncode == 0 else "unknown"
    return "not detected"


def firewall_state() -> str:
    try:
        if IS_MACOS:
            return _macos_firewall_state()
        if IS_LINUX:
            return _linux_firewall_state()
        if IS_WINDOWS:
            return _windows_firewall_state()
    except Exception:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------


def evaluate() -> PlatformReport:
    """Build a complete pre-flight report for the current host."""

    report = PlatformReport(
        os_name=OS_LABEL,
        os_version=probe_os_version(),
        arch=_platform.machine(),
        python=_platform.python_version(),
        is_admin=is_admin(),
        has_psutil=has_module("psutil"),
        has_scapy=has_module("scapy"),
        tools={
            name: which(name)
            for name in (
                "lsof",
                "netstat",
                "ss",
                "nmap",
                "route",
                "ip",
                "tasklist",
                "wmic",
                "netsh",
                "ufw",
            )
        },
    )

    report.permissions = [
        check_socket_table_access(),
        check_process_inspection(),
        check_dns_resolution(),
        check_tls_probe(),
        check_packet_capture(),
    ]

    fw = firewall_state()
    report.notes.append(f"Host firewall: {fw}")
    if not report.is_admin:
        report.notes.append(
            "Running unprivileged: NetWatch will still see this user's traffic, "
            "but not connections owned by other users or system daemons."
        )
    else:
        report.notes.append("Running elevated: full machine-wide socket visibility.")

    if report.has_scapy:
        report.notes.append("scapy detected - packet-level analysis techniques enabled.")
    else:
        report.notes.append("scapy absent - using socket-table, DNS, TLS and reputation techniques only.")

    return report


def requirements_text(report: Optional[PlatformReport] = None) -> str:
    """Human-readable pre-flight summary (used by the CLI)."""

    report = report or evaluate()
    lines = [
        f"Host      : {report.os_name} {report.os_version} ({report.arch})",
        f"Python    : {report.python}",
        f"Elevated  : {'yes' if report.is_admin else 'no'}",
        "",
        "Permissions:",
    ]
    for check in report.permissions:
        mark = "OK  " if check.granted else ("FAIL" if check.required else "OPT ")
        lines.append(f"  [{mark}] {check.title} - {check.detail}")
        if not check.granted and check.remediation:
            lines.append(f"         -> {check.remediation}")
    if report.notes:
        lines.append("")
        lines.append("Notes:")
        lines.extend(f"  - {note}" for note in report.notes)
    return "\n".join(lines)
