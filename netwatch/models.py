"""Core data models shared by every NetWatch collector, analyzer and view."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    """Overall trust verdict assigned to a connection."""

    SAFE = "safe"
    SECURE = "secure"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    @property
    def rank(self) -> int:
        return {
            Verdict.SAFE: 0,
            Verdict.SECURE: 0,
            Verdict.UNKNOWN: 1,
            Verdict.SUSPICIOUS: 2,
            Verdict.MALICIOUS: 3,
        }[self]

    @property
    def worst(self) -> "Verdict":
        return self

    @classmethod
    def from_flags(cls, flags: List["Flag"]) -> "Verdict":
        """Worst verdict implied by a set of flags.

        Severity-1 flags are *noteworthy* but not evidence of compromise, so a
        connection whose only flags are severity 1 stays UNKNOWN. Severity 2
        means SUSPICIOUS, severity 3 means MALICIOUS.
        """

        if not flags:
            return cls.UNKNOWN
        top = max(f.severity for f in flags)
        if top >= 3:
            return cls.MALICIOUS
        if top == 2:
            return cls.SUSPICIOUS
        return cls.UNKNOWN


SEVERITY_TO_VERDICT = {
    1: Verdict.UNKNOWN,
    2: Verdict.SUSPICIOUS,
    3: Verdict.MALICIOUS,
}


@dataclass
class Flag:
    """A single reason a connection is considered risky or noteworthy."""

    code: str
    message: str
    severity: int = 1  # 1 low, 2 medium, 3 high
    category: str = "security"  # security | privacy | hygiene | reputation
    evidence: str = ""

    @property
    def verdict(self) -> str:
        return SEVERITY_TO_VERDICT.get(self.severity, Verdict.SUSPICIOUS).value

    @property
    def label(self) -> str:
        return {1: "LOW", 2: "MEDIUM", 3: "HIGH"}.get(self.severity, "LOW")


@dataclass
class Endpoint:
    """One side of a TCP/UDP flow."""

    address: str = ""
    port: int = 0
    hostname: str = ""
    scope: str = "external"  # loopback | lan | external | unknown

    @property
    def ip(self) -> str:
        return self.address.split("%")[0]

    @property
    def pretty(self) -> str:
        host = self.hostname or self.ip
        return f"{host}:{self.port}"

    def is_private(self) -> bool:
        try:
            return ipaddress.ip_address(self.ip).is_private
        except ValueError:
            return False


@dataclass
class ProcessInfo:
    """The application/process owning a socket."""

    pid: Optional[int] = None
    name: str = ""
    exe: str = ""
    user: str = ""
    cmdline: str = ""

    @property
    def display(self) -> str:
        if self.name:
            return self.name
        if self.pid is not None:
            return f"pid {self.pid}"
        return "unknown"


@dataclass
class Connection:
    """A single live network connection."""

    proto: str = "tcp"
    local: Endpoint = field(default_factory=Endpoint)
    remote: Endpoint = field(default_factory=Endpoint)
    state: str = "ESTABLISHED"
    process: ProcessInfo = field(default_factory=ProcessInfo)
    direction: str = "outbound"  # inbound | outbound | local | listening
    bytes_sent: int = 0
    bytes_recv: int = 0
    started_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )
    last_seen: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )
    rtt_ms: Optional[float] = None
    tls_issuer: str = ""
    tls_subject: str = ""
    tls_expires: str = ""
    tls_version: str = ""
    asn: str = ""
    asn_org: str = ""
    country: str = ""
    reputation: str = ""
    flags: List[Flag] = field(default_factory=list)
    analysis: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return (
            f"{self.proto}|{self.local.address}:{self.local.port}"
            f"->{self.remote.address}:{self.remote.port}|{self.process.pid}"
        )

    @property
    def verdict(self) -> Verdict:
        return Verdict.from_flags(self.flags)

    @property
    def severity_score(self) -> int:
        """Highest flag severity on this connection (0 when clean)."""

        return max((f.severity for f in self.flags), default=0)

    @property
    def display_remote(self) -> str:
        return self.remote.pretty

    def add_flag(self, flag: Flag) -> None:
        if not any(f.code == flag.code for f in self.flags):
            self.flags.append(flag)

    def to_dict(self) -> Dict[str, Any]:
        payload = dataclasses.asdict(self)
        payload["verdict"] = self.verdict.value
        payload["severity_score"] = self.severity_score
        payload["flags"] = [
            {
                "code": f.code,
                "message": f.message,
                "severity": f.severity,
                "category": f.category,
                "evidence": f.evidence,
                "label": f.label,
            }
            for f in self.flags
        ]
        return payload


@dataclass
class ScanSummary:
    """Aggregated counters shown in the dashboard header."""

    total: int = 0
    inbound: int = 0
    outbound: int = 0
    local: int = 0
    listening: int = 0
    safe: int = 0
    secure: int = 0
    unknown: int = 0
    suspicious: int = 0
    malicious: int = 0
    applications: int = 0
    captured_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )

    @classmethod
    def from_connections(cls, connections: List[Connection]) -> "ScanSummary":
        s = cls(total=len(connections))
        apps = set()
        for c in connections:
            if c.direction == "inbound":
                s.inbound += 1
            elif c.direction == "outbound":
                s.outbound += 1
            elif c.direction == "listening":
                s.listening += 1
            else:
                s.local += 1
            v = c.verdict.value
            setattr(s, v, getattr(s, v) + 1)
            if c.process.name:
                apps.add(c.process.name)
        s.applications = len(apps)
        return s


@dataclass
class PermissionCheck:
    """Result of a pre-flight permission requirement."""

    key: str
    title: str
    required: bool
    granted: bool
    detail: str = ""
    remediation: str = ""


@dataclass
class PlatformReport:
    """Everything the collector knows about the host before monitoring starts."""

    os_name: str = ""
    os_version: str = ""
    arch: str = ""
    python: str = ""
    is_admin: bool = False
    has_psutil: bool = False
    has_scapy: bool = False
    tools: Dict[str, bool] = field(default_factory=dict)
    permissions: List[PermissionCheck] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return all(p.granted or not p.required for p in self.permissions)
