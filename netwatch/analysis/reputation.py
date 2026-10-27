"""Reputation data: allowlist, blocklist, suspicious TLDs, risky ports, risky processes.

All datasets are plain text files in ``netwatch/data`` so they can be audited
and extended without touching code. Parsing is line-oriented and tolerant of
comments and blank lines.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _data_path(name: str) -> str:
    return os.path.join(DATA_DIR, name)


def _read_lines(name: str) -> List[str]:
    path = _data_path(name)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh]
    except OSError:
        return []


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


@dataclass(frozen=True)
class HostRule:
    """A hostname or IP rule, optionally scoped to a port."""

    pattern: str
    port: Optional[int] = None

    def matches(self, host: str, port: int) -> bool:
        if self.port is not None and self.port != port:
            return False
        host = host.lower().rstrip(".")
        pattern = self.pattern.lower()
        if pattern.startswith("."):
            return host.endswith(pattern)
        return host == pattern or host.endswith("." + pattern)


@dataclass(frozen=True)
class PortRule:
    port: int
    severity: int
    proto: str
    description: str


@dataclass(frozen=True)
class ProcessRule:
    substring: str
    severity: int
    reason: str


@dataclass(frozen=True)
class SafeServiceRule:
    """A process/port pair that legitimately listens on all interfaces."""

    substring: str
    port: Optional[int]
    note: str

    def matches(self, process_name: str, port: int) -> bool:
        if self.port is not None and self.port != port:
            return False
        return self.substring in (process_name or "").lower()


@dataclass
class ReputationData:
    allow: List[HostRule] = field(default_factory=list)
    block: List[HostRule] = field(default_factory=list)
    suspicious_tlds: Set[str] = field(default_factory=set)
    risky_ports: Dict[Tuple[int, str], PortRule] = field(default_factory=dict)
    risky_processes: List[ProcessRule] = field(default_factory=list)
    safe_services: List[SafeServiceRule] = field(default_factory=list)

    @classmethod
    def load(cls) -> "ReputationData":
        data = cls()

        for line in _read_lines("allowlist.txt"):
            entry = _strip_comment(line)
            if not entry:
                continue
            host, port = _split_host_port(entry)
            if host:
                data.allow.append(HostRule(host, port))

        for line in _read_lines("blocklist.txt"):
            entry = _strip_comment(line)
            if not entry:
                continue
            host, port = _split_host_port(entry)
            if host:
                data.block.append(HostRule(host, port))

        for line in _read_lines("suspicious_tlds.txt"):
            entry = _strip_comment(line).lstrip(".").lower()
            if entry:
                data.suspicious_tlds.add(entry)

        for line in _read_lines("risky_ports.txt"):
            entry = _strip_comment(line)
            if not entry:
                continue
            parts = entry.split("|")
            if len(parts) < 4:
                continue
            try:
                port = int(parts[0])
                severity = int(parts[1])
            except ValueError:
                continue
            proto = parts[2].strip().lower()
            rule = PortRule(port, severity, proto, parts[3].strip())
            data.risky_ports[(port, proto)] = rule

        for line in _read_lines("risky_processes.txt"):
            entry = _strip_comment(line)
            if not entry:
                continue
            parts = entry.split("|")
            if len(parts) < 3:
                continue
            try:
                severity = int(parts[1])
            except ValueError:
                continue
            data.risky_processes.append(ProcessRule(parts[0].strip().lower(), severity, parts[2].strip()))

        for line in _read_lines("safe_services.txt"):
            entry = _strip_comment(line)
            if not entry:
                continue
            parts = entry.split("|")
            if len(parts) < 3:
                continue
            port_raw = parts[1].strip()
            port: Optional[int]
            if port_raw in ("*", ""):
                port = None
            else:
                try:
                    port = int(port_raw)
                except ValueError:
                    continue
            data.safe_services.append(
                SafeServiceRule(parts[0].strip().lower(), port, parts[2].strip())
            )

        return data

    # -- queries ---------------------------------------------------------

    @property
    def allowlist(self) -> List[HostRule]:
        return self.allow

    @property
    def blocklist(self) -> List[HostRule]:
        return self.block

    def match_allow(self, host: str, port: int) -> Optional[HostRule]:
        for rule in self.allow:
            if rule.matches(host, port):
                return rule
        return None

    def match_block(self, host: str, port: int) -> Optional[HostRule]:
        for rule in self.block:
            if rule.matches(host, port):
                return rule
        return None

    def is_suspicious_tld(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if "." not in host:
            return False
        tld = host.rsplit(".", 1)[-1]
        return tld in self.suspicious_tlds

    def port_rule(self, port: int, proto: str) -> Optional[PortRule]:
        proto = (proto or "").lower()
        return self.risky_ports.get((port, proto)) or self.risky_ports.get((port, "tcp"))

    def safe_service(self, process_name: str, port: int) -> Optional[SafeServiceRule]:
        for rule in self.safe_services:
            if rule.matches(process_name, port):
                return rule
        return None

    def process_rule(self, name: str) -> Optional[ProcessRule]:
        haystack = (name or "").lower()
        if not haystack:
            return None
        for rule in self.risky_processes:
            if rule.substring in haystack:
                return rule
        return None

    # -- aliases used by the public API --------------------------------

    def risky_port(self, port: int, proto: str = "tcp") -> Optional[PortRule]:
        return self.port_rule(port, proto)

    def risky_process(self, name: str) -> Optional[ProcessRule]:
        return self.process_rule(name)

    def suspicious_tld(self, host: str) -> Optional[str]:
        if not self.is_suspicious_tld(host):
            return None
        return host.lower().rstrip(".").rsplit(".", 1)[-1]


def load() -> ReputationData:
    """Read every dataset from disk and return a fresh instance."""

    return ReputationData.load()


_CACHE: Optional[ReputationData] = None


def reputation() -> ReputationData:
    """Return a process-wide cached dataset (parsed once)."""

    global _CACHE
    if _CACHE is None:
        _CACHE = ReputationData.load()
    return _CACHE


def _split_host_port(entry: str) -> Tuple[str, Optional[int]]:
    """Split ``host`` or ``host:port`` or ``1.2.3.4:443`` or ``[::1]:443``."""

    entry = entry.strip()
    if not entry:
        return "", None
    if entry.startswith("["):
        host, _, rest = entry[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else None
    if entry.count(":") == 1:
        host, _, port = entry.partition(":")
        return host, int(port) if port.isdigit() else None
    return entry, None


DGA_RE = re.compile(r"^[a-z0-9]{16,}$")

# Hyphenated infrastructure names: ``lb-140-82-114-25-iad``, ``ec2-52-32-205-191``.
INFRA_LABEL_RE = re.compile(r"^[a-z]{1,6}(-[a-z0-9]{1,6}){1,}$")


def looks_like_dga(host: str) -> bool:
    """Heuristic: long, random-looking single labels look algorithmically generated.

    Real DGAs are a single unstructured label of mixed letters and digits with
    no word boundaries, e.g. ``a8f7g9h2k4l6m1n3p5q7``. Legitimate infrastructure
    hostnames (``lb-140-82-114-25-iad``, ``ec2-52-32-205-191``) are hyphen-
    delimited, so they are explicitly excluded.
    """

    if not host or "." not in host:
        return False
    label = host.split(".")[0].lower()
    if len(label) < 12:
        return False
    # Hyphen- or dot-separated labels are structured names, not DGAs.
    if "-" in label or "_" in label:
        return False
    if not DGA_RE.match(label):
        return False
    digits = sum(c.isdigit() for c in label)
    vowels = sum(c in "aeiou" for c in label)
    letters = sum(c.isalpha() for c in label)
    if letters == 0:
        return False
    # Needs a real mix of digits and letters to be suspicious, and low vowel
    # density (random strings are consonant-heavy).
    if digits >= 4 and vowels / letters < 0.35:
        return True
    if len(label) >= 16 and vowels / letters < 0.2:
        return True
    return False


def is_raw_ip(host: str) -> bool:
    """True when the peer is an IP literal rather than a hostname."""

    import ipaddress

    try:
        ipaddress.ip_address(host.split("%")[0])
        return True
    except ValueError:
        return False
