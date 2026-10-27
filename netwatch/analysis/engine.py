"""The detection pipeline.

Every connection is run through an ordered set of independent *techniques*.
Each technique can attach one or more :class:`Flag` objects; the union of
flags determines the connection's :class:`Verdict`.

Techniques implemented here
---------------------------
T1  Blocklist match          - peer host/IP is on the known-bad list
T2  Allowlist match          - peer is a known-good vendor (reduces risk)
T3  TLS certificate grading  - trust chain, hostname, expiry, protocol version
T4  Plaintext protocol       - HTTP / Telnet / FTP / IRC on the wire
T5  Risky destination port   - SMB, RDP, Redis, Metasploit, TOR, ...
T6  Raw-IP external peer     - no DNS name, direct-to-IP dialling
T7  Suspicious TLD           - .zip/.xyz/.tk/.gq/... high-abuse TLDs
T8  DGA-style hostname       - algorithmically generated domain shape
T9  Risky owning process     - netcat, miners, C2 frameworks, web shells
T10 Inbound exposure         - externally reachable listener
T11 Interface exposure       - service bound to all interfaces on the LAN
T12 Unresolved reputation    - external peer with no allow/block/TLD signal

Design rules
------------
* Techniques never raise. A failing technique records a note and is skipped.
* Enrichment (DNS, TLS) is cached and only runs for external peers, so scanning
  200 loopback sockets costs nothing.
* The engine is thread-safe: the GUI calls ``analyze`` from a worker thread.
"""

from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Connection, Flag, ScanSummary, Verdict
from .dns import ReverseDNSCache
from .reputation import ReputationData, is_raw_ip, looks_like_dga
from .tls import TLS_PORTS, TLSCache, TLSResult

PLAINTEXT_PORTS: Dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    6667: "IRC",
    8080: "HTTP (alternate)",
}

# Processes that are normal system components; never flag them as unresolved.
SYSTEM_PROCESS_HINTS = (
    "system",
    "kernel",
    "launchd",
    "svchost",
    "systemd",
    "windowserver",
    "mds",
    "mdnsresponder",
    "configd",
    "cfprefsd",
)


class AnalysisEngine:
    """Applies every technique to every connection and assigns verdicts."""

    def __init__(
        self,
        reputation: Optional[ReputationData] = None,
        dns: Optional[ReverseDNSCache] = None,
        tls: Optional[TLSCache] = None,
        deep: bool = True,
    ) -> None:
        self.reputation = reputation or ReputationData.load()
        self.dns = dns or ReverseDNSCache()
        self.tls = tls or TLSCache()
        self.deep = deep
        self._lock = threading.Lock()
        self.techniques_run: Dict[str, int] = {}

    # -- public API ------------------------------------------------------

    def analyze(self, connections: Iterable[Connection]) -> List[Connection]:
        """Enrich and flag every connection in place; returns the same list."""

        result = list(connections)
        with self._lock:
            self.techniques_run = {}
            for conn in result:
                self._analyze_one(conn)
        return result

    def analyze_with_summary(
        self, connections: Iterable[Connection]
    ) -> Tuple[List[Connection], ScanSummary]:
        analyzed = self.analyze(connections)
        return analyzed, ScanSummary.from_connections(analyzed)

    # -- per-connection pipeline -----------------------------------------

    def _analyze_one(self, conn: Connection) -> None:
        conn.flags = []
        conn.analysis = {}

        peer_is_external = conn.remote.scope == "external"
        if peer_is_external:
            self._safe(self._enrich_peer, conn, "enrich")

        allowed = False
        allowed = self._safe(self._t2_allowlist, conn, "T2") or False
        self._safe(self._t1_blocklist, conn, "T1")

        if self.deep and peer_is_external and conn.remote.port in TLS_PORTS:
            self._safe(self._t3_tls, conn, "T3")

        self._safe(self._t4_plaintext, conn, "T4")
        self._safe(self._t5_risky_port, conn, "T5")

        if peer_is_external and not allowed:
            self._safe(self._t6_raw_ip, conn, "T6")

        if peer_is_external:
            self._safe(self._t7_suspicious_tld, conn, "T7")
            self._safe(self._t8_dga, conn, "T8")

        self._safe(self._t9_risky_process, conn, "T9")
        self._safe(self._t10_inbound, conn, "T10")
        self._safe(self._t11_exposure, conn, "T11")

        if peer_is_external and not allowed:
            self._safe(self._t12_unresolved, conn, "T12")

        self._finalize(conn)

    def _safe(self, fn, conn: Connection, tag: str):
        """Run one technique; never let a failure break the pipeline."""

        try:
            self.techniques_run[tag] = self.techniques_run.get(tag, 0) + 1
            return fn(conn)
        except Exception as exc:  # pragma: no cover - defensive
            conn.analysis.setdefault("errors", []).append(f"{tag}: {exc}")
            return None

    # -- enrichment ------------------------------------------------------

    def _enrich_peer(self, conn: Connection) -> None:
        ip = conn.remote.ip
        if not conn.remote.hostname:
            ptr = self.dns.lookup(ip)
            if ptr:
                conn.remote.hostname = ptr
                # Reverse DNS is a guess about who owns the IP, not the name
                # the application asked for. TLS grading must know the
                # difference, otherwise every CDN peer looks like a mismatch.
                conn.analysis["hostname_source"] = "ptr"
        else:
            conn.analysis["hostname_source"] = "app"
        conn.analysis["peer_ip"] = ip
        conn.analysis["peer_name"] = conn.remote.hostname or ip

    def _peer_names(self, conn: Connection) -> List[str]:
        names: List[str] = []
        if conn.remote.hostname:
            names.append(conn.remote.hostname)
        if conn.remote.ip:
            names.append(conn.remote.ip)
        return names

    # -- techniques ------------------------------------------------------

    def _t1_blocklist(self, conn: Connection) -> None:
        port = conn.remote.port
        for name in self._peer_names(conn):
            rule = self.reputation.match_block(name, port)
            if rule:
                conn.add_flag(
                    Flag(
                        code="BLOCKLIST",
                        message=f"Peer matches known-malicious blocklist entry '{rule.pattern}'",
                        severity=3,
                        category="reputation",
                        evidence=f"{name}:{port}",
                    )
                )
                conn.analysis["blocklist_match"] = rule.pattern
                return

    def _t2_allowlist(self, conn: Connection) -> bool:
        port = conn.remote.port
        for name in self._peer_names(conn):
            rule = self.reputation.match_allow(name, port)
            if rule:
                conn.analysis["allowlist_match"] = rule.pattern
                conn.add_flag(
                    Flag(
                        code="AUTHORIZED",
                        message=f"Peer is an authorised vendor/service ('{rule.pattern}')",
                        severity=1,
                        category="reputation",
                        evidence=f"{name}:{port}",
                    )
                )
                return True
        return False

    def _t3_tls(self, conn: Connection) -> None:
        # Only a real hostname is a meaningful SNI / hostname-check target.
        # Probing an IP with an IP SNI can never match a DNS certificate, so a
        # mismatch there would be pure noise - that case stays unverified.
        host = conn.remote.hostname or ""
        ptr_only = bool(host) and conn.analysis.get("hostname_source") == "ptr"
        result: TLSResult = self.tls.get(conn.remote.ip, conn.remote.port, host or None)
        conn.analysis["tls_sni"] = host
        conn.analysis["tls_ptr_only"] = ptr_only
        conn.analysis["tls"] = result.to_dict()
        conn.tls_version = result.version
        conn.tls_issuer = result.issuer
        conn.tls_subject = result.subject
        conn.tls_expires = result.not_after

        # A peer that answered with a "no SNI provided" placeholder certificate
        # never identified itself; every identity check below would be judging
        # that placeholder rather than the real service.
        if any("requires SNI" in note for note in result.notes):
            conn.analysis["tls_inconclusive"] = True
            conn.add_flag(
                Flag(
                    code="TLS_UNVERIFIED",
                    message="Peer requires SNI; certificate identity could not be checked",
                    severity=1,
                    category="hygiene",
                    evidence=(result.subject or result.error)[:200],
                )
            )
            return

        if not result.ok:
            err = result.error or ""
            # A peer that simply does not speak TLS on this port (QUIC/HTTP3
            # sockets, proxies, IP-only endpoints) or that refuses our
            # speculative handshake tells us nothing about intent.
            low = err.lower()
            # Every one of these means "we learned nothing about the peer":
            # the server refused our speculative handshake, the socket does
            # not speak TLS, or the name we offered was not the name it
            # serves. None of that is evidence of malicious intent.
            inconclusive = (
                not host
                or "handshake failure" in low
                or "handshake_failure" in low
                or "wrong version number" in low
                or "internal error" in low
                or "internal_error" in low
                or "timed out" in low
                or "connection reset" in low
                or "unrecognized name" in low
                or "certificate required" in low
                or "eof occurred" in low
            )
            conn.add_flag(
                Flag(
                    code="TLS_UNVERIFIED" if inconclusive else "TLS_HANDSHAKE_FAILED",
                    message=(
                        "TLS could not be verified for this peer (inconclusive)"
                        if inconclusive
                        else "TLS handshake failed - peer may not be a real HTTPS service"
                    ),
                    severity=1 if inconclusive else 2,
                    category="security" if not inconclusive else "hygiene",
                    evidence=err[:200],
                )
            )
            return
        if result.expired:
            conn.add_flag(
                Flag(
                    code="TLS_EXPIRED",
                    message="TLS certificate is expired",
                    severity=3,
                    category="security",
                    evidence=result.not_after,
                )
            )
        if result.self_signed:
            conn.add_flag(
                Flag(
                    code="TLS_SELF_SIGNED",
                    message="Self-signed certificate - identity is not vouched for by a CA",
                    severity=2,
                    category="security",
                    evidence=result.subject[:200],
                )
            )
        if not host:
            # No SNI was possible, so chain/hostname judgements would be about
            # a name we invented. Record the findings, but never let them
            # escalate: severity 1 keeps the verdict at UNKNOWN.
            conn.analysis["tls_inconclusive"] = True
            return
        if not result.chain_trusted:
            conn.add_flag(
                Flag(
                    code="TLS_UNTRUSTED",
                    message=(
                        "Certificate does not cover the reverse-DNS name for this IP "
                        "(the app did not supply a hostname)"
                        if ptr_only
                        else "Certificate chain does not validate against the system trust store"
                    ),
                    severity=1 if ptr_only else 2,
                    category="hygiene" if ptr_only else "security",
                    evidence=(result.error or result.issuer)[:200],
                )
            )
        if result.ok and not result.hostname_match:
            conn.add_flag(
                Flag(
                    code="TLS_NAME_NOT_IN_CERT" if ptr_only else "TLS_HOSTNAME_MISMATCH",
                    message=(
                        f"Certificate is for {result.subject or 'another name'}; the "
                        "reverse-DNS name for this IP is not listed"
                        if ptr_only
                        else "Certificate does not match the hostname being connected to"
                    ),
                    severity=1 if ptr_only else 2,
                    category="hygiene" if ptr_only else "security",
                    evidence=result.subject[:200],
                )
            )
        if result.weak_protocol:
            conn.add_flag(
                Flag(
                    code="TLS_WEAK_PROTOCOL",
                    message=f"Obsolete TLS protocol negotiated ({result.version})",
                    severity=2,
                    category="security",
                    evidence=result.version,
                )
            )
        if result.expiring_soon:
            conn.add_flag(
                Flag(
                    code="TLS_EXPIRING",
                    message=f"Certificate expires in {result.days_left} days",
                    severity=1,
                    category="hygiene",
                    evidence=result.not_after,
                )
            )

    def _t4_plaintext(self, conn: Connection) -> None:
        label = PLAINTEXT_PORTS.get(conn.remote.port)
        if not label or conn.direction == "listening":
            return
        severity = 2 if conn.remote.port in (23, 21, 110, 143) else 1
        conn.add_flag(
            Flag(
                code="PLAINTEXT",
                message=f"Traffic to {label} is unencrypted",
                severity=severity,
                category="privacy",
                evidence=f"port {conn.remote.port}",
            )
        )

    def _t5_risky_port(self, conn: Connection) -> None:
        port = conn.remote.port if conn.direction != "listening" else conn.local.port
        rule = self.reputation.port_rule(port, conn.proto)
        if not rule:
            return
        # Risky inbound services only matter when bound to a non-loopback address.
        if conn.direction == "listening" and conn.local.scope == "loopback":
            return
        conn.add_flag(
            Flag(
                code="RISKY_PORT",
                message=f"Port {port}/{rule.proto} is high-risk: {rule.description}",
                severity=rule.severity,
                category="security",
                evidence=f"{conn.proto}:{port}",
            )
        )

    def _t6_raw_ip(self, conn: Connection) -> None:
        ip = conn.remote.ip
        if not ip or not is_raw_ip(ip):
            return
        if conn.remote.hostname:
            return  # PTR resolved, so we have a name to reason about
        conn.add_flag(
            Flag(
                code="RAW_IP",
                message="Direct connection to a bare IP address with no DNS name",
                severity=1,
                category="hygiene",
                evidence=ip,
            )
        )

    def _t7_suspicious_tld(self, conn: Connection) -> None:
        for name in self._peer_names(conn):
            if self.reputation.is_suspicious_tld(name):
                tld = name.rsplit(".", 1)[-1]
                conn.add_flag(
                    Flag(
                        code="SUSPICIOUS_TLD",
                        message=f"Peer uses high-abuse TLD '.{tld}'",
                        severity=2,
                        category="reputation",
                        evidence=name,
                    )
                )
                return

    def _t8_dga(self, conn: Connection) -> None:
        for name in self._peer_names(conn):
            if looks_like_dga(name):
                conn.add_flag(
                    Flag(
                        code="DGA_HOSTNAME",
                        message="Hostname shape looks algorithmically generated (DGA)",
                        severity=2,
                        category="reputation",
                        evidence=name,
                    )
                )
                return

    def _t9_risky_process(self, conn: Connection) -> None:
        rule = self.reputation.process_rule(conn.process.name)
        if not rule:
            return
        conn.add_flag(
            Flag(
                code="RISKY_PROCESS",
                message=f"Process '{conn.process.name}' is a known risky tool: {rule.reason}",
                severity=rule.severity,
                category="security",
                evidence=conn.process.exe or conn.process.display,
            )
        )

    def _is_expected_service(self, conn: Connection) -> bool:
        """True when this listener is a known-good OS/LAN service.

        Only meaningful for listeners: it looks at the bound port and the
        owning process. Unbound UDP sockets (port 0) are never services, so
        they are excluded here and handled separately.
        """

        if conn.local.port == 0:
            return True
        rule = self.reputation.safe_service(conn.process.name, conn.local.port)
        if rule:
            conn.analysis["expected_service"] = rule.note
            return True
        return False

    def _t10_inbound(self, conn: Connection) -> None:
        if conn.direction != "listening":
            return
        if conn.local.scope not in ("any", "external"):
            return
        if self._is_expected_service(conn):
            return
        conn.add_flag(
            Flag(
                code="EXPOSED_LISTENER",
                message="Service is listening on all interfaces and reachable from the network",
                severity=2,
                category="security",
                evidence=f"{conn.local.pretty}",
            )
        )

    def _t11_exposure(self, conn: Connection) -> None:
        """Flag a non-loopback listener owned by a user-space app on a LAN address."""

        if conn.direction != "listening":
            return
        if conn.local.scope == "loopback":
            return
        if self._is_expected_service(conn):
            return
        name = (conn.process.name or "").lower()
        if any(hint in name for hint in SYSTEM_PROCESS_HINTS):
            return
        conn.add_flag(
            Flag(
                code="LAN_EXPOSURE",
                message="Application service is exposed beyond localhost",
                severity=1,
                category="hygiene",
                evidence=f"{conn.process.display} on {conn.local.pretty}",
            )
        )

    def _t12_unresolved(self, conn: Connection) -> None:
        if conn.flags:
            return
        if conn.remote.scope != "external":
            return
        conn.add_flag(
            Flag(
                code="UNVERIFIED_PEER",
                message="External peer has no allowlist, blocklist or TLS trust signal",
                severity=1,
                category="reputation",
                evidence=conn.remote.pretty,
            )
        )

    # -- verdict ---------------------------------------------------------

    def _finalize(self, conn: Connection) -> None:
        has_block = any(f.code == "BLOCKLIST" for f in conn.flags)
        trusted = conn.analysis.get("allowlist_match")
        tls = conn.analysis.get("tls") or {}
        tls_ok = bool(tls.get("ok")) and bool(tls.get("chain_trusted")) and bool(tls.get("hostname_match"))

        if has_block:
            verdict = Verdict.MALICIOUS
        elif any(f.severity >= 3 for f in conn.flags):
            verdict = Verdict.MALICIOUS
        elif any(f.severity == 2 for f in conn.flags):
            verdict = Verdict.SUSPICIOUS
        elif trusted and (tls_ok or conn.remote.port not in TLS_PORTS):
            verdict = Verdict.SECURE
        elif tls_ok:
            verdict = Verdict.SAFE
        elif conn.remote.scope in ("loopback", "lan", "any"):
            verdict = Verdict.SAFE if not conn.flags else Verdict.SUSPICIOUS
        else:
            verdict = Verdict.UNKNOWN

        conn.analysis["verdict"] = verdict.value
        conn.analysis["techniques"] = sorted({f.code for f in conn.flags})
        conn.analysis["tls_ok"] = tls_ok


def analyze_connections(
    connections: Iterable[Connection], deep: bool = True
) -> Tuple[List[Connection], ScanSummary]:
    """Module-level convenience wrapper."""

    engine = AnalysisEngine(deep=deep)
    return engine.analyze_with_summary(connections)
