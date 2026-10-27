"""TLS certificate inspection and grading.

Technique: open a short-lived TLS connection to the remote endpoint, fetch the
leaf certificate, then grade it on four independent axes:

  1. Trust chain validates against the system CA store.
  2. Hostname matches the certificate SAN/CN.
  3. Certificate is not expired / not expiring soon.
  4. Protocol version is modern (TLS 1.2+).

Results are cached per (host, port) so a monitoring loop does not re-handshake
the same server every refresh.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

CACHE_TTL_SECONDS = 900
TLS_PORTS = {443, 8443, 993, 995, 465, 587, 636, 853, 8883}


@dataclass
class TLSResult:
    ok: bool = False
    error: str = ""
    version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_left: Optional[int] = None
    hostname_match: bool = False
    chain_trusted: bool = False
    self_signed: bool = False
    expired: bool = False
    expiring_soon: bool = False
    weak_protocol: bool = False
    grade: str = "?"
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "error": self.error,
            "version": self.version,
            "cipher": self.cipher,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_left": self.days_left,
            "hostname_match": self.hostname_match,
            "chain_trusted": self.chain_trusted,
            "self_signed": self.self_signed,
            "expired": self.expired,
            "expiring_soon": self.expiring_soon,
            "weak_protocol": self.weak_protocol,
            "grade": self.grade,
            "notes": list(self.notes),
        }


def _name_to_str(name: Tuple[Tuple[Tuple[str, str], ...], ...]) -> str:
    flat: List[str] = []
    for rdn in name or ():
        for key, value in rdn:
            flat.append(f"{key}={value}")
    return ", ".join(flat)


def _parse_cert_time(value: str) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_dt.timezone.utc)
    except (ValueError, TypeError):
        return None


def _dnsname_match(pattern: str, host: str) -> bool:
    """RFC 6125 style wildcard match for a single certificate name."""

    pattern = pattern.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if pattern == host:
        return True
    if not pattern.startswith("*."):
        return False
    # A wildcard covers exactly one label and never a bare registered domain.
    suffix = pattern[1:]  # ".example.com"
    if not host.endswith(suffix):
        return False
    head = host[: -len(suffix)]
    return bool(head) and "." not in head


def _cert_names(cert: Dict[str, object]) -> List[str]:
    """Every DNS name the certificate is valid for (SANs first, then CN)."""

    names: List[str] = []
    for kind, value in cert.get("subjectAltName", ()) or ():  # type: ignore[union-attr]
        if kind == "DNS" and isinstance(value, str):
            names.append(value)
    if not names:
        for rdn in cert.get("subject", ()) or ():  # type: ignore[union-attr]
            for attr in rdn or ():
                if len(attr) != 2:
                    continue
                key, value = attr
                if key == "commonName" and isinstance(value, str):
                    names.append(value)
    return names


def _hostname_matches(host: str, cert: Dict[str, object]) -> bool:
    """True when ``host`` is covered by a SAN/CN entry in ``cert``.

    ``ssl.match_hostname`` was removed in Python 3.12, so the check is done
    here explicitly. A reverse-DNS name of an IP (``lb-140-82-114-25-iad.
    github.com``) is not in a certificate's SAN list and therefore cannot
    match - which is correct, so callers must only pass names that were
    actually used for SNI.
    """

    if not host:
        return False
    names = _cert_names(cert)
    if not names:
        return False
    return any(_dnsname_match(name, host) for name in names)


def _grade(result: TLSResult) -> str:
    if not result.ok:
        return "F"
    if result.expired or not result.chain_trusted or result.self_signed:
        return "F"
    if not result.hostname_match:
        return "D"
    if result.weak_protocol:
        return "C"
    if result.expiring_soon:
        return "B"
    return "A"


def probe(host: str, port: int, server_hostname: Optional[str] = None, timeout: float = 4.0) -> TLSResult:
    """Handshake with ``host:port`` and grade the presented certificate."""

    result = TLSResult()
    if not host or host == "*":
        result.error = "no host"
        return result

    ip = host.split("%")[0]
    try:
        ipaddress.ip_address(ip)
        is_ip = True
    except ValueError:
        is_ip = False

    # A verifying context always needs a hostname for SNI + hostname checking.
    # When we only have an IP we fall back to unverified inspection (pass 2),
    # because verifying an IP-literal connection is meaningless anyway.
    sni = server_hostname or (None if is_ip else ip)

    # Pass 1: verifying context - tells us whether the chain is trusted.
    if sni:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                    result.ok = True
                    result.chain_trusted = True
                    result.version = tls.version() or ""
                    cipher = tls.cipher()
                    result.cipher = cipher[0] if cipher else ""
                    cert = tls.getpeercert() or {}
                    _fill_cert(result, cert)
                    result.hostname_match = _hostname_matches(sni, cert)
                    result.weak_protocol = result.version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
                    result.grade = _grade(result)
                    return result
        except ssl.SSLCertVerificationError as exc:
            result.error = f"certificate verify failed: {exc.verify_message}"
            result.chain_trusted = False
            result.hostname_match = False
        except (ssl.SSLError, OSError) as exc:
            result.error = str(exc)
            result.grade = "F"
            return result

    # Pass 2: unverified context - still extract the certificate for grading.
    insecure = ssl._create_unverified_context()  # noqa: SLF001 - intentional
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with insecure.wrap_socket(raw, server_hostname=sni) as tls:
                result.ok = True
                result.version = tls.version() or ""
                cipher = tls.cipher()
                result.cipher = cipher[0] if cipher else ""
                cert = tls.getpeercert() or {}
                if not cert:
                    cert = _cert_from_der(tls.getpeercert(binary_form=True) or b"")
                _fill_cert(result, cert)
                if sni:
                    result.hostname_match = _hostname_matches(sni, cert)
                # A peer that is handed no SNI may answer with a placeholder
                # certificate ("No SNI provided - please fix your client." /
                # invalid2.invalid). That is the server declining to identify
                # itself, not a self-signed identity claim, so flag it as
                # inconclusive instead of grading it F.
                no_sni_placeholder = (
                    "no sni provided" in (result.subject or "").lower()
                    or "invalid2.invalid" in (result.subject or "").lower()
                )
                if no_sni_placeholder:
                    result.notes.append("peer requires SNI; identity unavailable")
                elif result.issuer and result.subject and result.issuer == result.subject:
                    result.self_signed = True
                result.weak_protocol = result.version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
    except (ssl.SSLError, OSError) as exc:
        result.error = result.error or str(exc)
        result.grade = "F"
        return result

    result.grade = _grade(result)
    return result


def _cert_from_der(der: bytes) -> Dict[str, object]:
    """Decode a DER certificate into the same dict shape getpeercert() returns.

    ``SSLSocket.getpeercert()`` returns an *empty* dict when the context does
    not verify certificates (which is exactly the unverified pass), even
    though the DER blob is available. Without this fallback the unverified
    pass learns nothing about the peer's identity.
    """

    if not der:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    # ``_test_decode_cert`` only accepts a *path*, not PEM text, so the blob has
    # to be materialised on disk before it can be decoded.
    tmp_path = ""
    try:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            tmp_path = fh.name
        return ssl._ssl._test_decode_cert(tmp_path) or {}  # noqa: SLF001
    except Exception:
        return {}
    finally:
        if tmp_path:
            try:
                import os

                os.unlink(tmp_path)
            except OSError:
                pass


def _fill_cert(result: TLSResult, cert: Dict[str, object]) -> None:
    result.subject = _name_to_str(cert.get("subject", ()))  # type: ignore[arg-type]
    result.issuer = _name_to_str(cert.get("issuer", ()))  # type: ignore[arg-type]
    result.not_before = str(cert.get("notBefore", ""))
    result.not_after = str(cert.get("notAfter", ""))
    not_after = _parse_cert_time(result.not_after)
    if not_after:
        now = _dt.datetime.now(_dt.timezone.utc)
        result.days_left = (not_after - now).days
        result.expired = result.days_left < 0
        result.expiring_soon = 0 <= result.days_left <= 14
    if not result.not_after:
        result.notes.append("certificate dates unavailable")


class TLSCache:
    """Thread-safe (host, port) -> TLSResult cache."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: Dict[Tuple[str, int], Tuple[TLSResult, float]] = {}
        import time

        self._time = time.time

    def get(self, host: str, port: int, server_hostname: Optional[str] = None) -> TLSResult:
        key = (host, port)
        now = self._time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[1] < CACHE_TTL_SECONDS:
                return hit[0]
        result = probe(host, port, server_hostname)
        with self._lock:
            self._cache[key] = (result, now)
        return result

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
