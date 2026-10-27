"""DNS / reverse-DNS enrichment.

Forward lookup is not needed: the process already dialled an IP. What matters
for accountability is the *reverse* mapping and, when the socket carries a TLS
SNI or an HTTP Host, the forward name that the client believes it is talking
to.

All lookups are cached and time-bounded so a scan never stalls on a slow
resolver.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from typing import Dict, Optional

CACHE_TTL_SECONDS = 600


class ReverseDNSCache:
    """Thread-safe PTR cache with a short TTL."""

    def __init__(self, timeout: float = 1.5) -> None:
        self.timeout = timeout
        self._lock = threading.Lock()
        self._cache: Dict[str, tuple[Optional[str], float]] = {}
        import time

        self._time = time.time

    def lookup(self, ip: str) -> Optional[str]:
        ip = (ip or "").split("%")[0]
        if not ip or ip == "*":
            return None
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return ip  # already a hostname
        if parsed.is_loopback or parsed.is_private or parsed.is_link_local or parsed.is_multicast:
            return None

        now = self._time()
        with self._lock:
            hit = self._cache.get(ip)
            if hit and now - hit[1] < CACHE_TTL_SECONDS:
                return hit[0]

        name: Optional[str] = None
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            host, _, _ = socket.gethostbyaddr(ip)
            name = host.rstrip(".") or None
        except (OSError, socket.herror, socket.gaierror):
            name = None
        finally:
            socket.setdefaulttimeout(old_timeout)

        with self._lock:
            self._cache[ip] = (name, now)
        return name

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
