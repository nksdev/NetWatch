"""Collector base class, endpoint parsing helpers and platform dispatch."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

from .. import platform as plat
from ..models import Connection, Endpoint, ProcessInfo


class CollectorError(RuntimeError):
    """Raised when the socket table cannot be read at all."""


def classify_scope(address: str) -> str:
    """Return loopback | lan | external | any | unknown for an address literal."""

    addr = address.strip().strip("[]")
    if addr in ("*", ""):
        return "any"
    addr = addr.split("%")[0]
    # Bare IPv6 zone-less literals sometimes arrive with trailing colons.
    addr = addr.rstrip(":") if addr.count(":") > 1 and not addr.endswith("::") else addr
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local or ip.is_private:
        return "lan"
    if ip.is_unspecified:
        return "any"
    return "external"


def split_endpoint(token: str, default_port: int = 0) -> Tuple[str, int]:
    """Split ``host:port``, ``[v6]:port``, ``*:port`` or bare host.

    Returns (address, port). The address keeps IPv6 literals unbracketed.
    """

    token = token.strip()
    if not token:
        return "", default_port
    if token == "*":
        return "*", default_port
    if token.startswith("["):
        host, _, rest = token[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else default_port
    if token.count(":") == 1:
        host, _, port = token.partition(":")
        return host, int(port) if port.isdigit() else default_port
    if token.count(":") > 1:
        # Bracketed-less IPv6: port is the final ``:<digits>`` only if the part
        # before it is still a valid IPv6 literal. ``2001:db8::1:443`` is
        # ambiguous, so prefer treating the whole token as the address when a
        # valid IPv6 parse succeeds.
        head, _, tail = token.rpartition(":")
        if tail.isdigit() and head:
            try:
                ipaddress.IPv6Address(head)
                return head, int(tail)
            except ValueError:
                pass
        return token, default_port
    return token, default_port


def make_endpoint(address: str, port: int) -> Endpoint:
    address = address.strip()
    if address in ("*", "0.0.0.0", "::", "[::]", ""):
        return Endpoint(address="*", port=port, scope="any")
    return Endpoint(address=address, port=port, scope=classify_scope(address))


CLIENT_PORTS = {443, 80, 22, 25, 53, 110, 143, 993, 995, 587, 5228, 8443, 9418}


def infer_direction(local: Endpoint, remote: Endpoint, state: str) -> str:
    """Classify the flow as listening | local | inbound | outbound."""

    if state.upper().startswith("LISTEN"):
        return "listening"
    if remote.scope == "any" or (remote.address in ("", "*") and remote.port == 0):
        return "listening"
    if local.scope == "loopback" or remote.scope == "loopback":
        return "local"
    if local.port in CLIENT_PORTS and remote.port >= 1024:
        return "inbound"
    if remote.port in CLIENT_PORTS:
        return "outbound"
    if local.port >= 32768 and remote.port >= 32768:
        # Peer-to-peer on the LAN; treat as inbound if the local side is private.
        return "inbound" if local.scope == "lan" else "outbound"
    return "outbound"


class Collector:
    """Common interface implemented by every OS collector."""

    os_name = "unknown"

    def collect(self) -> List[Connection]:  # pragma: no cover - interface
        raise NotImplementedError

    def _process_from_pid(self, pid: Optional[int], fallback_name: str = "") -> ProcessInfo:
        info = ProcessInfo(pid=pid, name=fallback_name)
        if pid is None:
            return info
        meta = process_metadata(pid)
        if meta:
            info.name = meta.get("name") or fallback_name or info.name
            info.exe = meta.get("exe", "")
            info.user = meta.get("user", "")
            info.cmdline = meta.get("cmdline", "")
        return info


_PROCESS_CACHE: Dict[int, Dict[str, str]] = {}


def process_metadata(pid: int) -> Dict[str, str]:
    """Best-effort PID -> name/exe/user/cmdline lookup, cached per pid."""

    if pid in _PROCESS_CACHE:
        return _PROCESS_CACHE[pid]

    meta: Dict[str, str] = {}

    if plat.IS_LINUX:
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
                meta["name"] = fh.read().strip()
        except OSError:
            pass
        try:
            meta["exe"] = readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                meta["cmdline"] = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            pass
        try:
            import os
            import pwd

            meta["user"] = pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
        except Exception:
            pass

    elif plat.IS_MACOS:
        # ``ps`` may be blocked by endpoint security / sandboxes, so use lsof
        # to discover the executable text file for this pid instead.
        proc = plat.run(["/usr/sbin/lsof", "-a", "-p", str(pid), "-d", "txt", "-Fn"], timeout=5)
        for line in proc.stdout.splitlines():
            if line.startswith("n"):
                meta["exe"] = line[1:]
                break
        uid = read_macos_uid(pid)
        if uid:
            meta["user"] = uid

    elif plat.IS_WINDOWS:
        if plat.has_module("psutil"):
            try:
                import psutil

                p = psutil.Process(pid)
                meta["name"] = p.name()
                meta["exe"] = p.exe()
                meta["user"] = p.username()
                meta["cmdline"] = " ".join(p.cmdline())
            except Exception:
                pass

    if meta:
        _PROCESS_CACHE[pid] = meta
    return meta


def readlink(path: str) -> str:
    import os

    return os.readlink(path)


def read_macos_uid(pid: int) -> str:
    """Resolve the owning user of a pid using lsof (avoids /bin/ps)."""

    try:
        import getpass
        import os
        import pwd

        if os.stat(f"/dev/fd") is None:  # pragma: no cover - always truthy
            return ""
        proc = plat.run(["/usr/sbin/lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fu"], timeout=4)
        for line in proc.stdout.splitlines():
            if line.startswith("u"):
                try:
                    return pwd.getpwuid(int(line[1:])).pw_name
                except Exception:
                    return getpass.getuser()
    except Exception:
        pass
    return ""


def get_collector() -> Collector:
    """Return the collector matching the current platform."""

    if plat.IS_MACOS:
        from .macos import MacOSCollector

        return MacOSCollector()
    if plat.IS_LINUX:
        from .linux import LinuxCollector

        return LinuxCollector()
    if plat.IS_WINDOWS:
        from .windows import WindowsCollector

        return WindowsCollector()
    raise CollectorError(f"unsupported platform: {plat.OS_LABEL}")
