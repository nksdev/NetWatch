"""Windows collector.

Primary backend: ``psutil.net_connections(kind="inet")`` which wraps
GetExtendedTcpTable / GetExtendedUdpTable and resolves the owning PID. This is
the same API Task Manager uses and needs no elevation for the current user's
sockets (elevation only widens visibility to other users' sockets).

Fallback backend: parse ``netstat -ano`` when psutil is unavailable. That path
still yields the 4-tuple, state and PID, but process names require
``tasklist``.

No shell is ever used, and no admin-only API is required.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .. import platform as plat
from ..models import Connection
from .base import Collector, CollectorError, infer_direction, make_endpoint

WIN_STATES = {
    "ESTABLISHED": "ESTABLISHED",
    "LISTEN": "LISTEN",
    "LISTENING": "LISTEN",
    "SYN_SENT": "SYN_SENT",
    "SYN_RECEIVED": "SYN_RECV",
    "FIN_WAIT_1": "FIN_WAIT1",
    "FIN_WAIT_2": "FIN_WAIT2",
    "TIME_WAIT": "TIME_WAIT",
    "CLOSE_WAIT": "CLOSE_WAIT",
    "CLOSING": "CLOSING",
    "LAST_ACK": "LAST_ACK",
    "DELETE_TCB": "CLOSE",
    "CLOSED": "CLOSE",
    "NONE": "",
}


def _clean_addr(addr: str) -> str:
    addr = (addr or "").strip()
    if addr in ("0.0.0.0", "::", ""):
        return "*"
    if addr.startswith("::ffff:"):
        return addr[7:]
    return addr


def parse_netstat_ano(text: str) -> List[Dict[str, object]]:
    """Parse ``netstat -ano`` output into socket dicts."""

    rows: List[Dict[str, object]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        proto = parts[0].lower()
        local_raw, remote_raw = parts[1], parts[2]
        state = ""
        pid_token = parts[-1]
        if proto == "tcp" and len(parts) >= 5:
            state = WIN_STATES.get(parts[3].upper(), parts[3].upper())
        if not pid_token.isdigit():
            continue
        rows.append(
            {
                "proto": proto,
                "local": local_raw,
                "remote": remote_raw,
                "state": state or ("UNCONN" if proto == "udp" else ""),
                "pid": int(pid_token),
            }
        )
    return rows


def parse_tasklist_csv(text: str) -> Dict[int, str]:
    """Map PID -> image name from ``tasklist /fo csv /nh``."""

    names: Dict[int, str] = {}
    for line in text.splitlines():
        cells = [c.strip().strip('"') for c in line.split('","')]
        if len(cells) < 2:
            continue
        name = cells[0].strip('"')
        pid_cell = cells[1].strip('"')
        if pid_cell.isdigit():
            names[int(pid_cell)] = name
    return names


def _split_hostport(token: str) -> tuple[str, int]:
    token = token.strip()
    if token in ("*:*", "*"):
        return "*", 0
    if token.startswith("["):
        host, _, rest = token[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else 0
    host, _, port = token.rpartition(":")
    if not host:
        return token, 0
    return host, int(port) if port.isdigit() else 0


class WindowsCollector(Collector):
    os_name = "windows"

    def __init__(self) -> None:
        self.errors: List[str] = []

    # -- psutil backend --------------------------------------------------

    def _collect_psutil(self) -> List[Connection]:
        import psutil

        connections: List[Connection] = []
        seen: set[str] = set()
        try:
            raw = psutil.net_connections(kind="inet")
        except Exception as exc:  # AccessDenied for other users' sockets
            self.errors.append(f"psutil.net_connections: {exc}")
            raw = []
        for item in raw:
            laddr = item.laddr
            raddr = item.raddr
            local_addr = _clean_addr(getattr(laddr, "ip", "") or "")
            local_port = int(getattr(laddr, "port", 0) or 0)
            remote_addr = _clean_addr(getattr(raddr, "ip", "") or "") if raddr else "*"
            remote_port = int(getattr(raddr, "port", 0) or 0) if raddr else 0
            local = make_endpoint(local_addr, local_port)
            remote = make_endpoint(remote_addr, remote_port)
            state = WIN_STATES.get(str(item.status).upper(), str(item.status).upper())
            direction = infer_direction(local, remote, state)
            process = self._process_from_pid(item.pid, "")
            if not process.name:
                process.name = "System" if item.pid in (0, 4) else "unknown"
            conn = Connection(
                proto="tcp" if item.type.name == "SOCK_STREAM" else "udp",
                local=local,
                remote=remote,
                state=state,
                direction=direction,
                process=process,
            )
            if conn.key in seen:
                continue
            seen.add(conn.key)
            connections.append(conn)
        return connections

    # -- netstat fallback ------------------------------------------------

    def _collect_netstat(self) -> List[Connection]:
        proc = plat.run(["netstat", "-ano"], timeout=20)
        if proc.returncode != 0 and not proc.stdout.strip():
            raise CollectorError(proc.stderr.strip() or "netstat returned no data")
        rows = parse_netstat_ano(proc.stdout)

        names: Dict[int, str] = {}
        task = plat.run(["tasklist", "/fo", "csv", "/nh"], timeout=20)
        if task.stdout.strip():
            names = parse_tasklist_csv(task.stdout)

        connections: List[Connection] = []
        seen: set[str] = set()
        for row in rows:
            local_addr, local_port = _split_hostport(str(row["local"]))
            remote_addr, remote_port = _split_hostport(str(row["remote"]))
            local = make_endpoint(local_addr, local_port)
            remote = make_endpoint(remote_addr, remote_port)
            state = str(row["state"])
            pid = int(row["pid"])  # type: ignore[arg-type]
            process = self._process_from_pid(pid, names.get(pid, ""))
            conn = Connection(
                proto=str(row["proto"]),
                local=local,
                remote=remote,
                state=state,
                direction=infer_direction(local, remote, state),
                process=process,
            )
            if conn.key in seen:
                continue
            seen.add(conn.key)
            connections.append(conn)
        return connections

    def collect(self) -> List[Connection]:
        self.errors = []
        if plat.has_module("psutil"):
            return self._collect_psutil()
        return self._collect_netstat()
