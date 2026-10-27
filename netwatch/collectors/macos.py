"""macOS collector built on ``lsof`` machine-readable output plus ``netstat -anv``.

Why lsof:
  * It ships with every macOS install (/usr/sbin/lsof).
  * ``-F`` field output is stable and does not need parsing of aligned columns.
  * It maps socket -> PID -> command name, which is exactly what NetWatch needs
    to attribute traffic to applications.
  * It does not require root for the current user's own sockets.

``netstat -anv -p tcp`` is merged in for byte counters (rxbytes/txbytes), which
lsof does not expose.

lsof field grammar used here (from ``-FpcuPnT``):
  p<pid>            start of a process block
  c<command>        command name
  u<uid>            user id
  f<fd>             start of a file/socket block
  P<proto>          protocol, e.g. TCP / UDP
  n<name>           socket name: ``local`` or ``local->remote``
  TST=<state>       TCP socket state, e.g. TST=LISTEN, TST=ESTABLISHED
  TQR=<n> TQS=<n>   socket queue sizes (ignored)

A listening socket appears as ``n*:7000`` with no ``->``; a connected socket
appears as ``n1.2.3.4:5555->5.6.7.8:443``. IPv6 is bracketed: ``[::1]:443``.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .. import platform as plat
from ..models import Connection, Endpoint
from .base import Collector, CollectorError, infer_direction, make_endpoint, split_endpoint

LSOF = "/usr/sbin/lsof"
NETSTAT = "/usr/sbin/netstat"

TCP_STATES = "ESTABLISHED,SYN_SENT,SYN_RCVD,LISTEN,CLOSE_WAIT,LAST_ACK,CLOSED"


def _parse_tcp_state(value: str) -> str:
    """lsof emits ``ST=ESTABLISHED``; older builds may emit the bare state."""

    if value.upper().startswith("ST="):
        return value[3:]
    return value


def parse_lsof_fields(text: str) -> List[Dict[str, object]]:
    """Parse ``lsof -F`` output into one dict per process, each with ``fds``."""

    records: List[Dict[str, object]] = []
    current: Optional[Dict[str, object]] = None
    for raw in text.splitlines():
        if not raw:
            continue
        tag, value = raw[0], raw[1:]
        if tag == "p":
            current = {
                "pid": int(value) if value.isdigit() else None,
                "command": "",
                "uid": "",
                "fds": [],
            }
            records.append(current)
            continue
        if current is None:
            continue
        if tag == "c":
            current["command"] = value
        elif tag == "u":
            current["uid"] = value
        elif tag == "f":
            current["fds"].append({"fd": value})  # type: ignore[union-attr]
        elif tag == "P":
            fds = current["fds"]  # type: ignore[assignment]
            if fds:
                fds[-1]["proto"] = value
        elif tag == "n":
            fds = current["fds"]  # type: ignore[assignment]
            if fds:
                fds[-1]["name"] = value
        elif tag == "T":
            fds = current["fds"]  # type: ignore[assignment]
            if fds and value.upper().startswith("ST="):
                fds[-1]["state"] = _parse_tcp_state(value)
    return records


def _netstat_addr(token: str) -> Tuple[str, int]:
    """macOS netstat uses ``1.2.3.4.443``, ``*.443`` and ``fe80::1.443``."""

    if token in ("*.*", "*"):
        return "*", 0
    if token.startswith("*."):
        port = token[2:]
        return "*", int(port) if port.isdigit() else 0
    head, _, port = token.rpartition(".")
    if not head:
        return token, 0
    return head.strip("[]"), int(port) if port.isdigit() else 0


def parse_netstat_rows(text: str) -> Dict[Tuple[str, int, str, int], Dict[str, int]]:
    """Parse ``netstat -anv -p tcp`` into 4-tuple -> {rx, tx} byte counters."""

    counters: Dict[Tuple[str, int, str, int], Dict[str, int]] = {}
    header_seen = False
    for line in text.splitlines():
        if not line.strip():
            continue
        if not header_seen:
            if line.lower().startswith("proto"):
                header_seen = True
            continue
        parts = line.split()
        if len(parts) < 7 or not parts[0].startswith("tcp"):
            continue
        local_ip, local_port = _netstat_addr(parts[3])
        remote_ip, remote_port = _netstat_addr(parts[4])
        # Column 5 is the state word; the byte counters follow it. Some
        # netstat builds omit the state column entirely, so take the last
        # two numeric fields instead of relying on fixed offsets.
        tail = parts[5:]
        numbers = []
        for token in reversed(tail):
            if token.isdigit():
                numbers.append(int(token))
            if len(numbers) == 2:
                break
        if len(numbers) == 2:
            tx, rx = numbers  # reversed() gave tx first
        else:
            rx = tx = 0
        counters[(local_ip, local_port, remote_ip, remote_port)] = {"rx": rx, "tx": tx}
    return counters


def _split_name(name: str) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """Split an lsof NAME field into (local, remote) endpoint pairs."""

    if "->" in name:
        local_raw, remote_raw = name.split("->", 1)
    else:
        local_raw, remote_raw = name, ""
    local_addr, local_port = split_endpoint(local_raw)
    remote_addr, remote_port = split_endpoint(remote_raw)
    return (local_addr, local_port), (remote_addr, remote_port)


class MacOSCollector(Collector):
    os_name = "macos"

    def __init__(self) -> None:
        self.errors: List[str] = []

    # -- raw reads -------------------------------------------------------

    def _read_lsof(self) -> str:
        cmd = [
            LSOF,
            "-nP",
            "-i",
            "-sTCP:" + TCP_STATES,
            "-FpcuPnT",
        ]
        proc = plat.run(cmd, timeout=20)
        if proc.returncode != 0 and not proc.stdout.strip():
            raise CollectorError(proc.stderr.strip() or "lsof returned no data")
        if proc.stderr.strip():
            self.errors.append(proc.stderr.strip().splitlines()[0])
        return proc.stdout

    def _read_netstat(self) -> str:
        proc = plat.run([NETSTAT, "-anv", "-p", "tcp"], timeout=10)
        if proc.returncode != 0:
            self.errors.append(proc.stderr.strip() or "netstat failed")
        return proc.stdout

    # -- collection ------------------------------------------------------

    def collect(self) -> List[Connection]:
        self.errors = []
        records = parse_lsof_fields(self._read_lsof())
        counters = parse_netstat_rows(self._read_netstat())

        connections: List[Connection] = []
        seen: set[str] = set()
        for record in records:
            pid = record.get("pid")
            command = str(record.get("command", ""))
            for fd in record.get("fds", []):  # type: ignore[union-attr]
                name = str(fd.get("name", ""))
                if not name:
                    continue
                proto = str(fd.get("proto", "TCP")).lower()
                (local_addr, local_port), (remote_addr, remote_port) = _split_name(name)
                local = make_endpoint(local_addr, local_port)
                remote = make_endpoint(remote_addr, remote_port)
                state = str(fd.get("state", ""))
                if not state:
                    state = "LISTEN" if proto == "tcp" and not remote_raw_present(name) else "ESTABLISHED"
                direction = infer_direction(local, remote, state)
                conn = Connection(
                    proto=proto,
                    local=local,
                    remote=remote,
                    state=state,
                    direction=direction,
                    process=self._process_from_pid(
                        int(pid) if isinstance(pid, int) else None, command
                    ),
                )
                if conn.key in seen:
                    continue
                seen.add(conn.key)
                counters_key = (local.ip, local.port, remote.ip, remote.port)
                if counters_key in counters:
                    conn.bytes_recv = counters[counters_key]["rx"]
                    conn.bytes_sent = counters[counters_key]["tx"]
                connections.append(conn)
        return connections


def remote_raw_present(name: str) -> bool:
    """True when lsof produced a real ``local->remote`` pair."""

    return "->" in name
