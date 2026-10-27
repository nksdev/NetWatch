"""Linux collector built on /proc/net/{tcp,tcp6,udp,udp6} and /proc/<pid>/fd.

Strategy:
  1. Parse the kernel socket tables in /proc/net/* - always readable, gives
     the exact 4-tuple and TCP state for every socket in the namespace.
  2. Build a socket-inode -> PID map by scanning /proc/<pid>/fd symlinks
     (``socket:[inode]``). Owned sockets resolve without root; other users'
     sockets need CAP_SYS_PTRACE/root and are reported as unattributed.
  3. Enrich with process name/exe/user from /proc/<pid>/.

No external binaries required - this works on any Linux including minimal
containers where netstat/ss/lsof are absent.
"""

from __future__ import annotations

import glob
import os
from typing import Dict, List, Optional, Tuple

from ..models import Connection
from .base import Collector, CollectorError, infer_direction, make_endpoint, split_endpoint

PROC_NET = "/proc/net"

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}


def _decode_proc_address(raw: str) -> Tuple[str, int]:
    """Decode a /proc/net address token like ``0100007F:1F90``.

    IPv4 is little-endian hex of the 4 bytes; IPv6 is four little-endian
    32-bit words. Port is big-endian hex.
    """

    addr_hex, _, port_hex = raw.partition(":")
    port = int(port_hex, 16) if port_hex else 0
    if len(addr_hex) == 8:
        octets = [int(addr_hex[i : i + 2], 16) for i in range(0, 8, 2)]
        return ".".join(str(b) for b in reversed(octets)), port
    if len(addr_hex) == 32:
        import ipaddress

        chunks = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
        words: List[int] = []
        for chunk in chunks:
            # /proc prints each 32-bit word in host (little-endian) order.
            words.extend(int(chunk[i : i + 2], 16) for i in range(6, -1, -2))
        packed = bytes(words)
        try:
            return str(ipaddress.IPv6Address(packed)), port
        except Exception:
            return "::", port
    return addr_hex or "*", port


def parse_proc_net(text: str, proto: str) -> List[Dict[str, object]]:
    """Parse a /proc/net/{tcp,udp}* table into socket dicts."""

    sockets: List[Dict[str, object]] = []
    lines = text.splitlines()
    if not lines:
        return sockets
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local_addr, local_port = _decode_proc_address(parts[1])
            remote_addr, remote_port = _decode_proc_address(parts[2])
            state_hex = parts[3]
            inode = int(parts[9])
        except (ValueError, IndexError):
            continue
        state = TCP_STATES.get(state_hex.upper(), "") if proto.startswith("tcp") else ""
        if proto.startswith("tcp") and not state:
            state = "UNKNOWN"
        if proto.startswith("udp") and not state:
            state = "UNCONN" if remote_port == 0 else "ESTABLISHED"
        sockets.append(
            {
                "proto": proto,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "state": state,
                "inode": inode,
            }
        )
    return sockets


def build_inode_pid_map() -> Dict[int, int]:
    """Map socket inode -> PID by scanning /proc/<pid>/fd symlinks."""

    mapping: Dict[int, int] = {}
    for pid_dir in glob.glob("/proc/[0-9]*"):
        pid_str = os.path.basename(pid_dir)
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        try:
            fd_names = os.listdir(f"{pid_dir}/fd")
        except OSError:
            continue  # other user or exited
        for fd in fd_names:
            try:
                target = os.readlink(f"{pid_dir}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                try:
                    mapping[int(target[8:-1])] = pid
                except ValueError:
                    continue
    return mapping


class LinuxCollector(Collector):
    os_name = "linux"

    def __init__(self) -> None:
        self.errors: List[str] = []

    def _read_table(self, name: str) -> str:
        path = os.path.join(PROC_NET, name)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            self.errors.append(f"{name}: {exc}")
            return ""

    def collect(self) -> List[Connection]:
        self.errors = []
        sockets: List[Dict[str, object]] = []
        for table, proto in (
            ("tcp", "tcp"),
            ("tcp6", "tcp6"),
            ("udp", "udp"),
            ("udp6", "udp6"),
        ):
            text = self._read_table(table)
            if text:
                sockets.extend(parse_proc_net(text, proto))

        if not sockets and self.errors:
            raise CollectorError("cannot read /proc/net tables: " + "; ".join(self.errors))

        inode_map = build_inode_pid_map()
        connections: List[Connection] = []
        seen: set[str] = set()

        for sock in sockets:
            local = make_endpoint(str(sock["local_addr"]), int(sock["local_port"]))
            remote = make_endpoint(str(sock["remote_addr"]), int(sock["remote_port"]))
            state = str(sock["state"])
            direction = infer_direction(local, remote, state)
            pid = inode_map.get(int(sock["inode"]))  # type: ignore[arg-type]
            process = self._process_from_pid(pid, "")
            conn = Connection(
                proto=str(sock["proto"]),
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
