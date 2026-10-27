"""The live connection table: sortable columns, verdict colouring, filters."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional, Sequence

from ..models import Connection
from . import theme

COLUMNS = (
    ("verdict", "VERDICT", 92, "w"),
    ("direction", "DIR", 78, "w"),
    ("application", "APPLICATION", 190, "w"),
    ("proto", "PROTO", 58, "w"),
    ("local", "LOCAL", 165, "w"),
    ("remote", "REMOTE / PEER", 210, "w"),
    ("state", "STATE", 92, "w"),
    ("findings", "FINDINGS", 190, "w"),
    ("traffic", "RX/TX", 100, "e"),
)

SORT_KEYS = {
    "verdict": lambda c: (-c.verdict.rank, c.process.name.lower()),
    "direction": lambda c: (c.direction, c.process.name.lower()),
    "application": lambda c: c.process.name.lower(),
    "proto": lambda c: c.proto,
    "local": lambda c: (c.local.address, c.local.port),
    "remote": lambda c: (c.remote.address, c.remote.port),
    "state": lambda c: c.state,
    "findings": lambda c: -c.severity_score,
    "traffic": lambda c: -(c.bytes_recv + c.bytes_sent),
}


def _fmt_bytes(n: int) -> str:
    if n <= 0:
        return ""
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}T"


def _findings_text(conn: Connection) -> str:
    if not conn.flags:
        return ""
    codes = [f.code for f in sorted(conn.flags, key=lambda f: -f.severity)]
    return ", ".join(codes[:3]) + (" +%d" % (len(codes) - 3) if len(codes) > 3 else "")


class ConnectionTable(tk.Frame):
    """A ttk.Treeview wired for verdict highlighting and sorting."""

    def __init__(self, master, on_select=None, **kwargs):
        super().__init__(master, bg=theme.BG, **kwargs)
        self.on_select = on_select
        self._rows: Dict[str, Connection] = {}
        self._sort_column = "verdict"
        self._sort_reverse = False

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "NetWatch.Treeview",
            background=theme.BG_ROW,
            fieldbackground=theme.BG_ROW,
            foreground=theme.FG,
            rowheight=24,
            borderwidth=0,
            font=theme.FONT_SMALL,
        )
        style.configure(
            "NetWatch.Treeview.Heading",
            background=theme.BG_ALT,
            foreground=theme.FG_DIM,
            relief="flat",
            font=theme.FONT_TINY,
            padding=(6, 5),
        )
        style.map(
            "NetWatch.Treeview",
            background=[("selected", theme.BG_SELECTED)],
            foreground=[("selected", theme.FG)],
        )
        style.map("NetWatch.Treeview.Heading", background=[("active", theme.BG_ROW)])

        self.tree = ttk.Treeview(
            self,
            columns=[c[0] for c in COLUMNS],
            show="headings",
            style="NetWatch.Treeview",
            selectmode="browse",
        )
        for key, label, width, anchor in COLUMNS:
            self.tree.heading(
                key, text=label, anchor=anchor, command=lambda k=key: self.sort_by(k)
            )
            self.tree.column(key, width=width, anchor=anchor, stretch=(key in ("remote", "findings")))

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.tag_configure("malicious", foreground=theme.VERDICT_COLORS["malicious"])
        self.tree.tag_configure("suspicious", foreground=theme.VERDICT_COLORS["suspicious"])
        self.tree.tag_configure("secure", foreground=theme.VERDICT_COLORS["secure"])
        self.tree.tag_configure("safe", foreground=theme.VERDICT_COLORS["safe"])
        self.tree.tag_configure("unknown", foreground=theme.FG)
        self.tree.tag_configure("alt", background=theme.BG_ROW_ALT)

        self.tree.bind("<<TreeviewSelect>>", self._selected)

    # -- population ------------------------------------------------------

    def set_connections(self, connections: Sequence[Connection]) -> None:
        """Replace the visible rows, preserving the selected connection if possible."""

        selected_key = None
        sel = self.tree.selection()
        if sel:
            current = self._rows.get(sel[0])
            selected_key = current.key if current else None

        ordered = sorted(connections, key=SORT_KEYS[self._sort_column], reverse=self._sort_reverse)

        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        restore = None
        for index, conn in enumerate(ordered):
            iid = f"r{index}"
            self._rows[iid] = conn
            tags = [conn.verdict.value]
            if index % 2:
                tags.append("alt")
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    conn.verdict.value.upper(),
                    conn.direction.upper(),
                    conn.process.name or "unknown",
                    conn.proto.upper(),
                    f"{conn.local.address}:{conn.local.port}" if conn.local.address else "-",
                    conn.remote.pretty,
                    conn.state,
                    _findings_text(conn),
                    self._traffic(conn),
                ),
                tags=tuple(tags),
            )
            if selected_key and conn.key == selected_key:
                restore = iid

        if restore:
            self.tree.selection_set(restore)
            self.tree.see(restore)

    def _traffic(self, conn: Connection) -> str:
        recv = _fmt_bytes(conn.bytes_recv)
        sent = _fmt_bytes(conn.bytes_sent)
        if recv and sent:
            return f"{recv}/{sent}"
        return recv or sent or ""

    def sort_by(self, column: str) -> None:
        if column not in SORT_KEYS:
            return
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False
        self.set_connections(list(self._rows.values()))

    # -- selection -------------------------------------------------------

    def _selected(self, _event=None) -> None:
        sel = self.tree.selection()
        conn = self._rows.get(sel[0]) if sel else None
        if self.on_select:
            self.on_select(conn)

    def selected_connection(self) -> Optional[Connection]:
        sel = self.tree.selection()
        return self._rows.get(sel[0]) if sel else None
