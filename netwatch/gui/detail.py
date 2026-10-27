"""Right-hand detail pane: everything known about the selected connection."""

from __future__ import annotations

import tkinter as tk
from typing import Optional

from ..models import Connection
from . import theme
from .widgets import Badge, FlagList, KeyValueList, SectionHeader, ScrollFrame


class DetailPane(tk.Frame):
    """Shows identity, peer, TLS and findings for one connection."""

    def __init__(self, master, **kwargs):
        super().__init__(master, bg=theme.BG, **kwargs)
        self._conn: Optional[Connection] = None

        head = tk.Frame(self, bg=theme.BG)
        head.pack(fill="x", padx=14, pady=(14, 6))
        self.badge = Badge(head, "NO SELECTION", theme.FG_FAINT)
        self.badge.pack(side="left")
        self.title = tk.Label(
            head,
            text="Select a connection",
            bg=theme.BG,
            fg=theme.FG,
            font=theme.FONT_UI_BOLD,
            anchor="w",
        )
        self.title.pack(side="left", padx=10, fill="x", expand=True)

        self.subtitle = tk.Label(
            self,
            text="Click any row in the table to inspect it.",
            bg=theme.BG,
            fg=theme.FG_FAINT,
            font=theme.FONT_SMALL,
            anchor="w",
            justify="left",
            wraplength=470,
        )
        self.subtitle.pack(fill="x", padx=14)

        self.scroll = ScrollFrame(self)
        self.scroll.pack(fill="both", expand=True, pady=(8, 0))

        self.section_identity = SectionHeader(self.scroll.inner, "Connection")
        self.section_identity.pack(fill="x", pady=(0, 4))
        self.identity = KeyValueList(self.scroll.inner)
        self.identity.pack(fill="x", padx=10, pady=(0, 10))

        self.section_peer = SectionHeader(self.scroll.inner, "Peer")
        self.section_peer.pack(fill="x", pady=(0, 4))
        self.peer = KeyValueList(self.scroll.inner)
        self.peer.pack(fill="x", padx=10, pady=(0, 10))

        self.section_tls = SectionHeader(self.scroll.inner, "Transport security")
        self.section_tls.pack(fill="x", pady=(0, 4))
        self.tls = KeyValueList(self.scroll.inner)
        self.tls.pack(fill="x", padx=10, pady=(0, 10))

        self.section_flags = SectionHeader(self.scroll.inner, "Findings")
        self.section_flags.pack(fill="x", pady=(0, 4))
        self.flags = FlagList(self.scroll.inner)
        self.flags.pack(fill="x", padx=10, pady=(0, 16))

    # -- rendering -------------------------------------------------------

    def show(self, conn: Optional[Connection]) -> None:
        self._conn = conn
        for section in (self.identity, self.peer, self.tls):
            section.clear()

        if conn is None:
            self.badge.set("NO SELECTION", theme.FG_FAINT)
            self.title.configure(text="Select a connection")
            self.subtitle.configure(text="Click any row in the table to inspect it.")
            self.flags.render([])
            return

        verdict = conn.verdict.value
        self.badge.set(theme.verdict_label(verdict), theme.verdict_color(verdict))
        self.title.configure(text=conn.process.name or "unknown process")
        owner = conn.process.pid if conn.process.pid is not None else "?"
        self.subtitle.configure(
            text=f"{conn.proto.upper()} {conn.direction}  \u2022  pid {owner}  \u2022  {conn.state}"
        )

        # -- connection
        self.identity.add("Local", f"{conn.local.address}:{conn.local.port}", mono=True)
        self.identity.add("Remote", conn.remote.pretty, mono=True)
        self.identity.add("Direction", conn.direction.capitalize(), theme.direction_color(conn.direction))
        self.identity.add("Protocol", conn.proto.upper())
        self.identity.add("State", conn.state)
        if conn.bytes_recv or conn.bytes_sent:
            self.identity.add("Traffic", f"{conn.bytes_recv} B in / {conn.bytes_sent} B out")
        if conn.started_at:
            self.identity.add("First seen", conn.started_at)

        # -- process / peer
        self.peer.add("Process", conn.process.display)
        if conn.process.exe:
            self.peer.add_wrapped("Executable", conn.process.exe, mono=False)
        if conn.process.user:
            self.peer.add("User", conn.process.user)
        self.peer.add("Peer scope", conn.remote.scope)
        if conn.remote.hostname:
            self.peer.add("Hostname", conn.remote.hostname)
        allow = conn.analysis.get("allowlist_match")
        block = conn.analysis.get("blocklist_match")
        if allow:
            self.peer.add("Authorised by", allow, theme.VERDICT_COLORS["safe"])
        if block:
            self.peer.add("Blocklist hit", block, theme.VERDICT_COLORS["malicious"])
        service = conn.analysis.get("expected_service")
        if service:
            self.peer.add("Expected service", service, theme.FG_DIM)

        # -- TLS
        tls = conn.analysis.get("tls")
        if tls:
            grade = tls.get("grade") or "-"
            grade_color = {
                "A": theme.VERDICT_COLORS["safe"],
                "B": theme.VERDICT_COLORS["safe"],
                "C": theme.VERDICT_COLORS["suspicious"],
                "D": theme.VERDICT_COLORS["suspicious"],
                "F": theme.VERDICT_COLORS["malicious"],
            }.get(grade, theme.FG_DIM)
            self.tls.add("Grade", grade, grade_color)
            if tls.get("version"):
                self.tls.add("Protocol", tls["version"])
            if tls.get("issuer"):
                self.tls.add_wrapped("Issuer", tls["issuer"])
            if tls.get("subject"):
                self.tls.add_wrapped("Subject", tls["subject"])
            if tls.get("not_after"):
                self.tls.add("Expires", tls["not_after"])
            self.tls.add(
                "Chain trusted",
                "yes" if tls.get("chain_trusted") else "no",
                theme.VERDICT_COLORS["safe"] if tls.get("chain_trusted") else theme.VERDICT_COLORS["malicious"],
            )
            self.tls.add(
                "Hostname match",
                "yes" if tls.get("hostname_match") else "no",
                theme.VERDICT_COLORS["safe"] if tls.get("hostname_match") else theme.VERDICT_COLORS["malicious"],
            )
        elif conn.direction == "listening":
            self.tls.add("Not applicable", "inbound listener")
        else:
            self.tls.add("Not inspected", "no TLS probe for this peer")

        # -- findings
        self.flags.render(conn.flags)
