"""The permission gate shown before monitoring starts.

On launch NetWatch probes the host and reports exactly which permissions it
has, which it needs, and what to do about any that are missing. Monitoring is
only offered once the *required* checks pass, which is what makes the tool
honest across macOS, Linux and Windows.
"""

from __future__ import annotations

import threading
import tkinter as tk
from typing import Callable, Optional

from .. import platform as plat
from ..models import PlatformReport
from . import theme
from .widgets import Badge, PermissionRow, ScrollFrame


class PermissionGate(tk.Frame):
    """Full-window pre-flight report with a Start button."""

    def __init__(self, master, on_start: Callable[[PlatformReport], None], **kwargs):
        super().__init__(master, bg=theme.BG, **kwargs)
        self.on_start = on_start
        self.report: Optional[PlatformReport] = None
        self._busy = False

        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=32, pady=(28, 6))
        tk.Label(
            header,
            text="NetWatch",
            bg=theme.BG,
            fg=theme.FG,
            font=("Helvetica Neue", 26, "bold"),
        ).pack(side="left")
        tk.Label(
            header,
            text="  live connection monitor",
            bg=theme.BG,
            fg=theme.FG_FAINT,
            font=theme.FONT_UI,
        ).pack(side="left", pady=(10, 0))

        self.subtitle = tk.Label(
            self,
            text="Checking what this machine lets NetWatch see\u2026",
            bg=theme.BG,
            fg=theme.FG_DIM,
            font=theme.FONT_UI,
            anchor="w",
        )
        self.subtitle.pack(fill="x", padx=32, pady=(0, 14))

        self.host_line = tk.Label(
            self, text="", bg=theme.BG, fg=theme.FG_FAINT, font=theme.FONT_MONO, anchor="w"
        )
        self.host_line.pack(fill="x", padx=32, pady=(0, 16))

        self.scroll = ScrollFrame(self)
        self.scroll.pack(fill="both", expand=True, padx=32, pady=(0, 12))

        notes = tk.Frame(self, bg=theme.BG)
        notes.pack(fill="x", padx=32)
        self.notes_label = tk.Label(
            notes,
            text="",
            bg=theme.BG,
            fg=theme.FG_FAINT,
            font=theme.FONT_SMALL,
            anchor="w",
            justify="left",
            wraplength=720,
        )
        self.notes_label.pack(fill="x")

        footer = tk.Frame(self, bg=theme.BG)
        footer.pack(fill="x", padx=32, pady=20)
        self.status = tk.Label(
            footer, text="", bg=theme.BG, fg=theme.FG_DIM, font=theme.FONT_SMALL, anchor="w"
        )
        self.status.pack(side="left")

        self.recheck_button = tk.Button(
            footer,
            text="Re-check",
            command=self.run_checks,
            bg=theme.BG_ALT,
            fg=theme.FG,
            activebackground=theme.BG_ROW,
            activeforeground=theme.FG,
            relief="flat",
            font=theme.FONT_UI,
            padx=16,
            pady=7,
        )
        self.recheck_button.pack(side="right", padx=(8, 0))

        self.start_button = tk.Button(
            footer,
            text="Start monitoring",
            command=self._start,
            bg=theme.ACCENT,
            fg="#0d0f13",
            activebackground="#6fb4ff",
            activeforeground="#0d0f13",
            relief="flat",
            font=theme.FONT_UI_BOLD,
            padx=22,
            pady=7,
            state="disabled",
        )
        self.start_button.pack(side="right")

    # -- checks ----------------------------------------------------------

    def run_checks(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.start_button.configure(state="disabled")
        self.recheck_button.configure(state="disabled")
        self.status.configure(text="Probing host\u2026", fg=theme.FG_DIM)
        self.subtitle.configure(text="Checking what this machine lets NetWatch see\u2026")

        # Tkinter is not thread safe: only the main thread may call widget
        # methods or ``after()``. The worker therefore just stores its result
        # in plain attributes and a main-thread polling callback reads it back.
        box: dict = {}
        done = threading.Event()

        def work() -> None:
            try:
                box["report"] = plat.evaluate()
            except Exception as exc:  # pragma: no cover - defensive
                box["error"] = exc
            finally:
                done.set()

        def poll() -> None:
            if not done.is_set():
                self.after(40, poll)
                return
            self._show(box.get("report"), box.get("error"))

        threading.Thread(target=work, daemon=True).start()
        self.after(40, poll)

    def _show(self, report: Optional[PlatformReport], error: Optional[Exception]) -> None:
        self._busy = False
        self.recheck_button.configure(state="normal")
        for child in self.scroll.inner.winfo_children():
            child.destroy()

        if report is None:
            self.subtitle.configure(text="Host probe failed")
            tk.Label(
                self.scroll.inner,
                text=f"Could not inspect this machine: {error}",
                bg=theme.BG,
                fg=theme.VERDICT_COLORS["malicious"],
                font=theme.FONT_UI,
                anchor="w",
                justify="left",
                wraplength=720,
            ).pack(fill="x", padx=4, pady=8)
            self.status.configure(text="Probe failed", fg=theme.VERDICT_COLORS["malicious"])
            return

        self.report = report
        self.host_line.configure(
            text=f"{report.os_name} {report.os_version}  \u2022  {report.arch}  \u2022  Python {report.python}  \u2022  {'elevated' if report.is_admin else 'unprivileged'}"
        )

        for check in report.permissions:
            PermissionRow(self.scroll.inner, check).pack(fill="x", pady=3)

        if report.notes:
            self.notes_label.configure(text="   ".join("\u2022 " + n for n in report.notes[:3]))
        else:
            self.notes_label.configure(text="")

        blocking = [c for c in report.permissions if c.required and not c.granted]
        optional_missing = [c for c in report.permissions if not c.required and not c.granted]

        if blocking:
            self.subtitle.configure(
                text=f"{len(blocking)} required permission{'s' if len(blocking) != 1 else ''} missing"
            )
            self.status.configure(
                text="Fix the items marked \u2717, then press Re-check. You can also restart NetWatch with elevation.",
                fg=theme.VERDICT_COLORS["suspicious"],
            )
            self.start_button.configure(state="disabled")
        else:
            self.subtitle.configure(
                text="Ready to monitor \u2014 all required permissions granted"
            )
            detail = "Monitoring will cover your own sockets."
            if report.is_admin:
                detail = "Monitoring will cover every process on this machine."
            if optional_missing:
                detail += "  Optional technique(s) unavailable: " + ", ".join(
                    c.title.lower() for c in optional_missing
                )
            self.status.configure(text=detail, fg=theme.VERDICT_COLORS["safe"])
            self.start_button.configure(state="normal")

    def _start(self) -> None:
        if self.report and self.report.ready:
            self.on_start(self.report)
