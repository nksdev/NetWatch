"""The main NetWatch window: dashboard, filters, live table, detail pane."""

from __future__ import annotations

import csv
import json
import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from .. import platform as plat
from ..analysis.engine import AnalysisEngine
from ..collectors import CollectorError, collect_connections
from ..models import Connection, PlatformReport, ScanSummary, Verdict
from . import theme
from .detail import DetailPane
from .gate import PermissionGate
from .table import ConnectionTable
from .widgets import StatChip

FILTERS = (
    ("all", "All connections"),
    ("risky", "Risky only"),
    ("malicious", "Malicious"),
    ("suspicious", "Suspicious"),
    ("external", "External peers"),
    ("inbound", "Inbound"),
    ("outbound", "Outbound"),
    ("listening", "Listening"),
    ("local", "Local"),
)


class NetWatchApp(tk.Tk):
    """Tk root window that swaps between the permission gate and the dashboard."""

    def __init__(self) -> None:
        super().__init__()
        self.title("NetWatch \u2014 live connection monitor")
        self.geometry("1360x820")
        self.minsize(1080, 640)
        self.configure(bg=theme.BG)

        self.report: Optional[PlatformReport] = None
        self.engine = AnalysisEngine(deep=True)
        self.connections: List[Connection] = []
        self.summary: Optional[ScanSummary] = None
        self._scanning = False
        self._stop = threading.Event()
        self._after_id: Optional[str] = None
        self._filter = "all"
        self._search = ""
        self._interval_ms = 4000

        self.container = tk.Frame(self, bg=theme.BG)
        self.container.pack(fill="both", expand=True)

        self.gate = PermissionGate(self.container, on_start=self.start_monitoring)
        self.gate.pack(fill="both", expand=True)
        self.dashboard: Optional[Dashboard] = None

        self.gate.run_checks()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- lifecycle -------------------------------------------------------

    def start_monitoring(self, report: PlatformReport) -> None:
        self.report = report
        self.gate.pack_forget()
        self.dashboard = Dashboard(self.container, self)
        self.dashboard.pack(fill="both", expand=True)
        self.dashboard.log(
            f"Monitoring started on {report.os_name} {report.os_version} "
            f"({'elevated' if report.is_admin else 'unprivileged'})."
        )
        self.schedule_scan(immediate=True)

    def schedule_scan(self, immediate: bool = False) -> None:
        if self._stop.is_set():
            return
        delay = 0 if immediate else self._interval_ms
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
        self._after_id = self.after(delay, self.run_scan)

    def run_scan(self) -> None:
        if self._scanning or self._stop.is_set():
            return
        self._scanning = True
        if self.dashboard:
            self.dashboard.set_scanning(True)

        # Tk is not thread safe, so the worker only fills this box and the
        # main thread polls it. Never call after() from the worker.
        box: dict = {}
        done = threading.Event()

        def work() -> None:
            try:
                raw = collect_connections()
                analyzed, summary = self.engine.analyze_with_summary(raw)
                box["analyzed"] = analyzed
                box["summary"] = summary
            except Exception as exc:  # pragma: no cover - defensive
                box["error"] = exc
            finally:
                done.set()

        def poll() -> None:
            if not done.is_set():
                self.after(50, poll)
                return
            self._apply(box.get("analyzed", []), box.get("summary"), box.get("error"))

        threading.Thread(target=work, daemon=True).start()
        self.after(50, poll)

    def _apply(self, analyzed: List[Connection], summary, error) -> None:
        self._scanning = False
        if self.dashboard:
            self.dashboard.set_scanning(False)
            if error is not None:
                self.dashboard.log(f"Scan failed: {error}")
            else:
                self.connections = analyzed
                self.summary = summary
                self.dashboard.update_connections(analyzed, summary)
        self.schedule_scan()

    def set_interval(self, ms: int) -> None:
        self._interval_ms = ms

    def _on_close(self) -> None:
        self._stop.set()
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
        self.destroy()

    # -- filtering -------------------------------------------------------

    def visible_connections(self) -> List[Connection]:
        result = []
        needle = self._search.strip().lower()
        for conn in self.connections:
            if self._filter == "risky" and conn.verdict.value not in ("suspicious", "malicious"):
                continue
            if self._filter in ("malicious", "suspicious") and conn.verdict.value != self._filter:
                continue
            if self._filter == "external" and conn.remote.scope != "external":
                continue
            if self._filter in ("inbound", "outbound", "listening", "local") and conn.direction != self._filter:
                continue
            if needle:
                haystack = " ".join(
                    (
                        conn.process.name or "",
                        conn.remote.hostname or "",
                        conn.remote.address,
                        conn.local.address,
                        " ".join(f.code for f in conn.flags),
                    )
                ).lower()
                if needle not in haystack:
                    continue
            result.append(conn)
        return result


class Dashboard(tk.Frame):
    """The monitoring view."""

    def __init__(self, master, app: NetWatchApp, **kwargs):
        super().__init__(master, bg=theme.BG, **kwargs)
        self.app = app

        # -- top bar
        top = tk.Frame(self, bg=theme.BG_ALT)
        top.pack(fill="x")
        tk.Label(
            top, text="NetWatch", bg=theme.BG_ALT, fg=theme.FG, font=theme.FONT_TITLE
        ).pack(side="left", padx=16, pady=10)
        self.host_label = tk.Label(
            top, text="", bg=theme.BG_ALT, fg=theme.FG_FAINT, font=theme.FONT_TINY
        )
        self.host_label.pack(side="left", padx=(0, 16))

        self.scan_label = tk.Label(
            top, text="", bg=theme.BG_ALT, fg=theme.FG_DIM, font=theme.FONT_TINY
        )
        self.scan_label.pack(side="right", padx=16)

        self.export_button = tk.Button(
            top,
            text="Export",
            command=self.export,
            bg=theme.BG_ROW,
            fg=theme.FG,
            activebackground=theme.BG_SELECTED,
            activeforeground=theme.FG,
            relief="flat",
            font=theme.FONT_SMALL,
            padx=14,
            pady=4,
        )
        self.export_button.pack(side="right", padx=(0, 12), pady=8)

        self.interval = tk.StringVar(value="4s")
        interval_box = ttk.Combobox(
            top,
            textvariable=self.interval,
            values=("2s", "4s", "10s", "30s"),
            width=5,
            state="readonly",
        )
        interval_box.pack(side="right", padx=(0, 8))
        interval_box.bind("<<ComboboxSelected>>", self._on_interval)
        tk.Label(
            top, text="refresh", bg=theme.BG_ALT, fg=theme.FG_FAINT, font=theme.FONT_TINY
        ).pack(side="right", padx=(0, 4))

        # -- stat chips
        strip = tk.Frame(self, bg=theme.BG_ALT)
        strip.pack(fill="x", padx=10, pady=(0, 8))
        self.chips = {
            "total": StatChip(strip, "connections", theme.FG),
            "outbound": StatChip(strip, "outbound", theme.DIRECTION_COLORS["outbound"]),
            "inbound": StatChip(strip, "inbound", theme.DIRECTION_COLORS["inbound"]),
            "listening": StatChip(strip, "listening", theme.FG_DIM),
            "secure": StatChip(strip, "secure", theme.VERDICT_COLORS["secure"]),
            "suspicious": StatChip(strip, "suspicious", theme.VERDICT_COLORS["suspicious"]),
            "malicious": StatChip(strip, "malicious", theme.VERDICT_COLORS["malicious"]),
            "apps": StatChip(strip, "apps", theme.ACCENT),
        }
        for chip in self.chips.values():
            chip.pack(side="left", padx=(0, 6))

        # -- filter bar
        bar = tk.Frame(self, bg=theme.BG)
        bar.pack(fill="x", padx=14, pady=(4, 6))
        self.filter_var = tk.StringVar(value="all")
        for key, label in FILTERS:
            tk.Radiobutton(
                bar,
                text=label,
                value=key,
                variable=self.filter_var,
                command=self.refresh_table,
                bg=theme.BG,
                fg=theme.FG_DIM,
                selectcolor=theme.BG_ROW,
                activebackground=theme.BG,
                activeforeground=theme.FG,
                font=theme.FONT_TINY,
                indicatoron=False,
                padx=10,
                pady=3,
                bd=0,
            ).pack(side="left", padx=(0, 2))

        search = tk.Frame(bar, bg=theme.BG)
        search.pack(side="right")
        tk.Label(
            search, text="search", bg=theme.BG, fg=theme.FG_FAINT, font=theme.FONT_TINY
        ).pack(side="left", padx=(0, 4))
        self.search_var = tk.StringVar()
        entry = tk.Entry(
            search,
            textvariable=self.search_var,
            bg=theme.BG_ROW,
            fg=theme.FG,
            insertbackground=theme.FG,
            relief="flat",
            font=theme.FONT_SMALL,
            width=24,
        )
        entry.pack(side="left", ipady=3)
        self.search_var.trace_add("write", lambda *_: self.refresh_table())

        # -- split: table | detail
        body = tk.PanedWindow(
            self,
            orient="horizontal",
            bg=theme.BORDER,
            sashwidth=4,
            sashrelief="flat",
            bd=0,
        )
        body.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        table_wrap = tk.Frame(body, bg=theme.BG)
        self.table = ConnectionTable(table_wrap, on_select=self._on_select)
        self.table.pack(fill="both", expand=True)
        body.add(table_wrap, minsize=520, stretch="always")

        self.detail = DetailPane(body)
        body.add(self.detail, minsize=380, stretch="never")

        # -- status bar
        bottom = tk.Frame(self, bg=theme.BG_ALT)
        bottom.pack(fill="x")
        self.status = tk.Label(
            bottom,
            text="Waiting for first scan\u2026",
            bg=theme.BG_ALT,
            fg=theme.FG_FAINT,
            font=theme.FONT_TINY,
            anchor="w",
        )
        self.status.pack(side="left", padx=12, pady=5)

    # -- updates ---------------------------------------------------------

    def update_connections(self, connections: List[Connection], summary: ScanSummary) -> None:
        if self.app.report:
            self.host_label.configure(
                text=f"{self.app.report.os_name} {self.app.report.os_version} "
                f"\u2022 {'elevated' if self.app.report.is_admin else 'unprivileged'}"
            )
        self.chips["total"].set(summary.total)
        self.chips["outbound"].set(summary.outbound)
        self.chips["inbound"].set(summary.inbound)
        self.chips["listening"].set(summary.listening)
        self.chips["secure"].set(summary.secure + summary.safe)
        self.chips["suspicious"].set(summary.suspicious)
        self.chips["malicious"].set(summary.malicious)
        self.chips["apps"].set(summary.applications)
        self.refresh_table()
        self.scan_label.configure(text=f"updated {time.strftime('%H:%M:%S')}")
        self.status.configure(
            text=f"{summary.total} sockets \u2022 {summary.applications} applications \u2022 "
            f"{summary.suspicious} suspicious \u2022 {summary.malicious} malicious"
        )

    def refresh_table(self) -> None:
        self.app._filter = self.filter_var.get()
        self.app._search = self.search_var.get()
        visible = self.app.visible_connections()
        self.table.set_connections(visible)
        current = self.detail._conn
        if current is not None:
            self.detail.show(current)

    def set_scanning(self, scanning: bool) -> None:
        if scanning:
            self.scan_label.configure(text="scanning\u2026", fg=theme.ACCENT)
        else:
            self.scan_label.configure(fg=theme.FG_DIM)

    def log(self, message: str) -> None:
        self.status.configure(text=message)

    def _on_select(self, conn: Optional[Connection]) -> None:
        self.detail.show(conn)

    def _on_interval(self, _event=None) -> None:
        value = self.interval.get().rstrip("s")
        try:
            self.app.set_interval(int(float(value) * 1000))
        except ValueError:
            pass

    # -- export ----------------------------------------------------------

    def export(self) -> None:
        connections = self.app.visible_connections()
        if not connections:
            messagebox.showinfo("NetWatch", "There is nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export scan results",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")],
            initialfile=f"netwatch-{time.strftime('%Y%m%d-%H%M%S')}.json",
        )
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                with open(path, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(
                        ["verdict", "direction", "application", "pid", "proto", "local", "remote", "state", "findings"]
                    )
                    for conn in connections:
                        writer.writerow(
                            [
                                conn.verdict.value,
                                conn.direction,
                                conn.process.name,
                                conn.process.pid,
                                conn.proto,
                                f"{conn.local.address}:{conn.local.port}",
                                conn.remote.pretty,
                                conn.state,
                                "; ".join(f.code for f in conn.flags),
                            ]
                        )
            else:
                payload = {
                    "host": {
                        "os": self.app.report.os_name if self.app.report else "",
                        "version": self.app.report.os_version if self.app.report else "",
                        "elevated": bool(self.app.report and self.app.report.is_admin),
                    },
                    "summary": self.app.summary.__dict__ if self.app.summary else {},
                    "connections": [conn.to_dict() for conn in connections],
                }
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2)
            self.status.configure(text=f"Exported {len(connections)} connections to {os.path.basename(path)}")
        except OSError as exc:
            messagebox.showerror("NetWatch", f"Could not write the file:\n{exc}")


def main() -> int:
    """Entry point used by ``netwatch-gui`` and ``python -m netwatch.gui``."""

    app = NetWatchApp()
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
