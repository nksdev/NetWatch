"""Small reusable Tk widgets: verdict badge, scrollable table, status bar."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional, Sequence

from . import theme


class Badge(tk.Label):
    """A rounded-looking coloured pill showing a verdict or severity."""

    def __init__(self, master, text: str = "", color: str = theme.FG_DIM, **kwargs):
        super().__init__(
            master,
            text=text,
            fg="#0d0f13",
            bg=color,
            font=theme.FONT_TINY,
            padx=7,
            pady=1,
            **kwargs,
        )

    def set(self, text: str, color: str) -> None:
        self.configure(text=text, bg=color)


class SectionHeader(tk.Frame):
    """A thin header strip with a title and optional right-hand text."""

    def __init__(self, master, title: str, **kwargs):
        super().__init__(master, bg=theme.BG_ALT, **kwargs)
        self.title = tk.Label(
            self,
            text=title.upper(),
            bg=theme.BG_ALT,
            fg=theme.FG_DIM,
            font=theme.FONT_TINY,
            anchor="w",
        )
        self.title.pack(side="left", padx=10, pady=5)
        self.right = tk.Label(
            self, text="", bg=theme.BG_ALT, fg=theme.FG_FAINT, font=theme.FONT_TINY, anchor="e"
        )
        self.right.pack(side="right", padx=10)

    def set_right(self, text: str) -> None:
        self.right.configure(text=text)


class KeyValueList(tk.Frame):
    """A two-column read-only property list."""

    def __init__(self, master, key_width: int = 108, **kwargs):
        super().__init__(master, bg=theme.BG, **kwargs)
        self.key_width = key_width
        self._rows = 0

    def clear(self) -> None:
        for child in self.winfo_children():
            child.destroy()
        self._rows = 0

    def add(self, key: str, value: str, color: Optional[str] = None, mono: bool = False) -> None:
        row = tk.Frame(self, bg=theme.BG)
        row.pack(fill="x", pady=1)
        tk.Label(
            row,
            text=key,
            bg=theme.BG,
            fg=theme.FG_FAINT,
            font=theme.FONT_SMALL,
            width=14,
            anchor="w",
        ).pack(side="left")
        tk.Label(
            row,
            text=value or "-",
            bg=theme.BG,
            fg=color or theme.FG,
            font=theme.FONT_MONO if mono else theme.FONT_SMALL,
            anchor="w",
            justify="left",
            wraplength=430,
        ).pack(side="left", fill="x", expand=True)
        self._rows += 1

    def add_wrapped(
        self,
        key: str,
        value: str,
        color: Optional[str] = None,
        mono: bool = False,
    ) -> None:
        row = tk.Frame(self, bg=theme.BG)
        row.pack(fill="x", pady=(2, 6))
        tk.Label(
            row,
            text=key,
            bg=theme.BG,
            fg=theme.FG_FAINT,
            font=theme.FONT_SMALL,
            width=14,
            anchor="nw",
        ).pack(side="left", anchor="n")
        tk.Label(
            row,
            text=value or "-",
            bg=theme.BG,
            fg=color or theme.FG,
            font=theme.FONT_MONO if mono else theme.FONT_SMALL,
            anchor="w",
            justify="left",
            wraplength=420,
        ).pack(side="left", fill="x", expand=True)
        self._rows += 1


class FlagList(tk.Frame):
    """Renders a list of Flag objects as coloured blocks with severity."""

    def __init__(self, master, **kwargs):
        super().__init__(master, bg=theme.BG, **kwargs)

    def clear(self) -> None:
        for child in self.winfo_children():
            child.destroy()

    def render(self, flags: Sequence) -> None:
        self.clear()
        if not flags:
            tk.Label(
                self,
                text="No findings - no technique flagged this connection.",
                bg=theme.BG,
                fg=theme.FG_FAINT,
                font=theme.FONT_SMALL,
                anchor="w",
            ).pack(fill="x", pady=4)
            return
        for flag in sorted(flags, key=lambda f: -f.severity):
            block = tk.Frame(self, bg=theme.BG_ALT, padx=8, pady=6)
            block.pack(fill="x", pady=3)
            top = tk.Frame(block, bg=theme.BG_ALT)
            top.pack(fill="x")
            Badge(top, flag.label, theme.severity_color(flag.severity)).pack(side="left")
            tk.Label(
                top,
                text=flag.code,
                bg=theme.BG_ALT,
                fg=theme.FG,
                font=theme.FONT_UI_BOLD,
                anchor="w",
            ).pack(side="left", padx=8)
            tk.Label(
                top,
                text=flag.category,
                bg=theme.BG_ALT,
                fg=theme.FG_FAINT,
                font=theme.FONT_TINY,
                anchor="e",
            ).pack(side="right")
            tk.Label(
                block,
                text=flag.message,
                bg=theme.BG_ALT,
                fg=theme.FG_DIM,
                font=theme.FONT_SMALL,
                anchor="w",
                justify="left",
                wraplength=420,
            ).pack(fill="x", pady=(3, 0))
            if flag.evidence:
                tk.Label(
                    block,
                    text=flag.evidence,
                    bg=theme.BG_ALT,
                    fg=theme.FG_FAINT,
                    font=theme.FONT_MONO,
                    anchor="w",
                    justify="left",
                    wraplength=420,
                ).pack(fill="x", pady=(2, 0))


class StatChip(tk.Frame):
    """A compact counter used in the dashboard strip."""

    def __init__(self, master, label: str, color: str = theme.FG, **kwargs):
        super().__init__(master, bg=theme.BG_ALT, padx=12, pady=6, **kwargs)
        self.value_label = tk.Label(
            self, text="0", bg=theme.BG_ALT, fg=color, font=theme.FONT_TITLE
        )
        self.value_label.pack(side="left")
        tk.Label(
            self, text=label, bg=theme.BG_ALT, fg=theme.FG_DIM, font=theme.FONT_TINY, anchor="w"
        ).pack(side="left", padx=(6, 0))

    def set(self, value: int) -> None:
        self.value_label.configure(text=str(value))


class PermissionRow(tk.Frame):
    """One row of the permission gate table."""

    def __init__(self, master, check, **kwargs):
        super().__init__(master, bg=theme.BG_ROW, padx=12, pady=9, **kwargs)
        if check.granted:
            mark, color = "\u2713", theme.VERDICT_COLORS["safe"]
        elif check.required:
            mark, color = "\u2717", theme.VERDICT_COLORS["malicious"]
        else:
            mark, color = "\u25cb", theme.VERDICT_COLORS["suspicious"]
        tk.Label(self, text=mark, bg=theme.BG_ROW, fg=color, font=("Helvetica Neue", 15, "bold")).pack(
            side="left", padx=(0, 10)
        )
        body = tk.Frame(self, bg=theme.BG_ROW)
        body.pack(side="left", fill="x", expand=True)
        title = check.title
        if not check.required:
            title += "  (optional)"
        tk.Label(
            body, text=title, bg=theme.BG_ROW, fg=theme.FG, font=theme.FONT_UI_BOLD, anchor="w"
        ).pack(fill="x")
        if check.detail:
            tk.Label(
                body,
                text=check.detail,
                bg=theme.BG_ROW,
                fg=theme.FG_DIM,
                font=theme.FONT_SMALL,
                anchor="w",
                justify="left",
                wraplength=560,
            ).pack(fill="x")
        if not check.granted and check.remediation:
            tk.Label(
                body,
                text="\u2192 " + check.remediation,
                bg=theme.BG_ROW,
                fg=theme.VERDICT_COLORS["suspicious"],
                font=theme.FONT_SMALL,
                anchor="w",
                justify="left",
                wraplength=560,
            ).pack(fill="x")


class ScrollFrame(tk.Frame):
    """A vertically scrollable frame."""

    def __init__(self, master, **kwargs):
        super().__init__(master, bg=theme.BG, **kwargs)
        self.canvas = tk.Canvas(self, bg=theme.BG, highlightthickness=0, bd=0)
        self.scroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scroll.set)
        self.scroll.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=theme.BG)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", self._on_inner)
        self.canvas.bind("<Configure>", self._on_canvas)

    def _on_inner(self, _event=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)
