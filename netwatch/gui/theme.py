"""Colours, fonts and small drawing helpers shared by the GUI."""

from __future__ import annotations

from ..models import Verdict

# -- palette -----------------------------------------------------------

BG = "#14161c"
BG_ALT = "#1a1d25"
BG_ROW = "#1f232d"
BG_ROW_ALT = "#191c24"
BG_SELECTED = "#2d3648"
FG = "#e6e9f0"
FG_DIM = "#8d94a6"
FG_FAINT = "#5d6478"
ACCENT = "#4c9ffe"
BORDER = "#2a2f3c"

VERDICT_COLORS = {
    Verdict.SAFE.value: "#3ecf8e",
    Verdict.SECURE.value: "#3ecf8e",
    Verdict.UNKNOWN.value: "#8d94a6",
    Verdict.SUSPICIOUS.value: "#f5a623",
    Verdict.MALICIOUS.value: "#ff5c5c",
}

VERDICT_LABELS = {
    Verdict.SAFE.value: "SAFE",
    Verdict.SECURE.value: "SECURE",
    Verdict.UNKNOWN.value: "UNKNOWN",
    Verdict.SUSPICIOUS.value: "SUSPICIOUS",
    Verdict.MALICIOUS.value: "MALICIOUS",
}

SEVERITY_COLORS = {
    1: "#7aa2f7",
    2: "#f5a623",
    3: "#ff5c5c",
}

DIRECTION_COLORS = {
    "inbound": "#c792ea",
    "outbound": "#4c9ffe",
    "listening": "#5d6478",
    "local": "#7fdbca",
}

# -- fonts -------------------------------------------------------------

FONT_UI = ("Helvetica Neue", 12)
FONT_UI_BOLD = ("Helvetica Neue", 12, "bold")
FONT_SMALL = ("Helvetica Neue", 11)
FONT_TINY = ("Helvetica Neue", 10)
FONT_TITLE = ("Helvetica Neue", 17, "bold")
FONT_MONO = ("Menlo", 11)


def verdict_color(verdict: str) -> str:
    return VERDICT_COLORS.get(verdict, FG_DIM)


def verdict_label(verdict: str) -> str:
    return VERDICT_LABELS.get(verdict, verdict.upper())


def direction_color(direction: str) -> str:
    return DIRECTION_COLORS.get(direction, FG_DIM)


def severity_color(severity: int) -> str:
    return SEVERITY_COLORS.get(severity, FG_DIM)
