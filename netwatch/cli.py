"""Command-line interface for NetWatch.

Two modes:

* ``netwatch``                - one-shot scan, human-readable table.
* ``netwatch --watch 5``      - refresh every 5 seconds until Ctrl-C.
* ``netwatch --json out.json``- machine-readable export.
* ``netwatch --check``        - print the permission report and exit.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List, Optional

from . import __version__
from . import platform as plat
from .analysis.engine import AnalysisEngine
from .collectors import CollectorError, collect_connections
from .models import Connection, ScanSummary

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

VERDICT_COLOR = {
    "safe": "\033[92m",
    "secure": "\033[92m",
    "unknown": "\033[90m",
    "suspicious": "\033[93m",
    "malicious": "\033[91m",
}


def _color(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def _short(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    return text[: width - 1] + "\u2026"


def print_table(connections: List[Connection], color: bool = True) -> None:
    header = (
        f"{'VERDICT':<11} {'DIR':<9} {'APPLICATION':<24} {'PROTO':<5} "
        f"{'REMOTE':<34} {'FINDINGS'}"
    )
    print(_color(header, BOLD, color))
    print(_color("-" * len(header), DIM, color))
    for conn in connections:
        verdict = conn.verdict.value
        findings = ", ".join(f.code for f in sorted(conn.flags, key=lambda f: -f.severity))
        line = (
            f"{verdict.upper():<11} {conn.direction:<9} "
            f"{_short(conn.process.name or 'unknown', 24)} "
            f"{conn.proto.upper():<5} {_short(conn.remote.pretty, 34)} {findings}"
        )
        print(_color(line, VERDICT_COLOR.get(verdict, ""), color))


def print_summary(summary: ScanSummary, color: bool = True) -> None:
    parts = [
        f"{summary.total} sockets",
        f"{summary.outbound} outbound",
        f"{summary.inbound} inbound",
        f"{summary.listening} listening",
        f"{summary.applications} apps",
    ]
    print()
    print(_color("  ".join(parts), BOLD, color))
    risk = (
        f"{summary.suspicious} suspicious, {summary.malicious} malicious"
        if (summary.suspicious or summary.malicious)
        else "no risky connections found"
    )
    tint = VERDICT_COLOR["malicious"] if summary.malicious else (
        VERDICT_COLOR["suspicious"] if summary.suspicious else VERDICT_COLOR["safe"]
    )
    print(_color(risk, tint, color))


def scan(engine: AnalysisEngine) -> tuple:
    raw = collect_connections()
    return engine.analyze_with_summary(raw)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="Live network connection monitor with security grading.",
    )
    parser.add_argument("--version", action="version", version=f"netwatch {__version__}")
    parser.add_argument(
        "--check", action="store_true", help="print the permission report and exit"
    )
    parser.add_argument(
        "--json", metavar="PATH", help="write the scan result as JSON to PATH"
    )
    parser.add_argument(
        "--watch",
        type=float,
        metavar="SECONDS",
        help="refresh continuously at this interval (Ctrl-C to stop)",
    )
    parser.add_argument(
        "--no-deep", action="store_true", help="skip DNS reverse lookups and TLS probes"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI colours"
    )
    parser.add_argument(
        "--only-risky", action="store_true", help="hide connections with no findings"
    )
    args = parser.parse_args(argv)

    color = not args.no_color and sys.stdout.isatty()

    if args.check:
        report = plat.evaluate()
        print(plat.requirements_text(report))
        print()
        print("Ready to monitor:", "yes" if report.ready else "NO (required permission missing)")
        return 0 if report.ready else 2

    engine = AnalysisEngine(deep=not args.no_deep)

    try:
        if not args.watch:
            analyzed, summary = scan(engine)
            shown = [c for c in analyzed if c.severity_score > 0] if args.only_risky else analyzed
            if color:
                print(f"{BOLD}NetWatch {__version__}{RESET} \u2022 {plat.OS_LABEL} {plat.probe_os_version()}")
            else:
                print(f"NetWatch {__version__} - {plat.OS_LABEL} {plat.probe_os_version()}")
            print()
            print_table(shown, color)
            print_summary(summary, color)
            if args.json:
                _write_json(args.json, analyzed, summary)
                print(f"\nWrote {args.json}")
            return 0 if summary.malicious == 0 else 1

        # Watch mode: clear screen each pass.
        while True:
            analyzed, summary = scan(engine)
            shown = [c for c in analyzed if c.severity_score > 0] if args.only_risky else analyzed
            if color:
                print("\033[2J\033[H", end="")
            stamp = time.strftime("%H:%M:%S")
            print(f"NetWatch {__version__} \u2022 {stamp} \u2022 refreshing every {args.watch:g}s")
            print()
            print_table(shown, color)
            print_summary(summary, color)
            sys.stdout.flush()
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    except CollectorError as exc:
        print(f"netwatch: could not read this host's connections: {exc}", file=sys.stderr)
        return 3


def _write_json(path: str, analyzed: List[Connection], summary: ScanSummary) -> None:
    payload = {
        "tool": "netwatch",
        "version": __version__,
        "host": {
            "os": plat.OS_LABEL,
            "version": plat.probe_os_version(),
            "elevated": plat.is_admin(),
        },
        "summary": summary.__dict__,
        "connections": [c.to_dict() for c in analyzed],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
