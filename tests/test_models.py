"""Tests for the data model: verdict ranking, endpoint handling, flag severity."""

from __future__ import annotations

import unittest

from netwatch.models import (
    SEVERITY_TO_VERDICT,
    Connection,
    Endpoint,
    Flag,
    ProcessInfo,
    ScanSummary,
    Verdict,
)


def make_conn(**kwargs) -> Connection:
    defaults = dict(
        proto="tcp",
        local=Endpoint(address="192.168.1.5", port=51000, scope="lan"),
        remote=Endpoint(address="93.184.216.34", port=443, scope="external"),
        state="ESTABLISHED",
        direction="outbound",
        process=ProcessInfo(pid=99, name="curl", exe="/usr/bin/curl"),
    )
    defaults.update(kwargs)
    return Connection(**defaults)


class TestVerdict(unittest.TestCase):
    def test_rank_is_ordered(self) -> None:
        self.assertLess(Verdict.SAFE.rank, Verdict.UNKNOWN.rank)
        self.assertLess(Verdict.UNKNOWN.rank, Verdict.SUSPICIOUS.rank)
        self.assertLess(Verdict.SUSPICIOUS.rank, Verdict.MALICIOUS.rank)

    def test_severity_one_never_escalates(self) -> None:
        """An informational finding must leave the verdict at UNKNOWN."""

        self.assertEqual(SEVERITY_TO_VERDICT[1], Verdict.UNKNOWN)
        flags = [Flag(code="RAW_IP", message="raw", severity=1)]
        self.assertEqual(Verdict.from_flags(flags), Verdict.UNKNOWN)

    def test_severity_two_is_suspicious(self) -> None:
        flags = [Flag(code="SUSPICIOUS_TLD", message="tld", severity=2)]
        self.assertEqual(Verdict.from_flags(flags), Verdict.SUSPICIOUS)

    def test_worst_flag_wins(self) -> None:
        flags = [
            Flag(code="RAW_IP", message="raw", severity=1),
            Flag(code="BLOCKLIST", message="blocked", severity=3),
        ]
        self.assertEqual(Verdict.from_flags(flags), Verdict.MALICIOUS)

    def test_no_flags_is_unknown(self) -> None:
        self.assertEqual(Verdict.from_flags([]), Verdict.UNKNOWN)


class TestEndpoint(unittest.TestCase):
    def test_ip_strips_zone_id(self) -> None:
        self.assertEqual(Endpoint(address="fe80::1%en0").ip, "fe80::1")

    def test_pretty_includes_hostname(self) -> None:
        ep = Endpoint(address="1.2.3.4", port=443, hostname="example.com")
        self.assertEqual(ep.pretty, "example.com:443")

    def test_pretty_falls_back_to_ip(self) -> None:
        ep = Endpoint(address="1.2.3.4", port=443)
        self.assertEqual(ep.pretty, "1.2.3.4:443")

    def test_private_detection(self) -> None:
        self.assertTrue(Endpoint(address="192.168.1.1").is_private())
        self.assertTrue(Endpoint(address="10.0.0.5").is_private())
        self.assertFalse(Endpoint(address="93.184.216.34").is_private())


class TestConnection(unittest.TestCase):
    def test_key_is_stable(self) -> None:
        a = make_conn()
        b = make_conn()
        self.assertEqual(a.key, b.key)

    def test_key_differs_by_remote(self) -> None:
        a = make_conn()
        b = make_conn(remote=Endpoint(address="1.1.1.1", port=443, scope="external"))
        self.assertNotEqual(a.key, b.key)

    def test_severity_score_is_max(self) -> None:
        conn = make_conn()
        conn.flags = [
            Flag(code="A", message="a", severity=1),
            Flag(code="B", message="b", severity=3),
            Flag(code="C", message="c", severity=2),
        ]
        self.assertEqual(conn.severity_score, 3)

    def test_add_flag_updates_verdict(self) -> None:
        conn = make_conn()
        conn.flags = []
        self.assertEqual(conn.verdict, Verdict.UNKNOWN)
        conn.add_flag(Flag(code="BLOCKLIST", message="bad", severity=3))
        self.assertEqual(conn.verdict, Verdict.MALICIOUS)

    def test_to_dict_is_serialisable(self) -> None:
        import json

        conn = make_conn()
        conn.flags = [Flag(code="RAW_IP", message="raw", severity=1)]
        payload = conn.to_dict()
        text = json.dumps(payload, default=str)
        self.assertIn("RAW_IP", text)
        self.assertEqual(payload["verdict"], "unknown")


class TestProcessInfo(unittest.TestCase):
    def test_display_prefers_name(self) -> None:
        self.assertEqual(ProcessInfo(pid=1, name="launchd").display, "launchd")

    def test_display_falls_back_to_pid(self) -> None:
        self.assertIn("42", ProcessInfo(pid=42).display)


class TestSummary(unittest.TestCase):
    def test_counts_directions_and_verdicts(self) -> None:
        out = make_conn()
        listen = make_conn(
            direction="listening",
            remote=Endpoint(address="*", port=0, scope="any"),
        )
        bad = make_conn()
        bad.flags = [Flag(code="BLOCKLIST", message="bad", severity=3)]
        summary = ScanSummary.from_connections([out, listen, bad])
        self.assertEqual(summary.total, 3)
        self.assertEqual(summary.outbound, 2)
        self.assertEqual(summary.listening, 1)
        self.assertEqual(summary.malicious, 1)
        self.assertEqual(summary.applications, 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
