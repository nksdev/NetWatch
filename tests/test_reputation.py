"""Tests for reputation data loading and structural hostname heuristics."""

from __future__ import annotations

import unittest

from netwatch.analysis.reputation import (
    ReputationData,
    looks_like_dga,
    load,
    reputation,
)


class TestDGAHeuristic(unittest.TestCase):
    def test_detects_random_label(self) -> None:
        self.assertTrue(looks_like_dga("a8f7g9h2k4l6m1n3p5q7.com"))
        self.assertTrue(looks_like_dga("k3j4h5g6f7d8s9a0q1w2.net"))

    def test_rejects_hyphenated_cdn_names(self) -> None:
        """CDN and cloud hostnames are long and digit-heavy but legitimate."""

        self.assertFalse(looks_like_dga("lb-140-82-114-25-iad.github.com"))
        self.assertFalse(looks_like_dga("ec2-52-32-205-191.us-west-2.compute.amazonaws.com"))
        self.assertFalse(looks_like_dga("ip-10-0-1-25.ec2.internal"))

    def test_rejects_normal_names(self) -> None:
        self.assertFalse(looks_like_dga("google.com"))
        self.assertFalse(looks_like_dga("mail.example.co.uk"))
        self.assertFalse(looks_like_dga("www.github.com"))

    def test_handles_empty_and_single_label(self) -> None:
        self.assertFalse(looks_like_dga(""))
        self.assertFalse(looks_like_dga("localhost"))


class TestBundledData(unittest.TestCase):
    def test_data_loads(self) -> None:
        data = load()
        self.assertIsInstance(data, ReputationData)
        self.assertGreater(len(data.allowlist), 10)
        self.assertGreater(len(data.blocklist), 10)
        self.assertGreater(len(data.suspicious_tlds), 5)
        self.assertGreater(len(data.risky_ports), 5)
        self.assertGreater(len(data.risky_processes), 5)
        self.assertGreater(len(data.safe_services), 5)

    def test_singleton_is_cached(self) -> None:
        self.assertIs(reputation(), reputation())

    def test_blocklist_match(self) -> None:
        data = load()
        self.assertIsNotNone(data.match_block("trickbot.com", 443))
        self.assertIsNone(data.match_block("github.com", 443))

    def test_allowlist_match(self) -> None:
        data = load()
        self.assertIsNotNone(data.match_allow("www.google.com", 443))
        self.assertIsNone(data.match_allow("totally-unknown-host.example", 443))

    def test_risky_port_lookup(self) -> None:
        data = load()
        self.assertIsNotNone(data.risky_port(445))
        self.assertIsNotNone(data.risky_port(4444))
        self.assertIsNone(data.risky_port(443))

    def test_risky_process_lookup(self) -> None:
        data = load()
        self.assertIsNotNone(data.risky_process("xmrig"))
        self.assertIsNotNone(data.risky_process("/usr/bin/ncat"))
        self.assertIsNone(data.risky_process("Google Chrome"))

    def test_safe_service_lookup(self) -> None:
        data = load()
        self.assertIsNotNone(data.safe_service("rapportd", 0))
        self.assertIsNotNone(data.safe_service("mDNSResponder", 5353))
        self.assertIsNone(data.safe_service("totally-unknown-daemon", 12345))


class TestSuspiciousTLD(unittest.TestCase):
    def test_flags_known_bad_tld(self) -> None:
        data = load()
        self.assertIsNotNone(data.suspicious_tld("evil-c2.xyz"))
        self.assertIsNotNone(data.suspicious_tld("payload.top"))

    def test_ignores_good_tld(self) -> None:
        data = load()
        self.assertIsNone(data.suspicious_tld("www.google.com"))
        self.assertIsNone(data.suspicious_tld("github.com"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
