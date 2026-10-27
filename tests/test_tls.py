"""Tests for the TLS grader: hostname matching, grading rules, DER decoding."""

from __future__ import annotations

import unittest

from netwatch.analysis.tls import (
    TLS_PORTS,
    TLSResult,
    _dnsname_match,
    _grade,
    _hostname_matches,
)


GITHUB_CERT = {
    "subject": ((('commonName', '*.github.com'),),),
    "subjectAltName": (("DNS", "*.github.com"), ("DNS", "github.com")),
}

GOOGLE_CERT = {
    "subject": ((('commonName', 'imap.gmail.com'),),),
    "subjectAltName": (("DNS", "imap.gmail.com"),),
}


class TestWildcardMatch(unittest.TestCase):
    def test_exact(self) -> None:
        self.assertTrue(_dnsname_match("github.com", "github.com"))

    def test_single_label_wildcard(self) -> None:
        self.assertTrue(_dnsname_match("*.github.com", "api.github.com"))

    def test_wildcard_never_covers_bare_domain(self) -> None:
        self.assertFalse(_dnsname_match("*.github.com", "github.com"))

    def test_wildcard_never_covers_two_labels(self) -> None:
        self.assertFalse(_dnsname_match("*.github.com", "a.b.github.com"))

    def test_suffix_confusion_rejected(self) -> None:
        self.assertFalse(_dnsname_match("*.github.com", "evilgithub.com"))
        self.assertFalse(_dnsname_match("*.github.com", "github.com.evil.net"))

    def test_case_insensitive(self) -> None:
        self.assertTrue(_dnsname_match("*.GitHub.com", "API.github.COM"))


class TestHostnameMatches(unittest.TestCase):
    def test_san_used_first(self) -> None:
        self.assertTrue(_hostname_matches("api.github.com", GITHUB_CERT))

    def test_literal_san(self) -> None:
        self.assertTrue(_hostname_matches("imap.gmail.com", GOOGLE_CERT))

    def test_cn_fallback_without_san(self) -> None:
        cert = {"subject": ((('commonName', 'legacy.example.com'),),)}
        self.assertTrue(_hostname_matches("legacy.example.com", cert))

    def test_wildcard_covers_cdn_label(self) -> None:
        """A single-label CDN name is covered by the *.github.com wildcard."""

        self.assertTrue(_hostname_matches("lb-140-82-114-25-iad.github.com", GITHUB_CERT))

    def test_empty_cert_never_matches(self) -> None:
        self.assertFalse(_hostname_matches("github.com", {}))

    def test_empty_host_never_matches(self) -> None:
        self.assertFalse(_hostname_matches("", GITHUB_CERT))

    def test_malformed_subject_is_tolerated(self) -> None:
        cert = {"subject": ((('commonName',),),)}
        self.assertFalse(_hostname_matches("x.com", cert))


class TestGrading(unittest.TestCase):
    def make(self, **kwargs) -> TLSResult:
        return TLSResult(**kwargs)

    def test_failed_handshake_is_f(self) -> None:
        self.assertEqual(_grade(self.make(ok=False)), "F")

    def test_untrusted_chain_is_f(self) -> None:
        self.assertEqual(_grade(self.make(ok=True, chain_trusted=False)), "F")

    def test_expired_is_f(self) -> None:
        self.assertEqual(_grade(self.make(ok=True, chain_trusted=True, expired=True)), "F")

    def test_hostname_mismatch_is_d(self) -> None:
        result = self.make(ok=True, chain_trusted=True, hostname_match=False)
        self.assertEqual(_grade(result), "D")

    def test_weak_protocol_is_c(self) -> None:
        result = self.make(
            ok=True, chain_trusted=True, hostname_match=True, weak_protocol=True
        )
        self.assertEqual(_grade(result), "C")

    def test_expiring_soon_is_b(self) -> None:
        result = self.make(
            ok=True, chain_trusted=True, hostname_match=True, expiring_soon=True
        )
        self.assertEqual(_grade(result), "B")

    def test_clean_cert_is_a(self) -> None:
        result = self.make(ok=True, chain_trusted=True, hostname_match=True)
        self.assertEqual(_grade(result), "A")


class TestPorts(unittest.TestCase):
    def test_common_tls_ports_present(self) -> None:
        for port in (443, 993, 995, 465, 8443):
            self.assertIn(port, TLS_PORTS)

    def test_plain_http_not_included(self) -> None:
        self.assertNotIn(80, TLS_PORTS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
