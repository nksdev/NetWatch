# Detection reference

Every connection accumulates `Flag` objects. Each flag carries a severity, and
the worst flag decides the verdict.

| Severity | Verdict | Meaning |
|----------|--------------|------------------------------------------------------------|
| 1 | `UNKNOWN` | Noteworthy but inconclusive - never escalates on its own |
| 2 | `SUSPICIOUS` | Warrants a look |
| 3 | `MALICIOUS` | Matches known-bad infrastructure or behaviour |
| - | `SAFE` | Peer is a known good service and nothing else fired |

`Connection.severity_score` is the **maximum** flag severity, not the sum.

---

## T1 - Blocklist

Matches the peer name or IP against `data/blocklist.txt`. A hit is severity 3
(`BLOCKLIST`). Entries may be `host` or `host:port`.

## T2 - Allowlist

Matches against `data/allowlist.txt`. A hit does not clear other findings; it
suppresses the low-value noise flags (T6, T12) so a recognised vendor peer is
not reported as unknown. A connection with no other finding becomes `UNKNOWN`
with an `AUTHORIZED` flag.

## T3 - TLS inspection

Runs only on peers whose port is in `TLS_PORTS` (443, 993, 995, 465, 8443, ...)
and only when `deep=True`.

The probe runs twice:

1. **Verified pass.** A default context validates the chain and the hostname.
   Success yields `chain_trusted = True` and an A-F grade.
2. **Unverified pass.** If the verified pass fails, a second handshake captures
   the certificate for grading. The DER blob is decoded with
   `_test_decode_cert`, because `getpeercert()` returns `{}` on an unverified
   context.

Flags produced:

| Code | Severity | Trigger |
|------|----------|---------|
| `TLS_UNTRUSTED` | 2 (1 if PTR-derived) | Chain does not validate |
| `TLS_HOSTNAME_MISMATCH` | 2 (1 if PTR-derived) | Certificate does not cover the name |
| `TLS_SELF_SIGNED` | 2 | Issuer equals subject |
| `TLS_EXPIRED` | 2 | `not_after` in the past |
| `TLS_EXPIRING` | 1 | Fewer than 30 days left |
| `TLS_WEAK_PROTOCOL` | 2 | TLS 1.0/1.1, SSLv3, SSLv2 |
| `TLS_HANDSHAKE_FAILED` | 2 | Handshake error that is *not* inconclusive |
| `TLS_UNVERIFIED` | 1 | Inconclusive: refused, reset, wrong protocol, no SNI, PTR-only name |

### Inconclusive is not malicious

These outcomes mean "we learned nothing about the peer" and are severity 1:

- the peer requires SNI and answers with a placeholder certificate
  (`No SNI provided`, `invalid2.invalid`)
- `handshake failure`, `internal error`, `wrong version number`, `timed out`,
  `connection reset`, `unrecognized name`, `certificate required`, `EOF`
- the name used for the check came from reverse DNS rather than the application

Without that rule every CDN edge and every QUIC-only endpoint would make a
healthy machine look compromised.

## T4 - Plaintext protocol

A well-known plaintext service port (HTTP/80, FTP/21, Telnet/23, SMTP/25,
POP3/110, IMAP/143) carrying an external session produces `PLAINTEXT_PROTOCOL`,
severity 2. Credentials on those ports are readable by anyone on the path.

## T5 - Risky port

Matches the remote port against `data/risky_ports.txt`
(`port|severity|proto|description`). Covers SMB/445, RDP/3389, NetBIOS,
Metasploit/4444, Tor/9050, mining pools, and similar.

## T6 - Raw IP peer

An external peer addressed by literal IP with no name produces `RAW_IP`,
severity 1. It is a hygiene signal, not a verdict - lots of legitimate traffic
dials IPs directly.

## T7 - Suspicious TLD

Matches the registrable suffix against `data/suspicious_tlds.txt` (`.xyz`,
`.top`, `.tk`, ...). Produces `SUSPICIOUS_TLD`, severity 2.

## T8 - DGA shape

`reputation.looks_like_dga` flags a single label that is at least 16 characters
of lowercase alphanumerics. Hyphenated labels and known CDN shapes
(`lb-140-82-114-25-iad`) are rejected so CloudFront/GitHub/AWS names do not
false-positive. Produces `DGA_LIKE_DOMAIN`, severity 2.

## T9 - Risky process

Matches the process name against `data/risky_processes.txt`
(`substring|severity|reason`). Covers miners (`xmrig`), tunnellers, netcat,
and credential dumpers.

## T10 - Inbound exposure

An unsolicited inbound session from an external peer produces `INBOUND_EXTERNAL`,
severity 1. Suppressed for expected services.

## T11 - LAN exposure

A listening socket bound to a non-loopback address produces `LAN_EXPOSED`,
severity 1. Suppressed for expected services via `data/safe_services.txt`
(`substring|port|note`, `*` = any port). Without that suppression a healthy Mac
reports eleven findings for mDNS, AirDrop, and printer discovery.

## T12 - Unresolved peer

An external peer with no name, no allowlist match, and no other flag produces
`UNRESOLVED_PEER`, severity 1.

---

## Reputation data

All datasets are plain text under `netwatch/netwatch/data/`. Edit them directly;
no rebuild is needed.

| File | Format |
|------|--------|
| `allowlist.txt` | `host` or `host:port` |
| `blocklist.txt` | `host` or `host:port` |
| `suspicious_tlds.txt` | `tld` |
| `risky_ports.txt` | `port|severity|proto|description` |
| `risky_processes.txt` | `substring|severity|reason` |
| `safe_services.txt` | `substring|port|note` |

Lines beginning with `#` are comments. Blank lines are ignored. Keep additions
conservative: a wrong blocklist entry produces a false `MALICIOUS` verdict, and a
wrong allowlist entry hides real traffic. Structural heuristics (T6-T8, T12)
carry most of the detection load precisely because they cannot go stale.
