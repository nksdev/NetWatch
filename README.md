# NetWatch

Cross-platform live network connection monitor with security grading and malware flagging.

NetWatch shows every connection on your machine - outbound, inbound, and listening - names
the application behind it, and tells you whether the peer is trustworthy.

```
VERDICT     DIR       APPLICATION               PROTO  REMOTE                                  FINDINGS
----------------------------------------------------------------------------------------------------
UNKNOWN     outbound  Google Chrome Helper      TCP    lb-140-82-113-25-iad.github.com:443     AUTHORIZED
SUSPICIOUS  outbound  ncat                      TCP    198.51.100.7:4444                       RISKY_PORT, RAW_IP, RISKY_PROCESS
MALICIOUS   outbound  svchost.exe               TCP    trickbot-c2.com:443                     BLOCKLIST
UNKNOWN     listening rapportd                  TCP    *:50284
```

## What it does

- Enumerates every socket on the host - outbound, inbound, and listening - with the owning
  process, PID, executable path, byte counters, and state.
- Names the application behind each connection, so a row is never just an IP.
- Grades each peer with twelve layered checks and a single verdict.
- Flags malicious infrastructure by blocklist, suspicious TLD, DGA shape, risky port, and
  risky process name.
- Checks TLS properly - chain trust, hostname match, expiry, protocol version - and reports
  an A-F grade per peer.
- Tells you what it needs on first launch, per platform, before it starts.

Works on macOS, Linux, and Windows. No mandatory third-party dependencies.

## Install

```bash
cd netwatch
python3 -m pip install -e .
```

No dependencies are required. Two optional extras improve coverage:

| Package  | What it adds                                              | Platform |
|----------|-----------------------------------------------------------|----------|
| `psutil` | Socket enumeration when `netstat` output is hard to parse | Windows  |
| `scapy`  | Packet-level capture                                      | All      |

```bash
python3 -m pip install psutil   # optional, Windows
python3 -m pip install scapy    # optional, deep packet inspection
```

## Run

```bash
netwatch-gui            # graphical dashboard
netwatch                # one-shot text report
netwatch --watch 5      # refresh every 5 seconds
netwatch --check        # permission report only
netwatch --json out.json
```

Without installation:

```bash
python3 -m netwatch        # GUI
python3 -m netwatch --cli  # text report
```

### CLI options

| Flag              | Meaning                                                                   |
|-------------------|---------------------------------------------------------------------------|
| `--check`         | Print the permission report and exit (0 = ready, 2 = missing requirement)  |
| `--json PATH`     | Also write the full result as JSON                                        |
| `--watch SECONDS` | Refresh continuously until Ctrl-C                                         |
| `--no-deep`       | Skip reverse DNS and TLS probing (fast, offline)                          |
| `--only-risky`    | Hide connections with no findings                                         |
| `--no-color`      | Disable ANSI colours                                                      |

Exit codes: `0` clean, `1` malicious connection found, `2` permission problem,
`3` the host's socket table could not be read.

### GUI

On launch the dashboard shows a pre-flight permission report. Once every required check
passes, **Start monitoring** opens the main view:

- Eight counters (total, outbound, inbound, listening, secure, suspicious, malicious, apps).
- Nine one-click filters and a live search box.
- Sortable table with colour-coded verdicts.
- Detail pane: connection, peer, transport security, and the full findings list.
- **Export** writes the current view as JSON or CSV.

## How a verdict is reached

Each connection accumulates findings. Every finding has a severity, and the worst finding
decides the verdict.

| Severity | Verdict      | Meaning                                                    |
|----------|--------------|------------------------------------------------------------|
| 1        | `UNKNOWN`    | Noteworthy but inconclusive - never escalates on its own    |
| 2        | `SUSPICIOUS` | Warrants a look                                            |
| 3        | `MALICIOUS`  | Matches known-bad infrastructure or behaviour              |
| -        | `SAFE`       | Peer is a known good service and nothing else fired        |

Severity 1 deliberately cannot escalate. Without that rule every raw IP and every
inconclusive TLS handshake would make the machine look compromised.

### Detection techniques

| #   | Technique          | What it catches                                                 |
|-----|--------------------|-----------------------------------------------------------------|
| T1  | Blocklist          | Known C2 domains, malware hosts, hostile IPs                    |
| T2  | Allowlist          | Recognised vendors - suppresses noise from trusted peers         |
| T3  | TLS inspection     | Untrusted chains, hostname mismatch, expiry, obsolete protocols  |
| T4  | Plaintext protocol | Credentials sent over HTTP, FTP, Telnet, SMTP                   |
| T5  | Risky port         | SMB, RDP, Metasploit, Tor, mining pools                         |
| T6  | Raw IP peer        | Direct-to-IP traffic that bypasses DNS                          |
| T7  | Suspicious TLD     | `.xyz`, `.top`, `.tk`, and similar abuse-heavy zones              |
| T8  | DGA shape          | Machine-generated domain names                                  |
| T9  | Risky process      | Miners, tunnellers, netcat, credential dumpers                  |
| T10 | Inbound exposure   | Unsolicited inbound sessions                                    |
| T11 | LAN exposure       | Services listening on non-loopback interfaces                   |
| T12 | Unresolved peer    | External peer with no name and no reputation                    |

T10 and T11 are suppressed for expected system services (mDNS, AirDrop, printers, DHCP,
and so on) so a healthy machine does not report eleven findings.

TLS results derived from a reverse-DNS name rather than the name the application actually
requested are reported as inconclusive, because judging a certificate against a PTR name
produces false alarms on CDN and shared-hosting infrastructure.

### Reputation data

All datasets are plain text under `netwatch/netwatch/data/` and can be edited directly -
no rebuild needed.

| File                  | Format                              | Purpose                             |
|-----------------------|-------------------------------------|-------------------------------------|
| `allowlist.txt`       | `host` or `host:port`               | Trusted vendors                     |
| `blocklist.txt`       | `host` or `host:port`               | Known-bad infrastructure            |
| `suspicious_tlds.txt` | `tld`                               | Abuse-heavy zones                   |
| `risky_ports.txt`     | `port|severity|proto|description`   | Dangerous services                  |
| `risky_processes.txt` | `substring|severity|reason`         | Dangerous tools                     |
| `safe_services.txt`   | `substring|port|note`               | Expected listeners (`*` = any port) |

Lines starting with `#` are comments. Severity is `1`, `2`, or `3`.

## Permissions

NetWatch checks permissions at launch and reports exactly what it can and cannot see.
Nothing is requested silently, and nothing is required beyond reading the socket table.

```bash
netwatch --check
```

```
Host      : macos 27.0.1 (arm64)
Python    : 3.14.5
Elevated  : no

Permissions:
  [OK  ] Socket / connection table access - lsof readable for user namanmic
  [OK  ] Application / process identification - lsof can resolve pid -> executable
  [OK  ] DNS resolution - outbound DNS/53 or system resolver reachable
  [OK  ] TLS certificate inspection - TLS handshake successful
  [OPT ] Packet capture (deep inspection) - scapy not installed

Ready to monitor: yes
```

Per-platform setup is in [`docs/permissions.md`](docs/permissions.md).

## Architecture

```
netwatch/
  platform.py        OS detection, permission probing
  models.py          Connection, Endpoint, Flag, Verdict, ScanSummary
  collectors/
    macos.py         lsof -F + netstat -anv
    linux.py         /proc/net/* + /proc/<pid>/fd
    windows.py       psutil or netstat -ano + tasklist
  analysis/
    engine.py        the T1-T12 pipeline
    reputation.py    datasets, DGA heuristic, allow/block matching
    dns.py           reverse DNS with cache
    tls.py           certificate probing and A-F grading
  gui/               Tk dashboard, permission gate, detail pane
  cli.py             text interface
  data/              editable reputation files
```

Collection, analysis, and rendering are separate. The collectors never inspect themselves,
the engine never touches the network beyond DNS and TLS, and the GUI only reads finished
`Connection` objects.

### Threading model

Tk is not thread-safe. Scans and permission probes run on a worker thread and hand results
back through a queue; the main thread polls with `after(40, ...)`. Workers never touch widgets.

## Tests

```bash
python3 -m unittest discover -s tests
```

80 tests cover the data model, reputation parsing, DGA heuristics, TLS hostname matching and
grading, and the macOS, Linux, and Windows parsers against captured fixtures. No live network
access is needed.

## Limitations

- Unprivileged runs see only the current user's sockets. Run elevated for a system-wide view.
- Reverse DNS tells you who owns an IP, not which name the application asked for. TLS results
  derived from a PTR name are reported as inconclusive.
- QUIC/HTTP3 traffic cannot be graded because it is not TLS over TCP.
- Reputation files are intentionally small. Structural heuristics carry the detection load,
  which keeps the false-positive rate near zero.

## Licence

MIT
