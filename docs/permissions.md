# Permissions per platform

NetWatch reads the host's socket table and the host's process table. It never
opens a listening port, never changes firewall rules, and never installs a
driver. Everything below is about *seeing*, not *changing*.

Run the pre-flight report at any time:

```bash
netwatch --check
```

Exit code `0` means every required check passed. Exit code `2` means something
required is missing and the report says what to do about it.

---

## macOS

### Required

| Check | How it is satisfied |
|-------|---------------------|
| Socket table access | `lsof` must be readable for your user. Always true for your own sockets. |
| Process identification | `lsof` resolves a PID to an executable path. |
| DNS resolution | The system resolver or an outbound connection to port 53. |
| TLS inspection | An outbound TLS handshake to a known host. |

### Optional

| Check | How to enable |
|-------|---------------|
| Packet capture | `python3 -m pip install scapy` - only needed for packet-level analysis. |

### Seeing other users' connections

An unprivileged run sees only your own sockets. That is usually what you want,
and it is enough to spot a rogue browser extension or a miner running as you.

For a system-wide view:

```bash
sudo netwatch --watch 5
```

When run under `sudo`, the report shows `Elevated : yes`.

### Firewall status

NetWatch reports the application firewall state as a note but never changes it.
Check it yourself with:

```bash
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```

### "Operation not permitted" from ps

On recent macOS releases `/bin/ps` is restricted. NetWatch does not call it -
process identification goes through `lsof` - so this error cannot occur.

---

## Linux

### Required

| Check | How it is satisfied |
|-------|---------------------|
| Socket table access | `/proc/net/tcp`, `/proc/net/udp`, and the IPv6 equivalents must be readable. |
| Process identification | `/proc/<pid>/fd` must be listable to map inodes to processes. |
| DNS resolution | The system resolver or outbound port 53. |
| TLS inspection | An outbound TLS handshake. |

### Seeing other users' connections

`/proc/net/*` is world-readable, so sockets are always visible. The **process**
behind a socket belonging to another user is not, because `/proc/<pid>/fd` is
restricted. Those connections appear with an unknown owner.

To resolve every PID:

```bash
sudo netwatch
```

Or grant the capability to the interpreter:

```bash
sudo setcap cap_net_admin,cap_net_raw+eip "$(readlink -f "$(which python3)")"
```

### Minimal containers

If `/proc/net/tcp` is absent, NetWatch falls back to `ss`/`netstat` when present
and otherwise reports that the host's socket table cannot be read.

---

## Windows

### Required

| Check | How it is satisfied |
|-------|---------------------|
| Socket table access | `psutil.net_connections()` if installed, otherwise `netstat -ano`. |
| Process identification | `tasklist /fo csv /nh`, or `psutil` when available. |
| DNS resolution | The system resolver or outbound port 53. |
| TLS inspection | An outbound TLS handshake. |

### Recommended

```bash
py -m pip install psutil
```

`psutil` makes enumeration faster and gives executable paths directly. Without
it, `netstat -ano` plus `tasklist` still identifies every application.

### Administrator rights

`netstat -ano` lists all sockets regardless of owner, but resolving the image
name for a process owned by another user needs elevation. Without it those rows
show a PID but no name.

To run elevated: right-click **Terminal** -> **Run as administrator**, then
`netwatch-gui`.

### Defender and third-party firewalls

NetWatch does not inject, hook, or modify network stacks, so it does not trip
Defender's tampering protection and needs no exclusion. It performs outbound DNS
and TLS lookups like any browser would.

---

## What NetWatch never does

- It never opens a listening port.
- It never modifies firewall rules.
- It never installs a driver or kernel extension.
- It never sends your connection list anywhere.
- It never writes outside its own output path when you pass `--json`.

The only outbound traffic it generates is reverse-DNS lookups and TLS
handshakes - the same requests a browser makes when you open a page.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Ready to monitor: NO` | A required check failed | Read the `->` line under the failing check |
| Every row shows an unknown application | Process inspection is blocked | Run elevated |
| No IPv6 connections listed | The platform collector fell back to IPv4-only output | Install `psutil` (Windows) or check `/proc/net/tcp6` exists (Linux) |
| `--check` exits 2 | Permission problem | Run `netwatch --check` and follow the remediation line |
| TLS shows `UNVERIFIED` for many peers | Those peers cannot be probed without the name the application used | Expected; see the README's limitations section |
