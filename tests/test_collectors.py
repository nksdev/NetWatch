"""Parser tests for all three platform collectors (fixtures, no live system calls)."""

from __future__ import annotations

import unittest

from netwatch.collectors.base import split_endpoint
from netwatch.collectors.linux import _decode_proc_address, parse_proc_net
from netwatch.collectors.macos import (
    _netstat_addr,
    _split_name,
    parse_lsof_fields,
    parse_netstat_rows,
    remote_raw_present,
)
from netwatch.collectors.windows import (
    _clean_addr,
    _split_hostport,
    parse_netstat_ano,
    parse_tasklist_csv,
)


LSOF_SAMPLE = """p1234
ccurl
unamanmic
f3
PTCP
n192.168.1.5:51000->93.184.216.34:443
TST=ESTABLISHED
f4
PTCP
n*:8080
TST=LISTEN
p5678
crapportd
unamanmic
f7
PTCP
n*:50284
TST=LISTEN
"""

NETSTAT_SAMPLE = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)    rxbytes     txbytes
 tcp4       0      0  192.168.1.5.51000      93.184.216.34.443      ESTABLISHED    1024       2048
 tcp6       0      0  fe80::1.50284          *.64625                LISTEN         0          0
"""

PROC_NET_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:D431 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1
"""

PROC_NET_UDP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2 0000000000000000 0
"""

NETSTAT_ANO = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1024
  TCP    192.168.1.5:51000      93.184.216.34:443      ESTABLISHED     4242
  TCP    [::]:445               [::]:0                 LISTENING       4
  UDP    0.0.0.0:5353           *:*                                    2048
"""

TASKLIST_CSV = """"System Idle Process","0","Services","0","8 K"
"svchost.exe","1024","Services","0","12,345 K"
"chrome.exe","4242","Console","1","250,000 K"
"""


class TestSplitEndpoint(unittest.TestCase):
    def test_ipv4(self) -> None:
        self.assertEqual(split_endpoint("1.2.3.4:443"), ("1.2.3.4", 443))

    def test_bracketed_ipv6(self) -> None:
        self.assertEqual(split_endpoint("[2001:db8::1]:443"), ("2001:db8::1", 443))

    def test_unbracketed_ipv6(self) -> None:
        self.assertEqual(split_endpoint("2001:db8::1:443"), ("2001:db8::1", 443))

    def test_wildcard(self) -> None:
        self.assertEqual(split_endpoint("*"), ("*", 0))

    def test_empty(self) -> None:
        self.assertEqual(split_endpoint(""), ("", 0))


class TestMacOSLsof(unittest.TestCase):
    def test_records_and_fds(self) -> None:
        records = parse_lsof_fields(LSOF_SAMPLE)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["pid"], 1234)
        self.assertEqual(records[0]["command"], "curl")
        self.assertEqual(len(records[0]["fds"]), 2)

    def test_state_and_name(self) -> None:
        records = parse_lsof_fields(LSOF_SAMPLE)
        fd = records[0]["fds"][0]
        self.assertEqual(fd["proto"], "TCP")
        self.assertEqual(fd["state"], "ESTABLISHED")
        self.assertIn("->", fd["name"])

    def test_listen_without_state_tag(self) -> None:
        records = parse_lsof_fields(LSOF_SAMPLE)
        self.assertEqual(records[1]["fds"][0]["state"], "LISTEN")

    def test_split_name_outbound(self) -> None:
        local, remote = _split_name("192.168.1.5:51000->93.184.216.34:443")
        self.assertEqual(local, ("192.168.1.5", 51000))
        self.assertEqual(remote, ("93.184.216.34", 443))

    def test_split_name_listener(self) -> None:
        local, remote = _split_name("*:8080")
        self.assertEqual(local, ("*", 8080))
        self.assertEqual(remote, ("", 0))

    def test_remote_raw_present(self) -> None:
        self.assertTrue(remote_raw_present("1.2.3.4:1->5.6.7.8:443"))
        self.assertFalse(remote_raw_present("*:8080"))


class TestMacOSNetstat(unittest.TestCase):
    def test_addr_ipv4(self) -> None:
        self.assertEqual(_netstat_addr("93.184.216.34.443"), ("93.184.216.34", 443))

    def test_addr_wildcard(self) -> None:
        self.assertEqual(_netstat_addr("*.64625"), ("*", 64625))
        self.assertEqual(_netstat_addr("*.*"), ("*", 0))

    def test_addr_ipv6(self) -> None:
        self.assertEqual(_netstat_addr("fe80::1.50284"), ("fe80::1", 50284))

    def test_counters(self) -> None:
        counters = parse_netstat_rows(NETSTAT_SAMPLE)
        key = ("192.168.1.5", 51000, "93.184.216.34", 443)
        self.assertIn(key, counters)
        self.assertEqual(counters[key], {"rx": 1024, "tx": 2048})

    def test_listen_row_has_counters(self) -> None:
        counters = parse_netstat_rows(NETSTAT_SAMPLE)
        self.assertIn(("fe80::1", 50284, "*", 64625), counters)


class TestLinuxProc(unittest.TestCase):
    def test_decode_ipv4(self) -> None:
        self.assertEqual(_decode_proc_address("0100007F:1F90"), ("127.0.0.1", 8080))

    def test_decode_ipv6(self) -> None:
        addr, port = _decode_proc_address("0000000000000000FFFF00000100007F:01BB")
        self.assertEqual(port, 443)
        self.assertIn(":", addr)

    def test_decode_unparseable(self) -> None:
        addr, port = _decode_proc_address("ZZZZ:0")
        self.assertEqual(port, 0)

    def test_parse_tcp(self) -> None:
        sockets = parse_proc_net(PROC_NET_TCP, "tcp")
        self.assertEqual(len(sockets), 2)
        self.assertEqual(sockets[0]["local_addr"], "127.0.0.1")
        self.assertEqual(sockets[0]["local_port"], 8080)
        self.assertEqual(sockets[0]["state"], "LISTEN")
        self.assertEqual(sockets[1]["remote_port"], 443)
        self.assertEqual(sockets[1]["state"], "ESTABLISHED")
        self.assertEqual(sockets[1]["inode"], 67890)

    def test_parse_udp_has_no_state_column(self) -> None:
        sockets = parse_proc_net(PROC_NET_UDP, "udp")
        self.assertEqual(len(sockets), 1)
        self.assertEqual(sockets[0]["local_port"], 53)
        self.assertEqual(sockets[0]["state"], "UNCONN")

    def test_parse_empty(self) -> None:
        self.assertEqual(parse_proc_net("", "tcp"), [])


class TestWindowsParsers(unittest.TestCase):
    def test_clean_addr(self) -> None:
        self.assertEqual(_clean_addr("0.0.0.0"), "*")
        self.assertEqual(_clean_addr("::"), "*")
        self.assertEqual(_clean_addr("::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(_clean_addr("1.2.3.4"), "1.2.3.4")

    def test_split_hostport(self) -> None:
        self.assertEqual(_split_hostport("1.2.3.4:443"), ("1.2.3.4", 443))
        self.assertEqual(_split_hostport("[::]:445"), ("::", 445))
        self.assertEqual(_split_hostport("*:*"), ("*", 0))

    def test_netstat_rows(self) -> None:
        rows = parse_netstat_ano(NETSTAT_ANO)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["proto"], "tcp")
        self.assertEqual(rows[0]["state"], "LISTEN")
        self.assertEqual(rows[0]["pid"], 1024)
        self.assertEqual(rows[1]["state"], "ESTABLISHED")
        self.assertEqual(rows[1]["pid"], 4242)

    def test_udp_row_defaults(self) -> None:
        rows = parse_netstat_ano(NETSTAT_ANO)
        udp = [r for r in rows if r["proto"] == "udp"]
        self.assertEqual(len(udp), 1)
        self.assertEqual(udp[0]["state"], "UNCONN")

    def test_tasklist_csv(self) -> None:
        names = parse_tasklist_csv(TASKLIST_CSV)
        self.assertEqual(names[1024], "svchost.exe")
        self.assertEqual(names[4242], "chrome.exe")

    def test_tasklist_ignores_bad_rows(self) -> None:
        self.assertEqual(parse_tasklist_csv("garbage"), {})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
