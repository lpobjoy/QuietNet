"""Checks for the DNS side of QuietNet: reading questions, writing answers, the small
helpers that tidy and classify addresses, the community list download, and one
end-to-end run of the real filter over UDP and TCP.

Run with:  python3 -m unittest discover tests

Standard library only. The "real internet" is a pretend upstream on this computer.
"""
import os
import queue
import socket
import struct
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_quietnet import ADULT, KID, Base, fake_answer, query, server


def drain_log():
    out = []
    while True:
        try:
            out.append(server.log_q.get_nowait())
        except queue.Empty:
            return out


def answer_with(data, records):
    """A reply to `data` carrying the given (type, rdata) records, each pointing back at the question name."""
    head = data[:2] + b"\x81\x80\x00\x01" + struct.pack(">H", len(records)) + b"\x00\x00\x00\x00"
    body = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata for rtype, rdata in records)
    return head + data[12:] + body


class Questions(unittest.TestCase):
    def test_a_normal_question_is_read(self):
        data = query("www.bbc.co.uk", qtype=28)
        self.assertEqual(server.parse_question(data), ("www.bbc.co.uk", 28, len(data)))

    def test_names_are_lower_cased(self):
        self.assertEqual(server.parse_question(query("WWW.BBC.co.UK"))[0], "www.bbc.co.uk")

    def test_packets_too_short_to_hold_a_question_are_refused(self):
        for data in (b"", b"\x00" * 12, query("a.bc")[:16]):
            self.assertIsNone(server.parse_question(data))

    def test_a_packet_with_no_question_is_refused(self):
        data = bytearray(query("www.bbc.co.uk"))
        data[4:6] = b"\x00\x00"
        self.assertIsNone(server.parse_question(bytes(data)))

    def test_a_name_that_runs_off_the_end_is_refused(self):
        data = query("www.bbc.co.uk")
        self.assertIsNone(server.parse_question(data[:-6]))        # cut through the name's ending
        self.assertIsNone(server.parse_question(data[:-2]))        # name whole, type and class cut short

    def test_a_pointer_inside_a_question_is_refused(self):
        # Questions never legitimately use pointers; following one could loop forever.
        data = query("www.bbc.co.uk")
        self.assertIsNone(server.parse_question(data[:12] + b"\xc0\x0c" + data[14:]))


class BlockedAnswers(unittest.TestCase):
    def blocked(self, qtype):
        data = query("ads.example.com", qtype)
        return data, server.blocked_reply(data, qtype, len(data))

    def test_ipv4_question_gets_the_nowhere_address(self):
        data, resp = self.blocked(1)
        self.assertEqual(struct.unpack(">HHHH", resp[4:12]), (1, 1, 0, 0))
        self.assertEqual(resp[-4:], bytes(4))                       # 0.0.0.0
        self.assertEqual(struct.unpack(">I", resp[-10:-6])[0], 60)  # remembered for a minute at most

    def test_ipv6_question_gets_the_ipv6_nowhere_address(self):
        data, resp = self.blocked(28)
        self.assertEqual(resp[-16:], bytes(16))                     # ::
        self.assertEqual(struct.unpack(">H", resp[-18:-16])[0], 16)

    def test_other_question_types_get_an_empty_answer(self):
        for qtype in (5, 15, 16, 33, 65):                           # CNAME, MX, TXT, SRV, HTTPS
            data, resp = self.blocked(qtype)
            self.assertEqual(struct.unpack(">HHHH", resp[4:12]), (1, 0, 0, 0), qtype)
            self.assertEqual(resp[3] & 15, 0)                       # "no error", just nothing there
            self.assertEqual(resp[12:], data[12:])                  # the question is echoed back, nothing more

    def test_the_answer_is_marked_as_a_reply_to_the_same_question(self):
        data, resp = self.blocked(1)
        self.assertEqual(resp[:2], data[:2])                        # same id, so the device accepts it
        self.assertTrue(resp[2] & 0x80)                             # it is a response
        self.assertTrue(resp[2] & 0x01)                             # the device's "please look it up" flag is kept
        self.assertTrue(resp[3] & 0x80)                             # "lookups are available here"


class ReadingAnswers(unittest.TestCase):
    def test_ipv4_and_ipv6_addresses_are_pulled_out(self):
        data = query("www.example.com")
        v6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        resp = answer_with(data, [(1, socket.inet_aton("203.0.113.5")), (28, v6), (1, socket.inet_aton("203.0.113.6"))])
        self.assertEqual(server.answer_ips(resp), ["203.0.113.5", "2001:db8::1", "203.0.113.6"])

    def test_an_alias_before_the_address_is_skipped(self):
        data = query("www.example.com")
        resp = answer_with(data, [(5, b"\x03cdn\xc0\x10"), (1, socket.inet_aton("203.0.113.5"))])
        self.assertEqual(server.answer_ips(resp), ["203.0.113.5"])

    def test_an_answer_with_no_addresses_gives_nothing(self):
        data = query("www.example.com")
        self.assertEqual(server.answer_ips(answer_with(data, [])), [])

    def test_garbage_gives_nothing_rather_than_an_error(self):
        good = fake_answer(query("www.example.com"))
        for bad in (b"", b"\x00" * 5, good[:14], good[:-8]):
            self.assertEqual(server.answer_ips(bad), [])


class AnsweringQueries(Base):
    def setUp(self):
        super().setUp()
        drain_log()
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)

    def test_every_lookup_is_written_down_with_who_asked(self):
        server.answer_query(query("www.bbc.co.uk"), KID, fake_answer)
        server.answer_query(query("ads.doubleclick.net"), ADULT, fake_answer)
        log = [(client, name, blocked) for ts, client, name, blocked in drain_log()]
        self.assertEqual(log, [(KID, "www.bbc.co.uk", 0), (ADULT, "ads.doubleclick.net", 1)])

    def test_a_blocked_lookup_never_reaches_the_internet(self):
        asked = []
        server.answer_query(query("ads.doubleclick.net"), KID, lambda d: asked.append(d) or fake_answer(d))
        self.assertEqual(asked, [])

    def test_lookups_from_this_computer_are_filed_under_its_network_address(self):
        server.S.local_ip = "192.168.1.60"
        server.answer_query(query("www.bbc.co.uk"), "127.0.0.1", fake_answer)
        self.assertEqual(drain_log()[0][1], "192.168.1.60")

    def test_home_network_names_are_passed_on_but_not_recorded(self):
        for name in ("printer.local", "nas.lan", "router.home", "box.internal", "1.1.168.192.in-addr.arpa"):
            resp = server.answer_query(query(name), KID, fake_answer)
            self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]), name)
        self.assertEqual(drain_log(), [])

    def test_home_network_names_still_work_during_the_kill_switch(self):
        server.set_internet_off("all", True)
        resp = server.answer_query(query("printer.local"), KID, fake_answer)
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))

    def test_a_packet_we_cannot_read_is_handed_on_untouched(self):
        junk = b"\x12\x34not a dns packet"
        seen = []
        self.assertEqual(server.answer_query(junk, KID, lambda d: seen.append(d) or b"reply"), b"reply")
        self.assertEqual(seen, [junk])
        self.assertEqual(drain_log(), [])

    def test_addresses_handed_out_are_remembered_for_the_enforcer(self):
        server.answer_query(query("www.bbc.co.uk"), KID, fake_answer)
        self.assertEqual(list(server.S.resolved["www.bbc.co.uk"]), ["93.184.216.34"])

    def test_addresses_of_blocked_names_are_not_looked_up_or_remembered(self):
        server.answer_query(query("ads.doubleclick.net"), KID, fake_answer)
        self.assertNotIn("ads.doubleclick.net", server.S.resolved)

    def test_the_memory_of_handed_out_addresses_is_capped(self):
        server.S.resolved = {"old%d.example.com" % i: {"203.0.113.1": float(i)} for i in range(4000)}
        server.record_resolved("new.example.com", fake_answer(query("new.example.com")))
        self.assertEqual(len(server.S.resolved), 3001)
        self.assertIn("new.example.com", server.S.resolved)
        self.assertNotIn("old0.example.com", server.S.resolved)         # the stalest went first
        self.assertIn("old3999.example.com", server.S.resolved)


class Helpers(Base):
    def test_typed_addresses_are_tidied(self):
        for typed, clean in (("example.com", "example.com"), ("  EXAMPLE.co.uk. ", "example.co.uk"),
                             ("https://www.Example.com/path?x=1", "example.com"),
                             ("example.com:8080", "example.com"), ("www.bbc.co.uk", "bbc.co.uk"),
                             ("ftp://files.example.org/a/b", "files.example.org")):
            self.assertEqual(server.clean_domain(typed), clean, typed)

    def test_things_that_are_not_addresses_are_refused(self):
        for typed in (None, "", "   ", "localhost", "exa mple.com", "http://", "example..com", "<script>.com",
                      "example.com;drop", "ex'ample.com"):
            self.assertIsNone(server.clean_domain(typed), typed)

    def test_every_parent_of_an_address_is_checked(self):
        self.assertEqual(server.suffixes("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"])
        self.assertEqual(server.suffixes("example.com"), ["example.com"])

    def test_grouping_by_owner_understands_co_uk_style_endings(self):
        for name, base in (("cdn.example.com", "example.com"), ("a.b.bbc.co.uk", "bbc.co.uk"),
                           ("bbc.co.uk", "bbc.co.uk"), ("shop.example.com.au", "example.com.au"),
                           ("example.com", "example.com")):
            self.assertEqual(server.base_of(name), base, name)

    def test_labels_shown_on_the_dashboard(self):
        self.assertEqual(server.verdict("stats.g.doubleclick.net"), "junk")
        for name in ("telemetry.example.com", "analytics.example.com", "ads2.example.com", "eu-tracking.example.com"):
            self.assertEqual(server.verdict(name), "suspect", name)
        for name in ("www.bbc.co.uk", "adsl.example.com", "downloads.example.com", "example.ads"):
            self.assertEqual(server.verdict(name), "ok", name)

    def test_possibly_junk_is_only_a_label_never_a_block(self):
        self.assertEqual(server.verdict("telemetry.example.com"), "suspect")
        self.assertFalse(server.decision("telemetry.example.com", KID)[0])

    def test_which_rule_sets_apply_to_a_device(self):
        self.assertEqual(server.scopes_for(None), ["all"])
        self.assertEqual(server.scopes_for(KID), ["all", "device:" + KID])
        server.S.dev_group = {KID: 3}
        self.assertEqual(server.scopes_for(KID), ["all", "device:" + KID, "group:3"])

    def test_scope_names_in_plain_words(self):
        server.S.group_names = {3: "Kids"}
        self.assertEqual(server.scope_label("all"), "whole house")
        self.assertEqual(server.scope_label("group:3"), "Kids group")
        self.assertEqual(server.scope_label("device:" + KID), "this device")

    def test_clock_times(self):
        self.assertEqual(server.clock_minutes("00:00"), 0)
        self.assertEqual(server.clock_minutes("21:30"), 21 * 60 + 30)
        for bad in ("24:00", "9:00", "12:60", "noon", ""):
            self.assertIsNone(server.CLOCK.fullmatch(bad), bad)

    def test_scope_format_is_strict(self):
        for good in ("all", "device:192.168.1.23", "device:fe80::1", "group:12"):
            self.assertTrue(server.SCOPE.fullmatch(good), good)
        for bad in ("", "ALL", "group:", "group:x", "device:", "device:192.168.1.23; drop", "all\n"):
            self.assertIsNone(server.SCOPE.fullmatch(bad), bad)


class CommunityList(Base):
    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, server.S, "junk_community", server.S.junk_community)
        self.addCleanup(lambda: os.path.exists(server.COMMUNITY_FILE) and os.remove(server.COMMUNITY_FILE))

    def download(self, text=None, error=None):
        page = mock.MagicMock()
        page.__enter__.return_value.read.return_value = (text or "").encode()
        with mock.patch.object(server.urllib.request, "urlopen", side_effect=error, return_value=page):
            server.update_community_list()

    def test_a_good_download_is_installed_and_saved(self):
        lines = ["# comment", "127.0.0.1 localhost", "0.0.0.0 Bad_Host!", "::1 ip6-localhost"]
        lines += ["0.0.0.0 tracker%d.example.net" % i for i in range(1200)]
        self.download("\n".join(lines))
        self.assertEqual(server.S.list_state, "idle")
        self.assertEqual(len(server.S.junk_community), 1200)
        self.assertTrue(server.is_junk("x.tracker7.example.net"))
        with open(server.COMMUNITY_FILE) as f:
            self.assertEqual(len(f.read().split()), 1200)

    def test_a_suspiciously_short_list_is_refused_and_the_old_one_kept(self):
        server.S.junk_community = {"kept.example.net"}
        self.download("\n".join("0.0.0.0 t%d.example.net" % i for i in range(50)))
        self.assertEqual(server.S.list_state, "error")
        self.assertIn("incomplete", server.S.list_error)
        self.assertEqual(server.S.junk_community, {"kept.example.net"})
        self.assertFalse(os.path.exists(server.COMMUNITY_FILE))

    def test_a_failed_download_is_reported_and_the_old_list_kept(self):
        server.S.junk_community = {"kept.example.net"}
        self.download(error=OSError("no internet"))
        self.assertEqual((server.S.list_state, server.S.list_error), ("error", "no internet"))
        self.assertEqual(server.S.junk_community, {"kept.example.net"})


class LiveFilter(Base):
    """The real filter, listening on a spare port, with a pretend internet behind it."""

    @classmethod
    def setUpClass(cls):
        cls.upstream_asked = []
        # One port number, opened for both UDP and TCP, to play the part of 1.1.1.1.
        cls.up_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.up_udp.bind(("127.0.0.1", 0))
        up_port = cls.up_udp.getsockname()[1]
        cls.up_tcp = socket.socket()
        cls.up_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.up_tcp.bind(("127.0.0.1", up_port))
        cls.up_tcp.listen(5)

        def udp_loop():
            while True:
                try:
                    data, addr = cls.up_udp.recvfrom(4096)
                except OSError:
                    return
                cls.upstream_asked.append(("udp", server.parse_question(data)[0]))
                cls.up_udp.sendto(fake_answer(data), addr)

        def tcp_loop():
            while True:
                try:
                    conn, _ = cls.up_tcp.accept()
                except OSError:
                    return
                with conn:
                    data = server.recv_exact(conn, int.from_bytes(server.recv_exact(conn, 2), "big"))
                    cls.upstream_asked.append(("tcp", server.parse_question(data)[0]))
                    resp = fake_answer(data)
                    conn.sendall(len(resp).to_bytes(2, "big") + resp)

        threading.Thread(target=udp_loop, daemon=True).start()
        threading.Thread(target=tcp_loop, daemon=True).start()
        cls.real_upstreams, cls.real_port = server.UPSTREAMS, server.S.dns_port
        server.UPSTREAMS = [("127.0.0.1", up_port)]

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:        # find a spare port for the filter
            s.bind(("0.0.0.0", 0))
            cls.port = s.getsockname()[1]
        server.S.dns_error = None
        server.start_dns(cls.port)
        if server.S.dns_error:
            raise unittest.SkipTest("could not open a port for the filter: %s" % server.S.dns_error)

    @classmethod
    def tearDownClass(cls):
        server.UPSTREAMS, server.S.dns_port = cls.real_upstreams, cls.real_port
        cls.up_udp.close()
        cls.up_tcp.close()

    def setUp(self):
        super().setUp()
        del self.upstream_asked[:]

    def ask_udp(self, name):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(query(name), ("127.0.0.1", self.port))
            return s.recvfrom(4096)[0]

    def ask_tcp(self, name):
        data = query(name)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(len(data).to_bytes(2, "big") + data)
            return server.recv_exact(s, int.from_bytes(server.recv_exact(s, 2), "big"))

    def test_an_allowed_name_is_fetched_and_its_lifetime_shortened(self):
        resp = self.ask_udp("www.bbc.co.uk")
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))
        self.assertEqual(struct.unpack(">I", resp[-10:-6])[0], server.MAX_TTL)
        self.assertEqual(self.upstream_asked, [("udp", "www.bbc.co.uk")])

    def test_a_blocked_name_is_answered_here_and_never_fetched(self):
        resp = self.ask_udp("ads.doubleclick.net")
        self.assertEqual(resp[-4:], bytes(4))
        self.assertEqual(self.upstream_asked, [])

    def test_the_same_rules_apply_over_tcp(self):
        self.assertEqual(self.ask_tcp("www.bbc.co.uk")[-4:], bytes([93, 184, 216, 34]))
        self.assertEqual(self.ask_tcp("ads.doubleclick.net")[-4:], bytes(4))
        self.assertEqual(self.upstream_asked, [("tcp", "www.bbc.co.uk")])

    def test_a_rule_change_bites_on_the_very_next_lookup(self):
        self.assertEqual(self.ask_udp("www.youtube.com")[-4:], bytes([93, 184, 216, 34]))
        server.set_service_block("all", "youtube", True)
        self.assertEqual(self.ask_udp("www.youtube.com")[-4:], bytes(4))

    def test_when_the_internet_does_not_answer_the_device_is_told_so(self):
        with mock.patch.object(server, "forward_udp", return_value=None):
            resp = self.ask_udp("www.bbc.co.uk")
        self.assertEqual(resp[3] & 15, 2)                                # "server failure"


if __name__ == "__main__":
    unittest.main()
