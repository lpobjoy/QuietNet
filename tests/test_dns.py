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
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_quietnet import ADULT, KID, Base, fake_answer, query, server

# The real check of whether this computer could hear the router over IPv6. Base swaps it for a
# stand-in in every test, so that no test reads the real machine's network cards; the tests of the
# check itself put this back, with stand-ins underneath it.
REAL_CAN_HEAR_ROUTER = server.can_hear_router


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

    def test_an_ipv4_device_asking_over_ipv6_is_filed_under_its_ipv4_address(self):
        server.answer_query(query("www.bbc.co.uk"), "::ffff:" + KID, fake_answer)
        self.assertEqual(drain_log()[0][1], KID)

    def test_lookups_from_this_computer_over_ipv6_are_filed_under_its_network_address(self):
        server.S.local_ip = "192.168.1.60"
        server.answer_query(query("www.bbc.co.uk"), "::1", fake_answer)
        self.assertEqual(drain_log()[0][1], "192.168.1.60")

    def test_an_ipv6_zone_suffix_is_not_part_of_a_devices_address(self):
        self.assertEqual(server.device_address("fe80::1%eth0"), "fe80::1")

    def test_an_ordinary_ipv6_address_is_kept_as_it_is(self):
        self.assertEqual(server.device_address("2001:db8::23"), "2001:db8::23")

    def ask(self, data, client=KID):
        """Answer `data` for `client`, noting each server list the stand-in forwarder was given
        (None meaning the usual public servers)."""
        self.sent_to = []

        def forwarder(d, servers=None):
            """A pretend internet and router that answer everything."""
            self.sent_to.append(servers)
            return fake_answer(d)
        return server.answer_query(data, client, forwarder)

    def test_home_network_names_are_sent_to_the_router_not_the_internet(self):
        server.S.router = "192.168.1.1"
        for name in ("printer.local", "nas.lan", "router.home", "box.internal", "pi.home.arpa"):
            resp = self.ask(query(name))
            self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]), name)
            self.assertEqual(self.sent_to, [[("192.168.1.1", 53)]], name)

    def test_home_network_names_get_no_such_name_when_the_router_is_unknown(self):
        resp = self.ask(query("printer.lan"))
        self.assertEqual(resp[3] & 15, 3)                           # "no such name"
        self.assertEqual(self.sent_to, [])

    def test_reverse_lookups_of_private_addresses_go_to_the_router(self):
        server.S.router = "192.168.1.1"
        self.ask(query("23.1.168.192.in-addr.arpa", qtype=12))
        self.assertEqual(self.sent_to, [[("192.168.1.1", 53)]])

    def test_reverse_lookups_of_public_addresses_still_go_to_the_internet(self):
        server.S.router = "192.168.1.1"
        self.ask(query("8.8.8.8.in-addr.arpa", qtype=12))
        self.assertEqual(self.sent_to, [None])

    def test_home_network_names_are_not_recorded(self):
        server.S.router = "192.168.1.1"
        for name in ("printer.local", "1.1.168.192.in-addr.arpa"):
            self.ask(query(name))
        self.assertEqual(drain_log(), [])

    def test_a_home_network_name_from_the_router_itself_is_not_sent_back_to_it(self):
        server.S.router = "192.168.1.1"
        resp = self.ask(query("printer.lan"), client="192.168.1.1")
        self.assertEqual(resp[3] & 15, 3)
        self.assertEqual(self.sent_to, [])

    def test_single_word_names_are_sent_to_the_router_not_the_internet(self):
        server.S.router = "192.168.1.1"
        resp = self.ask(query("nas"))
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))
        self.assertEqual(self.sent_to, [[("192.168.1.1", 53)]])

    def test_single_word_names_never_go_to_the_internet_when_the_router_is_unknown(self):
        resp = self.ask(query("nas"))
        self.assertEqual(resp[3] & 15, 3)                           # "no such name"
        self.assertEqual(self.sent_to, [])

    def test_a_signature_lookup_for_a_top_level_name_is_not_answered_no_such_name(self):
        resp = self.ask(query("com", qtype=43))                     # DS, asked by devices that check signatures
        self.assertNotEqual(resp[3] & 15, 3)
        self.assertEqual(self.sent_to, [None])                      # the internet, not the router

    def test_an_address_lookup_for_a_single_word_still_counts_as_a_home_name(self):
        self.assertTrue(server.is_home_name("nas", 1))
        self.assertFalse(server.is_home_name("com", 48))

    def test_a_question_already_waiting_on_the_router_gets_server_failure_not_a_second_ask(self):
        # A router that sends the lookup straight back to QuietNet: the second ask must stop there.
        server.S.router = "192.168.1.1"
        inner, asked = [], []

        def router_that_asks_back(d, servers=None):
            """Pass the question back to QuietNet, as a badly set-up router would."""
            asked.append(servers)
            if len(asked) == 1:
                inner.append(server.answer_query(d, "192.168.1.2", router_that_asks_back))
            return fake_answer(d)
        server.answer_query(query("nas.lan"), KID, router_that_asks_back)
        self.assertEqual(len(asked), 1)
        self.assertEqual(inner[0][3] & 15, 2)                       # "server failure"

    def test_the_same_home_name_can_be_asked_again_once_the_router_has_answered(self):
        server.S.router = "192.168.1.1"
        self.ask(query("nas.lan"))
        self.ask(query("nas.lan"))
        self.assertEqual(self.sent_to, [[("192.168.1.1", 53)]])

    def test_this_computer_is_never_used_as_the_router(self):
        server.S.local_ip = "192.168.1.60"
        server.S.router = "192.168.1.60"
        self.assertIsNone(server.home_router())

    def test_the_router_address_is_looked_up_once_and_remembered(self):
        server.S.router_checked = None
        with mock.patch.object(server.enforcer, "interface_and_gateway",
                               return_value=("eth0", "192.168.1.254")) as look:
            self.assertEqual(server.home_router(), "192.168.1.254")
            self.assertEqual(server.home_router(), "192.168.1.254")
        self.assertEqual(look.call_count, 1)

    def test_which_reverse_lookups_count_as_private(self):
        private = ("1.0.0.10.in-addr.arpa", "1.0.20.172.in-addr.arpa", "5.4.168.192.in-addr.arpa",
                   "1.0.254.169.in-addr.arpa", "1.0.0.127.in-addr.arpa", "168.192.in-addr.arpa",
                   "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
                   "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa")
        public = ("8.8.8.8.in-addr.arpa", "1.0.32.172.in-addr.arpa", "1.0.15.172.in-addr.arpa",
                  "1.1.1.1.in-addr.arpa", "192.in-addr.arpa", "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
                  "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.e.f.ip6.arpa")
        for name in private:
            self.assertTrue(server.is_private_reverse(name), name)
        for name in public:
            self.assertFalse(server.is_private_reverse(name), name)

    def test_home_network_names_are_answered_here_during_the_kill_switch(self):
        server.S.router = "192.168.1.1"
        server.set_internet_off("all", True)
        resp = self.ask(query("printer.local"))
        self.assertEqual(resp[-4:], bytes(4))                       # the blocked answer
        self.assertEqual(self.sent_to, [])

    def test_names_with_odd_characters_are_not_passed_on_during_the_kill_switch(self):
        server.set_internet_off("all", True)
        high_byte = (b"\x42\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x03a\xbcb\x06tunnel\x07example\x03com\x00"
                     + b"\x00\x01\x00\x01")
        for data in (query("ab+c.tunnel.example.com"), high_byte):
            resp = self.ask(data)
            self.assertEqual(resp[-4:], bytes(4))
        self.assertEqual(self.sent_to, [])

    def test_reverse_lookups_are_not_passed_on_while_a_devices_internet_is_off(self):
        server.set_internet_off("device:" + KID, True)
        self.ask(query("x.1.0.0.0.ip6.arpa"))
        self.assertEqual(self.sent_to, [])

    def test_odd_names_are_not_passed_on_during_an_all_internet_schedule(self):
        self.schedule(start="00:00", end="23:59")
        self.ask(query("evil.home"))
        self.assertEqual(self.sent_to, [])

    def test_odd_names_are_still_passed_on_when_the_internet_is_on(self):
        resp = self.ask(query("ab+c.example.com"))
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))
        self.assertEqual(self.sent_to, [None])

    def test_odd_names_from_this_computer_are_passed_on_during_the_kill_switch(self):
        server.set_internet_off("all", True)
        self.ask(query("ab+c.example.com"), client="127.0.0.1")
        self.assertEqual(self.sent_to, [None])

    def test_a_packet_we_cannot_read_gets_a_format_error_and_is_never_passed_on(self):
        junk = b"\x12\x34\x01\x00 not a dns packet"
        resp = self.ask(junk)
        self.assertEqual(resp[:2], b"\x12\x34")                     # same id
        self.assertEqual(resp[3] & 15, 1)                           # "format error"
        self.assertEqual(self.sent_to, [])
        self.assertEqual(drain_log(), [])

    def test_a_packet_too_short_for_a_header_gets_no_answer(self):
        self.assertIsNone(self.ask(b"\x12\x34abc"))
        self.assertEqual(self.sent_to, [])

    def test_an_unreadable_reply_sent_to_us_gets_no_answer(self):
        # Answering replies with errors could set two servers bouncing packets between them.
        self.assertIsNone(self.ask(b"\x12\x34\x81\x80 not a dns packet"))

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

    def test_a_name_a_devices_own_system_depends_on_says_who_needs_it(self):
        self.assertEqual(server.needed_by("samsungcloudsolution.net"), "Samsung TVs")
        self.assertEqual(server.needed_by("samsungcloudsolution.com"), "Samsung TVs")

    def test_a_sub_name_beneath_a_needed_name_is_not_itself_needed(self):
        self.assertEqual(server.needed_by("log-config.samsungcloudsolution.net"), "")

    def test_an_ordinary_name_is_needed_by_nobody(self):
        for name in ("example.com", "bbc.co.uk", "doubleclick.net"):
            self.assertEqual(server.needed_by(name), "", name)

    def test_a_sub_name_beneath_a_needed_name_keeps_its_own_label(self):
        self.assertEqual(server.verdict("log-config.samsungcloudsolution.net"), "suspect")

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


class NetworkDnsSignals(Base):
    """The names devices look up to ask whether to keep using the network's DNS (known issue 8)."""

    def setUp(self):
        super().setUp()
        drain_log()
        self.asked = []

    def ask(self, name, client=KID, qtype=1):
        """Answer a lookup, noting anything that reached the pretend internet."""
        return server.answer_query(query(name, qtype), client,
                                   lambda d: self.asked.append(d) or fake_answer(d))

    def test_firefox_is_told_its_secure_dns_signal_name_does_not_exist(self):
        resp = self.ask("use-application-dns.net")
        self.assertEqual(resp[3] & 15, 3)                           # "no such name"
        self.assertEqual(self.asked, [])

    def test_firefox_signal_name_does_not_exist_even_while_blocking_is_paused(self):
        server.S.paused_until = time.time() + 600
        self.assertEqual(self.ask("use-application-dns.net")[3] & 15, 3)

    def test_apple_private_relay_signal_names_are_blocked(self):
        for name in ("mask.icloud.com", "mask-h2.icloud.com"):
            self.assertEqual(self.ask(name)[-4:], bytes(4), name)
        self.assertEqual(self.asked, [])

    def test_apple_private_relay_signal_names_stay_blocked_while_blocking_is_paused(self):
        server.S.paused_until = time.time() + 600
        self.assertEqual(self.ask("mask.icloud.com", client=ADULT)[-4:], bytes(4))

    def test_apple_private_relay_signal_names_stay_blocked_even_if_icloud_is_always_allowed(self):
        server.unblock("icloud.com")
        self.assertEqual(self.ask("mask-h2.icloud.com")[-4:], bytes(4))

    def test_signal_lookups_are_written_down_as_blocked(self):
        self.ask("use-application-dns.net")
        self.ask("mask.icloud.com")
        log = [(client, name, blocked) for ts, client, name, blocked in drain_log()]
        self.assertEqual(log, [(KID, "use-application-dns.net", 1), (KID, "mask.icloud.com", 1)])

    def test_other_icloud_names_are_not_affected(self):
        self.assertEqual(self.ask("www.icloud.com")[-4:], bytes([93, 184, 216, 34]))


class OtherDnsServices(Base):
    """Names of other DNS services (secure DNS in a browser, Private DNS on a phone) are blocked for
    devices the owner controls, or every device if the owner chooses, so they fall back to
    ordinary DNS and come to QuietNet (known issue 8). KID has a rule of its own; ADULT has none."""

    def setUp(self):
        super().setUp()
        server.set_service_block("device:" + KID, "tiktok", True)
        drain_log()
        self.asked = []

    def ask(self, name, client=KID, qtype=1):
        """Answer a lookup, noting anything that reached the pretend internet."""
        return server.answer_query(query(name, qtype), client,
                                   lambda d: self.asked.append(d) or fake_answer(d))

    def test_every_listed_dns_service_is_blocked(self):
        for name in sorted(server.OTHER_DNS_SERVICES):
            self.assertEqual(self.ask(name)[-4:], bytes(4), name)
        self.assertEqual(self.asked, [])

    def test_the_list_holds_the_well_known_services(self):
        for name in ("dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
                     "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com",
                     "family.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net",
                     "dns11.quad9.net", "doh.opendns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
                     "dns.adguard.com", "dns.adguard-dns.com", "doh.mullvad.net", "dns.mullvad.net",
                     "chrome.cloudflare-dns.com", "doh.dns.sb", "dns.controld.com", "freedns.controld.com"):
            self.assertIn(name, server.OTHER_DNS_SERVICES)

    def test_a_dns_service_gets_a_real_answer_for_a_device_with_no_rules_of_its_own(self):
        self.assertEqual(self.ask("dns.google", client=ADULT)[-4:], bytes([93, 184, 216, 34]))
        self.assertNotIn(ADULT, server.S.other_dns)

    def test_a_dns_service_is_blocked_for_every_device_when_the_owner_chooses(self):
        server.S.other_dns_all = True
        self.assertEqual(self.ask("dns.google", client=ADULT)[-4:], bytes(4))

    def test_a_dns_service_is_blocked_for_a_device_in_a_group(self):
        server.S.group_names[7] = "Kids"
        server.S.dev_group[ADULT] = 7
        self.assertEqual(self.ask("dns.google", client=ADULT)[-4:], bytes(4))

    def test_a_dns_service_is_blocked_for_a_device_with_live_cut_on(self):
        server.S.enforced.add(ADULT)
        self.assertEqual(self.ask("dns.google", client=ADULT)[-4:], bytes(4))

    def test_a_dns_service_is_blocked_for_a_device_with_its_own_schedule(self):
        self.schedule(scope="device:" + ADULT)
        self.assertEqual(self.ask("dns.google", client=ADULT)[-4:], bytes(4))

    def test_a_name_beneath_a_dns_service_is_blocked(self):
        self.assertEqual(self.ask("abc123.dns.nextdns.io")[-4:], bytes(4))

    def test_a_dns_service_asked_for_in_capitals_is_blocked(self):
        self.assertEqual(self.ask("DNS.Google")[-4:], bytes(4))

    def test_a_dns_service_name_with_a_final_dot_still_counts(self):
        self.assertTrue(server.is_other_dns_service("Cloudflare-DNS.com."))

    def test_a_name_that_only_ends_the_same_way_does_not_count(self):
        self.assertFalse(server.is_other_dns_service("notdns.google"))
        self.assertFalse(server.is_other_dns_service("www.google.com"))

    def test_a_dns_service_ipv6_question_gets_the_blocked_answer(self):
        self.assertEqual(self.ask("dns.quad9.net", qtype=28)[-16:], bytes(16))

    def test_a_dns_service_stays_blocked_while_blocking_is_paused(self):
        server.S.paused_until = time.time() + 600
        self.assertEqual(self.ask("dns.google")[-4:], bytes(4))

    def test_a_dns_service_stays_blocked_even_if_always_allowed(self):
        server.unblock("cloudflare-dns.com")
        self.assertEqual(self.ask("cloudflare-dns.com")[-4:], bytes(4))

    def test_a_dns_service_lookup_is_written_down_as_blocked(self):
        self.ask("dns.google")
        log = [(client, name, blocked) for ts, client, name, blocked in drain_log()]
        self.assertEqual(log, [(KID, "dns.google", 1)])

    def test_a_dns_service_lookup_is_remembered_against_the_device(self):
        self.ask("doh.opendns.com")
        self.assertGreater(server.S.other_dns.get(KID, 0), time.time() - 60)

    def test_ordinary_google_names_are_not_affected(self):
        self.assertEqual(self.ask("www.google.com")[-4:], bytes([93, 184, 216, 34]))


class ReplyAddress(unittest.TestCase):
    """On Linux each answer leaves from the address its lookup was sent to, so a lookup the enforcer
    redirected from 8.8.8.8 is answered from the address it was redirected to. Stand-in sockets only."""

    PI = "192.168.1.60"

    def pktinfo(self, addressed_to):
        """The extra details Linux gives with a lookup: card number, local address, address it was sent to."""
        info = struct.pack("=i4s4s", 3, socket.inet_aton(self.PI), socket.inet_aton(addressed_to))
        return [(socket.IPPROTO_IP, server.IP_PKTINFO or 8, info)]

    def test_the_address_a_lookup_was_sent_to_is_read(self):
        with mock.patch.object(server, "IP_PKTINFO", 8):
            self.assertEqual(server.reply_address(self.pktinfo(self.PI)), self.PI)

    def test_a_lookup_sent_to_everyone_gives_no_reply_address(self):
        with mock.patch.object(server, "IP_PKTINFO", 8):
            self.assertIsNone(server.reply_address(self.pktinfo("255.255.255.255")))
            self.assertIsNone(server.reply_address(self.pktinfo("224.0.0.251")))

    def test_no_details_gives_no_reply_address(self):
        self.assertIsNone(server.reply_address([]))

    def test_the_answer_is_sent_from_the_address_the_lookup_was_sent_to(self):
        sock = mock.Mock()
        with mock.patch.object(server, "IP_PKTINFO", 8):
            server.send_answer(sock, b"answer", ("192.168.1.23", 5000), self.PI)
        sock.sendmsg.assert_called_once()
        (parts, ancillary, flags, addr), _ = sock.sendmsg.call_args
        self.assertEqual((parts, flags, addr), ([b"answer"], 0, ("192.168.1.23", 5000)))
        level, kind, info = ancillary[0]
        self.assertEqual((level, kind), (socket.IPPROTO_IP, 8))
        self.assertEqual(info, struct.pack("=i4s4s", 0, socket.inet_aton(self.PI), bytes(4)))
        sock.sendto.assert_not_called()

    def test_without_a_known_address_the_system_chooses(self):
        sock = mock.Mock()
        server.send_answer(sock, b"answer", ("192.168.1.23", 5000), None)
        sock.sendto.assert_called_once_with(b"answer", ("192.168.1.23", 5000))

    def test_if_the_address_cannot_be_sent_from_the_system_chooses(self):
        sock = mock.Mock()
        sock.sendmsg.side_effect = OSError("cannot assign requested address")
        with mock.patch.object(server, "IP_PKTINFO", 8):
            server.send_answer(sock, b"answer", ("192.168.1.23", 5000), self.PI)
        sock.sendto.assert_called_once_with(b"answer", ("192.168.1.23", 5000))

    def test_the_option_is_asked_for_on_linux_ipv4_sockets(self):
        sock = mock.Mock(family=socket.AF_INET)
        with mock.patch.object(server, "IP_PKTINFO", 8):
            self.assertTrue(server.ask_for_reply_address(sock))
        sock.setsockopt.assert_called_once_with(socket.IPPROTO_IP, 8, 1)

    def test_the_option_is_not_asked_for_away_from_linux(self):
        sock = mock.Mock(family=socket.AF_INET)
        with mock.patch.object(server, "IP_PKTINFO", None):
            self.assertFalse(server.ask_for_reply_address(sock))
        sock.setsockopt.assert_not_called()

    def test_the_option_is_not_asked_for_on_the_ipv6_listener(self):
        sock = mock.Mock(family=socket.AF_INET6)
        with mock.patch.object(server, "IP_PKTINFO", 8):
            self.assertFalse(server.ask_for_reply_address(sock))

    def test_the_listener_answers_from_the_address_each_lookup_was_sent_to(self):
        sock = mock.Mock(family=socket.AF_INET)
        sock.recvmsg.side_effect = [(query("www.bbc.co.uk"), self.pktinfo(self.PI), 0, ("192.168.1.23", 5000)),
                                    KeyboardInterrupt()]
        sent = []

        def run_now(fn, data, addr, source):
            """Answer the lookup straight away."""
            fn(data, addr, source)
        pool = mock.Mock(submit=run_now)
        with mock.patch.object(server, "IP_PKTINFO", 8), \
                mock.patch.object(server, "answer_query", return_value=b"answer"), \
                mock.patch.object(server, "send_answer", lambda s, resp, addr, source: sent.append((addr, source))), \
                mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock)
        self.assertEqual(sent, [(("192.168.1.23", 5000), self.PI)])


class RememberedAnswers(Base):
    """Answers kept in memory for their shortened lifetime (known issue 22)."""

    def setUp(self):
        super().setUp()
        self.asked = []

    def internet(self, d):
        """A pretend internet that notes each question it is asked."""
        self.asked.append(d)
        return fake_answer(d)

    def ask(self, name, client=KID, qid=0x4242):
        """Answer a lookup with the given id."""
        data = struct.pack(">H", qid) + query(name)[2:]
        return server.answer_query(data, client, self.internet)

    def test_a_second_identical_lookup_does_not_go_to_the_internet(self):
        first = self.ask("www.bbc.co.uk")
        second = self.ask("www.bbc.co.uk")
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(second[-4:], first[-4:])

    def test_a_remembered_answer_carries_the_askers_own_id(self):
        self.ask("www.bbc.co.uk", qid=0x1111)
        resp = self.ask("www.bbc.co.uk", qid=0x2222)
        self.assertEqual(resp[:2], b"\x22\x22")

    def test_a_remembered_answer_keeps_the_letter_case_the_device_asked_with(self):
        self.ask("www.bbc.co.uk")
        resp = self.ask("WWW.BBC.co.uk")
        self.assertIn(b"WWW\x03BBC", resp)
        self.assertEqual(len(self.asked), 1)

    def test_a_rule_change_forgets_remembered_answers(self):
        self.ask("www.bbc.co.uk")
        server.block("example.com")
        self.ask("www.bbc.co.uk")
        self.assertEqual(len(self.asked), 2)

    def test_an_answer_past_its_lifetime_is_fetched_again(self):
        self.ask("www.bbc.co.uk")
        later = time.monotonic() + server.MAX_TTL + 1
        clock = mock.Mock(wraps=time)
        clock.monotonic.return_value = later
        with mock.patch.object(server, "time", clock):
            self.ask("www.bbc.co.uk")
        self.assertEqual(len(self.asked), 2)

    def test_a_remembered_answers_lifetime_counts_down(self):
        self.ask("www.bbc.co.uk")
        clock = mock.Mock(wraps=time)
        clock.monotonic.return_value = time.monotonic() + 30
        with mock.patch.object(server, "time", clock):
            resp = self.ask("www.bbc.co.uk")
        self.assertLessEqual(struct.unpack(">I", resp[-10:-6])[0], server.MAX_TTL - 29)

    def test_a_device_whose_rules_block_a_name_is_not_given_the_remembered_answer(self):
        self.ask("www.disneyplus.com", client=ADULT)
        server.S.svc_blocks["device:" + KID] = {"disneyplus"}       # in memory only, so nothing is forgotten
        self.addCleanup(server.S.svc_blocks.pop, "device:" + KID, None)
        self.assertEqual(self.ask("www.disneyplus.com", client=KID)[-4:], bytes(4))

    def test_a_failure_from_the_internet_is_not_remembered(self):
        def failing(d):
            """A pretend internet that says 'server failure'."""
            self.asked.append(d)
            return server.reply(d, server.parse_question(d)[2], 2)
        for _ in range(2):
            server.answer_query(query("www.bbc.co.uk"), KID, failing)
        self.assertEqual(len(self.asked), 2)

    def test_no_answer_from_the_internet_is_not_remembered(self):
        server.answer_query(query("www.bbc.co.uk"), KID, lambda d: None)
        self.ask("www.bbc.co.uk")
        self.assertEqual(len(self.asked), 1)

    def test_lookups_of_different_record_types_are_remembered_apart(self):
        self.ask("www.bbc.co.uk")
        server.answer_query(query("www.bbc.co.uk", qtype=28), KID, self.internet)
        self.assertEqual(len(self.asked), 2)

    def test_the_memory_of_answers_is_capped_and_the_oldest_dropped(self):
        with mock.patch.object(server, "MAX_CACHED_ANSWERS", 2):
            for name in ("a.example.com", "b.example.com", "c.example.com"):
                self.ask(name)
            self.assertEqual([k[0] for k in server.answer_cache], ["b.example.com", "c.example.com"])

    # ----- what the question asked of the answer, and answer sizes

    @staticmethod
    def with_settings(name, size=1232, signatures=False, no_checking=False):
        """A question carrying a settings record (type 41) with the given UDP size and signature flag."""
        data = bytearray(query(name))
        data[11] = 1                                            # one extra record
        if no_checking:
            data[3] |= 0x10
        flags = 0x8000 if signatures else 0
        return bytes(data) + b"\x00" + struct.pack(">HHBBHH", 41, size, 0, 0, flags, 0)

    def plain_internet(self, d):
        """A pretend internet that answers the question alone (leaving out any settings record)."""
        self.asked.append(d)
        qend = server.parse_question(d)[2]
        head = d[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        return head + d[12:qend] + b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">IH", 300, 4) + bytes([1, 2, 3, 4])

    @staticmethod
    def big_answer(data, size):
        """An answer to `data` with one text record, padded to about `size` bytes."""
        qend = server.parse_question(data)[2]
        head = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        text = b"x" * (size - qend - 12)
        return head + data[12:qend] + b"\xc0\x0c\x00\x10\x00\x01" + struct.pack(">IH", 300, len(text)) + text

    def test_an_answer_over_the_size_limit_is_not_remembered(self):
        data = query("big.example.com", qtype=16)
        key = server.cache_key(data, server.parse_question(data))
        server.remember_answer(key, self.big_answer(data, server.MAX_CACHED_SIZE + 100))
        self.assertNotIn(key, server.answer_cache)

    def test_an_answer_within_the_size_limit_is_remembered(self):
        data = query("big.example.com", qtype=16)
        key = server.cache_key(data, server.parse_question(data))
        server.remember_answer(key, self.big_answer(data, 2000))
        self.assertIn(key, server.answer_cache)

    def test_a_remembered_answer_bigger_than_the_askers_stated_size_is_not_given_over_udp(self):
        data = self.with_settings("big.example.com", size=1232)
        q = server.parse_question(data)
        key = server.cache_key(data, q)
        server.remember_answer(key, self.big_answer(data[:q[2]], 1500))
        self.assertIsNone(server.cached_answer(data, key, q[2]))

    def test_a_remembered_answer_within_the_askers_stated_size_is_given_over_udp(self):
        data = self.with_settings("big.example.com", size=4096)
        q = server.parse_question(data)
        key = server.cache_key(data, q)
        server.remember_answer(key, self.big_answer(data[:q[2]], 1500))
        self.assertIsNotNone(server.cached_answer(data, key, q[2]))

    def test_a_big_remembered_answer_is_given_over_tcp_whatever_size_was_stated(self):
        data = query("big.example.com")
        q = server.parse_question(data)
        key = server.cache_key(data, q)
        server.remember_answer(key, self.big_answer(data, 1500))
        self.assertIsNotNone(server.cached_answer(data, key, q[2], over_tcp=True))

    def test_the_size_and_signature_flag_are_read_from_the_settings_record(self):
        data = self.with_settings("www.bbc.co.uk", size=1400, signatures=True)
        self.assertEqual(server.question_settings(data, server.parse_question(data)[2]), (True, 1400, True))
        plain = query("www.bbc.co.uk")
        self.assertEqual(server.question_settings(plain, server.parse_question(plain)[2]), (False, 512, False))

    def test_a_lookup_with_checking_turned_off_is_not_served_the_ordinary_remembered_answer(self):
        server.answer_query(query("www.bbc.co.uk"), KID, self.plain_internet)
        unchecked = bytearray(query("www.bbc.co.uk"))
        unchecked[3] |= 0x10
        server.answer_query(bytes(unchecked), KID, self.plain_internet)
        self.assertEqual(len(self.asked), 2)

    def test_an_answer_fetched_with_checking_turned_off_is_not_served_to_an_ordinary_lookup(self):
        unchecked = bytearray(query("www.bbc.co.uk"))
        unchecked[3] |= 0x10
        server.answer_query(bytes(unchecked), KID, self.plain_internet)
        server.answer_query(query("www.bbc.co.uk"), ADULT, self.plain_internet)
        self.assertEqual(len(self.asked), 2)

    def test_lookups_with_and_without_a_settings_record_are_remembered_apart(self):
        server.answer_query(query("www.bbc.co.uk"), KID, self.plain_internet)
        server.answer_query(self.with_settings("www.bbc.co.uk"), KID, self.plain_internet)
        self.assertEqual(len(self.asked), 2)

    def test_lookups_asking_and_not_asking_for_signatures_are_remembered_apart(self):
        server.answer_query(self.with_settings("www.bbc.co.uk"), KID, self.plain_internet)
        server.answer_query(self.with_settings("www.bbc.co.uk", signatures=True), KID, self.plain_internet)
        self.assertEqual(len(self.asked), 2)

    def test_the_same_kind_of_lookup_with_a_settings_record_is_answered_from_memory(self):
        server.answer_query(self.with_settings("www.bbc.co.uk"), KID, self.plain_internet)
        server.answer_query(self.with_settings("www.bbc.co.uk"), ADULT, self.plain_internet)
        self.assertEqual(len(self.asked), 1)

    def test_a_remembered_answer_still_counts_towards_the_enforcers_addresses(self):
        self.ask("www.bbc.co.uk")
        server.S.resolved = {}
        self.ask("www.bbc.co.uk")
        self.assertIn("93.184.216.34", server.S.resolved["www.bbc.co.uk"])


class LookupsOverIPv6(Base):
    """Devices asking from their own IPv6 address, and strangers on the internet (known issue 5)."""

    PHONE_V6 = "fd00::abcd"

    def setUp(self):
        super().setUp()
        drain_log()

    def answer(self, client, name="www.bbc.co.uk"):
        """Answer one lookup from `client` with a pretend internet."""
        return server.answer_query(query(name), client, fake_answer)

    def view(self, v4, v6, own=(set(), [], "")):
        """Work out the IPv6 view from stand-in neighbour tables: `v4` is {IPv4 address: (hardware
        address, freshness)}, `v6` the same for IPv6 addresses, or None for "could not be read"."""
        with mock.patch.object(server, "own_ipv6", return_value=own), \
                mock.patch.object(server, "neighbour_table", return_value=v4), \
                mock.patch.object(server, "ipv6_neighbour_table", return_value=v6):
            server.refresh_ipv6_view()

    def test_a_device_switched_off_by_its_ipv4_address_is_refused_from_an_ipv6_address_that_cannot_be_matched(self):
        server.set_internet_off("device:" + KID, True)
        self.assertEqual(self.answer(self.PHONE_V6)[3] & 15, 5)        # "refused": it tries its next DNS server

    def test_a_device_switched_off_by_its_ipv4_address_gets_the_blocked_answer_from_its_matched_ipv6_address(self):
        server.set_internet_off("device:" + KID, True)
        server.S.v6_devices = {self.PHONE_V6: KID}
        self.assertEqual(self.answer(self.PHONE_V6)[-4:], bytes(4))

    def test_a_matched_ipv6_lookup_is_filed_under_the_devices_ipv4_address(self):
        server.S.v6_devices = {self.PHONE_V6: KID}
        self.answer(self.PHONE_V6)
        self.assertEqual(drain_log()[0][1], KID)

    def test_a_bedtime_schedule_for_one_device_makes_unmatched_ipv6_lookups_refused(self):
        self.schedule(scope="device:" + ADULT)
        self.assertEqual(self.answer(self.PHONE_V6)[3] & 15, 5)

    def test_an_unmatched_ipv6_device_is_answered_as_itself_when_no_rule_names_a_device_or_group(self):
        server.set_service_block("all", "youtube", True)
        self.addCleanup(server.set_service_block, "all", "youtube", False)
        self.assertEqual(self.answer(self.PHONE_V6)[-4:], bytes([93, 184, 216, 34]))
        self.assertEqual(drain_log()[0][1], self.PHONE_V6)

    def test_this_computers_own_ipv6_address_counts_as_this_computer(self):
        server.S.local_ip = "192.168.1.60"
        server.S.v6_own = {"2001:db8:1:2::60"}
        self.answer("2001:db8:1:2::60")
        self.assertEqual(drain_log()[0][1], "192.168.1.60")

    def test_home_only_ipv6_addresses_may_ask(self):
        for host in ("::1", "fe80::1%eth0", "fd12:3456::1", "fc00::5", "::ffff:192.168.1.23"):
            self.assertTrue(server.v6_source_allowed(host), host)

    def test_a_public_ipv6_address_inside_the_home_range_may_ask(self):
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]
        self.assertTrue(server.v6_source_allowed("2001:db8:1:2::99"))

    def test_a_public_ipv6_address_outside_the_home_range_may_not_ask(self):
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]
        self.assertFalse(server.v6_source_allowed("2001:db8:9:9::1"))
        self.assertFalse(server.v6_source_allowed("::ffff:8.8.8.8"))

    def test_a_lookup_from_a_public_address_outside_the_home_range_gets_no_reply(self):
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]
        sock = mock.Mock(family=socket.AF_INET6)
        sock.recvfrom.side_effect = [(query("www.bbc.co.uk"), ("2001:db8:9:9::1", 5000, 0, 0)), KeyboardInterrupt()]
        submitted = []
        pool = mock.Mock(submit=lambda fn, data, addr, source: submitted.append(addr))
        with mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock)
        self.assertEqual(submitted, [])
        sock.sendto.assert_not_called()

    def test_a_lookup_from_inside_the_home_range_is_taken_on_the_ipv6_listener(self):
        sock = mock.Mock(family=socket.AF_INET6)
        sock.recvfrom.side_effect = [(query("www.bbc.co.uk"), ("fe80::1", 5000, 0, 2)), KeyboardInterrupt()]
        submitted = []
        pool = mock.Mock(submit=lambda fn, data, addr, source: submitted.append(addr))
        with mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock)
        self.assertEqual(len(submitted), 1)

    def test_a_tcp_connection_from_outside_the_home_range_is_turned_away(self):
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]
        self.assertFalse(server.TCPServer6.verify_request(None, "conn", ("2001:db8:9:9::1", 5000, 0, 0)))
        self.assertTrue(server.TCPServer6.verify_request(None, "conn", ("2001:db8:1:2::5", 5000, 0, 0)))

    def test_ipv6_neighbours_are_matched_to_ipv4_devices_by_hardware_address(self):
        self.view({KID: ("aa:bb:cc:dd:ee:01", "fresh")},
                  {self.PHONE_V6: ("aa:bb:cc:dd:ee:01", "fresh"), "fd00::2": ("aa:bb:cc:dd:ee:99", "fresh")})
        self.assertEqual(server.S.v6_devices, {self.PHONE_V6: KID})

    def test_a_device_known_only_from_the_last_scan_is_matched_to_its_ipv6_address(self):
        server.sql("INSERT OR REPLACE INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)",
                   (KID, "aa:bb:cc:dd:ee:01", "", time.time()), commit=True)
        self.addCleanup(server.sql, "DELETE FROM seen WHERE ip=?", (KID,), True)
        self.view({}, {self.PHONE_V6: ("aa:bb:cc:dd:ee:01", "stale")})
        self.assertEqual(server.S.v6_devices, {self.PHONE_V6: KID})

    def linux_neighbours(self, text, code=0):
        """What ipv6_neighbour_table makes of this `ip -6 neigh show` output and exit code."""
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/if_inet6"), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text, returncode=code)):
            return server.ipv6_neighbour_table()

    def test_the_linux_ipv6_neighbour_table_is_read(self):
        text = ("fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router REACHABLE\n"
                "fd00::ABCD dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
                "fd00::3 dev eth0 FAILED\n")
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/if_inet6"), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text, returncode=0)):
            found = server.ipv6_neighbours()
        self.assertEqual(found, {"fe80::1": "aa:bb:cc:dd:ee:01", "fd00::abcd": "aa:bb:cc:dd:ee:02"})

    def test_the_mac_ipv6_neighbour_table_is_read(self):
        text = ("Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n"
                "fe80::1%en0                     0:11:22:33:44:55   en0   23h59m58s S  R\n"
                "fd00::9                         (incomplete)       en0   expired   N\n")
        with mock.patch.object(server.os.path, "exists", lambda p: False), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text, returncode=0)):
            found = server.ipv6_neighbours()
        self.assertEqual(found, {"fe80::1": "00:11:22:33:44:55"})

    def test_the_mac_ipv6_neighbour_table_says_which_entries_are_fresh(self):
        text = ("Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n"
                "fe80::1%en0                     0:11:22:33:44:55   en0   23h59m58s S  R\n"
                "fd00::7                         0:11:22:33:44:77   en0   18s       R\n")
        with mock.patch.object(server.os.path, "exists", lambda p: False), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text, returncode=0)):
            found = server.ipv6_neighbour_table()
        self.assertEqual(found, {"fe80::1": ("00:11:22:33:44:55", "stale"), "fd00::7": ("00:11:22:33:44:77", "fresh")})

    def test_reachable_stale_delay_and_probe_ipv6_neighbours_are_all_kept(self):
        found = self.linux_neighbours("fd00::1 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
                                      "fd00::2 dev wlan0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
                                      "fd00::3 dev wlan0 lladdr aa:bb:cc:dd:ee:03 DELAY\n"
                                      "fd00::4 dev wlan0 lladdr aa:bb:cc:dd:ee:04 PROBE\n")
        self.assertEqual({a: fresh for a, (_, fresh) in found.items()},
                         {"fd00::1": "fresh", "fd00::2": "stale", "fd00::3": "fresh", "fd00::4": "fresh"})

    def test_failed_and_unfinished_ipv6_neighbours_are_left_out_even_with_a_hardware_address(self):
        found = self.linux_neighbours("fd00::5 dev wlan0 lladdr aa:bb:cc:dd:ee:05 FAILED\n"
                                      "fd00::6 dev wlan0 lladdr aa:bb:cc:dd:ee:06 INCOMPLETE\n"
                                      "fd00::7 dev wlan0 INCOMPLETE\n")
        self.assertEqual(found, {})

    def test_an_ipv6_address_listed_twice_keeps_its_reachable_entry_not_its_stale_one(self):
        for lines in (("fe80::9 dev wlan0 lladdr aa:bb:cc:dd:ee:09 REACHABLE\n", "fe80::9 dev eth0 lladdr aa:bb:cc:dd:ee:10 STALE\n"),
                      ("fe80::9 dev eth0 lladdr aa:bb:cc:dd:ee:10 STALE\n", "fe80::9 dev wlan0 lladdr aa:bb:cc:dd:ee:09 REACHABLE\n")):
            self.assertEqual(self.linux_neighbours("".join(lines)), {"fe80::9": ("aa:bb:cc:dd:ee:09", "fresh")})

    def test_an_ipv6_neighbour_table_that_cannot_be_read_is_not_an_empty_one(self):
        self.assertIsNone(self.linux_neighbours("", code=1))
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/if_inet6"), \
                mock.patch.object(server.subprocess, "run", side_effect=FileNotFoundError("no ip tool")):
            self.assertIsNone(server.ipv6_neighbour_table())
            self.assertEqual(server.ipv6_neighbours(), {})

    def test_the_view_says_when_the_ipv6_neighbour_table_cannot_be_read(self):
        self.view({KID: ("aa:bb:cc:dd:ee:01", "fresh")}, None)
        self.assertEqual((server.S.v6_devices, server.S.v6_neighbours_ok), ({}, False))
        self.assertIs(server.ipv6_dns_view()["neighbours_ok"], False)

    def test_the_view_says_when_the_ipv6_neighbour_table_was_read(self):
        self.view({}, {})
        self.assertIs(server.ipv6_dns_view()["neighbours_ok"], True)

    # The TV that moved from .65 to .67: Linux keeps the stale entry at .65 for a long time.
    TV_MAC, TV_OLD, TV_NEW, TV_V6 = "aa:bb:cc:dd:ee:65", "192.168.1.65", "192.168.1.67", "fd00::65"

    def test_a_stale_ipv4_entry_never_beats_a_reachable_one_whichever_is_listed_last(self):
        for order in ((self.TV_OLD, self.TV_NEW), (self.TV_NEW, self.TV_OLD)):
            table = {ip: (self.TV_MAC, "fresh" if ip == self.TV_NEW else "stale") for ip in order}
            self.view(table, {self.TV_V6: (self.TV_MAC, "stale")})
            self.assertEqual(server.S.v6_devices, {self.TV_V6: self.TV_NEW}, order)

    def test_a_stale_ipv4_entry_never_beats_one_of_unknown_freshness(self):
        self.view({self.TV_NEW: (self.TV_MAC, ""), self.TV_OLD: (self.TV_MAC, "stale")}, {self.TV_V6: (self.TV_MAC, "fresh")})
        self.assertEqual(server.S.v6_devices, {self.TV_V6: self.TV_NEW})

    def test_a_stale_ipv4_entry_still_beats_the_last_scan(self):
        server.sql("INSERT OR REPLACE INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)",
                   (self.TV_OLD, self.TV_MAC, "", time.time()), commit=True)
        self.addCleanup(server.sql, "DELETE FROM seen WHERE ip=?", (self.TV_OLD,), True)
        self.view({self.TV_NEW: (self.TV_MAC, "stale")}, {self.TV_V6: (self.TV_MAC, "fresh")})
        self.assertEqual(server.S.v6_devices, {self.TV_V6: self.TV_NEW})

    def test_between_two_equally_fresh_ipv4_entries_the_one_holding_the_devices_rules_wins(self):
        with mock.patch.object(server.S, "dev_mac", {self.TV_NEW: self.TV_MAC}):
            self.view({self.TV_OLD: (self.TV_MAC, "fresh"), self.TV_NEW: (self.TV_MAC, "fresh")},
                      {self.TV_V6: (self.TV_MAC, "fresh")})
        self.assertEqual(server.S.v6_devices, {self.TV_V6: self.TV_NEW})

    def test_between_two_equally_fresh_ipv4_entries_with_no_rules_the_answer_is_the_same_every_time(self):
        for order in ((self.TV_OLD, self.TV_NEW), (self.TV_NEW, self.TV_OLD)):
            self.view({ip: (self.TV_MAC, "fresh") for ip in order}, {self.TV_V6: (self.TV_MAC, "fresh")})
            self.assertEqual(server.S.v6_devices, {self.TV_V6: self.TV_OLD}, order)

    # A range extender shows the three devices behind it under its own hardware address.
    EXTENDER = "aa:bb:cc:dd:ee:70"
    BEHIND_V4 = ("192.168.1.70", "192.168.1.71", "192.168.1.72")
    BEHIND_V6 = ("fe80::a", "fe80::b", "fe80::c")

    def behind_an_extender(self):
        """Work out the IPv6 view of a home where three devices sit behind a known range extender
        and the child's phone (one IPv6 address, fd00::23) does not."""
        self.addCleanup(setattr, server.S, "shared_macs", server.S.shared_macs)
        server.S.shared_macs = {self.EXTENDER}
        v4 = {ip: (self.EXTENDER, "fresh") for ip in self.BEHIND_V4}
        v4[KID] = ("aa:bb:cc:dd:ee:01", "fresh")
        v6 = {addr: (self.EXTENDER, "fresh") for addr in self.BEHIND_V6}
        v6["fd00::23"] = ("aa:bb:cc:dd:ee:01", "fresh")
        self.view(v4, v6)

    def test_ipv6_addresses_behind_a_range_extender_each_count_against_a_share_of_their_own(self):
        self.behind_an_extender()
        self.assertEqual([server.share_key(addr) for addr in self.BEHIND_V6], list(self.BEHIND_V6))

    def test_one_busy_device_behind_a_range_extender_does_not_use_up_the_others_lookups(self):
        self.behind_an_extender()
        shares = server.Shares()
        for _ in range(server.MAX_DNS_PER_DEVICE):
            self.assertTrue(shares.take(server.share_key(self.BEHIND_V6[0]), server.MAX_DNS_PER_DEVICE))
        self.assertFalse(shares.take(server.share_key(self.BEHIND_V6[0]), server.MAX_DNS_PER_DEVICE))
        for other in self.BEHIND_V6[1:] + self.BEHIND_V4:
            self.assertTrue(shares.take(server.share_key(other), server.MAX_DNS_PER_DEVICE), other)

    def test_an_ordinary_devices_ipv6_address_still_counts_against_that_devices_share(self):
        self.behind_an_extender()
        self.assertEqual(server.share_key("fd00::23"), KID)

    def test_a_hardware_address_not_yet_known_as_a_range_extender_is_still_counted_as_one_device(self):
        self.behind_an_extender()
        server.S.shared_macs = set()                 # seen at several numbers, but not often enough yet
        self.view({ip: (self.EXTENDER, "fresh") for ip in self.BEHIND_V4},
                  {addr: (self.EXTENDER, "fresh") for addr in self.BEHIND_V6})
        self.assertEqual({server.share_key(addr) for addr in self.BEHIND_V6}, {self.BEHIND_V4[0]})

    def test_an_ipv6_address_behind_a_range_extender_keeps_the_rules_it_had_before(self):
        # Only whose share is counted changes here: which rules apply is the next part of the work.
        self.behind_an_extender()
        self.assertEqual({server.S.v6_devices[addr] for addr in self.BEHIND_V6}, {self.BEHIND_V4[0]})

    def test_the_addresses_behind_a_range_extender_are_forgotten_when_they_leave(self):
        self.behind_an_extender()
        self.view({}, {})
        self.assertEqual(server.S.v6_shared, frozenset())

    def test_an_ipv4_address_listed_twice_keeps_its_reachable_entry_not_its_stale_one(self):
        text = ("192.168.1.67 dev wlan0 lladdr aa:bb:cc:dd:ee:67 REACHABLE\n"
                "192.168.1.67 dev eth0 lladdr aa:bb:cc:dd:ee:99 STALE\n")
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/arp"), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text, returncode=0)):
            self.assertEqual(server.neighbour_table(), {"192.168.1.67": ("aa:bb:cc:dd:ee:67", "fresh")})

    def test_this_computers_public_ipv6_range_is_worked_out_from_its_own_addresses(self):
        text = ("\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n"
                "\tinet6 2001:db8:1:2::60 prefixlen 128 dynamic\n"
                "\tinet6 fd00::60 prefixlen 64 autoconf\n")
        with mock.patch.object(server.os.path, "exists", lambda p: False), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text)):
            own, ranges, _ = server.own_ipv6()
        self.assertEqual(own, {"fe80::1", "2001:db8:1:2::60", "fd00::60"})
        self.assertEqual(ranges, [server.ipaddress.IPv6Network("2001:db8:1:2::/64")])

    def test_a_lasting_unique_local_address_is_the_one_given_to_devices(self):
        text = ("\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0x1\n"
                "\tinet6 2001:db8:1:2::60 prefixlen 64 autoconf secured\n"
                "\tinet6 fd00::60 prefixlen 64 autoconf secured\n")
        with mock.patch.object(server.os.path, "exists", lambda p: False), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text)):
            self.assertEqual(server.own_ipv6()[2], "fd00::60")

    def test_a_temporary_address_is_never_given_to_devices(self):
        text = ("\tinet6 2001:db8:1:2::77 prefixlen 64 autoconf temporary\n"
                "\tinet6 2001:db8:1:2::60 prefixlen 64 autoconf secured\n")
        with mock.patch.object(server.os.path, "exists", lambda p: False), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text)):
            self.assertEqual(server.own_ipv6()[2], "2001:db8:1:2::60")

    def test_temporary_and_link_local_addresses_on_linux_are_never_given_to_devices(self):
        lines = ("20010db8000100020000000000000077 03 40 00 01   wlan0\n"      # temporary
                 "fe800000000000000000000000000060 03 40 20 80   wlan0\n")     # link-local
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/if_inet6"), \
                mock.patch("builtins.open", mock.mock_open(read_data=lines)):
            own, ranges, for_devices = server.own_ipv6()
        self.assertEqual((len(own), for_devices), (2, ""))

    def test_a_lasting_public_address_on_linux_is_given_to_devices(self):
        lines = "20010db8000100020000000000000060 03 40 00 00   wlan0\n"
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/if_inet6"), \
                mock.patch("builtins.open", mock.mock_open(read_data=lines)):
            self.assertEqual(server.own_ipv6()[2], "2001:db8:1:2::60")

    def test_the_address_for_devices_is_kept_with_the_ipv6_view(self):
        self.view({}, {}, own=(set(), [], "fd00::60"))
        self.assertEqual(server.S.v6_dns, "fd00::60")


class UnmatchedIPv6WhileADeviceIsTreatedDifferently(Base):
    """An IPv6 lookup that can't be matched to a device is refused while any device is treated
    differently from the whole house, including the two cases that carry no rule of their own."""

    PHONE_V6 = "fd00::abcd"

    def refused(self, qtype=1):
        """Is one unmatched IPv6 lookup refused?"""
        return server.answer_query(query("www.bbc.co.uk", qtype), self.PHONE_V6, fake_answer)[3] & 15 == 5

    def test_with_nothing_set_for_any_device_an_unmatched_ipv6_lookup_is_answered(self):
        self.assertFalse(server.device_rules_exist())
        self.assertFalse(self.refused())

    def test_a_device_with_only_cut_live_connections_makes_unmatched_ipv6_lookups_refused(self):
        server.S.enforced = {KID}
        self.assertTrue(self.refused())

    def test_an_unmatched_ipv6_lookup_gets_no_ipv6_addresses_back_while_a_device_has_cut_live_connections(self):
        server.S.enforced = {KID}
        self.assertTrue(self.refused(qtype=28))

    def test_a_member_of_a_group_with_no_rules_makes_unmatched_ipv6_lookups_refused(self):
        with mock.patch.object(server.S, "dev_group", {KID: 7}):
            self.assertEqual(server.S.svc_blocks, {})
            self.assertTrue(self.refused())

    def test_a_new_device_held_in_the_new_device_group_makes_unmatched_ipv6_lookups_refused(self):
        with mock.patch.object(server.S, "guest_group", {KID: ("aa:bb:cc:dd:ee:09", 7)}):
            self.assertTrue(self.refused())

    def test_an_unmatched_lookup_for_another_dns_service_is_refused_while_a_device_is_in_a_rule_less_group(self):
        with mock.patch.object(server.S, "dev_group", {KID: 7}):
            resp = server.answer_query(query("dns.google"), self.PHONE_V6, fake_answer)
        self.assertEqual(resp[3] & 15, 5)


class QuickLookForNewIPv6Addresses(Base):
    """A lookup from an IPv6 address no device is matched to asks for a look at the neighbours at
    once, and waits a moment for it, so a phone's new address is unmatched for seconds, not a
    minute. No real watcher thread or tool is run here."""

    PHONE_V6 = "fd00::abcd"

    def setUp(self):
        super().setUp()
        server.S.v6_watching = True
        self.addCleanup(setattr, server.S, "v6_watching", False)
        drain_log()

    def looked(self, matched=None):
        """A stand-in for v6_looked whose wait is "the watcher finished a look", which matched
        the phone to `matched` if given."""
        waited = mock.MagicMock()

        def wait_for(done, timeout):
            """Pretend the look happened while the lookup waited."""
            if matched:
                server.S.v6_devices = {self.PHONE_V6: matched}
            return True
        waited.wait_for.side_effect = wait_for
        return waited

    def test_a_lookup_from_an_unknown_ipv6_address_asks_for_a_look_at_once(self):
        with mock.patch.object(server, "v6_looked", self.looked()):
            server.matched_ipv6_device(self.PHONE_V6)
        self.assertTrue(server.v6_wanted.is_set())

    def test_a_lookup_from_a_matched_ipv6_address_asks_for_nothing(self):
        server.S.v6_devices = {self.PHONE_V6: KID}
        self.assertEqual(server.matched_ipv6_device(self.PHONE_V6), KID)
        self.assertFalse(server.v6_wanted.is_set())

    def test_nothing_is_asked_for_while_the_watcher_is_not_running(self):
        server.S.v6_watching = False
        self.assertIsNone(server.matched_ipv6_device(self.PHONE_V6))
        self.assertFalse(server.v6_wanted.is_set())

    def test_a_lookup_matched_by_the_quick_look_gets_its_devices_rules(self):
        server.set_internet_off("device:" + KID, True)
        with mock.patch.object(server, "v6_looked", self.looked(matched=KID)):
            resp = server.answer_query(query("www.bbc.co.uk"), self.PHONE_V6, fake_answer)
        self.assertEqual(resp[-4:], bytes(4))                         # blocked as the phone, not refused
        self.assertEqual(drain_log()[0][1], KID)

    def test_a_lookup_still_unmatched_after_the_quick_look_is_refused_while_device_rules_exist(self):
        server.set_internet_off("device:" + KID, True)
        with mock.patch.object(server, "v6_looked", self.looked()):
            resp = server.answer_query(query("www.bbc.co.uk"), self.PHONE_V6, fake_answer)
        self.assertEqual(resp[3] & 15, 5)

    def test_a_lookup_waits_no_longer_than_the_limit_for_a_look_that_never_comes(self):
        started = time.monotonic()
        with mock.patch.object(server, "V6_ANSWER_WAIT", 0.05):
            self.assertIsNone(server.matched_ipv6_device(self.PHONE_V6))
        self.assertLess(time.monotonic() - started, 1)

    def test_a_lookup_is_not_held_up_when_the_watcher_looked_a_moment_ago(self):
        server.S.v6_looked_at = time.monotonic()
        waited = self.looked(matched=KID)
        with mock.patch.object(server, "v6_looked", waited):
            self.assertIsNone(server.matched_ipv6_device(self.PHONE_V6))
        waited.wait_for.assert_not_called()
        self.assertTrue(server.v6_wanted.is_set())                    # the look is still asked for

    def test_a_lookup_is_not_held_up_when_enough_lookups_are_waiting_already(self):
        full = threading.BoundedSemaphore(1)
        full.acquire()
        waited = self.looked(matched=KID)
        with mock.patch.object(server, "v6_waiting", full), mock.patch.object(server, "v6_looked", waited):
            self.assertIsNone(server.matched_ipv6_device(self.PHONE_V6))
        waited.wait_for.assert_not_called()

    def ask_after_each_look(self, address, times):
        """Ask for a look `times` times, the watcher taking up each ask before the next."""
        out = []
        for _ in range(times):
            out.append(server.ask_for_ipv6_look(address))
            server.v6_wanted.clear()                                  # as the watcher does before it looks
        return out

    def test_one_address_may_set_off_only_so_many_looks_a_minute(self):
        asked = self.ask_after_each_look(self.PHONE_V6, server.V6_ASKS_PER_ADDRESS + 2)
        self.assertEqual(asked, [True] * server.V6_ASKS_PER_ADDRESS + [False, False])
        self.assertFalse(server.v6_wanted.is_set())
        self.assertTrue(server.ask_for_ipv6_look("fd00::beef"))       # another address still may

    def test_a_burst_of_lookups_from_one_address_sets_off_one_look_not_many(self):
        for _ in range(10):
            self.assertTrue(server.ask_for_ipv6_look(self.PHONE_V6))
        self.assertEqual(server.v6_askers[self.PHONE_V6][0], 1)

    def test_a_lookup_arriving_while_a_look_is_under_way_waits_for_it_even_with_its_asks_used_up(self):
        self.ask_after_each_look(self.PHONE_V6, server.V6_ASKS_PER_ADDRESS)
        server.S.v6_looking = True
        self.addCleanup(setattr, server.S, "v6_looking", False)
        with mock.patch.object(server, "v6_looked", self.looked(matched=KID)):
            self.assertEqual(server.matched_ipv6_device(self.PHONE_V6), KID)

    def test_a_lookup_whose_address_has_used_up_its_asks_is_not_held_up_when_no_look_is_coming(self):
        self.ask_after_each_look(self.PHONE_V6, server.V6_ASKS_PER_ADDRESS)
        waited = self.looked(matched=KID)
        with mock.patch.object(server, "v6_looked", waited):
            self.assertIsNone(server.matched_ipv6_device(self.PHONE_V6))
        waited.wait_for.assert_not_called()

    def test_an_address_may_ask_again_once_the_minute_is_over(self):
        self.ask_after_each_look(self.PHONE_V6, server.V6_ASKS_PER_ADDRESS)
        server.v6_askers[self.PHONE_V6][1] -= server.IPV6_RECHECK + 1
        self.assertTrue(server.ask_for_ipv6_look(self.PHONE_V6))

    def test_the_count_of_asking_addresses_never_grows_without_limit(self):
        with mock.patch.object(server, "V6_MAX_ASKERS", 4):
            for i in range(20):
                self.ask_after_each_look("fd00::%x" % (i + 1), 1)
            self.assertLessEqual(len(server.v6_askers), 4)

    def watch(self, asked, looks=2):
        """Run the watcher for `looks` looks with a stand-in clock, flag and view; returns (the
        waits it made for the flag, the sleeps it took)."""
        clock = mock.Mock(wraps=time)
        clock.sleep = mock.Mock()
        flag = mock.Mock()
        flag.wait.return_value = asked
        with mock.patch.object(server, "refresh_ipv6_view", side_effect=[None] * looks + [KeyboardInterrupt()]), \
                mock.patch.object(server, "time", clock), mock.patch.object(server, "v6_wanted", flag):
            with self.assertRaises(KeyboardInterrupt):
                server.ipv6_watcher()
        return [c[0][0] for c in flag.wait.call_args_list], [c[0][0] for c in clock.sleep.call_args_list]

    def test_the_watcher_looks_every_minute_when_nothing_asks(self):
        waits, sleeps = self.watch(asked=False)
        self.assertEqual((waits, sleeps), ([server.IPV6_RECHECK] * 2, []))

    def test_the_watcher_never_looks_twice_within_two_seconds_however_many_lookups_ask(self):
        _, sleeps = self.watch(asked=True)
        self.assertEqual(len(sleeps), 2)
        for gap in sleeps:
            self.assertGreater(gap, server.V6_QUICK_GAP - 0.5)
            self.assertLessEqual(gap, server.V6_QUICK_GAP)

    def test_the_watcher_looks_at_once_when_asked_long_after_its_last_look(self):
        clock = mock.Mock(wraps=time)
        clock.sleep = mock.Mock()
        clock.monotonic = mock.Mock(side_effect=[100.0, 160.0, 200.0, 260.0, 300.0])   # each look, then each wake
        flag = mock.Mock()
        flag.wait.return_value = True
        with mock.patch.object(server, "refresh_ipv6_view", side_effect=[None, None, KeyboardInterrupt()]), \
                mock.patch.object(server, "time", clock), mock.patch.object(server, "v6_wanted", flag):
            with self.assertRaises(KeyboardInterrupt):
                server.ipv6_watcher()
        self.assertEqual([c[0][0] for c in clock.sleep.call_args_list], [0.0, 0.0])

    def watch_the_real_flag(self, ask_during_first_look):
        """Run the watcher for two looks against the real "look now" flag, which a lookup set
        before the first; returns (whether the ask was still standing as each look began, how
        many sleeps it took). A lookup asks again during the first look if `ask_during_first_look`."""
        standing = []

        def look():
            """Note whether the ask is still standing, ask again if told to, stop at the second look."""
            standing.append(server.v6_wanted.is_set())
            if len(standing) == 2:
                raise KeyboardInterrupt()
            if ask_during_first_look:
                server.v6_wanted.set()
        clock = mock.Mock(wraps=time)
        clock.sleep = mock.Mock()
        server.v6_wanted.set()
        self.addCleanup(server.v6_wanted.clear)
        with mock.patch.object(server, "refresh_ipv6_view", side_effect=look), \
                mock.patch.object(server, "time", clock), mock.patch.object(server, "IPV6_RECHECK", 0.01):
            with self.assertRaises(KeyboardInterrupt):
                server.ipv6_watcher()
        return standing, clock.sleep.call_count

    def test_the_watcher_takes_up_an_ask_when_it_looks_so_one_ask_sets_off_one_look(self):
        standing, sleeps = self.watch_the_real_flag(ask_during_first_look=False)
        self.assertEqual(standing, [False, False])
        self.assertEqual(sleeps, 0)                  # the next look waited the full time, not the quick gap
        self.assertFalse(server.v6_wanted.is_set())

    def test_an_ask_that_arrives_during_a_look_earns_another_look(self):
        standing, sleeps = self.watch_the_real_flag(ask_during_first_look=True)
        self.assertEqual(standing, [False, False])
        self.assertEqual(sleeps, 1)                  # woken by the ask, so only the quick gap was waited

    def test_the_watcher_says_it_is_running_only_while_it_is(self):
        server.S.v6_watching = False
        seen = []

        def look():
            """Note whether the watcher says it is running, then stop it."""
            seen.append(server.S.v6_watching)
            raise KeyboardInterrupt()
        with mock.patch.object(server, "refresh_ipv6_view", side_effect=look):
            with self.assertRaises(KeyboardInterrupt):
                server.ipv6_watcher()
        self.assertEqual((seen, server.S.v6_watching), ([True], False))

    def test_a_look_says_it_is_under_way_only_while_it_is(self):
        seen = []
        with mock.patch.object(server, "refresh_ipv6_view", side_effect=lambda: seen.append(server.S.v6_looking)):
            server.ipv6_look()
        self.assertEqual((seen, server.S.v6_looking), ([True], False))

    def test_waiting_lookups_are_told_when_a_look_finishes_even_if_it_failed(self):
        before = server.S.v6_round
        with mock.patch.object(server, "refresh_ipv6_view", side_effect=RuntimeError("no tools")), \
                mock.patch("builtins.print"):
            server.ipv6_look()
        self.assertEqual(server.S.v6_round, before + 1)
        self.assertIsNotNone(server.S.v6_looked_at)
        self.assertFalse(server.S.v6_looking)

    def test_a_waiting_lookup_wakes_as_soon_as_the_real_look_finishes(self):
        def look():
            """The watcher's look: match the phone, as the neighbour table now would."""
            server.S.v6_devices = {self.PHONE_V6: KID}
        with mock.patch.object(server, "refresh_ipv6_view", side_effect=look), \
                mock.patch.object(server, "V6_ANSWER_WAIT", 5):
            threading.Timer(0.05, server.ipv6_look).start()
            started = time.monotonic()
            self.assertEqual(server.matched_ipv6_device(self.PHONE_V6), KID)
        self.assertLess(time.monotonic() - started, 3)

    def test_decision_is_never_asked_to_wait_for_a_look(self):
        with mock.patch.object(server, "matched_ipv6_device", side_effect=AssertionError("waited")), \
                mock.patch.object(server, "ask_for_ipv6_look", side_effect=AssertionError("asked")):
            server.decision("www.bbc.co.uk", self.PHONE_V6)


class AddressesBuiltFromAHardwareAddress(Base):
    """An IPv6 address built from a hardware address (the EUI-64 form) is a hint, never proof."""

    KID_MAC = "aa:bb:cc:dd:ee:01"
    KID_BUILT = "2001:db8:1:2:a8bb:ccff:fedd:ee01"          # built from KID_MAC: aa with one bit flipped is a8

    def test_the_hardware_address_is_read_back_with_its_flipped_bit(self):
        self.assertEqual(server.eui64_mac("2001:db8::211:22ff:fe33:4455"), "00:11:22:33:44:55")
        self.assertEqual(server.eui64_mac("fe80::11:22ff:fe33:4455"), "02:11:22:33:44:55")
        self.assertEqual(server.eui64_mac(self.KID_BUILT), self.KID_MAC)

    def test_a_zone_suffix_does_not_stop_the_hardware_address_being_read(self):
        self.assertEqual(server.eui64_mac("fe80::211:22ff:fe33:4455%wlan0"), "00:11:22:33:44:55")

    def test_an_address_not_built_that_way_gives_no_hardware_address(self):
        for address in ("2001:db8::1", "2001:db8::fffe:0:1", "2001:db8:ff:fe00::1", "192.168.1.23", "junk", ""):
            self.assertEqual(server.eui64_mac(address), "", address)

    def test_an_address_built_from_a_group_or_empty_hardware_address_gives_none(self):
        self.assertEqual(server.eui64_mac("fe80::200:ff:fe00:0"), "")           # 00:00:00:00:00:00
        self.assertEqual(server.eui64_mac("fe80::311:22ff:fe33:4455"), "")      # 01:11:..., a group address

    def view(self, v4, v6):
        """Work out the IPv6 view from stand-in neighbour tables."""
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbour_table", return_value=v4), \
                mock.patch.object(server, "ipv6_neighbour_table", return_value=v6):
            server.refresh_ipv6_view()

    def test_an_address_built_from_another_devices_hardware_address_does_not_get_that_devices_rules(self):
        # The grown-up's laptop makes itself an address that looks built from the child's phone.
        self.view({KID: (self.KID_MAC, "fresh"), ADULT: ("aa:bb:cc:dd:ee:02", "fresh")},
                  {self.KID_BUILT: ("aa:bb:cc:dd:ee:02", "fresh")})
        self.assertEqual(server.S.v6_devices, {self.KID_BUILT: ADULT})

    def test_an_address_built_from_a_known_hardware_address_is_not_matched_without_the_neighbour_table(self):
        self.view({KID: (self.KID_MAC, "fresh")}, {})
        self.assertEqual(server.S.v6_devices, {})
        server.set_internet_off("device:" + ADULT, True)
        resp = server.answer_query(query("www.bbc.co.uk"), self.KID_BUILT, fake_answer)
        self.assertEqual(resp[3] & 15, 5)                              # refused as unknown, not judged as the phone

    def devices(self):
        """The device list after one lookup filed under the built address and a scan that found the phone."""
        server.sql("INSERT INTO queries(ts, client, domain, blocked) VALUES(?,?,?,0)",
                   (time.time(), self.KID_BUILT, "www.bbc.co.uk"), commit=True)
        server.sql("INSERT OR REPLACE INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)", (KID, self.KID_MAC, "", time.time()), commit=True)
        self.addCleanup(server.sql, "DELETE FROM seen WHERE ip=?", (KID,), True)
        return {d["ip"]: d for d in server.api_devices()}

    def test_the_device_list_hints_which_device_an_unmatched_built_address_probably_is(self):
        self.assertEqual(self.devices()[self.KID_BUILT]["same_as"], KID)

    def test_the_hint_gives_the_unmatched_card_none_of_that_devices_rules_or_hardware_address(self):
        server.set_internet_off("device:" + KID, True)
        card = self.devices()[self.KID_BUILT]
        self.assertEqual((card["off"], card["mac"]), (False, ""))

    def test_there_is_no_hint_when_the_hardware_address_has_not_been_seen(self):
        server.sql("INSERT INTO queries(ts, client, domain, blocked) VALUES(?,?,?,0)",
                   (time.time(), self.KID_BUILT, "www.bbc.co.uk"), commit=True)
        self.assertEqual({d["ip"]: d for d in server.api_devices()}[self.KID_BUILT]["same_as"], "")

    def test_an_ipv4_card_never_carries_the_hint(self):
        self.assertEqual(self.devices()[KID]["same_as"], "")


def router_advert(*options):
    """A router announcement (ICMPv6 type 134) as it arrives on the socket: the 16-byte start, then
    the given options, each already in its on-the-wire form."""
    return bytes([134, 0, 0, 0, 64, 0]) + struct.pack(">HII", 1800, 0, 0) + b"".join(options)


def rdnss(lifetime, *addresses):
    """A DNS server option (type 25) naming the given IPv6 addresses for `lifetime` seconds."""
    body = b"".join(server.ipaddress.IPv6Address(a).packed for a in addresses)
    return bytes([25, 1 + 2 * len(addresses), 0, 0]) + struct.pack(">I", lifetime) + body


def prefix(valid, network):
    """An address range option (type 3) handing out `network` for `valid` seconds."""
    net = server.ipaddress.IPv6Network(network)
    return (bytes([3, 4, net.prefixlen, 0xC0]) + struct.pack(">III", valid, valid, 0)
            + net.network_address.packed)


class RouterAnnouncements(Base):
    """The router's IPv6 announcements, read to spot it telling devices to use its own IPv6 DNS
    server. Nothing here opens a real socket: the listener is handed stand-ins."""

    HUB = "fe80::1"
    PI = "2001:db8:1:2::60"

    def listen(self, packets, sock=None, hops=255):
        """Run the listener over these (data, source) packets, each arriving with this hop limit
        (None: the system noted none), then stop it."""
        sock = sock or mock.Mock()
        extra = [] if hops is None else [(server.socket.IPPROTO_IPV6, server.IPV6_HOPLIMIT, struct.pack("=i", hops))]
        sock.recvmsg.side_effect = [(data, extra, 0, source) for data, source in packets] + [KeyboardInterrupt()]
        with self.assertRaises(KeyboardInterrupt):
            server.router_advert_listener(sock)

    def test_a_dns_server_named_in_a_router_announcement_is_read(self):
        self.assertEqual(server.parse_router_advert(router_advert(rdnss(1200, self.HUB))), [(self.HUB, 1200)])

    def test_several_dns_servers_and_other_options_are_read(self):
        prefix_info = bytes([3, 4]) + bytes(30)                     # a prefix option, which is skipped
        link_addr = bytes([1, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        data = router_advert(link_addr, prefix_info, rdnss(600, self.HUB, "fd00::53"), rdnss(300, "2001:db8::53"))
        self.assertEqual(server.parse_router_advert(data),
                         [(self.HUB, 600), ("fd00::53", 600), ("2001:db8::53", 300)])

    def test_an_announcement_without_a_dns_server_gives_an_empty_list(self):
        self.assertEqual(server.parse_router_advert(router_advert()), [])

    def test_a_message_that_is_not_a_router_announcement_is_ignored(self):
        data = bytearray(router_advert(rdnss(600, self.HUB)))
        data[0] = 135                                               # a router question, not an announcement
        self.assertIsNone(server.parse_router_advert(bytes(data)))
        self.assertIsNone(server.parse_router_advert(b"\x86\x00\x00"))

    def test_a_cut_short_announcement_is_ignored(self):
        data = router_advert(rdnss(600, self.HUB))
        for size in (len(data) - 1, len(data) - 16, 17):
            self.assertIsNone(server.parse_router_advert(data[:size]), size)

    def test_an_option_of_length_zero_is_ignored(self):
        self.assertIsNone(server.parse_router_advert(router_advert(bytes([25, 0]) + bytes(6))))

    def test_a_dns_server_option_of_the_wrong_length_is_ignored(self):
        too_short = bytes([25, 1]) + bytes(6)
        even = bytes([25, 2]) + bytes(14)
        self.assertIsNone(server.parse_router_advert(router_advert(too_short)))
        self.assertIsNone(server.parse_router_advert(router_advert(even)))

    def test_an_option_longer_than_the_message_is_ignored(self):
        data = bytearray(router_advert(rdnss(600, self.HUB)))
        data[17] = 9                                                # claims 72 bytes; only 24 arrived
        self.assertIsNone(server.parse_router_advert(bytes(data)))

    def test_many_options_are_read_without_trouble(self):
        data = router_advert(*[rdnss(600, "2001:db8::%x" % i) for i in range(1, 200)])
        self.assertEqual(len(server.parse_router_advert(data)), 199)

    def test_addresses_no_device_could_use_for_dns_are_skipped(self):
        data = router_advert(rdnss(600, "ff02::1", "::", "::1", "::ffff:8.8.8.8", self.HUB))
        self.assertEqual(server.parse_router_advert(data), [(self.HUB, 600)])

    def test_a_server_named_with_lifetime_zero_is_forgotten(self):
        server.note_router_dns([(self.HUB, 600)], 1000.0)
        server.note_router_dns([(self.HUB, 0)], 1001.0)
        self.assertEqual(server.S.router_v6_dns, {})

    def test_a_named_server_is_kept_for_an_hour_at_most(self):
        server.note_router_dns([(self.HUB, 0xFFFFFFFF)], 1000.0)
        self.assertEqual(server.S.router_v6_dns, {self.HUB: 1000.0 + server.RA_HOLD_MAX})
        self.assertEqual(server.ipv6_dns_view(1000.0 + server.RA_HOLD_MAX + 1)["router_dns"], [])

    def test_only_so_many_named_servers_are_kept(self):
        server.note_router_dns([("2001:db8::%x" % i, 600 + i) for i in range(1, 50)], 1000.0)
        self.assertEqual(len(server.S.router_v6_dns), server.RA_MAX_SERVERS)
        self.assertIn("2001:db8::31", server.S.router_v6_dns)      # the longest-lived are the ones kept

    def test_the_warning_list_names_a_router_server_that_is_not_this_computer(self):
        server.note_router_dns([(self.HUB, 600)], time.time())
        view = server.ipv6_dns_view()
        self.assertEqual((view["router_dns"], view["router_dns_not_ours"]), ([self.HUB], [self.HUB]))

    def test_the_warning_list_is_empty_when_the_router_names_only_this_computer(self):
        server.S.v6_own = {self.PI}
        with mock.patch.object(server.S, "dns_ipv6", True):
            server.note_router_dns([(self.PI, 600)], time.time())
            self.assertEqual(server.ipv6_dns_view()["router_dns_not_ours"], [])

    def test_this_computer_counts_as_another_server_while_it_is_not_taking_ipv6_lookups(self):
        server.S.v6_own = {self.PI}
        with mock.patch.object(server.S, "dns_ipv6", False):
            server.note_router_dns([(self.PI, 600)], time.time())
            self.assertEqual(server.ipv6_dns_view()["router_dns_not_ours"], [self.PI])

    def test_the_warning_list_is_empty_when_nothing_was_heard(self):
        self.assertEqual(server.ipv6_dns_view()["router_dns_not_ours"], [])

    def test_the_status_carries_the_ipv6_address_for_devices_when_known(self):
        server.S.v6_dns = "fd12:3456::60"
        with mock.patch.object(server.S, "dns_ipv6", True):
            self.assertEqual(server.api_status()["ipv6"]["dns_address"], "fd12:3456::60")

    def test_no_ipv6_address_is_offered_while_ipv6_lookups_are_not_taken(self):
        server.S.v6_dns = "fd12:3456::60"
        with mock.patch.object(server.S, "dns_ipv6", False):
            self.assertEqual(server.api_status()["ipv6"]["dns_address"], "")

    def test_the_listener_records_a_router_announcement(self):
        self.listen([(router_advert(rdnss(600, self.HUB)), ("fe80::1%wlan0", 0, 0, 3))])
        self.assertIn(self.HUB, server.S.router_v6_dns)
        self.assertIsNotNone(server.S.ra_heard)

    def test_the_listener_ignores_announcements_whose_hop_limit_is_not_255(self):
        self.listen([(router_advert(rdnss(600, self.HUB)), ("fe80::1%wlan0", 0, 0, 3))], hops=64)
        self.assertEqual((server.S.router_v6_dns, server.S.ra_heard), ({}, None))

    def test_the_listener_accepts_announcements_when_the_system_gives_no_hop_limit(self):
        self.listen([(router_advert(rdnss(600, self.HUB)), ("fe80::1%wlan0", 0, 0, 3))], hops=None)
        self.assertIn(self.HUB, server.S.router_v6_dns)

    def test_the_socket_asks_for_each_announcements_hop_limit(self):
        sock = mock.Mock()
        with mock.patch.object(server.os.path, "exists", return_value=True), \
                mock.patch.object(server.socket, "socket", return_value=sock):
            self.assertIs(server.open_ra_socket(), sock)
        sock.setsockopt.assert_any_call(server.socket.IPPROTO_IPV6, server.IPV6_RECVHOPLIMIT, 1)

    def test_an_announcement_with_router_lifetime_zero_does_not_mean_the_network_has_ipv6(self):
        thread_router = bytearray(router_advert(prefix(0xFFFFFFFF, "fd11:22:33:44::/64")))
        thread_router[6:8] = bytes(2)                               # "not a router for you"
        self.listen([(bytes(thread_router), ("fe80::9%wlan0", 0, 0, 3))])
        self.assertIsNone(server.S.ra_heard)
        self.assertEqual(server.S.router_prefixes, {})
        self.assertFalse(server.ipv6_dns_view()["in_use"])

    def test_a_real_routers_address_range_is_remembered(self):
        self.listen([(router_advert(prefix(7200, "fd00:1::/64")), ("fe80::1%wlan0", 0, 0, 3))])
        self.assertIn(server.ipaddress.IPv6Network("fd00:1::/64"), server.S.router_prefixes)

    def test_a_range_announced_with_router_lifetime_zero_is_read(self):
        found = server.read_router_advert(router_advert(prefix(600, "fd11::/64")))
        self.assertEqual(found["prefixes"], [(server.ipaddress.IPv6Network("fd11::/64"), 600)])
        self.assertEqual(found["lifetime"], 1800)

    def test_a_unique_local_address_outside_every_announced_range_is_not_given_to_devices(self):
        text = "\tinet6 fd11:22:33:44::60 prefixlen 64 autoconf secured\n"
        with mock.patch.object(server.os.path, "exists", lambda p: False), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text)):
            self.assertEqual(server.own_ipv6([server.ipaddress.IPv6Network("fd00:1::/64")])[2], "")
            self.assertEqual(server.own_ipv6([server.ipaddress.IPv6Network("fd11:22:33:44::/64")])[2],
                             "fd11:22:33:44::60")

    HUB_MAC = "aa:bb:cc:dd:ee:ff"
    LINK_ADDR = bytes([1, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])      # option 1: the sender's hardware address

    def test_the_senders_hardware_address_is_read_from_an_announcement(self):
        found = server.read_router_advert(router_advert(self.LINK_ADDR, rdnss(600, self.HUB)))
        self.assertEqual(found["mac"], self.HUB_MAC)

    def test_an_announcement_without_a_hardware_address_gives_an_empty_one(self):
        self.assertEqual(server.read_router_advert(router_advert(rdnss(600, self.HUB)))["mac"], "")

    def test_a_hardware_address_option_of_another_size_is_passed_over_not_misread(self):
        # 16 bytes: not an Ethernet or Wi-Fi address. Its first six bytes, 02:03:04:05:06:07, would
        # be kept as a hardware address if they were misread as one.
        long_one = bytes([1, 2]) + bytes(range(2, 16))
        self.assertEqual(server.clean_mac("02:03:04:05:06:07"), "02:03:04:05:06:07")
        found = server.read_router_advert(router_advert(long_one, rdnss(600, self.HUB)))
        self.assertEqual((found["mac"], found["servers"]), ("", [(self.HUB, 600)]))

    def test_the_first_hardware_address_in_an_announcement_is_the_one_kept(self):
        second = bytes([1, 1, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
        found = server.read_router_advert(router_advert(self.LINK_ADDR, second))
        self.assertEqual(found["mac"], self.HUB_MAC)

    def test_a_group_or_empty_hardware_address_in_an_announcement_is_not_kept(self):
        for raw in (bytes(6), b"\xff" * 6, bytes([0x01, 0, 0x5e, 0, 0, 1])):
            self.assertEqual(server.read_router_advert(router_advert(bytes([1, 1]) + raw))["mac"], "", raw)

    def test_the_listener_keeps_a_real_routers_link_local_address_and_hardware_address(self):
        self.listen([(router_advert(self.LINK_ADDR, rdnss(600, self.HUB)), ("fe80::1%wlan0", 0, 0, 3))])
        self.assertEqual(list(server.S.routers_v6), ["fe80::1"])
        self.assertEqual(server.S.routers_v6["fe80::1"]["mac"], self.HUB_MAC)
        routers = server.ipv6_dns_view()["routers"]
        self.assertEqual([(r["address"], r["mac"]) for r in routers], [("fe80::1", self.HUB_MAC)])

    def test_a_sender_that_is_not_a_router_for_devices_is_not_kept_as_the_hub(self):
        thread_router = bytearray(router_advert(self.LINK_ADDR, prefix(600, "fd11:22:33:44::/64")))
        thread_router[6:8] = bytes(2)                               # router lifetime 0: an Apple TV or HomePod
        self.listen([(bytes(thread_router), ("fe80::9%wlan0", 0, 0, 3))])
        self.assertEqual((server.S.routers_v6, server.ipv6_dns_view()["routers"]), ({}, []))

    def test_an_announcement_without_a_hardware_address_keeps_the_one_that_router_gave_before(self):
        server.note_router_dns([], 1000.0, sender="fe80::1", mac=self.HUB_MAC)
        server.note_router_dns([], 1010.0, sender="fe80::1", mac="")
        self.assertEqual(server.S.routers_v6["fe80::1"], {"mac": self.HUB_MAC, "heard": 1010.0})

    def test_a_router_is_forgotten_an_hour_after_it_was_last_heard(self):
        server.note_router_dns([], 1000.0, sender="fe80::1", mac=self.HUB_MAC)
        self.assertEqual(len(server.ipv6_dns_view(1000.0 + server.RA_HOLD_MAX - 1)["routers"]), 1)
        self.assertEqual(server.ipv6_dns_view(1000.0 + server.RA_HOLD_MAX)["routers"], [])
        server.note_router_dns([], 1000.0 + server.RA_HOLD_MAX, router_lifetime=0)
        self.assertEqual(server.S.routers_v6, {})

    def test_only_so_many_routers_are_kept_and_the_latest_heard_stay(self):
        for i in range(1, 40):
            server.note_router_dns([], 1000.0 + i, sender="fe80::%x" % i, mac=self.HUB_MAC)
        self.assertEqual(len(server.S.routers_v6), server.RA_MAX_SERVERS)
        self.assertIn("fe80::27", server.S.routers_v6)               # 0x27 = 39, the last one heard

    def test_the_most_recently_heard_router_is_listed_first(self):
        server.note_router_dns([], 1000.0, sender="fe80::1", mac=self.HUB_MAC)
        server.note_router_dns([], 1005.0, sender="fe80::2", mac="aa:bb:cc:dd:ee:02")
        self.assertEqual([r["address"] for r in server.ipv6_dns_view(1010.0)["routers"]], ["fe80::2", "fe80::1"])

    def test_the_listener_notes_when_it_began_and_forgets_it_when_it_stops(self):
        began = []
        sock = mock.Mock()

        def receive(*args):
            """Note what the listener says of itself while running, then fail as a lost network would."""
            began.append((server.S.ra_listening, server.S.ra_since))
            raise OSError("network gone")
        sock.recvmsg.side_effect = receive
        with mock.patch("builtins.print"):
            server.router_advert_listener(sock)
        self.assertTrue(began[0][0])
        self.assertIsNotNone(began[0][1])
        self.assertEqual((server.S.ra_listening, server.S.ra_since), (False, None))

    def test_the_listener_ignores_announcements_not_from_a_link_local_address(self):
        self.listen([(router_advert(rdnss(600, "2001:db8::53")), ("2001:db8::99", 0, 0, 0))])
        self.assertEqual(server.S.router_v6_dns, {})

    def test_the_listener_ignores_badly_formed_announcements(self):
        self.listen([(b"\x86\x00" + bytes(40), ("fe80::1", 0, 0, 3)), (b"junk", ("fe80::1", 0, 0, 3))])
        self.assertEqual(server.S.router_v6_dns, {})

    def test_the_listener_looks_at_only_so_many_announcements_a_second(self):
        flood = [(router_advert(rdnss(600, "2001:db8::%x" % i)), ("fe80::1", 0, 0, 3)) for i in range(1, 40)]
        with mock.patch.object(server, "RA_MAX_SERVERS", 100), \
                mock.patch.object(server.time, "monotonic", return_value=500.0):
            self.listen(flood)
        self.assertEqual(len(server.S.router_v6_dns), server.RA_MAX_PER_SECOND)

    def test_the_listener_never_sends_anything(self):
        sock = mock.Mock()
        self.listen([(router_advert(rdnss(600, self.HUB)), ("fe80::1", 0, 0, 3))], sock)
        sock.sendto.assert_not_called()
        sock.send.assert_not_called()

    def test_the_listener_stops_quietly_when_the_socket_fails(self):
        sock = mock.Mock()
        sock.recvmsg.side_effect = OSError("network gone")
        with mock.patch("builtins.print"):
            server.router_advert_listener(sock)                    # returns, does not raise
        self.assertFalse(server.S.ra_listening)

    def test_the_listener_carries_on_quietly_when_the_socket_cannot_be_opened(self):
        with mock.patch.object(server.os.path, "exists", return_value=True), \
                mock.patch.object(server.socket, "socket", side_effect=PermissionError("no NET_RAW")):
            self.assertIsNone(server.open_ra_socket())
            server.router_advert_listener()                        # returns, does not raise
        self.assertFalse(server.S.ra_listening)

    def test_the_listener_is_not_tried_away_from_linux(self):
        with mock.patch.object(server.os.path, "exists", return_value=False), \
                mock.patch.object(server.socket, "socket") as opened:
            self.assertIsNone(server.open_ra_socket())
        opened.assert_not_called()

    def test_the_socket_is_set_to_pass_on_router_announcements_only(self):
        sock = mock.Mock()
        with mock.patch.object(server.os.path, "exists", return_value=True), \
                mock.patch.object(server.socket, "socket", return_value=sock):
            self.assertIs(server.open_ra_socket(), sock)
        level, option, value = sock.setsockopt.call_args_list[0][0]
        words = struct.unpack("=8I", value)
        self.assertEqual(words[4], 0xFFFFFFFF & ~(1 << 6))         # 134 = 4 * 32 + 6: the one type let through
        self.assertTrue(all(w == 0xFFFFFFFF for i, w in enumerate(words) if i != 4))


class NoIPv6ForLiveCutDevices(Base):
    """A device with "Cut live connections" on gets no IPv6 addresses, so its apps connect over
    IPv4, through the Pi, where they can be cut. Other devices are answered as normal."""

    V6 = bytes.fromhex("2a001450400908000000000000000200")

    def setUp(self):
        super().setUp()
        server.S.paused_ips = set()
        with server.answer_cache_lock:
            server.answer_cache.clear()
        self.asked = []

    def internet(self, d):
        """A pretend internet: one address for an A or AAAA question, one HTTPS record otherwise."""
        self.asked.append(d)
        qtype = server.parse_question(d)[1]
        if qtype == 1:
            return fake_answer(d)
        if qtype == 28:
            return answer_with(d, [(28, self.V6)])
        return answer_with(d, [(qtype, b"\x00\x01\x00\x00\x06\x00\x10" + self.V6)])   # ipv6hint

    def ask(self, client, qtype=28, name="www.youtube.com"):
        """Ask for `name` with the given kind of question, as `client`."""
        return server.answer_query(query(name, qtype), client, self.internet)

    def is_empty(self, resp):
        """True if `resp` is 'no error, no records'."""
        return resp[3] & 0x0F == 0 and resp[6:8] == b"\x00\x00"

    def test_an_ipv6_address_lookup_from_a_live_cut_device_gets_no_records(self):
        server.S.enforced = {KID}
        resp = self.ask(KID)
        self.assertTrue(self.is_empty(resp))
        self.assertEqual(self.asked, [])

    def test_an_https_lookup_from_a_live_cut_device_gets_no_records(self):
        server.S.enforced = {KID}
        self.assertTrue(self.is_empty(self.ask(KID, qtype=65)))
        self.assertTrue(self.is_empty(self.ask(KID, qtype=64)))

    def test_an_ipv4_address_lookup_from_a_live_cut_device_is_answered_as_normal(self):
        server.S.enforced = {KID}
        resp = self.ask(KID, qtype=1)
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))
        self.assertEqual(len(self.asked), 1)

    def test_a_device_without_live_cut_still_gets_its_ipv6_address(self):
        server.S.enforced = {KID}
        resp = self.ask(ADULT)
        self.assertIn(self.V6, resp)

    def test_a_device_whose_rules_are_paused_still_gets_its_ipv6_address(self):
        server.S.enforced, server.S.paused_ips = {KID}, {KID}
        self.assertIn(self.V6, self.ask(KID))

    def test_a_live_cut_devices_empty_answer_is_not_remembered_for_other_devices(self):
        server.S.enforced = {KID}
        self.ask(KID)
        self.assertIn(self.V6, self.ask(ADULT))
        self.assertEqual(len(self.asked), 1)

    def test_a_remembered_ipv6_answer_is_not_given_to_a_live_cut_device(self):
        server.S.enforced = {KID}
        self.assertIn(self.V6, self.ask(ADULT))
        self.assertTrue(self.is_empty(self.ask(KID)))

    def test_the_status_says_ipv6_is_in_use_when_this_computer_has_a_public_range(self):
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]
        self.assertTrue(server.ipv6_dns_view(1000.0)["in_use"])

    def test_the_status_says_ipv6_is_in_use_when_the_router_announced_it_lately(self):
        server.S.ra_heard = 1000.0
        self.assertTrue(server.ipv6_dns_view(1000.0 + 60)["in_use"])
        self.assertFalse(server.ipv6_dns_view(1000.0 + server.RA_HOLD_MAX + 1)["in_use"])

    def test_the_status_says_ipv6_is_not_in_use_on_an_ipv4_only_network(self):
        self.assertFalse(server.ipv6_dns_view(1000.0)["in_use"])


class IPv6IsOffOnTheHub(Base):
    """The "IPv6 is off on your hub" confirmation. It must only ever be shown on evidence: a
    listener that never started, a restart, or a watcher that isn't looking must not look like
    "protected"."""

    NOW, MONO = 1795000000.0, 50000.0
    HOUR = server.RA_HOLD_MAX

    def setUp(self):
        super().setUp()
        # Everything the confirmation needs: listening for just over the hour, this computer able
        # to hear the router for as long, nothing heard, no public range, no IPv6 DNS server named,
        # and the IPv6 view worked out a moment ago.
        server.S.ra_listening, server.S.ra_since = True, self.MONO - self.HOUR - 1
        server.S.v6_can_hear, server.S.v6_hear_since = True, self.MONO - self.HOUR - 1
        server.S.v6_checked = self.MONO - 5
        self.addCleanup(setattr, server.S, "ra_listening", False)

    def off(self):
        """Is the confirmation shown now?"""
        return server.ipv6_dns_view(self.NOW, self.MONO)["hub_off"]

    def test_it_is_shown_after_a_full_hour_of_listening_with_no_router_heard_and_no_public_address(self):
        self.assertTrue(self.off())

    def test_it_stays_off_until_the_listener_has_run_the_full_hour(self):
        server.S.ra_since = self.MONO - self.HOUR + 1
        self.assertFalse(self.off())

    def test_it_stays_off_when_the_listener_never_started(self):
        server.S.ra_listening, server.S.ra_since = False, None
        self.assertFalse(self.off())

    def test_it_stays_off_when_the_listener_has_stopped(self):
        server.S.ra_listening = False
        self.assertFalse(self.off())

    def test_it_stays_off_just_after_a_restart(self):
        server.S.ra_since = self.MONO - 30
        self.assertFalse(self.off())

    def test_it_stays_off_when_a_real_router_was_heard_within_the_hour(self):
        server.S.ra_heard, server.S.ra_heard_at = self.NOW - 600, self.MONO - 600
        self.assertFalse(self.off())

    def test_it_is_shown_again_once_the_router_has_been_quiet_for_the_full_hour(self):
        server.S.ra_since = self.MONO - 3 * self.HOUR
        server.S.ra_heard, server.S.ra_heard_at = self.NOW - self.HOUR - 1, self.MONO - self.HOUR - 1
        self.assertTrue(self.off())

    def test_it_stays_off_while_this_computer_holds_a_public_ipv6_range(self):
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]
        self.assertFalse(self.off())

    def test_it_stays_off_when_this_computers_ipv6_addresses_have_never_been_looked_at(self):
        server.S.v6_checked = None
        self.assertFalse(self.off())

    def test_it_stays_off_when_this_computers_ipv6_addresses_were_last_looked_at_long_ago(self):
        server.S.v6_checked = self.MONO - server.V6_VIEW_FRESH - 1
        self.assertFalse(self.off())

    def test_a_change_of_the_clock_does_not_count_as_an_hour_of_listening(self):
        # A Pi starts with the wrong time and jumps forward when it learns the right one.
        server.S.ra_since = self.MONO - 60
        self.assertFalse(server.ipv6_dns_view(self.NOW + 5 * self.HOUR, self.MONO)["hub_off"])

    def test_a_router_heard_a_minute_ago_keeps_it_off_even_if_the_clock_jumped_forward(self):
        server.S.ra_heard, server.S.ra_heard_at = self.NOW - 60, self.MONO - 60
        self.assertFalse(server.ipv6_dns_view(self.NOW + 5 * self.HOUR, self.MONO)["hub_off"])

    def test_an_apple_tv_announcing_its_own_range_does_not_stop_the_confirmation(self):
        server.note_router_dns([], self.NOW, router_lifetime=0,
                               prefixes=[(server.ipaddress.IPv6Network("fd11:22:33:44::/64"), 1800)])
        self.assertTrue(self.off())

    def test_a_real_announcement_arriving_switches_the_confirmation_off(self):
        # Real clocks here, since the announcement is noted with them.
        server.S.ra_since, server.S.v6_checked = time.monotonic() - self.HOUR - 1, time.monotonic()
        server.S.v6_hear_since = server.S.ra_since
        self.assertTrue(server.ipv6_dns_view()["hub_off"])
        server.note_router_dns([], time.time(), router_lifetime=1800)
        self.assertFalse(server.ipv6_dns_view()["hub_off"])

    def test_a_real_announcement_keeps_it_off_even_if_the_clock_then_jumps_forward(self):
        # Real clocks here, since the announcement is noted with them. Five hours on by the clock
        # the announcement looks old, but by the steady timer it was heard a moment ago.
        server.S.ra_since, server.S.v6_checked = time.monotonic() - self.HOUR - 1, time.monotonic()
        server.S.v6_hear_since = server.S.ra_since
        heard = time.time()
        self.assertTrue(server.ipv6_dns_view(heard + 5 * self.HOUR)["hub_off"])
        server.note_router_dns([], heard, router_lifetime=1800)
        self.assertFalse(server.ipv6_dns_view(heard + 5 * self.HOUR)["hub_off"])

    # A router with no IPv6 internet but a private range: it announces with router lifetime 0,
    # hands out fd.. addresses and names itself as IPv6 DNS server.
    PRIVATE_RANGE = [(server.ipaddress.IPv6Network("fd12:3456:789a::/64"), 1800)]
    PRIVATE_DNS = "fd12:3456:789a::1"

    def test_it_stays_off_while_an_announcement_with_router_lifetime_0_names_another_ipv6_dns_server(self):
        server.note_router_dns([(self.PRIVATE_DNS, 1800)], self.NOW - 10, router_lifetime=0,
                               prefixes=self.PRIVATE_RANGE, sender="fe80::1", mac="aa:bb:cc:dd:ee:ff")
        view = server.ipv6_dns_view(self.NOW, self.MONO)
        self.assertEqual((view["hub_off"], view["in_use"], view["router_dns_not_ours"]),
                         (False, False, [self.PRIVATE_DNS]))

    def test_it_stays_off_while_a_link_local_ipv6_dns_server_is_named(self):
        server.note_router_dns([("fe80::1", 1800)], self.NOW - 10, router_lifetime=0)
        self.assertFalse(self.off())

    def test_it_is_shown_when_the_only_ipv6_dns_server_named_is_this_computer(self):
        self.addCleanup(setattr, server.S, "dns_ipv6", server.S.dns_ipv6)
        server.S.dns_ipv6, server.S.v6_own = True, {"fd12:3456:789a::60"}
        server.note_router_dns([("fd12:3456:789a::60", 1800)], self.NOW - 10, router_lifetime=0)
        self.assertTrue(self.off())

    def test_this_computer_being_named_does_not_count_while_it_takes_no_lookups_over_ipv6(self):
        self.addCleanup(setattr, server.S, "dns_ipv6", server.S.dns_ipv6)
        server.S.dns_ipv6, server.S.v6_own = False, {"fd12:3456:789a::60"}
        server.note_router_dns([("fd12:3456:789a::60", 1800)], self.NOW - 10, router_lifetime=0)
        self.assertFalse(self.off())

    def test_it_is_shown_again_once_that_servers_time_has_run_out(self):
        server.note_router_dns([(self.PRIVATE_DNS, 600)], self.NOW - 601, router_lifetime=0)
        self.assertTrue(self.off())

    def test_it_is_shown_again_once_the_router_says_to_stop_using_that_server(self):
        server.note_router_dns([(self.PRIVATE_DNS, 1800)], self.NOW - 20, router_lifetime=0)
        self.assertFalse(self.off())
        server.note_router_dns([(self.PRIVATE_DNS, 0)], self.NOW - 10, router_lifetime=0)
        self.assertTrue(self.off())

    def test_ipv6_is_not_called_off_when_this_computer_has_no_link_local_address_on_its_home_network_card(self):
        server.S.v6_can_hear, server.S.v6_hear_since = False, None
        view = server.ipv6_dns_view(self.NOW, self.MONO)
        self.assertEqual((view["hub_off"], view["can_hear"], view["listening_for"]), (False, False, 0))

    def test_it_stays_off_when_it_is_not_known_whether_this_computer_can_hear_ipv6(self):
        server.S.v6_can_hear, server.S.v6_hear_since = None, None
        view = server.ipv6_dns_view(self.NOW, self.MONO)
        self.assertEqual((view["hub_off"], view["can_hear"], view["listening_for"]), (False, None, 0))

    def test_it_stays_off_when_the_last_look_found_this_computer_could_not_hear_whatever_was_noted_before(self):
        server.S.v6_can_hear = False                 # the time it first could is still there, by a slip
        self.assertFalse(self.off())

    def test_it_stays_off_until_this_computer_has_been_able_to_hear_for_the_full_hour(self):
        server.S.ra_since = self.MONO - 5 * self.HOUR
        server.S.v6_hear_since = self.MONO - self.HOUR + 1
        view = server.ipv6_dns_view(self.NOW, self.MONO)
        self.assertEqual((view["hub_off"], view["listening_for"]), (False, self.HOUR - 1))

    def test_the_status_says_this_computer_can_hear_the_router_when_it_can(self):
        self.assertIs(server.ipv6_dns_view(self.NOW, self.MONO)["can_hear"], True)

    def look(self, can_hear):
        """Work out the IPv6 view once, with a stand-in answer to "could this computer hear the
        router over IPv6?" and nothing on the home network."""
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbour_table", return_value={}), \
                mock.patch.object(server, "ipv6_neighbour_table", return_value={}), \
                mock.patch.object(server, "can_hear_router", return_value=can_hear):
            server.refresh_ipv6_view()

    def test_a_look_notes_when_this_computer_could_first_hear_the_router_and_keeps_that_time(self):
        server.S.v6_can_hear, server.S.v6_hear_since = None, None
        self.look(True)
        first = server.S.v6_hear_since
        self.assertLess(time.monotonic() - first, 5)
        self.look(True)
        self.assertEqual((server.S.v6_can_hear, server.S.v6_hear_since), (True, first))

    def test_a_look_that_finds_this_computer_cannot_hear_the_router_forgets_when_it_first_could(self):
        for answer in (False, None):
            server.S.v6_can_hear, server.S.v6_hear_since = True, self.MONO - self.HOUR - 1
            self.look(answer)
            self.assertEqual((server.S.v6_can_hear, server.S.v6_hear_since), (answer, None), answer)

    def test_the_hour_starts_again_when_the_link_local_address_comes_back(self):
        # Real clocks here, since a look notes the time itself. Listening for five hours, but IPv6
        # on this computer's own card was off until a moment ago.
        server.S.ra_since = time.monotonic() - 5 * self.HOUR
        self.look(False)
        self.look(True)
        view = server.ipv6_dns_view()
        self.assertEqual((view["hub_off"], view["can_hear"]), (False, True))
        self.assertLess(view["listening_for"], 60)
        self.assertTrue(server.ipv6_dns_view(mono=time.monotonic() + self.HOUR - 60)["listening_for"] < self.HOUR)

    # /proc/net/if_inet6 as Linux writes it: address, card number, range size, scope, flags, card.
    HOME_CARD_UP = ("00000000000000000000000000000001 01 80 10 80       lo\n"
                    "fe80000000000000dea632fffe112233 03 40 20 80    wlan0\n"
                    "fe80000000000000004242fffe000001 04 40 20 80  docker0\n")

    def on_card(self, text, card="wlan0"):
        """Ask whether `card` has working IPv6, with `text` standing in for the system's list of
        this computer's IPv6 addresses."""
        with mock.patch("builtins.open", mock.mock_open(read_data=text)) as opened:
            answer = server.ipv6_on_card(card)
        opened.assert_called_once_with("/proc/net/if_inet6")
        return answer

    def test_a_link_local_address_on_the_home_network_card_means_the_router_can_be_heard(self):
        self.assertIs(self.on_card(self.HOME_CARD_UP), True)

    def test_a_link_local_address_on_another_card_does_not_count_as_able_to_hear_the_router(self):
        only_docker = "".join(line for line in self.HOME_CARD_UP.splitlines(True) if "wlan0" not in line)
        self.assertIs(self.on_card(only_docker), False)
        self.assertIs(self.on_card(self.HOME_CARD_UP.replace("wlan0", "wlan01")), False)

    def test_a_link_local_address_still_being_checked_does_not_count(self):
        self.assertIs(self.on_card("fe80000000000000dea632fffe112233 03 40 20 40    wlan0\n"), False)

    def test_a_link_local_address_that_failed_its_check_does_not_count(self):
        self.assertIs(self.on_card("fe80000000000000dea632fffe112233 03 40 20 08    wlan0\n"), False)

    def test_a_private_or_public_address_alone_on_the_home_network_card_does_not_count(self):
        self.assertIs(self.on_card("fd123456789a0000dea632fffe112233 03 40 00 00    wlan0\n"
                                   "20010db800010002dea632fffe112233 03 40 00 00    wlan0\n"), False)

    def test_a_computer_with_no_ipv6_addresses_at_all_cannot_hear_the_router(self):
        self.assertIs(self.on_card(""), False)

    def test_whether_the_router_can_be_heard_is_not_known_when_the_address_list_cannot_be_read(self):
        with mock.patch("builtins.open", side_effect=OSError("no such file")):
            self.assertIsNone(server.ipv6_on_card("wlan0"))
        self.assertIsNone(self.on_card("fe80000000000000dea632fffe112233 03 40 20 zz    wlan0\n"))

    def test_whether_the_router_can_be_heard_is_not_known_without_the_home_network_card(self):
        with mock.patch("builtins.open", side_effect=AssertionError("looked anyway")):
            self.assertIsNone(server.ipv6_on_card(None))
            self.assertIsNone(server.ipv6_on_card(""))

    def test_the_card_asked_about_is_the_one_this_computers_default_route_uses(self):
        with mock.patch.object(server, "can_hear_router", REAL_CAN_HEAR_ROUTER), \
                mock.patch.object(server.enforcer, "interface_and_gateway", return_value=("wlan0", "192.168.1.254")), \
                mock.patch.object(server, "ipv6_on_card", return_value=True) as asked:
            self.assertIs(server.can_hear_router(), True)
        asked.assert_called_once_with("wlan0")

    def test_a_computer_with_no_default_route_does_not_know_whether_it_can_hear_the_router(self):
        with mock.patch.object(server, "can_hear_router", REAL_CAN_HEAR_ROUTER), \
                mock.patch.object(server.enforcer, "interface_and_gateway", return_value=(None, None)), \
                mock.patch("builtins.open", side_effect=AssertionError("looked anyway")):
            self.assertIsNone(server.can_hear_router())

    def test_the_status_says_how_long_the_listener_has_been_listening(self):
        server.S.ra_since = self.MONO - 600
        self.assertEqual(server.ipv6_dns_view(self.NOW, self.MONO)["listening_for"], 600)

    def test_the_time_listening_is_nothing_while_the_listener_is_not_running(self):
        server.S.ra_listening = False
        self.assertEqual(server.ipv6_dns_view(self.NOW, self.MONO)["listening_for"], 0)

    def test_the_real_view_marks_when_it_was_worked_out(self):
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbour_table", return_value={}), \
                mock.patch.object(server, "ipv6_neighbour_table", return_value={}):
            server.S.v6_checked = None
            server.refresh_ipv6_view()
        self.assertLess(time.monotonic() - server.S.v6_checked, 5)


class NoIPv6AnswersForAnyone(Base):
    """The optional switch "Give no device IPv6 addresses": off unless the owner turns it on, and
    never applied to names only the home network can answer, or to QuietNet's own machine."""

    V6 = bytes.fromhex("2a001450400908000000000000000200")

    def setUp(self):
        super().setUp()
        with server.answer_cache_lock:
            server.answer_cache.clear()
        self.asked = []
        self.addCleanup(setattr, server.S, "no_ipv6_all", False)

    def internet(self, d, servers=None):
        """A pretend internet (and home router): an IPv6 address for an AAAA question, one IPv4 otherwise."""
        self.asked.append(servers)
        qtype = server.parse_question(d)[1]
        if qtype == 1:
            return fake_answer(d)
        if qtype == 28:
            return answer_with(d, [(28, self.V6)])
        return answer_with(d, [(qtype, b"\x00\x01\x00\x00\x06\x00\x10" + self.V6)])

    def ask(self, qtype=28, name="www.bbc.co.uk", client=ADULT):
        """Ask for `name` with the given kind of question."""
        return server.answer_query(query(name, qtype), client, self.internet)

    def is_empty(self, resp):
        """True if `resp` is 'no error, no records'."""
        return resp[3] & 0x0F == 0 and resp[6:8] == b"\x00\x00"

    def test_the_switch_is_off_unless_the_owner_turns_it_on(self):
        self.assertFalse(server.S.no_ipv6_all)
        self.assertIn(self.V6, self.ask())

    def test_with_the_switch_on_no_device_gets_ipv6_addresses(self):
        server.S.no_ipv6_all = True
        for client in (KID, ADULT):
            self.assertTrue(self.is_empty(self.ask(client=client)), client)
        self.assertEqual(self.asked, [])                               # the internet was never asked

    def test_with_the_switch_on_https_and_svcb_lookups_get_no_records_either(self):
        server.S.no_ipv6_all = True
        self.assertTrue(self.is_empty(self.ask(qtype=65)))
        self.assertTrue(self.is_empty(self.ask(qtype=64)))

    def test_with_the_switch_on_ipv4_address_lookups_are_answered_as_normal(self):
        server.S.no_ipv6_all = True
        self.assertEqual(self.ask(qtype=1)[-4:], bytes([93, 184, 216, 34]))

    def test_with_the_switch_on_a_home_network_name_still_gets_its_ipv6_address_from_the_router(self):
        server.S.no_ipv6_all = True
        server.S.router = "192.168.1.254"
        for name in ("printer.local", "nas", "tv.home"):
            self.assertIn(self.V6, self.ask(name=name), name)
        self.assertEqual(self.asked, [[("192.168.1.254", 53)]] * 3)

    def test_the_switch_never_applies_to_a_home_network_name(self):
        server.S.no_ipv6_all = True
        for name in ("printer.local", "nas", "tv.home", "box.home.arpa", "1.0.168.192.in-addr.arpa"):
            self.assertFalse(server.no_ipv6_for_everyone(name, 28, ADULT), name)
        self.assertTrue(server.no_ipv6_for_everyone("www.bbc.co.uk", 28, ADULT))

    def test_with_the_switch_on_quietnets_own_machine_still_gets_ipv6_addresses(self):
        server.S.no_ipv6_all = True
        server.S.local_ip = "192.168.1.60"
        self.assertIn(self.V6, self.ask(client="127.0.0.1"))
        self.assertIn(self.V6, self.ask(client="192.168.1.60"))

    def test_a_blocked_name_is_still_blocked_with_the_switch_on(self):
        server.S.no_ipv6_all = True
        resp = self.ask(name="ads.doubleclick.net")
        self.assertEqual(resp[-16:], bytes(16))                        # "::", the blocked answer

    def test_switching_it_off_again_gives_ipv6_addresses_back_at_once(self):
        server.S.no_ipv6_all = True
        self.assertTrue(self.is_empty(self.ask()))
        server.S.no_ipv6_all = False
        self.assertIn(self.V6, self.ask())

    def test_the_empty_answer_is_not_remembered_for_after_the_switch_goes_off(self):
        server.S.no_ipv6_all = True
        self.ask()
        server.S.no_ipv6_all = False
        self.ask()
        self.assertEqual(len(self.asked), 1)                           # asked the internet: nothing empty was remembered

    def test_the_switch_is_remembered_across_a_restart(self):
        server.set_setting("no_ipv6_all", "1")
        server.init_db()
        self.assertTrue(server.S.no_ipv6_all)
        server.set_setting("no_ipv6_all", "0")
        server.init_db()
        self.assertFalse(server.S.no_ipv6_all)


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
        lines = ["# comment", "127.0.0.1 localhost", "0.0.0.0 0.0.0.0", "0.0.0.0 Bad_Host!", "::1 ip6-localhost"]
        lines += ["0.0.0.0 tracker%d.example.net" % i for i in range(1200)]
        self.download("\n".join(lines))
        self.assertEqual(server.S.list_state, "idle")
        self.assertEqual(len(server.S.junk_community), 1200)
        self.assertTrue(server.is_junk("x.tracker7.example.net"))
        with open(server.COMMUNITY_FILE) as f:
            self.assertEqual(len(f.read().split()), 1200)

    def test_a_new_community_list_of_the_same_size_changes_the_activity_marker(self):
        self.download("\n".join("0.0.0.0 old%d.example.net" % i for i in range(1200)))
        before = server.activity_marker("192.168.1.23", 24, 0)
        self.download("\n".join("0.0.0.0 new%d.example.net" % i for i in range(1200)))
        self.assertNotEqual(server.activity_marker("192.168.1.23", 24, 0), before)

    def test_a_new_community_list_forgets_remembered_answers(self):
        with server.answer_cache_lock:
            server.answer_cache[("x.example.net", 1, 1)] = (time.monotonic() + 60, time.monotonic(), b"")
        self.download("\n".join("0.0.0.0 t%d.example.net" % i for i in range(1200)))
        self.assertNotIn(("x.example.net", 1, 1), server.answer_cache)

    def test_a_suspiciously_short_list_is_refused_and_the_old_one_kept(self):
        server.S.junk_community = {"kept.example.net"}
        self.download("\n".join("0.0.0.0 t%d.example.net" % i for i in range(50)))
        self.assertEqual(server.S.list_state, "error")
        self.assertIn("incomplete", server.S.list_error)
        self.assertEqual(server.S.junk_community, {"kept.example.net"})
        self.assertFalse(os.path.exists(server.COMMUNITY_FILE))

    def test_the_download_uses_the_shared_secure_connection_settings(self):
        settings = object()
        page = mock.MagicMock()
        page.__enter__.return_value.read.return_value = b""
        with mock.patch.object(server.cloud_agent, "tls_context", return_value=settings), \
                mock.patch.object(server.urllib.request, "urlopen", return_value=page) as opened:
            server.update_community_list()
        self.assertIs(opened.call_args[1]["context"], settings)

    def test_a_failed_download_is_reported_and_the_old_list_kept(self):
        server.S.junk_community = {"kept.example.net"}
        self.download(error=OSError("no internet"))
        self.assertEqual((server.S.list_state, server.S.list_error), ("error", "no internet"))
        self.assertEqual(server.S.junk_community, {"kept.example.net"})


class Forwarding(unittest.TestCase):
    def test_an_answer_from_anyone_but_the_server_we_asked_is_ignored(self):
        # A pretend upstream that, on each question, first has a stranger send a forged answer
        # (right id, wrong address) and only then sends the real one. The forgery must lose.
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stranger.bind(("127.0.0.1", 0))
        self.addCleanup(upstream.close)
        self.addCleanup(stranger.close)

        def serve():
            try:
                data, addr = upstream.recvfrom(4096)
            except OSError:
                return
            forged = fake_answer(data)[:-4] + bytes([6, 6, 6, 6])
            stranger.sendto(forged, addr)
            upstream.sendto(fake_answer(data), addr)

        threading.Thread(target=serve, daemon=True).start()
        with mock.patch.object(server, "UPSTREAMS", [upstream.getsockname()]):
            resp = server.forward_udp(query("www.bbc.co.uk"))
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))

    def test_an_answer_with_the_wrong_id_is_ignored(self):
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        self.addCleanup(upstream.close)

        def serve():
            try:
                data, addr = upstream.recvfrom(4096)
            except OSError:
                return
            upstream.sendto(b"\x00\x00" + fake_answer(data)[2:-4] + bytes([6, 6, 6, 6]), addr)
            upstream.sendto(fake_answer(data), addr)

        threading.Thread(target=serve, daemon=True).start()
        with mock.patch.object(server, "UPSTREAMS", [upstream.getsockname()]):
            resp = server.forward_udp(query("www.bbc.co.uk"))
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))

    def test_an_answer_to_a_different_question_is_ignored(self):
        # Right id, but answering some other name: someone guessing, or a muddled server.
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        self.addCleanup(upstream.close)

        def serve():
            try:
                data, addr = upstream.recvfrom(4096)
            except OSError:
                return
            other = fake_answer(data[:2] + query("evil.example.net")[2:])
            upstream.sendto(other[:-4] + bytes([6, 6, 6, 6]), addr)
            upstream.sendto(fake_answer(data), addr)

        threading.Thread(target=serve, daemon=True).start()
        with mock.patch.object(server, "UPSTREAMS", [upstream.getsockname()]):
            resp = server.forward_udp(query("www.bbc.co.uk"))
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))

    def test_an_answer_that_only_changes_letter_case_is_accepted(self):
        q = query("www.bbc.co.uk")
        resp = fake_answer(q[:12] + q[12:].replace(b"bbc", b"BbC"))
        self.assertTrue(server.same_question(q, resp))

    def test_the_spare_server_is_used_when_the_first_is_silent(self):
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        dead_port = silent.getsockname()
        silent.close()                                           # nothing listens here now
        spare = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        spare.bind(("127.0.0.1", 0))
        self.addCleanup(spare.close)

        def serve():
            try:
                data, addr = spare.recvfrom(4096)
            except OSError:
                return
            spare.sendto(fake_answer(data), addr)

        threading.Thread(target=serve, daemon=True).start()
        with mock.patch.object(server, "UPSTREAMS", [dead_port, spare.getsockname()]):
            resp = server.forward_udp(query("www.bbc.co.uk"))
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))


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
        with mock.patch.object(server, "ipv6_watcher", lambda: None):     # never read the real machine's IPv6 setup
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

    def test_lookups_are_also_answered_over_ipv6(self):
        if not server.S.dns_ipv6:
            self.skipTest("this computer could not listen on IPv6")
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(query("ads.doubleclick.net"), ("::1", self.port))
            self.assertEqual(s.recvfrom(4096)[0][-4:], bytes(4))

    def test_when_the_internet_does_not_answer_the_device_is_told_so(self):
        with mock.patch.object(server, "forward_udp", return_value=None):
            resp = self.ask_udp("www.bbc.co.uk")
        self.assertEqual(resp[3] & 15, 2)                                # "server failure"


class Limits(unittest.TestCase):
    """Floods and slow clients can't pile up threads or memory without limit."""

    def test_a_tcp_client_that_trickles_its_question_is_dropped(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        b.sendall(b"\x00")                                       # half the length, then nothing more
        start = time.monotonic()
        with self.assertRaises((ValueError, OSError)):
            server.recv_exact(a, 2, deadline=time.monotonic() + 0.3)
        self.assertLess(time.monotonic() - start, 2)

    def test_tcp_connections_beyond_the_limit_are_turned_away(self):
        srv = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(srv.server_close)
        srv.slots = threading.BoundedSemaphore(1)
        srv.slots.acquire()                                      # the only slot is taken
        closed = []
        srv.shutdown_request = closed.append
        srv.process_request("conn", ("192.168.1.23", 5000))
        self.assertEqual(closed, ["conn"])

    def test_one_device_cannot_take_more_than_its_share_of_tcp_connections(self):
        srv = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(srv.server_close)
        with mock.patch.object(server, "MAX_TCP_PER_DEVICE", 2):
            taken = [srv.take_slot(("192.168.1.23", 5000 + i)) for i in range(3)]
            other = srv.take_slot(("192.168.1.40", 6000))
        self.assertEqual(taken, [True, True, False])
        self.assertTrue(other)

    def test_a_device_gets_its_tcp_share_back_once_a_connection_is_finished(self):
        srv = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(srv.server_close)
        with mock.patch.object(server, "MAX_TCP_PER_DEVICE", 1):
            self.assertTrue(srv.take_slot(("192.168.1.23", 5000)))
            srv.give_slot_back(("192.168.1.23", 5000))
            self.assertTrue(srv.take_slot(("192.168.1.23", 5001)))

    def test_a_tcp_connection_turned_away_for_its_device_share_is_closed(self):
        srv = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(srv.server_close)
        closed = []
        srv.shutdown_request = closed.append
        with mock.patch.object(server, "MAX_TCP_PER_DEVICE", 0):
            srv.process_request("conn", ("192.168.1.23", 5000))
        self.assertEqual(closed, ["conn"])

    def test_an_ipv4_device_over_ipv6_shares_its_tcp_share_with_itself_over_ipv4(self):
        srv = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(srv.server_close)
        with mock.patch.object(server, "MAX_TCP_PER_DEVICE", 1):
            self.assertTrue(srv.take_slot(("192.168.1.23", 5000)))
            self.assertFalse(srv.take_slot(("::ffff:192.168.1.23", 5001, 0, 0)))

    def test_failing_to_listen_on_ipv6_does_not_stop_the_filter(self):
        server.S.dns_error = None
        with mock.patch.object(server.socket, "socket", side_effect=OSError("no IPv6 here")), \
                mock.patch.object(server, "ipv6_watcher", lambda: None), \
                mock.patch("builtins.print"):
            self.assertFalse(server.start_dns6(53))
        self.assertIsNone(server.S.dns_error)

    def test_the_ipv6_watcher_is_started_even_when_the_ipv6_port_cannot_be_opened(self):
        started = threading.Event()
        with mock.patch.object(server.socket, "socket", side_effect=OSError("port in use")), \
                mock.patch.object(server.socket, "has_ipv6", True), \
                mock.patch.object(server, "ipv6_watcher", started.set), \
                mock.patch("builtins.print"):
            self.assertFalse(server.start_dns6(53))
            self.assertTrue(started.wait(5))

    def test_ipv6_is_still_tried_when_the_ipv4_port_cannot_be_opened(self):
        self.addCleanup(setattr, server.S, "dns_error", server.S.dns_error)
        self.addCleanup(setattr, server.S, "dns_port", server.S.dns_port)
        with mock.patch.object(server.socket, "socket", side_effect=OSError("port 53 is in use")), \
                mock.patch.object(server, "start_dns6") as tried, mock.patch("builtins.print"):
            server.start_dns(53)
        tried.assert_called_once_with(53)
        self.assertEqual(server.S.dns_error, "port 53 is in use")

    def test_a_half_opened_ipv4_listener_is_closed_when_its_tcp_side_fails(self):
        self.addCleanup(setattr, server.S, "dns_error", server.S.dns_error)
        self.addCleanup(setattr, server.S, "dns_port", server.S.dns_port)
        sock = mock.Mock()
        with mock.patch.object(server.socket, "socket", return_value=sock), \
                mock.patch.object(server, "TCPServer", side_effect=OSError("TCP port in use")), \
                mock.patch.object(server, "start_dns6"), mock.patch("builtins.print"):
            server.start_dns(53)
        sock.close.assert_called_once_with()

    def test_the_ipv4_and_ipv6_listeners_are_given_the_same_counts_of_each_devices_share(self):
        self.addCleanup(setattr, server.S, "dns_error", server.S.dns_error)
        self.addCleanup(setattr, server.S, "dns_port", server.S.dns_port)
        self.addCleanup(setattr, server.S, "dns_ipv6", server.S.dns_ipv6)
        server.S.dns_error = None
        with mock.patch.object(server.socket, "socket"), mock.patch.object(server.socket, "has_ipv6", True), \
                mock.patch.object(server, "TCPServer") as tcp4, mock.patch.object(server, "TCPServer6") as tcp6, \
                mock.patch.object(server, "ipv6_watcher", lambda: None), \
                mock.patch.object(server, "udp_server") as udp:
            server.start_dns(53)
            for _ in range(100):                                     # the two UDP threads start at once
                if udp.call_count == 2:
                    break
                time.sleep(0.01)
        self.assertIs(tcp4.return_value.shares, server.TCP_SHARES)
        self.assertIs(tcp6.return_value.shares, server.TCP_SHARES)
        self.assertEqual([c[0][1] for c in udp.call_args_list], [server.UDP_SHARES] * 2)

    PHONE, PHONE_V6, PHONE_V6_TOO = "192.168.1.23", "fd00::23", "2001:db8:1:2::23"

    def match_the_phone(self):
        """Have both the phone's IPv6 addresses matched to its IPv4 address, until the test ends."""
        self.addCleanup(setattr, server.S, "v6_devices", server.S.v6_devices)
        self.addCleanup(setattr, server.S, "v6_prefixes", server.S.v6_prefixes)
        server.S.v6_devices = {self.PHONE_V6: self.PHONE, self.PHONE_V6_TOO: self.PHONE}
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]

    def taken_over_udp(self, senders, shares, family=socket.AF_INET):
        """Run a UDP listener over one lookup from each sender, with a pool that never answers;
        returns the senders whose lookups were taken.

        The stand-in socket hands lookups over through recvfrom only. On Linux an IPv4 listener
        would otherwise ask which address each lookup was sent to and read with recvmsg (see
        server.ask_for_reply_address), which the stand-in does not answer, so that option is
        switched off here. These tests are about shares, the same on every system; ReplyAddress
        covers the option itself."""
        sock = mock.Mock(family=family)
        sock.recvfrom.side_effect = [(query("www.bbc.co.uk"), (host, 5000 + i, 0, 0)) for i, host in enumerate(senders)] \
            + [KeyboardInterrupt()]
        taken = []
        pool = mock.Mock(submit=lambda fn, data, addr, source: taken.append(addr[0]))
        with mock.patch.object(server, "MAX_DNS_PER_DEVICE", 2), \
                mock.patch.object(server, "IP_PKTINFO", None), \
                mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock, shares)
        return taken

    def test_all_of_a_devices_ipv6_addresses_count_against_one_udp_share(self):
        self.match_the_phone()
        taken = self.taken_over_udp([self.PHONE_V6, self.PHONE_V6_TOO, self.PHONE_V6, self.PHONE_V6_TOO],
                                    server.Shares(), socket.AF_INET6)
        self.assertEqual(len(taken), 2)

    def test_a_devices_udp_share_is_one_across_the_ipv4_and_ipv6_listeners(self):
        self.match_the_phone()
        shares = server.Shares()
        self.assertEqual(self.taken_over_udp([self.PHONE, self.PHONE], shares), [self.PHONE] * 2)
        self.assertEqual(self.taken_over_udp([self.PHONE_V6, "::ffff:" + self.PHONE], shares, socket.AF_INET6), [])

    def test_an_unmatched_ipv6_address_has_a_udp_share_of_its_own(self):
        self.match_the_phone()
        shares = server.Shares()
        self.taken_over_udp([self.PHONE, self.PHONE], shares)
        self.assertEqual(self.taken_over_udp(["fd00::77"], shares, socket.AF_INET6), ["fd00::77"])

    def test_a_udp_listener_started_by_itself_keeps_its_own_count(self):
        self.assertEqual(len(self.taken_over_udp([self.PHONE] * 3, None)), 2)
        self.assertEqual(len(self.taken_over_udp([self.PHONE] * 3, None)), 2)
        self.assertEqual(server.UDP_SHARES.count, {})

    def test_a_udp_share_goes_back_to_the_device_it_was_taken_from_if_the_match_changes_meanwhile(self):
        self.match_the_phone()
        shares = server.Shares()
        sock = mock.Mock(family=socket.AF_INET6)
        sock.recvfrom.side_effect = [(query("www.bbc.co.uk"), (self.PHONE_V6, 5000, 0, 0)), KeyboardInterrupt()]

        def answer_later(fn, data, addr, source):
            """The match is lost while the lookup is in hand; then it is answered."""
            server.S.v6_devices = {}
            fn(data, addr, source)
        pool = mock.Mock(submit=answer_later)
        with mock.patch.object(server, "answer_query", return_value=None), \
                mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock, shares)
        self.assertEqual(shares.count, {})

    def test_this_computers_own_addresses_count_against_one_share(self):
        self.addCleanup(setattr, server.S, "v6_own", server.S.v6_own)
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        server.S.local_ip, server.S.v6_own = "192.168.1.60", {"fd00::60"}
        self.assertEqual({server.share_key(h) for h in ("127.0.0.1", "::1", "fd00::60", "192.168.1.60", "fd00::60%wlan0")},
                         {"192.168.1.60"})

    def test_a_devices_tcp_share_is_one_across_the_ipv4_and_ipv6_listeners_and_all_its_addresses(self):
        self.match_the_phone()
        v4 = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        v6 = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(v4.server_close)
        self.addCleanup(v6.server_close)
        v4.shares = v6.shares = server.Shares()
        with mock.patch.object(server, "MAX_TCP_PER_DEVICE", 2):
            self.assertTrue(v4.take_slot((self.PHONE, 5000)))
            self.assertTrue(v6.take_slot((self.PHONE_V6, 5001, 0, 0)))
            self.assertFalse(v6.take_slot((self.PHONE_V6_TOO, 5002, 0, 0)))
            self.assertFalse(v4.take_slot((self.PHONE, 5003)))
            self.assertTrue(v6.take_slot(("fd00::77", 5004, 0, 0)))  # another device still gets in

    def test_a_tcp_share_goes_back_to_the_device_it_was_taken_from_if_the_match_changes_meanwhile(self):
        self.match_the_phone()
        srv = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(srv.server_close)
        self.assertTrue(srv.take_slot((self.PHONE_V6, 5000, 0, 0)))
        server.S.v6_devices = {}
        srv.give_slot_back((self.PHONE_V6, 5000, 0, 0))
        self.assertEqual((srv.shares.count, srv.holders), ({}, {}))

    def test_a_tcp_connection_turned_away_for_the_house_limit_does_not_use_up_its_devices_share(self):
        srv = server.TCPServer(("127.0.0.1", 0), server.TCPHandler)
        self.addCleanup(srv.server_close)
        srv.slots = threading.BoundedSemaphore(1)
        srv.slots.acquire()                                      # the house has no connections left
        self.assertFalse(srv.take_slot((self.PHONE, 5000)))
        self.assertEqual(srv.shares.count, {})

    def test_a_udp_lookup_dropped_for_the_house_limit_does_not_use_up_its_devices_share(self):
        shares = server.Shares()
        with mock.patch.object(server, "MAX_DNS_WAITING", 1):
            taken = self.taken_over_udp([self.PHONE, self.PHONE], shares)
        self.assertEqual((len(taken), shares.count), (1, {self.PHONE: 1}))

    def test_udp_lookups_beyond_the_limit_are_dropped_not_queued(self):
        sock = mock.Mock()
        incoming = [(query("n%d.example.com" % i), ("192.168.1.23", 5000 + i)) for i in range(5)]
        sock.recvfrom.side_effect = incoming + [KeyboardInterrupt()]
        submitted = []
        pool = mock.Mock(submit=lambda fn, data, addr, source: submitted.append(addr))
        with mock.patch.object(server, "MAX_DNS_WAITING", 2), \
                mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock)
        self.assertEqual(len(submitted), 2)                      # the rest were dropped, not queued

    def test_one_device_cannot_take_more_than_its_share_of_udp_slots(self):
        sock = mock.Mock()
        greedy = [(query("n%d.example.com" % i), ("192.168.1.23", 5000 + i)) for i in range(5)]
        other = [(query("www.bbc.co.uk"), ("192.168.1.40", 6000))]
        sock.recvfrom.side_effect = greedy + other + [KeyboardInterrupt()]
        submitted = []
        pool = mock.Mock(submit=lambda fn, data, addr, source: submitted.append(addr[0]))
        with mock.patch.object(server, "MAX_DNS_PER_DEVICE", 2), \
                mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock)
        self.assertEqual(submitted, ["192.168.1.23", "192.168.1.23", "192.168.1.40"])

    def test_a_device_gets_its_share_back_once_its_lookups_are_answered(self):
        sock = mock.Mock()
        incoming = [(query("n%d.example.com" % i), ("192.168.1.23", 5000 + i)) for i in range(4)]
        sock.recvfrom.side_effect = incoming + [KeyboardInterrupt()]
        submitted = []

        def run_now(fn, data, addr, source):
            """Answer each lookup straight away, as if the pool had a free worker."""
            submitted.append(addr)
            fn(data, addr, source)
        pool = mock.Mock(submit=run_now)
        with mock.patch.object(server, "MAX_DNS_PER_DEVICE", 1), \
                mock.patch.object(server, "answer_query", return_value=None), \
                mock.patch.object(server, "ThreadPoolExecutor", lambda max_workers: pool):
            with self.assertRaises(KeyboardInterrupt):
                server.udp_server(sock)
        self.assertEqual(len(submitted), 4)


if __name__ == "__main__":
    unittest.main()
