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
    every device, so it falls back to ordinary DNS and comes to QuietNet (known issue 8)."""

    def setUp(self):
        super().setUp()
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

    def test_a_dns_service_is_blocked_for_a_device_with_no_rules(self):
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

    def test_a_device_switched_off_by_its_ipv4_address_is_refused_from_an_ipv6_address_that_cannot_be_matched(self):
        server.set_internet_off("device:" + KID, True)
        self.assertEqual(self.answer(self.PHONE_V6)[3] & 15, 5)        # "refused": it asks over IPv4 instead

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
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbours", return_value={KID: "aa:bb:cc:dd:ee:01"}), \
                mock.patch.object(server, "ipv6_neighbours",
                                  return_value={self.PHONE_V6: "aa:bb:cc:dd:ee:01", "fd00::2": "aa:bb:cc:dd:ee:99"}):
            server.refresh_ipv6_view()
        self.assertEqual(server.S.v6_devices, {self.PHONE_V6: KID})

    def test_a_device_known_only_from_the_last_scan_is_matched_to_its_ipv6_address(self):
        server.sql("INSERT OR REPLACE INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)",
                   (KID, "aa:bb:cc:dd:ee:01", "", time.time()), commit=True)
        self.addCleanup(server.sql, "DELETE FROM seen WHERE ip=?", (KID,), True)
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbours", return_value={}), \
                mock.patch.object(server, "ipv6_neighbours", return_value={self.PHONE_V6: "aa:bb:cc:dd:ee:01"}):
            server.refresh_ipv6_view()
        self.assertEqual(server.S.v6_devices, {self.PHONE_V6: KID})

    def test_the_linux_ipv6_neighbour_table_is_read(self):
        text = ("fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router REACHABLE\n"
                "fd00::ABCD dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
                "fd00::3 dev eth0 FAILED\n")
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/if_inet6"), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text)):
            found = server.ipv6_neighbours()
        self.assertEqual(found, {"fe80::1": "aa:bb:cc:dd:ee:01", "fd00::abcd": "aa:bb:cc:dd:ee:02"})

    def test_the_mac_ipv6_neighbour_table_is_read(self):
        text = ("Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n"
                "fe80::1%en0                     0:11:22:33:44:55   en0   23h59m58s S  R\n"
                "fd00::9                         (incomplete)       en0   expired   N\n")
        with mock.patch.object(server.os.path, "exists", lambda p: False), \
                mock.patch.object(server.subprocess, "run", return_value=mock.Mock(stdout=text)):
            found = server.ipv6_neighbours()
        self.assertEqual(found, {"fe80::1": "00:11:22:33:44:55"})

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
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "fd00::60")), \
                mock.patch.object(server, "neighbours", return_value={}), \
                mock.patch.object(server, "ipv6_neighbours", return_value={}):
            server.refresh_ipv6_view()
        self.assertEqual(server.S.v6_dns, "fd00::60")


def router_advert(*options):
    """A router announcement (ICMPv6 type 134) as it arrives on the socket: the 16-byte start, then
    the given options, each already in its on-the-wire form."""
    return bytes([134, 0, 0, 0, 64, 0]) + struct.pack(">HII", 1800, 0, 0) + b"".join(options)


def rdnss(lifetime, *addresses):
    """A DNS server option (type 25) naming the given IPv6 addresses for `lifetime` seconds."""
    body = b"".join(server.ipaddress.IPv6Address(a).packed for a in addresses)
    return bytes([25, 1 + 2 * len(addresses), 0, 0]) + struct.pack(">I", lifetime) + body


class RouterAnnouncements(Base):
    """The router's IPv6 announcements, read to spot it telling devices to use its own IPv6 DNS
    server. Nothing here opens a real socket: the listener is handed stand-ins."""

    HUB = "fe80::1"
    PI = "2001:db8:1:2::60"

    def listen(self, packets, sock=None):
        """Run the listener over these (data, source) packets, then stop it."""
        sock = sock or mock.Mock()
        sock.recvfrom.side_effect = list(packets) + [KeyboardInterrupt()]
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
        sock.recvfrom.side_effect = OSError("network gone")
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
        level, option, value = sock.setsockopt.call_args[0]
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
                mock.patch("builtins.print"):
            self.assertFalse(server.start_dns6(53))
        self.assertIsNone(server.S.dns_error)

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
