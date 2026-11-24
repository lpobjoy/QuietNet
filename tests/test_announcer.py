"""Checks for the trial that announces this computer as an IPv6 DNS server (announcer.py):
the bytes of the message, its lifetimes, when it is and is not sent, how it stops, and that it
is off unless the owner switches it on. Also its switch in the dashboard's API and on the page.

Run with:  python3 -m unittest discover tests

Standard library only. Nothing is sent onto a network: the sending socket, the network card's
details and the clock are stand-ins, and the only real connections are test questions to a
stand-in DNS server on 127.0.0.1 (and on ::1, where the computer has it). No raw socket is opened
and no system tool is run.
"""
import contextlib
import inspect
import io
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_dashboard_api import Api  # noqa: E402
from test_quietnet import Base, server  # noqa: E402
import announcer  # noqa: E402
import enforcer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARD, MAC, ADDR = "wlan0", "b8:27:eb:12:34:56", "fe80::ba27:ebff:fe12:3456"
OTHER = "fe80::1234"


def read(*parts):
    """The text of one of the repository's files."""
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()

# Whole frames for the hardware address and address above, made once and read back with tcpdump
# (`tcpdump -vv -e -r`), which reported for each: "[icmp6 sum ok] ICMP6, router advertisement",
# "hop limit 0, Flags [none], pref medium, router lifetime 0s, reachable time 0ms, retrans timer
# 0ms", and one "rdnss option (25), length 24 (3)" with the lifetime given and this address.
KNOWN_ANNOUNCEMENT = bytes.fromhex(
    "333300000001" "b827eb123456" "86dd"                                   # to every device, from the Pi, IPv6
    "60000000" "0028" "3a" "ff"                                            # IPv6, 40 bytes follow, ICMPv6, hop limit 255
    "fe80000000000000ba27ebfffe123456"                                     # from the Pi's own home-only address
    "ff020000000000000000000000000001"                                     # to every device on this network
    "86" "00" "b11a" "00" "00" "0000" "00000000" "00000000"                # router announcement, router lifetime 0
    "19" "03" "0000" "00000258"                                            # DNS part: 600 seconds
    "fe80000000000000ba27ebfffe123456")                                    # the server: the sender itself
KNOWN_GOODBYE = bytes.fromhex(
    "333300000001" "b827eb123456" "86dd" "60000000" "0028" "3a" "ff"
    "fe80000000000000ba27ebfffe123456" "ff020000000000000000000000000001"
    "86" "00" "b372" "00" "00" "0000" "00000000" "00000000"
    "19" "03" "0000" "00000000"                                            # DNS part: 0 seconds, "stop using it"
    "fe80000000000000ba27ebfffe123456")
KNOWN_GOODBYE_FOR_TWO = bytes.fromhex(
    "333300000001" "b827eb123456" "86dd" "60000000" "0040" "3a" "ff"
    "fe80000000000000ba27ebfffe123456" "ff020000000000000000000000000001"
    "86" "00" "89a2" "00" "00" "0000" "00000000" "00000000"
    "19" "03" "0000" "00000000" "fe80000000000000ba27ebfffe123456"
    "19" "03" "0000" "00000000" "fe800000000000000000000000001234")


def parts_of(frame):
    """The parts (options) after the 16-byte announcement in a frame, as (type, bytes) pairs.
    Written out separately from the program's own reader, so the two can't share a mistake."""
    out, at = [], 14 + 40 + 16
    while at < len(frame):
        size = frame[at + 1] * 8
        assert size, "a part with no length"
        out.append((frame[at], frame[at:at + size]))
        at += size
    assert at == len(frame), "the parts don't fill the frame exactly"
    return out


def dns_servers(frame):
    """[(address text, lifetime)] for each DNS part in a frame."""
    return [(socket.inet_ntop(socket.AF_INET6, part[8:24]), int.from_bytes(part[4:8], "big"))
            for kind, part in parts_of(frame) if kind == 25]


def checksum_holds(frame):
    """Does the frame's ICMPv6 check number come out right? Worked out the long way: add up the
    made-up header and the whole message, check number included, 16 bits at a time; a correct
    message adds up to all ones."""
    message = frame[54:]
    data = frame[22:38] + frame[38:54] + len(message).to_bytes(4, "big") + b"\x00\x00\x00\x3a" + message
    data += b"\x00" * (len(data) % 2)
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


class TheFrame(unittest.TestCase):
    def frame(self, lifetime=announcer.DNS_LIFETIME, withdrawn=()):
        return announcer.build_dns_announcement(MAC, ADDR, lifetime, withdrawn)

    def test_the_announcement_matches_a_known_good_frame_byte_for_byte(self):
        self.assertEqual(self.frame(600).hex(), KNOWN_ANNOUNCEMENT.hex())

    def test_the_goodbye_matches_a_known_good_frame_byte_for_byte(self):
        self.assertEqual(self.frame(0).hex(), KNOWN_GOODBYE.hex())

    def test_a_goodbye_that_also_calls_off_an_earlier_address_matches_a_known_good_frame(self):
        self.assertEqual(self.frame(0, [OTHER]).hex(), KNOWN_GOODBYE_FOR_TWO.hex())

    def test_the_frame_is_addressed_to_every_device_on_the_home_network(self):
        self.assertEqual(self.frame()[:6].hex(":"), "33:33:00:00:00:01")
        self.assertEqual(socket.inet_ntop(socket.AF_INET6, self.frame()[38:54]), "ff02::1")

    def test_the_frame_comes_from_this_computers_own_card_and_home_only_address(self):
        self.assertEqual(self.frame()[6:12].hex(":"), MAC)
        self.assertEqual(socket.inet_ntop(socket.AF_INET6, self.frame()[22:38]), ADDR)

    def test_the_frame_is_marked_as_ipv6_carrying_icmpv6(self):
        frame = self.frame()
        self.assertEqual(frame[12:14], b"\x86\xdd")
        self.assertEqual(frame[14] >> 4, 6)
        self.assertEqual(frame[20], 58)

    def test_the_length_in_the_ipv6_header_is_the_length_of_the_message(self):
        for frame in (self.frame(), self.frame(0, [OTHER])):
            self.assertEqual(int.from_bytes(frame[18:20], "big"), len(frame) - 54)

    def test_the_hop_limit_is_255_so_devices_accept_it(self):
        self.assertEqual(self.frame()[21], 255)

    def test_it_is_a_router_announcement(self):
        self.assertEqual(self.frame()[54:56], bytes([134, 0]))

    def test_the_router_lifetime_is_zero_so_no_device_sends_its_traffic_through_the_pi(self):
        for frame in (self.frame(), self.frame(0), self.frame(0, [OTHER])):
            self.assertEqual(frame[60:62], b"\x00\x00")

    def test_neither_dhcpv6_flag_is_set_and_the_router_preference_is_ordinary(self):
        self.assertEqual(self.frame()[59], 0)

    def test_it_gives_devices_no_hop_limit_or_timers_to_adopt(self):
        frame = self.frame()
        self.assertEqual(frame[58], 0)
        self.assertEqual(frame[62:70], bytes(8))

    def test_it_carries_nothing_but_the_dns_part(self):
        # No address range (3), no route (24), no hardware address (1), no size limit (5): only DNS (25).
        self.assertEqual([kind for kind, _ in parts_of(self.frame())], [25])
        self.assertEqual(len(self.frame()), 14 + 40 + 16 + 24)

    def test_the_dns_part_is_24_bytes_holding_one_address(self):
        kind, part = parts_of(self.frame())[0]
        self.assertEqual((kind, part[1], part[2:4], len(part)), (25, 3, b"\x00\x00", 24))

    def test_the_dns_server_it_names_is_the_computer_that_sent_it(self):
        frame = self.frame()
        self.assertEqual(dns_servers(frame), [(ADDR, announcer.DNS_LIFETIME)])
        self.assertEqual(parts_of(frame)[0][1][8:24], frame[22:38])

    def test_the_dns_lifetime_is_ten_minutes(self):
        self.assertEqual(announcer.DNS_LIFETIME, 600)
        self.assertEqual(dns_servers(self.frame())[0][1], 600)

    def test_the_dns_lifetime_outlasts_two_lost_announcements(self):
        self.assertGreaterEqual(announcer.DNS_LIFETIME, 3 * announcer.ANNOUNCE_EVERY)

    def test_the_dns_lifetime_is_longer_than_android_needs(self):
        self.assertGreater(announcer.DNS_LIFETIME, 120)

    def test_the_goodbye_has_a_dns_lifetime_of_zero(self):
        self.assertEqual(dns_servers(self.frame(0)), [(ADDR, 0)])

    def test_the_check_number_is_right(self):
        for frame in (self.frame(), self.frame(0), self.frame(0, [OTHER]), self.frame(1), self.frame(0xFFFFFFFF)):
            self.assertTrue(checksum_holds(frame))

    def test_the_check_number_covers_the_addresses_as_well_as_the_message(self):
        other = announcer.build_dns_announcement(MAC, "fe80::1", 600)
        self.assertTrue(checksum_holds(other))
        self.assertNotEqual(other[56:58], self.frame(600)[56:58])

    def test_a_message_of_odd_length_is_still_checked_correctly(self):
        self.assertEqual(announcer.checksum(bytes(16), bytes(16), b"\x01"), 0xFFFF - (1 + 58 + 0x0100))

    def test_quietnets_own_listener_reads_it_as_dns_only_from_something_that_is_not_a_router(self):
        self.assertEqual(server.read_router_advert(self.frame()[54:]),
                         {"lifetime": 0, "servers": [(ADDR, 600)], "prefixes": [], "mac": ""})

    def test_an_earlier_address_is_only_ever_added_with_a_lifetime_of_zero(self):
        self.assertEqual(dns_servers(self.frame(600, [OTHER])), [(ADDR, 600), (OTHER, 0)])

    def test_an_earlier_address_that_is_the_current_one_is_not_added_twice(self):
        self.assertEqual(dns_servers(self.frame(600, [ADDR, OTHER, OTHER])), [(ADDR, 600), (OTHER, 0)])

    def test_it_refuses_to_come_from_an_address_that_works_outside_the_home(self):
        for bad in ("2a00:23c8::1", "fd00::1", "::1", "ff02::1", "192.168.1.5", "fe80::1%wlan0", "", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                announcer.build_dns_announcement(MAC, bad, 600)

    def test_it_refuses_to_call_off_an_address_that_works_outside_the_home(self):
        for bad in ("2a00:23c8::1", "fd00::1", "nonsense"):
            with self.assertRaises(ValueError, msg=bad):
                self.frame(0, [bad])

    def test_it_refuses_a_hardware_address_that_is_not_one_cards_own(self):
        for bad in ("33:33:00:00:00:01", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "b8:27:eb:12:34", "b8-27-eb-12-34-56",
                    "b8:27:eb:12:34:5g", "", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                announcer.build_dns_announcement(bad, ADDR, 600)

    def test_it_refuses_a_lifetime_that_is_not_a_whole_number_of_seconds_that_fits(self):
        for bad in (-1, 2 ** 32, 1.5, "600", None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.frame(bad)

    def test_it_refuses_to_call_off_more_than_a_few_earlier_addresses(self):
        many = ["fe80::%x" % n for n in range(1, announcer.MAX_WITHDRAWN + 2)]
        self.assertEqual(len(dns_servers(self.frame(0, many[:-1]))), announcer.MAX_WITHDRAWN + 1)
        with self.assertRaises(ValueError):
            self.frame(0, many)


class ThisComputersCard(unittest.TestCase):
    """Reading the card's details from stand-in copies of the two system files."""

    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="quietnet-announcer-test-")
        self.inet6 = os.path.join(self.folder, "if_inet6")
        self.cards = os.path.join(self.folder, "net")
        self.write("fe80000000000000ba27ebfffe123456 03 40 20 80    wlan0\n")
        self.card("wlan0", MAC + "\n")

    def write(self, text):
        with open(self.inet6, "w") as f:
            f.write(text)

    def card(self, name, address):
        os.makedirs(os.path.join(self.cards, name), exist_ok=True)
        with open(os.path.join(self.cards, name, "address"), "w") as f:
            f.write(address)

    def facts(self, card="wlan0"):
        return announcer.card_facts(card, self.inet6, self.cards)

    def test_the_cards_own_home_only_address_is_found(self):
        self.assertEqual(announcer.link_local_of("wlan0", self.inet6), ADDR)

    def test_an_address_on_another_card_is_not_used(self):
        self.write("fe800000000000000000000000000099 02 40 20 80     eth0\n"
                   "fe80000000000000ba27ebfffe123456 03 40 20 80    wlan0\n")
        self.assertEqual(announcer.link_local_of("wlan0", self.inet6), ADDR)
        self.assertEqual(announcer.link_local_of("docker0", self.inet6), "")

    def test_a_public_or_private_range_address_is_never_chosen(self):
        self.write("2a0023c8000000000000000000000005 03 40 00 00    wlan0\n"
                   "fd000000000000000000000000000005 03 40 00 00    wlan0\n")
        self.assertEqual(announcer.link_local_of("wlan0", self.inet6), "")

    def test_an_address_that_failed_its_check_or_is_still_being_checked_is_not_used(self):
        for flags in ("08", "40", "20", "c8"):
            self.write("fe80000000000000ba27ebfffe123456 03 40 20 %s    wlan0\n" % flags)
            self.assertEqual(announcer.link_local_of("wlan0", self.inet6), "", flags)

    def test_the_same_address_is_chosen_every_time_when_the_card_has_two(self):
        self.write("fe80000000000000ba27ebfffe123456 03 40 20 80    wlan0\n"
                   "fe800000000000000000000000000002 03 40 20 80    wlan0\n")
        self.assertEqual(announcer.link_local_of("wlan0", self.inet6), "fe80::2")

    def test_every_working_home_only_address_of_the_card_is_listed_lowest_first(self):
        self.write("fe80000000000000ba27ebfffe123456 03 40 20 80    wlan0\n"
                   "fe800000000000000000000000000002 03 40 20 80    wlan0\n"
                   "fe800000000000000000000000000003 03 40 20 40    wlan0\n"      # still being checked
                   "fe800000000000000000000000000001 02 40 20 80     eth0\n")
        self.assertEqual(announcer.link_locals_of("wlan0", self.inet6), ["fe80::2", ADDR])
        self.assertEqual(announcer.link_locals_of("wlan0", os.path.join(self.folder, "missing")), [])

    def test_a_card_with_two_home_only_addresses_gives_the_facts_and_a_reason_not_to_announce(self):
        # QuietNet's answers could leave from the one that was not announced; the facts are still
        # given, so devices already told can be sent a goodbye.
        self.write("fe80000000000000ba27ebfffe123456 03 40 20 80    wlan0\n"
                   "fe800000000000000000000000000002 03 40 20 80    wlan0\n")
        card, mac, address, reason = self.facts()
        self.assertEqual((card, mac, address), ("wlan0", MAC, "fe80::2"))
        self.assertIn("more than one home-only IPv6 address (fe80::2 and %s)" % ADDR, reason)
        self.assertIn("Remove the extra address, or leave the trial off.", reason)

    def test_a_list_that_cannot_be_read_gives_no_address(self):
        self.assertEqual(announcer.link_local_of("wlan0", os.path.join(self.folder, "missing")), "")
        self.write("this is not the list\nzz80000000000000ba27ebfffe123456 03 40 20 80 wlan0\n")
        self.assertEqual(announcer.link_local_of("wlan0", self.inet6), "")

    def test_the_cards_hardware_address_is_read(self):
        self.assertEqual(announcer.hardware_address_of("wlan0", self.cards), MAC)

    def test_a_card_name_that_could_point_outside_the_folder_is_refused(self):
        self.card("wlan0", MAC)
        with open(os.path.join(self.folder, "address"), "w") as f:
            f.write("aa:aa:aa:aa:aa:aa")
        for bad in ("..", "../net/wlan0", "wlan0/../wlan0", "/etc", "", "a" * 16, "wlan 0", None, 5):
            self.assertEqual(announcer.hardware_address_of(bad, self.cards), "", repr(bad))

    def test_everything_needed_is_found_for_a_working_card(self):
        self.assertEqual(self.facts(), ("wlan0", MAC, ADDR, ""))

    def test_a_card_with_no_ipv6_address_of_its_own_gives_a_plain_reason(self):
        self.write("")
        card, mac, address, reason = self.facts()
        self.assertEqual((card, mac, address), (None, None, None))
        self.assertIn("no IPv6 address of its own", reason)

    def test_a_card_with_no_usable_hardware_address_gives_a_plain_reason(self):
        for bad in ("00:00:00:00:00:00", "33:33:00:00:00:01", "nonsense"):
            self.card("wlan0", bad)
            self.assertIn("no hardware address", self.facts()[3], bad)

    def test_no_card_at_all_gives_a_plain_reason(self):
        for bad in ("", "../x", 7):
            self.assertIn("could not find the network card", self.facts(bad)[3])

    def test_the_card_is_the_one_the_home_network_is_on_when_none_is_named(self):
        with mock.patch.object(announcer.enforcer, "interface_and_gateway", return_value=("wlan0", "192.168.1.254")):
            self.assertEqual(announcer.card_facts(None, self.inet6, self.cards), ("wlan0", MAC, ADDR, ""))
        with mock.patch.object(announcer.enforcer, "interface_and_gateway", return_value=(None, None)):
            self.assertIn("could not find", announcer.card_facts(None, self.inet6, self.cards)[3])


class StandInDns:
    """A DNS server on 127.0.0.1 (or on ::1 when asked) for the test question.
    `answer(question)` gives the reply to send back, or None to stay silent. Raises OSError if
    the computer has no such address."""

    def __init__(self, answer, family=socket.AF_INET, address="127.0.0.1"):
        self.answer = answer
        self.asked = []
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            self.sock.bind((address, 0))
        except OSError:
            self.sock.close()
            raise
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.done.is_set():
            try:
                data, who = self.sock.recvfrom(512)
            except OSError:
                continue
            self.asked.append(data)
            reply = self.answer(data)
            if reply:
                self.sock.sendto(reply, who)

    def close(self):
        self.done.set()
        self.thread.join(2)
        self.sock.close()


class TheTestQuestion(Base):
    def stand_in(self, answer):
        dns = StandInDns(answer)
        self.addCleanup(dns.close)
        return dns

    def ask(self, dns, **kw):
        kw.setdefault("wait", 0.2)
        return announcer.dns_answers("127.0.0.1", port=dns.port, **kw)

    def test_quietnet_answering_counts_as_answering(self):
        dns = self.stand_in(lambda q: server.answer_query(q, "::1", lambda d, **kw: self.fail("asked the internet")))
        self.assertTrue(self.ask(dns))

    def test_the_question_is_a_bare_twelve_byte_header_with_no_name_in_it(self):
        dns = self.stand_in(lambda q: q[:2] + b"\x80\x81" + bytes(8))
        self.ask(dns)
        self.assertEqual(len(dns.asked[0]), 12)
        self.assertEqual(dns.asked[0][2:], bytes(10))

    def test_quietnet_answers_the_question_at_once_without_asking_the_internet(self):
        question = b"\x12\x34" + bytes(10)
        reply = server.answer_query(question, "fe80::1", lambda d, **kw: self.fail("asked the internet"))
        self.assertEqual(reply[:2], b"\x12\x34")
        self.assertTrue(reply[2] & 0x80)

    def test_quietnet_does_not_write_the_question_into_the_history(self):
        while not server.log_q.empty():
            server.log_q.get_nowait()
        server.answer_query(b"\x12\x34" + bytes(10), "fe80::1", lambda d, **kw: None)
        self.assertTrue(server.log_q.empty())

    def test_silence_counts_as_not_answering(self):
        dns = self.stand_in(lambda q: None)
        self.assertFalse(self.ask(dns, wait=0.05))

    def test_the_question_is_asked_again_once_before_giving_up(self):
        dns = self.stand_in(lambda q: None)
        self.ask(dns, wait=0.05)
        self.assertEqual(len(dns.asked), announcer.PROBE_TRIES)
        self.assertEqual(announcer.PROBE_TRIES, 2)

    def test_an_answer_to_the_second_question_is_enough(self):
        seen = []
        dns = self.stand_in(lambda q: seen.append(q) or (q[:2] + b"\x80\x81" + bytes(8) if len(seen) > 1 else None))
        self.assertTrue(self.ask(dns, wait=0.1))

    def test_an_answer_carrying_the_wrong_number_does_not_count(self):
        dns = self.stand_in(lambda q: bytes([q[0] ^ 0xFF, q[1]]) + b"\x80\x81" + bytes(8))
        self.assertFalse(self.ask(dns, wait=0.05))

    def test_the_question_sent_straight_back_does_not_count(self):
        dns = self.stand_in(lambda q: q)
        self.assertFalse(self.ask(dns, wait=0.05))

    def test_a_cut_short_answer_does_not_count(self):
        dns = self.stand_in(lambda q: q[:2] + b"\x80")
        self.assertFalse(self.ask(dns, wait=0.05))

    def test_nothing_listening_counts_as_not_answering(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spare:
            spare.bind(("127.0.0.1", 0))
            port = spare.getsockname()[1]
        self.assertFalse(announcer.dns_answers("127.0.0.1", port=port, wait=0.05))

    def test_an_address_that_cannot_be_read_counts_as_not_answering(self):
        for bad in ("", "nonsense", None, "fe80::1%nothing"):
            self.assertFalse(announcer.dns_answers(bad, wait=0.05), repr(bad))

    def test_a_home_only_address_on_a_card_that_does_not_exist_counts_as_not_answering(self):
        with mock.patch.object(socket, "if_nametoindex", side_effect=OSError("no such card")):
            self.assertFalse(announcer.dns_answers(ADDR, "nocard0", wait=0.05))

    # -- over IPv6, which is the only way a Pi ever asks ---------------------------

    def test_quietnet_answering_over_ipv6_counts_as_answering(self):
        try:
            dns = StandInDns(lambda q: server.answer_query(q, "::1", lambda d, **kw: self.fail("asked the internet")),
                             socket.AF_INET6, "::1")
        except OSError:
            self.skipTest("this computer has no IPv6 loopback address")
        self.addCleanup(dns.close)
        self.assertTrue(announcer.dns_answers("::1", port=dns.port, wait=0.2))
        self.assertEqual(len(dns.asked), 1)

    def answering_sockets(self, made):
        """A stand-in for socket.socket: each socket it makes is noted in `made` as (family,
        kind, socket), connects anywhere, and answers whatever is sent with a well-formed reply
        carrying the same number."""
        def make(family, kind):
            """One stand-in socket."""
            sock = mock.Mock()
            sock.send.side_effect = lambda q: sock.recv.configure_mock(return_value=q[:2] + b"\x80\x81" + bytes(8))
            made.append((family, kind, sock))
            return sock
        return make

    def test_a_home_only_address_is_asked_over_ipv6_through_its_own_card(self):
        made = []
        with mock.patch.object(socket, "socket", self.answering_sockets(made)), \
                mock.patch.object(socket, "if_nametoindex", return_value=7) as index:
            self.assertTrue(announcer.dns_answers(ADDR, CARD))
        index.assert_called_once_with(CARD)
        (family, kind, sock), = made
        self.assertEqual((family, kind), (socket.AF_INET6, socket.SOCK_DGRAM))
        sock.connect.assert_called_once_with((ADDR, 53, 0, 7))
        sock.close.assert_called_once_with()

    def test_an_address_that_works_anywhere_is_asked_without_naming_a_card(self):
        made = []
        with mock.patch.object(socket, "socket", self.answering_sockets(made)), \
                mock.patch.object(socket, "if_nametoindex", side_effect=AssertionError("looked up a card")):
            self.assertTrue(announcer.dns_answers("2001:db8::53", CARD))
        (family, kind, sock), = made
        self.assertEqual((family, kind), (socket.AF_INET6, socket.SOCK_DGRAM))
        sock.connect.assert_called_once_with(("2001:db8::53", 53, 0, 0))


class FakeSender:
    """Stands in for the raw sending socket: notes each frame and where it was sent."""

    def __init__(self, test):
        self.test = test

    def sendto(self, frame, where):
        if self.test.send_fails:
            raise self.test.send_fails
        if self.test.refuse_goodbyes and not any(lifetime for _, lifetime in dns_servers(frame)):
            raise OSError("Network is down")
        self.test.sent.append((bytes(frame), where))
        return len(frame)

    def close(self):
        self.test.closed += 1


class Trial(unittest.TestCase):
    """The announcer driven one step at a time, with a stand-in clock, card and socket."""

    def setUp(self):
        self.now = 1000.0
        self.sent, self.opened, self.closed, self.send_fails = [], [], 0, None
        self.refuse_goodbyes = False          # true: the stand-in card sends announcements but refuses goodbyes
        self.hold, self.hold_asked = "", []   # the reason to hold back the rest of QuietNet gives ('' = none)
        self.listening, self.answering, self.asked = True, True, []
        self.facts = (CARD, MAC, ADDR, "")
        self.facts_asked = 0
        self.pauses, self.logged = [], []

    def make(self, on=False, unavailable=""):
        def facts():
            self.facts_asked += 1
            return self.facts

        def answers(address, card):
            self.asked.append((address, card))
            return self.answering

        def open_sender(card):
            self.opened.append(card)
            return FakeSender(self)

        def hold_reason(address):
            self.hold_asked.append(address)
            return self.hold

        an = announcer.Announcer(lambda: self.listening, on=on, log=self.logged.append, facts=facts, answers=answers,
                                 open_sender=open_sender, clock=lambda: self.now, pause=self.pauses.append,
                                 unavailable=unavailable, hold_reason=hold_reason)
        self.addCleanup(an.stop, 2)
        return an

    def settled(self):
        """An announcer past its first quick announcements, so the next one is 200 seconds away."""
        an = self.make(on=True)
        for _ in range(announcer.FIRST_ANNOUNCEMENTS):
            an.step()
            self.now += announcer.FIRST_GAP
        return an

    def goodbyes(self):
        """How many frames sent so far are goodbyes (no address offered, every lifetime 0)."""
        return sum(1 for frame, _ in self.sent if not any(lifetime for _, lifetime in dns_servers(frame)))

    def lifetimes(self):
        """The DNS lifetime of this computer's address in each frame sent so far."""
        return [dict(dns_servers(frame)).get(ADDR) for frame, _ in self.sent]

    def offers(self):
        """How many frames sent so far offer this computer as a DNS server (lifetime above 0)."""
        return sum(1 for frame, _ in self.sent for _, lifetime in dns_servers(frame) if lifetime)

    # -- off unless switched on ------------------------------------------------

    def test_a_new_announcer_is_off(self):
        an = announcer.Announcer(lambda: True, unavailable="")
        self.assertIs(an.on, False)
        self.assertEqual(an.status()["state"], "off")

    def test_nothing_is_sent_while_the_trial_is_off(self):
        an = self.make()
        for _ in range(5):
            an.step()
            self.now += 300
        self.assertEqual(self.sent, [])

    def test_no_socket_is_opened_while_the_trial_is_off(self):
        self.make().step()
        self.assertEqual(self.opened, [])

    def test_the_card_is_not_even_looked_at_while_the_trial_is_off(self):
        self.make().step()
        self.assertEqual((self.facts_asked, self.asked), (0, []))

    def test_while_off_there_is_nothing_to_do_until_it_is_switched(self):
        self.assertIsNone(self.make().step())

    def test_the_background_thread_sends_nothing_while_the_trial_is_off(self):
        an = self.make()
        an.start()
        time.sleep(0.1)
        an.stop(2)
        self.assertEqual((self.sent, self.opened), ([], []))

    # -- announcing ------------------------------------------------------------

    def test_switched_on_it_sends_the_announcement_with_the_ten_minute_dns_lifetime(self):
        an = self.make()
        an.switch(True)
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT])

    def test_frames_are_sent_out_of_the_home_network_card_marked_as_ipv6(self):
        self.make(on=True).step()
        self.assertEqual(self.sent[0][1], ("wlan0", 0x86DD))
        self.assertEqual(self.opened, ["wlan0"])

    def test_the_first_three_announcements_go_sixteen_seconds_apart(self):
        an = self.make(on=True)
        times = []
        for _ in range(40):
            before = len(self.sent)
            an.step()
            if len(self.sent) > before:
                times.append(self.now - 1000)
            self.now += 1
        self.assertEqual(times, [0, 16, 32])

    def test_after_the_first_three_one_goes_every_two_hundred_seconds(self):
        an = self.make(on=True)
        times = []
        for _ in range(700):
            before = len(self.sent)
            an.step()
            if len(self.sent) > before:
                times.append(self.now - 1000)
            self.now += 1
        self.assertEqual(times, [0, 16, 32, 232, 432, 632])
        self.assertEqual(self.lifetimes(), [600] * 6)

    def test_no_announcement_is_sent_before_the_next_is_due(self):
        an = self.make(on=True)
        an.step()
        self.now += 15
        an.step()
        self.assertEqual(len(self.sent), 1)

    def test_one_socket_is_kept_for_all_the_announcements(self):
        an = self.make(on=True)
        for _ in range(3):
            an.step()
            self.now += 20
        self.assertEqual(len(self.opened), 1)

    def test_the_next_look_is_never_more_than_twenty_seconds_away(self):
        an = self.make(on=True)
        for _ in range(60):
            wait = an.step()
            self.assertLessEqual(wait, announcer.CHECK_EVERY)
            self.assertGreaterEqual(wait, 1)
            self.now += wait

    def test_the_status_says_what_is_being_announced(self):
        an = self.make(on=True)
        an.step()
        status = an.status()
        self.assertEqual((status["on"], status["state"], status["address"], status["reason"]), (True, "announcing", ADDR, ""))
        self.assertEqual((status["lifetime"], status["every"], status["available"]), (600, 200, True))
        self.assertAlmostEqual(status["sent"], time.time(), delta=5)

    # -- only while QuietNet answers over IPv6 -----------------------------------

    def test_it_never_offers_itself_while_the_ipv6_listener_is_not_open(self):
        self.listening = False
        an = self.make(on=True)
        for _ in range(30):
            an.step()
            self.now += 20
        self.assertEqual(self.offers(), 0)
        self.assertEqual(an.status()["state"], "held")

    def test_it_never_offers_itself_while_quietnet_does_not_answer_the_test_question(self):
        self.answering = False
        an = self.make(on=True)
        for _ in range(30):
            an.step()
            self.now += 20
        self.assertEqual(self.offers(), 0)
        self.assertIn("did not answer a test lookup over IPv6", an.status()["reason"])

    def test_the_test_question_goes_to_the_very_address_about_to_be_announced(self):
        self.make(on=True).step()
        self.assertEqual(self.asked, [(ADDR, "wlan0")])

    def test_the_test_question_is_asked_before_every_announcement_and_between_them(self):
        an = self.make(on=True)
        for _ in range(12):
            self.now += an.step()
        self.assertEqual(len(self.asked), 12)
        self.assertLess(len(self.sent), 12)

    def test_the_test_question_is_not_asked_while_the_listener_is_not_open(self):
        self.listening = False
        self.make(on=True).step()
        self.assertEqual(self.asked, [])

    def test_a_check_that_breaks_counts_as_not_answering(self):
        an = self.make(on=True)
        an._answers = mock.Mock(side_effect=RuntimeError("broken"))
        an.dns_listening = mock.Mock(side_effect=RuntimeError("broken"))
        an.step()
        self.assertEqual((self.offers(), an.status()["state"]), (0, "held"))

    def test_devices_are_told_to_stop_as_soon_as_quietnet_stops_answering(self):
        an = self.make(on=True)
        an.step()
        self.answering = False
        self.now += announcer.CHECK_EVERY
        an.step()
        self.assertEqual(self.lifetimes(), [600, 0, 0, 0])
        self.assertEqual([frame for frame, _ in self.sent[1:]], [KNOWN_GOODBYE] * 3)

    def test_quietnet_not_answering_is_noticed_within_twenty_seconds(self):
        an = self.make(on=True)
        for _ in range(5):
            self.now += an.step()
        self.assertLessEqual(an.step(), 20)

    def test_while_held_back_the_goodbye_is_not_sent_over_and_over(self):
        an = self.make(on=True)
        an.step()
        self.answering = False
        for _ in range(10):
            self.now += 20
            an.step()
        self.assertEqual(self.lifetimes(), [600, 0, 0, 0])

    def test_announcing_starts_again_at_once_when_quietnet_answers_again(self):
        # From the settled state, where the next announcement would not be due for 200 seconds.
        an = self.settled()
        self.answering = False
        self.now += 20
        an.step()
        self.answering = True
        self.now += 20
        an.step()
        self.assertEqual(self.lifetimes(), [600] * 3 + [0] * 3 + [600])
        self.assertEqual(an.status()["state"], "announcing")

    def test_starting_again_the_first_three_announcements_go_sixteen_seconds_apart_again(self):
        an = self.settled()
        self.answering = False
        self.now += 20
        an.step()
        self.answering = True
        self.now += 20
        began, times = self.now, []
        for _ in range(40):
            before = len(self.sent)
            an.step()
            if len(self.sent) > before:
                times.append(self.now - began)
            self.now += 1
        self.assertEqual(times, [0, 16, 32])

    def test_started_while_unable_to_answer_it_tells_devices_to_stop_once(self):
        # QuietNet may have ended without warning while announcing; devices could still hold it.
        self.listening = False
        an = self.make(on=True)
        for _ in range(4):
            an.step()
            self.now += 20
        self.assertEqual(self.lifetimes(), [0, 0, 0])

    def test_the_status_while_held_back_gives_the_reason_and_no_address(self):
        self.listening = False
        an = self.make(on=True)
        an.step()
        status = an.status()
        self.assertEqual((status["state"], status["address"], status["sent"]), ("held", "", None))
        self.assertIn("not taking lookups over IPv6 on the usual DNS port (53)", status["reason"])

    def test_once_held_back_the_status_no_longer_says_when_it_last_announced(self):
        an = self.make(on=True)
        an.step()
        self.listening = False
        self.now += 20
        an.step()
        status = an.status()
        self.assertEqual((status["state"], status["address"], status["sent"]), ("held", "", None))

    def test_switched_on_from_off_the_status_says_starting_until_the_first_step(self):
        an = self.make()
        an.switch(True)
        self.assertEqual((an.status()["on"], an.status()["state"]), (True, "starting"))

    def test_switched_off_while_announcing_the_status_says_stopping_until_the_goodbye(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        self.assertEqual((an.status()["on"], an.status()["state"]), (False, "stopping"))

    def test_while_stopping_the_status_gives_no_address_and_no_time(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        status = an.status()
        self.assertEqual((status["address"], status["sent"]), ("", None))

    # -- holding back when the rest of QuietNet gives a reason ---------------------

    def test_nothing_is_announced_while_there_is_a_reason_to_hold_back(self):
        self.hold = "Some devices here connect through a Wi-Fi range extender."
        an = self.make(on=True)
        for _ in range(30):
            an.step()
            self.now += 20
        self.assertEqual(self.offers(), 0)
        self.assertEqual((an.status()["state"], an.status()["reason"]), ("held", self.hold))

    def test_with_no_reason_to_hold_back_the_frames_are_byte_for_byte_as_before(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)
        self.assertEqual(self.hold_asked, [ADDR])

    def test_the_reason_is_asked_about_the_very_address_about_to_be_announced(self):
        self.facts = (CARD, MAC, OTHER, "")
        self.make(on=True).step()
        self.assertEqual(self.hold_asked, [OTHER])

    def test_the_reason_is_asked_before_every_announcement_and_between_them(self):
        an = self.make(on=True)
        for _ in range(12):
            self.now += an.step()
        self.assertEqual(len(self.hold_asked), 12)

    def test_a_reason_appearing_while_announcing_sends_the_goodbye_and_holds(self):
        an = self.settled()
        self.hold = "A range extender has been noticed."
        self.now += 20
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] * 3 + [KNOWN_GOODBYE] * 3)
        self.assertEqual(an.status()["state"], "held")

    def test_while_the_reason_lasts_the_goodbye_is_sent_once_and_not_again(self):
        an = self.settled()
        self.hold = "A range extender has been noticed."
        for _ in range(10):
            self.now += 20
            an.step()
        self.assertEqual(self.lifetimes(), [600] * 3 + [0] * 3)

    def test_announcing_resumes_at_once_when_the_reason_clears(self):
        an = self.settled()
        self.hold = "A range extender has been noticed."
        self.now += 20
        an.step()
        self.hold = ""
        self.now += 20
        an.step()
        self.assertEqual(self.lifetimes(), [600] * 3 + [0] * 3 + [600])
        self.assertEqual(an.status()["state"], "announcing")

    def test_the_test_question_is_not_asked_while_there_is_a_reason_to_hold_back(self):
        self.hold = "A range extender has been noticed."
        self.make(on=True).step()
        self.assertEqual(self.asked, [])

    def test_a_hold_back_check_that_breaks_counts_as_a_reason(self):
        an = self.make(on=True)
        an.hold_reason = mock.Mock(side_effect=RuntimeError("broken"))
        an.step()
        self.assertEqual((self.offers(), an.status()["state"]), (0, "held"))
        self.assertIn("could not tell whether it is safe to announce itself", an.status()["reason"])

    def test_an_announcer_given_no_hold_back_check_announces(self):
        sent = []
        sender = mock.Mock()
        sender.sendto.side_effect = lambda frame, where: sent.append(bytes(frame))
        an = announcer.Announcer(lambda: True, on=True, log=lambda line: None, facts=lambda: (CARD, MAC, ADDR, ""),
                                 answers=lambda a, c: True, open_sender=lambda card: sender, unavailable="")
        an.step()
        self.assertEqual(sent, [KNOWN_ANNOUNCEMENT])

    # -- stopping ----------------------------------------------------------------

    def test_switching_off_sends_the_goodbye_three_times(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)
        self.assertEqual(announcer.GOODBYES, 3)

    def test_the_goodbyes_are_spaced_a_moment_apart(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        an.step()
        self.assertEqual(self.pauses, [announcer.GOODBYE_GAP] * 2)

    def test_nothing_more_is_sent_after_the_goodbye(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        for _ in range(5):
            an.step()
            self.now += 300
        self.assertEqual(self.lifetimes(), [600, 0, 0, 0])

    def test_switching_off_closes_the_socket(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        an.step()
        self.assertEqual(self.closed, 1)
        self.assertEqual(an.status()["state"], "off")

    def test_switched_off_before_anything_was_announced_no_goodbye_is_sent(self):
        an = self.make()
        an.switch(True)
        an.switch(False)
        an.step()
        self.assertEqual(self.sent, [])

    def test_switched_on_again_it_announces_at_once(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        an.step()
        an.switch(True)
        an.step()
        self.assertEqual(self.lifetimes(), [600, 0, 0, 0, 600])

    def test_a_clean_stop_sends_the_goodbye_before_the_thread_ends(self):
        an = self.make(on=True)
        an.start()
        deadline = time.time() + 5
        while not self.sent and time.time() < deadline:
            time.sleep(0.01)
        an.stop(5)
        self.assertFalse(an._thread.is_alive())
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)
        self.assertEqual(self.closed, 1)

    def test_switching_off_reaches_the_running_thread_at_once(self):
        an = self.make(on=True)
        an.start()
        deadline = time.time() + 5
        while not self.sent and time.time() < deadline:
            time.sleep(0.01)
        an.switch(False)
        while len(self.sent) < 4 and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.lifetimes(), [600, 0, 0, 0])

    def test_the_wait_at_a_clean_stop_covers_a_check_under_way_and_the_goodbyes(self):
        # main() calls AN.stop() with the wait it comes with; the thread is a daemon, so if the
        # wait ran out the program would end before the goodbyes left.
        wait = inspect.signature(announcer.Announcer.stop).parameters["wait"].default
        check = announcer.PROBE_TRIES * announcer.PROBE_WAIT            # a test question already under way
        goodbyes = (announcer.GOODBYES - 1) * announcer.GOODBYE_GAP     # the pauses between the goodbyes
        self.assertEqual(announcer.GOODBYE_GAP, 0.3)
        self.assertLessEqual(check + goodbyes + 1, wait)                # a second to spare
        grace = int(re.search(r"stop_grace_period: (\d+)s", read("docker-compose.yml")).group(1))
        enforcer_wait = inspect.signature(enforcer.Enforcer.stop).parameters["wait"].default
        self.assertLessEqual(enforcer_wait + wait, grace)               # both waits fit the container's stop time

    # -- a goodbye that could not be sent ------------------------------------------

    def test_a_goodbye_the_card_refused_is_tried_again_at_the_next_look(self):
        an = self.make(on=True)
        an.step()
        self.answering, self.send_fails = False, OSError("Network is down")
        self.now += 20
        an.step()
        self.assertEqual((self.lifetimes(), an.status()["state"]), ([600], "held"))
        self.send_fails = None
        self.now += 20
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_a_goodbye_that_went_at_the_second_go_is_not_sent_again(self):
        an = self.make(on=True)
        an.step()
        self.answering, self.send_fails = False, OSError("Network is down")
        self.now += 20
        an.step()
        self.send_fails = None
        for _ in range(5):
            self.now += 20
            an.step()
        self.assertEqual(self.lifetimes(), [600, 0, 0, 0])

    def test_a_goodbye_that_never_got_out_is_given_up_once_the_dns_lifetime_has_passed(self):
        an = self.make(on=True)
        an.step()
        self.answering, self.send_fails = False, OSError("Network is down")
        for _ in range(announcer.DNS_LIFETIME // 20):
            self.now += 20
            an.step()
        tried = len(self.opened)
        self.assertGreater(tried, 10)                    # it kept trying while devices still held the address
        self.send_fails = None
        for _ in range(5):
            self.now += 20
            an.step()
        self.assertEqual((self.lifetimes(), len(self.opened)), ([600], tried))

    def test_started_without_the_right_to_send_the_goodbye_is_not_retried_for_ever(self):
        self.listening, self.send_fails = False, PermissionError("Operation not permitted")
        an = self.make(on=True)
        for _ in range(6):
            an.step()
            self.now += 20
        self.assertEqual(len(self.opened), 1)

    def test_when_the_card_loses_its_address_the_goodbye_goes_from_the_last_announced_one(self):
        # The frame is sent whole, so it needs no IPv6 address on the card any more.
        an = self.make(on=True)
        an.step()
        self.facts = (None, None, None, "This computer's home network card has no IPv6 address of its own.")
        self.now += 20
        an.step()
        self.assertEqual(self.sent[1:], [(KNOWN_GOODBYE, (CARD, 0x86DD))] * 3)
        self.assertEqual(an.status()["state"], "held")

    def test_switching_off_while_the_card_has_no_address_still_sends_the_goodbye(self):
        an = self.make(on=True)
        an.step()
        self.facts = (None, None, None, "This computer's home network card has no IPv6 address of its own.")
        an.switch(False)
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)
        self.assertEqual(an.status()["state"], "off")

    def test_a_clean_stop_while_the_card_has_no_address_still_sends_the_goodbye(self):
        an = self.make(on=True)
        an.step()
        self.facts = (None, None, None, "This computer's home network card has no IPv6 address of its own.")
        an.ask_to_stop()
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_a_goodbye_still_goes_when_asking_about_the_card_breaks(self):
        an = self.make(on=True)
        an.step()
        an._facts = mock.Mock(side_effect=RuntimeError("broken"))
        an.switch(False)
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_switching_off_just_after_the_card_went_missing_still_sends_the_goodbye(self):
        # One look found no card and could send nothing; the card is back when the trial is switched off.
        an = self.make(on=True)
        an.step()
        working = self.facts
        self.facts, self.send_fails = (None, None, None, "QuietNet could not find the network card."), OSError("No such device")
        self.now += 20
        an.step()
        self.facts, self.send_fails = working, None
        an.switch(False)
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_a_clean_stop_just_after_the_card_went_missing_still_sends_the_goodbye(self):
        an = self.make(on=True)
        an.step()
        working = self.facts
        self.facts, self.send_fails = (None, None, None, "QuietNet could not find the network card."), OSError("No such device")
        self.now += 20
        an.step()
        self.facts, self.send_fails = working, None
        an.ask_to_stop()
        an.step()
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_an_address_lost_while_the_card_was_missing_is_still_called_off_when_a_new_one_appears(self):
        an = self.make(on=True)
        an.step()
        self.facts, self.send_fails = (None, None, None, "QuietNet could not find the network card."), OSError("No such device")
        self.now += 20
        an.step()
        self.facts, self.send_fails = (CARD, MAC, OTHER, ""), None
        self.now += 20
        an.step()
        self.assertEqual([dns_servers(frame) for frame, _ in self.sent],
                         [[(ADDR, 600)]] + [[(OTHER, 0), (ADDR, 0)]] * 3 + [[(OTHER, 600)]])

    def test_an_old_address_whose_goodbye_keeps_failing_does_not_make_announcements_come_faster(self):
        # The new address is announced; the goodbye for the old one is refused at every look. That
        # must not start the quick first announcements again each time.
        an = self.make(on=True)
        an.step()
        self.facts, self.refuse_goodbyes = (CARD, MAC, OTHER, ""), True
        began, times = self.now + 20, []
        for _ in range(12):
            self.now += 20
            before = len(self.sent)
            an.step()
            if len(self.sent) > before:
                times.append(self.now - began)
        self.assertEqual(times, [0, 20, 40])             # the first three, then nothing until 200 seconds on
        self.assertEqual(self.goodbyes(), 0)

    def test_the_log_never_says_devices_were_told_when_no_goodbye_left(self):
        an = self.make(on=True)
        an.step()
        self.send_fails = OSError("Network is down")
        an.switch(False)
        an.step()
        self.assertEqual(self.goodbyes(), 0)
        self.assertFalse(any("were told to stop" in line for line in self.logged))
        self.assertTrue(any("switched off, but this computer could not send the message telling devices to stop"
                            in line for line in self.logged))

    def test_a_clean_stop_that_cannot_send_the_goodbye_says_so_in_the_log(self):
        an = self.make(on=True)
        an.step()
        self.send_fails = OSError("Network is down")
        an.ask_to_stop()
        self.assertIsNone(an.step())
        self.assertFalse(any("were told to stop" in line for line in self.logged))
        self.assertIn("IPv6 DNS announcement trial: stopped, but this computer could not send the message telling "
                      "devices to stop using it for IPv6 DNS. They stop by themselves within 10 minutes.", self.logged)

    def test_switched_off_with_a_goodbye_still_owed_it_keeps_looking_every_twenty_seconds(self):
        an = self.make(on=True)
        an.step()
        self.send_fails = OSError("Network is down")
        an.switch(False)
        self.assertEqual(an.step(), announcer.CHECK_EVERY)
        status = an.status()
        self.assertEqual((status["on"], status["state"], status["address"]), (False, "stopping", ""))
        self.assertIn("could not send the message yet", status["reason"])

    def test_switching_off_keeps_trying_the_goodbye_until_it_goes(self):
        an = self.make(on=True)
        an.step()
        self.send_fails = OSError("Network is down")
        an.switch(False)
        for _ in range(3):
            an.step()
            self.now += 20
        self.send_fails = None
        self.assertIsNone(an.step())
        self.assertEqual([frame for frame, _ in self.sent], [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)
        self.assertEqual((an.status()["state"], an.status()["reason"]), ("off", ""))
        self.assertTrue(self.logged[-1].endswith("Devices were told to stop using this computer for IPv6 DNS."))

    def test_the_line_saying_the_goodbye_could_not_be_sent_is_logged_once_not_at_every_look(self):
        an = self.make(on=True)
        an.step()
        self.send_fails = OSError("Network is down")
        an.switch(False)
        for _ in range(8):
            an.step()
            self.now += 20
        self.assertEqual(sum(1 for line in self.logged if "could not send the message" in line), 1)

    def test_switched_off_and_never_able_to_send_it_gives_up_after_the_ten_minutes_and_says_so(self):
        an = self.make(on=True)
        an.step()
        self.send_fails = OSError("Network is down")
        an.switch(False)
        waits = []
        for _ in range(announcer.DNS_LIFETIME // 20 + 1):
            waits.append(an.step())
            self.now += 20
        self.assertEqual((waits[0], waits[-1], an.status()["state"]), (announcer.CHECK_EVERY, None, "off"))
        self.assertIn("The message telling devices to stop never got out", self.logged[-1])
        self.assertFalse(any("were told to stop" in line for line in self.logged))

    def test_switched_on_again_while_a_goodbye_is_owed_it_announces_again(self):
        an = self.make(on=True)
        an.step()
        self.send_fails = OSError("Network is down")
        an.switch(False)
        an.step()
        self.send_fails = None
        an.switch(True)
        self.assertEqual(an.status()["state"], "starting")
        self.now += 20
        an.step()
        self.assertEqual((self.lifetimes(), an.status()["state"]), ([600, 600], "announcing"))

    # -- a card with two home-only addresses ----------------------------------------

    def test_a_card_with_two_home_only_addresses_is_not_announced_from_and_the_reason_says_so(self):
        self.facts = (CARD, MAC, "fe80::2", "This computer's home network card has more than one home-only IPv6 address.")
        an = self.make(on=True)
        for _ in range(5):
            an.step()
            self.now += 20
        self.assertEqual(self.offers(), 0)
        self.assertEqual((an.status()["state"], an.status()["reason"]), ("held", self.facts[3]))

    def test_devices_are_still_told_to_stop_when_a_second_address_appears_while_announcing(self):
        an = self.make(on=True)
        an.step()
        self.facts = (CARD, MAC, "fe80::2", "This computer's home network card has more than one home-only IPv6 address.")
        self.now += 20
        an.step()
        self.assertEqual([dns_servers(frame) for frame, _ in self.sent],
                         [[(ADDR, 600)]] + [[("fe80::2", 0), (ADDR, 0)]] * 3)

    def test_switching_off_with_two_addresses_on_the_card_still_sends_the_goodbye(self):
        an = self.make(on=True)
        an.step()
        self.facts = (CARD, MAC, "fe80::2", "This computer's home network card has more than one home-only IPv6 address.")
        an.switch(False)
        an.step()
        self.assertEqual([dns_servers(frame) for frame, _ in self.sent],
                         [[(ADDR, 600)]] + [[("fe80::2", 0), (ADDR, 0)]] * 3)
        self.assertEqual(an.status()["state"], "off")

    def test_a_stop_while_off_sends_nothing(self):
        an = self.make()
        an.start()
        an.stop(2)
        self.assertEqual(self.sent, [])

    def test_a_step_that_breaks_does_not_end_the_thread(self):
        an = self.make(on=True)
        calls = []

        def facts():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("broken once")
            return self.facts

        an._facts = facts
        with mock.patch.object(announcer, "CHECK_EVERY", 0.01):
            an.start()
            deadline = time.time() + 5
            while not self.sent and time.time() < deadline:
                time.sleep(0.01)
        self.assertEqual(self.lifetimes()[:1], [600])
        self.assertTrue(any("problem (broken once)" in line for line in self.logged))

    # -- when things are missing or change -----------------------------------------

    def test_a_changed_address_is_called_off_and_the_new_one_announced_at_once(self):
        # From the settled state, where the next announcement would not be due for 200 seconds.
        an = self.settled()
        self.facts = (CARD, MAC, OTHER, "")
        self.now += 20
        an.step()
        self.assertEqual([dns_servers(frame) for frame, _ in self.sent],
                         [[(ADDR, 600)]] * 3 + [[(OTHER, 0), (ADDR, 0)]] * 3 + [[(OTHER, 600)]])
        self.assertEqual(an.status()["address"], OTHER)

    def test_a_changed_address_is_announced_at_once_even_just_after_an_announcement(self):
        an = self.make(on=True)
        an.step()
        self.facts = (CARD, MAC, OTHER, "")
        self.now += 5
        an.step()
        self.assertEqual(dns_servers(self.sent[-1][0]), [(OTHER, 600)])

    def test_a_changed_address_gets_its_first_three_announcements_sixteen_seconds_apart(self):
        an = self.settled()
        self.facts = (CARD, MAC, OTHER, "")
        self.now += 20
        began, times = self.now, []
        for _ in range(40):
            before = self.offers()
            an.step()
            if self.offers() > before:
                times.append(self.now - began)
            self.now += 1
        self.assertEqual(times, [0, 16, 32])

    def test_every_frame_ever_sent_has_a_correct_check_number_and_router_lifetime_zero(self):
        an = self.make(on=True)
        an.step()
        self.facts = (CARD, MAC, OTHER, "")
        self.now += 20
        an.step()
        an.switch(False)
        an.step()
        self.assertEqual(len(self.sent), 8)
        for frame, _ in self.sent:
            self.assertTrue(checksum_holds(frame))
            self.assertEqual(frame[60:62], b"\x00\x00")

    def test_a_missing_card_is_reported_and_nothing_is_sent(self):
        self.facts = (None, None, None, "QuietNet could not find the network card.")
        an = self.make(on=True)
        self.assertEqual(an.step(), announcer.CHECK_EVERY)
        self.assertEqual(self.sent, [])
        self.assertEqual((an.status()["state"], an.status()["reason"]), ("held", "QuietNet could not find the network card."))

    def test_when_the_card_comes_back_announcing_starts(self):
        self.facts = (None, None, None, "QuietNet could not find the network card.")
        an = self.make(on=True)
        an.step()
        self.facts = (CARD, MAC, ADDR, "")
        self.now += 20
        an.step()
        self.assertEqual(self.lifetimes(), [600])

    def test_a_frame_the_system_refuses_to_send_is_reported_not_raised(self):
        self.send_fails = PermissionError("Operation not permitted")
        an = self.make(on=True)
        self.assertEqual(an.step(), announcer.CHECK_EVERY)
        status = an.status()
        self.assertEqual(status["state"], "held")
        self.assertIn("would not send the announcement (Operation not permitted)", status["reason"])
        self.assertIn("NET_RAW", status["reason"])

    def test_a_socket_that_cannot_be_opened_is_reported_not_raised(self):
        an = self.make(on=True)
        an._open_sender = mock.Mock(side_effect=PermissionError("Operation not permitted"))
        an.step()
        self.assertEqual((self.sent, an.status()["state"]), ([], "held"))

    def test_a_card_whose_details_would_make_a_bad_frame_is_held_back(self):
        self.facts = (CARD, "33:33:00:00:00:01", ADDR, "")
        an = self.make(on=True)
        an.step()
        self.assertEqual((self.sent, an.status()["state"]), ([], "held"))

    def test_where_it_cannot_run_it_says_so_and_sends_nothing(self):
        an = self.make(on=True, unavailable="This trial only works on Linux.")
        self.assertIsNone(an.step())
        status = an.status()
        self.assertEqual((status["available"], status["state"], status["reason"]),
                         (False, "unavailable", "This trial only works on Linux."))
        self.assertEqual((self.sent, self.opened, self.facts_asked), ([], [], 0))

    def test_it_can_still_be_switched_off_where_it_cannot_run(self):
        an = self.make(on=True, unavailable="This trial only works on Linux.")
        an.step()
        an.switch(False)
        an.step()
        self.assertEqual((an.status()["on"], an.status()["state"]), (False, "off"))

    def test_changes_of_state_are_written_to_the_log_in_plain_words(self):
        an = self.make(on=True)
        an.step()
        an.switch(False)
        an.step()
        self.assertIn("IPv6 DNS announcement trial: announcing %s on wlan0, about every 200 seconds." % ADDR, self.logged)
        self.assertTrue(any("Devices were told to stop using this computer for IPv6 DNS" in line for line in self.logged))


class TheSendingSocket(unittest.TestCase):
    def test_it_is_opened_for_sending_only(self):
        made = []
        with mock.patch.object(announcer, "AF_PACKET", 17), \
                mock.patch.object(announcer.socket, "socket", side_effect=lambda *a: made.append(a) or "the socket"):
            self.assertEqual(announcer.open_sender("wlan0"), "the socket")
        self.assertEqual(made, [(17, socket.SOCK_RAW, 0)])     # protocol 0: Linux hands it nothing to read

    def test_without_raw_frames_on_this_computer_it_fails_plainly(self):
        with mock.patch.object(announcer, "AF_PACKET", None):
            with self.assertRaises(OSError):
                announcer.open_sender("wlan0")

    def test_the_trial_is_unavailable_where_raw_frames_cannot_be_sent(self):
        with mock.patch.object(announcer, "AF_PACKET", None):
            self.assertIn("only works where QuietNet runs on a Raspberry Pi", announcer.why_unavailable())

    def test_the_trial_is_available_on_linux_with_ipv6(self):
        with mock.patch.object(announcer, "AF_PACKET", 17), mock.patch.object(announcer.os.path, "exists", return_value=True):
            self.assertEqual(announcer.why_unavailable(), "")


class InTheServer(Api):
    """The trial's wiring into server.py: the saved choice, the status, the switch."""

    def setUp(self):
        super().setUp()
        self.sent = []
        test = self

        class Sender:
            """Notes each frame instead of sending it."""

            def sendto(self, frame, where):
                test.sent.append(bytes(frame))

            def close(self):
                pass

        self.an = announcer.Announcer(lambda: True, facts=lambda: (CARD, MAC, ADDR, ""), answers=lambda a, c: True,
                                      open_sender=lambda card: Sender(), pause=lambda s: None, unavailable="",
                                      log=lambda line: None)
        p = mock.patch.object(server, "AN", self.an)
        p.start()
        self.addCleanup(p.stop)

    def test_the_trial_is_off_unless_the_owner_has_switched_it_on(self):
        self.assertIs(server.make_announcer().on, False)

    def test_the_owners_choice_is_kept_across_a_restart(self):
        self.ok("/api/dns-announce-switch", {"on": True})
        self.assertIs(server.make_announcer().on, True)
        self.ok("/api/dns-announce-switch", {"on": False})
        self.assertIs(server.make_announcer().on, False)

    def test_the_status_shows_the_trial_as_off_to_begin_with(self):
        trial = self.get("/api/status")[1]["dns_announce"]
        self.assertEqual((trial["on"], trial["state"], trial["address"]), (False, "off", ""))

    def test_switching_it_on_through_the_api_starts_the_announcements(self):
        out = self.ok("/api/dns-announce-switch", {"on": True})
        self.assertEqual((out["ok"], out["on"], out["state"]), (True, True, "starting"))
        self.an.step()
        self.assertEqual(self.sent, [KNOWN_ANNOUNCEMENT])
        self.assertEqual(self.get("/api/status")[1]["dns_announce"]["state"], "announcing")

    def test_switching_it_off_through_the_api_sends_the_goodbye(self):
        self.ok("/api/dns-announce-switch", {"on": True})
        self.an.step()
        out = self.ok("/api/dns-announce-switch", {"on": False})
        self.assertEqual((out["on"], out["state"], out["address"]), (False, "stopping", ""))
        self.an.step()
        self.assertEqual(self.sent, [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_only_a_plain_true_switches_it_on(self):
        for not_true in ("yes", 1, "true", None, {}, [True]):
            self.ok("/api/dns-announce-switch", {"on": not_true})
            self.assertIs(self.an.on, False, repr(not_true))
            self.assertIs(server.make_announcer().on, False, repr(not_true))

    def test_the_switch_is_refused_unless_it_arrives_as_json(self):
        status, _ = self.post("/api/dns-announce-switch", raw="on=true", ctype="application/x-www-form-urlencoded")
        self.assertNotEqual(status, 200)
        self.assertIs(self.an.on, False)

    def test_before_the_announcer_exists_the_switch_says_so_and_saves_nothing(self):
        with mock.patch.object(server, "AN", None):
            status, out = self.post("/api/dns-announce-switch", {"on": True})
            self.assertEqual(status, 400)
            self.assertIn("not running", out["error"])
            self.assertIsNone(self.get("/api/status")[1]["dns_announce"])
        self.assertIs(server.make_announcer().on, False)

    def test_the_announcer_asks_whether_the_ipv6_listener_is_open_on_port_53(self):
        made = server.make_announcer()
        self.assertIs(made.dns_listening, server.ipv6_dns_listening)
        for dns_ipv6, port, expected in ((True, 53, True), (False, 53, False), (True, 5353, False), (False, 5353, False)):
            with mock.patch.object(server.S, "dns_ipv6", dns_ipv6), mock.patch.object(server.S, "dns_port", port):
                self.assertIs(server.ipv6_dns_listening(), expected)

    def test_announcing_changes_nothing_the_dashboard_says_about_ipv6_and_bypassing(self):
        # The hub still names its own server, so the trial must never make anything look covered.
        now, mono = time.time(), time.monotonic()
        server.S.ra_heard, server.S.router_v6_dns = now, {"fe80::1": now + 600}
        before = server.ipv6_dns_view(now, mono)
        self.assertEqual((before["in_use"], before["router_dns_not_ours"], before["hub_off"]), (True, ["fe80::1"], False))
        self.ok("/api/dns-announce-switch", {"on": True})
        self.an.step()
        self.assertEqual(self.an.status()["state"], "announcing")
        self.assertEqual(server.ipv6_dns_view(now, mono), before)

    def test_hearing_its_own_announcement_does_not_count_as_a_router_or_as_another_dns_server(self):
        heard = server.read_router_advert(KNOWN_ANNOUNCEMENT[54:])
        with mock.patch.object(server.S, "v6_own", {ADDR}), mock.patch.object(server.S, "dns_ipv6", True):
            server.note_router_dns(heard["servers"], time.time(), heard["lifetime"], heard["prefixes"], sender=ADDR)
            view = server.ipv6_dns_view()
        self.assertEqual((view["router_dns_not_ours"], view["in_use"], view["routers"]), ([], False, []))

    # -- reasons to hold back (server.announce_hold_reason) ---------------------------

    def router_heard(self, ago=10, servers=("fe80::1",)):
        """As if a real router announced IPv6 `ago` seconds ago, naming these IPv6 DNS servers."""
        server.S.ra_heard, server.S.ra_heard_at = time.time() - ago, time.monotonic() - ago
        server.S.router_v6_dns = {addr: time.time() + 600 for addr in servers}

    def listening_for(self, seconds, can_hear=True):
        """As if the announcement listener had been running, and able to hear, for this long."""
        server.S.ra_listening, server.S.v6_can_hear = True, can_hear
        server.S.ra_since = server.S.v6_hear_since = time.monotonic() - seconds

    def test_the_announcer_is_given_the_servers_reason_to_hold_back(self):
        self.assertIs(server.make_announcer().hold_reason, server.announce_hold_reason)

    def test_it_may_announce_when_the_router_names_an_ipv6_dns_server_of_its_own(self):
        self.router_heard(servers=("fe80::1",))
        self.assertEqual(server.announce_hold_reason(ADDR), "")

    def test_it_holds_back_when_a_router_hands_out_ipv6_but_names_no_ipv6_dns_server(self):
        # QuietNet's would be an Android phone's only one, and losing it can drop the phone off Wi-Fi.
        self.router_heard(servers=())
        self.listening_for(server.ANNOUNCE_AFTER_QUIET * 3)
        reason = server.announce_hold_reason(ADDR)
        self.assertIn("Your router hands out IPv6 but names no IPv6 DNS server of its own.", reason)
        self.assertIn("Android phones could drop off Wi-Fi", reason)

    def test_a_server_whose_time_has_run_out_does_not_count_as_named(self):
        self.router_heard()
        server.S.router_v6_dns = {"fe80::1": time.time() - 1}
        self.assertIn("names no IPv6 DNS server of its own", server.announce_hold_reason(ADDR))

    def test_its_own_announcement_does_not_count_as_another_server(self):
        self.router_heard(servers=(ADDR,))
        self.assertIn("names no IPv6 DNS server of its own", server.announce_hold_reason(ADDR))

    def test_this_computers_other_addresses_do_not_count_as_another_server(self):
        self.router_heard(servers=("fd00::5",))
        with mock.patch.object(server.S, "v6_own", {"fd00::5", ADDR}):
            self.assertIn("names no IPv6 DNS server of its own", server.announce_hold_reason(ADDR))

    def test_it_may_announce_when_no_router_has_been_heard_for_the_set_time(self):
        # No router, so no device has an IPv6 route, and none counts its IPv6 as set up.
        self.listening_for(server.ANNOUNCE_AFTER_QUIET + 1)
        self.assertEqual(server.announce_hold_reason(ADDR), "")

    def test_it_holds_back_while_it_has_not_listened_long_enough_to_know(self):
        self.listening_for(server.ANNOUNCE_AFTER_QUIET - 30)
        self.assertIn("still listening for your router's IPv6 announcements", server.announce_hold_reason(ADDR))

    def test_the_time_it_listens_is_longer_than_a_router_may_leave_between_announcements(self):
        self.assertGreater(server.ANNOUNCE_AFTER_QUIET, 1800)

    def test_it_holds_back_when_it_cannot_hear_the_routers_announcements(self):
        self.assertIn("can't hear your router's IPv6 announcements", server.announce_hold_reason(ADDR))
        self.listening_for(server.ANNOUNCE_AFTER_QUIET * 3, can_hear=False)
        self.assertIn("can't hear your router's IPv6 announcements", server.announce_hold_reason(ADDR))

    def test_a_router_heard_within_the_hour_still_counts_however_long_the_listening(self):
        self.router_heard(ago=server.RA_HOLD_MAX - 60, servers=())
        self.listening_for(server.RA_HOLD_MAX * 3)
        self.assertIn("names no IPv6 DNS server of its own", server.announce_hold_reason(ADDR))

    def test_a_router_last_heard_over_an_hour_ago_counts_as_no_router(self):
        self.router_heard(ago=server.RA_HOLD_MAX + 1, servers=())
        self.listening_for(server.RA_HOLD_MAX * 3)
        self.assertEqual(server.announce_hold_reason(ADDR), "")

    def test_a_known_range_extender_holds_the_trial_back(self):
        # Over IPv6 the devices behind one can't be told apart (issues 95 and 101).
        self.router_heard()
        self.assertEqual(server.announce_hold_reason(ADDR), "")
        with mock.patch.object(server.S, "shared_macs", {"aa:bb:cc:00:00:01"}):
            reason = server.announce_hold_reason(ADDR)
        self.assertIn("Wi-Fi range extender", reason)
        self.assertIn("QuietNet is not announcing itself.", reason)

    def test_with_the_device_tables_the_reason_says_lookups_behind_an_extender_get_no_devices_rules(self):
        # Their IPv6 addresses are matched to no device, so nobody gets another device's rules.
        self.router_heard()
        with mock.patch.object(server.S, "shared_macs", {"aa:bb:cc:00:00:01"}), \
                mock.patch.object(server.S, "devices_ready", True):
            reason = server.announce_hold_reason(ADDR)
        self.assertIn("would refuse their lookups or give them only the whole house's rules", reason)
        self.assertNotIn("another's rules", reason)

    def test_on_an_older_database_the_reason_says_one_device_could_get_anothers_rules(self):
        # Not yet moved to the device tables: every device behind one is judged under one number's rules.
        self.router_heard()
        with mock.patch.object(server.S, "shared_macs", {"aa:bb:cc:00:00:01"}), \
                mock.patch.object(server.S, "devices_ready", False):
            reason = server.announce_hold_reason(ADDR)
        self.assertIn("could give one device another's rules", reason)

    def test_the_reason_to_hold_back_is_worked_out_without_the_database(self):
        self.router_heard()
        with mock.patch.object(server, "sql", side_effect=AssertionError("asked the database")), \
                mock.patch.object(server, "db", None):
            self.assertEqual(server.announce_hold_reason(ADDR), "")

    def wired(self):
        """An announcer joined to the server's own reason to hold back, with a stand-in card and
        socket; self.sent collects its frames."""
        an = announcer.Announcer(lambda: True, on=True, facts=lambda: (CARD, MAC, ADDR, ""), answers=lambda a, c: True,
                                 open_sender=self.an._open_sender, pause=lambda s: None, unavailable="",
                                 log=lambda line: None, hold_reason=server.announce_hold_reason)
        self.addCleanup(an.stop, 2)
        return an

    def test_with_a_router_that_names_no_dns_server_nothing_is_announced(self):
        self.router_heard(servers=())
        an = self.wired()
        an.step()
        self.assertFalse(any(lifetime for frame in self.sent for _, lifetime in dns_servers(frame)))
        self.assertEqual(an.status()["state"], "held")
        self.assertIn("names no IPv6 DNS server of its own", an.status()["reason"])

    def test_when_the_routers_server_stops_being_named_it_says_goodbye_once_and_not_again(self):
        self.router_heard()
        an = self.wired()
        an.step()
        server.S.router_v6_dns = {}
        for _ in range(4):
            an.step()
        self.assertEqual(self.sent, [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_a_range_extender_noticed_while_announcing_calls_the_announcement_off(self):
        self.router_heard()
        an = self.wired()
        an.step()
        with mock.patch.object(server.S, "shared_macs", {"aa:bb:cc:00:00:01"}):
            an.step()
            self.assertEqual(an.status()["state"], "held")
        self.assertEqual(self.sent, [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_holding_back_changes_nothing_the_dashboard_says_about_ipv6_and_bypassing(self):
        # hub_off and the "Can bypass over IPv6" labels never look at the announcer's reasons.
        self.router_heard(servers=())
        self.listening_for(server.RA_HOLD_MAX * 3)
        now, mono = time.time(), time.monotonic()
        before = server.ipv6_dns_view(now, mono)
        self.assertNotEqual(server.announce_hold_reason(ADDR), "")
        self.assertEqual(server.ipv6_dns_view(now, mono), before)
        for reader in (server.ipv6_dns_view, server.api_devices):
            self.assertNotIn("announce_hold_reason", inspect.getsource(reader))
            self.assertNotIn("AN.", inspect.getsource(reader))

    def test_a_clean_stop_asks_for_the_goodbye_first_and_waits_for_it_last(self):
        text = inspect.getsource(server.main)
        tidy_up = text[text.index("finally:"):]
        self.assertLess(tidy_up.index("AN.ask_to_stop()"), tidy_up.index("ENF.stop()"))
        self.assertLess(tidy_up.index("ENF.stop()"), tidy_up.index("AN.stop()"))
        self.assertLess(tidy_up.index("AN.stop()"), tidy_up.index("QuietNet stopped."))

    def test_the_program_starts_the_announcer_from_the_saved_choice(self):
        text = inspect.getsource(server.main)
        self.assertIn("AN = make_announcer()", text)
        self.assertLess(text.index("start_dns(args.dns_port)"), text.index("AN.start()"))

    def test_the_announcer_starts_only_once_the_dashboard_is_open_and_a_stop_request_is_caught(self):
        # Started any earlier, a start-up that then failed would leave an announcement with no goodbye.
        text = inspect.getsource(server.main)
        self.assertEqual(text.count("AN.start()"), 1)
        started = text.index("AN.start()")
        self.assertLess(text.index("ThreadingHTTPServer(("), started)
        self.assertLess(text.index("signal.signal(signal.SIGTERM, _stop_requested)"), started)
        self.assertLess(text.index("try:"), started)
        self.assertLess(started, text.index("web.serve_forever()"))
        self.assertLess(started, text.index("finally:"))


class StartingUp(Base):
    """main() run for real, with everything that touches the network replaced by a stand-in: when
    the announcer starts, and that a failure after it has started still ends in the goodbye."""

    def setUp(self):
        super().setUp()
        self.sent = []
        test = self

        class Sender:
            """Notes each frame instead of sending it."""

            def sendto(self, frame, where):
                test.sent.append(bytes(frame))

            def close(self):
                pass

        self.an = announcer.Announcer(lambda: True, on=True, facts=lambda: (CARD, MAC, ADDR, ""),
                                      answers=lambda a, c: True, open_sender=lambda card: Sender(),
                                      pause=lambda s: None, unavailable="", log=lambda line: None)
        self.addCleanup(self.an.stop, 2)
        self.web = mock.Mock()
        nothing = lambda *a, **kw: None     # noqa: E731
        stand_ins = [mock.patch.object(server, name, value) for name, value in (
            ("AN", None), ("ENF", None), ("CA", None),             # main() sets these; put back afterwards
            ("make_announcer", lambda: self.an), ("start_dns", nothing), ("find_local_ip", lambda: "192.168.1.2"),
            ("log_writer", nothing), ("router_advert_listener", nothing), ("address_watcher", nothing),
            # The device keeper never ends, and every 5 seconds reads this computer's real neighbour
            # table and writes to the database: left running it would disturb every later test.
            ("device_keeper", nothing),
            ("ThreadingHTTPServer", mock.Mock(return_value=self.web)))]
        stand_ins += [mock.patch.object(server.enforcer, "Enforcer", mock.Mock()),
                      mock.patch.object(server.cloud_agent, "CloudAgent", mock.Mock()),
                      mock.patch.object(server.signal, "signal", nothing),
                      mock.patch.object(server.S, "local_ip", server.S.local_ip),
                      mock.patch.object(sys, "argv", ["server.py", "--no-browser", "--no-device-names"])]
        for p in stand_ins:
            p.start()
            self.addCleanup(p.stop)

    def run_main(self):
        """Run main() with what it prints thrown away."""
        with contextlib.redirect_stdout(io.StringIO()):
            server.main()

    def test_a_start_up_that_fails_before_the_dashboard_opens_announces_nothing(self):
        server.ThreadingHTTPServer.side_effect = OSError("Address already in use")
        with self.assertRaises(OSError):
            self.run_main()
        time.sleep(0.05)
        self.assertEqual(self.sent, [])
        self.assertIsNone(self.an._thread)

    def test_a_start_up_that_fails_while_making_the_enforcer_announces_nothing(self):
        server.enforcer.Enforcer.side_effect = RuntimeError("broken")
        with self.assertRaises(RuntimeError):
            self.run_main()
        time.sleep(0.05)
        self.assertEqual(self.sent, [])
        self.assertIsNone(self.an._thread)

    def test_a_stop_request_after_the_announcer_has_started_ends_in_the_goodbye(self):
        def serve_forever():
            """Wait for the first announcement, then act as a stop request does."""
            deadline = time.time() + 5
            while not self.sent and time.time() < deadline:
                time.sleep(0.01)
            raise KeyboardInterrupt

        self.web.serve_forever.side_effect = serve_forever
        self.run_main()
        self.assertEqual(self.sent, [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)

    def test_a_dashboard_that_breaks_after_the_announcer_has_started_still_ends_in_the_goodbye(self):
        def serve_forever():
            """Wait for the first announcement, then fail."""
            deadline = time.time() + 5
            while not self.sent and time.time() < deadline:
                time.sleep(0.01)
            raise RuntimeError("the dashboard broke")

        self.web.serve_forever.side_effect = serve_forever
        with self.assertRaises(RuntimeError):
            self.run_main()
        self.assertEqual(self.sent, [KNOWN_ANNOUNCEMENT] + [KNOWN_GOODBYE] * 3)


class OnTheDashboard(unittest.TestCase):
    """What the page says about the trial. These read the page's script; nothing runs in a browser."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "index.html"),
                  encoding="utf-8") as f:
            cls.page = f.read()

    def part(self, name):
        """The script of one function on the page."""
        start = self.page.index("function %s(" % name)
        return self.page[start:self.page.index("\nfunction ", start + 1)]

    def words(self, name):
        """The same, with every run of spaces and line breaks made one space, so a sentence can
        be looked for wherever its lines happen to break."""
        return " ".join(self.part(name).split())

    def test_it_is_labelled_a_trial_in_its_heading(self):
        self.assertIn('<h2>Announce QuietNet as an IPv6 DNS server <span class="badge warn">Trial</span></h2>',
                      self.part("dnsAnnounceSwitch"))

    def test_it_says_it_is_off_unless_turned_on(self):
        self.assertIn("A trial, off unless you turn it on.", self.part("dnsAnnounceSwitch"))

    def test_it_says_plainly_that_it_does_not_stop_devices_getting_round_quietnet(self):
        text = self.words("dnsAnnounceSwitch")
        self.assertIn("<b>It does not stop any device getting round QuietNet.</b>", text)
        self.assertIn('devices marked "Can bypass over IPv6" still can', text)

    def test_the_switch_says_devices_never_set_up_may_start_using_quietnet_and_get_whole_house_rules(self):
        # The announcement goes to every device, not only those the owner pointed at QuietNet.
        text = self.words("dnsAnnounceSwitch")
        self.assertIn("<b>Devices you never set up to use QuietNet may start using it too.</b>", text)
        self.assertIn('Their lookups then get your whole-house rules (advert blocking, whole-house blocked services and '
                      'schedules, and "internet off" for the whole house)', text)
        self.assertIn("the rules of any group they are in, including the group new devices are put in", text)
        self.assertIn("and are written to the history", text)

    def test_the_switch_says_what_to_do_if_a_device_that_was_left_out_stops_working(self):
        self.assertIn("If a device you left out stops working after you turn this on, turn it off.",
                      self.words("dnsAnnounceSwitch"))

    def test_the_switch_says_that_with_the_routers_ipv6_off_quietnet_is_the_only_ipv6_dns_server(self):
        self.assertIn("With IPv6 switched off on your router, QuietNet is the only IPv6 DNS server devices are told of",
                      self.words("dnsAnnounceSwitch"))

    def test_the_switch_says_when_it_holds_back(self):
        text = self.words("dnsAnnounceSwitch")
        self.assertIn("while a Wi-Fi range extender is in use", text)
        self.assertIn("while your router hands out IPv6 without naming an IPv6 DNS server of its own", text)
        self.assertIn("until it has listened to your router for long enough to know", text)

    def test_it_warns_what_happens_if_the_pi_loses_power(self):
        text = self.words("dnsAnnounceSwitch")
        self.assertIn("If this computer loses power without warning, devices that chose it, including ones you never "
                      "set up, may be slow to look names up for up to ${mins} minutes.", text)

    def test_it_says_how_to_undo_it(self):
        self.assertIn("Turning this off, or stopping QuietNet in the ordinary way, tells devices to stop at once.",
                      self.part("dnsAnnounceSwitch"))

    def test_the_switch_is_ticked_only_when_the_pi_says_the_trial_is_on(self):
        self.assertIn('id="dnsAnnounceSwitch" ${a.on ? \'checked\' : \'\'}', self.part("dnsAnnounceSwitch"))

    def test_the_switch_cannot_be_turned_on_where_the_trial_cannot_run(self):
        self.assertIn("${a.available === false && !a.on ? 'disabled' : ''}", self.part("dnsAnnounceSwitch"))

    def test_an_older_pi_without_the_trial_is_not_offered_it(self):
        self.assertIn("if(a == null) return '';", self.part("dnsAnnounceSwitch"))

    def test_the_switch_sits_with_the_other_ipv6_choices_on_the_setup_page(self):
        setup = self.part("viewSetup")
        self.assertIn("${dnsAnnounceSwitch(S.status || {})}</div>`;", setup)
        self.assertLess(setup.index("${noIpv6Switch("), setup.index("${dnsAnnounceSwitch("))

    def test_turning_the_switch_calls_the_trials_api(self):
        self.assertIn("if(e.target.id === 'dnsAnnounceSwitch'){ await api('/api/dns-announce-switch', "
                      "{on:e.target.checked}).catch(oops); refresh(); }", self.page)

    def test_the_address_and_the_reason_from_the_pi_are_escaped(self):
        state = self.part("dnsAnnounceState")
        self.assertIn("<b>${esc(a.address)}</b>", state)
        self.assertIn("${esc(a.reason)}", state)
        self.assertIn("esc(ago(a.sent))", state)
        self.assertNotIn("${a.", state.replace("${a.sent ? ", ""))

    def test_the_minutes_shown_are_made_safe_as_a_number(self):
        self.assertIn("const mins = num(Math.round((a.lifetime || 600) / 60));", self.part("dnsAnnounceSwitch"))

    def test_announcing_is_not_described_as_devices_using_it(self):
        self.assertIn("That does not mean they do.", self.part("dnsAnnounceState"))

    def test_a_goodbye_that_could_not_be_sent_yet_is_explained_in_the_pis_words_escaped(self):
        self.assertIn("if(a.state === 'stopping') return `<p class=\"small\">Telling devices to stop using this computer "
                      "for IPv6 DNS… ${esc(a.reason || '')}</p>`;", self.part("dnsAnnounceState"))

    def test_being_switched_on_but_not_announcing_is_shown_as_a_warning(self):
        self.assertIn('if(a.state === \'held\') return `<div class="notice warn"><b>Switched on, but not announcing.</b>',
                      self.part("dnsAnnounceState"))

    def test_the_trial_adds_no_fixed_colours_or_inline_styles(self):
        for part in (self.part("dnsAnnounceSwitch"), self.part("dnsAnnounceState")):
            self.assertNotIn("style=", part)
            self.assertNotRegex(part, r"#[0-9a-fA-F]{3,6}\b")


class WhatTheDocsSay(unittest.TestCase):
    """The warnings the owner must be able to find in the written guides, not only on the page."""

    @classmethod
    def setUpClass(cls):
        issues = read("docs", "KNOWN_ISSUES.md")
        start = issues.index("### 101. ")
        cls.issue = " ".join(issues[start:issues.index("\n### ", start + 1)].split())
        cls.readme = " ".join(read("README.md").split())
        cls.testing = read("docs", "TESTING.md")

    def test_known_issue_101_says_devices_never_set_up_can_be_brought_in(self):
        self.assertIn("It can bring in devices that were never set up to use QuietNet.", self.issue)
        self.assertIn("A blocked answer is final", self.issue)

    def test_known_issue_101_no_longer_calls_the_hub_off_case_harmless(self):
        self.assertNotIn("not known to cause harm", self.issue)
        self.assertIn("the only IPv6 DNS server", self.issue)

    def test_known_issue_101_says_why_the_trial_holds_back_for_a_range_extender(self):
        self.assertIn("range extender", self.issue)
        self.assertIn("fewer than three looks", self.issue)

    def test_known_issue_101_says_what_losing_the_only_ipv6_dns_server_does_to_an_android_phone(self):
        self.assertIn("names no IPv6 DNS server", self.issue)
        self.assertIn("not tried on a phone", self.issue)

    def test_the_readme_says_devices_never_set_up_may_start_using_quietnet(self):
        self.assertIn("Devices you never set up to use QuietNet may start using it too", self.readme)
        self.assertIn("whole-house rules", self.readme)

    def test_there_is_a_manual_step_for_a_device_that_was_never_pointed_at_quietnet(self):
        self.assertRegex(self.testing, r"\n\d+\. \*\*A device that was never pointed at QuietNet\.\*\*")


if __name__ == "__main__":
    unittest.main()
