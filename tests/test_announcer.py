"""Checks for the trial that announces this computer as an IPv6 DNS server (announcer.py):
the bytes of the message, its lifetimes, when it is and is not sent, how it stops, and that it
is off unless the owner switches it on. Also its switch in the dashboard's API and on the page.

Run with:  python3 -m unittest discover tests

Standard library only. Nothing is sent onto a network: the sending socket, the network card's
details and the clock are stand-ins, and the only real connections are test questions to a
stand-in DNS server on 127.0.0.1. No raw socket is opened and no system tool is run.
"""
import inspect
import os
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

CARD, MAC, ADDR = "wlan0", "b8:27:eb:12:34:56", "fe80::ba27:ebff:fe12:3456"
OTHER = "fe80::1234"

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
    """A DNS server on 127.0.0.1 for the test question. `answer(question)` gives the reply to
    send back, or None to stay silent."""

    def __init__(self, answer):
        self.answer = answer
        self.asked = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
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


class FakeSender:
    """Stands in for the raw sending socket: notes each frame and where it was sent."""

    def __init__(self, test):
        self.test = test

    def sendto(self, frame, where):
        if self.test.send_fails:
            raise self.test.send_fails
        self.test.sent.append((bytes(frame), where))
        return len(frame)

    def close(self):
        self.test.closed += 1


class Trial(unittest.TestCase):
    """The announcer driven one step at a time, with a stand-in clock, card and socket."""

    def setUp(self):
        self.now = 1000.0
        self.sent, self.opened, self.closed, self.send_fails = [], [], 0, None
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

        an = announcer.Announcer(lambda: self.listening, on=on, log=self.logged.append, facts=facts, answers=answers,
                                 open_sender=open_sender, clock=lambda: self.now, pause=self.pauses.append,
                                 unavailable=unavailable)
        self.addCleanup(an.stop, 2)
        return an

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
        an = self.make(on=True)
        an.step()
        self.answering = False
        self.now += 20
        an.step()
        self.answering = True
        self.now += 20
        an.step()
        self.assertEqual(self.lifetimes(), [600, 0, 0, 0, 600])
        self.assertEqual(an.status()["state"], "announcing")

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
        an = self.make(on=True)
        an.step()
        self.facts = (CARD, MAC, OTHER, "")
        self.now += 20
        an.step()
        self.assertEqual([dns_servers(frame) for frame, _ in self.sent],
                         [[(ADDR, 600)]] + [[(OTHER, 0), (ADDR, 0)]] * 3 + [[(OTHER, 600)]])
        self.assertEqual(an.status()["address"], OTHER)

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
        self.assertEqual((out["ok"], out["on"]), (True, True))
        self.an.step()
        self.assertEqual(self.sent, [KNOWN_ANNOUNCEMENT])
        self.assertEqual(self.get("/api/status")[1]["dns_announce"]["state"], "announcing")

    def test_switching_it_off_through_the_api_sends_the_goodbye(self):
        self.ok("/api/dns-announce-switch", {"on": True})
        self.an.step()
        self.ok("/api/dns-announce-switch", {"on": False})
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

    def test_it_is_labelled_a_trial_in_its_heading(self):
        self.assertIn('<h2>Announce QuietNet as an IPv6 DNS server <span class="badge warn">Trial</span></h2>',
                      self.part("dnsAnnounceSwitch"))

    def test_it_says_it_is_off_unless_turned_on(self):
        self.assertIn("A trial, off unless you turn it on.", self.part("dnsAnnounceSwitch"))

    def test_it_says_plainly_that_it_does_not_stop_devices_getting_round_quietnet(self):
        text = self.part("dnsAnnounceSwitch")
        self.assertIn("<b>It does not stop any device getting round QuietNet.</b>", text)
        self.assertIn('devices marked "Can bypass\n      over IPv6" still can', text)

    def test_it_warns_what_happens_if_the_pi_loses_power(self):
        text = self.part("dnsAnnounceSwitch")
        self.assertIn("If this computer loses power without warning, devices that chose it may be slow to look names up", text)
        self.assertIn("${mins} minutes", text)

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

    def test_being_switched_on_but_not_announcing_is_shown_as_a_warning(self):
        self.assertIn('if(a.state === \'held\') return `<div class="notice warn"><b>Switched on, but not announcing.</b>',
                      self.part("dnsAnnounceState"))

    def test_the_trial_adds_no_fixed_colours_or_inline_styles(self):
        for part in (self.part("dnsAnnounceSwitch"), self.part("dnsAnnounceState")):
            self.assertNotIn("style=", part)
            self.assertNotRegex(part, r"#[0-9a-fA-F]{3,6}\b")


if __name__ == "__main__":
    unittest.main()
