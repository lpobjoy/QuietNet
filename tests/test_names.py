"""Checks for finding device names (names.py): reading Bonjour, Windows network, UPnP and DHCP
packets, including broken and hostile ones; fetching UPnP descriptions safely; tidying names;
which source wins; the time budget; and the listeners.

Run with:  python3 -m unittest discover tests

Nothing here opens a multicast or broadcast socket or talks to the home network. Network sockets
are replaced by FakeSocket; the only real connections are to a small web server on 127.0.0.1,
standing in for a device's UPnP description.
"""
import collections
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import names  # noqa: E402

PHONE, TV, PC = "192.168.1.54", "192.168.1.60", "192.168.1.70"


def name_bytes(name):
    """A dotted name in DNS's own form."""
    return names.encode_name(name)


def record(owner, rtype, rdata, owner_raw=None):
    """One encoded answer record."""
    return (owner_raw or name_bytes(owner)) + struct.pack(">HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


def answer_packet(records, questions=b"", qd=0):
    """A DNS-style answer (the 'answer' bit set) holding the given encoded records."""
    return struct.pack(">HHHHHH", 0, 0x8400, qd, len(records), 0, 0) + questions + b"".join(records)


def ptr_answer(ip, target):
    """A Bonjour answer saying the device at `ip` is called `target`."""
    return answer_packet([record(names.reverse_pointer(ip), 12, name_bytes(target))])


def txt(*items):
    """The data of a text record."""
    return b"".join(bytes([len(i)]) + i.encode() for i in items)


def nbstat_answer(entries):
    """A Windows network answer listing (name, ending byte, is a group) entries."""
    body = bytes([len(entries)])
    for name, suffix, group in entries:
        body += name.encode().ljust(15, b" ") + bytes([suffix]) + struct.pack(">H", 0x8000 if group else 0x0400)
    return struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0) + names.NBSTAT_NAME + struct.pack(">HHIH", 0x21, 1, 0, len(body)) + body


def dhcp_packet(kind=1, options=b"", op=1, mac=b"\xaa\xbb\xcc\x00\x11\x22"):
    """A DHCP packet from a device, of the given message kind, with extra options."""
    head = bytes([op, 1, 6, 0]) + bytes(24) + mac + bytes(10) + bytes(192) + b"\x63\x82\x53\x63"
    return head + bytes([53, 1, kind]) + options + b"\xff"


def ip_udp_packet(payload, port=67, protocol=17, fragment=0):
    """An IPv4 packet from 0.0.0.0 to 255.255.255.255 carrying `payload` in UDP to `port`."""
    udp = struct.pack(">HHHH", 68, port, 8 + len(payload), 0) + payload
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, fragment, 64, protocol, 0,
                       bytes(4), b"\xff" * 4) + udp


class FakeSocket:
    """Stands in for a UDP socket: records what is sent and hands back queued answers, then
    behaves as if the time ran out. Nothing reaches the network."""
    made = []
    replier = None                              # called with (data, where) for every packet sent

    def __init__(self, *args):
        """Start with nothing sent and nothing to answer."""
        self.sent, self.answers, self.bound, self.options = [], collections.deque(), None, []
        self.reply = FakeSocket.replier
        FakeSocket.made.append(self)

    def __enter__(self):
        """Used in a with-block, like a real socket."""
        return self

    def __exit__(self, *exc):
        """Nothing to close."""
        return False

    def setsockopt(self, *args):
        """Record a socket option."""
        self.options.append(args)

    def settimeout(self, t):
        """Ignored: answers are handed back at once."""

    def bind(self, where):
        """Record where the socket was bound."""
        self.bound = where

    def sendto(self, data, where):
        """Record a packet, and queue any answer the test set up for it."""
        self.sent.append((data, where))
        if self.reply:
            for answer in self.reply(data, where) or []:
                self.answers.append(answer)

    def recvfrom(self, n):
        """The next queued answer, or a time-out when there are none."""
        if not self.answers:
            raise socket.timeout("timed out")
        data, source = self.answers.popleft()
        return data[:n], (source, 5353)

    def close(self):
        """Nothing to close."""


class ReadingNames(unittest.TestCase):
    def test_a_name_with_a_pointer_to_an_earlier_name_is_read_whole(self):
        data = b"\x00" * 12 + name_bytes("local") + b"\x05phone\xc0\x0c"
        labels, after = names.read_name(data, 12 + 7)
        self.assertEqual((labels, after), ([b"phone", b"local"], len(data)))

    def test_a_pointer_to_itself_is_refused_rather_than_followed_for_ever(self):
        data = b"\x00" * 12 + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            names.read_name(data, 12)

    def test_two_pointers_that_point_at_each_other_are_refused(self):
        # A label at 12, then a pointer back to 12: following it would come straight back here.
        data = b"\x00" * 12 + b"\x01a\xc0\x0c"
        with self.assertRaises(ValueError):
            names.read_name(data, 12)

    def test_a_name_cut_short_is_refused(self):
        with self.assertRaises(ValueError):
            names.read_name(b"\x00" * 12 + b"\x05pho", 12)
        with self.assertRaises(ValueError):
            names.read_name(b"\x00" * 12 + b"\xc0", 12)

    def test_a_name_longer_than_dns_allows_is_refused(self):
        data = b"\x00" * 12 + b"\x3f" + b"a" * 63
        data = data * 1 + (b"\x3f" + b"a" * 63) * 4 + b"\x00"
        with self.assertRaises(ValueError):
            names.read_name(data, 12)


class Bonjour(unittest.TestCase):
    def test_an_answer_about_an_address_names_that_device(self):
        found = names.learn_from_mdns(ptr_answer(PHONE, "Lewiss-iPhone.local"), PHONE, {PHONE})
        self.assertEqual(found, {PHONE: {"name": "Lewiss-iPhone.local"}})

    def test_an_answer_about_another_devices_address_is_ignored(self):
        # Anyone hearing the question could answer it; only the device itself is believed.
        found = names.learn_from_mdns(ptr_answer(PHONE, "Dads-Laptop.local"), "192.168.1.99", {PHONE, "192.168.1.99"})
        self.assertEqual(found, {})

    def test_an_answer_about_a_device_not_asked_about_is_ignored(self):
        self.assertEqual(names.learn_from_mdns(ptr_answer(PC, "x.local"), PC, {PHONE}), {})

    def test_a_question_is_not_taken_for_an_answer(self):
        packet = bytearray(ptr_answer(PHONE, "phone.local"))
        packet[2] = 0
        self.assertEqual(names.learn_from_mdns(bytes(packet), PHONE, {PHONE}), {})

    def test_a_device_may_announce_its_own_address(self):
        packet = answer_packet([record("tv.local", 1, socket.inet_aton(TV))])
        self.assertEqual(names.learn_from_mdns(packet, TV, {TV}), {TV: {"name": "tv.local"}})

    def test_a_device_may_not_announce_a_name_for_another_address(self):
        packet = answer_packet([record("tv.local", 1, socket.inet_aton(TV))])
        self.assertEqual(names.learn_from_mdns(packet, PHONE, {TV, PHONE}), {})

    def test_device_information_gives_the_owners_name_and_the_model(self):
        packet = answer_packet([record("Lewis's MacBook Pro._device-info._tcp.local", 16, txt("model=MacBookPro18,3", "osxvers=24"))])
        found = names.learn_from_mdns(packet, PC, {PC})
        self.assertEqual(found, {PC: {"friendly": "Lewis's MacBook Pro", "model": "MacBookPro18,3"}})

    def test_a_truncated_answer_gives_what_came_before_the_break_and_no_error(self):
        good = record(names.reverse_pointer(PHONE), 12, name_bytes("phone.local"))
        packet = answer_packet([good, record("tv.local", 1, socket.inet_aton(TV))])
        packet = packet[:-3]
        packet = packet[:6] + struct.pack(">H", 2) + packet[8:]
        self.assertEqual(names.learn_from_mdns(packet, PHONE, {PHONE, TV}), {PHONE: {"name": "phone.local"}})

    def test_an_answer_whose_name_points_at_itself_is_survived(self):
        packet = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 1, 2) + b"\xc0\x0c"
        self.assertEqual(names.read_records(packet), [])

    def test_an_answer_claiming_thousands_of_records_reads_only_a_few(self):
        rec = record(names.reverse_pointer(PHONE), 12, name_bytes("p.local"))
        packet = struct.pack(">HHHHHH", 0, 0x8400, 0, 65535, 65535, 65535) + rec * 200
        self.assertEqual(len(names.read_records(packet)), names.MAX_RECORDS)

    def test_a_question_asks_for_a_direct_answer_about_each_address(self):
        packet = names.mdns_query([names.reverse_pointer(PHONE)])
        self.assertEqual(struct.unpack(">H", packet[4:6])[0], 1)
        self.assertTrue(packet.endswith(struct.pack(">HH", 12, 0x8001)))
        self.assertIn(b"\x0254\x011\x03168\x03192\x07in-addr\x04arpa\x00", packet)


class WindowsNetwork(unittest.TestCase):
    def test_the_computers_own_name_is_its_first_unique_workstation_name(self):
        packet = nbstat_answer([("WORKGROUP", 0, True), ("LEWIS-PC", 0x20, False), ("LEWIS-PC", 0, False)])
        self.assertEqual(names.parse_nbstat(packet), "LEWIS-PC")

    def test_an_answer_with_only_group_names_gives_no_name(self):
        self.assertEqual(names.parse_nbstat(nbstat_answer([("WORKGROUP", 0, True)])), "")

    def test_an_answer_claiming_more_names_than_it_holds_is_read_safely(self):
        packet = bytearray(nbstat_answer([("NAS", 0, False)]))
        packet[12 + len(names.NBSTAT_NAME) + 10] = 250                   # says 250 names, holds one
        self.assertEqual(names.parse_nbstat(bytes(packet)), "NAS")
        self.assertEqual(names.parse_nbstat(bytes(packet[:-10])), "")

    def test_rubbish_gives_no_name(self):
        for junk in (b"", b"\x00" * 11, b"\xff" * 60, nbstat_answer([("A", 0, False)])[:30]):
            self.assertEqual(names.parse_nbstat(junk), "")


class Dhcp(unittest.TestCase):
    def test_a_device_joining_gives_its_name_software_and_hardware_address(self):
        packet = dhcp_packet(3, b"\x0c\x0dLewiss-iPhone" + b"\x3c\x08MSFT 5.0")
        self.assertEqual(names.parse_dhcp(packet), {"mac": "aa:bb:cc:00:11:22", "name": "Lewiss-iPhone", "vendor": "MSFT 5.0"})

    def test_a_dhcp_servers_own_answers_are_ignored(self):
        self.assertIsNone(names.parse_dhcp(dhcp_packet(2, b"\x0c\x02tv", op=2)))
        self.assertIsNone(names.parse_dhcp(dhcp_packet(5, b"\x0c\x02tv")))

    def test_an_option_running_off_the_end_is_not_read(self):
        packet = dhcp_packet(1, b"\x0c\x02tv")[:-1] + b"\x3c\xffshort"
        self.assertEqual(names.parse_dhcp(packet)["vendor"], "")

    def test_a_packet_too_short_or_without_the_dhcp_marker_is_refused(self):
        self.assertIsNone(names.parse_dhcp(dhcp_packet(1, b"\x0c\x02tv")[:200]))
        broken = bytearray(dhcp_packet(1, b"\x0c\x02tv"))
        broken[236] = 0
        self.assertIsNone(names.parse_dhcp(bytes(broken)))

    def test_a_name_in_the_file_field_is_read_when_the_device_says_so(self):
        packet = bytearray(dhcp_packet(3, b"\x34\x01\x01"))
        field = b"\x0c\x08Den-Roku\xff"
        packet[108:108 + len(field)] = field
        self.assertEqual(names.parse_dhcp(bytes(packet))["name"], "Den-Roku")

    def test_a_name_in_the_server_name_field_is_read_when_the_device_says_so(self):
        packet = bytearray(dhcp_packet(3, b"\x34\x01\x02"))
        field = b"\x0c\x08Den-Roku\xff"
        packet[44:44 + len(field)] = field
        self.assertEqual(names.parse_dhcp(bytes(packet))["name"], "Den-Roku")

    def test_the_file_field_is_not_read_unless_the_device_says_so(self):
        packet = bytearray(dhcp_packet(3, b"\x3c\x03abc"))
        field = b"\x0c\x08Den-Roku\xff"
        packet[108:108 + len(field)] = field
        self.assertEqual(names.parse_dhcp(bytes(packet))["name"], "")

    def test_an_option_in_the_file_field_may_not_run_past_it(self):
        packet = bytearray(dhcp_packet(3, b"\x34\x01\x01\x3c\x01x"))
        packet[230:233] = b"\x0c\x20A"                                   # says 32 bytes, 6 left
        self.assertEqual(names.parse_dhcp(bytes(packet))["name"], "")

    def test_a_packet_full_of_padding_does_not_hang(self):
        packet = dhcp_packet(1, b"\x00" * 60000)
        self.assertIsNone(names.parse_dhcp(packet))                      # no name before the limit

    def test_the_dhcp_message_is_taken_from_a_whole_packet_to_port_67(self):
        message = dhcp_packet(3, b"\x0c\x02tv")
        self.assertEqual(names.dhcp_from_ip_packet(ip_udp_packet(message)), message)

    def test_a_packet_to_another_port_or_not_udp_gives_no_dhcp_message(self):
        message = dhcp_packet(3, b"\x0c\x02tv")
        self.assertIsNone(names.dhcp_from_ip_packet(ip_udp_packet(message, port=68)))
        self.assertIsNone(names.dhcp_from_ip_packet(ip_udp_packet(message, protocol=6)))

    def test_a_piece_of_a_split_packet_gives_no_dhcp_message(self):
        self.assertIsNone(names.dhcp_from_ip_packet(ip_udp_packet(dhcp_packet(3), fragment=0x2000)))

    def test_a_cut_short_or_rubbish_packet_gives_no_dhcp_message(self):
        packet = ip_udp_packet(dhcp_packet(3))
        for junk in (b"", packet[:24], b"\x60" + packet[1:], b"\x4f" + packet[1:]):
            self.assertIsNone(names.dhcp_from_ip_packet(junk))

    def test_common_software_labels_are_put_in_plain_words(self):
        self.assertEqual(names.vendor_words("MSFT 5.0"), "Runs Windows")
        self.assertEqual(names.vendor_words("android-dhcp-13"), "Runs Android")
        self.assertEqual(names.vendor_words("udhcp 1.30"), "Software: udhcp 1.30")


class Upnp(unittest.TestCase):
    def test_the_description_address_is_read_from_an_answer(self):
        packet = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://192.168.1.60:8080/desc.xml\r\n\r\n"
        self.assertEqual(names.parse_ssdp(packet), "http://192.168.1.60:8080/desc.xml")

    def test_a_message_that_is_not_an_answer_gives_nothing(self):
        self.assertEqual(names.parse_ssdp(b"NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.1.60/\r\n\r\n"), "")

    def test_a_description_is_fetched_only_from_the_devices_own_address(self):
        self.assertTrue(names.location_allowed("http://192.168.1.60:8080/d.xml", TV))
        for url in ("http://192.168.1.61/d.xml", "http://example.com/d.xml", "https://192.168.1.60/d.xml",
                    "http://user@192.168.1.60/d.xml", "http://192.168.1.60:bad/d.xml", "file:///etc/passwd"):
            self.assertFalse(names.location_allowed(url, TV), url)
        self.assertFalse(names.location_allowed("http://8.8.8.8/d.xml", "8.8.8.8"))

    def test_another_computers_address_is_never_contacted(self):
        connect = mock.Mock()
        self.assertIsNone(names.fetch_description("http://192.168.1.99/d.xml", TV, connect=connect))
        connect.assert_not_called()

    def test_the_name_maker_and_model_are_read_from_a_description(self):
        body = (b'<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
                b'<friendlyName>Living Room</friendlyName><manufacturer>Sonos, Inc.</manufacturer>'
                b'<modelName>Sonos One</modelName><deviceList><device><friendlyName>Inner</friendlyName>'
                b'</device></deviceList></device></root>')
        self.assertEqual(names.parse_description(body), {"name": "Living Room", "manufacturer": "Sonos, Inc.", "model": "Sonos One"})

    def test_a_description_declaring_a_document_type_or_entities_is_refused(self):
        for body in (b'<!DOCTYPE root><root><device><friendlyName>x</friendlyName></device></root>',
                     b'<?xml version="1.0"?><!doctype r [<!ENTITY a "aaaa">]><root/>',
                     '<root><device><friendlyName>x</friendlyName></device></root>'.encode("utf-16")):
            self.assertIsNone(names.parse_description(body))

    def test_a_description_that_is_not_xml_is_refused(self):
        self.assertIsNone(names.parse_description(b"<root><device>"))
        self.assertIsNone(names.parse_description(b"<root>no device</root>"))


class DescriptionServer(BaseHTTPRequestHandler):
    """A stand-in for a device's UPnP description, on 127.0.0.1. What it sends depends on the path."""
    GOOD = b"<root><device><friendlyName>Den TV</friendlyName><manufacturer>Samsung</manufacturer></device></root>"

    def log_message(self, *a):
        """Keep the test output quiet."""

    def do_GET(self):
        """Answer as a good, redirecting, huge, hostile or slow device would."""
        if self.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "http://127.0.0.1:%d/good" % self.server.server_address[1])
            self.end_headers()
            return
        body = {"/good": self.GOOD, "/huge": b"<root>" + b"x" * (names.MAX_DESCRIPTION + 10) + b"</root>",
                "/entity": b'<!DOCTYPE r [<!ENTITY a "b">]><root><device><friendlyName>&a;</friendlyName></device></root>'}.get(self.path)
        if self.path == "/drip-headers":
            self.wfile.write(b"HTTP/1.1 200 OK\r\n")
            for _ in range(40):
                try:
                    self.wfile.write(b"X")
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.1)
            return
        if self.path == "/chunked":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n<root\r\n0\r\n\r\n")
            return
        if self.path == "/slow":
            self.send_response(200)
            self.end_headers()
            for _ in range(40):
                try:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.1)
            return
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        if self.path != "/huge":
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FetchingDescriptions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), DescriptionServer)
        cls.httpd.daemon_threads = True
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        # 127.0.0.1 stands in for a device's private address for these tests only.
        cls.patch = mock.patch.object(names, "usable_address", lambda ip: ip == "127.0.0.1")
        cls.patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def fetch(self, path, timeout=2.0):
        return names.fetch_description("http://127.0.0.1:%d%s" % (self.port, path), "127.0.0.1", timeout)

    def test_a_good_description_is_read(self):
        self.assertEqual(self.fetch("/good"), {"name": "Den TV", "manufacturer": "Samsung", "model": ""})

    def test_a_redirect_is_not_followed(self):
        self.assertIsNone(self.fetch("/redirect"))

    def test_a_description_bigger_than_the_limit_is_refused(self):
        self.assertIsNone(self.fetch("/huge"))

    def test_a_description_with_entities_is_refused_after_download(self):
        self.assertIsNone(self.fetch("/entity"))

    def test_a_device_dripping_its_headers_is_given_up_on_in_time(self):
        start = time.monotonic()
        self.assertIsNone(self.fetch("/drip-headers", timeout=0.5))
        self.assertLess(time.monotonic() - start, 1.5)

    def test_an_answer_sent_in_pieces_is_refused(self):
        self.assertIsNone(self.fetch("/chunked"))

    def test_a_device_dripping_its_answer_is_given_up_on_in_time(self):
        start = time.monotonic()
        self.assertIsNone(self.fetch("/slow", timeout=0.5))
        self.assertLess(time.monotonic() - start, 1.5)


class Tidying(unittest.TestCase):
    def test_home_endings_and_the_home_domain_are_dropped(self):
        self.assertEqual(names.tidy_name("Lewiss-iPhone.local"), "Lewiss iPhone")
        self.assertEqual(names.tidy_name("nas.home"), "nas")
        self.assertEqual(names.tidy_name("printer.example.org", "example.org"), "printer")

    def test_dashes_become_spaces_only_between_real_words(self):
        self.assertEqual(names.tidy_name("Lewiss-MacBook-Pro"), "Lewiss MacBook Pro")
        self.assertEqual(names.tidy_name("DESKTOP-4F2K1JQ"), "DESKTOP-4F2K1JQ")
        self.assertEqual(names.tidy_name("RX-V685"), "RX-V685")

    def test_friendly_names_with_spaces_are_kept_as_they_are(self):
        self.assertEqual(names.tidy_name("Living Room TV.v2"), "Living Room TV.v2")

    def test_names_are_capped_at_forty_characters(self):
        self.assertEqual(len(names.tidy_name("A very long name " * 10)), 40)

    def test_control_characters_and_invisible_marks_are_removed(self):
        self.assertEqual(names.tidy_name("Den\x00\x1b[31m​TV\r\n"), "Den[31mTV")

    def test_markup_stays_plain_text(self):
        self.assertEqual(names.tidy_name("<img src=x onerror=alert(1)>"), "<img src=x onerror=alert(1)>")

    def test_an_identity_number_is_no_name(self):
        self.assertEqual(names.tidy_name("e2a5c5b2-8c4b-c9d4-b6a7-1234abcd5678.local"), "")
        self.assertEqual(names.tidy_name("001A2B3C4D5E"), "")

    def test_a_word_followed_by_a_hardware_address_is_no_name(self):
        self.assertEqual(names.tidy_name("Sonos-000E58A1B2C3.local"), "")
        self.assertEqual(names.tidy_name("android-1a2b3c4d5e6f7a8b"), "")

    def test_short_codes_and_ordinary_words_are_not_taken_for_machine_names(self):
        for text in ("DESKTOP-4F2K1JQ", "RX-V685", "Cafe", "ACE2"):
            self.assertEqual(names.tidy_name(text), text)

    def test_an_address_or_nothing_is_no_name(self):
        for text in ("", "   ", "192.168.1.54", ".local", "\x00\x01"):
            self.assertEqual(names.tidy_name(text), "", repr(text))

    def test_the_home_domain_is_read_from_the_resolver_settings(self):
        fd, path = tempfile.mkstemp(prefix="quietnet-resolv-")
        with os.fdopen(fd, "w") as f:
            f.write("# made by a router\nnameserver 192.168.1.254\nsearch home\n")
        self.addCleanup(os.remove, path)
        self.assertEqual(names.home_domain(path), "home")
        self.assertEqual(names.home_domain(path + ".missing"), "")


class PrivateAddresses(unittest.TestCase):
    def test_a_made_up_wifi_address_is_recognised(self):
        self.assertTrue(names.is_private_mac("da:a1:19:00:00:01"))
        self.assertTrue(names.is_private_mac("2:a1:19:00:00:01"))

    def test_a_makers_address_is_not_counted_as_private(self):
        self.assertFalse(names.is_private_mac("00:1b:63:00:00:01"))
        self.assertFalse(names.is_private_mac("ff:ff:ff:ff:ff:ff"))
        self.assertFalse(names.is_private_mac(""))


class Choosing(unittest.TestCase):
    def test_a_dhcp_name_beats_every_other_source(self):
        by = {"dns": {"name": "a"}, "ssdp": {"name": "b"}, "netbios": {"name": "c"}, "mdns": {"name": "d"}, "dhcp": {"name": "e"}}
        self.assertEqual(names.choose(by)["name"], "e")
        self.assertEqual(names.choose(by)["source"], "DHCP")

    def test_the_sources_rank_bonjour_windows_upnp_then_the_router(self):
        by = {"dns": {"name": "a"}, "ssdp": {"name": "b"}, "netbios": {"name": "c"}, "mdns": {"name": "d"}}
        order = []
        for key in ("mdns", "netbios", "ssdp", "dns"):
            hint = names.choose(by)
            order.append(hint["source"])
            by.pop(key)
        self.assertEqual(order, ["Bonjour", "Windows network", "UPnP", "router"])

    def test_a_source_with_only_a_useless_name_gives_way_to_the_next(self):
        self.assertEqual(names.choose({"dhcp": {"name": "192.168.1.9"}, "dns": {"name": "tv"}})["source"], "router")

    def test_a_machine_made_bonjour_name_gives_way_to_the_upnp_friendly_name(self):
        by = {"mdns": {"name": "e2a5c5b2-8c4b-c9d4-b6a7-1234abcd5678.local"}, "ssdp": {"name": "Living Room TV"}}
        self.assertEqual(names.choose(by)["name"], "Living Room TV")

    def test_the_owners_bonjour_name_is_preferred_to_the_network_name(self):
        self.assertEqual(names.choose({"mdns": {"name": "Lewiss-MacBook-Pro.local", "friendly": "Lewis's Mac"}})["name"], "Lewis's Mac")

    def test_the_detail_gives_the_model_and_maker_a_device_reported(self):
        self.assertEqual(names.choose({"ssdp": {"name": "Den", "manufacturer": "Sonos, Inc.", "model": "One"}})["detail"],
                         "Model: One (Sonos, Inc.)")
        self.assertEqual(names.choose({"mdns": {"model": "MacBookPro18,3"}})["detail"], "Model: MacBookPro18,3")
        self.assertEqual(names.choose({"dhcp": {"name": "pc", "vendor": "MSFT 5.0"}})["detail"], "Runs Windows")


def quiet_namer(**kw):
    """A Namer whose network is FakeSocket, with no resolver settings and no reverse lookups."""
    return names.Namer(reverse=kw.pop("reverse", None), make_socket=FakeSocket, connect=kw.pop("connect", mock.Mock()),
                       domain_file="/nonexistent/resolv.conf", packet_capture=kw.pop("packet_capture", False))


class Rounds(unittest.TestCase):
    def setUp(self):
        FakeSocket.made = []
        self.addCleanup(setattr, FakeSocket, "replier", None)

    def test_bonjour_asks_the_group_and_each_device_directly(self):
        namer = quiet_namer()
        namer.ask_mdns({PHONE: "", TV: ""}, time.monotonic() + 1)
        sent = [where for s in FakeSocket.made for _, where in s.sent]
        self.assertEqual(sorted(sent), sorted([names.MDNS, (PHONE, 5353), (TV, 5353)]))
        self.assertEqual(FakeSocket.made[0].bound, ("", 0))              # a passing port, never 5353

    def test_bonjour_answers_name_the_devices(self):
        namer = quiet_namer()
        FakeSocket.replier = lambda data, where: [(ptr_answer(PHONE, "Lewiss-iPhone.local"), PHONE)] if where[0] == PHONE else []
        found = namer.ask_mdns({PHONE: ""}, time.monotonic() + 1)
        self.assertEqual(found, {PHONE: {"name": "Lewiss-iPhone.local"}})

    def test_windows_network_names_come_only_from_the_device_itself(self):
        namer = quiet_namer()
        FakeSocket.replier = lambda data, where: [(nbstat_answer([("LEWIS-PC", 0, False)]), where[0]),
                                                  (nbstat_answer([("FAKE", 0, False)]), "10.9.9.9")]
        found = namer.ask_netbios({PC: ""}, time.monotonic() + 1)
        self.assertEqual(found, {PC: {"name": "LEWIS-PC"}})

    def test_upnp_reads_the_description_of_a_device_that_answered(self):
        loc = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.60:1400/xml/device_description.xml\r\n\r\n"
        FakeSocket.replier = lambda data, where: [(loc, TV), (loc.replace(b"192.168.1.60", b"192.168.1.99"), PHONE)]
        namer = quiet_namer()
        fetched = []
        with mock.patch.object(names, "fetch_description",
                                  lambda url, ip, timeout, connect: fetched.append((url, ip)) or {"name": "Den"}):
            found = namer.ask_ssdp({TV: "", PHONE: ""}, time.monotonic() + 1)
        self.assertEqual(found, {TV: {"name": "Den"}})
        self.assertEqual(fetched, [("http://192.168.1.60:1400/xml/device_description.xml", TV)])

    def test_a_description_being_fetched_is_not_fetched_again_by_the_next_round(self):
        loc = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.60/d.xml\r\n\r\n"
        FakeSocket.replier = lambda data, where: [(loc, TV)]
        namer = quiet_namer()
        started, release = [], threading.Event()

        def stuck(url, ip, timeout, connect):
            started.append(url)
            release.wait(2)
            return None
        self.addCleanup(release.set)
        with mock.patch.object(names, "fetch_description", stuck):
            namer.ask_ssdp({TV: ""}, time.monotonic() + 0.2)
            namer.ask_ssdp({TV: ""}, time.monotonic() + 0.2)
        self.assertEqual(started, ["http://192.168.1.60/d.xml"])

    def test_a_slow_source_does_not_hold_up_the_round(self):
        namer = quiet_namer()
        namer.sources = [("netbios", lambda devices, deadline: time.sleep(5) or {PC: {"name": "late"}}),
                         ("dns", lambda devices, deadline: {PC: {"name": "router-name"}})]
        start = time.monotonic()
        hints = namer.round({PC: ""}, budget=0.3)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(hints[PC]["name"], "router name")

    def test_a_source_still_stuck_from_last_time_is_not_started_again(self):
        namer = quiet_namer()
        calls = []
        namer.sources = [("netbios", lambda devices, deadline: calls.append(1) or time.sleep(2) or {})]
        namer.round({PC: ""}, budget=0.1)
        namer.round({PC: ""}, budget=0.1)
        self.assertEqual(len(calls), 1)

    def test_a_failing_source_finds_nothing_and_the_others_still_count(self):
        namer = quiet_namer()
        namer.sources = [("mdns", lambda d, t: 1 / 0), ("dns", lambda d, t: {PC: {"name": "pc"}})]
        self.assertEqual(namer.round({PC: ""}, budget=0.5)[PC]["source"], "router")

    def test_a_name_heard_once_is_still_suggested_in_the_next_round(self):
        namer = quiet_namer()
        namer.sources = [("mdns", lambda d, t: {PHONE: {"name": "phone.local"}})]
        namer.round({PHONE: "aa:00:00:00:00:01"}, budget=0.5)
        namer.sources = [("mdns", lambda d, t: {})]
        self.assertEqual(namer.round({PHONE: "aa:00:00:00:00:01"}, budget=0.5)[PHONE]["name"], "phone")

    def test_a_reused_address_does_not_inherit_the_last_devices_name(self):
        namer = quiet_namer()
        namer.sources = [("mdns", lambda d, t: {PHONE: {"name": "phone.local"}})]
        namer.round({PHONE: "aa:00:00:00:00:01"}, budget=0.5)
        namer.sources = [("mdns", lambda d, t: {})]
        self.assertNotIn(PHONE, namer.round({PHONE: "aa:00:00:00:00:02"}, budget=0.5))

    def test_only_home_network_addresses_are_asked_about(self):
        namer = quiet_namer()
        asked = []
        namer.sources = [("dns", lambda d, t: asked.append(sorted(d)) or {})]
        namer.round({PC: "", "8.8.8.8": "", "224.0.0.251": "", "127.0.0.1": "", "nonsense": ""}, budget=0.5)
        self.assertEqual(asked, [[PC]])

    def test_reverse_lookups_that_hang_are_left_behind(self):
        namer = quiet_namer(reverse=lambda ip: time.sleep(3) or "late" if ip == PC else "tv")
        start = time.monotonic()
        found = namer.ask_router({PC: "", TV: ""}, time.monotonic() + 0.3)
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertEqual(found, {TV: {"name": "tv"}})


class Listeners(unittest.TestCase):
    def test_a_listener_that_cannot_open_its_port_is_survived_and_reported_once(self):
        namer = quiet_namer()

        def refuse():
            raise PermissionError(13, "Permission denied")
        namer.open_mdns_listener = refuse
        namer.open_dhcp_listener = refuse
        with mock.patch("builtins.print") as said:
            namer.start_listeners()
        self.assertEqual(said.call_count, 2)
        self.assertEqual(namer.listening, {"bonjour": False, "dhcp": False})
        self.assertIn("Permission denied", said.call_args_list[0][0][0])

    def test_the_bonjour_listener_joins_the_group_on_its_own_address_only(self):
        namer = quiet_namer()
        sock = namer.open_mdns_listener()
        self.assertEqual(sock.bound, names.MDNS)
        self.assertIn(socket.IP_ADD_MEMBERSHIP, [o[1] for o in sock.options])

    def test_the_dhcp_listener_hears_broadcasts_only_and_sends_nothing(self):
        namer = quiet_namer()
        sock = namer.open_dhcp_listener()
        self.assertEqual(sock.bound, ("255.255.255.255", 67))
        self.assertEqual(sock.sent, [])

    def test_a_device_joining_is_named_by_its_hardware_address(self):
        namer = quiet_namer()
        namer.hear_dhcp(dhcp_packet(3, b"\x0c\x0dLewiss-iPhone"), "0.0.0.0")
        self.assertEqual(namer.ask_dhcp({PHONE: "aa:bb:cc:00:11:22", TV: "00:00:00:00:00:01"}, 0),
                         {PHONE: {"name": "Lewiss-iPhone", "vendor": ""}})

    def test_bonjour_announcements_are_added_to_the_answers(self):
        namer = quiet_namer()
        namer.hear_mdns(answer_packet([record("tv.local", 1, socket.inet_aton(TV))]), TV)
        found = namer.ask_mdns({TV: ""}, time.monotonic() + 0.1)
        self.assertEqual(found[TV]["name"], "tv.local")

    def test_a_bonjour_announcement_is_not_passed_to_the_next_device_on_the_address(self):
        namer = quiet_namer()
        namer.sources = [("mdns", namer.ask_mdns)]
        iphone, pc = "aa:aa:aa:aa:aa:aa", "00:11:22:33:44:55"
        namer.round({PHONE: iphone}, budget=0.3)
        namer.hear_mdns(answer_packet([record("Lewiss-iPhone.local", 1, socket.inet_aton(PHONE))]), PHONE)
        self.assertEqual(namer.round({PHONE: iphone}, budget=0.3)[PHONE]["name"], "Lewiss iPhone")
        self.assertNotIn(PHONE, namer.round({PHONE: pc}, budget=0.3))

    def test_a_bonjour_announcement_heard_before_the_device_was_known_is_tied_to_it_at_the_next_round(self):
        namer = quiet_namer()
        namer.hear_mdns(answer_packet([record("tv.local", 1, socket.inet_aton(TV))]), TV)
        namer.ask_mdns({TV: "aa:aa:aa:aa:aa:aa"}, time.monotonic() + 0.1)
        self.assertEqual(namer.ask_mdns({TV: "00:11:22:33:44:55"}, time.monotonic() + 0.1), {})

    def test_a_bonjour_announcement_older_than_the_keeping_time_is_dropped(self):
        namer = quiet_namer()
        namer.hear_mdns(answer_packet([record("tv.local", 1, socket.inet_aton(TV))]), TV)
        namer.heard_mdns[TV]["when"] -= names.KEEP_SECONDS + 1
        self.assertEqual(namer.ask_mdns({TV: ""}, time.monotonic() + 0.1), {})
        self.assertNotIn(TV, namer.heard_mdns)

    def test_keeping_a_bonjour_announcement_does_not_make_it_look_new(self):
        namer = quiet_namer()
        namer.sources = [("mdns", namer.ask_mdns)]
        namer.hear_mdns(answer_packet([record("tv.local", 1, socket.inet_aton(TV))]), TV)
        namer.heard_mdns[TV]["when"] -= 1000
        heard = namer.heard_mdns[TV]["when"]
        namer.round({TV: ""}, budget=0.3)
        self.assertEqual(namer.cache[TV]["by"]["mdns"][0], heard)

    def test_the_dhcp_listener_on_linux_reads_packets_without_taking_port_67(self):
        namer = quiet_namer(packet_capture=True)
        sock = namer.open_dhcp_listener()
        self.assertIsNone(sock.bound)
        self.assertIn(names.SO_ATTACH_FILTER, [o[1] for o in sock.options])
        self.assertEqual(sock.sent, [])

    def test_a_dhcp_listener_without_its_packet_filter_is_not_opened(self):
        namer = quiet_namer(packet_capture=True)
        with mock.patch.object(FakeSocket, "setsockopt", side_effect=OSError(1, "Operation not permitted")):
            with self.assertRaises(OSError):
                namer.open_dhcp_listener()

    def test_the_packet_listener_names_a_device_joining(self):
        namer = quiet_namer(packet_capture=True)
        namer.hear_dhcp_packet(ip_udp_packet(dhcp_packet(3, b"\x0c\x0dLewiss-iPhone")), "eth0")
        self.assertEqual(namer.heard_dhcp["aa:bb:cc:00:11:22"]["name"], "Lewiss-iPhone")

    def test_the_packet_filter_jumps_stay_inside_it(self):
        for n, (code, jt, jf, _) in enumerate(names.DHCP_FILTER):
            if code & 0x07 == 0x05:                                      # a jump
                self.assertLess(n + 1 + max(jt, jf), len(names.DHCP_FILTER))
        self.assertEqual(names.DHCP_FILTER[-1], (0x06, 0, 0, 0))

    def test_the_tables_of_things_heard_are_capped(self):
        namer = quiet_namer()
        for n in range(names.MAX_LEARNT + 50):
            mac = b"\x02\x00" + n.to_bytes(4, "big")
            namer.hear_dhcp(dhcp_packet(1, b"\x0c\x01x", mac=mac), "0.0.0.0")
        self.assertEqual(len(namer.heard_dhcp), names.MAX_LEARNT)


if __name__ == "__main__":
    unittest.main()
