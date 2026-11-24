"""Checks for taking IPv6 away from steered devices (design option c2): the IPv6Steerer class, the
neighbour-discovery frame builders, the ip6 firewall redirect, and how the enforcer drives them.

Run with:  python3 -m unittest discover tests

Nothing here touches the real network. Frames are built in memory and checked byte for byte; the
sending is a stand-in that writes down what it was asked to send. The important safety point - a
claim is never sent to the wrong address - is checked directly.
"""
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import enforcer  # noqa: E402

HUB_LL, HUB_MAC = "fe80::1", "98:99:99:99:99:99"   # even first byte: a single device's address, not a group
PI_MAC = "aa:aa:aa:aa:aa:aa"
DEV_IP, DEV_LL, DEV_MAC = "192.168.1.23", "fe80::23", "10:22:33:44:55:66"
# The steering claim for the device above, captured from a run and checked by hand: Ethernet to the
# device from the Pi, IPv6 from the router's link-local to the device's, hop limit 255, a neighbour
# advertisement with router/solicited/override set, the target the router's address, the option the
# Pi's hardware address.
STEER_FRAME = bytes.fromhex(
    "102233445566aaaaaaaaaaaa86dd6000000000203afffe80000000000000"
    "0000000000000001fe800000000000000000000000000023880099fbe000"
    "0000fe8000000000000000000000000000010201aaaaaaaaaaaa")


def solicitation(src_ip, src_mac, target, eth_dst=PI_MAC, hop=255, with_option=True):
    """Build one neighbour-solicitation frame the way a device asks "who has this address?"."""
    body = bytes([enforcer.ND_SOLICIT, 0, 0, 0, 0, 0, 0, 0]) + enforcer.v6_bytes(target)
    if with_option:
        body += bytes([1, 1]) + enforcer.mac_to_bytes(src_mac)
    ip6 = bytes([0x60, 0, 0, 0]) + struct.pack(">H", len(body)) + bytes([enforcer.IPPROTO_ICMPV6, hop])
    ip6 += enforcer.v6_bytes(src_ip) + enforcer.v6_bytes(target)
    eth = enforcer.mac_to_bytes(eth_dst) + enforcer.mac_to_bytes(src_mac) + struct.pack(">H", enforcer.ETH_IPV6)
    return eth + ip6 + body


def checksum_ok(frame):
    """True if the frame's ICMPv6 checksum is right (the sum over the whole message, checksum and
    all, comes to zero when it is)."""
    src = str(enforcer.ipaddress.IPv6Address(frame[22:38]))
    dst = str(enforcer.ipaddress.IPv6Address(frame[38:54]))
    return enforcer.icmpv6_checksum(src, dst, frame[54:]) == 0


class Frames(unittest.TestCase):
    """The neighbour-discovery frames are built byte for byte, with the right checksum and hop limit."""

    def test_the_steering_claim_matches_a_known_good_frame(self):
        frame = enforcer.neighbour_advertisement(HUB_LL, PI_MAC, DEV_LL, DEV_MAC, eth_src=PI_MAC)
        self.assertEqual(frame, STEER_FRAME)

    def test_the_claim_carries_a_correct_checksum(self):
        self.assertTrue(checksum_ok(enforcer.neighbour_advertisement(HUB_LL, PI_MAC, DEV_LL, DEV_MAC)))

    def test_the_claim_carries_hop_limit_255(self):
        frame = enforcer.neighbour_advertisement(HUB_LL, PI_MAC, DEV_LL, DEV_MAC)
        self.assertEqual(frame[21], 255)

    def test_the_claim_is_addressed_only_to_the_one_device(self):
        frame = enforcer.neighbour_advertisement(HUB_LL, PI_MAC, DEV_LL, DEV_MAC, eth_src=PI_MAC)
        self.assertEqual(frame[0:6], enforcer.mac_to_bytes(DEV_MAC))        # Ethernet to the device
        self.assertEqual(frame[6:12], enforcer.mac_to_bytes(PI_MAC))       # from the Pi
        self.assertEqual(frame[38:54], enforcer.v6_bytes(DEV_LL))          # IPv6 to the device

    def test_the_claim_says_the_routers_address_is_at_the_pi(self):
        frame = enforcer.neighbour_advertisement(HUB_LL, PI_MAC, DEV_LL, DEV_MAC)
        self.assertEqual(frame[62:78], enforcer.v6_bytes(HUB_LL))          # the address claimed
        self.assertEqual(frame[-6:], enforcer.mac_to_bytes(PI_MAC))        # at the Pi's hardware address

    def test_the_correction_gives_the_routers_real_hardware_address(self):
        frame = enforcer.neighbour_advertisement(HUB_LL, HUB_MAC, DEV_LL, DEV_MAC, eth_src=PI_MAC, solicited=False)
        self.assertEqual(frame[-6:], enforcer.mac_to_bytes(HUB_MAC))
        self.assertEqual(frame[58] & 0x40, 0)                              # not "solicited"
        self.assertEqual(frame[58] & 0x20, 0x20)                           # but "override" set
        self.assertTrue(checksum_ok(frame))

    def test_a_solicitation_is_read(self):
        got = enforcer.parse_neighbour_solicitation(solicitation(DEV_LL, DEV_MAC, HUB_LL))
        self.assertEqual(got, (DEV_LL, DEV_MAC, HUB_LL))

    def test_the_asker_falls_back_to_the_frame_when_it_gives_no_option(self):
        got = enforcer.parse_neighbour_solicitation(solicitation(DEV_LL, DEV_MAC, HUB_LL, with_option=False))
        self.assertEqual(got, (DEV_LL, DEV_MAC, HUB_LL))

    def test_a_solicitation_with_the_wrong_hop_limit_is_refused(self):
        self.assertIsNone(enforcer.parse_neighbour_solicitation(solicitation(DEV_LL, DEV_MAC, HUB_LL, hop=64)))

    def test_a_duplicate_address_check_is_never_answered(self):
        # Its source is the unspecified address; answering would tell a device its own address is taken.
        self.assertIsNone(enforcer.parse_neighbour_solicitation(solicitation("::", DEV_MAC, HUB_LL)))

    def test_the_solicited_node_group_and_its_hardware_address(self):
        self.assertEqual(enforcer.solicited_node_multicast(HUB_LL), "ff02::1:ff00:1")
        self.assertEqual(enforcer.multicast_mac("ff02::1:ff00:1"), "33:33:ff:00:00:01")


class NeverTheWrongAddress(unittest.TestCase):
    """A claim is only ever safe to send to a single device's own link-local and hardware addresses."""

    FORBIDDEN = {HUB_MAC, PI_MAC}

    def test_a_device_link_local_and_hardware_address_are_allowed(self):
        self.assertEqual(enforcer.na_claim_problem(DEV_LL, DEV_MAC, self.FORBIDDEN), "")

    def test_the_all_nodes_group_is_refused(self):
        self.assertTrue(enforcer.na_claim_problem("ff02::1", DEV_MAC, self.FORBIDDEN))

    def test_a_non_link_local_address_is_refused(self):
        self.assertTrue(enforcer.na_claim_problem("2001:db8::23", DEV_MAC, self.FORBIDDEN))

    def test_the_routers_hardware_address_is_refused(self):
        self.assertTrue(enforcer.na_claim_problem(DEV_LL, HUB_MAC, self.FORBIDDEN))

    def test_this_computers_hardware_address_is_refused(self):
        self.assertTrue(enforcer.na_claim_problem(DEV_LL, PI_MAC, self.FORBIDDEN))

    def test_a_group_hardware_address_is_refused(self):
        self.assertTrue(enforcer.na_claim_problem(DEV_LL, "33:33:00:00:00:01", self.FORBIDDEN))

    def test_all_zero_and_broken_hardware_addresses_are_refused(self):
        self.assertTrue(enforcer.na_claim_problem(DEV_LL, "00:00:00:00:00:00", self.FORBIDDEN))
        self.assertTrue(enforcer.na_claim_problem(DEV_LL, "not a mac", self.FORBIDDEN))


class RedirectRuleText(unittest.TestCase):
    """The ip6 DNS redirect added to the firewall, as text, catches only the steered devices' lookups
    for the router's IPv6 address and sends them to QuietNet."""

    IPV6 = {"target": "fd00::9", "port": 53, "servers": [HUB_LL], "macs": [DEV_MAC]}

    def ruleset(self, ipv6=None):
        """The firewall text for one steered IPv4 device, with the IPv6 redirect `ipv6`."""
        return enforcer.nft_ruleset({DEV_IP: {"off": True, "ips": set()}}, "192.168.1.60", 53, ipv6=ipv6)

    def test_without_ipv6_the_text_is_unchanged(self):
        self.assertNotIn("ip6", self.ruleset())
        self.assertNotIn("dns_redirect6", self.ruleset())

    def test_the_redirect_catches_the_device_by_hardware_address(self):
        text = self.ruleset(self.IPV6)
        for proto in ("udp", "tcp"):
            self.assertIn("ether saddr { %s } ip6 daddr { %s } %s dport 53 dnat ip6 to [fd00::9]:53"
                          % (DEV_MAC, HUB_LL, proto), text)

    def test_the_redirect_is_made_before_routing_in_a_nat_chain(self):
        self.assertIn("    type nat hook prerouting priority -100; policy accept;", self.ruleset(self.IPV6))

    def test_nothing_is_added_without_a_device_or_a_server(self):
        self.assertNotIn("dns_redirect6", self.ruleset({"target": "fd00::9", "port": 53, "servers": [], "macs": [DEV_MAC]}))
        self.assertNotIn("dns_redirect6", self.ruleset({"target": "fd00::9", "port": 53, "servers": [HUB_LL], "macs": []}))

    def test_the_whole_table_is_still_replaced_in_one_step(self):
        self.assertTrue(self.ruleset(self.IPV6).startswith(
            "table inet quietnet\ndelete table inet quietnet\ntable inet quietnet {"))

    def test_a_bad_address_is_refused(self):
        for bad in ("fd00::9; flush", "192.168.1.9", "not an address"):
            with self.assertRaises(ValueError, msg=bad):
                self.ruleset({"target": bad, "port": 53, "servers": [HUB_LL], "macs": [DEV_MAC]})

    def test_a_bad_hardware_address_is_refused(self):
        with self.assertRaises(ValueError):
            self.ruleset({"target": "fd00::9", "port": 53, "servers": [HUB_LL], "macs": ["11:22:33:44:55:zz"]})

    def test_a_bad_server_address_is_refused(self):
        with self.assertRaises(ValueError):
            self.ruleset({"target": "fd00::9", "port": 53, "servers": ["fe80::} flush {"], "macs": [DEV_MAC]})

    def test_a_bad_port_is_refused(self):
        for bad in (0, 65536, True, "53"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.ruleset({"target": "fd00::9", "port": bad, "servers": [HUB_LL], "macs": [DEV_MAC]})


class Sent:
    """A stand-in for the enforcer's raw socket that writes down the frames it is asked to send."""
    def __init__(self):
        self.frames = []

    def __call__(self, frame):
        self.frames.append(frame)


def steerer(saves=None):
    """An IPv6Steerer wired to a stand-in socket, with the usual device turned on."""
    sent = Sent()
    s = enforcer.IPv6Steerer("wlan0", PI_MAC, sent, log=lambda m: None, save=saves or (lambda: None))
    s.set_target({"enabled": True, "hub": {"v6": HUB_LL, "mac": HUB_MAC}, "our_v6": "fd00::9",
                  "port": 53, "servers": [HUB_LL], "shared": [], "devices": {DEV_IP: {"mac": DEV_MAC, "ll": DEV_LL}}})
    return s, sent


class Steering(unittest.TestCase):
    """The IPv6Steerer sends claims, answers checks, and refuses the wrong devices."""

    def test_a_chosen_device_is_sent_the_claim(self):
        s, sent = steerer()
        s.steer()
        self.assertEqual(sent.frames, [STEER_FRAME])
        self.assertTrue(s.active())

    def test_a_range_extender_is_left_alone_and_said_so(self):
        s, sent = steerer()
        s.shared = {DEV_MAC.lower()}
        problems = s.steer()
        self.assertEqual(sent.frames, [])
        self.assertIn("range extender", problems[DEV_IP])

    def test_nothing_is_sent_until_the_routers_address_is_known(self):
        s, sent = steerer()
        s.hub = {}
        s.steer()
        self.assertEqual(sent.frames, [])

    def test_turning_it_off_hands_the_device_back(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.enabled = False
        s.steer()
        # one correction with the router's real hardware address, then forgotten
        self.assertEqual(len(sent.frames), 1)
        self.assertEqual(sent.frames[0][-6:], enforcer.mac_to_bytes(HUB_MAC))
        self.assertFalse(s.active())

    def test_a_steered_devices_reachability_check_is_answered(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.handle_solicitation(solicitation(DEV_LL, DEV_MAC, HUB_LL))
        self.assertEqual(sent.frames, [STEER_FRAME])

    def test_a_check_from_an_unsteered_device_is_not_answered(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.handle_solicitation(solicitation("fe80::99", "77:77:77:77:77:77", HUB_LL))
        self.assertEqual(sent.frames, [])

    def test_a_check_about_another_address_is_not_answered(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.handle_solicitation(solicitation(DEV_LL, DEV_MAC, "fe80::abcd"))
        self.assertEqual(sent.frames, [])

    def test_the_redirect_names_only_steered_devices(self):
        s, _ = steerer()
        s.steer()
        info = s.redirect_info()
        self.assertEqual(info["macs"], [DEV_MAC])
        self.assertEqual(info["servers"], [HUB_LL])

    def test_no_redirect_without_a_lasting_address_of_our_own(self):
        s, _ = steerer()
        s.our_v6 = ""
        s.steer()
        self.assertIsNone(s.redirect_info())


class SaveAndRestore(unittest.TestCase):
    """Steered devices are saved by hardware address and handed back after a restart."""

    def test_the_steered_set_is_offered_for_saving(self):
        s, _ = steerer()
        s.steer()
        self.assertEqual(s.state_dict(), {DEV_MAC: DEV_LL})

    def test_the_save_callback_runs_when_the_set_changes(self):
        calls = []
        s, _ = steerer(saves=lambda: calls.append(1))
        s.steer()
        self.assertEqual(len(calls), 1)
        s.steer()                                   # same set again: nothing new to save
        self.assertEqual(len(calls), 1)

    def test_an_adopted_device_is_handed_back_if_no_longer_chosen(self):
        s, sent = steerer()
        s.adopt({DEV_MAC: DEV_LL})
        s.set_target({"enabled": True, "hub": {"v6": HUB_LL, "mac": HUB_MAC}, "devices": {}})
        s.steer()
        self.assertEqual(len(sent.frames), 1)       # a correction for the adopted device
        self.assertEqual(sent.frames[0][-6:], enforcer.mac_to_bytes(HUB_MAC))
        self.assertEqual(s.state_dict(), {})


class EnforcerDrives(unittest.TestCase):
    """The enforcer sends IPv6 claims on its tick, loads the ip6 redirect with its other rules, saves
    the steered set to its notes file, and hands everything back when it stops."""

    def setUp(self):
        self.commands = []

        def run(args, **kw):
            self.commands.append((args, kw.get("input")))

            class R:
                returncode, stderr, stdout = 0, "", ""
            return R()

        for name, fake in (("interface_and_gateway", lambda: ("wlan0", "192.168.1.254")),
                           ("local_subnet", lambda iface: enforcer.ipaddress.IPv4Network("192.168.1.0/24")),
                           ("mac_of_interface", lambda iface: PI_MAC),
                           ("sysctl_get", lambda key: "1" if ("forward" in key and "ipv6" not in key) else "0"),
                           ("sysctl_set", lambda key, value: True)):
            p = mock.patch.object(enforcer, name, fake)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(enforcer.subprocess, "run", run)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(enforcer, "shutil", mock.Mock(which=lambda t: "/sbin/" + t if t == "nft" else None))
        p.start()
        self.addCleanup(p.stop)

        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        self.config = {"enabled": True, "hub": {"v6": HUB_LL, "mac": HUB_MAC}, "our_v6": "fd00::9",
                       "port": 53, "servers": [HUB_LL], "shared": [],
                       "devices": {DEV_IP: {"mac": DEV_MAC, "ll": DEV_LL}}}
        self.e = enforcer.Enforcer("192.168.1.60", lambda: {DEV_IP: {"off": True, "ips": set(), "mac": DEV_MAC}},
                                   lambda: {DEV_IP: DEV_MAC, "192.168.1.254": HUB_MAC}, log=lambda m: None,
                                   data_dir=self.dir, dns_port=53, plan6=lambda: self.config)
        self.e.iface, self.e.gateway_ip, self.e.our_mac, self.e.backend = "wlan0", "192.168.1.254", PI_MAC, "nft"
        self.e.reason = ""
        self.sent = Sent()
        self.e._sock = mock.Mock(send=self.sent)

    def loaded(self):
        return [text for args, text in self.commands if args == ["nft", "-f", "-"]]

    def tick(self):
        """One whole enforcer pass in the running order (IPv6 first, then IPv4), as _run does."""
        self.e._tick_v6()
        self.e._tick()

    def test_the_tick_sends_the_claim(self):
        self.e._tick()                        # IPv4 steers the device first, so it is one we hold
        self.sent.frames.clear()
        self.e._tick_v6()
        self.assertEqual(self.sent.frames, [STEER_FRAME])

    def test_the_firewall_gets_the_ip6_redirect_after_steering(self):
        self.tick()                           # first tick: IPv4 steers; IPv6 claim lands the tick after
        self.tick()
        self.assertTrue(any("dns_redirect6" in text for text in self.loaded()))
        self.assertTrue(any("dnat ip6 to [fd00::9]:53" in text for text in self.loaded()))

    def test_the_steered_set_is_written_to_the_notes_file(self):
        self.e._tick()
        self.e._tick_v6()
        with open(os.path.join(self.dir, "enforcer_state.json")) as f:
            self.assertEqual(json.load(f)["v6_spoofed"], {DEV_MAC: DEV_LL})

    def test_the_hub_is_written_to_the_notes_file_with_the_steered_set(self):
        self.e._tick()
        self.e._tick_v6()
        with open(os.path.join(self.dir, "enforcer_state.json")) as f:
            self.assertEqual(json.load(f)["v6_hub"], {"v6": HUB_LL, "mac": HUB_MAC})

    def test_a_restart_hands_saved_devices_back_before_the_hub_is_heard(self):
        with open(os.path.join(self.dir, "enforcer_state.json"), "w") as f:
            json.dump({"sysctls": {}, "spoofed": {}, "v6_spoofed": {DEV_MAC: DEV_LL},
                       "v6_hub": {"v6": HUB_LL, "mac": HUB_MAC}}, f)
        self.config = {"enabled": False, "hub": {}, "devices": {}}   # the hub is not known on the first tick
        self.e._recover()
        self.e._tick_v6()
        correction = enforcer.neighbour_advertisement(HUB_LL, HUB_MAC, DEV_LL, DEV_MAC,
                                                       eth_src=PI_MAC, solicited=False, override=True)
        self.assertIn(correction, self.sent.frames)
        self.assertFalse(self.e._v6.active())
        self.assertFalse(os.path.exists(os.path.join(self.dir, "enforcer_state.json")))

    def test_a_restart_with_no_saved_hub_forgets_the_devices_and_sends_nothing(self):
        with open(os.path.join(self.dir, "enforcer_state.json"), "w") as f:
            json.dump({"sysctls": {}, "spoofed": {}, "v6_spoofed": {DEV_MAC: DEV_LL}}, f)
        self.config = {"enabled": False, "hub": {}, "devices": {}}
        self.e._recover()
        self.e._tick_v6()
        self.assertEqual([f for f in self.sent.frames if f[12:14] == b"\x86\xdd"], [])
        self.assertFalse(self.e._v6.active())

    def test_a_saved_hub_that_is_not_a_valid_address_is_ignored(self):
        with open(os.path.join(self.dir, "enforcer_state.json"), "w") as f:
            json.dump({"sysctls": {}, "spoofed": {}, "v6_spoofed": {DEV_MAC: DEV_LL},
                       "v6_hub": {"v6": "ff02::1", "mac": "ff:ff:ff:ff:ff:ff"}}, f)
        self.config = {"enabled": False, "hub": {}, "devices": {}}
        self.e._recover()
        self.e._tick_v6()
        self.assertEqual([f for f in self.sent.frames if f[12:14] == b"\x86\xdd"], [])

    def test_stopping_hands_the_device_back(self):
        self.e._tick()
        self.e._tick_v6()
        self.sent.frames.clear()
        self.e._teardown()
        self.assertTrue(any(f[-6:] == enforcer.mac_to_bytes(HUB_MAC) for f in self.sent.frames
                            if f[12:14] == b"\x86\xdd"))

    def test_the_status_reports_the_steering(self):
        self.e._tick()
        self.e._tick_v6()
        status = self.e.status()["ipv6_steering"]
        self.assertTrue(status["offered"] and status["enabled"] and status["hub_known"])
        self.assertEqual(status["steered"], 1)

    def test_no_claim_is_sent_when_only_iptables_is_installed(self):
        self.e.backend = "iptables"
        self.e._tick()
        self.e._tick_v6()
        self.assertEqual([f for f in self.sent.frames if f[12:14] == b"\x86\xdd"], [])
        self.assertFalse(self.e._v6.active())

    def test_the_status_says_ipv6_steering_is_not_offered_without_nft(self):
        self.e.backend = "iptables"
        self.assertEqual(self.e.ipv6_status(), {"offered": False})

    def test_no_claim_is_sent_while_ipv6_forwarding_is_on_and_the_status_says_why(self):
        self.patch_forwarding_on()
        self.e._tick()
        self.e._tick_v6()
        self.assertEqual([f for f in self.sent.frames if f[12:14] == b"\x86\xdd"], [])
        self.assertIn("pass IPv6 traffic on", self.e.ipv6_status()["problem"])

    def patch_forwarding_on(self):
        real = enforcer.sysctl_get
        p = mock.patch.object(enforcer, "sysctl_get",
                              lambda key: "1" if "forward" in key else "0")
        p.start()
        self.addCleanup(p.stop)

    def test_no_claim_is_sent_while_ipv4_steering_is_paused(self):
        # Make routing look blocked so IPv4 steering pauses and holds no device.
        self.e._tick()
        self.sent.frames.clear()
        p = mock.patch.object(self.e, "_routing_ready", lambda: "a firewall is in the way")
        p.start()
        self.addCleanup(p.stop)
        self.e._tick()                        # releases the IPv4 hold on the device (_spoofed emptied)
        self.sent.frames.clear()
        self.e._tick_v6()
        self.assertEqual([f for f in self.sent.frames if f[12:14] == b"\x86\xdd"], [])

    def test_the_tick_v6_reads_no_neighbour_table_of_its_own(self):
        # gateway_mac reuses the table the IPv4 tick stored, so the IPv6 tick runs no `ip neigh`.
        self.e._hosts = {"192.168.1.254": HUB_MAC}
        calls = []
        self.e.neighbours = lambda: calls.append(1) or {"192.168.1.254": HUB_MAC}
        self.assertEqual(self.e.gateway_mac(), HUB_MAC)
        self.assertEqual(calls, [])

    def test_a_failed_ip6_load_is_retried_without_it_and_the_ipv4_rules_still_land(self):
        # The device is steered, then an nft load with the ip6 chain is rejected.
        self.e._tick()
        self.e._tick_v6()
        rejected = {"n": 0}

        def run(args, **kw):
            text = kw.get("input")
            if args == ["nft", "-f", "-"] and text and "dns_redirect6" in text:
                rejected["n"] += 1
                self.commands.append((args, text))

                class Bad:
                    returncode, stderr, stdout = 1, "boom", ""
                return Bad()
            self.commands.append((args, text))

            class R:
                returncode, stderr, stdout = 0, "", ""
            return R()

        p = mock.patch.object(enforcer.subprocess, "run", run)
        p.start()
        self.addCleanup(p.stop)
        self.e._applied = ""                  # force a reload
        self.e._tick()
        self.assertTrue(rejected["n"] >= 1)
        self.assertTrue(self.e._v6_load_failed)
        # The rules did land, without the ip6 chain.
        self.assertTrue(any(t and "dns_redirect6" not in t and "table inet quietnet {" in t
                            for a, t in self.commands if a == ["nft", "-f", "-"]))

    def test_ipv6_steering_stops_and_reports_why_after_a_failed_load(self):
        self.e._v6_load_failed = True
        self.e._tick()
        self.e._tick_v6()
        self.assertEqual([f for f in self.sent.frames if f[12:14] == b"\x86\xdd"], [])
        self.assertIn("nft firewall tool", self.e.ipv6_status()["problem"])

    def test_turning_the_setting_off_and_on_tries_the_load_again(self):
        self.e._v6_load_failed = True
        self.config = dict(self.config, enabled=False)
        self.e._tick_v6()
        self.assertFalse(self.e._v6_load_failed)   # seen off: the next load may try the ip6 chain again

    def test_the_running_loop_starts_the_listener_with_the_stop_signal(self):
        started = []
        self.e._open_socket = lambda: mock.Mock(send=self.sent, recv=mock.Mock(side_effect=OSError("closed")))
        self.e._v6.listen = lambda stop: started.append(stop)
        self.e.start()
        self.addCleanup(self.e.stop)
        for _ in range(100):
            if started:
                break
            time.sleep(0.02)
        self.assertEqual(started, [self.e._stop])

    def test_a_fault_in_ipv6_steering_does_not_stop_the_ipv4_tick(self):
        ticks = []
        self.e._tick_v6 = mock.Mock(side_effect=RuntimeError("boom"))
        self.e._tick = lambda: ticks.append(1)
        self.e._open_socket = lambda: mock.Mock(send=self.sent, recv=mock.Mock(side_effect=OSError("closed")))
        self.e._v6.listen = lambda stop: None
        self.e.start()
        self.addCleanup(self.e.stop)
        self.e.poke()
        for _ in range(100):
            if ticks:
                break
            time.sleep(0.02)
        self.assertTrue(ticks)

    def test_it_is_not_offered_with_the_iptables_tool(self):
        self.e.backend = "iptables"
        self.assertFalse(self.e.status()["ipv6_steering"]["offered"])


class FakeSock:
    """A stand-in socket for the listener: it hands over the frames it was given, remembers the
    multicast groups it was asked to join, and raises a timeout (running `then` first) once empty."""
    def __init__(self, frames=(), then=None):
        self.frames = list(frames)
        self.then = then or (lambda: None)
        self.options = []
        self.bound = None
        self.closed = False

    def bind(self, addr):
        self.bound = addr

    def settimeout(self, _):
        pass

    def setsockopt(self, *a):
        self.options.append(a)

    def recv(self, _n):
        if self.frames:
            return self.frames.pop(0)
        self.then()
        raise socket.timeout()

    def close(self):
        self.closed = True


class OnceStop:
    """A stop signal that lets a listen loop run one round: it reads not-set until wait() or set() is
    called, after which it reads set, so the loop finishes quickly without a real wait."""
    def __init__(self):
        self.flag = False

    def is_set(self):
        return self.flag

    def set(self):
        self.flag = True

    def wait(self, _t=None):
        self.flag = True
        return True


class ListenerSockets(unittest.TestCase):
    """The listener joins the right groups, learns and answers from stand-in sockets, and stops
    cleanly. No real socket is opened (AF_PACKET is None off Linux)."""

    def patch(self, target, value):
        p = mock.patch.object(target[0], target[1], value)
        p.start()
        self.addCleanup(p.stop)

    def wired(self, frames):
        """A steerer with one device steered, the listener sockets replaced by stand-ins, and a stop
        that fires once the frames run out."""
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        stop = OnceStop()
        pkt = FakeSock(frames, then=stop.set)
        join = FakeSock()
        self.patch((enforcer, "AF_PACKET"), 17)
        self.patch((enforcer.socket, "socket"), lambda family, *a: pkt if family == 17 else join)
        self.patch((enforcer.socket, "if_nametoindex"), lambda n: 7)
        return s, sent, pkt, join, stop

    def test_joining_asks_for_the_hubs_solicited_node_group(self):
        s, sent, pkt, join, stop = self.wired([])
        s.listen(stop)
        want = enforcer.v6_bytes("ff02::1:ff00:1") + struct.pack("@I", 7)
        self.assertIn((socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, want), join.options)

    def test_it_joins_the_mdns_and_report_groups_too(self):
        s, sent, pkt, join, stop = self.wired([])
        s.listen(stop)
        joined = {o[2] for o in join.options}
        self.assertIn(enforcer.v6_bytes("ff02::fb") + struct.pack("@I", 7), joined)
        self.assertIn(enforcer.v6_bytes("ff02::16") + struct.pack("@I", 7), joined)

    def test_a_steered_devices_check_heard_on_the_socket_is_answered(self):
        s, sent, pkt, join, stop = self.wired([solicitation(DEV_LL, DEV_MAC, HUB_LL)])
        s.listen(stop)
        self.assertIn(STEER_FRAME, sent.frames)
        self.assertEqual(pkt.bound, ("wlan0", enforcer.ETH_IPV6))

    def test_a_link_local_is_learned_from_a_frame_heard(self):
        other = "aa:00:00:00:00:01"
        eth = enforcer.mac_to_bytes(PI_MAC) + enforcer.mac_to_bytes(other) + struct.pack(">H", enforcer.ETH_IPV6)
        frame = eth + bytes([0x60, 0, 0, 0, 0, 0, 59, 64]) + enforcer.v6_bytes("fe80::55") + enforcer.v6_bytes("ff02::fb")
        s, sent, pkt, join, stop = self.wired([frame])
        s.listen(stop)
        self.assertEqual(s._heard.get(other), "fe80::55")

    def test_both_sockets_are_closed_when_asked_to_stop(self):
        s, sent, pkt, join, stop = self.wired([])
        s.listen(stop)
        self.assertTrue(pkt.closed and join.closed)

    def test_the_listener_holds_no_socket_while_the_setting_is_off(self):
        opened = []
        self.patch((enforcer, "AF_PACKET"), 17)
        self.patch((enforcer.socket, "socket"), lambda *a: opened.append(1) or FakeSock())
        s, _ = steerer()
        s.enabled = False
        s._steered = {}
        s.listen(OnceStop())
        self.assertEqual(opened, [])


class ScopeIds(unittest.TestCase):
    """An address that names a network card after a '%' is refused before it reaches a firewall rule."""

    def rules(self, **over):
        ipv6 = dict({"target": "fd00::9", "port": 53, "servers": [HUB_LL], "macs": [DEV_MAC]}, **over)
        return enforcer.nft_ruleset({DEV_IP: {"off": True, "ips": set()}}, "192.168.1.60", 53, ipv6=ipv6)

    def test_a_target_address_naming_a_network_card_is_refused(self):
        for bad in ("fd00::5%eth0", "fe80::1%wlan0 } ; flush ruleset ; #"):
            with self.assertRaises(ValueError, msg=bad):
                self.rules(target=bad)

    def test_a_server_address_naming_a_network_card_is_refused(self):
        for bad in ("fe80::1%wlan0", "fe80::1%wlan0 } ; flush ruleset ; #"):
            with self.assertRaises(ValueError, msg=bad):
                self.rules(servers=[bad])

    def test_the_checker_keeps_a_plain_address(self):
        self.assertEqual(enforcer._checked_ipv6("fd00::9"), "fd00::9")


class NothingIsSentToTheWrongAddress(unittest.TestCase):
    """The safety check is applied where it is used, not only in the helper: no claim leaves for a
    group, a non-link-local address, or the hub's, this computer's, a fixed or a group hardware address."""

    def one(self, mac=DEV_MAC, ll=DEV_LL, **kw):
        s, sent = steerer()
        for k, v in kw.items():
            setattr(s, k, v)
        s.devices = {DEV_IP: {"mac": mac, "ll": ll}}
        problems = s.steer()
        return s, sent, problems

    def test_the_routers_hardware_address_is_only_refused_by_the_forbidden_list(self):
        # With an even first byte it is a single device's address, so the forbidden list is what stops it.
        self.assertEqual(enforcer.na_claim_problem(DEV_LL, HUB_MAC, set()), "")

    def test_no_claim_is_sent_to_the_all_nodes_group(self):
        s, sent, problems = self.one(ll="ff02::1")
        self.assertEqual(sent.frames, [])
        self.assertIn(DEV_IP, problems)
        self.assertFalse(s.active())

    def test_no_claim_is_sent_to_an_address_that_is_not_link_local(self):
        s, sent, problems = self.one(ll="2001:db8::23")
        self.assertEqual(sent.frames, [])
        self.assertIn(DEV_IP, problems)

    def test_no_claim_is_sent_to_the_routers_hardware_address(self):
        for mac in (HUB_MAC, HUB_MAC.upper()):
            s, sent, problems = self.one(mac=mac)
            self.assertEqual(sent.frames, [])
            self.assertIn(DEV_IP, problems)

    def test_no_claim_is_sent_to_this_computers_hardware_address(self):
        s, sent, problems = self.one(mac=PI_MAC)
        self.assertEqual(sent.frames, [])

    def test_no_claim_is_sent_to_a_fixed_hardware_address(self):
        s, sent, problems = self.one(fixed_macs={DEV_MAC})
        self.assertEqual(sent.frames, [])

    def test_no_claim_is_sent_to_a_group_hardware_address(self):
        s, sent, problems = self.one(mac="33:33:00:00:00:01")
        self.assertEqual(sent.frames, [])

    def test_a_check_from_the_router_is_never_answered(self):
        s, sent = steerer()
        s.steer()
        s._steered[HUB_MAC] = HUB_LL          # even if it somehow got in
        sent.frames.clear()
        s.handle_solicitation(solicitation("fe80::1", HUB_MAC, HUB_LL))
        self.assertEqual(sent.frames, [])

    def test_no_check_is_answered_while_the_setting_is_off(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.enabled = False
        s.handle_solicitation(solicitation(DEV_LL, DEV_MAC, HUB_LL))
        self.assertEqual(sent.frames, [])

    def test_the_correction_sent_on_turning_off_overrides(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.enabled = False
        s.steer()
        self.assertEqual(len(sent.frames), 1)
        frame = sent.frames[0]
        self.assertEqual(frame[0:6], enforcer.mac_to_bytes(DEV_MAC))
        self.assertEqual(frame[38:54], enforcer.v6_bytes(DEV_LL))
        self.assertEqual(frame[58] & 0x20, 0x20)
        self.assertEqual(frame[58] & 0x40, 0)


class AnsweringChecks(unittest.TestCase):
    """A reachability check is answered to the device's recorded link-local address, whatever source
    the question used, and only for a device being steered (design (c2))."""

    def test_a_check_from_a_public_source_is_answered_to_the_recorded_link_local(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.handle_solicitation(solicitation("2a00:23c8::1234", DEV_MAC, HUB_LL))
        self.assertEqual(len(sent.frames), 1)
        self.assertEqual(sent.frames[0][38:54], enforcer.v6_bytes(DEV_LL))
        self.assertNotEqual(sent.frames[0][38:54], enforcer.v6_bytes("2a00:23c8::1234"))

    def test_a_check_is_not_answered_when_the_redirect_is_not_possible(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.our_v6 = ""                          # redirect no longer possible, so ready() is false
        s.handle_solicitation(solicitation(DEV_LL, DEV_MAC, HUB_LL))
        self.assertEqual(sent.frames, [])


class LearningLinkLocal(unittest.TestCase):
    """The steerer learns a device's link-local address from frames it hears, and keeps a chosen device
    steered at its last known address when the neighbour table loses it."""

    def frame_from(self, src_mac, src_ip):
        """A minimal IPv6 frame from one hardware address and IPv6 source, for note_frame."""
        eth = enforcer.mac_to_bytes(PI_MAC) + enforcer.mac_to_bytes(src_mac) + struct.pack(">H", enforcer.ETH_IPV6)
        ip6 = bytes([0x60, 0, 0, 0, 0, 0, 59, 64]) + enforcer.v6_bytes(src_ip) + enforcer.v6_bytes("ff02::fb")
        return eth + ip6

    def test_a_link_local_heard_from_a_frame_gets_the_device_steered(self):
        s, sent = steerer()
        s.devices = {DEV_IP: {"mac": DEV_MAC, "ll": ""}}
        self.assertEqual(s.steer().get(DEV_IP, "")[:8], "QuietNet")   # no address yet: reported
        self.assertEqual(sent.frames, [])
        s.note_frame(self.frame_from(DEV_MAC, DEV_LL))
        s.devices = {DEV_IP: {"mac": DEV_MAC, "ll": ""}}
        s.steer()
        self.assertEqual(sent.frames, [STEER_FRAME])

    def test_a_chosen_device_stays_steered_when_the_table_loses_its_address(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.devices = {DEV_IP: {"mac": DEV_MAC, "ll": ""}}   # table lost the link-local
        s.steer()
        self.assertEqual(sent.frames, [STEER_FRAME])       # re-claimed at the last known address
        self.assertTrue(s.active())

    def test_a_device_with_no_known_link_local_is_named_in_problems(self):
        s, sent = steerer()
        s.devices = {DEV_IP: {"mac": DEV_MAC, "ll": ""}}
        problems = s.steer()
        self.assertEqual(sent.frames, [])
        self.assertIn(DEV_IP, problems)

    def test_a_frame_from_the_hub_teaches_nothing(self):
        s, sent = steerer()
        s.note_frame(self.frame_from(HUB_MAC, "fe80::9"))
        self.assertNotIn(HUB_MAC.lower(), s._heard)

    def test_a_frame_with_a_non_link_local_source_teaches_nothing(self):
        s, sent = steerer()
        s.note_frame(self.frame_from("12:34:56:78:9a:bc", "2001:db8::9"))
        self.assertNotIn("12:34:56:78:9a:bc", s._heard)

    def test_a_frame_from_a_group_hardware_address_teaches_nothing(self):
        s, sent = steerer()
        s.note_frame(self.frame_from("33:33:00:00:00:01", "fe80::9"))
        self.assertEqual(s._heard, {})


class UnclearDevices(unittest.TestCase):
    """A device marked unclear (several link-local addresses, perhaps behind an unrecognised extender)
    is left alone and said so, and handed back if it was already steered."""

    def test_an_unclear_device_is_not_steered_and_said_so(self):
        s, sent = steerer()
        s.devices = {DEV_IP: {"mac": DEV_MAC, "ll": "", "unclear": True}}
        problems = s.steer()
        self.assertEqual(sent.frames, [])
        self.assertIn("share", problems[DEV_IP])

    def test_a_device_that_becomes_unclear_is_handed_back(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.devices = {DEV_IP: {"mac": DEV_MAC, "ll": "", "unclear": True}}
        s.steer()
        self.assertEqual(len(sent.frames), 1)
        self.assertEqual(sent.frames[0][-6:], enforcer.mac_to_bytes(HUB_MAC))
        self.assertFalse(s.active())


class RangeExtenderReported(unittest.TestCase):
    """A range-extender device passed through with no link-local address is reported and never steered."""

    def test_an_extender_device_with_no_link_local_is_named_and_not_steered(self):
        s, sent = steerer()
        s.shared = {DEV_MAC.lower()}
        s.devices = {DEV_IP: {"mac": DEV_MAC, "ll": ""}}
        problems = s.steer()
        self.assertEqual(sent.frames, [])
        self.assertIn("range extender", problems[DEV_IP])


class WithheldWhenNoRedirect(unittest.TestCase):
    """No claim is sent unless its lookups can be answered: the redirect must be possible."""

    def test_no_claim_without_a_lasting_address_of_our_own(self):
        s, sent = steerer()
        s.our_v6 = ""
        s.steer()
        self.assertEqual(sent.frames, [])
        self.assertIn("lasting IPv6 address", s.why_not_ready())

    def test_no_claim_while_not_listening_over_ipv6(self):
        s, sent = steerer()
        s.port = None
        s.steer()
        self.assertEqual(sent.frames, [])

    def test_no_claim_when_the_firewall_cannot_load_the_redirect(self):
        s, sent = steerer()
        s.redirect_ok = False
        s.steer()
        self.assertEqual(sent.frames, [])

    def test_a_steered_device_is_handed_back_when_the_redirect_stops_being_possible(self):
        s, sent = steerer()
        s.steer()
        sent.frames.clear()
        s.redirect_ok = False
        s.steer()
        self.assertEqual(len(sent.frames), 1)
        self.assertEqual(sent.frames[0][-6:], enforcer.mac_to_bytes(HUB_MAC))
        self.assertFalse(s.active())


if __name__ == "__main__":
    unittest.main()
