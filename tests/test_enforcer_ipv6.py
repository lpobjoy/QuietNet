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
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import enforcer  # noqa: E402

HUB_LL, HUB_MAC = "fe80::1", "99:99:99:99:99:99"
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
                           ("sysctl_get", lambda key: "1" if "forward" in key else "0"),
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

    def test_the_tick_sends_the_claim(self):
        self.e._tick_v6()
        self.assertEqual(self.sent.frames, [STEER_FRAME])

    def test_the_firewall_gets_the_ip6_redirect_after_steering(self):
        self.e._tick_v6()
        self.e._tick()
        self.assertTrue(any("dns_redirect6" in text for text in self.loaded()))
        self.assertTrue(any("dnat ip6 to [fd00::9]:53" in text for text in self.loaded()))

    def test_the_steered_set_is_written_to_the_notes_file(self):
        self.e._tick_v6()
        with open(os.path.join(self.dir, "enforcer_state.json")) as f:
            self.assertEqual(json.load(f)["v6_spoofed"], {DEV_MAC: DEV_LL})

    def test_a_restart_adopts_and_hands_back_the_saved_devices(self):
        with open(os.path.join(self.dir, "enforcer_state.json"), "w") as f:
            json.dump({"sysctls": {}, "spoofed": {}, "v6_spoofed": {DEV_MAC: DEV_LL}}, f)
        self.config = {"enabled": False, "hub": {"v6": HUB_LL, "mac": HUB_MAC}, "devices": {}}
        self.e._recover()
        self.e._tick_v6()
        self.assertTrue(any(f[-6:] == enforcer.mac_to_bytes(HUB_MAC) for f in self.sent.frames))
        self.assertFalse(self.e._v6.active())

    def test_stopping_hands_the_device_back(self):
        self.e._tick_v6()
        self.sent.frames.clear()
        self.e._teardown()
        self.assertTrue(any(f[-6:] == enforcer.mac_to_bytes(HUB_MAC) for f in self.sent.frames))

    def test_the_status_reports_the_steering(self):
        self.e._tick_v6()
        status = self.e.status()["ipv6_steering"]
        self.assertTrue(status["offered"] and status["enabled"] and status["hub_known"])
        self.assertEqual(status["steered"], 1)


if __name__ == "__main__":
    unittest.main()
