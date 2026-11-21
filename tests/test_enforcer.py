"""Checks for the live-connection enforcer's behaviour (the `Enforcer` class).

Run with:  python3 -m unittest discover tests

Nothing here touches the real network. The raw socket, the firewall command and the
kernel settings are all replaced with stand-ins that write down what they were asked
to do, so these checks run safely on any computer, with or without admin rights.
"""
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import enforcer  # noqa: E402

US, GATEWAY = "192.168.1.60", "192.168.1.254"
OUR_MAC, GATEWAY_MAC = "aa:aa:aa:aa:aa:aa", "99:99:99:99:99:99"
KID, KID_MAC = "192.168.1.23", "11:22:33:44:55:66"
TV, TV_MAC = "192.168.1.30", "77:77:77:77:77:77"


class FakeSocket:
    def __init__(self):
        self.frames, self.closed = [], False

    def send(self, frame):
        self.frames.append(frame)

    def close(self):
        self.closed = True


class Result:
    def __init__(self, returncode=0, stderr=""):
        self.returncode, self.stderr, self.stdout = returncode, stderr, ""


def claims(frame):
    """What an ARP frame says: (who it is sent to, 'this address...', '...is at this hardware address')."""
    mac = lambda b: ":".join("%02x" % x for x in b)
    return mac(frame[0:6]), socket.inet_ntoa(frame[28:32]), mac(frame[22:28])


class EnforcerCase(unittest.TestCase):
    def setUp(self):
        self.plan = {}
        self.hosts = {KID: KID_MAC, TV: TV_MAC, GATEWAY: GATEWAY_MAC, US: OUR_MAC}
        self.log, self.commands, self.sysctl = [], [], {
            "net.ipv4.ip_forward": "0", "net.ipv4.conf.all.send_redirects": "1",
            "net.ipv4.conf.eth0.send_redirects": "1"}
        self.nft_fails = False

        def run(args, **kw):
            self.commands.append((args, kw.get("input")))
            return Result(1, "boom") if (self.nft_fails and args[0] == "nft") else Result()

        for name, fake in (("sysctl_get", lambda key: self.sysctl.get(key, "")),
                           ("sysctl_set", lambda key, value: self.sysctl.__setitem__(key, str(value)))):
            p = mock.patch.object(enforcer, name, fake)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(enforcer.subprocess, "run", run)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(enforcer.time, "sleep", lambda s: None)
        p.start()
        self.addCleanup(p.stop)

        self.e = enforcer.Enforcer(US, lambda: self.plan, lambda: self.hosts, log=self.log.append)
        self.e.iface, self.e.gateway_ip, self.e.our_mac, self.e.backend = "eth0", GATEWAY, OUR_MAC, "nft"
        self.e.reason = ""
        self.e._sock = self.sock = FakeSocket()

    def loaded_rules(self):
        return [text for args, text in self.commands if args == ["nft", "-f", "-"]]


class Ticking(EnforcerCase):
    def test_with_nobody_chosen_it_touches_nothing(self):
        self.e._tick()
        self.assertEqual(self.sock.frames, [])
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "0")
        self.assertFalse(self.e.status()["active"])
        self.assertTrue(all("drop" not in text for text in self.loaded_rules()))

    def test_a_chosen_device_is_steered_through_us(self):
        self.plan = {KID: {"off": False, "ips": {"203.0.113.5"}}}
        self.e._tick()
        # Told only the chosen device: "the router's address is at OUR hardware address".
        self.assertEqual([claims(f) for f in self.sock.frames], [(KID_MAC, GATEWAY, OUR_MAC)])
        self.assertTrue(self.e.status()["active"])

    def test_forwarding_is_switched_on_so_everything_else_still_flows(self):
        self.plan = {KID: {"off": False, "ips": {"203.0.113.5"}}}
        self.e._tick()
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "1")
        # Redirects off, or the kernel would tell the device to go straight to the router and bypass us.
        self.assertEqual(self.sysctl["net.ipv4.conf.all.send_redirects"], "0")
        self.assertEqual(self.sysctl["net.ipv4.conf.eth0.send_redirects"], "0")

    def test_only_the_blocked_addresses_are_dropped(self):
        self.plan = {KID: {"off": False, "ips": {"203.0.113.5"}}}
        self.e._tick()
        self.assertEqual(len(self.loaded_rules()), 1)
        self.assertIn("ip saddr %s ip daddr { 203.0.113.5 } drop" % KID, self.loaded_rules()[0])
        self.assertIn("policy accept", self.loaded_rules()[0])

    def test_the_firewall_is_only_reloaded_when_the_plan_changes(self):
        self.plan = {KID: {"off": False, "ips": {"203.0.113.5"}}}
        for _ in range(3):
            self.e._tick()
        self.assertEqual(len(self.loaded_rules()), 1)
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._tick()
        self.assertEqual(len(self.loaded_rules()), 2)
        self.assertIn("ip daddr != %s drop" % US, self.loaded_rules()[1])

    def test_steering_is_repeated_every_tick_so_the_device_does_not_drift_back(self):
        self.plan = {KID: {"off": False, "ips": set()}}
        for _ in range(3):
            self.e._tick()
        self.assertEqual(len(self.sock.frames), 3)

    def test_a_device_whose_hardware_address_is_unknown_is_left_alone(self):
        self.plan = {"192.168.1.99": {"off": True, "ips": set()}}
        self.e._tick()
        self.assertEqual(self.sock.frames, [])

    def test_this_computer_is_never_steered_or_cut(self):
        self.plan = {US: {"off": True, "ips": set()}, KID: {"off": True, "ips": set()}}
        self.e._tick()
        self.assertEqual([claims(f)[0] for f in self.sock.frames], [KID_MAC])
        self.assertNotIn("ip saddr %s " % US, self.loaded_rules()[0])

    def test_devices_not_in_the_plan_are_never_sent_anything(self):
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._tick()
        self.assertNotIn(TV_MAC, [claims(f)[0] for f in self.sock.frames])

    def test_when_the_last_device_is_released_the_kernel_settings_go_back(self):
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._tick()
        self.plan = {}
        self.e._tick()
        self.assertEqual(self.sysctl, {"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.send_redirects": "1",
                                       "net.ipv4.conf.eth0.send_redirects": "1"})
        self.assertNotIn("drop", self.loaded_rules()[-1])
        self.assertFalse(self.e.status()["active"])

    def test_a_firewall_failure_is_reported_and_tried_again(self):
        self.plan = {KID: {"off": True, "ips": set()}}
        self.nft_fails = True
        self.e._tick()
        self.assertEqual(self.log, ["nft load failed: boom"])
        self.nft_fails = False
        self.e._tick()
        self.assertEqual(len(self.loaded_rules()), 2)                    # it did not assume the first load worked

    def test_a_socket_error_is_reported_not_fatal(self):
        self.plan = {KID: {"off": True, "ips": set()}}
        self.sock.send = mock.Mock(side_effect=OSError("network down"))
        self.e._tick()
        self.assertEqual(self.log, ["Could not steer %s: network down" % KID])

    def test_the_older_iptables_tool_gets_the_same_plan(self):
        self.e.backend = "iptables"
        self.plan = {KID: {"off": False, "ips": {"203.0.113.5"}}, TV: {"off": True, "ips": set()}}
        self.e._tick()
        self.e._tick()
        cmds = [args for args, _ in self.commands]
        self.assertEqual(cmds, [["iptables", "-F", "QUIETNET"],
                                ["iptables", "-A", "QUIETNET", "-s", KID, "-d", "203.0.113.5", "-j", "DROP"],
                                ["iptables", "-A", "QUIETNET", "-s", TV, "!", "-d", US, "-j", "DROP"]])


class Teardown(EnforcerCase):
    def test_every_device_is_told_the_routers_real_address_again(self):
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._tick()
        del self.sock.frames[:]
        self.e._teardown()
        told = {claims(f) for f in self.sock.frames}
        self.assertEqual(told, {(KID_MAC, GATEWAY, GATEWAY_MAC), (TV_MAC, GATEWAY, GATEWAY_MAC)})
        self.assertEqual(len(self.sock.frames), 10)                      # five rounds, in case one is missed

    def test_the_firewall_table_is_removed_and_settings_restored(self):
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._tick()
        self.e._teardown()
        self.assertIn((["nft", "delete", "table", "inet", "quietnet"], None), self.commands)
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "0")
        self.assertEqual(self.sysctl["net.ipv4.conf.all.send_redirects"], "1")
        self.assertTrue(self.sock.closed)
        self.assertFalse(self.e.status()["active"])
        self.assertEqual(self.log[-1], "Enforcer stopped; network restored.")

    def test_iptables_teardown_removes_its_chain(self):
        self.e.backend = "iptables"
        self.e._teardown()
        cmds = [args for args, _ in self.commands]
        self.assertEqual(cmds, [["iptables", "-D", "FORWARD", "-j", "QUIETNET"], ["iptables", "-F", "QUIETNET"],
                                ["iptables", "-X", "QUIETNET"]])

    def test_if_the_routers_hardware_address_is_unknown_it_still_cleans_up(self):
        del self.hosts[GATEWAY]
        self.e._teardown()
        self.assertEqual(self.sock.frames, [])       # it cannot heal without knowing the real address...
        self.assertIn((["nft", "delete", "table", "inet", "quietnet"], None), self.commands)    # ...but still tidies


class Availability(unittest.TestCase):
    def make(self, linux=True, root=True, route=("eth0", GATEWAY), mac=OUR_MAC, tools=("nft",)):
        with mock.patch.object(enforcer, "IS_LINUX", linux), \
                mock.patch.object(enforcer, "AF_PACKET", 17 if linux else None), \
                mock.patch.object(enforcer.os, "geteuid", lambda: 0 if root else 1000, create=True), \
                mock.patch.object(enforcer, "interface_and_gateway", lambda: route), \
                mock.patch.object(enforcer, "mac_of_interface", lambda iface: mac), \
                mock.patch.object(enforcer.shutil, "which", lambda tool: "/usr/sbin/" + tool if tool in tools else None):
            return enforcer.Enforcer(US, dict, dict, log=lambda m: None)

    def test_ready_on_a_linux_box_with_admin_rights_and_a_firewall_tool(self):
        e = self.make()
        self.assertTrue(e.available())
        self.assertEqual(e.status(), {"available": True, "reason": "", "active": False, "backend": "nft",
                                      "gateway": GATEWAY})

    def test_off_on_a_mac_with_a_plain_explanation(self):
        e = self.make(linux=False)
        self.assertFalse(e.available())
        self.assertIn("runs on Linux", e.reason)

    def test_off_without_admin_rights(self):
        self.assertIn("admin rights", self.make(root=False).reason)

    def test_off_when_the_network_cannot_be_worked_out(self):
        self.assertIn("Couldn't work out", self.make(route=(None, None)).reason)
        self.assertIn("Couldn't work out", self.make(mac=None).reason)

    def test_off_without_a_firewall_tool(self):
        e = self.make(tools=())
        self.assertIn("No firewall tool", e.reason)
        self.assertIsNone(e.backend)

    def test_nft_is_preferred_and_iptables_is_the_fallback(self):
        self.assertEqual(self.make(tools=("nft", "iptables")).backend, "nft")
        self.assertEqual(self.make(tools=("iptables",)).backend, "iptables")

    def test_starting_when_unavailable_does_nothing(self):
        e = self.make(linux=False)
        e.log = mock.Mock()
        with mock.patch.object(enforcer.threading, "Thread") as thread:
            e.start()
        thread.assert_not_called()
        self.assertIn("Enforcer off", e.log.call_args[0][0])


class SystemFacts(unittest.TestCase):
    ROUTES = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
              "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
              "eth0\t00000000\tFE01A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")

    def test_the_router_is_read_from_the_default_route(self):
        with mock.patch.object(enforcer, "open", mock.mock_open(read_data=self.ROUTES), create=True):
            self.assertEqual(enforcer.interface_and_gateway(), ("eth0", "192.168.1.254"))

    def test_no_default_route_means_no_answer(self):
        only_local = "\n".join(self.ROUTES.splitlines()[:2]) + "\n"
        with mock.patch.object(enforcer, "open", mock.mock_open(read_data=only_local), create=True):
            self.assertEqual(enforcer.interface_and_gateway(), (None, None))

    def test_a_missing_routing_table_means_no_answer(self):
        with mock.patch.object(enforcer, "open", mock.Mock(side_effect=OSError), create=True):
            self.assertEqual(enforcer.interface_and_gateway(), (None, None))
            self.assertIsNone(enforcer.mac_of_interface("eth0"))

    def test_hardware_addresses_become_six_bytes(self):
        self.assertEqual(enforcer.mac_to_bytes("AA:bb:0c:0D:1e:ff"), bytes.fromhex("aabb0c0d1eff"))
        for bad in ("", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff"):
            self.assertRaises(ValueError, enforcer.mac_to_bytes, bad)

    def test_an_arp_frame_is_exactly_the_standard_size(self):
        self.assertEqual(len(enforcer.build_arp_reply(GATEWAY, OUR_MAC, KID, KID_MAC)), 42)


if __name__ == "__main__":
    unittest.main()
