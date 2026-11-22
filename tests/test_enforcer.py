"""Checks for the live-connection enforcer's behaviour (the `Enforcer` class).

Run with:  python3 -m unittest discover tests

Nothing here touches the real network. The raw socket, the firewall command and the
kernel settings are all replaced with stand-ins that write down what they were asked
to do, so these checks run safely on any computer, with or without admin rights.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
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
        chains = set()

        def run(args, **kw):
            self.commands.append((args, kw.get("input")))
            if self.nft_fails and args[:2] == ["nft", "-f"]:
                return Result(1, "boom")
            if "-N" in args:                     # like the real command: making a chain that exists fails
                if "QUIETNET" in chains:
                    return Result(1, "Chain already exists.")
                chains.add("QUIETNET")
            return Result()

        # This machine's network, as the enforcer would read it - never the real one, which on a
        # Linux machine (a Pi, a CI runner) would not be 192.168.1.0/24.
        for name, fake in (("interface_and_gateway", lambda: ("eth0", GATEWAY)),
                           ("local_subnet", lambda iface: enforcer.ipaddress.IPv4Network("192.168.1.0/24")),
                           ("mac_of_interface", lambda iface: OUR_MAC)):
            p = mock.patch.object(enforcer, name, fake)
            p.start()
            self.addCleanup(p.stop)
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

    def test_each_load_replaces_the_old_rules_rather_than_adding_to_them(self):
        # Loading a table that already exists adds to it. If the text did not delete the old table
        # first, a device switched back on would stay cut off, because its old "drop everything"
        # rule would still be in the kernel. (Confirmed against the real nft tool on 21/11/26.)
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._tick()
        self.plan = {KID: {"off": False, "ips": set()}}
        self.e._tick()
        for text in self.loaded_rules():
            self.assertTrue(text.startswith("table inet quietnet\ndelete table inet quietnet\ntable inet quietnet {"), text)
        self.assertNotIn("drop", self.loaded_rules()[-1])

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
        # Each command waits for the firewall lock (-w 5), the chain and the jump to it are checked
        # every tick, and the rules themselves are loaded once.
        cmds = [args for args, _ in self.commands if "-S" not in args]
        w = ["iptables", "-w", "5"]
        self.assertEqual(cmds, [w + ["-N", "QUIETNET"], w + ["-C", "FORWARD", "-j", "QUIETNET"],
                                w + ["-F", "QUIETNET"],
                                w + ["-A", "QUIETNET", "-s", KID, "-d", "203.0.113.5", "-j", "DROP"],
                                w + ["-A", "QUIETNET", "-s", TV, "!", "-d", US, "-j", "DROP"],
                                w + ["-N", "QUIETNET"], w + ["-C", "FORWARD", "-j", "QUIETNET"]])

    def test_iptables_rules_are_loaded_again_if_a_command_failed(self):
        self.e.backend = "iptables"
        self.plan = {KID: {"off": True, "ips": set()}}
        failing = {"on": True}
        run = enforcer.subprocess.run

        def flaky(args, **kw):
            if failing["on"] and "-A" in args:
                self.commands.append((args, None))
                return Result(1, "Another app is currently holding the xtables lock")
            return run(args, **kw)
        with mock.patch.object(enforcer.subprocess, "run", flaky):
            self.e._tick()
            failing["on"] = False
            self.e._tick()
        appends = [args for args, _ in self.commands if "-A" in args]
        self.assertEqual(len(appends), 2)                        # tried again on the next tick
        self.assertIn("iptables update failed; will try again.", self.log)

    def test_the_iptables_jump_is_put_back_if_something_removed_it(self):
        self.e.backend = "iptables"
        self.plan = {KID: {"off": True, "ips": set()}}
        run = enforcer.subprocess.run

        def no_jump(args, **kw):
            if "-C" in args:
                self.commands.append((args, None))
                return Result(1)
            return run(args, **kw)
        with mock.patch.object(enforcer.subprocess, "run", no_jump):
            self.e._tick()
        self.assertIn(["iptables", "-w", "5", "-I", "FORWARD", "-j", "QUIETNET"], [a for a, _ in self.commands])


class Safety(EnforcerCase):
    """The checks that stop the enforcer cutting a device off by mistake, and the hand-back paths."""

    def steer_kid(self):
        self.plan = {KID: {"off": False, "ips": set()}}
        self.e._tick()
        del self.sock.frames[:]

    def test_a_device_leaving_the_plan_is_handed_back_at_once(self):
        self.steer_kid()
        self.plan = {}
        self.e._tick()
        self.assertEqual({claims(f) for f in self.sock.frames}, {(KID_MAC, GATEWAY, GATEWAY_MAC)})

    def test_hand_back_messages_are_sent_from_our_own_hardware_address(self):
        # Switches and Wi-Fi ignore or mis-learn frames that claim to come from another machine.
        self.steer_kid()
        self.plan = {}
        self.e._tick()
        self.assertTrue(self.sock.frames)
        for f in self.sock.frames:
            self.assertEqual(f[6:12], enforcer.mac_to_bytes(OUR_MAC))

    def test_nothing_is_steered_when_this_machine_will_not_pass_traffic_on(self):
        with mock.patch.object(enforcer, "sysctl_set", lambda key, value: False):
            self.plan = {KID: {"off": False, "ips": set()}}
            self.e._tick()
        self.assertEqual(self.sock.frames, [])
        self.assertIn("won't pass traffic on", self.e.status()["problem"])

    def test_nothing_is_steered_when_another_firewall_drops_passed_on_traffic(self):
        self.e._forward_blocker = lambda: "table 'filter'"
        self.plan = {KID: {"off": False, "ips": set()}}
        self.e._tick()
        self.assertEqual(self.sock.frames, [])
        self.assertIn("DOCKER-USER -i eth0 -o eth0 -j ACCEPT", self.e.status()["problem"])

    def test_steered_devices_are_handed_back_if_it_becomes_unsafe(self):
        self.steer_kid()
        self.e._forward_blocker = lambda: "table 'filter'"
        self.e._tick()
        self.assertEqual({claims(f) for f in self.sock.frames}, {(KID_MAC, GATEWAY, GATEWAY_MAC)})

    def test_the_router_and_addresses_off_the_home_network_are_never_steered(self):
        self.e.subnet = enforcer.ipaddress.IPv4Network("192.168.1.0/24")
        self.hosts["10.0.0.5"] = "cc:cc:cc:cc:cc:cc"
        self.plan = {GATEWAY: {"off": True, "ips": set()}, "10.0.0.5": {"off": True, "ips": set()},
                     "192.168.1.255": {"off": True, "ips": set()}}
        self.e._tick()
        self.assertEqual(self.sock.frames, [])

    def test_a_device_that_now_has_someone_elses_address_is_left_alone_and_reported(self):
        self.plan = {KID: {"off": True, "ips": set(), "mac": "bb:bb:bb:bb:bb:bb"}}
        self.e._tick()
        self.assertEqual(self.sock.frames, [])
        self.assertIn("different device", self.e.status()["problems"][KID])

    def test_one_devices_problem_is_not_reported_for_another(self):
        self.plan = {KID: {"off": True, "ips": set(), "mac": "bb:bb:bb:bb:bb:bb"},
                     TV: {"off": True, "ips": set(), "mac": TV_MAC}}
        self.e._tick()
        status = self.e.status()
        self.assertEqual(set(status["problems"]), {KID})
        self.assertEqual(status["problem"], "")                         # nothing stops steering in general
        self.assertEqual([claims(f)[0] for f in self.sock.frames], [TV_MAC])

    def test_a_chosen_devices_hardware_address_is_learned_the_first_time_it_is_seen(self):
        learned = []
        self.e.learn_mac = lambda ip, mac: learned.append((ip, mac))
        self.plan = {KID: {"off": False, "ips": set(), "mac": ""}}
        self.e._tick()
        self.assertEqual(learned, [(KID, KID_MAC)])

    def test_if_the_routers_address_is_unknown_devices_stay_listed_and_keep_their_internet(self):
        self.steer_kid()
        del self.hosts[GATEWAY]
        self.plan = {}
        self.e._tick()
        self.assertIn(KID, self.e._spoofed)                              # still owed a hand-back
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "1")        # so it isn't cut off meanwhile
        self.hosts[GATEWAY] = GATEWAY_MAC
        self.e._tick()
        self.assertEqual(self.e._spoofed, {})
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "0")

    def test_a_late_answer_is_not_sent_to_a_device_already_handed_back(self):
        self.steer_kid()
        reply = enforcer.build_arp_reply(GATEWAY, OUR_MAC, KID, KID_MAC)
        self.plan = {}
        self.e._tick()
        del self.sock.frames[:]
        self.e._resteer(KID, KID_MAC, reply)
        self.assertEqual(self.sock.frames, [])


def router_question(asker_ip, asker_mac, about=GATEWAY):
    """An ARP frame asking 'who has <about>?', as a device sends it."""
    mac = enforcer.mac_to_bytes(asker_mac)
    return (b"\xff" * 6 + mac + b"\x08\x06" + enforcer.struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
            + mac + socket.inet_aton(asker_ip) + bytes(6) + socket.inet_aton(about))


class AnsweringQuestions(EnforcerCase):
    """Answering a steered device's 'who is the router?' so it doesn't slip back to the real one."""

    def test_a_steered_device_asking_for_the_router_gets_answers_planned(self):
        self.e._spoofed = {KID: KID_MAC}
        frames = [router_question(KID, KID_MAC), router_question(TV, TV_MAC)]   # TV isn't steered

        def recv(n):
            if frames:
                return frames.pop(0)
            raise OSError("closed")
        self.sock.recv, self.sock.settimeout = recv, lambda t: None
        with mock.patch.object(self.e, "_schedule_answers") as plan:
            self.e._answer_questions()
        plan.assert_called_once_with(KID, KID_MAC)

    def test_the_router_asking_about_a_steered_device_gets_it_steered_again(self):
        self.e._spoofed = {KID: KID_MAC}
        frames = [router_question(GATEWAY, GATEWAY_MAC, about=KID), router_question(GATEWAY, GATEWAY_MAC, about=TV)]

        def recv(n):
            if frames:
                return frames.pop(0)
            raise OSError("closed")
        self.sock.recv, self.sock.settimeout = recv, lambda t: None
        with mock.patch.object(self.e, "_schedule_answers") as plan:
            self.e._answer_questions()
        plan.assert_called_once_with(KID, KID_MAC)                      # not the TV, which isn't steered

    def test_a_flood_of_questions_costs_one_entry_and_one_thread(self):
        self.e._spoofed = {KID: KID_MAC}
        self.e._stop.set()                       # so the sending thread ends at once
        before = threading.active_count()
        for _ in range(3000):
            self.e._schedule_answers(KID, KID_MAC)
        self.assertEqual(list(self.e._pending), [KID])
        self.assertLessEqual(threading.active_count() - before, 1)

    def test_planned_answers_go_out_and_then_stop(self):
        self.e._spoofed = {KID: KID_MAC}
        clock = [100.0]
        with mock.patch.object(enforcer.time, "monotonic", lambda: clock[0]):
            self.e._pending = {KID: (KID_MAC, [100.0 + d for d in self.e.ANSWER_AT])}
            real_sleep = []
            with mock.patch.object(enforcer.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + 0.5) or real_sleep.append(s)):
                self.e._send_answers()
        self.assertEqual(len(self.sock.frames), len(self.e.ANSWER_AT))
        self.assertEqual({claims(f) for f in self.sock.frames}, {(KID_MAC, GATEWAY, OUR_MAC)})
        self.assertEqual(self.e._pending, {})


class FirewallCheckFailures(EnforcerCase):
    """When the other firewalls can't be seen, it doesn't steer."""

    def test_a_listing_that_fails_counts_as_a_blocker(self):
        real = enforcer.subprocess.run

        def run(args, **kw):
            if args[:2] == ["nft", "list"]:
                return Result(1, "Error: unknown expression")
            return real(args, **kw)
        with mock.patch.object(enforcer.subprocess, "run", run):
            self.plan = {KID: {"off": False, "ips": set()}}
            self.e._tick()
        self.assertEqual(self.sock.frames, [])
        self.assertIn("couldn't list", self.e.status()["problem"])

    def test_an_old_firewall_that_is_not_loaded_at_all_is_not_a_blocker(self):
        real = enforcer.subprocess.run

        def run(args, **kw):
            if args[0] == "iptables-legacy":
                return Result(3, "iptables v1.8: can't initialize iptables table `filter': Table does not exist")
            return real(args, **kw)
        with mock.patch.object(enforcer.subprocess, "run", run), \
                mock.patch.object(enforcer.shutil, "which", lambda t: "/usr/sbin/" + t):
            self.assertEqual(self.e._forward_blocker(), "")

    def test_iptables_rules_are_loaded_again_after_something_flushed_them(self):
        self.e.backend = "iptables"
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._tick()
        real = enforcer.subprocess.run

        def flushed(args, **kw):                 # the jump has gone: someone ran 'iptables -F'
            if "-C" in args:
                self.commands.append((args, None))
                return Result(1)
            return real(args, **kw)
        with mock.patch.object(enforcer.subprocess, "run", flushed):
            self.e._tick()
        appends = [a for a, _ in self.commands if "-A" in a]
        self.assertEqual(len(appends), 2)        # loaded once, then again after the flush


class StartingUnavailable(EnforcerCase):
    """What happens when the enforcer can't run at start-up."""

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.e.state_path = os.path.join(self.tmp.name, "enforcer_state.json")

    def notes(self, spoofed):
        with open(self.e.state_path, "w") as f:
            json.dump({"sysctls": {"net.ipv4.ip_forward": "0"}, "spoofed": spoofed}, f)
        self.sysctl["net.ipv4.ip_forward"] = "1"

    def test_a_crashed_runs_leftovers_are_tidied_even_when_it_cannot_start(self):
        self.notes({})
        self.e._recover_without_steering()
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "0")
        self.assertFalse(os.path.exists(self.e.state_path))
        self.assertIn((["nft", "delete", "table", "inet", "quietnet"], None), self.commands)

    def test_forwarding_is_kept_on_if_steered_devices_cannot_be_handed_back(self):
        self.notes({KID: KID_MAC})
        self.e._recover_without_steering()
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "1")      # they keep their internet meanwhile
        self.assertTrue(os.path.exists(self.e.state_path))             # and the next start can finish

    def test_it_starts_by_itself_once_the_network_appears(self):
        self.e.iface = self.e.gateway_ip = None
        waits = iter([False, True])
        started = []
        with mock.patch.object(self.e._stop, "wait", lambda t: next(waits)), \
                mock.patch.object(enforcer, "IS_LINUX", True), \
                mock.patch.object(enforcer, "AF_PACKET", 17), \
                mock.patch.object(enforcer.os, "geteuid", lambda: 0, create=True), \
                mock.patch.object(enforcer.threading, "Thread",
                                  lambda target, daemon: mock.Mock(start=lambda: started.append(target))):
            self.e._wait_for_network()
        self.assertEqual(started, [self.e._run])
        self.assertTrue(self.e.available())


class CrashRecovery(EnforcerCase):
    """Notes on disk let the next start undo what a killed or crashed run left behind."""

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.e.state_path = os.path.join(self.tmp.name, "enforcer_state.json")

    def fresh(self):
        e = enforcer.Enforcer(US, dict, lambda: self.hosts, log=self.log.append, data_dir=self.tmp.name)
        e.iface, e.gateway_ip, e.our_mac, e.backend, e.reason = "eth0", GATEWAY, OUR_MAC, "nft", ""
        e._sock = FakeSocket()
        return e

    def test_steering_is_written_down_while_it_happens(self):
        self.plan = {KID: {"off": False, "ips": set()}}
        self.e._tick()
        with open(self.e.state_path) as f:
            notes = json.load(f)
        self.assertEqual(notes["spoofed"], {KID: KID_MAC})
        self.assertEqual(notes["sysctls"]["net.ipv4.ip_forward"], "0")

    def test_the_next_start_hands_devices_back_and_restores_settings(self):
        self.plan = {KID: {"off": False, "ips": set()}}
        self.e._tick()                                    # ...and then the program is killed
        e = self.fresh()
        e._recover()
        self.assertEqual({claims(f) for f in e._sock.frames}, {(KID_MAC, GATEWAY, GATEWAY_MAC)})
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "0")
        self.assertFalse(os.path.exists(self.e.state_path))

    def test_the_notes_are_removed_once_everything_is_restored(self):
        self.plan = {KID: {"off": False, "ips": set()}}
        self.e._tick()
        self.e._teardown()
        self.assertFalse(os.path.exists(self.e.state_path))

    def test_a_stop_that_cannot_hand_devices_back_keeps_the_notes(self):
        self.plan = {KID: {"off": False, "ips": set()}}
        self.e._tick()
        del self.hosts[GATEWAY]
        self.e._teardown()
        self.assertTrue(os.path.exists(self.e.state_path))
        self.assertEqual(self.sysctl["net.ipv4.ip_forward"], "1")       # left on so the device keeps working


class FirewallChecks(unittest.TestCase):
    """Spotting another firewall that would drop the traffic we pass on."""

    DOCKER = ("table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n"
              "\t\tcounter packets 0 bytes 0 jump DOCKER-USER\n\t}\n\tchain DOCKER-USER {\n\t}\n}\n")

    def test_dockers_drop_policy_is_spotted(self):
        self.assertEqual(enforcer.foreign_forward_drop(self.DOCKER, "eth0"), "filter")

    def test_following_our_advice_clears_it(self):
        fixed = self.DOCKER.replace("chain DOCKER-USER {\n",
                                    'chain DOCKER-USER {\n\t\tiifname "eth0" oifname "eth0" counter packets 0 bytes 0 accept\n')
        self.assertEqual(enforcer.foreign_forward_drop(fixed, "eth0"), "")

    def test_a_chain_that_ends_by_rejecting_is_spotted(self):
        firewalld = ("table inet firewalld {\n\tchain filter_FORWARD {\n"
                     "\t\ttype filter hook forward priority filter + 10; policy accept;\n"
                     "\t\tct state established,related accept\n\t\treject with icmpx admin-prohibited\n\t}\n}\n")
        self.assertEqual(enforcer.foreign_forward_drop(firewalld, "eth0"), "firewalld")

    def test_our_own_table_does_not_count(self):
        ours = enforcer.nft_ruleset({KID: {"off": True, "ips": set()}}, US).replace("policy accept", "policy drop")
        self.assertEqual(enforcer.foreign_forward_drop(ours, "eth0"), "")

    def test_the_older_tools_drop_policy_is_spotted(self):
        self.assertTrue(enforcer.iptables_forward_drop("-P INPUT ACCEPT\n-P FORWARD DROP\n", "eth0"))
        self.assertFalse(enforcer.iptables_forward_drop("-P FORWARD DROP\n-A DOCKER-USER -i eth0 -o eth0 -j ACCEPT\n", "eth0"))
        self.assertFalse(enforcer.iptables_forward_drop("-P FORWARD ACCEPT\n", "eth0"))


class Helpers(unittest.TestCase):
    """The small pure functions added for safety."""

    def test_only_ordinary_devices_on_the_home_network_may_be_steered(self):
        net = enforcer.ipaddress.IPv4Network("192.168.1.0/24")
        self.assertEqual(enforcer.target_problem(KID, net, GATEWAY, US), "")
        for bad in ("999.1.1.1", GATEWAY, US, "192.168.1.0", "192.168.1.255", "10.0.0.5", "127.0.0.1",
                    "224.0.0.1", "169.254.1.1", "nonsense"):
            self.assertNotEqual(enforcer.target_problem(bad, net, GATEWAY, US), "", bad)

    def test_who_is_the_router_questions_are_recognised(self):
        mac = enforcer.mac_to_bytes(KID_MAC)
        req = (b"\xff" * 6 + mac + b"\x08\x06" + enforcer.struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
               + mac + socket.inet_aton(KID) + bytes(6) + socket.inet_aton(GATEWAY))
        self.assertEqual(enforcer.parse_arp_request(req), (KID, KID_MAC, GATEWAY))
        self.assertIsNone(enforcer.parse_arp_request(enforcer.build_arp_reply(GATEWAY, OUR_MAC, KID, KID_MAC)))
        self.assertIsNone(enforcer.parse_arp_request(b"short"))

    def test_kernel_settings_are_found_in_proc_even_for_interfaces_with_dots(self):
        self.assertEqual(enforcer._proc_path("net.ipv4.ip_forward"), "/proc/sys/net/ipv4/ip_forward")
        self.assertEqual(enforcer._proc_path("net.ipv4.conf.eth0.10.send_redirects"),
                         "/proc/sys/net/ipv4/conf/eth0.10/send_redirects")

    def test_the_home_network_is_read_from_the_routing_table(self):
        with mock.patch.object(enforcer, "open", mock.mock_open(read_data=SystemFacts.ROUTES), create=True):
            self.assertEqual(str(enforcer.local_subnet("eth0")), "192.168.1.0/24")
            self.assertIsNone(enforcer.local_subnet("wlan0"))


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

    def test_a_poke_runs_the_next_tick_at_once(self):
        # So the kill switch bites straight away instead of up to two seconds later.
        ticks = []
        self.e._open_socket = lambda: self.sock
        self.e._tick = lambda: ticks.append(1)
        self.e._answer_questions = lambda: None
        self.e.start()
        self.addCleanup(self.e.stop)
        time.sleep(0.2)
        self.e.poke()
        deadline = time.time() + 1
        while not ticks and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(ticks, "the poke did not cause a tick within a second")

    def test_stop_waits_until_the_network_has_been_restored(self):
        # stop() must not return while devices are still pointed at us, or the program
        # could exit first and leave the firewall table and kernel settings behind.
        self.plan = {KID: {"off": True, "ips": set()}}
        self.e._open_socket = lambda: self.sock
        self.e.start()
        self.assertTrue(self.e._thread.is_alive())
        self.e.stop()
        self.assertFalse(self.e._thread.is_alive())
        self.assertEqual(self.log[-1], "Enforcer stopped; network restored.")
        self.assertIn((["nft", "delete", "table", "inet", "quietnet"], None), self.commands)
        self.assertTrue(self.sock.closed)

    def test_stop_before_start_is_harmless(self):
        self.e.stop()
        self.assertEqual(self.commands, [])

    def test_iptables_teardown_removes_its_chain(self):
        self.e.backend = "iptables"
        self.e._teardown()
        cmds = [args for args, _ in self.commands]
        w = ["iptables", "-w", "5"]
        self.assertEqual(cmds, [w + ["-D", "FORWARD", "-j", "QUIETNET"], w + ["-F", "QUIETNET"],
                                w + ["-X", "QUIETNET"]])

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
                mock.patch.object(enforcer, "local_subnet", lambda iface: None), \
                mock.patch.object(enforcer.shutil, "which", lambda tool: "/usr/sbin/" + tool if tool in tools else None):
            return enforcer.Enforcer(US, dict, dict, log=lambda m: None)

    def test_ready_on_a_linux_box_with_admin_rights_and_a_firewall_tool(self):
        e = self.make()
        self.assertTrue(e.available())
        self.assertEqual(e.status(), {"available": True, "reason": "", "problem": "", "problems": {},
                                      "active": False, "backend": "nft", "gateway": GATEWAY})

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
