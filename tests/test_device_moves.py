"""Checks that a device's rules follow the device (its hardware address) when it changes address:
refresh_devices, the new-device group, and the "Move the rules to this device" notice in server.py.

Run with:  python3 -m unittest discover tests

Standard library only. The neighbour table is always a stand-in passed to refresh_devices (or
patched for the API), so nothing reads the real network.
"""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_quietnet import Base, server  # noqa: E402
from test_dashboard_api import Api  # noqa: E402

PI, ROUTER = "192.168.1.60", "192.168.1.254"
OLD, NEW, OTHER = "192.168.1.54", "192.168.1.71", "192.168.1.80"
PHONE = "00:11:22:33:44:01"          # an ordinary (maker's) hardware address
LAPTOP = "00:11:22:33:44:02"
PRIVATE = "da:11:22:33:44:03"         # a made-up private Wi-Fi address (second bit of the first byte set)
GUEST = "00:11:22:33:44:05"           # a visitor's device with an ordinary hardware address
TV = "00:11:22:33:44:06"
EXTENDER = "00:11:22:33:44:07"        # a range extender showing every device behind it with its own address
PI_MAC, ROUTER_MAC = "00:11:22:33:44:60", "00:11:22:33:44:fe"


def blocked_for(ip):
    """Is YouTube blocked for this device right now?"""
    return server.decision("youtube.com", ip)[0]


def fresh(mac):
    """A neighbour-table entry confirmed reachable just now."""
    return (mac, "fresh")


def stale(mac):
    """A neighbour-table entry the system has not confirmed for a while."""
    return (mac, "stale")


class Setup:
    """Shared steps: a quiet network with this computer, the router and nothing else."""

    def start_clean(self):
        for table in ("devices", "seen", "settings"):
            server.sql("DELETE FROM %s" % table, commit=True)
        server.init_db()
        saved = server.S.local_ip
        server.S.local_ip, server.S.router, server.S.router_checked = PI, ROUTER, float("inf")
        self.addCleanup(setattr, server.S, "local_ip", saved)
        self.addCleanup(setattr, server.S, "router", "")
        self.now = time.time()
        # The first look only records what is there; do it now so later devices count as new.
        self.look({})

    def look(self, table, later=0):
        """One round of refresh_devices with this neighbour table (plus this computer and the router)."""
        full = {PI: PI_MAC, ROUTER: ROUTER_MAC}
        full.update(table)
        server.refresh_devices(full, now=self.now + later)

    def give_rules(self, ip, name="Wilf's iPad"):
        """A name and a YouTube block for one address."""
        server.sql("INSERT OR REPLACE INTO devices(ip, name) VALUES(?,?)", (ip, name), commit=True)
        server.set_service_block("device:" + ip, "youtube", True)

    def name_of(self, ip):
        rows = server.sql("SELECT name FROM devices WHERE ip=?", (ip,))
        return rows[0][0] if rows else ""

    def events(self):
        return [t for (t,) in server.sql("SELECT text FROM events ORDER BY id")]

    def make_group(self, name, service=None):
        """A group, with one service blocked for it if given. Returns its id."""
        with server.db_lock:
            gid = server.db.execute("INSERT INTO groups(name) VALUES(?)", (name,)).lastrowid
            server.db.commit()
        server.S.group_names[gid] = name
        if service:
            server.set_service_block("group:%d" % gid, service, True)
        return gid

    def enforce(self, ip, mac):
        """Switch "cut live connections" on for this address, for this hardware address."""
        with server.db_lock:
            server.S.enforced.add(ip)
            server.S.enforced_mac[ip] = mac
            server.db.execute("INSERT OR REPLACE INTO enforced(ip, mac) VALUES(?,?)", (ip, mac))
            server.db.commit()


class FollowTheDevice(Base, Setup):
    def setUp(self):
        super().setUp()
        self.start_clean()

    def test_rules_move_with_a_known_device_to_a_new_free_address(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({NEW: PHONE}, later=60)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))
        self.assertEqual(self.name_of(NEW), "Wilf's iPad")
        self.assertEqual(self.name_of(OLD), "")

    def test_a_move_is_noted_in_plain_english(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({NEW: PHONE}, later=60)
        self.assertIn("Wilf's iPad moved from %s to %s; its rules moved with it." % (OLD, NEW), self.events())

    def test_group_and_schedule_move_with_the_device(self):
        with server.db_lock:
            gid = server.db.execute("INSERT INTO groups(name) VALUES('Kids')").lastrowid
            server.db.commit()
        server.S.group_names[gid] = "Kids"
        server.S.dev_group[OLD] = gid
        server.sql("INSERT INTO device_group VALUES(?,?)", (OLD, gid), commit=True)
        self.schedule(scope="device:" + OLD)
        self.look({OLD: PHONE})
        self.look({NEW: PHONE}, later=60)
        self.assertEqual(server.S.dev_group.get(NEW), gid)
        self.assertNotIn(OLD, server.S.dev_group)
        self.assertEqual([x["scope"] for x in server.S.schedules], ["device:" + NEW])

    def test_rules_are_not_merged_when_the_new_address_has_rules_of_its_own(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        server.set_internet_off("device:" + NEW, True)
        self.look({NEW: PHONE}, later=60)
        self.assertEqual(server.S.svc_blocks.get("device:" + OLD), {"youtube"})
        self.assertFalse(server.S.svc_blocks.get("device:" + NEW))
        self.assertIn("device:" + NEW, server.S.off)

    def test_both_devices_are_warned_when_rules_cannot_be_moved(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        server.set_internet_off("device:" + NEW, True)
        self.look({NEW: PHONE}, later=60)
        self.assertIn(NEW, server.S.device_warnings[OLD])
        self.assertIn(OLD, server.S.device_warnings[NEW])

    def test_rules_pause_when_a_different_device_takes_the_address(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: LAPTOP}, later=60)
        self.assertIn(OLD, server.S.paused_ips)
        self.assertFalse(blocked_for(OLD))
        self.assertEqual(server.S.svc_blocks.get("device:" + OLD), {"youtube"})    # kept, not deleted

    def test_a_paused_address_shows_why_on_its_page(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: LAPTOP}, later=60)
        self.assertEqual(server.S.device_warnings[OLD],
                         "This number now belongs to a different device; the rules for Wilf's iPad are paused "
                         "until it comes back.")

    def test_whole_house_rules_still_apply_to_a_paused_address(self):
        self.give_rules(OLD)
        server.set_service_block("all", "tiktok", True)
        self.look({OLD: PHONE})
        self.look({OLD: LAPTOP}, later=60)
        self.assertTrue(server.decision("tiktok.com", OLD)[0])

    def test_paused_rules_apply_again_when_the_device_comes_back(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: LAPTOP}, later=60)
        self.look({OLD: PHONE}, later=120)
        self.assertNotIn(OLD, server.S.paused_ips)
        self.assertTrue(blocked_for(OLD))

    def test_paused_rules_move_when_the_device_comes_back_at_another_address(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: LAPTOP}, later=60)
        self.look({OLD: LAPTOP, NEW: PHONE}, later=120)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))
        self.assertNotIn(NEW, server.S.paused_ips)
        self.assertNotIn(OLD, server.S.paused_ips)

    def test_a_pause_lasts_through_a_restart(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: LAPTOP}, later=60)
        server.init_db()
        self.assertIn(OLD, server.S.paused_ips)
        self.assertEqual(server.S.dev_mac[OLD], PHONE)

    def test_a_paused_address_is_not_steered(self):
        self.give_rules(OLD)
        with server.db_lock:
            server.S.enforced.add(OLD)
            server.S.enforced_mac[OLD] = PHONE
            server.db.execute("INSERT INTO enforced(ip, mac) VALUES(?,?)", (OLD, PHONE))
            server.db.commit()
        self.look({OLD: LAPTOP}, later=60)
        self.assertNotIn(OLD, server.enforcement_plan())

    def test_cut_live_connections_moves_with_the_device(self):
        self.give_rules(OLD)
        with server.db_lock:
            server.S.enforced.add(OLD)
            server.S.enforced_mac[OLD] = PHONE
            server.db.execute("INSERT INTO enforced(ip, mac) VALUES(?,?)", (OLD, PHONE))
            server.db.commit()
        self.look({OLD: PHONE})
        self.look({NEW: PHONE}, later=60)
        self.assertEqual(server.S.enforced, {NEW})
        self.assertEqual(server.S.enforced_mac, {NEW: PHONE})
        self.assertEqual(server.sql("SELECT ip, mac FROM enforced"), [(NEW, PHONE)])

    def test_memory_and_the_database_agree_after_a_move(self):
        self.give_rules(OLD)
        server.set_internet_off("device:" + OLD, True)
        self.look({OLD: PHONE})
        self.look({NEW: PHONE}, later=60)
        before = (dict(server.S.svc_blocks), set(server.S.off), dict(server.S.dev_group),
                  dict(server.S.dev_mac), set(server.S.paused_ips), set(server.S.enforced))
        server.init_db()                     # reload everything from the database
        after = (dict(server.S.svc_blocks), set(server.S.off), dict(server.S.dev_group),
                 dict(server.S.dev_mac), set(server.S.paused_ips), set(server.S.enforced))
        self.assertEqual(before, after)
        self.assertEqual(server.S.dev_mac, {NEW: PHONE})

    def test_this_computer_and_the_router_never_move(self):
        self.give_rules(ROUTER, "Router")
        with server.db_lock:
            server.set_owner(ROUTER, ROUTER_MAC)
            server.db.commit()
        # The router's hardware address turns up at another address (as when a second router or a
        # mesh point answers for it): its rules stay where they are.
        server.refresh_devices({PI: PI_MAC, ROUTER: LAPTOP, NEW: ROUTER_MAC}, now=self.now + 60)
        self.assertEqual(server.S.svc_blocks.get("device:" + ROUTER), {"youtube"})
        self.assertFalse(server.S.svc_blocks.get("device:" + NEW))
        self.assertNotIn(ROUTER, server.S.paused_ips)

    def test_rules_never_move_onto_this_computer(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        server.refresh_devices({PI: PHONE}, now=self.now + 60)
        self.assertEqual(server.S.svc_blocks.get("device:" + OLD), {"youtube"})
        self.assertFalse(server.S.svc_blocks.get("device:" + PI))

    def test_malformed_hardware_addresses_are_ignored(self):
        for bad in ("", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "(incomplete)",
                    "00:11:22:33:44", "zz:11:22:33:44:55", "00:11:22:33:44:55:66", None, 7):
            self.assertEqual(server.clean_mac(bad), "", bad)
        self.assertEqual(server.clean_mac("0:1B:2:33:44:5"), "00:1b:02:33:44:05")

    def test_a_malformed_hardware_address_does_not_pause_rules(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: "00:00:00:00:00:00"}, later=60)
        self.look({OLD: "ff:ff:ff:ff:ff:ff", "not an address": LAPTOP}, later=120)
        self.assertNotIn(OLD, server.S.paused_ips)
        self.assertTrue(blocked_for(OLD))

    def test_hardware_addresses_are_kept_in_lower_case(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE.upper()})
        self.assertEqual(server.S.dev_mac[OLD], PHONE)


class TrickyNetworks(Base, Setup):
    """Range extenders, stale neighbour entries, devices that swap addresses, and addresses left
    holding a departed device's name or group."""

    def setUp(self):
        super().setUp()
        self.start_clean()

    def test_rules_stay_with_an_address_whose_hardware_address_is_a_range_extender(self):
        self.give_rules(OLD)
        for minute in range(1, server.SHARED_AFTER + 1):
            self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=60 * minute)
        self.look({NEW: fresh(EXTENDER)}, later=600)
        self.assertTrue(blocked_for(OLD))
        self.assertFalse(blocked_for(NEW))
        self.assertNotIn(OLD, server.S.paused_ips)
        self.assertEqual(server.S.device_warnings[OLD], server.EXTENDER_OWNER)

    def test_a_device_seen_at_two_addresses_for_a_moment_is_not_taken_for_a_range_extender(self):
        self.give_rules(OLD)
        self.look({OLD: fresh(PHONE)})
        self.look({OLD: fresh(PHONE), NEW: fresh(PHONE)}, later=60)
        self.look({NEW: fresh(PHONE)}, later=120)
        self.assertEqual(server.S.shared_macs, set())
        self.assertTrue(blocked_for(NEW))

    def test_rules_are_not_paused_when_a_range_extender_answers_for_the_address(self):
        self.give_rules(OLD)
        self.look({OLD: fresh(PHONE)})
        for minute in range(1, server.SHARED_AFTER + 1):
            self.look({OTHER: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=60 * minute)
        self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=600)
        self.assertNotIn(OLD, server.S.paused_ips)
        self.assertTrue(blocked_for(OLD))
        self.assertIn("range extender", server.S.device_warnings[OLD])

    def test_a_range_extender_is_still_known_after_a_restart(self):
        for minute in range(1, server.SHARED_AFTER + 1):
            self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=60 * minute)
        server.init_db()
        self.assertEqual(server.S.shared_macs, {EXTENDER})

    def test_a_stale_entry_at_the_old_address_does_not_hold_the_rules_back(self):
        self.give_rules(OLD)
        self.look({OLD: fresh(PHONE)})
        self.look({OLD: stale(PHONE), NEW: fresh(PHONE)}, later=60)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))

    def test_each_device_keeps_its_own_rules_when_two_devices_swap_addresses(self):
        self.give_rules(OLD, "Kid phone")
        server.sql("INSERT INTO devices(ip, name) VALUES(?,?)", (NEW, "Dad laptop"), commit=True)
        server.set_service_block("device:" + NEW, "tiktok", True)
        self.look({OLD: PHONE, NEW: LAPTOP})
        self.look({OLD: LAPTOP, NEW: PHONE}, later=60)
        self.assertFalse(blocked_for(OLD))                          # Dad's laptop: no YouTube block
        self.assertTrue(server.decision("tiktok.com", OLD)[0])      # but its own TikTok block
        self.assertTrue(blocked_for(NEW))                           # the child's phone keeps its block
        self.assertFalse(server.decision("tiktok.com", NEW)[0])

    def test_both_devices_are_warned_when_two_devices_swap_addresses(self):
        self.give_rules(OLD, "Kid phone")
        server.set_service_block("device:" + NEW, "tiktok", True)
        self.look({OLD: PHONE, NEW: LAPTOP})
        self.look({OLD: LAPTOP, NEW: PHONE}, later=60)
        self.assertEqual(server.S.paused_ips, {OLD, NEW})
        self.assertIn(NEW, server.S.device_warnings[OLD])
        self.assertIn(OLD, server.S.device_warnings[NEW])

    def test_a_device_keeps_its_own_rules_at_an_address_with_rules_of_an_absent_device(self):
        self.give_rules(OLD)
        server.set_internet_off("device:" + NEW, True)
        self.look({OLD: PHONE, NEW: TV})
        self.look({NEW: PHONE}, later=60)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(server.decision("www.bbc.co.uk", NEW)[0])  # the TV's internet switch is not applied
        self.assertIn("device:" + NEW, server.S.off)                # but it is kept for the TV

    def test_live_cut_follows_a_device_whose_rules_could_not_be_moved(self):
        self.give_rules(OLD)
        self.enforce(OLD, PHONE)
        server.set_internet_off("device:" + NEW, True)
        self.look({OLD: PHONE, NEW: TV})
        self.look({NEW: PHONE}, later=60)
        with server.db_lock:
            self.assertEqual(server.live_cut_devices(), {NEW: PHONE})

    def test_rules_move_onto_an_address_that_only_has_the_name_of_a_device_not_here(self):
        self.give_rules(OLD)
        server.sql("INSERT INTO devices(ip, name) VALUES(?,?)", (NEW, "TV"), commit=True)
        self.look({OLD: PHONE, NEW: TV})
        self.look({NEW: PHONE}, later=60)
        self.assertTrue(blocked_for(NEW))
        self.assertEqual(self.name_of(NEW), "Wilf's iPad")
        self.assertNotIn(NEW, server.S.paused_ips)
        self.assertTrue(any("name or group that %s had before was replaced" % NEW in t for t in self.events()))

    def test_rules_move_onto_an_address_a_departed_guest_was_auto_grouped_at(self):
        visitors = self.make_group("Visitors")
        server.set_new_device_group(visitors)
        self.give_rules(OLD)
        self.look({OLD: PHONE, NEW: GUEST}, later=30)
        self.assertEqual(server.S.dev_group.get(NEW), visitors)
        self.look({NEW: PHONE}, later=60)
        self.assertTrue(blocked_for(NEW))
        self.assertNotIn(NEW, server.S.dev_group)                   # the visitors' group did not stick
        self.assertEqual(server.S.paused_ips, set())

    def test_a_new_visitor_at_a_departed_visitors_address_is_put_in_the_group(self):
        visitors = self.make_group("Visitors")
        server.set_new_device_group(visitors)
        self.look({NEW: GUEST}, later=30)
        self.look({NEW: PRIVATE}, later=600)
        self.assertEqual(server.S.dev_mac[NEW], PRIVATE)
        self.assertEqual(server.S.device_notices, [])

    def test_a_moved_device_without_a_group_leaves_none_at_its_new_address(self):
        gid = self.make_group("Visitors")
        with server.db_lock:
            server.S.dev_group[NEW] = gid
            server.db.execute("INSERT INTO device_group VALUES(?,?)", (NEW, gid))
            server.move_rules(OLD, NEW, PHONE)
        self.assertNotIn(NEW, server.S.dev_group)
        self.assertEqual(server.sql("SELECT * FROM device_group WHERE ip=?", (NEW,)), [])


class SameNumberNewAddress(Api, Setup):
    """A phone that makes up a new private Wi-Fi address and is given its old number back."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: PRIVATE}, later=60)

    def test_a_device_with_a_new_private_address_at_the_same_number_keeps_its_rules(self):
        self.assertNotIn(OLD, server.S.paused_ips)
        self.assertTrue(blocked_for(OLD))

    def test_the_owner_is_asked_whether_it_is_the_same_device(self):
        notices = self.get("/api/status")[1]["device_notices"]
        self.assertEqual([(n["from"], n["to"], n["same"]) for n in notices], [(OLD, OLD, True)])

    def test_saying_it_is_the_same_device_makes_the_rules_belong_to_it(self):
        self.neighbours_now = {OLD: PRIVATE}
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.assertEqual(server.S.dev_mac[OLD], PRIVATE)
        self.look({OLD: PRIVATE}, later=120)
        self.assertEqual(server.S.device_notices, [])
        self.assertTrue(blocked_for(OLD))

    def test_saying_it_is_a_different_device_pauses_the_rules(self):
        self.neighbours_now = {OLD: PRIVATE}
        self.ok("/api/different-device", {"ip": OLD})
        self.look({OLD: PRIVATE}, later=120)
        self.assertIn(OLD, server.S.paused_ips)
        self.assertFalse(blocked_for(OLD))
        self.assertEqual(server.S.device_notices, [])

    def test_saying_it_is_a_different_device_is_refused_for_the_device_the_rules_belong_to(self):
        self.neighbours_now = {OLD: PHONE}
        status, out = self.post("/api/different-device", {"ip": OLD})
        self.assertEqual(status, 400)
        self.assertIn("belong to", out["error"])

    def test_saying_it_is_a_different_device_refuses_anything_but_an_address(self):
        for body in ({}, {"ip": 5}, {"ip": "1; drop"}):
            self.assertEqual(self.post("/api/different-device", body)[0], 400, body)

    def test_a_paused_address_can_be_confirmed_as_the_same_device(self):
        self.look({OLD: LAPTOP}, later=120)                         # an ordinary address: paused
        self.assertIn(OLD, server.S.paused_ips)
        self.neighbours_now = {OLD: LAPTOP}
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.assertNotIn(OLD, server.S.paused_ips)
        self.assertTrue(blocked_for(OLD))


class PausedAddressNewcomer(Base, Setup):
    """A device never seen before that turns up at an address whose rules are paused."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OTHER: LAPTOP}, later=10)                       # a device already known, with no rules
        self.kids = self.make_group("Kids", "tiktok")
        server.set_new_device_group(self.kids)
        self.give_rules(OLD)
        self.look({OLD: PHONE}, later=20)

    def test_a_new_device_at_a_paused_address_gets_the_new_device_group(self):
        self.look({OLD: GUEST}, later=60)
        self.assertIn(OLD, server.S.paused_ips)
        self.assertTrue(server.decision("tiktok.com", OLD)[0])
        self.assertFalse(blocked_for(OLD))                          # the absent device's own rules stay paused

    def test_the_new_device_group_at_a_paused_address_lasts_through_a_restart(self):
        self.look({OLD: GUEST}, later=60)
        server.init_db()
        self.assertTrue(server.decision("tiktok.com", OLD)[0])

    def test_a_known_device_at_a_paused_address_gets_no_group(self):
        self.look({OLD: LAPTOP}, later=60)
        self.assertFalse(server.decision("tiktok.com", OLD)[0])

    def test_the_group_goes_when_the_new_device_leaves_and_a_known_one_arrives(self):
        self.look({OLD: GUEST, OTHER: LAPTOP}, later=60)
        self.look({OLD: LAPTOP}, later=120)
        self.assertFalse(server.decision("tiktok.com", OLD)[0])


class KnownHardwareAddresses(Base, Setup):
    """The record of every hardware address seen stays small."""

    def setUp(self):
        super().setUp()
        self.start_clean()

    def test_hardware_addresses_unseen_for_a_month_are_forgotten(self):
        self.look({NEW: LAPTOP})
        self.look({}, later=(server.KNOWN_MACS_DAYS + 1) * 86400)
        self.assertEqual(server.sql("SELECT mac FROM known_macs"), [])

    def test_the_record_keeps_only_the_most_recently_seen(self):
        with mock.patch.object(server, "MAX_KNOWN_MACS", 3):
            for i in range(6):
                self.look({"192.168.1.%d" % (100 + i): "00:11:22:33:55:%02x" % i}, later=i)
        self.assertEqual(sorted(m for (m,) in server.sql("SELECT mac FROM known_macs")),
                         ["00:11:22:33:55:03", "00:11:22:33:55:04", "00:11:22:33:55:05"])

    def test_a_hardware_address_that_rules_belong_to_is_never_forgotten(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({}, later=(server.KNOWN_MACS_DAYS + 1) * 86400)
        self.assertEqual(server.sql("SELECT mac FROM known_macs"), [(PHONE,)])

    def test_only_the_hardware_addresses_on_the_network_now_are_looked_up(self):
        self.look({NEW: LAPTOP})
        statements = []
        with server.db_lock:
            real = server.db
            server.db = mock.Mock(wraps=real)
            server.db.execute.side_effect = lambda q, *a: statements.append(q) or real.execute(q, *a)
            try:
                server.note_new_devices({NEW: LAPTOP}, {}, self.now + 60)
            finally:
                server.db = real
        self.assertNotIn("SELECT mac FROM known_macs", statements)
        self.assertTrue(any("WHERE mac IN" in q for q in statements))


class NeighbourTable(unittest.TestCase):
    """Reading the neighbour table, with stand-ins for the system's tools."""

    def test_the_neighbour_table_says_which_entries_are_fresh(self):
        text = ("192.168.1.54 dev wlan0 lladdr 00:11:22:33:44:01 STALE\n"
                "192.168.1.71 dev wlan0 lladdr 00:11:22:33:44:01 REACHABLE\n"
                "192.168.1.72 dev wlan0 lladdr 00:11:22:33:44:02 DELAY\n"
                "192.168.1.73 dev wlan0  FAILED\n"
                "192.168.1.74 dev wlan0 lladdr 00:11:22:33:44:04 FAILED\n")
        done = mock.Mock(stdout=text, returncode=0)
        with mock.patch.object(server.os.path, "exists", lambda p: p == "/proc/net/arp"), \
                mock.patch.object(server.subprocess, "run", return_value=done):
            found = server.neighbour_table()
        self.assertEqual(found, {"192.168.1.54": (PHONE, "stale"), "192.168.1.71": (PHONE, "fresh"),
                                 "192.168.1.72": (LAPTOP, "fresh")})


class NewDeviceGroup(Base, Setup):
    def setUp(self):
        super().setUp()
        self.start_clean()
        with server.db_lock:
            self.gid = server.db.execute("INSERT INTO groups(name) VALUES('Kids')").lastrowid
            server.db.commit()
        server.S.group_names[self.gid] = "Kids"

    def test_a_device_never_seen_before_goes_into_the_chosen_group(self):
        server.set_new_device_group(self.gid)
        self.look({NEW: PRIVATE}, later=60)
        self.assertEqual(server.S.dev_group.get(NEW), self.gid)
        self.assertEqual(server.sql("SELECT gid FROM device_group WHERE ip=?", (NEW,)), [(self.gid,)])
        self.assertTrue(any("put in the Kids group" in t for t in self.events()))

    def test_a_device_seen_before_is_not_put_in_the_group(self):
        self.look({NEW: PRIVATE}, later=30)
        server.set_new_device_group(self.gid)
        self.look({NEW: PRIVATE}, later=60)
        self.assertNotIn(NEW, server.S.dev_group)

    def test_no_group_is_given_when_none_is_chosen(self):
        self.look({NEW: PRIVATE}, later=60)
        self.assertNotIn(NEW, server.S.dev_group)

    def test_the_first_look_puts_nobody_in_the_group(self):
        server.sql("DELETE FROM known_macs", commit=True)
        server.sql("DELETE FROM settings", commit=True)
        server.set_new_device_group(self.gid)
        self.look({NEW: PRIVATE, OTHER: LAPTOP}, later=60)
        self.assertEqual(server.S.dev_group, {})

    def test_deleting_the_group_clears_the_setting(self):
        server.set_new_device_group(self.gid)
        server.delete_group(self.gid)
        self.assertIsNone(server.S.new_device_group)
        server.init_db()
        self.assertIsNone(server.S.new_device_group)


class MoveNotice(Api, Setup):
    def setUp(self):
        super().setUp()
        self.start_clean()

    def quiet_then_new(self):
        """Wilf's iPad (rules at OLD) is last seen, then goes quiet; a new private address appears."""
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({NEW: PRIVATE}, later=server.QUIET_AFTER + 120)

    def test_a_notice_appears_when_a_device_with_rules_goes_quiet_and_a_new_private_device_appears(self):
        self.quiet_then_new()
        status, out = self.get("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual([(n["from"], n["name"], n["to"]) for n in out["device_notices"]],
                         [(OLD, "Wilf's iPad", NEW)])

    def test_no_notice_while_the_device_with_rules_is_still_seen(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: PHONE, NEW: PRIVATE}, later=server.QUIET_AFTER + 120)
        self.assertEqual(self.get("/api/status")[1]["device_notices"], [])

    def test_move_the_rules_moves_them_through_the_api(self):
        self.quiet_then_new()
        self.neighbours_now = {NEW: PRIVATE}
        self.ok("/api/move-rules", {"from": OLD, "to": NEW})
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))
        self.assertEqual(server.S.dev_mac, {NEW: PRIVATE})
        self.assertEqual(self.get("/api/status")[1]["device_notices"], [])
        devices = {d["ip"]: d for d in self.get("/api/devices")[1]}
        self.assertEqual(devices[NEW]["name"], "Wilf's iPad")

    def test_move_the_rules_is_refused_when_the_new_device_has_rules(self):
        self.quiet_then_new()
        server.set_internet_off("device:" + NEW, True)
        status, out = self.post("/api/move-rules", {"from": OLD, "to": NEW})
        self.assertEqual(status, 400)
        self.assertIn("already has rules", out["error"])
        self.assertTrue(blocked_for(OLD))

    def test_move_the_rules_refuses_anything_but_two_addresses(self):
        for body in ({"from": OLD}, {"from": OLD, "to": 5}, {"from": "1; drop", "to": NEW},
                     {"from": OLD, "to": OLD}, {"from": OLD, "to": PI}, {"from": OLD, "to": ROUTER}):
            self.assertEqual(self.post("/api/move-rules", body)[0], 400, body)

    def test_a_paused_device_is_marked_in_the_device_list(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({OLD: LAPTOP}, later=60)
        d = {d["ip"]: d for d in self.get("/api/devices")[1]}[OLD]
        self.assertTrue(d["paused"])
        self.assertIn("paused", d["warning"])

    def test_the_new_device_group_is_saved_through_the_api(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.assertEqual(self.ok("/api/new-device-group", {"group": gid})["group"], gid)
        self.assertEqual(self.get("/api/status")[1]["new_device_group"], gid)

    def test_an_unknown_new_device_group_counts_as_none(self):
        for value in (999, "1", True, None, [1]):
            self.assertIsNone(self.ok("/api/new-device-group", {"group": value})["group"], value)

    def test_device_notes_are_listed_in_the_status_summary(self):
        self.give_rules(OLD)
        self.look({OLD: PHONE})
        self.look({NEW: PHONE}, later=60)
        texts = [e["text"] for e in self.get("/api/status")[1]["device_events"]]
        self.assertIn("Wilf's iPad moved from %s to %s; its rules moved with it." % (OLD, NEW), texts)


class DecisionStaysFast(unittest.TestCase):
    def test_decision_never_touches_the_database(self):
        with mock.patch.object(server, "sql", side_effect=AssertionError("database used")), \
                mock.patch.object(server, "db", None):
            server.S.paused_ips = {OLD}
            try:
                server.decision("youtube.com", OLD)
            finally:
                server.S.paused_ips = set()


if __name__ == "__main__":
    unittest.main()
