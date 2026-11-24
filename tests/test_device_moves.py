"""Checks that a device's name, group and rules are held against the device (its hardware address),
whatever address it has: whose rules a lookup from each address gets (S.addr_rules), a device that
may be another one with a new hardware address, what a DHCP request changes, where the enforcer
steers, the one-off move of an older household's rules to the devices, and the safeguard kept on a
database that has not been moved yet.

Run with:  python3 -m unittest discover tests

Standard library only. The neighbour table is always a stand-in passed to the looks (or patched
for the API and the enforcer's plan), so nothing reads the real network.
"""
import os
import sqlite3
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_quietnet import Base, server, query, fake_answer  # noqa: E402
from test_dashboard_api import Api  # noqa: E402
import test_devices as older  # noqa: E402  (the older household's addresses and hardware addresses)
from test_devices import OlderHousehold, drain  # noqa: E402

PI, ROUTER = "192.168.1.60", "192.168.1.254"
OLD, NEW, OTHER = "192.168.1.54", "192.168.1.71", "192.168.1.80"
PHONE = "00:11:22:33:44:01"          # an ordinary (maker's) hardware address
LAPTOP = "00:11:22:33:44:02"
PRIVATE = "da:11:22:33:44:03"         # a made-up private Wi-Fi address (second bit of the first byte set)
PRIVATE_TOO = "da:11:22:33:44:04"
GUEST = "00:11:22:33:44:05"           # a visitor's device with an ordinary hardware address
TV = "00:11:22:33:44:06"
EXTENDER = "00:11:22:33:44:07"        # a range extender showing every device behind it with its own address
PI_MAC, ROUTER_MAC = "00:11:22:33:44:60", "00:11:22:33:44:fe"
V6_A, V6_B = "2a00:23c8:1:2::a", "fe80::1c2d:3e4f"


def blocked_for(ip, name="youtube.com"):
    """Is this name blocked for a lookup from this address right now?"""
    return server.decision(name, ip)[0]


def answered_blocked(ip, name="www.youtube.com"):
    """Does a real lookup from this address get the blocked answer?"""
    return server.answer_query(query(name), ip, fake_answer)[-4:] == bytes(4)


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
        server.rebuild_address_map()
        server.rebuild_rule_map()
        self.now = time.time()
        # The first look only records what is there; do it now so later devices count as new.
        self.look({})
        drain()

    def look(self, table, later=0):
        """The minute's look (refresh_devices) at this neighbour table, plus this computer and the router."""
        full = {PI: PI_MAC, ROUTER: ROUTER_MAC}
        full.update(table)
        server.refresh_devices(full, now=self.now + later)

    def look6(self, table, later=0):
        """One look at this IPv6 neighbour table."""
        server.note_ipv6_addresses(table, now=self.now + later)

    def number(self, mac):
        """The number of the device with this hardware address."""
        return server.S.hw_device[mac]

    def give_rules(self, mac, name="Wilf's iPad", service="youtube"):
        """A name and a blocked service for the device with this hardware address. Returns its number."""
        number = self.number(mac)
        server.set_device_name(number, name)
        self.assertTrue(server.set_service_block("dev:%d" % number, service, True))
        return number

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

    def plan(self, table):
        """The enforcer's plan with this (stand-in) neighbour table as the live one."""
        full = {PI: fresh(PI_MAC), ROUTER: fresh(ROUTER_MAC)}
        full.update(table)
        with mock.patch.object(server, "neighbour_table", return_value=full):
            return server.enforcement_plan()

    def notices(self):
        return [(n["from"], n["to"], n["same"]) for n in server.S.device_notices]


class RulesStayWithTheDevice(Base, Setup):
    """Nothing is moved when a device changes address: its rules are held against the device."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: PHONE})
        self.phone = self.give_rules(PHONE)

    def test_rules_stay_with_a_known_device_at_a_new_address(self):
        self.look({NEW: PHONE}, later=60)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))
        self.assertEqual(server.S.given[self.phone], "Wilf's iPad")

    def test_nothing_is_moved_or_noted_when_a_device_changes_address(self):
        before = (dict(server.S.svc_blocks), server.sql("SELECT scope, service FROM service_blocks"))
        self.look({NEW: PHONE}, later=60)
        self.assertEqual((dict(server.S.svc_blocks), server.sql("SELECT scope, service FROM service_blocks")), before)
        self.assertEqual(self.events(), [])

    def test_a_devices_rules_apply_at_every_address_it_has(self):
        self.look6({V6_A: fresh(PHONE), V6_B: stale(PHONE)})
        for address in (OLD, V6_A, V6_B):
            self.assertTrue(answered_blocked(address), address)

    def test_a_lookup_over_ipv6_gets_the_devices_rules_even_if_it_was_never_seen_over_ipv4(self):
        self.look6({V6_A: fresh(TV)})
        server.set_internet_off("dev:%d" % self.number(TV), True)
        self.assertTrue(answered_blocked(V6_A, "www.bbc.co.uk"))

    def test_group_and_schedule_stay_with_the_device(self):
        gid = self.make_group("Kids", "tiktok")
        server.set_device_group(self.phone, gid)
        self.schedule(scope="dev:%d" % self.phone)
        self.look({NEW: PHONE}, later=60)
        self.assertEqual(server.S.dev_group, {self.phone: gid})
        self.assertEqual([x["scope"] for x in server.S.schedules], ["dev:%d" % self.phone])
        self.assertTrue(blocked_for(NEW, "tiktok.com"))

    def test_a_device_arriving_at_an_address_another_device_had_keeps_only_its_own_rules(self):
        self.look({OLD: PHONE, NEW: TV})
        server.set_internet_off("dev:%d" % self.number(TV), True)
        self.look({NEW: PHONE}, later=60)                           # the TV has gone; the phone is given its number
        self.assertTrue(blocked_for(NEW))                           # the phone's own block
        self.assertFalse(blocked_for(NEW, "www.bbc.co.uk"))         # not the TV's internet switch
        self.assertIn("dev:%d" % self.number(TV), server.S.off)     # which is kept for the TV

    def test_a_different_device_given_the_address_gets_none_of_the_rules(self):
        self.look({OLD: LAPTOP}, later=60)
        self.assertFalse(blocked_for(OLD))
        self.assertFalse(answered_blocked(OLD))

    def test_the_rules_are_kept_for_the_device_that_left(self):
        self.look({OLD: LAPTOP}, later=60)
        self.assertEqual(server.S.svc_blocks.get("dev:%d" % self.phone), {"youtube"})
        self.assertEqual(server.sql("SELECT scope, service FROM service_blocks"), [("dev:%d" % self.phone, "youtube")])

    def test_whole_house_rules_still_apply_to_the_device_now_at_the_address(self):
        server.set_service_block("all", "tiktok", True)
        self.look({OLD: LAPTOP}, later=60)
        self.assertTrue(blocked_for(OLD, "tiktok.com"))

    def test_the_rules_apply_again_when_the_device_comes_back(self):
        self.look({OLD: LAPTOP}, later=60)
        self.look({OLD: PHONE}, later=120)
        self.assertTrue(blocked_for(OLD))

    def test_the_rules_apply_when_the_device_comes_back_at_another_address(self):
        self.look({OLD: LAPTOP}, later=60)
        self.look({OLD: LAPTOP, NEW: PHONE}, later=120)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))

    def test_each_device_keeps_its_own_rules_when_two_devices_swap_addresses(self):
        self.look({OLD: PHONE, NEW: LAPTOP})
        self.give_rules(LAPTOP, "Dad laptop", "tiktok")
        self.look({OLD: LAPTOP, NEW: PHONE}, later=60)
        self.assertFalse(blocked_for(OLD))                          # Dad's laptop: no YouTube block
        self.assertTrue(blocked_for(OLD, "tiktok.com"))             # but its own TikTok block
        self.assertTrue(blocked_for(NEW))                           # the child's phone keeps its block
        self.assertFalse(blocked_for(NEW, "tiktok.com"))

    def test_rules_last_through_a_restart(self):
        server.init_db()
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % self.phone: {"youtube"}})
        self.assertEqual(server.S.given, {self.phone: "Wilf's iPad"})
        self.look({NEW: PHONE}, later=60)                           # the first look after the restart
        self.assertTrue(blocked_for(NEW))

    def test_after_a_restart_no_address_gets_a_devices_rules_until_a_look_has_been_taken(self):
        # Whose rules an address gets comes from the neighbour table alone, never from the record
        # of who used it (address_use), which is all a restart has to go by.
        server.init_db()
        self.assertEqual(server.sql("SELECT addr FROM address_use WHERE device=?", (self.phone,)), [(OLD,)])
        self.assertNotIn(OLD, server.S.addr_rules)
        self.assertFalse(blocked_for(OLD))

    def test_memory_and_the_database_agree_after_a_restart(self):
        gid = self.make_group("Kids")
        server.set_device_group(self.phone, gid)
        server.set_internet_off("dev:%d" % self.phone, True)
        server.set_live_cut(self.phone, True)
        self.look({NEW: PHONE}, later=60)
        before = (dict(server.S.svc_blocks), set(server.S.off), dict(server.S.dev_group), dict(server.S.given),
                  set(server.S.enforced), dict(server.S.enforced_mac))
        server.init_db()                     # reload everything from the database
        after = (dict(server.S.svc_blocks), set(server.S.off), dict(server.S.dev_group), dict(server.S.given),
                 set(server.S.enforced), dict(server.S.enforced_mac))
        self.assertEqual(before, after)

    def test_the_routers_rules_never_reach_a_household_device(self):
        server.set_service_block("device:" + ROUTER, "tiktok", True)
        self.assertEqual(server.S.svc_blocks.get("dev:%d" % server.S.hub_device), {"tiktok"})
        # The router's hardware address turns up at another address too (a mesh point answering for it).
        server.refresh_devices({PI: PI_MAC, ROUTER: ROUTER_MAC, NEW: ROUTER_MAC, OLD: PHONE}, now=self.now + 60)
        self.assertEqual((server.S.addr_rules[ROUTER], server.S.addr_rules[NEW]), (server.S.hub_device,) * 2)
        self.assertFalse(blocked_for(OLD, "tiktok.com"))
        # A new router takes the address: whatever has the old one's hardware address is an ordinary
        # device from then on, and gets none of the router's rules.
        server.refresh_devices({PI: PI_MAC, ROUTER: LAPTOP, NEW: ROUTER_MAC, OLD: PHONE}, now=self.now + 120)
        self.assertEqual(server.S.addr_rules[ROUTER], server.S.hub_device)
        self.assertFalse(blocked_for(NEW, "tiktok.com"))

    def test_a_household_devices_rules_never_reach_this_computer(self):
        server.refresh_devices({PI: PHONE, ROUTER: ROUTER_MAC}, now=self.now + 60)
        self.assertEqual(server.S.addr_rules[PI], server.S.pi_device)
        self.assertFalse(blocked_for(PI))

    def test_malformed_hardware_addresses_are_ignored(self):
        for bad in ("", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "(incomplete)",
                    "00:11:22:33:44", "zz:11:22:33:44:55", "00:11:22:33:44:55:66", None, 7):
            self.assertEqual(server.clean_mac(bad), "", bad)
        self.assertEqual(server.clean_mac("0:1B:2:33:44:5"), "00:1b:02:33:44:05")

    def test_a_malformed_hardware_address_does_not_take_the_rules_away(self):
        self.look({OLD: "00:00:00:00:00:00"}, later=60)
        self.look({OLD: "ff:ff:ff:ff:ff:ff", "not an address": LAPTOP}, later=120)
        self.assertTrue(blocked_for(OLD))

    def test_hardware_addresses_are_kept_in_lower_case(self):
        self.look({NEW: LAPTOP.upper()})
        self.assertIn(LAPTOP, server.S.hw_device)


class WhoseRulesALookupGets(Base, Setup):
    """S.addr_rules: wider than the record the history is filed by, so that an idle phone still
    gets its own rules, but never so wide that one device gets another's."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: fresh(PHONE)})
        self.phone = self.give_rules(PHONE)

    def test_a_phone_whose_entry_has_gone_stale_still_gets_its_rules(self):
        self.look({OLD: stale(PHONE)}, later=60)
        self.assertNotIn(OLD, server.S.addr_device)                 # not confirmed: its history waits
        self.assertTrue(blocked_for(OLD))                           # but its rules apply

    def test_a_phone_whose_entry_has_gone_altogether_still_gets_its_rules(self):
        self.look({}, later=60)
        self.assertTrue(blocked_for(OLD))
        self.look({OTHER: fresh(LAPTOP)}, later=120)
        self.assertTrue(blocked_for(OLD))

    def test_a_stale_entry_at_the_old_address_does_not_hold_the_rules_there(self):
        self.look({OLD: stale(PHONE), NEW: fresh(PHONE)}, later=60)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))

    def test_an_address_the_device_has_left_no_longer_gets_its_rules(self):
        self.look({NEW: fresh(PHONE)}, later=60)                    # no entry at the old address at all
        self.assertFalse(blocked_for(OLD))

    def test_an_address_stops_getting_the_rules_once_the_device_is_listed_elsewhere_even_stale(self):
        self.look({}, later=60)
        self.look({NEW: stale(PHONE)}, later=120)
        self.assertFalse(blocked_for(OLD))
        self.assertTrue(blocked_for(NEW))

    def test_a_stale_entry_for_a_hardware_address_never_seen_makes_no_device_and_gets_no_rules(self):
        self.look({NEW: stale(TV)}, later=60)
        self.assertNotIn(TV, server.S.hw_device)
        self.assertNotIn(NEW, server.S.addr_rules)

    def test_stale_entries_at_two_addresses_give_the_rules_only_to_the_one_it_was_last_confirmed_at(self):
        self.look({NEW: fresh(PHONE)}, later=60)
        self.look({OLD: stale(PHONE), NEW: stale(PHONE)}, later=120)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))

    def test_a_second_live_address_gets_no_rules_until_the_first_goes(self):
        self.look({OLD: fresh(PHONE), NEW: fresh(PHONE)}, later=60)
        self.assertTrue(blocked_for(OLD))
        self.assertFalse(blocked_for(NEW))                          # it may be another device behind an extender
        self.assertEqual(server.S.device_warnings[self.phone], server.UNSETTLED_WARNING)
        self.look({NEW: fresh(PHONE)}, later=120)
        self.assertTrue(blocked_for(NEW))

    def test_a_device_seen_at_two_addresses_for_a_moment_is_not_taken_for_a_range_extender(self):
        self.look({OLD: fresh(PHONE), NEW: fresh(PHONE)}, later=60)
        self.look({NEW: fresh(PHONE)}, later=120)
        self.assertEqual(server.S.shared_macs, set())

    def test_an_ipv6_address_of_a_hardware_address_at_two_live_addresses_gets_no_rules(self):
        self.look({OLD: fresh(PHONE), NEW: fresh(PHONE)}, later=60)
        self.look6({V6_A: fresh(PHONE)}, later=60)
        self.assertNotIn(V6_A, server.S.addr_rules)

    def test_the_map_is_swapped_whole_so_a_lookup_never_sees_it_half_made(self):
        before = server.S.addr_rules
        self.look({NEW: fresh(PHONE)}, later=60)
        self.assertIsNot(server.S.addr_rules, before)
        self.assertIn(OLD, before)                                  # the old one was left as it was

    def test_this_computers_own_addresses_always_get_this_computers_rules(self):
        server.S.v6_own = {"fd00::60"}
        self.addCleanup(setattr, server.S, "v6_own", set())
        server.rebuild_rule_map()
        for address in ("127.0.0.1", "::1", PI, "fd00::60"):
            self.assertEqual(server.S.addr_rules[address], server.S.pi_device, address)

    def test_a_lookup_from_an_address_no_device_is_known_for_gets_the_whole_houses_rules(self):
        server.set_service_block("all", "tiktok", True)
        self.assertEqual(server.scopes_for(OTHER), ["all"])
        self.assertTrue(answered_blocked(OTHER, "www.tiktok.com"))
        self.assertFalse(answered_blocked(OTHER))

    def test_a_lookup_finds_whose_rules_it_gets_without_touching_the_database(self):
        with mock.patch.object(server, "sql", side_effect=AssertionError("database used")), \
                mock.patch.object(server, "db", None), mock.patch.object(server, "read_db", None):
            self.assertTrue(answered_blocked(OLD))
        drain()

    def test_a_lookup_does_not_wait_for_the_lock_that_guards_the_map(self):
        with server.rule_map_lock, server.db_lock:
            done = []
            t = threading.Thread(target=lambda: done.append(answered_blocked(OLD)))
            t.start()
            t.join(5)
        self.assertEqual(done, [True])
        drain()

    def test_the_ipv6_look_gives_a_known_devices_new_address_its_rules_before_the_database_is_touched(self):
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbour_table", return_value={OLD: fresh(PHONE)}), \
                mock.patch.object(server, "ipv6_neighbour_table", return_value={V6_A: fresh(PHONE)}), \
                mock.patch.object(server, "db", None):
            server.refresh_ipv6_view()
        self.assertEqual(server.S.addr_rules[V6_A], self.phone)

    def test_an_ipv6_address_behind_a_range_extender_gets_no_devices_rules_from_the_look(self):
        with mock.patch.object(server.S, "shared_macs", {PHONE}):
            self.assertEqual(server.ipv6_rules({V6_A: fresh(PHONE)}), {})


class RangeExtenders(Base, Setup):
    def setUp(self):
        super().setUp()
        self.start_clean()

    def become_an_extender(self, table, start=1):
        """Look at this table until the hardware address at two addresses counts as a range extender."""
        for minute in range(start, start + server.SHARED_AFTER):
            self.look(table, later=60 * minute)
        self.assertEqual(server.S.shared_macs, {EXTENDER})

    def test_rules_stay_with_a_number_behind_a_range_extender(self):
        server.set_service_block("device:" + OLD, "youtube", True)  # held against the number: nothing else is known
        self.become_an_extender({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        self.assertTrue(blocked_for(OLD))
        self.assertFalse(blocked_for(NEW))
        self.assertEqual(server.S.device_warnings[server.S.addr_only[OLD]], server.EXTENDER_OWNER)
        self.look({NEW: fresh(EXTENDER)}, later=600)                # the device behind it at OLD goes quiet
        self.assertTrue(blocked_for(OLD))

    def test_rules_held_against_a_number_apply_while_the_extender_is_not_yet_known_to_be_one(self):
        server.set_service_block("device:" + OLD, "youtube", True)
        self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=60)
        self.assertEqual(server.S.shared_macs, set())
        self.assertTrue(blocked_for(OLD))
        self.assertFalse(blocked_for(NEW))

    def test_a_range_extender_is_still_known_after_a_restart(self):
        self.become_an_extender({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        server.init_db()
        self.assertEqual(server.S.shared_macs, {EXTENDER})

    def test_a_devices_rules_keep_applying_to_its_number_when_an_extender_starts_answering_for_it(self):
        self.look({OLD: fresh(PHONE)})
        phone = self.give_rules(PHONE)
        self.become_an_extender({OLD: fresh(PHONE), OTHER: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=600)      # the phone now connects through it
        self.assertTrue(blocked_for(OLD))
        self.assertEqual(server.S.provisional, {server.S.addr_only[OLD]: phone})
        self.assertIn("range extender", server.S.device_warnings[server.S.addr_only[OLD]])
        self.assertFalse(blocked_for(NEW))

    def test_that_stops_when_the_device_is_seen_away_from_the_extender(self):
        self.look({OLD: fresh(PHONE)})
        self.give_rules(PHONE)
        self.become_an_extender({OLD: fresh(PHONE), OTHER: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=600)
        self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER), OTHER: fresh(PHONE)}, later=660)
        self.assertEqual(server.S.provisional, {})
        self.assertFalse(blocked_for(OLD))                          # whoever is behind the extender at that number
        self.assertTrue(blocked_for(OTHER))                         # the phone itself

    def test_a_number_behind_an_extender_cannot_be_joined_to_another_device(self):
        self.look({OLD: fresh(PHONE)})
        phone = self.give_rules(PHONE)
        self.become_an_extender({OLD: fresh(PHONE), OTHER: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        self.look({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}, later=600)
        error = server.same_device_by_hand(server.S.addr_only[OLD], phone)
        self.assertIn("only by its number", error)
        self.assertTrue(blocked_for(OLD))

    def test_a_number_behind_an_extender_is_steered_only_on_its_own_switch(self):
        self.look({OLD: fresh(PHONE)})
        phone = self.give_rules(PHONE)
        server.set_live_cut(phone, True)
        self.become_an_extender({OLD: fresh(PHONE), OTHER: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        table = {OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)}
        self.look(table, later=600)                                 # the phone now connects through the extender
        self.assertTrue(server.live_cut_on(OLD))                    # its lookups still get no IPv6 addresses
        self.assertEqual(self.plan(table), {})                      # but QuietNet can't tell who is there: no steering
        server.set_live_cut(server.S.addr_only[NEW], True)
        self.assertEqual({ip: rule["mac"] for ip, rule in self.plan(table).items()}, {NEW: EXTENDER})

    def test_a_device_newly_shown_behind_an_extender_is_not_put_in_the_new_device_group(self):
        visitors = self.make_group("Visitors", "tiktok")
        server.set_new_device_group(visitors)
        self.become_an_extender({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        self.assertNotIn(server.S.addr_only[OLD], server.S.dev_group)
        self.assertFalse(blocked_for(OLD, "tiktok.com"))

    def test_an_extender_not_seen_sharing_for_a_month_is_forgotten(self):
        self.become_an_extender({OLD: fresh(EXTENDER), NEW: fresh(EXTENDER)})
        self.look({}, later=(server.KNOWN_MACS_DAYS + 1) * 86400)
        self.assertEqual(server.S.shared_macs, set())


class MayBeTheSameDevice(Api, Setup):
    """A phone that makes up a new private Wi-Fi address and is given its old number back: a new
    device, never merged automatically, but held to the old one's rules until the owner answers."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: PHONE})
        self.phone = self.give_rules(PHONE)
        self.look({OLD: PRIVATE}, later=60)
        self.newcomer = self.number(PRIVATE)

    def test_a_new_private_hardware_address_is_a_new_device_never_merged_automatically(self):
        self.assertNotEqual(self.newcomer, self.phone)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 2)

    def test_a_device_with_a_new_private_address_at_the_same_number_is_held_to_the_rules(self):
        self.assertEqual(server.S.provisional, {self.newcomer: self.phone})
        self.assertTrue(blocked_for(OLD))
        self.assertTrue(answered_blocked(OLD))

    def test_the_rules_follow_the_newcomer_to_another_address_until_the_owner_answers(self):
        self.look({NEW: PRIVATE}, later=120)
        self.assertTrue(blocked_for(NEW))

    def test_the_newcomers_own_rules_apply_as_well(self):
        server.set_service_block("dev:%d" % self.newcomer, "tiktok", True)
        self.assertEqual(server.scopes_for(OLD), ["all", "dev:%d" % self.newcomer, "dev:%d" % self.phone])
        self.assertTrue(blocked_for(OLD, "tiktok.com"))
        self.assertTrue(blocked_for(OLD))

    def test_the_other_devices_group_applies_to_the_newcomer_too(self):
        kids = self.make_group("Kids", "tiktok")
        server.set_device_group(self.phone, kids)
        self.assertTrue(blocked_for(OLD, "tiktok.com"))

    def test_the_owner_is_asked_whether_it_is_the_same_device(self):
        notices = self.get("/api/status")[1]["device_notices"]
        self.assertEqual([(n["from"], n["to"], n["same"], n["name"], n["from_device"], n["to_device"], n["held"])
                          for n in notices], [(OLD, OLD, True, "Wilf's iPad", self.phone, self.newcomer, False)])

    def test_the_follow_is_noted_in_plain_english(self):
        self.assertIn("A device with a new private Wi-Fi address now has the number %s, which Wilf's iPad had. It may "
                      "be the same device, so the rules for Wilf's iPad apply to it until you say." % OLD, self.events())

    def test_both_devices_say_so_on_their_pages(self):
        cards = {d["id"]: d for d in self.get("/api/devices?all=1")[1]}
        self.assertIn("may be the same device", cards[self.newcomer]["warning"])
        self.assertIn("may be this one", cards[self.phone]["warning"])

    def test_the_newcomers_controls_say_where_the_other_devices_rules_come_from(self):
        controls = self.get("/api/controls?scope=dev:%d" % self.newcomer)[1]
        self.assertEqual(controls["services"]["youtube"], {"on": False, "from": "for Wilf's iPad, which this device may be"})

    def test_the_follow_lasts_through_a_restart(self):
        server.init_db()
        self.assertEqual(server.S.provisional, {self.newcomer: self.phone})
        self.look({OLD: PRIVATE}, later=120)
        self.assertTrue(blocked_for(OLD))

    def test_saying_it_is_the_same_device_joins_the_two(self):
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.assertEqual(server.S.hw_device[PRIVATE], self.phone)
        self.assertEqual(server.sql("SELECT mac FROM device_hw WHERE device=? ORDER BY mac", (self.phone,)),
                         [(PHONE,), (PRIVATE,)])
        self.assertEqual(server.sql("SELECT id FROM device WHERE id=?", (self.newcomer,)), [])
        self.assertEqual(server.S.provisional, {})
        self.look({OLD: PRIVATE}, later=120)
        self.assertEqual(server.S.device_notices, [])
        self.assertTrue(blocked_for(OLD))

    def test_joining_is_noted_in_plain_english(self):
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.assertIn("You said the device at %s is the same device as Wilf's iPad, so they are now one device with "
                      "one set of rules." % OLD, self.events())

    def test_saying_it_is_the_same_device_by_the_two_numbers_joins_them(self):
        self.ok("/api/move-rules", {"from_device": self.phone, "to_device": self.newcomer})
        self.assertEqual(server.S.hw_device[PRIVATE], self.phone)

    def test_once_joined_the_device_keeps_its_rules_under_either_hardware_address(self):
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.look({NEW: PHONE}, later=120)
        self.assertTrue(blocked_for(NEW))
        self.look({OTHER: PRIVATE}, later=180)
        self.assertTrue(blocked_for(OTHER))

    def test_joining_gives_the_newcomers_history_to_the_device(self):
        server.sql("INSERT INTO queries(ts,client,domain,blocked,device) VALUES(?,?,?,0,?)",
                   (self.now, OLD, "new.example.com", self.newcomer), commit=True)
        server.sql("INSERT INTO queries(ts,client,domain,blocked,device) VALUES(?,?,?,0,?)",
                   (self.now - 600, OLD, "old.example.com", self.phone), commit=True)
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.assertEqual(server.sql("SELECT DISTINCT device FROM queries"), [(self.phone,)])

    def test_saying_it_is_a_different_device_stops_the_rules_applying_to_it(self):
        self.ok("/api/different-device", {"ip": OLD})
        self.assertFalse(blocked_for(OLD))
        self.assertEqual(server.S.device_notices, [])
        self.assertEqual(server.S.svc_blocks.get("dev:%d" % self.phone), {"youtube"})   # kept for the phone

    def test_once_answered_no_the_question_is_not_asked_again(self):
        self.ok("/api/different-device", {"device": self.newcomer})
        self.look({OLD: PRIVATE}, later=120)
        self.look({NEW: PRIVATE}, later=180)
        self.look({OLD: PRIVATE}, later=240)
        self.assertEqual((server.S.provisional, server.S.device_notices), ({}, []))
        server.init_db()
        self.assertIn((self.newcomer, self.phone), server.S.not_same)

    def test_a_newcomer_answered_no_goes_into_the_new_device_group(self):
        visitors = self.make_group("Visitors", "tiktok")
        server.set_new_device_group(visitors)
        self.assertNotIn(self.newcomer, server.S.dev_group)         # not while it may be the phone
        self.ok("/api/different-device", {"ip": OLD})
        self.assertEqual(server.S.dev_group.get(self.newcomer), visitors)
        self.assertTrue(blocked_for(OLD, "tiktok.com"))

    def test_the_question_answers_itself_when_the_first_device_is_seen_again_beside_the_newcomer(self):
        self.look({OLD: PRIVATE, NEW: PHONE}, later=120)
        self.assertEqual(server.S.provisional, {})
        self.assertFalse(blocked_for(OLD))
        self.assertTrue(blocked_for(NEW))
        self.assertTrue(any("is on the network again" in t for t in self.events()))

    def test_saying_it_is_a_different_device_is_refused_when_nothing_is_being_asked(self):
        self.ok("/api/different-device", {"ip": OLD})
        status, out = self.post("/api/different-device", {"ip": OLD})
        self.assertEqual(status, 400)
        self.assertIn("no rules here", out["error"])

    def test_saying_it_is_a_different_device_refuses_anything_but_a_device(self):
        for body in ({}, {"ip": 5}, {"ip": "1; drop"}, {"device": "x"}, {"device": [1]}):
            self.assertEqual(self.post("/api/different-device", body)[0], 400, body)

    def test_the_follow_ends_when_the_other_devices_rules_are_all_removed(self):
        server.set_service_block("dev:%d" % self.phone, "youtube", False)
        server.set_device_name(self.phone, "")
        self.look({OLD: PRIVATE}, later=120)
        self.assertEqual((server.S.provisional, server.S.device_notices), ({}, []))

    def test_both_devices_are_kept_while_the_question_is_open(self):
        server.set_device_name(self.phone, "")                       # nothing but the block keeps the phone
        server.forget_old_devices(now=self.now + 40 * 86400)
        self.assertIn(self.phone, server.S.device_kind)
        self.assertIn(self.newcomer, server.S.device_kind)


class WhenNoQuestionIsAsked(Base, Setup):
    """The cases that must NOT hold a newcomer to another device's rules."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OTHER: LAPTOP}, later=10)                       # a device already known, with no rules
        self.look({OLD: PHONE}, later=20)
        self.phone = self.give_rules(PHONE)

    def test_a_newcomer_with_an_ordinary_hardware_address_is_not_held_to_the_rules(self):
        self.look({OLD: GUEST}, later=60)
        self.assertEqual(server.S.provisional, {})
        self.assertFalse(blocked_for(OLD))

    def test_a_device_already_known_is_not_held_to_the_rules(self):
        self.look({OTHER: PRIVATE}, later=30)                      # seen long before the phone goes
        self.look({OLD: PHONE, OTHER: PRIVATE}, later=40 + 2 * server.QUIET_AFTER)
        self.look({OLD: PRIVATE}, later=60 + 2 * server.QUIET_AFTER)
        self.assertEqual(server.S.provisional, {})
        self.assertFalse(blocked_for(OLD))

    def test_nobody_is_held_to_the_rules_of_a_device_that_is_still_on_the_network(self):
        self.look({OLD: PRIVATE, NEW: PHONE}, later=60)
        self.assertEqual(server.S.provisional, {})
        self.assertFalse(blocked_for(OLD))

    def test_a_newcomer_with_rules_of_its_own_is_not_held_to_another_devices(self):
        self.look({NEW: PRIVATE}, later=30)
        server.set_internet_off("dev:%d" % self.number(PRIVATE), True)
        self.look({OLD: PRIVATE}, later=60)
        self.assertEqual(server.S.provisional, {})

    def test_a_visitor_at_a_departed_visitors_number_is_just_put_in_the_new_device_group(self):
        visitors = self.make_group("Visitors")
        server.set_new_device_group(visitors)
        self.look({NEW: GUEST}, later=30)
        self.assertEqual(server.S.dev_group.get(self.number(GUEST)), visitors)
        self.look({NEW: PRIVATE}, later=600)
        self.assertEqual(server.S.dev_group.get(self.number(PRIVATE)), visitors)
        self.assertEqual((server.S.provisional, server.S.device_notices), ({}, []))

    def test_the_router_and_this_computer_are_never_held_to_anothers_rules(self):
        server.refresh_devices({PI: PRIVATE, ROUTER: PRIVATE_TOO}, now=self.now + 60)
        self.assertEqual(server.S.provisional, {})


class RulesHeldAgainstANumber(Api, Setup):
    """Rules set for an address before QuietNet could tell which device has it: they apply to
    lookups from that number, and the device seen there is given them for now and the owner asked."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.ok("/api/service-block", {"scope": "device:" + OLD, "service": "youtube", "on": True})
        self.held = server.S.addr_only[OLD]

    def test_a_rule_for_an_address_no_device_is_known_at_is_held_against_that_number(self):
        self.assertEqual(server.S.device_kind[self.held], "addr")
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % self.held: {"youtube"}})
        self.assertTrue(answered_blocked(OLD))

    def test_the_device_then_seen_there_is_given_the_rules_for_now(self):
        self.look({OLD: PHONE}, later=60)
        self.assertEqual(server.S.provisional, {self.number(PHONE): self.held})
        self.assertTrue(answered_blocked(OLD))

    def test_the_owner_is_asked_whether_the_rules_are_that_devices(self):
        self.look({OLD: PHONE}, later=60)
        notices = self.get("/api/status")[1]["device_notices"]
        self.assertEqual([(n["to"], n["same"], n["held"], n["to_device"]) for n in notices],
                         [(OLD, True, True, self.number(PHONE))])

    def test_yes_gives_the_rules_to_the_device_itself(self):
        self.look({OLD: PHONE}, later=60)
        phone = self.number(PHONE)
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % phone: {"youtube"}})
        self.assertNotIn(self.held, server.S.device_kind)
        self.look({NEW: PHONE}, later=120)                          # and they go with it from now on
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))

    def test_no_leaves_the_rules_with_the_number_and_off_the_device(self):
        self.look({OLD: PHONE}, later=60)
        self.ok("/api/different-device", {"ip": OLD})
        self.assertFalse(blocked_for(OLD))
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % self.held: {"youtube"}})

    def test_the_next_device_at_that_number_is_asked_about_too(self):
        self.look({OLD: PHONE}, later=60)
        self.ok("/api/different-device", {"ip": OLD})
        self.look({OLD: LAPTOP}, later=120)
        self.assertEqual(server.S.provisional, {self.number(LAPTOP): self.held})

    def test_a_device_with_rules_of_its_own_gets_both_while_the_question_is_open(self):
        self.look({NEW: PHONE}, later=30)
        server.set_service_block("dev:%d" % self.number(PHONE), "tiktok", True)
        self.look({OLD: PHONE}, later=60)
        self.assertTrue(blocked_for(OLD))
        self.assertTrue(blocked_for(OLD, "tiktok.com"))


class NewDeviceGroup(Base, Setup):
    def setUp(self):
        super().setUp()
        self.start_clean()
        self.gid = self.make_group("Kids", "tiktok")

    def test_a_device_never_seen_before_goes_into_the_chosen_group(self):
        server.set_new_device_group(self.gid)
        self.look({NEW: PRIVATE}, later=60)
        new = self.number(PRIVATE)
        self.assertEqual(server.S.dev_group.get(new), self.gid)
        self.assertEqual(server.sql("SELECT gid FROM group_member WHERE device=?", (new,)), [(self.gid,)])
        self.assertTrue(any("put in the Kids group" in t for t in self.events()))
        self.assertTrue(blocked_for(NEW, "tiktok.com"))

    def test_the_group_goes_with_the_device_not_the_address(self):
        server.set_new_device_group(self.gid)
        self.look({NEW: GUEST}, later=60)
        server.set_new_device_group(None)
        self.look({OTHER: LAPTOP}, later=70)
        self.look({NEW: LAPTOP, OTHER: GUEST}, later=120)
        self.assertTrue(blocked_for(OTHER, "tiktok.com"))           # the visitor, wherever it is
        self.assertFalse(blocked_for(NEW, "tiktok.com"))            # not whoever has its old number

    def test_a_device_seen_before_is_not_put_in_the_group(self):
        self.look({NEW: PRIVATE}, later=30)
        server.set_new_device_group(self.gid)
        self.look({NEW: PRIVATE}, later=60)
        self.assertEqual(server.S.dev_group, {})

    def test_a_device_first_seen_over_ipv6_goes_into_the_group_too(self):
        server.set_new_device_group(self.gid)
        self.look6({V6_A: fresh(TV)}, later=60)
        self.assertEqual(server.S.dev_group.get(self.number(TV)), self.gid)

    def test_no_group_is_given_when_none_is_chosen(self):
        self.look({NEW: PRIVATE}, later=60)
        self.assertEqual(server.S.dev_group, {})

    def test_the_first_look_puts_nobody_in_the_group(self):
        for table in ("device", "device_hw", "address_use", "settings"):
            server.sql("DELETE FROM %s" % table, commit=True)
        server.init_db()                                             # a household with nothing seen yet
        gid = self.make_group("Kids")
        server.set_new_device_group(gid)
        self.look({NEW: PRIVATE, OTHER: LAPTOP}, later=60)
        self.assertEqual(server.S.dev_group, {})
        self.look({OLD: PHONE}, later=120)                           # after that, a new device is new
        self.assertEqual(server.S.dev_group, {self.number(PHONE): gid})

    def test_the_first_look_is_not_taken_twice_after_a_restart(self):
        server.init_db()
        server.set_new_device_group(self.gid)
        self.look({NEW: PRIVATE}, later=60)
        self.assertEqual(server.S.dev_group.get(self.number(PRIVATE)), self.gid)

    def test_the_router_is_never_put_in_the_group(self):
        server.set_new_device_group(self.gid)
        self.look({NEW: ROUTER_MAC}, later=60)
        self.assertEqual(server.S.dev_group, {})

    def test_deleting_the_group_clears_the_setting_and_its_members(self):
        server.set_new_device_group(self.gid)
        self.look({NEW: PRIVATE}, later=60)
        server.delete_group(self.gid)
        self.assertIsNone(server.S.new_device_group)
        server.init_db()
        self.assertEqual((server.S.new_device_group, server.S.dev_group), (None, {}))
        self.assertEqual(server.sql("SELECT * FROM group_member"), [])


class GoneQuietNotice(Api, Setup):
    """A device with rules goes quiet and a new private-address device appears at ANOTHER address:
    only a suggestion. Nothing is applied until the owner says they are the same."""

    def setUp(self):
        super().setUp()
        self.start_clean()

    def quiet_then_new(self):
        """Wilf's iPad is last seen, then goes quiet; a new private address appears elsewhere."""
        self.look({OLD: PHONE})
        phone = self.give_rules(PHONE)
        self.look({NEW: PRIVATE}, later=server.QUIET_AFTER + 120)
        return phone

    def test_a_notice_appears_when_a_device_with_rules_goes_quiet_and_a_new_private_device_appears(self):
        phone = self.quiet_then_new()
        status, out = self.get("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual([(n["from"], n["name"], n["to"], n["same"], n["from_device"], n["to_device"])
                          for n in out["device_notices"]],
                         [(OLD, "Wilf's iPad", NEW, False, phone, self.number(PRIVATE))])

    def test_a_suggestion_applies_nothing(self):
        self.quiet_then_new()
        self.assertEqual(server.S.provisional, {})
        self.assertFalse(blocked_for(NEW))

    def test_no_notice_while_the_device_with_rules_is_still_seen(self):
        self.look({OLD: PHONE})
        self.give_rules(PHONE)
        self.look({OLD: PHONE, NEW: PRIVATE}, later=server.QUIET_AFTER + 120)
        self.assertEqual(self.get("/api/status")[1]["device_notices"], [])

    def test_no_notice_for_a_new_device_with_an_ordinary_hardware_address(self):
        self.look({OLD: PHONE})
        self.give_rules(PHONE)
        self.look({NEW: GUEST}, later=server.QUIET_AFTER + 120)
        self.assertEqual(server.S.device_notices, [])

    def test_saying_it_is_the_same_device_joins_them_through_the_api(self):
        phone = self.quiet_then_new()
        self.ok("/api/move-rules", {"from": OLD, "to": NEW})
        self.assertTrue(blocked_for(NEW))
        self.assertEqual(server.S.hw_device[PRIVATE], phone)
        self.assertEqual(self.get("/api/status")[1]["device_notices"], [])
        devices = {d["ip"]: d for d in self.get("/api/devices")[1]}
        self.assertEqual((devices[NEW]["name"], devices[NEW]["id"], devices[NEW]["macs"]),
                         ("Wilf's iPad", phone, [PHONE, PRIVATE]))

    def test_the_new_device_group_given_to_the_newcomer_does_not_stick_to_the_device_it_turns_out_to_be(self):
        self.look({OLD: PHONE})
        phone = self.give_rules(PHONE)
        visitors = self.ok("/api/group", {"name": "Visitors"})["id"]
        self.ok("/api/new-device-group", {"group": visitors})
        self.look({NEW: PRIVATE}, later=server.QUIET_AFTER + 120)
        self.assertEqual(server.S.dev_group, {self.number(PRIVATE): visitors})
        self.ok("/api/move-rules", {"from_device": phone, "to_device": self.number(PRIVATE)})
        self.assertEqual(server.S.dev_group, {})
        self.assertEqual(server.sql("SELECT * FROM group_member"), [])

    def test_a_group_the_owner_gave_the_newcomer_is_kept_when_the_two_are_joined(self):
        kids = self.ok("/api/group", {"name": "Kids"})["id"]
        phone = self.quiet_then_new()
        self.ok("/api/device-group", {"device": self.number(PRIVATE), "group": kids})
        self.ok("/api/move-rules", {"from_device": phone, "to_device": self.number(PRIVATE)})
        self.assertEqual(server.S.dev_group, {phone: kids})

    def test_joining_is_refused_when_the_new_device_has_rules_of_its_own(self):
        self.quiet_then_new()
        server.set_internet_off("dev:%d" % self.number(PRIVATE), True)
        status, out = self.post("/api/move-rules", {"from": OLD, "to": NEW})
        self.assertEqual(status, 400)
        self.assertIn("already has rules", out["error"])
        self.assertEqual(server.S.svc_blocks.get("dev:%d" % self.number(PHONE)), {"youtube"})

    def test_joining_refuses_anything_but_two_devices(self):
        self.quiet_then_new()
        for body in ({"from": OLD}, {"from": OLD, "to": 5}, {"from": "1; drop", "to": NEW},
                     {"from": NEW, "to": NEW}, {"from": OLD, "to": PI}, {"from": OLD, "to": ROUTER},
                     {"from_device": 99999, "to_device": self.number(PRIVATE)}, {"to_device": "x"}):
            self.assertEqual(self.post("/api/move-rules", body)[0], 400, body)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 2)

    def test_the_new_device_group_is_saved_through_the_api(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.assertEqual(self.ok("/api/new-device-group", {"group": gid})["group"], gid)
        self.assertEqual(self.get("/api/status")[1]["new_device_group"], gid)

    def test_an_unknown_new_device_group_counts_as_none(self):
        for value in (999, "1", True, None, [1]):
            self.assertIsNone(self.ok("/api/new-device-group", {"group": value})["group"], value)

    def test_device_notes_are_listed_in_the_status_summary(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/new-device-group", {"group": gid})
        self.look({NEW: PRIVATE}, later=60)
        texts = [e["text"] for e in self.get("/api/status")[1]["device_events"]]
        self.assertIn("A new device appeared at %s and was put in the Kids group, as you asked for new devices." % NEW, texts)


class JoiningTwoDevices(Base, Setup):
    """merge_devices: nothing either device carried is dropped."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: PHONE, NEW: LAPTOP})
        self.keep, self.gone = self.number(PHONE), self.number(LAPTOP)

    def test_the_kept_device_ends_with_every_rule_either_had(self):
        kids = self.make_group("Kids")
        server.set_device_name(self.gone, "Old tablet")
        server.set_device_group(self.gone, kids)
        server.set_internet_off("dev:%d" % self.gone, True)
        server.set_service_block("dev:%d" % self.gone, "tiktok", True)
        server.set_service_block("dev:%d" % self.keep, "youtube", True)
        server.set_live_cut(self.gone, True)
        self.schedule(scope="dev:%d" % self.gone)
        server.merge_devices(self.keep, self.gone)
        scope = "dev:%d" % self.keep
        self.assertEqual((server.S.given, server.S.dev_group, server.S.off, server.S.svc_blocks, server.S.enforced),
                         ({self.keep: "Old tablet"}, {self.keep: kids}, {scope}, {scope: {"tiktok", "youtube"}}, {self.keep}))
        self.assertEqual([x["scope"] for x in server.S.schedules], [scope])
        server.init_db()                     # and the database says the same
        self.assertEqual((server.S.given, server.S.dev_group, server.S.off, server.S.svc_blocks, server.S.enforced),
                         ({self.keep: "Old tablet"}, {self.keep: kids}, {scope}, {scope: {"tiktok", "youtube"}}, {self.keep}))

    def test_the_kept_devices_own_name_and_group_win(self):
        kids, adults = self.make_group("Kids"), self.make_group("Adults")
        server.set_device_name(self.keep, "Phone")
        server.set_device_name(self.gone, "Tablet")
        server.set_device_group(self.keep, adults)
        server.set_device_group(self.gone, kids)
        server.merge_devices(self.keep, self.gone)
        self.assertEqual((server.S.given, server.S.dev_group), ({self.keep: "Phone"}, {self.keep: adults}))

    def test_both_addresses_get_the_rules_at_once(self):
        server.set_service_block("dev:%d" % self.keep, "youtube", True)
        server.merge_devices(self.keep, self.gone)
        self.assertTrue(blocked_for(OLD))
        self.assertTrue(blocked_for(NEW))
        self.assertEqual(server.S.addr_device[NEW], self.keep)

    def test_the_number_of_the_device_that_went_is_never_used_again(self):
        server.merge_devices(self.keep, self.gone)
        self.look({OTHER: TV}, later=60)
        self.assertGreater(self.number(TV), self.gone)

    def test_joining_is_refused_for_this_computer_and_the_router(self):
        server.set_device_name(self.keep, "Phone")
        for fixed in (server.S.pi_device, server.S.hub_device):
            self.assertIn("this computer or the router", server.same_device_by_hand(fixed, self.keep))
            self.assertIn("this computer or the router", server.same_device_by_hand(self.keep, fixed))

    def test_joining_a_device_with_nothing_to_give_is_refused(self):
        self.assertEqual(server.same_device_by_hand(self.keep, self.gone), "There are no rules to move.")
        self.assertEqual(server.same_device_by_hand(self.keep, self.keep), "There are no rules to move.")


class DevicesWithRulesAreKept(Base, Setup):
    """A device with a name or rules is never forgotten, however long it has been away."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: PHONE, NEW: LAPTOP})
        self.phone = self.number(PHONE)
        self.long_after = self.now + (server.KEEP_DAYS + 30) * 86400

    def kept(self):
        server.forget_old_devices(now=self.long_after)
        return self.phone in server.S.device_kind

    def test_a_device_with_nothing_of_its_own_is_forgotten_after_a_month_away(self):
        self.assertFalse(self.kept())

    def test_a_named_device_is_never_forgotten(self):
        server.set_device_name(self.phone, "Wilf's iPad")
        self.assertTrue(self.kept())

    def test_a_device_in_a_group_is_never_forgotten(self):
        server.set_device_group(self.phone, self.make_group("Kids"))
        self.assertTrue(self.kept())

    def test_a_device_with_its_internet_switched_off_is_never_forgotten(self):
        server.set_internet_off("dev:%d" % self.phone, True)
        self.assertTrue(self.kept())

    def test_a_device_with_a_blocked_service_is_never_forgotten(self):
        server.set_service_block("dev:%d" % self.phone, "youtube", True)
        self.assertTrue(self.kept())

    def test_a_device_with_a_schedule_is_never_forgotten(self):
        self.schedule(scope="dev:%d" % self.phone)
        self.assertTrue(self.kept())

    def test_a_device_with_cut_live_connections_is_never_forgotten(self):
        server.set_live_cut(self.phone, True)
        self.assertTrue(self.kept())

    def test_a_kept_device_still_has_its_rules_when_it_comes_back(self):
        server.set_service_block("dev:%d" % self.phone, "youtube", True)
        self.assertTrue(self.kept())
        server.refresh_devices({PI: PI_MAC, ROUTER: ROUTER_MAC, OTHER: PHONE}, now=self.long_after + 60)
        self.assertTrue(blocked_for(OTHER))

    def test_a_question_about_a_forgotten_device_is_forgotten_with_it(self):
        with server.db_lock:
            server.db.execute("INSERT INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
                              (self.number(LAPTOP), self.phone, "no", self.now))
            server.db.commit()
        server.init_db()
        self.assertEqual(server.S.not_same, {(self.number(LAPTOP), self.phone)})
        server.forget_old_devices(now=self.long_after)
        self.assertEqual((server.S.not_same, server.sql("SELECT * FROM device_follow")), (set(), []))

    def test_devices_with_rules_do_not_count_towards_the_limit_on_remembered_devices(self):
        server.set_device_name(self.phone, "Wilf's iPad")
        with mock.patch.object(server, "MAX_DEVICES", 0):
            server.forget_old_devices(now=self.now)
        self.assertEqual({k for k, kind in server.S.device_kind.items() if kind == "hw"}, {self.phone})


class DhcpSightings(Base, Setup):
    """A device says which address it is taking as it joins. That word changes whose rules the
    address gets straight away; the neighbour table confirms or overrules it at the next look."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        no_look = mock.patch.object(server, "look_soon")
        self.look_soon = no_look.start()
        self.addCleanup(no_look.stop)
        server.dhcp_window[:] = [0.0, 0]
        self.look({OLD: fresh(TV), NEW: fresh(PHONE)})
        self.tv, self.phone = self.number(TV), self.give_rules(PHONE)
        server.set_internet_off("dev:%d" % self.tv, True)
        self.look({OLD: stale(TV)}, later=60)                       # both go quiet: the TV's entry stays, stale
        self.assertTrue(blocked_for(OLD, "www.bbc.co.uk"))

    def test_a_known_device_taking_a_new_address_gets_its_rules_there_at_once(self):
        self.assertTrue(server.note_dhcp(PHONE, OTHER))
        self.assertTrue(blocked_for(OTHER))
        self.assertTrue(answered_blocked(OTHER))

    def test_a_known_device_taking_another_devices_old_address_gets_its_own_rules_not_the_others(self):
        server.note_dhcp(PHONE, OLD)
        self.assertTrue(blocked_for(OLD))                           # the phone's YouTube block
        self.assertFalse(blocked_for(OLD, "www.bbc.co.uk"))         # not the TV's internet switch

    def test_a_device_never_seen_taking_an_address_pauses_the_old_devices_rules_on_it(self):
        server.note_dhcp(GUEST, OLD)
        self.assertNotIn(OLD, server.S.addr_rules)
        self.assertFalse(blocked_for(OLD, "www.bbc.co.uk"))
        self.assertIn("dev:%d" % self.tv, server.S.off)             # the TV keeps its rule, for when it is back

    def test_a_dhcp_request_never_makes_a_device(self):
        before = dict(server.S.device_kind)
        server.note_dhcp(GUEST, OLD)
        self.assertEqual(server.S.device_kind, before)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device_hw WHERE mac=?", (GUEST,)), [(0,)])

    def test_the_word_is_ignored_while_the_neighbour_table_confirms_another_device_there(self):
        self.look({OLD: fresh(TV)}, later=120)
        server.note_dhcp(GUEST, OLD)
        self.assertEqual(server.S.addr_rules[OLD], self.tv)
        server.note_dhcp(PHONE, OLD)
        self.assertEqual(server.S.addr_rules[OLD], self.tv)

    def test_the_word_takes_effect_once_the_device_that_was_there_is_no_longer_confirmed(self):
        self.look({OLD: fresh(TV)}, later=120)
        server.note_dhcp(PHONE, OLD)
        self.look({OLD: stale(TV)}, later=125)                      # the TV really had just left
        self.assertEqual(server.S.addr_rules[OLD], self.phone)

    def test_the_next_look_that_confirms_the_device_settles_it(self):
        server.note_dhcp(PHONE, OLD)
        self.look({OLD: fresh(PHONE)}, later=120)
        self.assertEqual((server.S.addr_rules[OLD], server.S.dhcp_claims), (self.phone, {}))

    def test_a_look_that_confirms_someone_else_overrules_the_word(self):
        server.note_dhcp(PHONE, OLD)
        self.look({OLD: fresh(LAPTOP)}, later=120)
        self.assertEqual((server.S.addr_rules[OLD], server.S.dhcp_claims), (self.number(LAPTOP), {}))

    def test_a_stale_entry_for_the_device_that_was_there_does_not_overrule_the_word(self):
        server.note_dhcp(GUEST, OLD)
        self.look({OLD: stale(TV)}, later=120)
        self.assertNotIn(OLD, server.S.addr_rules)

    def test_the_word_lapses_if_nothing_confirms_it(self):
        clock = [1000.0]
        with mock.patch.object(server.time, "monotonic", lambda: clock[0]):
            server.note_dhcp(GUEST, OLD)
            clock[0] += server.DHCP_HOLD + 1
            server.rebuild_rule_map()
        self.assertEqual((server.S.addr_rules.get(OLD), server.S.dhcp_claims), (self.tv, {}))

    def test_rules_held_against_the_number_itself_still_apply_after_such_a_word(self):
        server.set_service_block("device:" + OTHER, "tiktok", True)  # nothing known there: held against the number
        server.note_dhcp(GUEST, OTHER)
        self.assertTrue(blocked_for(OTHER, "tiktok.com"))

    def test_the_word_of_a_range_extender_or_an_unsettled_hardware_address_names_no_device(self):
        with mock.patch.object(server.S, "shared_macs", {PHONE}):
            self.assertIsNone(server.dhcp_device(PHONE))
        with mock.patch.object(server.S, "hw_unsettled", frozenset({PHONE})):
            self.assertIsNone(server.dhcp_device(PHONE))
        self.assertEqual(server.dhcp_device(PHONE), self.phone)

    def test_this_computers_and_the_routers_addresses_are_never_taken_on_a_devices_word(self):
        for mac, address in ((PHONE, PI), (PHONE, ROUTER), (ROUTER_MAC, OTHER), (PHONE, "127.0.0.1"),
                             (PHONE, "0.0.0.0"), (PHONE, "224.0.0.1")):
            self.assertFalse(server.note_dhcp(mac, address), (mac, address))
        self.assertEqual(server.S.dhcp_claims, {})

    def test_a_malformed_word_is_ignored(self):
        for mac, address in (("", OLD), ("ff:ff:ff:ff:ff:ff", OLD), (PHONE, "not an address"), (PHONE, "fe80::1"),
                             (PHONE, None), (None, OLD)):
            self.assertFalse(server.note_dhcp(mac, address), (mac, address))

    def test_only_so_many_words_are_taken_in_each_second(self):
        taken = [server.note_dhcp(PHONE, "192.168.1.%d" % (100 + i)) for i in range(server.DHCP_MAX_PER_SECOND + 5)]
        self.assertEqual(taken.count(True), server.DHCP_MAX_PER_SECOND)

    def test_only_so_many_words_are_remembered(self):
        with mock.patch.object(server, "DHCP_MAX_CLAIMS", 3), mock.patch.object(server, "DHCP_MAX_PER_SECOND", 100):
            for i in range(6):
                server.note_dhcp(GUEST, "192.168.1.%d" % (100 + i))
        self.assertEqual(len(server.S.dhcp_claims), 3)
        self.assertIn("192.168.1.105", server.S.dhcp_claims)

    def test_a_word_asks_for_a_look_at_the_neighbours(self):
        server.note_dhcp(PHONE, OTHER)
        self.look_soon.assert_called_once_with()

    def test_a_device_is_never_steered_on_its_word_alone(self):
        server.set_live_cut(self.phone, True)
        server.note_dhcp(PHONE, OTHER)
        self.assertEqual(self.plan({}), {})

    def test_nothing_is_taken_on_a_devices_word_before_the_device_tables_are_in_use(self):
        with mock.patch.object(server.S, "devices_ready", False):
            self.assertFalse(server.note_dhcp(PHONE, OTHER))
        self.assertEqual(server.S.dhcp_claims, {})

    def test_the_device_name_listener_passes_what_it_hears_to_the_rules(self):
        server.NAMER.on_address(PHONE, OTHER)
        self.assertEqual(server.S.dhcp_claims[OTHER][0], PHONE)
        self.assertTrue(blocked_for(OTHER))

    def test_a_dhcp_request_is_handled_without_the_database(self):
        with mock.patch.object(server, "sql", side_effect=AssertionError("database used")), \
                mock.patch.object(server, "db", None):
            self.assertTrue(server.note_dhcp(PHONE, OTHER))


class LookSoon(unittest.TestCase):
    def test_one_look_is_on_its_way_at_a_time_however_many_devices_speak(self):
        started = []

        class Later:
            """A stand-in thread that is never run."""
            def __init__(self, target=None, daemon=None):
                started.append(target)

            def start(self):
                pass
        server.look_due.clear()
        self.addCleanup(server.look_due.clear)
        with mock.patch.object(server.threading, "Thread", Later):
            server.look_soon()
            server.look_soon()
            server.look_soon()
        self.assertEqual(len(started), 1)

    def test_the_look_comes_a_moment_later_and_lets_the_next_one_be_asked_for(self):
        ran = []

        class Now:
            """A stand-in thread that runs at once."""
            def __init__(self, target=None, daemon=None):
                self.target = target

            def start(self):
                self.target()
        server.look_due.clear()
        with mock.patch.object(server.threading, "Thread", Now), \
                mock.patch.object(server.time, "sleep", lambda s: ran.append(("sleep", s))), \
                mock.patch.object(server, "note_ipv4_addresses", lambda: ran.append("look")):
            server.look_soon()
        self.assertEqual(ran, [("sleep", server.DHCP_LOOK_DELAY), "look"])
        self.assertFalse(server.look_due.is_set())


class WhereTheEnforcerSteers(Base, Setup):
    """The address to steer comes only from the live neighbour table, with a fresh entry whose
    hardware address is the device's own."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: fresh(PHONE)})
        self.phone = self.give_rules(PHONE)
        server.set_live_cut(self.phone, True)

    def test_a_device_is_steered_at_the_address_it_is_confirmed_at(self):
        plan = self.plan({OLD: fresh(PHONE)})
        self.assertEqual({ip: rule["mac"] for ip, rule in plan.items()}, {OLD: PHONE})

    def test_cut_live_connections_follows_the_device_to_its_new_address(self):
        self.look({NEW: fresh(PHONE)}, later=60)
        self.assertEqual({ip: rule["mac"] for ip, rule in self.plan({NEW: fresh(PHONE)}).items()}, {NEW: PHONE})
        self.assertEqual(server.S.enforced, {self.phone})

    def test_a_stale_neighbour_entry_never_steers(self):
        self.look({OLD: stale(PHONE)}, later=60)
        self.assertEqual(self.plan({OLD: stale(PHONE)}), {})

    def test_a_stale_address_record_never_steers(self):
        # The record says the phone used this address; the live table says nothing. No steering.
        self.assertEqual(server.S.addr_use[OLD][0], self.phone)
        self.look({}, later=60)
        self.assertEqual(self.plan({}), {})

    def test_a_record_left_by_a_restart_never_steers(self):
        server.init_db()
        self.assertEqual(server.sql("SELECT addr FROM address_use WHERE device=?", (self.phone,)), [(OLD,)])
        self.assertEqual(self.plan({OLD: fresh(PHONE)}), {})        # not until a look has confirmed it there

    def test_a_different_device_now_at_the_address_is_not_steered(self):
        self.look({OLD: fresh(LAPTOP)}, later=60)
        self.assertEqual(self.plan({OLD: fresh(LAPTOP)}), {})

    def test_an_address_whose_hardware_address_changed_since_the_last_look_is_not_steered(self):
        self.assertEqual(self.plan({OLD: fresh(LAPTOP)}), {})       # the map still says the phone; the table does not

    def test_a_second_live_address_of_the_same_hardware_address_is_not_steered(self):
        self.look({OLD: fresh(PHONE), NEW: fresh(PHONE)}, later=60)
        self.assertEqual(sorted(self.plan({OLD: fresh(PHONE), NEW: fresh(PHONE)})), [OLD])

    def test_this_computer_and_the_router_are_never_in_the_plan(self):
        server.set_live_cut(server.S.pi_device, True)
        server.set_live_cut(server.S.hub_device, True)
        self.assertEqual(sorted(self.plan({OLD: fresh(PHONE)})), [OLD])

    def test_a_device_held_to_another_devices_rules_is_steered_while_that_lasts(self):
        self.look({OLD: fresh(PRIVATE)}, later=60)                  # a new private address at the phone's number
        self.assertEqual({ip: rule["mac"] for ip, rule in self.plan({OLD: fresh(PRIVATE)}).items()}, {OLD: PRIVATE})

    def test_a_device_with_two_hardware_addresses_is_steered_at_each(self):
        self.look({OLD: fresh(PHONE), NEW: fresh(LAPTOP)}, later=60)        # its Wi-Fi and its cable, joined by the owner
        server.merge_devices(self.phone, self.number(LAPTOP))
        table = {OLD: fresh(PHONE), NEW: fresh(LAPTOP)}
        self.look(table, later=120)
        self.assertEqual({ip: rule["mac"] for ip, rule in self.plan(table).items()}, {OLD: PHONE, NEW: LAPTOP})

    def test_the_plan_works_out_the_blocks_by_the_device_not_the_address(self):
        server.record_resolved("www.youtube.com", fake_answer(query("www.youtube.com")))
        self.look({NEW: fresh(PHONE)}, later=60)
        plan = self.plan({NEW: fresh(PHONE)})
        self.assertEqual(plan[NEW]["ips"], {"93.184.216.34"})

    def test_the_enforcer_is_given_the_table_the_plan_just_read(self):
        with mock.patch.object(server, "neighbour_table", return_value={OLD: fresh(PHONE)}) as read:
            server.enforcement_plan()
            self.assertEqual(server.plan_neighbours(), {OLD: PHONE})
        self.assertEqual(read.call_count, 1)

    def test_with_no_device_to_steer_the_neighbour_table_is_not_read_for_the_plan(self):
        server.set_live_cut(self.phone, False)
        with mock.patch.object(server, "neighbour_table", side_effect=AssertionError("read")):
            self.assertEqual(server.enforcement_plan(), {})

    def test_an_address_that_is_not_an_ipv4_address_never_reaches_the_plan(self):
        with server.db_lock:
            self.assertEqual(server.live_cut_devices({"192.168.1.54; drop": fresh(PHONE), "fe80::1": fresh(PHONE)}), {})


class DecisionStaysFast(Base, Setup):
    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: PHONE})
        self.give_rules(PHONE)
        self.look({OLD: PRIVATE}, later=60)                         # held to the phone's rules for now

    def test_decision_never_touches_the_database(self):
        with mock.patch.object(server, "sql", side_effect=AssertionError("database used")), \
                mock.patch.object(server, "db", None), mock.patch.object(server, "read_db", None):
            self.assertTrue(server.decision("youtube.com", OLD)[0])
            self.assertTrue(server.decision("youtube.com", server.S.hw_device[PRIVATE])[0])
            self.assertFalse(server.decision("youtube.com", NEW)[0])

    def test_decision_takes_no_lock(self):
        with server.rule_map_lock, server.db_lock:
            done = []
            t = threading.Thread(target=lambda: done.append(server.decision("youtube.com", OLD)[0]))
            t.start()
            t.join(5)
        self.assertEqual(done, [True])


class TheApiByDevice(Api, Setup):
    """Changes name a device by its number, or by the address it is listed under."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: PHONE})
        self.phone = self.number(PHONE)

    def test_a_change_to_a_card_a_scan_found_goes_to_the_hardware_address_that_card_shows(self):
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (NEW, TV, "tv", self.now), commit=True)
        self.assertEqual([(d["ip"], d["id"], d["mac"]) for d in self.get("/api/devices")[1] if d["ip"] == NEW],
                         [(NEW, None, TV)])                          # found by a scan; no look has confirmed it yet
        self.ok("/api/device-name", {"ip": NEW, "name": "Lounge TV"})
        tv = self.number(TV)
        self.assertEqual((server.S.device_kind[tv], server.S.given[tv]), ("hw", "Lounge TV"))
        self.look({OLD: PHONE, NEW: TV}, later=60)                  # when it is seen there, no question is asked
        self.assertEqual((server.S.provisional, server.S.device_notices), ({}, []))
        self.assertEqual([(d["id"], d["name"]) for d in self.get("/api/devices")[1] if d["ip"] == NEW], [(tv, "Lounge TV")])

    def test_the_live_neighbour_table_wins_over_an_old_scan_when_a_card_is_first_changed(self):
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (NEW, TV, "tv", self.now - 9000), commit=True)
        self.neighbours_now = {NEW: LAPTOP}                         # the scan is out of date: the laptop is there now
        self.ok("/api/internet", {"scope": "device:" + NEW, "off": True})
        self.assertEqual(server.S.off, {"dev:%d" % self.number(LAPTOP)})
        self.assertNotIn(TV, server.S.hw_device)
        card = [d for d in self.get("/api/devices")[1] if d["ip"] == NEW][0]
        self.assertEqual((card["id"], card["off"]), (self.number(LAPTOP), True))

    def test_a_change_to_a_scanned_card_behind_a_range_extender_is_held_against_the_number(self):
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (NEW, EXTENDER, "", self.now), commit=True)
        with mock.patch.object(server.S, "shared_macs", {EXTENDER}):
            self.ok("/api/device-name", {"ip": NEW, "name": "Garden tablet"})
        self.assertEqual(server.S.given, {server.S.addr_only[NEW]: "Garden tablet"})
        self.assertNotIn(EXTENDER, server.S.hw_device)

    def test_a_rule_given_by_address_is_kept_against_the_device_listed_there(self):
        self.ok("/api/internet", {"scope": "device:" + OLD, "off": True})
        self.assertEqual(server.S.off, {"dev:%d" % self.phone})

    def test_a_rule_can_be_given_by_the_devices_number(self):
        self.ok("/api/service-block", {"scope": "dev:%d" % self.phone, "service": "youtube", "on": True})
        self.assertTrue(blocked_for(OLD))
        self.assertTrue(self.get("/api/controls?scope=dev:%d" % self.phone)[1]["services"]["youtube"]["on"])
        self.assertTrue(self.get("/api/controls?scope=device:" + OLD)[1]["services"]["youtube"]["on"])

    def test_a_rule_for_a_device_number_quietnet_does_not_know_is_refused(self):
        status, out = self.post("/api/internet", {"scope": "dev:99999", "off": True})
        self.assertEqual((status, out), (400, {"error": "QuietNet doesn't know that device."}))
        self.assertEqual(server.S.off, set())

    def test_the_controls_of_a_device_quietnet_does_not_know_show_only_what_reaches_everyone(self):
        self.ok("/api/kill", {"on": True})
        self.addCleanup(server.set_internet_off, "all", False)
        self.assertEqual(self.get("/api/controls?scope=dev:99999")[1]["off_from"], "by the kill switch")

    def test_a_name_can_be_given_by_number_or_by_address(self):
        self.ok("/api/device-name", {"device": self.phone, "name": "Wilf's iPad"})
        self.assertEqual(server.S.given, {self.phone: "Wilf's iPad"})
        self.ok("/api/device-name", {"ip": OLD, "name": "Wilf's tablet"})
        self.assertEqual(server.sql("SELECT name FROM device WHERE id=?", (self.phone,)), [("Wilf's tablet",)])

    def test_a_name_for_something_that_is_not_a_device_is_refused(self):
        for body in ({"name": "x"}, {"ip": "not an address", "name": "x"}, {"device": 99999, "name": "x"}):
            self.assertEqual(self.post("/api/device-name", body)[0], 400, body)

    def test_a_group_can_be_given_by_number(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/device-group", {"device": self.phone, "group": gid})
        self.assertEqual(server.S.dev_group, {self.phone: gid})
        groups = self.get("/api/groups")[1]
        self.assertEqual((groups[0]["members"], groups[0]["devices"]), ([OLD], [self.phone]))

    def test_a_schedule_for_a_device_is_kept_against_it_and_shown_both_ways(self):
        self.ok("/api/schedule", {"name": "Bedtime", "scope": "device:" + OLD, "days": [0], "start": "21:00",
                                  "end": "07:00", "off": True})
        self.assertEqual([x["scope"] for x in server.S.schedules], ["dev:%d" % self.phone])
        shown = self.get("/api/schedules")[1][0]
        self.assertEqual((shown["scope"], shown["device"]), ("device:" + OLD, self.phone))

    def test_a_schedule_follows_the_device_to_its_new_address_in_what_the_page_is_shown(self):
        self.ok("/api/schedule", {"name": "Bedtime", "scope": "dev:%d" % self.phone, "days": [0], "start": "21:00",
                                  "end": "07:00", "off": True})
        self.look({NEW: PHONE}, later=60)
        self.assertEqual(self.get("/api/schedules")[1][0]["scope"], "device:" + NEW)

    def test_a_schedule_for_a_device_with_no_address_now_is_shown_by_its_number(self):
        self.ok("/api/schedule", {"name": "Bedtime", "scope": "dev:%d" % self.phone, "days": [0], "start": "21:00",
                                  "end": "07:00", "off": True})
        self.look({OLD: LAPTOP}, later=60)                          # the phone has gone and its number was given away
        shown = self.get("/api/schedules")[1][0]
        self.assertEqual((shown["scope"], shown["device"]), ("dev:%d" % self.phone, self.phone))

    def test_a_schedule_for_a_device_quietnet_does_not_know_is_refused(self):
        status, out = self.post("/api/schedule", {"name": "Bedtime", "scope": "dev:99999", "days": [0],
                                                  "start": "21:00", "end": "07:00", "off": True})
        self.assertEqual((status, out["error"]), (400, "Please choose who the schedule is for."))

    def test_the_activity_list_shows_the_devices_own_block_decisions_at_whatever_address(self):
        server.set_service_block("dev:%d" % self.phone, "youtube", True)
        server.sql("INSERT INTO queries(ts,client,domain,blocked,device) VALUES(?,?,?,0,?)",
                   (self.now, OLD, "www.youtube.com", self.phone), commit=True)
        self.look({NEW: PHONE}, later=60)
        for ask in ("device=%d" % self.phone, "ip=%s&device=%d" % (NEW, self.phone)):
            _, groups = self.get("/api/activity?hours=24&" + ask)
            self.assertEqual([(g["base"], g["b"]) for g in groups], [("youtube.com", True)], ask)

    def test_the_devices_page_reads_its_switches_by_the_device(self):
        self.ok("/api/internet", {"scope": "dev:%d" % self.phone, "off": True})
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/device-group", {"device": self.phone, "group": gid})
        self.look({NEW: PHONE}, later=60)
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["ip"], d["id"], d["off"], d["group"], d["paused"]), (NEW, self.phone, True, gid, False))

    def test_the_number_wins_when_a_request_names_a_device_both_ways(self):
        self.look({OLD: PHONE, NEW: LAPTOP})
        self.ok("/api/device-name", {"ip": NEW, "device": self.phone, "name": "Wilf's iPad"})
        self.assertEqual(server.S.given, {self.phone: "Wilf's iPad"})

    def test_the_routers_own_address_always_means_the_router(self):
        self.assertEqual(server.address_holder(ROUTER), server.S.hub_device)
        self.assertEqual(server.address_holder(PI), server.S.pi_device)
        self.assertEqual(server.stored_scope("device:" + ROUTER), "dev:%d" % server.S.hub_device)

    def test_cut_live_connections_is_refused_for_the_router_and_this_computer_by_number(self):
        for fixed in (server.S.hub_device, server.S.pi_device):
            status, out = self.post("/api/enforce", {"device": fixed, "on": True})
            self.assertEqual((status, out["error"]), (400, "QuietNet can't steer the router or itself."))
        self.assertEqual(server.S.enforced, set())

    def test_a_group_lists_a_member_that_has_no_address_now(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/device-group", {"device": self.phone, "group": gid})
        self.look({OLD: LAPTOP}, later=60)                          # the phone has gone and its number was given away
        group = self.get("/api/groups")[1][0]
        self.assertEqual((group["members"], group["devices"]), ([""], [self.phone]))

    def test_a_try_at_another_dns_service_is_remembered_against_the_device_not_the_address(self):
        server.set_internet_off("dev:%d" % self.phone, True)       # a device the owner controls
        server.answer_query(query("dns.google"), OLD, fake_answer)
        drain()
        self.look({OLD: LAPTOP, NEW: PHONE}, later=60)
        server.set_device_name(self.number(LAPTOP), "Dad laptop")
        cards = {d["id"]: d for d in self.get("/api/devices?all=1")[1]}
        self.assertGreater(cards[self.phone]["other_dns"], 0)
        self.assertEqual((cards[self.number(LAPTOP)]["ip"], cards[self.number(LAPTOP)]["other_dns"]), (OLD, 0))

    def test_a_suggested_name_is_filed_under_the_device_as_well_as_the_address(self):
        hint = {"name": "Sams iPad", "source": "Bonjour", "detail": ""}
        hints = server.hints_by_device({OLD: hint}, {OLD: PHONE})
        self.assertEqual(hints, {OLD: hint, self.phone: hint})
        server.set_internet_off("dev:%d" % self.phone, True)       # so it is listed without any history
        with mock.patch.object(server.S, "hints", hints):
            self.look({NEW: PHONE}, later=60)                       # at another address the suggestion is still its own
            card = self.get("/api/devices")[1][0]
            self.assertEqual((card["ip"], card["hint"]), (NEW, "Sams iPad"))

    def test_a_suggested_name_for_the_router_or_an_unknown_hardware_address_is_filed_by_address_only(self):
        hint = {"name": "hub", "source": "router", "detail": ""}
        self.assertEqual(server.hints_by_device({ROUTER: hint, NEW: hint}, {ROUTER: ROUTER_MAC, NEW: TV}),
                         {ROUTER: hint, NEW: hint})

    def test_the_new_calls_refuse_values_of_the_wrong_kind(self):
        for path, body in (("/api/rule-conflict", {}), ("/api/rule-conflict", {"id": "1", "choice": "give"}),
                           ("/api/rule-conflict", {"id": 1, "choice": 5}), ("/api/rule-conflict", {"id": True, "choice": "keep"}),
                           ("/api/rule-conflict", {"id": 12345, "choice": "give"}),
                           ("/api/rule-conflict", {"id": 1, "choice": "drop table"})):
            self.assertEqual(self.post(path, body)[0], 400, (path, body))


class TheOlderDatabase(OlderHousehold):
    """Before the move (or if it can't be done): names, groups and rules are still kept under
    addresses, and the one safeguard that matters is kept."""

    # The older household (test_devices.OlderHousehold): the phone at KEPT with YouTube blocked, and
    # here also the TV with its internet switched off at SPOT, recorded as the TV's.
    SPOT, KEPT, ELSEWHERE = older.OLD_SPOT, older.OTHER, older.NEW_SPOT
    ITS_TV, ANOTHER = older.TV, older.LAPTOP

    def household(self, old):
        super().household(old)
        old.execute("INSERT INTO internet_off VALUES(?)", ("device:" + self.SPOT,))
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (self.SPOT, self.ITS_TV))

    def look(self, table, later=0):
        full = {PI: PI_MAC, ROUTER: older.ROUTER_MAC}
        full.update(table)
        server.refresh_devices(full, now=self.now + later)

    def test_rules_still_apply_by_address(self):
        self.assertFalse(server.S.devices_ready)
        self.assertTrue(answered_blocked(self.KEPT))
        self.assertTrue(answered_blocked(self.SPOT, "www.bbc.co.uk"))

    def test_a_different_device_at_an_address_does_not_get_the_rules_kept_there(self):
        self.look({self.SPOT: self.ANOTHER})
        self.assertEqual(server.S.paused_ips, {self.SPOT})
        self.assertFalse(answered_blocked(self.SPOT, "www.bbc.co.uk"))
        self.assertIn("paused", server.S.device_warnings[self.SPOT])

    def test_the_rules_apply_again_when_their_device_is_back(self):
        self.look({self.SPOT: self.ANOTHER})
        self.look({self.SPOT: self.ITS_TV}, later=60)
        self.assertEqual(server.S.paused_ips, set())
        self.assertTrue(answered_blocked(self.SPOT, "www.bbc.co.uk"))

    def test_a_pause_lasts_through_a_restart(self):
        self.look({self.SPOT: self.ANOTHER})
        server.init_db()
        self.assertEqual(server.S.paused_ips, {self.SPOT})

    def test_a_paused_address_is_not_steered(self):
        server.set_live_cut(self.SPOT, True, self.ITS_TV)
        self.look({self.SPOT: self.ANOTHER})
        self.assertEqual(server.enforcement_plan(), {})

    def test_an_address_nobody_is_at_keeps_its_rules(self):
        self.look({})
        self.assertEqual(server.S.paused_ips, set())
        self.assertTrue(answered_blocked(self.SPOT, "www.bbc.co.uk"))

    def test_nothing_is_paused_when_a_range_extender_answers_for_the_address(self):
        with mock.patch.object(server, "note_shared_macs"), mock.patch.object(server.S, "shared_macs", {self.ANOTHER}):
            self.look({self.SPOT: self.ANOTHER})
        self.assertEqual(server.S.paused_ips, set())

    def test_this_computer_and_the_router_are_never_paused(self):
        server.set_service_block("device:" + ROUTER, "youtube", True)
        with server.db_lock:
            server.set_owner(ROUTER, older.ROUTER_MAC)
            server.db.commit()
        server.refresh_devices({PI: PI_MAC, ROUTER: self.ANOTHER}, now=self.now)
        self.assertEqual(server.S.paused_ips, set())

    def test_rules_are_no_longer_moved_from_address_to_address(self):
        self.look({self.ELSEWHERE: self.ITS_TV})
        self.assertEqual(server.S.off, {"device:" + self.SPOT})
        self.assertFalse(hasattr(server, "move_rules"))
        self.assertFalse(hasattr(server.S, "follow"))

    def test_changes_are_still_kept_under_addresses(self):
        server.set_device_name(self.SPOT, "Telly")
        server.set_device_group(self.SPOT, None)
        self.assertTrue(server.set_internet_off("device:" + self.KEPT, True))
        self.assertEqual(server.sql("SELECT name FROM devices WHERE ip=?", (self.SPOT,)), [("Telly",)])
        self.assertIn("device:" + self.KEPT, server.S.off)

    def test_a_rule_by_device_number_is_refused_until_the_data_has_been_moved(self):
        self.assertFalse(server.set_internet_off("dev:1", True))
        self.assertEqual(server.S.off, {"device:" + self.SPOT})

    def test_same_device_answers_wait_until_the_data_has_been_moved(self):
        self.assertEqual(server.same_device_by_hand(1, 2), server.STILL_MOVING)
        self.assertEqual(server.different_device_by_hand(1), server.STILL_MOVING)
        self.assertEqual(server.move_old_rules(), server.STILL_MOVING)

    def test_the_owner_is_told_rules_do_not_follow_a_device_while_the_move_is_waiting(self):
        with mock.patch.object(server, "space_for_move", return_value=(False, 900, 12)):
            self.assertEqual(server.move_to_devices(), "waiting")
        self.assertIn("each device's rules stay with its number and do not follow it to a new one", server.S.devices_notice)



class MovingTheRules(OlderHousehold):
    """The one-off move of an older household's names, groups and rules to the devices."""

    A, B, C, D, E, F = ("192.168.1.%d" % n for n in (101, 102, 103, 104, 105, 106))

    def household(self, old):
        now = self.now
        old.execute("INSERT INTO groups(id, name) VALUES(1, 'Kids')")
        old.execute("INSERT INTO groups(id, name) VALUES(2, 'Visitors')")
        old.executemany("INSERT INTO known_macs VALUES(?,?,?,?)", [
            (PHONE, self.A, now - 5 * 86400, now - 60),              # the phone is at A
            (TV, self.C, now - 20 * 86400, now - 120),               # the TV was last seen at C
            (LAPTOP, self.D, now - 9 * 86400, now - 300),            # the laptop has D now
            (GUEST, self.D, now - 86400, now - 200),
            (EXTENDER, self.F, now - 86400, now - 60)])
        old.execute("INSERT INTO shared_macs VALUES(?,?,?)", (EXTENDER, 3, now))
        # The phone: a name, a group, a block, a schedule and a live cut at A, certainly its own.
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (self.A, PHONE))
        old.execute("INSERT INTO devices VALUES(?,?)", (self.A, "Wilf's iPad"))
        old.execute("INSERT INTO device_group VALUES(?,?)", (self.A, 1))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + self.A, "youtube"))
        old.execute("INSERT INTO schedules(id,name,scope,days,t_from,t_to,off,services,enabled) "
                    "VALUES(7,'Bedtime',?,'0123456','21:00','07:00',1,'[]',1)", ("device:" + self.A,))
        old.execute("INSERT INTO enforced VALUES(?,?)", (self.A, PHONE))
        # The TV: rules under two numbers, both certainly its own, and a name under each.
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (self.B, TV))
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (self.C, TV))
        old.execute("INSERT INTO devices VALUES(?,?)", (self.B, "Old telly"))
        old.execute("INSERT INTO devices VALUES(?,?)", (self.C, "Lounge TV"))
        old.execute("INSERT INTO internet_off VALUES(?)", ("device:" + self.B,))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + self.C, "netflix"))
        # D: the laptop's rules, paused because a visitor (never seen before) has the number now.
        old.execute("INSERT INTO device_mac(ip, mac, paused, guest_mac, guest_gid) VALUES(?,?,1,?,2)", (self.D, LAPTOP, GUEST))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + self.D, "tiktok"))
        # E: a rule nobody's device was ever recorded for.
        old.execute("INSERT INTO internet_off VALUES(?)", ("device:" + self.E,))
        old.execute("INSERT INTO devices VALUES(?,?)", (self.E, "Spare tablet"))
        # F: behind a range extender.
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (self.F, EXTENDER))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + self.F, "roblox"))
        # The whole house and a group have rules too, which must not be touched.
        old.execute("INSERT INTO service_blocks VALUES('all', 'fortnite')")
        old.execute("INSERT INTO internet_off VALUES('group:1')")
        old.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", [
            (now - 600, self.A, "phone.example.com"), (now - 500, self.E, "spare.example.com")])

    def setUp(self):
        super().setUp()
        server.load_lists()
        self.assertEqual(server.move_to_devices(), "ready")

    def device(self, mac):
        return server.S.hw_device[mac]

    def held(self, address):
        return server.S.addr_only[address]

    def look(self, table, later=0):
        full = {PI: PI_MAC, ROUTER: ROUTER_MAC}
        full.update(table)
        server.refresh_devices(full, now=self.now + later)

    def test_a_devices_name_group_and_rules_go_to_the_device_on_certain_evidence(self):
        phone, scope = self.device(PHONE), "dev:%d" % self.device(PHONE)
        self.assertEqual(server.S.given[phone], "Wilf's iPad")
        self.assertEqual(server.S.dev_group[phone], 1)
        self.assertEqual(server.S.svc_blocks[scope], {"youtube"})
        self.assertIn(phone, server.S.enforced)
        self.assertEqual([(x["id"], x["scope"], x["enabled"], x["off"]) for x in server.S.schedules], [(7, scope, True, True)])

    def test_the_moved_rules_apply_wherever_the_device_is_seen(self):
        self.look({OTHER: PHONE})
        self.assertTrue(answered_blocked(OTHER))
        self.assertFalse(answered_blocked(self.A))

    def test_paused_rules_go_to_the_device_they_belong_to_not_the_device_at_the_number_now(self):
        self.assertEqual(server.S.svc_blocks["dev:%d" % self.device(LAPTOP)], {"tiktok"})
        self.assertNotIn("dev:%d" % self.device(GUEST), server.S.svc_blocks)

    def test_a_new_device_held_in_the_new_device_group_at_a_paused_number_keeps_that_group(self):
        self.assertEqual(server.S.dev_group[self.device(GUEST)], 2)

    def test_rules_nobody_was_recorded_for_stay_with_their_number(self):
        held = self.held(self.E)
        self.assertEqual(server.S.device_kind[held], "addr")
        self.assertIn("dev:%d" % held, server.S.off)
        self.assertEqual(server.S.given[held], "Spare tablet")

    def test_rules_left_with_a_number_still_apply_to_lookups_from_it(self):
        self.assertTrue(answered_blocked(self.E, "www.bbc.co.uk"))

    def test_the_device_then_seen_at_that_number_is_given_them_for_now_and_the_owner_is_asked(self):
        self.look({self.E: PRIVATE})
        self.assertEqual(server.S.provisional, {self.device(PRIVATE): self.held(self.E)})
        self.assertTrue(answered_blocked(self.E, "www.bbc.co.uk"))
        self.assertEqual([(n["to"], n["held"]) for n in server.S.device_notices], [(self.E, True)])

    def test_rules_behind_a_range_extender_stay_with_the_number(self):
        self.assertEqual(server.S.svc_blocks["dev:%d" % self.held(self.F)], {"roblox"})
        self.assertNotIn(EXTENDER, server.S.hw_device)

    def test_rules_from_two_numbers_of_one_device_are_not_merged(self):
        tv = self.device(TV)
        self.assertEqual(server.S.svc_blocks["dev:%d" % tv], {"netflix"})      # where it was last seen: in use
        self.assertNotIn("dev:%d" % tv, server.S.off)                          # the other set is not newly applied
        self.assertIn("dev:%d" % self.held(self.B), server.S.off)              # nor dropped: left with its number

    def test_the_conflict_is_listed_for_the_owner_with_what_was_left(self):
        conflicts = server.api_status()["devices"]["conflicts"]
        self.assertEqual([(c["device"], c["held"], c["addr"]) for c in conflicts],
                         [(self.device(TV), self.held(self.B), self.B)])
        self.assertIn("The same device had rules under two numbers. Those kept under %s are in use. Those kept under %s "
                      "were left with that number: called \"Old telly\"; internet switched off." % (self.C, self.B),
                      conflicts[0]["text"])

    def test_the_rules_left_with_the_number_keep_applying_there(self):
        self.assertTrue(answered_blocked(self.B, "www.bbc.co.uk"))

    def test_choosing_give_adds_them_to_the_device(self):
        cid = server.S.rule_conflicts[0]["id"]
        tv = self.device(TV)
        self.assertIsNone(server.settle_conflict(cid, "give"))
        self.assertIn("dev:%d" % tv, server.S.off)
        self.assertEqual(server.S.svc_blocks["dev:%d" % tv], {"netflix"})
        self.assertEqual((server.S.rule_conflicts, server.sql("SELECT * FROM rule_conflict")), ([], []))
        self.assertNotIn(self.B, server.S.addr_only)

    def test_choosing_remove_removes_them(self):
        cid, held = server.S.rule_conflicts[0]["id"], self.held(self.B)
        self.assertIsNone(server.settle_conflict(cid, "remove"))
        self.assertNotIn("dev:%d" % held, server.S.off)
        self.assertNotIn("dev:%d" % self.device(TV), server.S.off)
        self.assertEqual(server.S.rule_conflicts, [])
        self.assertFalse(answered_blocked(self.B, "www.bbc.co.uk"))

    def test_choosing_keep_leaves_them_with_the_number_and_closes_the_question(self):
        cid, held = server.S.rule_conflicts[0]["id"], self.held(self.B)
        self.assertIsNone(server.settle_conflict(cid, "keep"))
        self.assertIn("dev:%d" % held, server.S.off)
        self.assertEqual(server.S.rule_conflicts, [])

    def test_the_choice_can_be_made_through_the_dashboard(self):
        cid = server.S.rule_conflicts[0]["id"]
        Api.setUpClass()
        try:
            api = Api("call")
            self.assertEqual(api.call("POST", "/api/rule-conflict", {"id": cid, "choice": "remove"}), (200, {"ok": True}))
            self.assertEqual(api.call("GET", "/api/status")[1]["devices"]["conflicts"], [])
        finally:
            Api.tearDownClass()

    def test_an_unknown_choice_changes_nothing(self):
        cid = server.S.rule_conflicts[0]["id"]
        for wrong in ((cid, "merge"), (cid + 99, "give")):
            self.assertEqual(server.settle_conflict(*wrong), "QuietNet doesn't know that choice.")
        self.assertEqual(len(server.S.rule_conflicts), 1)

    def test_two_names_on_one_device_keep_the_one_from_where_it_was_last_seen(self):
        self.assertEqual(server.S.given[self.device(TV)], "Lounge TV")
        self.assertEqual(server.S.given[self.held(self.B)], "Old telly")   # it went with the rules left at that number

    def test_no_rule_is_dropped_or_added_by_the_move(self):
        scopes = lambda table: sorted(s for (s,) in server.sql("SELECT scope FROM %s" % table))   # noqa: E731
        self.assertEqual(len(scopes("internet_off")), 3)                    # B, E and the Kids group
        self.assertEqual(len(scopes("service_blocks")), 5)                  # A, C, D, F and the whole house
        self.assertEqual(server.sql("SELECT COUNT(*) FROM schedules")[0][0], 1)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM live_cut")[0][0], 1)
        self.assertEqual(sorted(server.sql("SELECT gid FROM group_member")), [(1,), (2,)])
        self.assertEqual(sorted(name for (name,) in server.sql("SELECT name FROM device WHERE name!=''")),
                         ["Lounge TV", "Old telly", "Spare tablet", "Wilf's iPad"])

    def test_rules_for_the_whole_house_and_for_groups_are_left_alone(self):
        self.assertEqual(server.S.svc_blocks["all"], {"fortnite"})
        self.assertIn("group:1", server.S.off)

    def test_the_old_tables_are_left_empty(self):
        for table in ("devices", "device_group", "enforced", "device_mac"):
            self.assertEqual(server.sql("SELECT COUNT(*) FROM %s" % table)[0][0], 0, table)
        for table in ("internet_off", "service_blocks", "schedules"):
            self.assertEqual(server.sql("SELECT COUNT(*) FROM %s WHERE scope LIKE 'device:%%'" % table)[0][0], 0, table)
        self.assertEqual(server.S.old_rules, 0)

    def test_the_copy_kept_before_the_move_still_has_the_rules_as_they_were(self):
        copy = sqlite3.connect(self.copy())
        try:
            self.assertEqual(copy.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 4)
            self.assertEqual(copy.execute("SELECT COUNT(*) FROM device_mac").fetchone()[0], 5)
        finally:
            copy.close()

    def test_a_report_of_what_was_done_is_kept_for_the_home_page(self):
        report = server.api_status()["devices"]["report"]
        self.assertTrue(any("The rules kept under %s (" % self.A in line and "are now kept with the device itself" in line
                            for line in report))
        self.assertTrue(any("could not tell for certain which device the rules kept under %s" % self.E in line for line in report))
        self.assertTrue(any("Wi-Fi range extender" in line and self.F in line for line in report))
        self.assertTrue(any("The same device had rules under two numbers" in line for line in report))
        server.init_db()
        self.assertEqual(server.S.move_report, report)

    def test_a_report_that_cannot_be_read_is_shown_as_empty(self):
        for broken in ("not json", "{}", ""):
            server.set_setting("rules_move_report", broken)
            server.init_db()
            self.assertEqual(server.S.move_report, [], broken)

    def test_the_report_says_what_each_set_of_rules_was(self):
        line = [l for l in server.S.move_report if "kept under %s (" % self.A in l][0]
        self.assertIn('in the Kids group; 1 blocked service (YouTube); the "Bedtime" schedule; cut live connections', line)

    def test_the_owner_is_told_in_the_recent_changes(self):
        notes = [text for (text,) in server.sql("SELECT text FROM events ORDER BY id")]
        self.assertIn("QuietNet now keeps each device's name, group and rules with the device itself, whatever number it "
                      "has, so nothing has to be moved when a number changes. The rules of 3 devices went with their "
                      "device, 2 stayed with a number, and 1 needs your decision on the home page.", notes)

    def test_the_tables_are_at_the_version_that_holds_rules_against_devices(self):
        self.assertEqual(server.get_setting("devices_version", ""), "2")
        self.assertTrue(server.rules_on_devices())

    def test_the_moved_database_is_ready_straight_away_at_the_next_start(self):
        before = (dict(server.S.given), dict(server.S.dev_group), set(server.S.off), dict(server.S.svc_blocks), set(server.S.enforced))
        server.init_db()
        self.assertTrue(server.S.devices_ready)
        self.assertEqual((dict(server.S.given), dict(server.S.dev_group), set(server.S.off), dict(server.S.svc_blocks),
                          set(server.S.enforced)), before)

    def test_a_lost_version_setting_does_not_make_a_moved_database_look_unmoved(self):
        server.sql("DELETE FROM settings WHERE key='devices_version'", commit=True)
        server.init_db()
        self.assertTrue(server.S.devices_ready)
        self.assertEqual(server.S.given[self.device(PHONE)], "Wilf's iPad")

    def test_devices_the_move_knew_do_not_count_as_new_afterwards(self):
        server.set_new_device_group(2)
        self.look({OTHER: TV})
        self.assertNotIn(self.device(TV), server.S.dev_group)


class MovingTheRulesSmallerCases(OlderHousehold):
    A, B = "192.168.1.101", "192.168.1.102"

    def household(self, old):
        now = self.now
        old.execute("INSERT INTO groups(id, name) VALUES(1, 'Kids')")
        old.executemany("INSERT INTO known_macs VALUES(?,?,?,?)", [(PHONE, self.A, now - 86400, now - 60)])
        old.execute("INSERT INTO seen VALUES(?,?,?,?)", (ROUTER, ROUTER_MAC, "hub", now))
        # The phone: internet off and a block under A; only the same block again under B.
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (self.A, PHONE))
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (self.B, PHONE))
        old.execute("INSERT INTO internet_off VALUES(?)", ("device:" + self.A,))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + self.A, "youtube"))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + self.B, "youtube"))
        old.execute("INSERT INTO devices VALUES(?,?)", (self.B, "Wilf's old number"))
        old.execute("INSERT INTO devices VALUES(?,?)", (self.A, "Wilf's iPad"))
        # A name alone, at a number the last scan found the TV at: a best guess is good enough for a name.
        old.execute("INSERT INTO seen VALUES(?,?,?,?)", ("192.168.1.103", TV, "tv", now - 3600))
        old.execute("INSERT INTO devices VALUES(?,?)", ("192.168.1.103", "Lounge TV"))
        # A group alone, with nobody recorded for it; and one in a group that no longer exists.
        old.execute("INSERT INTO device_group VALUES(?,?)", ("192.168.1.104", 1))
        old.execute("INSERT INTO device_group VALUES(?,?)", ("192.168.1.105", 99))
        # This computer and the router, named and with a rule each.
        old.execute("INSERT INTO devices VALUES(?,?)", (PI, "QuietNet Pi"))
        old.execute("INSERT INTO devices VALUES(?,?)", (ROUTER, "BT hub"))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + ROUTER, "tiktok"))
        # Cut live connections with the hardware address noted, and nothing else recorded.
        old.execute("INSERT INTO enforced VALUES(?,?)", ("192.168.1.106", LAPTOP))
        old.execute("INSERT INTO enforced VALUES(?,?)", ("192.168.1.107", ""))

    def setUp(self):
        super().setUp()
        self.assertEqual(server.move_to_devices(), "ready")

    def test_a_second_number_that_asks_for_nothing_more_is_folded_in_with_no_question(self):
        phone = server.S.hw_device[PHONE]
        self.assertEqual(server.S.svc_blocks["dev:%d" % phone], {"youtube"})
        self.assertIn("dev:%d" % phone, server.S.off)
        self.assertEqual(server.S.rule_conflicts, [])

    def test_a_name_that_gives_way_is_recorded_not_lost_silently(self):
        self.assertEqual(server.S.given[server.S.hw_device[PHONE]], "Wilf's iPad")
        text = ('The name "Wilf\'s old number", kept under %s, was not kept: that device is now called "Wilf\'s iPad", '
                'the name kept under %s.' % (self.B, self.A))
        self.assertIn(text, [t for (t,) in server.sql("SELECT text FROM events")])
        self.assertIn(text, server.S.move_report)

    def test_a_name_alone_goes_to_the_device_on_a_best_guess(self):
        self.assertEqual(server.S.given[server.S.hw_device[TV]], "Lounge TV")

    def test_a_group_nobody_was_recorded_for_stays_with_its_number(self):
        self.assertEqual(server.S.dev_group[server.S.addr_only["192.168.1.104"]], 1)

    def test_membership_of_a_group_that_no_longer_exists_is_not_carried_over(self):
        self.assertNotIn(99, server.S.dev_group.values())

    def test_this_computer_and_the_router_keep_their_names_and_rules_as_the_fixed_devices(self):
        self.assertEqual((server.S.given[server.S.pi_device], server.S.given[server.S.hub_device]), ("QuietNet Pi", "BT hub"))
        self.assertEqual(server.S.svc_blocks["dev:%d" % server.S.hub_device], {"tiktok"})

    def test_the_hardware_address_noted_for_a_live_cut_counts_as_certain_evidence(self):
        self.assertIn(server.S.hw_device[LAPTOP], server.S.enforced)

    def test_a_live_cut_with_no_hardware_address_noted_stays_with_its_number(self):
        held = server.S.addr_only["192.168.1.107"]
        self.assertEqual((held in server.S.enforced, server.S.enforced_mac[held]), (True, ""))


class WhenTheRulesCannotBeMoved(OlderHousehold):
    def household(self, old):
        super().household(old)
        old.execute("INSERT INTO internet_off VALUES(?)", ("device:" + OTHER_PHONE,))

    def fail_in_the_rules(self):
        """Run the move with a fault after the rules have already been written to the devices."""
        real = server.move_rules_to_devices

        def broken(now):
            real(now)
            raise RuntimeError("the disk went away")
        with mock.patch.object(server, "move_rules_to_devices", broken):
            return server.move_to_devices()

    def state(self):
        return (sorted(server.sql("SELECT name FROM sqlite_master WHERE type='table'")),
                server.sql("SELECT * FROM devices"), server.sql("SELECT * FROM device_mac"),
                sorted(server.sql("SELECT * FROM service_blocks")), sorted(server.sql("SELECT * FROM internet_off")),
                server.sql("SELECT * FROM settings ORDER BY key"))

    def test_a_fault_while_moving_the_rules_leaves_the_database_exactly_as_it_was(self):
        before = self.state()
        self.assertEqual(self.fail_in_the_rules(), "failed")
        self.assertEqual(self.state(), before)

    def test_a_fault_while_moving_the_rules_leaves_every_rule_in_force(self):
        self.fail_in_the_rules()
        self.assertFalse(server.S.devices_ready)
        self.assertEqual(server.S.svc_blocks, {"device:" + OTHER_PHONE: {"youtube"}})
        self.assertTrue(answered_blocked(OTHER_PHONE))
        self.assertTrue(answered_blocked(OTHER_PHONE, "www.bbc.co.uk"))

    def test_the_owner_is_told_and_the_move_is_tried_again_at_the_next_start(self):
        self.fail_in_the_rules()
        self.assertIn("Nothing has been changed", server.S.devices_notice)
        server.init_db()
        self.assertEqual(server.move_to_devices(), "ready")
        self.assertIn("dev:%d" % server.S.hw_device[older.PHONE], server.S.off)


OTHER_PHONE = older.OTHER                    # where the older household's phone is, with YouTube blocked


class ADatabaseWithOnlyItsHistoryMoved(OlderHousehold):
    """A database that has the device tables for its history but still keeps rules under
    addresses (version 1) gets only the second half of the move."""

    def setUp(self):
        super().setUp()
        with mock.patch.object(server, "move_rules_to_devices", lambda now: {"moved": 0, "held": 0, "conflicts": 0, "lines": []}):
            with server.db_lock:                                     # the first half alone, as version 1 did it
                server.make_device_tables()
                for table in ("group_member", "live_cut", "device_follow", "rule_conflict"):
                    server.db.execute("DROP TABLE %s" % table)
                server.build_devices(self.now)
                server.db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('devices_version', '1')")
                server.db.commit()
        server.init_db()
        server.S.local_ip, server.S.router, server.S.router_checked = PI, ROUTER, float("inf")

    def test_it_runs_on_its_rules_under_addresses_until_the_rest_is_done(self):
        self.assertFalse(server.S.devices_ready)
        self.assertTrue(answered_blocked(OTHER_PHONE))

    def test_the_rest_of_the_move_holds_the_rules_against_the_devices(self):
        devices = server.sql("SELECT id, key FROM device ORDER BY id")
        self.assertEqual(server.move_to_devices(), "ready")
        self.assertEqual(server.sql("SELECT id, key FROM device ORDER BY id"), devices)       # no device made twice
        phone = server.S.hw_device[older.PHONE]
        self.assertEqual((server.S.given[phone], server.S.svc_blocks), ("Sam's phone", {"dev:%d" % phone: {"youtube"}}))

    def test_the_time_the_history_was_moved_is_left_as_it_was(self):
        before = server.get_setting("devices_moved_at", "")
        server.move_to_devices()
        self.assertEqual(server.get_setting("devices_moved_at", ""), before)

    def test_the_copy_is_kept_for_thirty_days_from_this_move_not_from_the_first(self):
        server.set_setting("devices_moved_at", repr(self.now - 29 * 86400))
        server.move_to_devices()
        self.assertFalse(server.forget_old_copy(now=time.time() + 2 * 86400))
        self.assertTrue(os.path.exists(self.copy()))
        self.assertTrue(server.forget_old_copy(now=time.time() + 31 * 86400))


class RulesAnOlderVersionLeftBehind(OlderHousehold):
    """An older QuietNet run on a moved database writes names and rules to the old tables, which
    this version no longer reads. The owner is told and offered to have them brought in."""

    def setUp(self):
        super().setUp()
        self.assertEqual(server.move_to_devices(), "ready")
        # What an older version would have written while it was running on this data.
        server.sql("INSERT INTO devices VALUES(?,?)", ("192.168.1.90", "Games console"), commit=True)
        server.sql("INSERT INTO internet_off VALUES(?)", ("device:192.168.1.90",), commit=True)
        server.sql("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", ("192.168.1.90", LAPTOP), commit=True)
        server.init_db()
        server.S.local_ip, server.S.router, server.S.router_checked = PI, ROUTER, float("inf")

    def test_the_owner_is_told_how_many_numbers_carry_rules_that_are_not_in_use(self):
        self.assertEqual(server.api_status()["devices"]["old_rules"], 1)

    def test_they_are_not_in_use_until_the_owner_says(self):
        self.assertNotIn("device:192.168.1.90", [sc for sc in server.S.off if sc.startswith("dev:")])
        self.assertFalse(answered_blocked("192.168.1.90", "www.bbc.co.uk"))

    def test_bringing_them_in_holds_them_against_the_device(self):
        self.assertIsNone(server.move_old_rules())
        laptop = server.S.hw_device[LAPTOP]
        self.assertEqual(server.S.given[laptop], "Games console")
        self.assertIn("dev:%d" % laptop, server.S.off)
        self.assertEqual(server.api_status()["devices"]["old_rules"], 0)

    def test_bringing_them_in_can_be_asked_for_through_the_dashboard(self):
        Api.setUpClass()
        try:
            api = Api("call")
            self.assertEqual(api.call("POST", "/api/move-old-rules", {}), (200, {"ok": True}))
            self.assertEqual(api.call("GET", "/api/status")[1]["devices"]["old_rules"], 0)
        finally:
            Api.tearDownClass()

    def test_bringing_them_in_keeps_the_rules_already_held_against_devices(self):
        phone = server.S.hw_device[older.PHONE]
        server.move_old_rules()
        self.assertEqual((server.S.given[phone], server.S.svc_blocks["dev:%d" % phone]), ("Sam's phone", {"youtube"}))

    def test_the_report_gains_what_was_brought_in(self):
        before = len(server.S.move_report)
        server.move_old_rules()
        self.assertGreater(len(server.S.move_report), before)
        self.assertTrue(any("192.168.1.90" in line for line in server.S.move_report))

    def test_a_fault_while_bringing_them_in_changes_nothing(self):
        with mock.patch.object(server, "move_rules_to_devices", side_effect=RuntimeError("no")):
            self.assertIn("Nothing was changed", server.move_old_rules())
        self.assertEqual(server.sql("SELECT ip FROM devices"), [("192.168.1.90",)])
        self.assertEqual(server.S.old_rules, 1)


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


if __name__ == "__main__":
    unittest.main()
