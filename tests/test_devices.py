"""Checks for the device tables: one device is one hardware address, whatever address it has.

Run with:  python3 -m unittest discover tests

Covers the record of which device has which address (and its safeguards against filing one
device's lookups as another's), the history written against the device, the clean-up pass, the
device list and activity by device, and the one-off move of an older household's database.

Nothing here reads the real neighbour table or runs a system tool: every look is handed a
stand-in table. The older-household tests build their database in a throwaway folder.
"""
import os
import queue
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_dashboard_api import Api
from test_quietnet import Base, fake_answer, query, server

PI, ROUTER = "192.168.1.60", "192.168.1.254"
ROUTER_MAC = "00:11:22:33:44:01"
TV, PHONE, LAPTOP = "64:e7:d8:5d:c7:42", "a2:11:22:33:44:55", "3c:22:fb:aa:bb:cc"
EXTENDER = "00:aa:bb:cc:dd:ee"
OLD_SPOT, NEW_SPOT, OTHER = "192.168.1.65", "192.168.1.67", "192.168.1.70"
V6_A, V6_B, V6_C = "2a00:23c8:1:2:1111::1", "2a00:23c8:1:2:2222::2", "fe80::1c2d:3e4f:5a6b:7c8d"


def fresh(mac):
    """A neighbour-table entry the system confirmed just now."""
    return (mac, "fresh")


def stale(mac):
    """A neighbour-table entry the system has not confirmed for a while."""
    return (mac, "stale")


def drain():
    """Everything waiting on the history queue."""
    out = []
    while True:
        try:
            out.append(server.log_q.get_nowait())
        except queue.Empty:
            return out


class WriterStop(BaseException):
    """Raised by the stand-in for waiting on the queue, to end the history writer's endless loop.
    Not an ordinary error, so the writer's own catch of database faults cannot swallow it."""


def one_round_of_the_writer():
    """Run the history writer (log_writer) on what is waiting, without its one-second pause, until
    it goes back to wait for more. Returns the stand-in for prune_history."""
    waiting = server.log_q.get

    def get_or_stop():
        """Hand over the next waiting lookup, or end the round when there is none."""
        if server.log_q.empty():
            raise WriterStop()
        return waiting()
    with mock.patch.object(server.time, "sleep", lambda seconds: None), \
            mock.patch.object(server.log_q, "get", get_or_stop), \
            mock.patch.object(server, "prune_history") as prune:
        try:
            server.log_writer()
        except WriterStop:
            pass
    return prune


class Devices(Base):
    """Shared steps: a home with this computer at PI and the router at ROUTER."""

    def setUp(self):
        super().setUp()
        for table in ("devices", "seen", "settings"):
            server.sql("DELETE FROM %s" % table, commit=True)
        server.init_db()
        saved = server.S.local_ip
        server.S.local_ip, server.S.router, server.S.router_checked = PI, ROUTER, float("inf")
        self.addCleanup(setattr, server.S, "local_ip", saved)
        self.addCleanup(setattr, server.S, "router", "")
        server.rebuild_address_map()
        self.now = time.time()
        drain()

    def look(self, table, ago=0):
        """One look at this IPv4 neighbour table, `ago` seconds in the past."""
        server.note_ipv4_addresses(table, now=self.now - ago)

    def look6(self, table, ago=0):
        """One look at this IPv6 neighbour table, `ago` seconds in the past."""
        server.note_ipv6_addresses(table, now=self.now - ago)

    def lookup(self, address, name="www.bbc.co.uk"):
        """One lookup from this address, answered and saved as the history writer would."""
        server.answer_query(query(name), address, fake_answer)
        with server.db_lock:
            server.save_history(drain())

    def row(self, client, name, ago, device=None):
        """Put one history row straight into the database, made `ago` seconds in the past."""
        server.sql("INSERT INTO queries(ts,client,domain,blocked,device) VALUES(?,?,?,0,?)",
                   (self.now - ago, client, name, device), commit=True)

    def filed(self):
        """{name: device number} for every history row."""
        return dict(server.sql("SELECT domain, device FROM queries"))

    def device_at(self, address):
        return server.S.addr_device.get(address)

    def kind(self, number):
        return server.sql("SELECT kind FROM device WHERE id=?", (number,))[0][0]


class TheTables(Devices):
    def test_a_new_household_gets_the_device_tables_at_start_up(self):
        tables = {name for (name,) in server.sql("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"device", "device_hw", "address_use", "moved_address"} <= tables)
        self.assertTrue(server.S.devices_ready)
        self.assertEqual(server.S.devices_state, "ready")

    def test_this_computer_and_the_router_are_fixed_devices_from_the_start(self):
        kinds = dict(server.sql("SELECT kind, id FROM device"))
        self.assertEqual(kinds, {"pi": server.S.pi_device, "hub": server.S.hub_device})

    def test_the_fixed_devices_keep_their_numbers_across_a_restart(self):
        before = (server.S.pi_device, server.S.hub_device)
        server.init_db()
        self.assertEqual((server.S.pi_device, server.S.hub_device), before)

    def test_a_device_number_is_never_used_twice(self):
        self.look({OLD_SPOT: fresh(TV)})
        first = self.device_at(OLD_SPOT)
        server.sql("DELETE FROM device WHERE id=?", (first,), commit=True)
        server.sql("DELETE FROM device_hw", commit=True)
        server.init_db()
        self.look({OLD_SPOT: fresh(PHONE)})
        self.assertGreater(self.device_at(OLD_SPOT), first)

    def test_the_address_record_is_read_back_after_a_restart(self):
        self.look({OLD_SPOT: fresh(TV)})
        tv = self.device_at(OLD_SPOT)
        server.init_db()
        self.assertEqual(server.S.addr_use[OLD_SPOT][0], tv)
        self.assertEqual(server.S.hw_device[TV], tv)

    def test_no_more_devices_are_made_once_twice_the_limit_are_remembered(self):
        with mock.patch.object(server, "MAX_DEVICES", 2):
            self.look({"192.168.1.%d" % (70 + i): fresh("3c:22:fb:00:00:%02x" % i) for i in range(6)})
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 2)   # 2 fixed + 2 = twice the limit


class WhichDeviceHasWhichAddress(Devices):
    def test_a_device_is_its_hardware_address(self):
        self.look({OLD_SPOT: fresh(TV)})
        self.assertEqual(self.kind(self.device_at(OLD_SPOT)), "hw")
        self.assertEqual(server.sql("SELECT mac FROM device_hw WHERE device=?", (self.device_at(OLD_SPOT),)), [(TV,)])

    def test_a_tv_that_moves_to_a_new_address_is_still_the_same_device(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        tv = self.device_at(OLD_SPOT)
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV)})
        self.assertEqual(self.device_at(NEW_SPOT), tv)

    def test_an_address_the_device_has_left_is_no_longer_in_the_map(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV)})
        self.assertIsNone(self.device_at(OLD_SPOT))

    def test_a_stale_entry_alone_does_not_put_an_address_in_the_map(self):
        self.look({OLD_SPOT: stale(TV)})
        self.assertIsNone(self.device_at(OLD_SPOT))

    def test_an_address_that_goes_stale_drops_out_of_the_map_but_keeps_its_record(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        tv = self.device_at(OLD_SPOT)
        self.look({OLD_SPOT: stale(TV)})
        self.assertIsNone(self.device_at(OLD_SPOT))
        self.assertEqual(server.S.addr_use[OLD_SPOT][0], tv)

    def test_an_entry_of_unknown_freshness_counts_as_confirmed(self):
        self.look({OLD_SPOT: TV})                            # a Mac's table gives no freshness
        self.assertIsNotNone(self.device_at(OLD_SPOT))

    def test_an_address_taken_by_another_device_belongs_to_that_device_at_once(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        tv = self.device_at(OLD_SPOT)
        self.look({OLD_SPOT: fresh(PHONE)})
        self.assertNotEqual(self.device_at(OLD_SPOT), tv)
        self.assertEqual(server.S.hw_device[PHONE], self.device_at(OLD_SPOT))

    def test_a_change_of_holder_opens_a_new_row_and_keeps_the_old_one(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.look({OLD_SPOT: fresh(PHONE)})
        rows = server.sql("SELECT device, first, last FROM address_use WHERE addr=? ORDER BY first", (OLD_SPOT,))
        self.assertEqual([r[0] for r in rows], [server.S.hw_device[TV], server.S.hw_device[PHONE]])
        self.assertAlmostEqual(rows[0][2], self.now - 600, delta=1)       # the TV's row stopped when it was last confirmed

    def test_a_new_private_hardware_address_is_a_new_device_never_merged(self):
        self.look({OLD_SPOT: fresh(PHONE)}, ago=600)
        before = self.device_at(OLD_SPOT)
        self.look({OLD_SPOT: fresh("a2:99:88:77:66:55")})    # the same phone after "forget this network"
        self.assertNotEqual(self.device_at(OLD_SPOT), before)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 2)

    def test_one_hardware_address_at_two_live_addresses_keeps_only_the_address_it_already_had(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        tv = self.device_at(OLD_SPOT)
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)})
        self.assertEqual(self.device_at(OLD_SPOT), tv)
        self.assertIsNone(self.device_at(NEW_SPOT))

    def test_one_hardware_address_live_at_two_addresses_it_had_before_keeps_the_one_confirmed_last(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        tv = self.device_at(OLD_SPOT)
        self.look({NEW_SPOT: fresh(TV)}, ago=300)
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)})
        self.assertEqual((self.device_at(OLD_SPOT), self.device_at(NEW_SPOT)), (None, tv))

    def test_the_second_address_gets_the_device_once_the_first_is_no_longer_confirmed(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        tv = self.device_at(OLD_SPOT)
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)}, ago=300)
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV)})
        self.assertEqual(self.device_at(NEW_SPOT), tv)

    def test_a_hardware_address_new_at_two_addresses_at_once_is_given_neither(self):
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)})
        self.assertIsNone(self.device_at(OLD_SPOT))
        self.assertIsNone(self.device_at(NEW_SPOT))

    def test_a_hardware_address_at_two_live_addresses_is_marked_unsettled(self):
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)})
        self.assertEqual(server.S.hw_unsettled, {TV})
        self.look({NEW_SPOT: fresh(TV)})
        self.assertEqual(server.S.hw_unsettled, frozenset())

    def test_the_first_address_keeps_the_device_across_a_restart_while_both_are_live(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        tv = self.device_at(OLD_SPOT)
        server.tidy_history()
        server.init_db()
        server.S.local_ip = PI
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)})
        self.assertEqual((self.device_at(OLD_SPOT), self.device_at(NEW_SPOT)), (tv, None))

    def test_each_address_behind_a_range_extender_is_a_device_of_its_own(self):
        server.S.shared_macs = {EXTENDER}
        self.look({OLD_SPOT: fresh(EXTENDER), NEW_SPOT: fresh(EXTENDER)})
        one, two = self.device_at(OLD_SPOT), self.device_at(NEW_SPOT)
        self.assertNotEqual(one, two)
        self.assertEqual((self.kind(one), self.kind(two)), ("addr", "addr"))

    def test_a_range_extenders_hardware_address_is_not_a_device(self):
        server.S.shared_macs = {EXTENDER}
        self.look({OLD_SPOT: fresh(EXTENDER), NEW_SPOT: fresh(EXTENDER)})
        self.assertNotIn(EXTENDER, server.S.hw_device)

    def test_a_group_or_malformed_hardware_address_is_ignored(self):
        self.look({OLD_SPOT: fresh("ff:ff:ff:ff:ff:ff"), NEW_SPOT: fresh("not-an-address"), OTHER: fresh("00:00:00:00:00:00")})
        self.assertEqual(server.S.map4, {})

    def test_the_map_is_swapped_whole_so_a_lookup_never_sees_it_half_made(self):
        before = server.S.addr_device
        self.look({OLD_SPOT: fresh(TV)})
        self.assertIsNot(server.S.addr_device, before)
        self.assertNotIn(OLD_SPOT, before)

    def test_the_minute_look_that_moves_rules_keeps_the_map_too(self):
        server.refresh_devices({PI: "b8:27:eb:00:00:01", ROUTER: ROUTER_MAC, OLD_SPOT: TV}, now=self.now)
        self.assertEqual(self.device_at(OLD_SPOT), server.S.hw_device[TV])

    def test_at_most_the_limit_of_addresses_are_followed(self):
        with mock.patch.object(server, "MAX_ADDRESS_USE", 1):
            self.look({OLD_SPOT: fresh(TV), OTHER: fresh(LAPTOP)})
        self.assertEqual(server.sql("SELECT COUNT(*) FROM address_use")[0][0], 1)


class TheFixedDevices(Devices):
    def test_this_computers_own_addresses_belong_to_the_pi_device(self):
        server.S.v6_own = {"fd12:3456:789a::60"}
        server.rebuild_address_map()
        for address in ("127.0.0.1", "::1", PI, "fd12:3456:789a::60"):
            self.assertEqual(self.device_at(address), server.S.pi_device, address)

    def test_this_computers_lookups_are_filed_against_the_pi_device(self):
        self.lookup("127.0.0.1")
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.pi_device})

    def test_this_computers_lookups_are_its_own_even_before_any_look(self):
        server.S.addr_device = {}
        self.assertEqual(server.device_of_lookup("::1", PI), server.S.pi_device)

    def test_the_routers_address_belongs_to_the_hub_device(self):
        self.look({ROUTER: fresh(ROUTER_MAC)})
        self.assertEqual(self.device_at(ROUTER), server.S.hub_device)

    def test_the_routers_hardware_address_belongs_to_the_hub_and_no_other_device(self):
        self.look({ROUTER: fresh(ROUTER_MAC)})
        self.assertEqual(server.S.hw_device[ROUTER_MAC], server.S.hub_device)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 0)

    def test_another_address_with_the_routers_hardware_address_is_the_hub_too(self):
        self.look({ROUTER: fresh(ROUTER_MAC), "192.168.1.253": fresh(ROUTER_MAC)})
        self.assertEqual(self.device_at("192.168.1.253"), server.S.hub_device)

    def test_a_hardware_address_found_to_be_the_routers_is_taken_from_its_ordinary_device(self):
        with mock.patch.object(server.S, "router", ""):
            self.look({ROUTER: fresh(ROUTER_MAC)})           # the router is not known to be one yet
        self.assertEqual(self.kind(self.device_at(ROUTER)), "hw")
        self.look({ROUTER: fresh(ROUTER_MAC)})
        self.assertEqual(self.device_at(ROUTER), server.S.hub_device)
        self.assertEqual(server.sql("SELECT device FROM device_hw WHERE mac=?", (ROUTER_MAC,)), [(server.S.hub_device,)])

    def test_a_replaced_router_lets_go_of_the_old_ones_hardware_address(self):
        self.look({ROUTER: fresh(ROUTER_MAC)})
        self.look({ROUTER: fresh("00:11:22:33:44:99")})
        self.assertNotIn(ROUTER_MAC, server.S.hw_device)
        self.assertEqual(server.S.hub_mac, "00:11:22:33:44:99")

    def test_the_routers_ipv6_address_belongs_to_the_hub_device(self):
        self.look({ROUTER: fresh(ROUTER_MAC)})
        self.look6({"fe80::1": fresh(ROUTER_MAC)})
        self.assertEqual(self.device_at("fe80::1"), server.S.hub_device)

    def test_this_computer_in_the_neighbour_table_is_never_made_a_device(self):
        self.look({PI: fresh("b8:27:eb:00:00:01")})
        self.assertEqual(self.device_at(PI), server.S.pi_device)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 0)

    def test_the_fixed_devices_are_never_forgotten(self):
        server.sql("UPDATE device SET last=0", commit=True)
        server.forget_old_devices()
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device")[0][0], 2)


class AddressesOverIPv6(Devices):
    def test_many_ipv6_addresses_give_one_device(self):
        self.look({OLD_SPOT: fresh(PHONE)})
        self.look6({V6_A: fresh(PHONE), V6_B: stale(PHONE), V6_C: fresh(PHONE)})
        phone = self.device_at(OLD_SPOT)
        self.assertEqual([self.device_at(a) for a in (V6_A, V6_B, V6_C)], [phone] * 3)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 1)

    def test_a_new_ipv6_address_the_next_day_is_still_the_same_device(self):
        self.look({OLD_SPOT: fresh(PHONE)}, ago=86400)
        self.look6({V6_A: fresh(PHONE)}, ago=86400)
        self.look6({V6_A: stale(PHONE), V6_B: fresh(PHONE)})
        self.assertEqual(self.device_at(V6_B), server.S.hw_device[PHONE])

    def test_a_stale_ipv6_entry_still_counts(self):
        self.look6({V6_A: stale(PHONE)})
        self.assertEqual(self.device_at(V6_A), server.S.hw_device[PHONE])

    def test_a_stale_ipv6_entry_does_not_move_its_last_seen_time_forward(self):
        self.look6({V6_A: fresh(PHONE)}, ago=600)
        self.look6({V6_A: stale(PHONE)})
        self.assertAlmostEqual(server.S.addr_use[V6_A][2], self.now - 600, delta=1)

    def test_an_ipv6_address_behind_a_range_extender_is_not_matched(self):
        server.S.shared_macs = {EXTENDER}
        self.look6({V6_A: fresh(EXTENDER)})
        self.assertIsNone(self.device_at(V6_A))

    def test_an_ipv6_address_of_an_unsettled_hardware_address_is_not_matched(self):
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)})
        self.look6({V6_A: fresh(TV)})
        self.assertIsNone(self.device_at(V6_A))

    def test_an_address_built_from_a_hardware_address_proves_nothing(self):
        self.look({OLD_SPOT: fresh(TV)})
        built = "2a00:23c8:1:2:66e7:d8ff:fe5d:c742"          # built from the TV's hardware address
        self.assertEqual(server.eui64_mac(built), TV)
        self.look6({built: fresh(LAPTOP)})                    # but the neighbour table says the laptop has it
        self.assertEqual(self.device_at(built), server.S.hw_device[LAPTOP])

    def test_an_ipv6_address_the_neighbour_table_has_not_seen_is_in_no_ones_name(self):
        self.look({OLD_SPOT: fresh(TV)})
        self.look6({})
        self.assertIsNone(self.device_at("2a00:23c8:1:2:66e7:d8ff:fe5d:c742"))

    def test_this_computers_own_ipv6_address_is_never_given_to_another_device(self):
        server.S.v6_own = {V6_A}
        self.look6({V6_A: fresh(LAPTOP)})
        self.assertEqual(self.device_at(V6_A), server.S.pi_device)

    def test_a_lookup_over_ipv6_is_judged_under_the_ipv4_address_and_filed_against_the_device(self):
        self.look({OLD_SPOT: fresh(PHONE)})
        self.look6({V6_A: fresh(PHONE)})
        server.S.v6_devices = {V6_A: OLD_SPOT}
        self.lookup(V6_A)
        self.assertEqual(server.sql("SELECT client, device FROM queries"), [(OLD_SPOT, server.S.hw_device[PHONE])])

    def test_the_address_a_lookup_came_from_decides_its_device_when_the_two_disagree(self):
        self.look({OLD_SPOT: fresh(PHONE)})                  # the phone now holds this number
        self.look6({V6_A: fresh(TV)})                         # the neighbour table says the address is the TV's
        server.S.v6_devices = {V6_A: OLD_SPOT}                # a stale match still judges it under the phone's number
        self.lookup(V6_A)
        self.assertEqual(server.sql("SELECT client, device FROM queries"), [(OLD_SPOT, server.S.hw_device[TV])])

    def test_an_ipv6_look_finishes_while_the_database_lock_is_held(self):
        # As while an older household's data is being moved: a lookup may be waiting on this look.
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (OLD_SPOT, PHONE, "", self.now), commit=True)
        done = threading.Event()
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbour_table", return_value={}), \
                mock.patch.object(server, "ipv6_neighbour_table", return_value={V6_A: fresh(PHONE)}):
            with server.db_lock:
                t = threading.Thread(target=lambda: (server.refresh_ipv6_view(), done.set()), daemon=True)
                t.start()
                finished = done.wait(10)
            t.join(10)
        self.assertTrue(finished)
        self.assertEqual(server.S.v6_devices, {V6_A: OLD_SPOT})     # matched through the last scan, read without the lock

    def test_the_ipv6_look_keeps_the_table_it_read_for_the_device_record(self):
        table = {V6_A: fresh(PHONE)}
        with mock.patch.object(server, "own_ipv6", return_value=(set(), [], "")), \
                mock.patch.object(server, "neighbour_table", return_value={}), \
                mock.patch.object(server, "ipv6_neighbour_table", return_value=table):
            server.ipv6_look()
        self.assertEqual(self.device_at(V6_A), server.S.hw_device[PHONE])

    def test_a_lookup_waiting_for_the_ipv6_look_is_woken_before_the_device_record_is_written(self):
        order = []
        with mock.patch.object(server, "refresh_ipv6_view", lambda: order.append("looked")), \
                mock.patch.object(server, "note_ipv6_addresses", lambda: order.append((server.S.v6_looking, "noted"))):
            server.ipv6_look()
        self.assertEqual(order, ["looked", (False, "noted")])

    def test_a_fault_in_the_device_record_does_not_stop_the_ipv6_look(self):
        with mock.patch.object(server, "refresh_ipv6_view", lambda: None), \
                mock.patch.object(server, "note_ipv6_addresses", side_effect=RuntimeError("no")), \
                mock.patch("builtins.print"):
            server.ipv6_look()
        self.assertFalse(server.S.v6_looking)


class HistoryAgainstTheDevice(Devices):
    def test_a_lookup_from_a_confirmed_address_is_saved_with_its_device(self):
        self.look({OLD_SPOT: fresh(TV)})
        self.lookup(OLD_SPOT)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.hw_device[TV]})

    def test_the_lookup_carries_its_device_and_where_it_came_from(self):
        self.look({OLD_SPOT: fresh(TV)})
        server.answer_query(query("www.bbc.co.uk"), OLD_SPOT, fake_answer)
        item = drain()[0]
        self.assertEqual(item[1:], (OLD_SPOT, "www.bbc.co.uk", 0, server.S.hw_device[TV], OLD_SPOT))

    def test_a_lookup_from_an_unconfirmed_address_is_saved_without_a_device(self):
        self.lookup(OLD_SPOT)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": None})

    def test_the_writer_asks_the_map_again_for_a_lookup_that_had_no_device(self):
        server.answer_query(query("www.bbc.co.uk"), OLD_SPOT, fake_answer)
        waiting = drain()
        self.look({OLD_SPOT: fresh(TV)})                     # confirmed in the second before it is written
        with server.db_lock:
            server.save_history(waiting)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.hw_device[TV]})

    def test_the_writer_asks_again_by_the_address_the_lookup_came_from(self):
        self.look({OLD_SPOT: fresh(PHONE)})
        waiting = [(self.now, OLD_SPOT, "www.bbc.co.uk", 0, None, V6_A)]   # no device when it was made; came from V6_A
        self.look6({V6_A: fresh(TV)})                         # confirmed as the TV's before it is written
        with server.db_lock:
            server.save_history(waiting)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.hw_device[TV]})

    def test_the_history_writer_saves_a_lookup_against_its_device(self):
        self.look({OLD_SPOT: fresh(TV)})
        server.answer_query(query("www.bbc.co.uk"), OLD_SPOT, fake_answer)
        prune = one_round_of_the_writer()
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.hw_device[TV]})
        prune.assert_called_once_with()

    def test_a_blocked_lookup_is_filed_against_its_device_too(self):
        self.look({OLD_SPOT: fresh(TV)})
        self.lookup(OLD_SPOT, "ads.doubleclick.net")
        self.assertEqual(server.sql("SELECT blocked, device FROM queries"), [(1, server.S.hw_device[TV])])

    def test_an_item_in_the_older_four_part_form_is_still_saved(self):
        with server.db_lock:
            server.save_history([(self.now, OLD_SPOT, "www.bbc.co.uk", 0)])
        self.assertEqual(self.filed(), {"www.bbc.co.uk": None})

    def test_a_tv_keeps_one_history_across_both_its_addresses(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.lookup(OLD_SPOT, "old.example.com")
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV)})
        self.lookup(NEW_SPOT, "new.example.com")
        tv = server.S.hw_device[TV]
        self.assertEqual(self.filed(), {"old.example.com": tv, "new.example.com": tv})

    def test_a_reused_address_keeps_the_two_devices_histories_apart(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.lookup(OLD_SPOT, "tv.example.com")
        self.look({OLD_SPOT: fresh(PHONE)})
        self.lookup(OLD_SPOT, "phone.example.com")
        self.assertEqual(self.filed(), {"tv.example.com": server.S.hw_device[TV],
                                        "phone.example.com": server.S.hw_device[PHONE]})

    def test_a_lookup_finds_its_device_without_touching_the_database(self):
        self.look({OLD_SPOT: fresh(TV)})
        real = server.db
        server.db = mock.Mock(wraps=real)
        try:
            server.answer_query(query("www.bbc.co.uk"), OLD_SPOT, fake_answer)
            touched = server.db.mock_calls
        finally:
            server.db = real
        self.assertEqual(touched, [])
        self.assertEqual(drain()[0][4], server.S.hw_device[TV])

    def test_a_lookup_does_not_wait_for_the_database_lock(self):
        self.look({OLD_SPOT: fresh(TV)})
        done = threading.Event()
        with server.db_lock:
            t = threading.Thread(target=lambda: (server.answer_query(query("www.bbc.co.uk"), OLD_SPOT, fake_answer),
                                                 done.set()), daemon=True)
            t.start()
            answered = done.wait(10)
        t.join(10)
        self.assertTrue(answered)


class TheCleanUpPass(Devices):
    def test_a_waiting_lookup_is_filed_once_a_later_look_confirms_who_was_there(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3600)
        self.look({OLD_SPOT: stale(TV)}, ago=120)             # asleep: not confirmed when it asked
        self.row(OLD_SPOT, "www.bbc.co.uk", ago=60)
        self.look({OLD_SPOT: fresh(TV)}, ago=55)              # the look after the lookup finds it awake
        self.assertEqual(server.tidy_history(self.now), 1)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.hw_device[TV]})

    def test_a_waiting_lookup_stays_waiting_until_a_look_confirms_someone(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3600)
        self.row(OLD_SPOT, "www.bbc.co.uk", ago=60)           # nobody confirmed there since
        self.assertEqual(server.tidy_history(self.now), 0)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": None})

    def test_a_lookup_made_just_before_a_device_was_first_seen_is_that_devices(self):
        self.row(OLD_SPOT, "www.bbc.co.uk", ago=60)
        self.look({OLD_SPOT: fresh(TV)}, ago=55)
        server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.hw_device[TV]})

    def test_a_lookup_made_long_before_a_device_was_first_seen_is_not_given_to_it(self):
        self.row(OLD_SPOT, "www.bbc.co.uk", ago=server.ADDRESS_GRACE + 30)
        self.look({OLD_SPOT: fresh(TV)}, ago=10)
        server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": None})

    def test_a_lookup_never_matched_to_the_device_that_came_later_is_filed_under_the_address(self):
        self.row(OLD_SPOT, "www.bbc.co.uk", ago=server.ADDRESS_WAIT + 100)
        self.look({OLD_SPOT: fresh(TV)}, ago=10)
        server.tidy_history(self.now)
        self.assertEqual(self.kind(self.filed()["www.bbc.co.uk"]), "addr")

    def test_a_lookup_from_before_the_address_changed_hands_goes_to_the_device_that_had_it_then(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3600)
        self.look({OLD_SPOT: stale(TV)}, ago=3000)
        self.row(OLD_SPOT, "tv.example.com", ago=2000)
        self.look({OLD_SPOT: fresh(TV)}, ago=1995)
        self.look({OLD_SPOT: fresh(PHONE)}, ago=20)
        server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"tv.example.com": server.S.hw_device[TV]})

    def test_a_lookup_just_before_a_new_device_took_the_address_is_the_new_devices(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3600)
        self.look({OLD_SPOT: stale(TV)}, ago=3000)            # the TV left long ago; its entry lingers
        self.row(OLD_SPOT, "phone.example.com", ago=22)
        self.look({OLD_SPOT: fresh(PHONE)}, ago=20)
        server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"phone.example.com": server.S.hw_device[PHONE]})

    def test_a_lookup_nobody_was_matched_to_is_filed_under_its_address_after_the_wait(self):
        self.row(OTHER, "www.bbc.co.uk", ago=server.ADDRESS_WAIT + 5)
        server.tidy_history(self.now)
        number = self.filed()["www.bbc.co.uk"]
        self.assertEqual(server.sql("SELECT kind, key FROM device WHERE id=?", (number,)), [("addr", "addr:" + OTHER)])

    def test_a_lookup_nobody_was_matched_to_waits_until_the_wait_is_over(self):
        self.row(OTHER, "www.bbc.co.uk", ago=server.ADDRESS_WAIT - 30)
        self.assertEqual(server.tidy_history(self.now), 0)

    def test_two_lookups_from_one_unmatched_address_share_one_address_device(self):
        self.row(V6_A, "a.example.com", ago=600)
        self.row(V6_A, "b.example.com", ago=500)
        server.tidy_history(self.now)
        self.assertEqual(len(set(self.filed().values())), 1)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='addr'")[0][0], 1)

    def test_lookups_from_a_second_live_address_are_never_joined_to_the_first_device(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3600)
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)}, ago=600)
        self.row(NEW_SPOT, "second.example.com", ago=590)
        self.look({OLD_SPOT: fresh(TV), NEW_SPOT: fresh(TV)}, ago=10)
        server.tidy_history(self.now)
        number = self.filed()["second.example.com"]
        self.assertNotEqual(number, server.S.hw_device[TV])
        self.assertEqual(self.kind(number), "addr")

    def test_lookups_behind_a_range_extender_are_filed_by_address_not_joined(self):
        server.S.shared_macs = {EXTENDER}
        self.look({OLD_SPOT: fresh(EXTENDER), NEW_SPOT: fresh(EXTENDER)})
        self.lookup(OLD_SPOT, "one.example.com")
        self.lookup(NEW_SPOT, "two.example.com")
        filed = self.filed()
        self.assertNotEqual(filed["one.example.com"], filed["two.example.com"])
        self.assertEqual({self.kind(n) for n in filed.values()}, {"addr"})

    def test_this_computers_waiting_lookups_are_its_own(self):
        self.row(PI, "www.bbc.co.uk", ago=5)
        server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.pi_device})

    def test_a_lookup_already_filed_is_left_alone(self):
        self.look({OLD_SPOT: fresh(PHONE)}, ago=50)
        self.row(OLD_SPOT, "www.bbc.co.uk", ago=40, device=server.S.pi_device)
        server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.S.pi_device})

    def test_the_pass_lets_go_of_the_lock_between_steps(self):
        for i in range(25):
            self.row(OTHER, "n%d.example.com" % i, ago=1000 + i)
        free = []

        def lock_free_for_another_thread(seconds):
            got = []

            def other():                                # db_lock is re-entrant, so ask from another thread
                ok = server.db_lock.acquire(blocking=False)
                got.append(ok)
                if ok:
                    server.db_lock.release()
            t = threading.Thread(target=other)
            t.start()
            t.join()
            free.append(got[0])
        with mock.patch.object(server, "TIDY_BATCH", 10), \
                mock.patch.object(server.time, "sleep", lock_free_for_another_thread):
            self.assertEqual(server.tidy_history(self.now), 25)
        self.assertEqual(free, [True, True])

    def test_the_pass_saves_how_recently_each_address_was_confirmed(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.look({OLD_SPOT: fresh(TV)}, ago=5)
        self.assertAlmostEqual(server.sql("SELECT last FROM address_use")[0][0], self.now - 600, delta=1)   # not yet saved
        server.tidy_history(self.now)
        self.assertAlmostEqual(server.sql("SELECT last FROM address_use")[0][0], self.now - 5, delta=1)

    def test_a_look_does_not_write_to_the_database_when_nothing_changed(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        before = server.db.total_changes
        self.look({OLD_SPOT: fresh(TV)})
        self.assertEqual(server.db.total_changes, before)
        self.assertFalse(server.db.in_transaction)

    def test_a_lookup_that_can_get_no_device_because_too_many_are_remembered_is_filed_against_no_device(self):
        self.row(OTHER, "www.bbc.co.uk", ago=server.ADDRESS_WAIT + 5)
        with mock.patch.object(server, "MAX_DEVICES", 1):     # the two fixed devices are already twice that
            server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.NO_DEVICE})

    def test_a_row_with_no_address_is_filed_against_no_device(self):
        self.row(None, "www.bbc.co.uk", ago=5)
        server.tidy_history(self.now)
        self.assertEqual(self.filed(), {"www.bbc.co.uk": server.NO_DEVICE})


class ForgettingOldDevices(Devices):
    def test_a_device_not_seen_for_thirty_days_is_forgotten(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=31 * 86400)
        self.look({OTHER: fresh(LAPTOP)})
        server.forget_old_devices(self.now)
        self.assertEqual(set(server.S.hw_device), {LAPTOP})
        self.assertEqual([a for (a,) in server.sql("SELECT addr FROM address_use")], [OTHER])

    def test_a_forgotten_device_that_comes_back_is_a_new_device(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=31 * 86400)
        old = server.S.hw_device[TV]
        server.forget_old_devices(self.now)
        self.look({OLD_SPOT: fresh(TV)})
        self.assertGreater(server.S.hw_device[TV], old)

    def test_a_device_still_on_the_network_stays_in_the_map_when_others_are_forgotten(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=31 * 86400)
        self.look({OTHER: fresh(LAPTOP)})
        server.forget_old_devices(self.now)
        self.assertEqual(self.device_at(OTHER), server.S.hw_device[LAPTOP])

    def test_a_device_first_seen_long_ago_and_seen_again_today_is_not_forgotten(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=31 * 86400)
        number = server.S.hw_device[TV]
        self.look({OLD_SPOT: fresh(TV)})
        server.forget_old_devices(self.now)
        self.assertEqual(server.S.hw_device.get(TV), number)
        self.assertEqual(self.device_at(OLD_SPOT), number)

    def test_a_device_seen_again_today_only_over_ipv6_is_not_forgotten(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=31 * 86400)
        number = server.S.hw_device[TV]
        self.look6({V6_A: fresh(TV)})
        server.forget_old_devices(self.now)
        self.assertEqual(server.S.hw_device.get(TV), number)
        self.assertEqual(self.device_at(V6_A), number)

    def test_beyond_the_limit_the_longest_unseen_address_records_go_first(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3000)
        self.look({OTHER: fresh(LAPTOP)}, ago=2000)
        self.look({NEW_SPOT: fresh(PHONE)}, ago=1000)
        with mock.patch.object(server, "MAX_ADDRESS_USE", 2):
            server.forget_old_devices(self.now)
        self.assertEqual({a for (a,) in server.sql("SELECT addr FROM address_use")}, {OTHER, NEW_SPOT})

    def test_beyond_the_limit_the_longest_unseen_devices_go_first(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3000)
        self.look({OTHER: fresh(LAPTOP)}, ago=2000)
        self.look({NEW_SPOT: fresh(PHONE)}, ago=1000)
        with mock.patch.object(server, "MAX_DEVICES", 2):
            server.forget_old_devices(self.now)
        self.assertEqual(set(server.S.hw_device), {LAPTOP, PHONE})


class DeviceList(Api):
    """GET /api/devices and /api/activity by device, through the real web server."""

    def setUp(self):
        super().setUp()
        saved = server.S.local_ip
        server.S.local_ip, server.S.router, server.S.router_checked = PI, ROUTER, float("inf")
        self.addCleanup(setattr, server.S, "local_ip", saved)
        self.addCleanup(setattr, server.S, "router", "")
        server.rebuild_address_map()
        self.now = time.time()
        drain()

    def look(self, table, ago=0):
        server.note_ipv4_addresses(table, now=self.now - ago)

    def lookup(self, address, name="www.bbc.co.uk"):
        server.answer_query(query(name), address, fake_answer)
        with server.db_lock:
            server.save_history(drain())

    def devices(self, everything=False):
        status, out = self.get("/api/devices" + ("?all=1" if everything else ""))
        self.assertEqual(status, 200)
        return out

    def names_for(self, number, ip=""):
        _, groups = self.get("/api/activity?ip=%s&device=%s&hours=24" % (ip, number))
        return sorted(h["d"] for g in groups for h in g["hosts"])

    def tv_moves(self):
        """The TV looks something up at .65, moves to .67 and looks something else up."""
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.lookup(OLD_SPOT, "old.example.com")
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV)})
        self.lookup(NEW_SPOT, "new.example.com")
        return server.S.hw_device[TV]

    def address_changes_hands(self):
        """The TV looks something up at .65 and leaves; a phone gets .65 and looks something up."""
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.lookup(OLD_SPOT, "tv.example.com")
        self.look({OLD_SPOT: fresh(PHONE)})
        self.lookup(OLD_SPOT, "phone.example.com")
        return server.S.hw_device[TV], server.S.hw_device[PHONE]

    def test_the_tv_that_moved_is_one_entry_at_its_new_address_with_both_histories(self):
        tv = self.tv_moves()
        devices = self.devices()
        self.assertEqual(len(devices), 1)
        d = devices[0]
        self.assertEqual((d["id"], d["ip"], d["n"], d["kind"], d["macs"], d["mac"]), (tv, NEW_SPOT, 2, "hw", [TV], TV))

    def test_an_entry_lists_the_addresses_the_device_has_and_recently_had(self):
        self.tv_moves()
        addresses = self.devices()[0]["addresses"]
        self.assertEqual([(a["address"], a["now"]) for a in addresses], [(NEW_SPOT, True), (OLD_SPOT, False)])
        self.assertAlmostEqual(addresses[1]["last"], self.now - 600, delta=2)

    def test_an_address_last_used_more_than_a_day_ago_is_not_listed_with_the_device(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=3 * 86400)
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV)})
        self.lookup(NEW_SPOT)
        self.assertEqual([a["address"] for a in self.devices()[0]["addresses"]], [NEW_SPOT])

    def test_ipv6_addresses_are_listed_with_the_device_after_its_ipv4_address(self):
        self.look({OLD_SPOT: fresh(PHONE)})
        server.note_ipv6_addresses({V6_A: fresh(PHONE), V6_B: fresh(PHONE)}, now=self.now)
        self.lookup(OLD_SPOT)
        d = self.devices()[0]
        self.assertEqual(d["ip"], OLD_SPOT)
        self.assertEqual([a["address"] for a in d["addresses"]], [OLD_SPOT, V6_A, V6_B])

    def test_no_more_than_the_limit_of_addresses_are_listed_with_one_device(self):
        self.look({OLD_SPOT: fresh(PHONE)})
        many = ["2a00:23c8:1:2::%x" % n for n in range(1, 6)]
        server.note_ipv6_addresses({addr: fresh(PHONE) for addr in many}, now=self.now)
        self.lookup(OLD_SPOT)
        with mock.patch.object(server, "MAX_LISTED_ADDRESSES", 3):
            listed = [a["address"] for a in self.devices()[0]["addresses"]]
        self.assertEqual(listed, [OLD_SPOT] + many[:2])

    def test_a_device_never_seen_over_ipv4_is_listed_under_its_ipv6_address(self):
        server.note_ipv6_addresses({V6_A: fresh(PHONE)}, now=self.now)
        phone = server.S.hw_device[PHONE]
        server.sql("INSERT INTO queries(ts,client,domain,blocked,device) VALUES(?,?,?,0,?)",
                   (self.now - 5, V6_A, "sixer.example.com", phone), commit=True)
        self.assertEqual([(d["id"], d["ip"], d["n"]) for d in self.devices()], [(phone, V6_A, 1)])

    def test_a_reused_address_shows_each_device_its_own_history(self):
        tv, phone = self.address_changes_hands()
        self.assertEqual(self.names_for(tv), ["tv.example.com"])
        self.assertEqual(self.names_for(phone, OLD_SPOT), ["phone.example.com"])

    def test_the_device_that_has_the_address_now_is_the_one_listed_under_it(self):
        tv, phone = self.address_changes_hands()
        listed = {d["id"]: d for d in self.devices()}
        self.assertEqual((listed[phone]["ip"], listed[phone]["n"]), (OLD_SPOT, 1))

    def test_a_device_that_left_and_whose_address_went_to_another_has_no_address_but_keeps_its_history(self):
        tv, phone = self.address_changes_hands()
        listed = {d["id"]: d for d in self.devices(everything=True)}
        self.assertEqual((listed[tv]["ip"], listed[tv]["n"]), ("", 1))

    def test_a_device_with_no_address_of_its_own_is_only_listed_when_asked_for(self):
        tv, phone = self.address_changes_hands()
        self.assertEqual([d["id"] for d in self.devices()], [phone])
        self.assertEqual(sorted(d["id"] for d in self.devices(everything=True)), sorted([tv, phone]))

    def test_no_two_entries_share_an_address(self):
        self.address_changes_hands()
        self.look({OLD_SPOT: fresh(PHONE), NEW_SPOT: fresh(LAPTOP)})
        self.lookup(NEW_SPOT)
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (OLD_SPOT, TV, "", self.now - 900), commit=True)
        server.set_internet_off("device:" + OLD_SPOT, True)   # a rule on the address two devices have had
        self.ok("/api/device-name", {"ip": NEW_SPOT, "name": "Laptop"})
        listed = self.devices(everything=True)
        self.assertEqual(len(listed), 3)
        ips = [d["ip"] for d in listed if d["ip"]]
        self.assertEqual(len(ips), len(set(ips)))

    def test_a_named_address_the_last_scan_saw_another_device_at_is_listed_once(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (OLD_SPOT, TV, "", self.now - 600), commit=True)
        self.look({NEW_SPOT: fresh(TV), OLD_SPOT: fresh(PHONE)})          # the TV moves, and a phone is given its number
        self.lookup(OLD_SPOT)
        self.lookup(NEW_SPOT)
        self.ok("/api/device-name", {"ip": OLD_SPOT, "name": "Sam's phone"})
        listed = self.devices(everything=True)
        self.assertEqual(sorted(d["ip"] for d in listed), [OLD_SPOT, NEW_SPOT])
        here = [d for d in listed if d["ip"] == OLD_SPOT][0]
        self.assertEqual((here["kind"], here["macs"], here["name"], here["on_network"]), ("hw", [PHONE], "Sam's phone", 0))

    def test_a_scan_of_another_device_at_an_address_with_a_warning_does_not_list_the_address_twice(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (OLD_SPOT, TV, "", self.now - 600), commit=True)
        self.look({NEW_SPOT: fresh(TV), OLD_SPOT: fresh(PHONE)})
        self.lookup(OLD_SPOT)
        with mock.patch.object(server.S, "device_warnings", {server.S.hw_device[TV]: "Its hardware address is at two numbers."}):
            listed = self.devices(everything=True)
        self.assertEqual(sorted(d["ip"] for d in listed), [OLD_SPOT, NEW_SPOT])

    def test_a_device_whose_old_address_this_computer_now_has_is_not_listed_under_it(self):
        self.look({OTHER: fresh(LAPTOP)}, ago=600)
        self.lookup(OTHER, "laptop.example.com")
        self.look({})                                         # the laptop has gone
        server.S.local_ip = OTHER                             # and the router gave this computer its number
        server.rebuild_address_map()
        self.lookup("127.0.0.1", "pi.example.com")
        listed = {d["id"]: d for d in self.devices(everything=True)}
        self.assertEqual(listed[server.S.pi_device]["ip"], OTHER)
        self.assertEqual((listed[server.S.hw_device[LAPTOP]]["ip"], listed[server.S.hw_device[LAPTOP]]["addresses"]), ("", []))

    def test_a_device_found_only_by_a_scan_is_listed_under_the_address_it_was_found_at(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.look({})                                         # no longer in the neighbour table
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (OLD_SPOT, TV, "tv", self.now - 60), commit=True)
        d = self.devices()[0]
        self.assertEqual((d["id"], d["ip"], d["last"]), (server.S.hw_device[TV], OLD_SPOT, 0))
        self.assertAlmostEqual(d["on_network"], self.now - 60, delta=2)

    def test_a_scan_of_a_device_no_look_has_seen_is_listed_by_address(self):
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (OTHER, LAPTOP, "", self.now), commit=True)
        d = self.devices()[0]
        self.assertEqual((d["id"], d["kind"], d["ip"], d["mac"], d["macs"]), (None, "addr", OTHER, LAPTOP, [LAPTOP]))

    def test_an_old_scan_of_another_device_does_not_count_for_the_device_there_now(self):
        self.look({OLD_SPOT: fresh(PHONE)})
        self.lookup(OLD_SPOT)
        server.sql("INSERT INTO seen(ip, mac, host, ts) VALUES(?,?,?,?)", (OLD_SPOT, "3c:22:fb:00:00:01", "old-laptop",
                                                                         self.now - 900), commit=True)
        d = [d for d in self.devices() if d["id"] == server.S.hw_device[PHONE]][0]
        self.assertEqual((d["on_network"], d["hint"]), (0, ""))

    def test_names_and_rules_are_read_from_the_address_the_device_is_listed_under(self):
        self.tv_moves()
        self.ok("/api/device-name", {"ip": NEW_SPOT, "name": "Living room TV"})
        server.set_internet_off("device:" + NEW_SPOT, True)
        d = self.devices()[0]
        self.assertEqual((d["name"], d["off"]), ("Living room TV", True))

    def test_a_rule_given_by_a_devices_old_address_reaches_the_device_and_adds_no_entry(self):
        tv = self.tv_moves()
        server.set_service_block("device:" + OLD_SPOT, "youtube", True)       # the TV was the last device seen there
        listed = self.devices(everything=True)
        self.assertEqual([(d["id"], d["ip"]) for d in listed], [(tv, NEW_SPOT)])
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % tv: {"youtube"}})

    def left_and_replaced(self):
        """The TV leaves and a phone is given its number, so the TV has no address of its own.
        Returns the TV's number."""
        tv, _ = self.address_changes_hands()
        self.assertEqual([d["id"] for d in self.devices()], [server.S.hw_device[PHONE]])
        return tv

    def entry_of(self, number):
        """The entry of one device in the full list (GET /api/devices?all=1)."""
        return [d for d in self.devices(everything=True) if d["id"] == number][0]

    def test_a_device_that_left_keeps_its_internet_switch_and_is_still_listed(self):
        tv = self.left_and_replaced()
        server.set_internet_off("dev:%d" % tv, True)
        self.assertEqual((self.entry_of(tv)["ip"], self.entry_of(tv)["off"]), ("", True))

    def test_a_device_that_left_keeps_its_name_and_is_still_listed(self):
        tv = self.left_and_replaced()
        self.ok("/api/device-name", {"device": tv, "name": "Old telly"})
        self.assertEqual(self.entry_of(tv)["name"], "Old telly")

    def test_a_device_that_left_keeps_its_group_and_is_still_listed(self):
        tv = self.left_and_replaced()
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/device-group", {"device": tv, "group": gid})
        self.assertEqual(self.entry_of(tv)["group"], gid)

    def test_a_device_with_only_a_schedule_and_no_history_is_listed(self):
        tv = self.left_and_replaced()
        server.sql("DELETE FROM queries", commit=True)
        self.schedule(scope="dev:%d" % tv)
        self.assertEqual(self.entry_of(tv)["id"], tv)

    def test_a_device_that_left_keeps_cut_live_connections_and_is_still_listed(self):
        tv = self.left_and_replaced()
        self.ok("/api/enforce", {"device": tv, "on": True})
        self.assertTrue(self.entry_of(tv)["enforced"])

    def test_the_device_now_at_a_number_does_not_get_the_rules_of_the_device_that_left(self):
        tv = self.left_and_replaced()
        server.set_internet_off("dev:%d" % tv, True)
        phone = [d for d in self.devices() if d["ip"] == OLD_SPOT][0]
        self.assertEqual((phone["id"], phone["off"]), (server.S.hw_device[PHONE], False))

    def test_a_rule_set_while_a_device_was_away_goes_with_it_when_it_returns_elsewhere(self):
        self.look({OLD_SPOT: fresh(PHONE)}, ago=600)
        self.lookup(OLD_SPOT)
        self.look({})                                         # the phone leaves; its card stays, under its last address
        self.assertEqual([d["ip"] for d in self.devices()], [OLD_SPOT])
        self.ok("/api/internet", {"scope": "device:" + OLD_SPOT, "off": True})
        self.ok("/api/device-name", {"ip": OLD_SPOT, "name": "Sam's phone"})
        self.look({NEW_SPOT: fresh(PHONE)})                   # and it comes back at another address
        listed = self.devices()
        self.assertEqual([(d["ip"], d["id"], d["off"], d["name"]) for d in listed],
                         [(NEW_SPOT, server.S.hw_device[PHONE], True, "Sam's phone")])

    def test_a_device_whose_name_was_cleared_is_not_listed_for_that_alone(self):
        tv = self.left_and_replaced()
        server.sql("DELETE FROM queries", commit=True)
        self.ok("/api/device-name", {"device": tv, "name": "Old telly"})
        self.assertIn(tv, [d["id"] for d in self.devices(everything=True)])
        self.ok("/api/device-name", {"device": tv, "name": ""})
        self.assertNotIn(tv, [d["id"] for d in self.devices(everything=True)])

    def test_naming_an_address_no_device_is_known_for_makes_it_a_device_known_by_that_address(self):
        self.ok("/api/device-name", {"ip": OTHER, "name": "Spare tablet"})
        self.assertEqual([(d["ip"], d["kind"], d["name"]) for d in self.devices()], [(OTHER, "addr", "Spare tablet")])
        self.assertEqual(self.devices()[0]["id"], server.S.addr_only[OTHER])

    def test_a_request_that_names_a_card_by_its_address_reaches_the_device_that_card_shows(self):
        self.address_changes_hands()
        self.ok("/api/device-name", {"ip": OLD_SPOT, "name": "Sam's phone"})
        self.assertEqual(server.S.given, {server.S.hw_device[PHONE]: "Sam's phone"})


    def test_lookups_waiting_to_be_filed_count_for_the_device_that_has_the_address_now(self):
        self.look({OLD_SPOT: fresh(TV)})
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,1)", (self.now - 30, OLD_SPOT, "a.example.com"),
                   commit=True)
        d = self.devices()[0]
        self.assertEqual((d["id"], d["n"], d["nb"]), (server.S.hw_device[TV], 1, 1))
        self.assertAlmostEqual(d["last"], self.now - 30, delta=2)

    def test_lookups_waiting_to_be_filed_show_in_the_devices_activity(self):
        self.look({OLD_SPOT: fresh(TV)})
        self.lookup(OLD_SPOT, "filed.example.com")
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", (self.now - 30, OLD_SPOT, "waiting.example.com"),
                   commit=True)
        self.assertEqual(self.names_for(server.S.hw_device[TV], OLD_SPOT), ["filed.example.com", "waiting.example.com"])

    def test_an_address_with_no_hardware_address_is_one_entry_for_its_filed_and_waiting_lookups(self):
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", (self.now - 600, OTHER, "filed.example.com"),
                   commit=True)
        server.tidy_history(self.now)                         # nobody was matched: filed under the address
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", (self.now - 5, OTHER, "waiting.example.com"),
                   commit=True)
        devices = self.devices()
        self.assertEqual([(d["ip"], d["kind"], d["n"]) for d in devices], [(OTHER, "addr", 2)])
        self.assertEqual(self.names_for(devices[0]["id"], OTHER), ["filed.example.com", "waiting.example.com"])

    def test_this_computer_is_listed_as_the_pi_device(self):
        self.lookup("127.0.0.1")
        d = self.devices()[0]
        self.assertEqual((d["kind"], d["id"], d["ip"], d["this_computer"]), ("pi", server.S.pi_device, PI, True))

    def test_the_router_is_listed_as_the_hub_device_once_it_has_history(self):
        self.look({ROUTER: fresh(ROUTER_MAC)})
        self.lookup(ROUTER)
        d = self.devices()[0]
        self.assertEqual((d["kind"], d["id"], d["ip"], d["macs"]), ("hub", server.S.hub_device, ROUTER, [ROUTER_MAC]))

    def test_an_address_behind_a_range_extender_is_listed_as_known_by_its_address(self):
        server.S.shared_macs = {EXTENDER}
        self.look({OLD_SPOT: fresh(EXTENDER)})
        self.lookup(OLD_SPOT)
        d = self.devices()[0]
        self.assertEqual((d["kind"], d["ip"], d["macs"]), ("addr", OLD_SPOT, []))

    def test_a_name_found_for_any_of_a_devices_addresses_is_offered_as_its_hint(self):
        self.tv_moves()
        with mock.patch.object(server.S, "hints", {OLD_SPOT: {"name": "Samsung TV", "source": "mDNS", "detail": ""}}):
            d = self.devices()[0]
        self.assertEqual((d["ip"], d["hint"], d["hint_source"]), (NEW_SPOT, "Samsung TV", "mDNS"))

    def test_a_try_at_another_dns_service_from_any_of_a_devices_addresses_is_flagged(self):
        self.tv_moves()
        tried = time.time() - 60
        with mock.patch.object(server.S, "other_dns", {OLD_SPOT: tried}):
            self.assertEqual(self.devices()[0]["other_dns"], tried)

    def test_a_device_number_must_be_a_whole_number_of_a_known_device(self):
        tv = self.tv_moves()
        self.assertEqual((server.device_number(tv), server.device_number(str(tv))), (tv, tv))
        for wrong in (True, None, "", "x", "1.5", [tv], 10 ** 9, float("inf"), float("-inf"), float("nan"), "1e999"):
            self.assertIsNone(server.device_number(wrong), wrong)

    def test_activity_by_device_number_covers_every_address_the_device_had(self):
        tv = self.tv_moves()
        self.assertEqual(self.names_for(tv, NEW_SPOT), ["new.example.com", "old.example.com"])

    def test_activity_by_address_alone_is_what_was_recorded_under_that_address(self):
        self.tv_moves()
        _, groups = self.get("/api/activity?ip=%s&hours=24" % NEW_SPOT)
        self.assertEqual([h["d"] for g in groups for h in g["hosts"]], ["new.example.com"])

    def test_activity_with_a_device_number_quietnet_does_not_know_falls_back_to_the_address(self):
        self.tv_moves()
        for unknown in ("99999", "abc", "-1", "1.5"):
            _, groups = self.get("/api/activity?ip=%s&device=%s&hours=24" % (NEW_SPOT, unknown))
            self.assertEqual([h["d"] for g in groups for h in g["hosts"]], ["new.example.com"], unknown)

    def test_activity_by_device_shows_the_block_decisions_of_the_address_given(self):
        tv = self.tv_moves()
        server.set_internet_off("device:" + NEW_SPOT, True)
        _, groups = self.get("/api/activity?ip=%s&device=%s&hours=24" % (NEW_SPOT, tv))
        self.assertTrue(all(g["b"] for g in groups))

    def test_activity_by_device_with_no_address_uses_the_devices_own_address_for_decisions(self):
        tv = self.tv_moves()
        server.set_internet_off("device:" + NEW_SPOT, True)
        _, groups = self.get("/api/activity?device=%s&hours=24" % tv)
        self.assertTrue(all(g["b"] for g in groups))

    def test_the_activity_marker_for_a_device_changes_when_it_looks_something_up_at_another_address(self):
        self.look({OLD_SPOT: fresh(TV)}, ago=600)
        self.lookup(OLD_SPOT, "old.example.com")
        tv = server.S.hw_device[TV]
        path = "/api/activity?ip=%s&device=%s&hours=24&since=%%s" % (OLD_SPOT, tv)
        first = self.get(path % "")[1]["marker"]
        self.assertTrue(self.get(path % first)[1]["unchanged"])
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV)})
        self.lookup(NEW_SPOT, "new.example.com")
        self.assertFalse(self.get(path % first)[1]["unchanged"])

    def test_the_activity_marker_for_a_device_changes_when_a_waiting_lookup_arrives(self):
        self.look({OLD_SPOT: fresh(TV)})
        self.lookup(OLD_SPOT, "old.example.com")
        path = "/api/activity?ip=%s&device=%s&hours=24&since=%%s" % (OLD_SPOT, server.S.hw_device[TV])
        first = self.get(path % "")[1]["marker"]
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", (time.time(), OLD_SPOT, "waiting.example.com"),
                   commit=True)
        self.assertFalse(self.get(path % first)[1]["unchanged"])

    def test_the_activity_marker_for_a_device_changes_when_waiting_lookups_are_filed(self):
        self.look({OLD_SPOT: fresh(TV)})
        self.lookup(OLD_SPOT, "old.example.com")
        path = "/api/activity?ip=%s&device=%s&hours=24&since=%%s" % (OLD_SPOT, server.S.hw_device[TV])
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", (time.time() - 5, OTHER, "other.example.com"),
                   commit=True)
        first = self.get(path % "")[1]["marker"]
        self.look({OLD_SPOT: fresh(TV), OTHER: fresh(LAPTOP)})
        self.assertEqual(server.tidy_history(), 1)
        self.assertFalse(self.get(path % first)[1]["unchanged"])

    def test_clearing_a_device_by_number_clears_its_history_at_every_address(self):
        tv = self.tv_moves()
        self.look({OLD_SPOT: stale(TV), NEW_SPOT: fresh(TV), OTHER: fresh(LAPTOP)})
        self.lookup(OTHER, "laptop.example.com")
        self.ok("/api/clear-history", {"ip": NEW_SPOT, "device": tv})
        server.last_clear.join(30)
        self.assertEqual(server.sql("SELECT domain FROM queries"), [("laptop.example.com",)])

    def test_clearing_a_device_by_number_clears_its_waiting_lookups_too(self):
        self.look({OLD_SPOT: fresh(TV), OTHER: fresh(LAPTOP)})
        for address, name in ((OLD_SPOT, "waiting.example.com"), (OTHER, "laptop-waiting.example.com")):
            server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", (self.now, address, name), commit=True)
        self.ok("/api/clear-history", {"device": server.S.hw_device[TV]})
        server.last_clear.join(30)
        self.assertEqual(server.sql("SELECT domain FROM queries"), [("laptop-waiting.example.com",)])

    def test_clearing_by_number_alone_leaves_other_devices_history(self):
        self.look({OLD_SPOT: fresh(TV), OTHER: fresh(LAPTOP)})
        self.lookup(OLD_SPOT, "tv.example.com")
        self.lookup(OTHER, "laptop.example.com")
        self.ok("/api/clear-history", {"device": server.S.hw_device[TV]})
        server.last_clear.join(30)
        self.assertEqual(server.sql("SELECT domain FROM queries"), [("laptop.example.com",)])

    def test_clearing_one_device_leaves_another_devices_history_at_the_same_address(self):
        tv, phone = self.address_changes_hands()
        self.ok("/api/clear-history", {"ip": OLD_SPOT, "device": phone})
        server.last_clear.join(30)
        self.assertEqual(server.sql("SELECT domain FROM queries"), [("tv.example.com",)])

    def test_clearing_with_a_device_number_quietnet_does_not_know_and_no_address_clears_nothing(self):
        self.tv_moves()
        # An infinite number is sent as "Infinity", which the server's reading of JSON accepts.
        for unknown in (99999, "abc", None, True, [1], float("inf")):
            status, out = self.post("/api/clear-history", {"device": unknown})
            self.assertEqual(status, 400, unknown)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries")[0][0], 2)

    def test_clearing_with_a_device_number_too_large_to_be_one_falls_back_to_the_address(self):
        self.tv_moves()
        self.ok("/api/clear-history", {"device": float("inf"), "ip": NEW_SPOT})
        server.last_clear.join(30)
        self.assertEqual(server.sql("SELECT domain FROM queries"), [("old.example.com",)])

    def test_clearing_a_devices_history_in_steps_lets_go_of_the_lock_between_them(self):
        self.look({OLD_SPOT: fresh(TV)})
        for i in range(25):
            self.lookup(OLD_SPOT, "n%d.example.com" % i)
        pauses = []
        with mock.patch.object(server, "PRUNE_BATCH", 10), \
                mock.patch.object(server.time, "sleep", lambda s: pauses.append(server.db.in_transaction)):
            server.clear_history(device=server.S.hw_device[TV])
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries")[0][0], 0)
        self.assertEqual(pauses, [False, False])

    def test_history_by_device_is_answered_from_an_index(self):
        # A month of a household's lookups: a question that reads every row makes the dashboard crawl.
        def plan(statement, args):
            return " | ".join(row[-1] for row in server.sql("EXPLAIN QUERY PLAN " + statement, args))
        whole = plan(server.DEVICE_HISTORY_SQL, (0,))
        self.assertNotIn("SCAN queries", whole)
        self.assertIn("COVERING INDEX q_device_ts (device=? AND ts>?)", whole)
        self.assertIn("COVERING INDEX q_device_ts (device>?)", whole)
        self.assertIn("INDEX q_device_ts (device=? AND ts>?)", plan(server.DEVICE_ACTIVITY_SQL, (1, 0)))
        self.assertIn("INDEX q_client_ts (client=? AND ts>?)", plan(server.UNFILED_ACTIVITY_SQL, (PI, 0)))
        self.assertIn("INDEX q_device_ts (device=? AND ts>?)", plan(server.UNFILED_COUNTS_SQL, (0,)))
        newest = plan(server.NEWEST_BY_ADDRESS_SQL, ())
        self.assertNotIn("SCAN queries", newest)
        self.assertIn("q_client_ts (client=?)", newest)
        self.assertIn("COVERING INDEX q_device_ts (device=?)", plan(server.NEWEST_FOR_NUMBER_SQL, (1,)))
        self.assertIn("COVERING INDEX q_device_ts (device=? AND ts>?)", plan(server.OLDEST_FOR_NUMBER_SQL, (1, 0)))

    def test_the_clean_up_pass_and_the_clears_find_their_rows_through_an_index(self):
        def plan(statement, args):
            return " | ".join(row[-1] for row in server.sql("EXPLAIN QUERY PLAN " + statement, args))
        for statement, args in ((server.UNFILED_SQL, (0, 1)), (server.UNFILED_NEXT_SQL, (0, 1))):
            self.assertIn("INDEX q_device_ts (device=? AND ts>?)", plan(statement, args))
        self.assertIn("INDEX q_device_ts (device=? AND ts<?)", plan(server.FILL_SQL, (0, 1)))
        self.assertIn("q_device_ts (device=?", plan(server.CLEAR_BY_NUMBER_SQL, (1, 0, 1)))
        self.assertIn("q_client_ts (client=?", plan(server.CLEAR_UNFILED_SQL, (PI, 0, 1)))
        self.assertIn("INDEX address_use_addr (addr=?)",
                      plan("SELECT device, first, last FROM address_use WHERE addr=? ORDER BY first, rowid", (PI,)))

    def test_the_device_list_does_not_wait_for_the_database_lock(self):
        self.tv_moves()
        rows = server.sql("SELECT ip, name FROM devices")      # the two small questions still on the main connection
        done = threading.Event()
        with mock.patch.object(server, "sql", lambda *a, **k: rows):
            with server.db_lock:
                t = threading.Thread(target=lambda: (server.api_devices(), done.set()), daemon=True)
                t.start()
                finished = done.wait(10)
            t.join(10)
        self.assertTrue(finished)

    def test_the_status_says_the_device_tables_are_ready(self):
        self.assertEqual(self.get("/api/status")[1]["devices"],
                         {"state": "ready", "notice": "", "filling": False, "report": [], "conflicts": [], "old_rules": 0})


class TheDashboardPage(unittest.TestCase):
    """The few places the dashboard page uses the device's number. Reads the page's script only;
    nothing is run in a browser."""

    @classmethod
    def setUpClass(cls):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "static", "index.html"), encoding="utf-8") as f:
            cls.page = f.read()
        cls.notice = cls.page[cls.page.index("function devicesNotice("):cls.page.index("function noIpv6Switch(")]

    def test_the_page_asks_for_activity_by_the_devices_number_when_it_has_one(self):
        self.assertIn("${id ? '&device=' + encodeURIComponent(id) : ''}", self.page)

    def test_the_page_clears_history_by_the_devices_number_when_it_has_one(self):
        self.assertIn("id ? {ip:S.device, device:id} : {ip:S.device}", self.page)

    def test_the_page_only_takes_a_whole_number_as_a_devices_number(self):
        self.assertIn("Number.isInteger(d.id) ? String(d.id) : ''", self.page)

    def test_the_page_leaves_out_entries_with_no_address_of_their_own(self):
        self.assertIn("api('/api/devices').then(x => S.devices = x.filter(d => d.ip))", self.page)

    def test_the_note_about_the_move_is_shown_on_the_home_page(self):
        home = self.page[self.page.index("function viewHome(){"):self.page.index("// The household setting \"Stop every device")]
        self.assertIn("${devicesNotice()}", home)

    def test_the_note_about_the_move_is_escaped(self):
        self.assertIn("${esc(dv.notice)}", self.notice)
        self.assertNotIn("${dv.notice}", self.notice)
        self.assertNotIn("${dv.old_rules}", self.notice)
        self.assertNotIn("${c.", self.notice)
        self.assertNotIn("${line}", self.notice)

    def test_rules_left_for_the_owner_to_decide_are_shown_with_the_three_choices(self):
        self.assertIn("(dv.conflicts || []).map(c =>", self.notice)
        self.assertIn("${esc(c.text)}", self.notice)
        for choice, label in (("give", "Give them to the device"), ("remove", "Remove them"),
                              ("keep", "Leave them with the number")):
            self.assertIn("choose(c, '%s', '%s'" % (choice, label), self.notice)
        self.assertIn('data-act="conflict" data-id="${esc(c.id)}" data-choice="${choice}"', self.notice)
        self.assertIn("api('/api/rule-conflict', {id:+d.id, choice:d.choice})", self.page)

    def test_rules_left_for_the_owner_say_what_applies_until_a_choice_is_made(self):
        self.assertIn("Until you choose, they stay with that number and apply to whichever device has it.", self.notice)

    def test_rules_an_older_version_left_behind_are_offered_not_brought_in_unasked(self):
        self.assertIn("dv.old_rules ?", self.notice)
        self.assertIn("${num(dv.old_rules)}", self.notice)
        self.assertIn('<button class="btn" data-act="oldrules">Bring them in</button>', self.notice)
        self.assertIn("api('/api/move-old-rules', {})", self.page)

    def test_the_report_of_the_move_is_on_the_home_page_and_escaped(self):
        home = self.page[self.page.index("function viewHome(){"):self.page.index("// The household setting \"Stop every device")]
        self.assertIn("${moveReport()}", home)
        self.assertIn("${esc(line)}", self.notice)
        self.assertIn("if(!lines.length) return '';", self.notice)

    def test_the_page_names_a_device_by_its_number_as_well_as_its_address_when_it_changes_it(self):
        self.assertIn("const who = ip => { const id = deviceId(ip); return id ? {ip, device:id} : {ip}; };", self.page)
        for call in ("api('/api/device-name', Object.assign(who(ip), {name}))",
                     "api('/api/device-group', Object.assign(who(S.device), {group:",
                     "api('/api/enforce', Object.assign(who(S.device), {on:e.target.checked}))"):
            self.assertIn(call, self.page)

    def test_the_page_keeps_a_devices_rules_under_its_number_when_it_has_one(self):
        self.assertIn("return id ? 'dev:' + id : 'device:' + ip;", self.page)
        self.assertIn("${controls(scopeOf(S.device), 'this device')}", self.page)
        self.assertIn("jobs.push(ctl(scopeOf(S.device)))", self.page)

    def test_the_page_matches_a_schedule_to_a_device_by_its_number(self):
        self.assertIn("x.scope === scope || (x.device != null && scope === 'dev:' + x.device)", self.page)
        self.assertIn("S.schedules.filter(x => forScope(x, scope))", self.page)
        self.assertIn("if(x.device != null) S.edit.scope = 'dev:' + x.device;", self.page)

    def test_the_note_about_the_move_copes_with_a_pi_that_sends_none(self):
        self.assertIn("const dv = (S.status || {}).devices || {};", self.notice)
        self.assertIn("(dv.conflicts || [])", self.notice)
        self.assertIn("((S.status || {}).devices || {}).report || []", self.notice)


OLD_TABLES = """
    CREATE TABLE queries(id INTEGER PRIMARY KEY, ts REAL, client TEXT, domain TEXT, blocked INTEGER);
    CREATE INDEX q_client_ts ON queries(client, ts);
    CREATE INDEX q_ts ON queries(ts, client, blocked);
    CREATE TABLE blocked(domain TEXT PRIMARY KEY, ts REAL);
    CREATE TABLE allowed(domain TEXT PRIMARY KEY, ts REAL);
    CREATE TABLE devices(ip TEXT PRIMARY KEY, name TEXT);
    CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE groups(id INTEGER PRIMARY KEY, name TEXT);
    CREATE TABLE schedules(id INTEGER PRIMARY KEY, name TEXT, scope TEXT, days TEXT,
        t_from TEXT, t_to TEXT, off INTEGER, services TEXT, enabled INTEGER);
    CREATE TABLE seen(ip TEXT PRIMARY KEY, mac TEXT, host TEXT, ts REAL);
    CREATE TABLE device_group(ip TEXT PRIMARY KEY, gid INTEGER);
    CREATE TABLE service_blocks(scope TEXT, service TEXT, PRIMARY KEY(scope, service));
    CREATE TABLE internet_off(scope TEXT PRIMARY KEY);
    CREATE TABLE enforced(ip TEXT PRIMARY KEY, mac TEXT);
    CREATE TABLE device_mac(ip TEXT PRIMARY KEY, mac TEXT, paused INTEGER DEFAULT 0, guest_mac TEXT, guest_gid INTEGER);
    CREATE TABLE known_macs(mac TEXT PRIMARY KEY, ip TEXT, first REAL, last REAL);
    CREATE INDEX known_macs_last ON known_macs(last);
    CREATE TABLE shared_macs(mac TEXT PRIMARY KEY, hits INTEGER, last REAL);
    CREATE TABLE events(id INTEGER PRIMARY KEY, ts REAL, ip TEXT, text TEXT);
"""


class OlderHousehold(Base):
    """Shared steps: QuietNet started on a database made before the device tables, in a throwaway
    folder, with the household described by `household()`. The usual test database is put back
    afterwards."""

    def household(self, old):
        """Fill the older database. `old` is its connection; the tests' classes add to this."""
        now = self.now
        old.executemany("INSERT INTO known_macs VALUES(?,?,?,?)", [
            (TV, NEW_SPOT, now - 20 * 86400, now - 60), (PHONE, OTHER, now - 5 * 86400, now - 120)])
        old.execute("INSERT INTO seen VALUES(?,?,?,?)", (OLD_SPOT, TV, "tv", now - 10 * 86400))
        old.execute("INSERT INTO seen VALUES(?,?,?,?)", (ROUTER, ROUTER_MAC, "hub", now - 10 * 86400))
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,0)", (OTHER, PHONE))
        old.execute("INSERT INTO devices VALUES(?,?)", (OTHER, "Sam's phone"))
        old.execute("INSERT INTO service_blocks VALUES(?,?)", ("device:" + OTHER, "youtube"))
        old.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,?)", [
            (now - 9 * 86400, OLD_SPOT, "old.example.com", 0), (now - 3600, NEW_SPOT, "new.example.com", 0),
            (now - 1800, OTHER, "phone.example.com", 1), (now - 900, "192.168.1.99", "stranger.example.com", 0),
            (now - 600, V6_A, "sixer.example.com", 0), (now - 300, PI, "pi.example.com", 0),
            (now - 200, ROUTER, "hub.example.com", 0)])

    def setUp(self):
        super().setUp()
        self.now = time.time()
        self.usual, self.folder = server.DATA, tempfile.mkdtemp(prefix="quietnet-older-")
        saved = server.S.local_ip
        self.addCleanup(setattr, server.S, "local_ip", saved)
        self.addCleanup(setattr, server.S, "router", "")
        self.addCleanup(self.back_to_the_usual_database)
        old = sqlite3.connect(os.path.join(self.folder, "quietnet.db"))
        old.executescript(OLD_TABLES)
        self.household(old)
        old.commit()
        old.close()
        server.db.close()
        server.DATA = self.folder
        server.init_db()
        server.S.local_ip, server.S.router, server.S.router_checked = PI, ROUTER, float("inf")
        quiet = mock.patch("builtins.print")
        quiet.start()
        self.addCleanup(quiet.stop)
        drain()

    def back_to_the_usual_database(self):
        server.db.close()
        server.DATA = self.usual
        server.init_db()
        shutil.rmtree(self.folder, ignore_errors=True)

    def copy(self):
        """Where the copy of the database from before the move is kept, in the throwaway folder."""
        return os.path.join(self.folder, server.BEFORE_DEVICES)

    def tables(self):
        return {name for (name,) in server.sql("SELECT name FROM sqlite_master WHERE type='table'")}

    def history_columns(self):
        return [row[1] for row in server.sql("PRAGMA table_info(queries)")]

    def device_of(self, address):
        """The device the move gave an address to, as (kind, key, certain)."""
        rows = server.sql("SELECT d.kind, d.key, m.certain FROM moved_address m JOIN device d ON d.id=m.device "
                          "WHERE m.addr=?", (address,))
        return rows[0] if rows else None

    def fill(self):
        """Run the whole fill of older history, without its pauses."""
        moved = dict(server.sql("SELECT addr, device FROM moved_address"))
        while server.fill_step(moved):
            pass

    def filed(self):
        """{name: (kind, key) of the device it is filed against} for every history row."""
        return {name: (kind, key) for name, kind, key in server.sql(
            "SELECT q.domain, d.kind, d.key FROM queries q LEFT JOIN device d ON d.id=q.device")}


class BeforeTheMove(OlderHousehold):
    def test_an_older_database_is_left_exactly_as_it_was_at_start_up(self):
        self.assertNotIn("device", self.tables())
        self.assertNotIn("device", self.history_columns())
        self.assertFalse(server.S.devices_ready)
        self.assertEqual(server.S.devices_state, "old")

    def test_start_up_does_not_run_the_move(self):
        with mock.patch.object(server, "move_to_devices") as move:
            server.init_db()
        move.assert_not_called()

    def test_lookups_are_answered_and_saved_as_before(self):
        self.assertTrue(server.answer_query(query("www.bbc.co.uk"), OTHER, fake_answer))
        with server.db_lock:
            server.save_history(drain())
        self.assertEqual(server.sql("SELECT client FROM queries WHERE domain='www.bbc.co.uk'"), [(OTHER,)])

    def test_the_history_writer_saves_a_lookup_on_an_older_database(self):
        server.answer_query(query("www.bbc.co.uk"), OTHER, fake_answer)
        one_round_of_the_writer()
        self.assertEqual(server.sql("SELECT client FROM queries WHERE domain='www.bbc.co.uk'"), [(OTHER,)])

    def test_the_device_list_is_by_address_as_before(self):
        listed = {d["ip"]: d for d in server.api_devices()}
        self.assertEqual(set(listed), {OLD_SPOT, NEW_SPOT, OTHER, "192.168.1.99", V6_A, PI, ROUTER})
        self.assertEqual((listed[OTHER]["id"], listed[OTHER]["kind"], listed[OTHER]["name"]), (None, "addr", "Sam's phone"))
        self.assertEqual(listed[OTHER]["addresses"][0]["address"], OTHER)

    def test_activity_ignores_a_device_number(self):
        self.assertIsNone(server.device_number("1"))
        groups = server.api_activity(OTHER, 24, None, server.device_number("1"))
        self.assertEqual([h["d"] for g in groups for h in g["hosts"]], ["phone.example.com"])

    def test_the_looks_and_the_clean_up_pass_do_nothing(self):
        server.note_ipv4_addresses({OTHER: fresh(PHONE)})
        server.note_ipv6_addresses({V6_A: fresh(PHONE)})
        self.assertEqual(server.tidy_history(), 0)
        server.forget_old_devices()
        self.assertEqual(server.S.addr_device, {})

    def test_the_minute_look_still_notes_which_device_an_addresss_rules_belong_to(self):
        server.refresh_devices({PI: "b8:27:eb:00:00:01", ROUTER: ROUTER_MAC, OTHER: PHONE}, now=self.now)
        self.assertEqual(server.S.dev_mac, {OTHER: PHONE})

    def test_the_status_says_the_move_has_not_been_tried(self):
        told = server.api_status()["devices"]
        self.assertEqual((told["state"], told["notice"], told["filling"]), ("old", "", False))


class TheMove(OlderHousehold):
    def setUp(self):
        super().setUp()
        self.assertEqual(server.move_to_devices(), "ready")

    def test_the_move_makes_the_device_tables_and_starts_using_them(self):
        self.assertTrue({"device", "device_hw", "address_use", "moved_address"} <= self.tables())
        self.assertIn("device", self.history_columns())
        self.assertTrue(server.S.devices_ready)

    def test_a_device_is_made_for_each_hardware_address_the_old_tables_know(self):
        self.assertEqual(set(server.sql("SELECT d.kind, h.mac FROM device_hw h JOIN device d ON d.id=h.device")),
                         {("hw", TV), ("hw", PHONE), ("hub", ROUTER_MAC)})

    def test_an_address_goes_to_the_device_its_rules_were_recorded_for_and_that_is_certain(self):
        self.assertEqual(self.device_of(OTHER), ("hw", "hw:" + PHONE, 1))

    def test_an_address_with_no_rules_goes_to_the_hardware_address_last_seen_there_as_a_best_guess(self):
        self.assertEqual(self.device_of(NEW_SPOT), ("hw", "hw:" + TV, 0))

    def test_failing_that_an_address_goes_to_the_hardware_address_the_last_scan_found_there(self):
        self.assertEqual(self.device_of(OLD_SPOT), ("hw", "hw:" + TV, 0))

    def test_the_tv_at_two_addresses_becomes_one_device(self):
        self.assertEqual(self.device_of(OLD_SPOT)[:2], self.device_of(NEW_SPOT)[:2])
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='hw'")[0][0], 2)

    def test_an_address_with_no_hardware_address_becomes_a_device_known_by_that_address(self):
        self.assertEqual(self.device_of("192.168.1.99"), ("addr", "addr:192.168.1.99", 1))

    def test_an_ipv6_address_in_the_old_history_becomes_a_device_known_by_that_address(self):
        self.assertEqual(self.device_of(V6_A), ("addr", "addr:" + V6_A, 1))

    def test_this_computer_and_the_router_go_to_the_fixed_devices(self):
        self.assertEqual((self.device_of(PI)[:2], self.device_of(ROUTER)[:2]), (("pi", "pi"), ("hub", "hub")))

    def test_the_version_and_the_time_of_the_move_are_saved(self):
        self.assertEqual(server.get_setting("devices_version", ""), str(server.DEVICES_VERSION))
        self.assertAlmostEqual(float(server.get_setting("devices_moved_at", "0")), time.time(), delta=300)
        self.assertEqual(server.S.devices_moved_at, float(server.get_setting("devices_moved_at", "0")))

    def test_a_copy_of_the_database_from_before_the_move_is_kept(self):
        copy = sqlite3.connect(os.path.join(self.folder, server.BEFORE_DEVICES))
        try:
            tables = {name for (name,) in copy.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            rows = copy.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
            columns = [row[1] for row in copy.execute("PRAGMA table_info(queries)")]
        finally:
            copy.close()
        self.assertNotIn("device", tables)
        self.assertNotIn("device", columns)
        self.assertEqual(rows, 7)

    def test_no_part_written_copy_is_left_behind(self):
        self.assertEqual([f for f in os.listdir(self.folder) if ".part" in f], [])

    def test_names_and_rules_go_from_their_addresses_to_the_device(self):
        phone = server.S.hw_device[PHONE]
        self.assertEqual(server.sql("SELECT id, name FROM device WHERE name!=''"), [(phone, "Sam's phone")])
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % phone: {"youtube"}})
        self.assertEqual(server.sql("SELECT ip, name FROM devices"), [])

    def test_the_owner_is_told_what_was_done_and_where_the_copy_is(self):
        notes = [text for (text,) in server.sql("SELECT text FROM events ORDER BY id")]
        self.assertEqual(len(notes), 2)                       # the history, then the rules
        self.assertIn(server.BEFORE_DEVICES, notes[0])
        self.assertIn("with the device itself", notes[1])

    def test_the_owner_is_told_how_long_the_copy_is_kept(self):
        note = server.sql("SELECT text FROM events ORDER BY id")[0][0]
        self.assertIn("for %d days and then deleted" % server.KEEP_DAYS, note)
        self.assertIn("Forgetting everyone's history deletes it too", note)

    def test_the_copy_kept_before_the_move_is_deleted_once_it_is_thirty_days_old(self):
        self.assertEqual(server.KEEP_DAYS, 30)
        self.assertTrue(server.forget_old_copy(now=server.S.devices_moved_at + 30 * 86400))
        self.assertFalse(os.path.exists(self.copy()))

    def test_the_copy_kept_before_the_move_stays_while_it_is_younger_than_thirty_days(self):
        self.assertFalse(server.forget_old_copy(now=server.S.devices_moved_at + 30 * 86400 - 60))
        self.assertTrue(os.path.exists(self.copy()))

    def test_the_age_of_the_copy_is_counted_from_the_move_not_from_the_file(self):
        long_ago = self.now - 90 * 86400
        os.utime(self.copy(), (long_ago, long_ago))           # as after the file was copied about or restored
        self.assertFalse(server.forget_old_copy(now=server.S.devices_moved_at + 86400))
        self.assertTrue(os.path.exists(self.copy()))

    def test_forgetting_everyones_history_deletes_the_copy_kept_before_the_move(self):
        server.clear_history()
        self.assertFalse(os.path.exists(self.copy()))
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries")[0][0], 0)

    def test_forgetting_one_devices_history_leaves_the_copy_kept_before_the_move(self):
        self.fill()
        server.clear_history(ip=OTHER)
        server.clear_history(ip=NEW_SPOT, device=server.S.hw_device[TV])
        self.assertTrue(os.path.exists(self.copy()))
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE client IN (?,?,?)", (OTHER, NEW_SPOT, OLD_SPOT))[0][0], 0)

    def test_a_missing_copy_is_not_an_error(self):
        os.remove(self.copy())
        self.assertTrue(server.forget_old_copy())
        self.assertTrue(server.forget_old_copy(at_once=True))
        server.clear_history()                                # and forgetting everyone's history still works

    def test_a_copy_that_cannot_be_deleted_is_reported_and_tried_again_later(self):
        with mock.patch.object(server.os, "remove", side_effect=OSError("read-only")):
            self.assertFalse(server.forget_old_copy(at_once=True))      # no fault reaches the caller
        self.assertTrue(os.path.exists(self.copy()))
        self.assertTrue(server.forget_old_copy(at_once=True))
        self.assertFalse(os.path.exists(self.copy()))

    def test_only_the_copy_is_deleted_never_the_database_beside_it(self):
        server.forget_old_copy(at_once=True)
        left = sorted(f for f in os.listdir(self.folder) if not f.endswith(("-wal", "-shm")))
        self.assertEqual(left, ["quietnet.db"])

    def test_old_history_waits_for_its_device_until_the_fill(self):
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NOT NULL")[0][0], 0)
        self.assertTrue(server.S.history_fill)
        told = server.api_status()["devices"]
        self.assertEqual((told["state"], told["notice"], told["filling"]), ("ready", "", True))

    def test_the_clean_up_pass_leaves_older_history_for_the_fill(self):
        self.assertEqual(server.tidy_history(), 0)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NOT NULL")[0][0], 0)
        self.fill()
        self.assertEqual(self.filed()["old.example.com"], ("hw", "hw:" + TV))

    def test_the_fill_gives_every_old_row_the_device_its_address_was_given_to(self):
        self.fill()
        self.assertEqual(self.filed(), {
            "old.example.com": ("hw", "hw:" + TV), "new.example.com": ("hw", "hw:" + TV),
            "phone.example.com": ("hw", "hw:" + PHONE), "stranger.example.com": ("addr", "addr:192.168.1.99"),
            "sixer.example.com": ("addr", "addr:" + V6_A), "pi.example.com": ("pi", "pi"), "hub.example.com": ("hub", "hub")})

    def test_the_fill_does_the_newest_rows_first(self):
        with mock.patch.object(server, "FILL_BATCH", 3):
            server.fill_step(dict(server.sql("SELECT addr, device FROM moved_address")))
        done = {name for (name,) in server.sql("SELECT domain FROM queries WHERE device IS NOT NULL")}
        self.assertEqual(done, {"hub.example.com", "pi.example.com", "sixer.example.com"})

    def test_the_fill_lets_go_of_the_lock_between_steps(self):
        pauses = []
        server.S.moved_steady -= server.FILL_SETTLE           # the history writer has long caught up
        with mock.patch.object(server, "FILL_BATCH", 3), \
                mock.patch.object(server.time, "sleep", lambda s: pauses.append(server.db.in_transaction)):
            server.fill_old_history()
        self.assertEqual(pauses, [False, False, False])
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NULL")[0][0], 0)

    def test_the_fill_is_marked_done_when_it_finishes(self):
        self.fill()
        self.assertFalse(server.S.history_fill)
        self.assertEqual(server.get_setting("devices_fill", ""), "done")

    def test_each_step_of_the_fill_changes_the_activity_marker_for_a_device(self):
        phone = server.sql("SELECT device FROM moved_address WHERE addr=?", (OTHER,))[0][0]
        before = server.activity_marker(OTHER, 24, self.now - 86400, device=phone)
        with mock.patch.object(server, "FILL_BATCH", 3):                  # three rows, none of them the phone's
            server.fill_step(dict(server.sql("SELECT addr, device FROM moved_address")))
        self.assertNotEqual(server.activity_marker(OTHER, 24, self.now - 86400, device=phone), before)

    def test_the_fill_is_not_called_finished_until_the_writer_has_caught_up(self):
        moved = dict(server.sql("SELECT addr, device FROM moved_address"))
        self.assertEqual(server.fill_step(moved, finish=False), 7)
        self.assertEqual(server.fill_step(moved, finish=False), 0)        # nothing waiting, but more may arrive
        self.assertTrue(server.S.history_fill)
        self.assertEqual(server.get_setting("devices_fill", ""), "pending")

    def test_just_after_the_move_the_fill_looks_again_each_second_before_it_finishes(self):
        waits = []

        def sleep(seconds):
            """Note the wait, and let the settling time pass at the third look for more."""
            waits.append(seconds)
            if waits.count(1) == 3:
                server.S.moved_steady -= server.FILL_SETTLE
        with mock.patch.object(server.time, "sleep", sleep):
            server.fill_old_history()
        self.assertEqual(waits, [server.FILL_PAUSE, 1, 1, 1])
        self.assertEqual(server.get_setting("devices_fill", ""), "done")

    def test_after_a_restart_the_fill_finishes_without_waiting(self):
        server.init_db()                                      # nothing is waiting to be written after a restart
        waits = []
        with mock.patch.object(server.time, "sleep", waits.append):
            server.fill_old_history()
        self.assertEqual(waits, [server.FILL_PAUSE])
        self.assertEqual(server.get_setting("devices_fill", ""), "done")

    def test_a_fill_cut_short_by_a_restart_carries_on_afterwards(self):
        with mock.patch.object(server, "FILL_BATCH", 3):
            server.fill_step(dict(server.sql("SELECT addr, device FROM moved_address")))
        server.init_db()                                      # the power was pulled and QuietNet started again
        self.assertTrue(server.S.devices_ready)
        self.assertTrue(server.S.history_fill)
        self.fill()
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NULL")[0][0], 0)

    def test_a_finished_fill_is_not_started_again_after_a_restart(self):
        self.fill()
        server.init_db()
        self.assertFalse(server.S.history_fill)

    def test_an_old_row_from_an_address_the_move_did_not_see_gets_a_device_of_its_own(self):
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)",
                   (server.S.devices_moved_at - 5, "192.168.1.111", "late.example.com"), commit=True)
        self.fill()
        self.assertEqual(self.filed()["late.example.com"], ("addr", "addr:192.168.1.111"))

    def test_the_device_list_shows_unfilled_history_under_the_device_that_has_the_address(self):
        listed = {d["ip"]: d for d in server.api_devices()}
        self.assertEqual((listed[NEW_SPOT]["kind"], listed[NEW_SPOT]["n"], listed[OTHER]["nb"]), ("hw", 1, 1))
        self.assertAlmostEqual(listed[NEW_SPOT]["last"], self.now - 3600, delta=2)

    def test_the_tv_is_one_entry_after_the_move_and_the_fill(self):
        self.fill()
        tv = [d for d in server.api_devices() if d["macs"] == [TV]]
        self.assertEqual([(d["ip"], d["kind"]) for d in tv], [(NEW_SPOT, "hw")])
        groups = server.api_activity(NEW_SPOT, 24 * 30, None, tv[0]["id"])
        self.assertEqual(sorted(h["d"] for g in groups for h in g["hosts"]), ["new.example.com", "old.example.com"])

    def test_a_lookup_made_after_the_move_is_filed_by_the_live_record_not_the_move(self):
        server.note_ipv4_addresses({OLD_SPOT: fresh(LAPTOP)})             # the laptop has the TV's old address now
        server.answer_query(query("laptop.example.com"), OLD_SPOT, fake_answer)
        with server.db_lock:
            server.save_history(drain())
        self.assertEqual(self.filed()["laptop.example.com"], ("hw", "hw:" + LAPTOP))

    def test_the_move_is_not_done_twice(self):
        with mock.patch.object(server, "copy_database") as copy:
            self.assertEqual(server.move_to_devices(), "ready")
        copy.assert_not_called()

    def test_the_moved_database_is_ready_straight_away_at_the_next_start(self):
        server.init_db()
        self.assertEqual((server.S.devices_ready, server.S.devices_state), (True, "ready"))


class TheMoveWithTrickyHouseholds(OlderHousehold):
    def household(self, old):
        now = self.now
        old.executemany("INSERT INTO known_macs VALUES(?,?,?,?)", [
            (TV, OLD_SPOT, now - 20 * 86400, now - 5 * 86400),            # the TV was last seen at .65 days ago
            (PHONE, OLD_SPOT, now - 86400, now - 60),                     # the phone has .65 now
            (EXTENDER, NEW_SPOT, now - 86400, now - 60),
            ("ff:ff:ff:ff:ff:ff", "192.168.1.255", now, now)])
        old.execute("INSERT INTO shared_macs VALUES(?,?,?)", (EXTENDER, 3, now))
        old.execute("INSERT INTO device_mac(ip, mac, paused) VALUES(?,?,1)", (OLD_SPOT, TV))     # the TV's rules, paused
        old.execute("INSERT INTO seen VALUES(?,?,?,?)", (NEW_SPOT, EXTENDER, "", now))
        old.execute("INSERT INTO seen VALUES(?,?,?,?)", (OTHER, "", "", now))
        old.execute("INSERT INTO devices VALUES(?,?)", ("192.168.1.81", "Spare tablet"))        # a name, no history
        old.execute("INSERT INTO device_group VALUES(?,?)", ("192.168.1.82", 1))               # a group, no history
        old.execute("INSERT INTO enforced VALUES(?,?)", ("192.168.1.83", ""))                   # a live cut, no history
        old.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,?)", [
            (now - 100, OLD_SPOT, "now.example.com", 0), (now - 90, NEW_SPOT, "behind.example.com", 0),
            (now - 80, None, "nobody.example.com", 0)])

    def setUp(self):
        super().setUp()
        self.assertEqual(server.move_to_devices(), "ready")

    def test_a_paused_address_goes_to_the_device_that_has_it_now_as_a_best_guess(self):
        self.assertEqual(self.device_of(OLD_SPOT), ("hw", "hw:" + PHONE, 0))

    def test_a_range_extenders_hardware_address_is_not_made_a_device(self):
        self.assertEqual({mac for (mac,) in server.sql("SELECT mac FROM device_hw")}, {TV, PHONE})

    def test_an_address_behind_a_range_extender_becomes_a_device_known_by_that_address(self):
        self.assertEqual(self.device_of(NEW_SPOT), ("addr", "addr:" + NEW_SPOT, 1))

    def test_a_group_hardware_address_is_not_made_a_device_and_its_address_is_left_out(self):
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device_hw WHERE mac='ff:ff:ff:ff:ff:ff'")[0][0], 0)
        self.assertIsNone(self.device_of("192.168.1.255"))

    def test_a_scanned_address_with_no_hardware_address_becomes_a_device_known_by_that_address(self):
        self.assertEqual(self.device_of(OTHER), ("addr", "addr:" + OTHER, 1))

    def test_an_address_with_only_a_name_a_group_or_a_live_cut_is_given_a_device_in_the_move(self):
        for addr in ("192.168.1.81", "192.168.1.82", "192.168.1.83"):
            self.assertEqual(self.device_of(addr), ("addr", "addr:" + addr, 1))

    def test_an_old_row_with_no_address_is_filed_against_no_device(self):
        self.fill()
        self.assertEqual(server.sql("SELECT device FROM queries WHERE domain='nobody.example.com'"), [(server.NO_DEVICE,)])
        self.assertFalse(server.S.history_fill)


class TheMoveOfAHistoryFullOfMadeUpAddresses(OlderHousehold):
    def household(self, old):
        old.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)", [
            (self.now - i, "10.9.8.%d" % i, "n%d.example.com" % i) for i in range(1, 7)])

    def test_only_so_many_addresses_become_devices_and_the_rest_are_filed_against_no_device(self):
        with mock.patch.object(server, "MAX_DEVICES", 4):
            self.assertEqual(server.move_to_devices(), "ready")
        self.assertEqual(server.sql("SELECT COUNT(*) FROM device WHERE kind='addr'")[0][0], 4)
        self.fill()
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device=?", (server.NO_DEVICE,))[0][0], 2)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NULL")[0][0], 0)


class WhenTheMoveCannotBeDone(OlderHousehold):
    def before(self):
        """What the database holds: its tables, the history's columns and every history row."""
        return (self.tables(), self.history_columns(), server.sql("SELECT * FROM queries ORDER BY id"),
                server.sql("SELECT * FROM known_macs ORDER BY mac"), server.sql("SELECT * FROM settings ORDER BY key"))

    def fail_part_way(self):
        """Run the move with a fault after it has already made tables and devices."""
        real = server.build_devices

        def broken(now):
            real(now)
            raise RuntimeError("the disk went away")
        with mock.patch.object(server, "build_devices", broken):
            return server.move_to_devices()

    def test_a_move_that_fails_part_way_leaves_the_database_exactly_as_it_was(self):
        before = self.before()
        self.assertEqual(self.fail_part_way(), "failed")
        self.assertEqual(self.before(), before)

    def test_a_failed_move_leaves_quietnet_running_on_the_old_data(self):
        self.fail_part_way()
        self.assertFalse(server.S.devices_ready)
        self.assertTrue(server.answer_query(query("www.bbc.co.uk"), OTHER, fake_answer))
        with server.db_lock:
            server.save_history(drain())
        self.assertEqual(server.sql("SELECT client FROM queries WHERE domain='www.bbc.co.uk'"), [(OTHER,)])
        self.assertIn(OTHER, {d["ip"] for d in server.api_devices()})
        self.assertEqual(server.S.svc_blocks, {"device:" + OTHER: {"youtube"}})
        self.assertEqual(server.S.given, {OTHER: "Sam's phone"})

    def test_a_failed_move_still_blocks_what_was_blocked(self):
        self.fail_part_way()
        reply = server.answer_query(query("www.youtube.com"), OTHER, fake_answer)
        self.assertEqual(reply[-4:], bytes(4))

    def test_a_failed_move_tells_the_owner_and_says_nothing_was_changed(self):
        self.fail_part_way()
        told = server.api_status()["devices"]
        self.assertEqual(told["state"], "failed")
        self.assertIn("the disk went away", told["notice"])
        self.assertIn("Nothing has been changed", told["notice"])

    def test_a_failed_copy_stops_the_move_before_anything_is_changed(self):
        before = self.before()
        with mock.patch.object(server, "copy_database", side_effect=OSError("no room")):
            self.assertEqual(server.move_to_devices(), "failed")
        self.assertEqual(self.before(), before)

    def test_a_copy_that_fails_part_way_leaves_no_file_under_the_copys_name(self):
        with mock.patch.object(server.os, "fsync", side_effect=OSError("the disk is full")):
            self.assertEqual(server.move_to_devices(), "failed")
        self.assertFalse(os.path.exists(self.copy()))

    def test_a_part_written_copy_from_an_earlier_try_does_not_spoil_the_next_copy(self):
        part = self.copy() + ".part"
        for name in (part, part + "-journal"):
            with open(name, "wb") as f:
                f.write(b"half a copy " * 500)
        self.assertEqual(server.move_to_devices(), "ready")
        copy = sqlite3.connect(self.copy())
        try:
            rows = copy.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
            sound = copy.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            copy.close()
        self.assertEqual((rows, sound), (7, "ok"))
        self.assertEqual([f for f in os.listdir(self.folder) if ".part" in f], [])

    def test_a_copy_left_by_a_failed_move_is_deleted_once_the_file_is_thirty_days_old(self):
        self.fail_part_way()
        self.assertTrue(os.path.exists(self.copy()))
        self.assertFalse(server.forget_old_copy())            # written a moment ago: it stays
        self.assertTrue(os.path.exists(self.copy()))
        long_ago = time.time() - 31 * 86400
        os.utime(self.copy(), (long_ago, long_ago))
        self.assertTrue(server.forget_old_copy())
        self.assertFalse(os.path.exists(self.copy()))

    def test_a_part_written_copy_left_behind_is_deleted_once_it_is_thirty_days_old(self):
        part = self.copy() + ".part"
        with open(part, "wb") as f:
            f.write(b"half a copy")
        server.forget_old_copy()
        self.assertTrue(os.path.exists(part))
        long_ago = time.time() - 31 * 86400
        os.utime(part, (long_ago, long_ago))
        server.forget_old_copy()
        self.assertFalse(os.path.exists(part))

    def test_forgetting_everyones_history_deletes_the_copy_left_by_a_failed_move(self):
        self.fail_part_way()
        server.clear_history()
        self.assertFalse(os.path.exists(self.copy()))

    def test_forgetting_everyones_history_while_the_copy_is_being_made_deletes_it_when_the_move_ends(self):
        real = server.copy_database

        def copy_then_forget(dest):
            """Make the copy, and have the owner forget everyone's history before the move is over."""
            real(dest)
            server.clear_history()
            self.assertTrue(os.path.exists(dest))             # left alone while the move is under way
        with mock.patch.object(server, "copy_database", copy_then_forget):
            self.assertEqual(server.move_to_devices(), "ready")
        self.assertFalse(os.path.exists(self.copy()))
        self.assertFalse(server.S.copy_unwanted)

    def test_a_failed_move_is_tried_again_at_the_next_start_and_can_then_succeed(self):
        self.fail_part_way()
        server.init_db()
        self.assertEqual(server.S.devices_state, "old")
        self.assertEqual(server.move_to_devices(), "ready")

    def test_too_little_free_space_skips_the_move_and_tells_the_owner(self):
        before = self.before()
        with mock.patch.object(server.shutil, "disk_usage", return_value=mock.Mock(free=1000)):
            self.assertEqual(server.move_to_devices(), "waiting")
        self.assertEqual(self.before(), before)
        self.assertFalse(os.path.exists(os.path.join(self.folder, server.BEFORE_DEVICES)))
        told = server.api_status()["devices"]
        self.assertEqual(told["state"], "waiting")
        self.assertIn("free space", told["notice"])
        self.assertIn("Nothing has been changed", told["notice"])

    def test_the_move_wants_twice_the_size_of_the_database_free(self):
        path = os.path.join(self.folder, "quietnet.db")
        size = sum(os.path.getsize(p) for p in (path, path + "-wal") if os.path.exists(p))
        with mock.patch.object(server.shutil, "disk_usage", return_value=mock.Mock(free=2 * size - 1)):
            self.assertFalse(server.space_for_move()[0])
        with mock.patch.object(server.shutil, "disk_usage", return_value=mock.Mock(free=2 * size)):
            self.assertTrue(server.space_for_move()[0])

    def test_the_move_goes_ahead_once_there_is_room(self):
        with mock.patch.object(server.shutil, "disk_usage", return_value=mock.Mock(free=1000)):
            server.move_to_devices()
        self.assertEqual(server.move_to_devices(), "ready")
        self.assertEqual(server.api_status()["devices"]["notice"], "")

    def test_lookups_are_answered_while_the_move_holds_the_database(self):
        holding, let_go, answered = threading.Event(), threading.Event(), []
        real = server.build_devices

        def slow(now):
            holding.set()
            let_go.wait(60)
            return real(now)
        with mock.patch.object(server, "build_devices", slow):
            mover = threading.Thread(target=server.move_to_devices, daemon=True)
            mover.start()
            self.assertTrue(holding.wait(60))
            answered.append(server.answer_query(query("www.bbc.co.uk"), OTHER, fake_answer))
            answered.append(server.answer_query(query("www.youtube.com"), OTHER, fake_answer)[-4:])
            let_go.set()
            mover.join(60)
        self.assertTrue(answered[0])
        self.assertEqual(answered[1], bytes(4))               # and the phone's YouTube block still bites
        self.assertTrue(server.S.devices_ready)

    def test_a_lookup_made_during_the_move_is_saved_once_it_is_over(self):
        server.answer_query(query("during.example.com"), OTHER, fake_answer)
        waiting = drain()
        server.move_to_devices()
        with server.db_lock:
            server.save_history(waiting)
        self.assertEqual(server.sql("SELECT client FROM queries WHERE domain='during.example.com'"), [(OTHER,)])


class TheKeeper(OlderHousehold):
    class Stop(BaseException):
        """Raised by the stand-in for sleeping, to end the keeper's endless loop."""

    def run_until_the_first_pause(self):
        def stop(seconds):
            raise self.Stop()
        # The keeper looks for the router afresh before the move: hand it a stand-in routing table.
        # The keeper looks at the neighbours before its first pause: a stand-in, never the real table.
        with mock.patch.object(server.time, "sleep", stop), mock.patch.object(server, "fill_old_history") as fill, \
                mock.patch.object(server, "note_ipv4_addresses"), \
                mock.patch.object(server.enforcer, "interface_and_gateway", lambda: ("wlan0", ROUTER)):
            with self.assertRaises(self.Stop):
                server.device_keeper()
        return fill

    def test_the_keeper_moves_an_older_database_before_anything_else(self):
        self.run_until_the_first_pause()
        self.assertTrue(server.S.devices_ready)

    def test_the_keeper_starts_the_fill_once_the_move_is_done(self):
        fill = self.run_until_the_first_pause()
        for _ in range(500):
            if fill.called:
                break
            time.sleep(0.02)
        fill.assert_called_once_with()

    def test_the_keeper_does_not_try_a_failed_move_again_until_a_restart(self):
        with mock.patch.object(server, "copy_database", side_effect=OSError("no room")):
            self.run_until_the_first_pause()
        with mock.patch.object(server, "move_to_devices") as move:
            self.run_until_the_first_pause()
        move.assert_not_called()

    def test_the_keeper_survives_a_fault_in_the_move(self):
        with mock.patch.object(server, "move_to_devices", side_effect=RuntimeError("no")):
            self.run_until_the_first_pause()                  # ends at the pause, not with the fault
        self.assertFalse(server.S.devices_ready)


class TheMoveWaitsForThisComputersAddress(OlderHousehold):
    """A Pi can start QuietNet before its Wi-Fi is connected (after a power cut, say). The move
    decides once which old history is this computer's and which the router's, so the keeper holds
    it back until this computer knows its own address. Run on a stand-in clock, with a stand-in
    for the routing table."""

    class Stop(BaseException):
        """Raised by the stand-in for sleeping, to end the keeper's endless loop."""

    def setUp(self):
        super().setUp()
        self.gateway = None                                   # what the stand-in routing table says the router is
        server.S.local_ip, server.S.router, server.S.router_checked = "127.0.0.1", "", None
        self.addCleanup(setattr, server.S, "router_checked", float("inf"))

    def run_keeper(self, pauses, network_up_after=None, move=True):
        """Run the keeper for `pauses` pauses of ADDRESS_LOOK seconds. After `network_up_after` of
        them this computer finds its address and its router. With `move` false the move itself
        is a stand-in. Returns that stand-in."""
        clock, slept = [5000.0], []

        def sleep(seconds):
            """One pause on the stand-in clock."""
            if len(slept) >= pauses:
                raise self.Stop()
            slept.append(seconds)
            clock[0] += server.ADDRESS_LOOK
            if len(slept) == network_up_after:
                server.S.local_ip, self.gateway = PI, ROUTER

        def routes():
            """The stand-in routing table: the network card and the router, once there is one."""
            return ("wlan0", self.gateway) if self.gateway else (None, None)
        with mock.patch.object(server.time, "sleep", sleep), \
                mock.patch.object(server.time, "monotonic", lambda: clock[0]), \
                mock.patch.object(server.enforcer, "interface_and_gateway", routes), \
                mock.patch.object(server, "move_to_devices", wraps=server.move_to_devices) as moving, \
                mock.patch.object(server, "fill_old_history"), \
                mock.patch.object(server, "note_ipv4_addresses"), \
                mock.patch.object(server, "tidy_history"):
            if not move:
                moving.side_effect = lambda: "ready"
            with self.assertRaises(self.Stop):
                server.device_keeper()
        return moving

    def test_the_move_waits_while_this_computer_does_not_know_its_address(self):
        moving = self.run_keeper(5, move=False)
        moving.assert_not_called()
        self.assertFalse(server.S.devices_ready)

    def test_lookups_are_still_answered_and_blocked_while_the_move_waits(self):
        self.run_keeper(5, move=False)
        self.assertTrue(server.answer_query(query("www.bbc.co.uk"), OTHER, fake_answer))
        self.assertEqual(server.answer_query(query("www.youtube.com"), OTHER, fake_answer)[-4:], bytes(4))

    def test_the_move_goes_ahead_as_soon_as_the_address_is_known(self):
        moving = self.run_keeper(2, network_up_after=2, move=False)
        self.assertEqual(moving.call_count, 1)

    def test_the_move_goes_ahead_after_the_wait_even_with_no_address(self):
        rounds = server.MOVE_ADDRESS_WAIT // server.ADDRESS_LOOK
        self.run_keeper(rounds - 1, move=False).assert_not_called()
        self.assertEqual(self.run_keeper(rounds, move=False).call_count, 1)

    def test_a_computer_that_knows_its_address_is_moved_at_once(self):
        server.S.local_ip = PI
        self.assertEqual(self.run_keeper(0, move=False).call_count, 1)

    def test_the_move_looks_for_the_router_afresh_and_does_not_trust_an_earlier_empty_answer(self):
        server.S.local_ip, self.gateway = PI, ROUTER
        server.S.router, server.S.router_checked = "", 5000.0             # "no router", found a moment ago
        self.run_keeper(0)
        self.assertEqual(self.device_of(ROUTER)[:2], ("hub", "hub"))

    def test_after_a_start_with_no_network_this_computers_and_the_routers_old_history_go_to_the_fixed_devices(self):
        self.run_keeper(3, network_up_after=2)                # the network comes up ten seconds after the start
        self.assertTrue(server.S.devices_ready)
        self.fill()
        filed = self.filed()
        self.assertEqual((filed["pi.example.com"], filed["hub.example.com"]), (("pi", "pi"), ("hub", "hub")))
        self.assertEqual(server.sql("SELECT d.kind FROM device_hw h JOIN device d ON d.id=h.device WHERE h.mac=?",
                                    (ROUTER_MAC,)), [("hub",)])


class LookupsMadeJustBeforeTheMove(OlderHousehold):
    """The history writer holds each lookup for a second before saving it, so one made just before
    the move is saved just after it: with a time from before the move, and no device."""

    def test_a_lookup_made_just_before_the_move_and_saved_after_it_still_gets_its_device(self):
        server.answer_query(query("late.example.com"), OTHER, fake_answer)
        waiting = drain()                                     # the writer is still holding it
        self.assertEqual(server.move_to_devices(), "ready")

        def sleep(seconds):
            """The fill's waits. At its first one-second wait the writer saves what it held, and
            the settling time then passes."""
            if seconds == 1 and waiting:
                with server.db_lock:
                    server.save_history(waiting)
                del waiting[:]
                self.assertEqual(server.sql("SELECT device FROM queries WHERE domain='late.example.com'"), [(None,)])
                server.S.moved_steady -= server.FILL_SETTLE
        with mock.patch.object(server.time, "sleep", sleep):
            server.fill_old_history()
        self.assertEqual(waiting, [])
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NULL")[0][0], 0)
        self.assertEqual(self.filed()["late.example.com"], ("hw", "hw:" + PHONE))
        self.assertEqual(server.get_setting("devices_fill", ""), "done")

    def test_the_real_writer_and_the_fill_together_leave_no_lookup_without_a_device(self):
        server.answer_query(query("late.example.com"), OTHER, fake_answer)   # made just before the move
        self.assertEqual(server.move_to_devices(), "ready")
        moved = dict(server.sql("SELECT addr, device FROM moved_address"))
        while server.fill_step(moved, finish=False):          # the fill reaches the end of a small history at once
            pass
        one_round_of_the_writer()                             # and only then does the writer save the lookup
        server.S.moved_steady -= server.FILL_SETTLE
        with mock.patch.object(server.time, "sleep", lambda seconds: None):
            server.fill_old_history()
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NULL")[0][0], 0)
        self.assertFalse(server.S.history_fill)


class TheKeepersRounds(Devices):
    """The device keeper's loop, run for a set number of pauses with a stand-in clock. The looks
    themselves are stand-ins, so the real neighbour table is never read."""

    class Stop(BaseException):
        """Raised by the stand-in for sleeping, to end the keeper's endless loop."""

    def run_rounds(self, pauses, seconds_per_pause=server.ADDRESS_LOOK):
        """Run the keeper until it has paused `pauses` times and is about to pause again. Returns
        the stand-ins for the move, the look, the clean-up pass and the forgetting."""
        clock = [1000.0]
        slept = []

        def sleep(seconds):
            if len(slept) >= pauses:
                raise self.Stop()
            slept.append(seconds)
            clock[0] += seconds_per_pause
        with mock.patch.object(server.time, "sleep", sleep), \
                mock.patch.object(server.time, "monotonic", lambda: clock[0]), \
                mock.patch.object(server, "move_to_devices") as move, \
                mock.patch.object(server, "note_ipv4_addresses") as look, \
                mock.patch.object(server, "tidy_history") as tidy, \
                mock.patch.object(server, "forget_old_devices") as forget, \
                mock.patch.object(server, "forget_old_copy") as self.forget_copy, \
                mock.patch.object(server.enforcer, "interface_and_gateway", lambda: ("wlan0", ROUTER)):
            with self.assertRaises(self.Stop):
                server.device_keeper()
        self.assertLessEqual(set(slept), {server.ADDRESS_LOOK})
        return move, look, tidy, forget

    def test_the_keeper_looks_at_the_neighbours_before_every_pause(self):
        move, look, tidy, forget = self.run_rounds(3)
        self.assertEqual(look.call_count, 4)                  # before each of three pauses, and before the fourth
        move.assert_not_called()

    def test_the_first_look_comes_before_the_first_pause(self):
        # Whose rules each address gets is not kept across a restart: it must be worked out at once.
        move, look, tidy, forget = self.run_rounds(0)
        self.assertEqual(look.call_count, 1)

    def test_the_clean_up_pass_runs_once_a_minute_not_on_every_look(self):
        move, look, tidy, forget = self.run_rounds(server.TIDY_EVERY // server.ADDRESS_LOOK)
        self.assertEqual(tidy.call_count, 1)
        forget.assert_not_called()

    def test_old_devices_are_forgotten_once_an_hour(self):
        move, look, tidy, forget = self.run_rounds(2, seconds_per_pause=1800)
        self.assertEqual(forget.call_count, 1)

    def test_the_copy_from_before_the_move_is_checked_for_its_age_once_an_hour(self):
        self.run_rounds(2, seconds_per_pause=1800)
        self.forget_copy.assert_called_once_with()

    def test_the_copy_is_checked_for_its_age_even_when_the_move_has_failed(self):
        server.S.devices_ready, server.S.devices_state = False, "failed"
        self.addCleanup(server.init_db)
        move, look, tidy, forget = self.run_rounds(2, seconds_per_pause=1800)
        self.forget_copy.assert_called_once_with()
        move.assert_not_called()

    def test_a_fault_in_a_look_does_not_stop_the_keeper(self):
        with mock.patch("builtins.print"):
            clock = [0]

            def sleep(seconds):
                clock[0] += 1
                if clock[0] > 3:
                    raise self.Stop()
            with mock.patch.object(server.time, "sleep", sleep), \
                    mock.patch.object(server, "note_ipv4_addresses", side_effect=RuntimeError("no")) as look:
                with self.assertRaises(self.Stop):
                    server.device_keeper()
        self.assertEqual(look.call_count, 4)                  # it kept coming round, fault after fault

    def test_too_little_free_space_is_tried_again_after_an_hour_not_before(self):
        server.S.devices_ready, server.S.devices_state = False, "waiting"
        self.addCleanup(server.init_db)
        move, look, tidy, forget = self.run_rounds(3)
        self.assertEqual(move.call_count, 1)                  # three pauses of 5 seconds: not yet
        move, look, tidy, forget = self.run_rounds(3, seconds_per_pause=server.MOVE_RETRY)
        self.assertEqual(move.call_count, 4)
        look.assert_not_called()                              # nothing is looked at until the tables are in use


class StartUp(unittest.TestCase):
    """main() itself, with a stand-in for every part it starts: no database, socket, thread,
    firewall tool or web server is touched, only the order of the starts is noted."""

    def start_up(self):
        """Run main() to the end with stand-ins. Returns (what was started, in order; the stand-in
        for move_to_devices, to see whether start-up itself ran the move)."""
        order = []

        class Thread:
            """Stands in for threading.Thread: notes the function, never runs it."""

            def __init__(self, target=None, daemon=None):
                self.target = target

            def start(self):
                """Note which background job was started."""
                order.append(self.target.__name__)

        class Part:
            """Stands in for the enforcer, the cloud link and the dashboard's web server."""
            reason = "this is a test"

            def __init__(self, name):
                self.name = name

            def start(self):
                """Note that this part was started."""
                order.append(self.name)

            def serve_forever(self):
                """Note that the dashboard was reached, and come straight back."""
                order.append(self.name)

            def available(self):
                """The enforcer is never ready in this test."""
                return False

            def stop(self):
                """Nothing to stop."""

        threads = mock.Mock(wraps=threading)
        threads.Thread = Thread
        swaps = [
            mock.patch.object(sys, "argv", ["server.py", "--no-browser", "--no-device-names"]),
            mock.patch.object(server, "init_db", lambda: order.append("init_db")),
            mock.patch.object(server, "load_lists", lambda: None),
            mock.patch.object(server, "find_local_ip", lambda: PI),
            mock.patch.object(server, "start_dns", lambda port: order.append("start_dns")),
            mock.patch.object(server, "threading", threads),
            mock.patch.object(server.enforcer, "Enforcer", lambda *a, **k: Part("enforcer")),
            mock.patch.object(server.cloud_agent, "CloudAgent", lambda *a, **k: Part("cloud link")),
            mock.patch.object(server, "ThreadingHTTPServer", lambda *a, **k: Part("dashboard")),
            mock.patch.object(server.signal, "signal", lambda *a: None),
            mock.patch.object(server, "ENF", None), mock.patch.object(server, "CA", None),
            mock.patch.object(server.S, "local_ip", PI),
            mock.patch("builtins.print"),
        ]
        for swap in swaps:
            swap.start()
            self.addCleanup(swap.stop)
        with mock.patch.object(server, "move_to_devices") as move:
            server.main()
        return order, move

    def test_the_device_keeper_is_started_only_after_the_filter_and_the_enforcer(self):
        order, _ = self.start_up()
        self.assertEqual(order.count("device_keeper"), 1)
        self.assertGreater(order.index("device_keeper"), order.index("start_dns"))
        self.assertGreater(order.index("device_keeper"), order.index("enforcer"))

    def test_start_up_leaves_the_move_to_the_device_keeper(self):
        _, move = self.start_up()
        move.assert_not_called()

    def test_the_history_writer_is_started_at_start_up(self):
        order, _ = self.start_up()
        self.assertEqual(order.count("log_writer"), 1)


BIG_ROWS = int(os.environ.get("QUIETNET_BIG_ROWS", "2000000"))


class ABigHistory(OlderHousehold):
    """The move on a history as big as QuietNet keeps (MAX_HISTORY_ROWS): two million rows. Set
    QUIETNET_BIG_ROWS to a smaller number for a quicker run."""

    def household(self, old):
        now = self.now
        clients = ["192.168.1.%d" % i for i in range(20, 60)]
        old.executemany("INSERT INTO known_macs VALUES(?,?,?,?)", [
            ("3c:22:fb:00:00:%02x" % i, "192.168.1.%d" % i, now - 20 * 86400, now - 60) for i in range(20, 60)])
        span = 30 * 86400.0 / BIG_ROWS
        old.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,?)", (
            (now - 30 * 86400 + i * span, clients[(i * 7919) % 40], "host%d.example%d.com" % (i % 50, i % 397), i % 7 == 0)
            for i in range(BIG_ROWS)))

    def setUp(self):
        if shutil.disk_usage(tempfile.gettempdir()).free < 600 * BIG_ROWS:
            self.skipTest("not enough free space for a history of %d rows" % BIG_ROWS)
        super().setUp()

    def test_a_two_million_row_history_is_moved_and_filled_without_holding_anything_up_for_long(self):
        self.assertEqual(server.MAX_HISTORY_ROWS, 2000000)
        started = time.monotonic()
        self.assertEqual(server.move_to_devices(), "ready")
        moving = time.monotonic() - started
        # The move is the one long hold of the database (the dashboard waits; lookups do not).
        # About a second on a laptop. The limits here are loose on purpose, so that a busy
        # machine does not fail the test: they are there to catch work that grows out of hand.
        self.assertLess(moving, 600)
        # The device list is quick straight away, before a single old row has its device...
        started = time.monotonic()
        listed = server.api_devices()
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(len(listed), 40)
        self.assertGreater(sum(d["n"] for d in listed), 0)
        # ...and each step of the fill holds the database only briefly.
        moved, worst, steps = dict(server.sql("SELECT addr, device FROM moved_address")), 0.0, 0
        while True:
            started = time.monotonic()
            done = server.fill_step(moved)
            worst = max(worst, time.monotonic() - started)
            steps += 1
            if not done:
                break
        self.assertLess(worst, 30)
        self.assertEqual(steps, BIG_ROWS // server.FILL_BATCH + 1)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries WHERE device IS NULL")[0][0], 0)
        started = time.monotonic()
        listed = server.api_devices()
        self.assertLess(time.monotonic() - started, 30)
        self.assertAlmostEqual(sum(d["n"] for d in listed),
                               server.sql("SELECT COUNT(*) FROM queries WHERE ts>?", (time.time() - 86400,))[0][0], delta=2)
        self.assertEqual({d["kind"] for d in listed}, {"hw"})


if __name__ == "__main__":
    unittest.main()
