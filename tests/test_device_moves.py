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
PI_MAC, ROUTER_MAC = "00:11:22:33:44:60", "00:11:22:33:44:fe"


def blocked_for(ip):
    """Is YouTube blocked for this device right now?"""
    return server.decision("youtube.com", ip)[0]


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
