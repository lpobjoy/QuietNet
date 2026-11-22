"""Checks for QuietNet's rules engine. Run with:  python3 -m unittest discover tests

Uses only Python's standard library, and a throwaway data folder - it never
touches your real history or rules, and never sends anything to the network.
"""
import calendar
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

os.environ["QUIETNET_DATA"] = tempfile.mkdtemp(prefix="quietnet-test-")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402
import enforcer  # noqa: E402

KID, ADULT = "192.168.1.23", "192.168.1.40"


def at(day, hhmm):
    """A moment on a given weekday (0 = Monday) at a given local time."""
    base = time.mktime((2026, 11, 16, 0, 0, 0, 0, 0, -1))      # 16 Nov 2026 is a Monday
    assert time.localtime(base).tm_wday == 0
    return base + day * 86400 + int(hhmm[:2]) * 3600 + int(hhmm[3:]) * 60


def query(name, qtype=1):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack(">HH", qtype, 1)


def fake_answer(data, ttl=86400):
    """What the real internet would say: one address, remembered for a day."""
    head = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    return head + data[12:] + b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">IH", ttl, 4) + bytes([93, 184, 216, 34])


def is_blocked(name, client):
    resp = server.answer_query(query(name), client, fake_answer)
    return resp[-4:] == bytes(4)


class Base(unittest.TestCase):
    def setUp(self):
        if server.db is None:
            server.init_db()
            server.load_lists()
        for table in ("blocked", "allowed", "groups", "device_group", "service_blocks",
                      "internet_off", "schedules", "queries", "enforced"):
            server.sql("DELETE FROM %s" % table, commit=True)
        server.init_db()
        server.S.junk_on, server.S.paused_until = True, 0
        server.S.enforced, server.S.resolved = set(), {}
        # No home router, and never look one up: the routing table is the real machine's.
        server.S.router, server.S.router_checked = "", float("inf")

    def schedule(self, **kw):
        body = {"name": "Bedtime", "scope": "device:" + KID, "days": [0, 1, 2, 3, 4, 5, 6],
                "start": "21:00", "end": "07:00", "off": True, "services": []}
        body.update(kw)
        self.assertIsNone(server.save_schedule(body))
        return server.S.schedules[-1]


class Rules(Base):
    def test_adverts_blocked_everything_else_allowed(self):
        self.assertTrue(is_blocked("stats.g.doubleclick.net", KID))
        self.assertFalse(is_blocked("www.bbc.co.uk", KID))

    def test_your_own_block_covers_everything_under_it(self):
        server.block("example.com")
        self.assertTrue(is_blocked("example.com", KID))
        self.assertTrue(is_blocked("a.b.example.com", KID))
        self.assertFalse(is_blocked("notexample.com", KID))

    def test_unblocking_a_listed_advert_makes_an_exception(self):
        server.unblock("doubleclick.net")
        self.assertFalse(is_blocked("ads.doubleclick.net", KID))
        self.assertIn("doubleclick.net", server.S.allowed)

    def test_service_block_only_hits_the_chosen_device(self):
        server.set_service_block("device:" + KID, "disneyplus", True)
        self.assertTrue(is_blocked("www.disneyplus.com", KID))
        self.assertTrue(is_blocked("cdn.bamgrid.com", KID))
        self.assertFalse(is_blocked("www.disneyplus.com", ADULT))
        self.assertFalse(is_blocked("www.netflix.com", KID))

    def test_group_rules_reach_members_only(self):
        with server.db_lock:
            gid = server.db.execute("INSERT INTO groups(name) VALUES('Kids')").lastrowid
            server.db.execute("INSERT INTO device_group VALUES(?,?)", (KID, gid))
            server.db.commit()
        server.init_db()
        server.set_service_block("group:%d" % gid, "fortnite", True)
        self.assertTrue(is_blocked("launcher.epicgames.com", KID))
        self.assertFalse(is_blocked("launcher.epicgames.com", ADULT))
        server.set_internet_off("group:%d" % gid, True)
        self.assertTrue(is_blocked("www.bbc.co.uk", KID))
        self.assertFalse(is_blocked("www.bbc.co.uk", ADULT))
        server.delete_group(gid)
        self.assertFalse(is_blocked("www.bbc.co.uk", KID))
        self.assertFalse(is_blocked("launcher.epicgames.com", KID))

    def test_pause_only_pauses_adverts(self):
        server.set_service_block("all", "youtube", True)
        server.S.paused_until = time.time() + 600
        self.assertFalse(is_blocked("ads.doubleclick.net", KID))
        self.assertTrue(is_blocked("www.youtube.com", KID))


class KillSwitch(Base):
    def test_kill_switch_stops_everyone_and_survives_pause(self):
        server.set_internet_off("all", True)
        server.S.paused_until = time.time() + 600
        for client in (KID, ADULT):
            self.assertTrue(is_blocked("www.bbc.co.uk", client))
        self.assertEqual(server.decision("www.bbc.co.uk", KID)[1], "kill")
        self.assertTrue(server.api_status()["kill"])

    def test_the_kill_switch_does_not_stop_this_computers_own_lookups(self):
        # Otherwise the Pi loses the relay and the owner can't switch it back on from outside.
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        server.S.local_ip = "192.168.1.60"
        server.set_internet_off("all", True)
        for client in ("127.0.0.1", "192.168.1.60"):
            self.assertFalse(is_blocked("relay.example.com", client), client)

    def test_a_whole_house_bedtime_does_not_stop_this_computers_own_lookups(self):
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        server.S.local_ip = "192.168.1.60"
        self.schedule(scope="all", start="00:00", end="23:59")
        self.assertTrue(is_blocked("www.bbc.co.uk", KID))
        self.assertFalse(is_blocked("www.bbc.co.uk", "127.0.0.1"))

    def test_the_device_list_does_not_show_this_computer_as_switched_off(self):
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        server.S.local_ip = "192.168.1.60"
        server.set_internet_off("device:192.168.1.60", True)
        self.assertFalse(server.internet_off_for("192.168.1.60"))
        self.assertFalse(is_blocked("www.bbc.co.uk", "192.168.1.60"))

    def test_this_computers_own_lookups_still_follow_the_advert_list(self):
        self.assertTrue(is_blocked("ads.doubleclick.net", "127.0.0.1"))

    def test_kill_switch_overrides_always_allowed(self):
        server.unblock("doubleclick.net")
        server.set_internet_off("all", True)
        self.assertTrue(is_blocked("doubleclick.net", KID))

    def test_turning_it_off_restores_everything(self):
        server.set_internet_off("all", True)
        server.set_internet_off("all", False)
        self.assertFalse(is_blocked("www.bbc.co.uk", KID))
        self.assertFalse(server.api_status()["kill"])

    def test_unblock_during_kill_switch_adds_no_exception(self):
        server.set_internet_off("all", True)
        server.unblock("www.bbc.co.uk")
        self.assertEqual(server.S.allowed, set())


class Schedules(Base):
    def test_daytime_window(self):
        x = self.schedule(days=[0, 1, 2, 3, 4], start="16:00", end="18:00")
        self.assertFalse(server.schedule_in_force(x, at(0, "15:59")))
        self.assertTrue(server.schedule_in_force(x, at(0, "16:00")))
        self.assertTrue(server.schedule_in_force(x, at(4, "17:59")))
        self.assertFalse(server.schedule_in_force(x, at(0, "18:00")))
        self.assertFalse(server.schedule_in_force(x, at(5, "17:00")))       # Saturday

    def test_overnight_window_belongs_to_the_evening_it_started(self):
        x = self.schedule(days=[6, 0, 1, 2, 3], start="21:00", end="07:00")  # school nights: Sun-Thu
        self.assertTrue(server.schedule_in_force(x, at(6, "21:00")))        # Sunday evening
        self.assertTrue(server.schedule_in_force(x, at(0, "06:59")))        # ...into Monday morning
        self.assertFalse(server.schedule_in_force(x, at(0, "07:00")))
        self.assertTrue(server.schedule_in_force(x, at(3, "23:30")))        # Thursday night
        self.assertTrue(server.schedule_in_force(x, at(4, "02:00")))        # ...into Friday morning
        self.assertFalse(server.schedule_in_force(x, at(4, "22:00")))       # Friday night is free
        self.assertFalse(server.schedule_in_force(x, at(5, "03:00")))       # so is Saturday morning
        self.assertFalse(server.schedule_in_force(x, at(6, "03:00")))       # and Sunday morning

    def test_week_wraps_from_sunday_to_monday(self):
        x = self.schedule(days=[6], start="23:00", end="01:00")
        self.assertTrue(server.schedule_in_force(x, at(0, "00:30")))
        self.assertFalse(server.schedule_in_force(x, at(1, "00:30")))

    def test_bedtime_turns_internet_off_for_that_device_only(self):
        self.schedule(start="00:00", end="23:59")                           # in force now
        self.assertTrue(is_blocked("www.bbc.co.uk", KID))
        self.assertFalse(is_blocked("www.bbc.co.uk", ADULT))
        self.assertEqual(server.decision("www.bbc.co.uk", KID)[1:], ("schedule", "Bedtime"))
        self.assertTrue(server.internet_off_for(KID))

    def test_service_schedule_blocks_only_those_services(self):
        self.schedule(name="Homework", start="00:00", end="23:59", off=False, services=["youtube", "fortnite"])
        self.assertTrue(is_blocked("www.youtube.com", KID))
        self.assertTrue(is_blocked("fortnite.com", KID))
        self.assertFalse(is_blocked("www.bbc.co.uk", KID))
        self.assertFalse(is_blocked("www.youtube.com", ADULT))

    def test_schedule_outside_its_hours_or_switched_off_does_nothing(self):
        now = time.localtime()
        later = "%02d:00" % ((now.tm_hour + 2) % 24)
        later_end = "%02d:00" % ((now.tm_hour + 3) % 24)
        self.schedule(start=later, end=later_end)
        self.assertFalse(is_blocked("www.bbc.co.uk", KID))
        x = self.schedule(name="Always", start="00:00", end="23:59")
        self.assertTrue(is_blocked("www.bbc.co.uk", KID))
        server.sql("UPDATE schedules SET enabled=0 WHERE id=?", (x["id"],), commit=True)
        server.load_schedules()
        self.assertFalse(is_blocked("www.bbc.co.uk", KID))

    def test_whole_house_schedule_and_pause(self):
        self.schedule(scope="all", start="00:00", end="23:59", off=False, services=["tiktok"])
        server.S.paused_until = time.time() + 600
        self.assertTrue(is_blocked("www.tiktok.com", ADULT))

    def test_bad_schedules_are_refused(self):
        good = {"name": "x", "scope": "all", "days": [0], "start": "21:00", "end": "07:00", "off": True}
        for change in ({"days": []}, {"days": [7]}, {"days": "0"}, {"start": "25:00"}, {"end": ""}, {"end": "21:00"},
                       {"scope": "group:999"}, {"scope": "nonsense"}, {"off": False, "services": []},
                       {"off": False, "services": ["not-a-service"]},
                       {"days": [1.0, 2.0]}, {"days": [True, False]}, {"days": [0, 1.5]},   # not whole-number days
                       {"off": False, "services": 5}, {"off": False, "services": "netflix"}):  # services not a list
            self.assertIsInstance(server.save_schedule(dict(good, **change)), str, change)
        self.assertEqual(server.S.schedules, [])

    def test_schedules_survive_a_reload_after_every_save(self):
        # A bad save must never leave a row that stops the schedules loading again (which would stop the app starting).
        server.save_schedule({"scope": "all", "days": [1.0], "start": "09:00", "end": "10:00", "off": True})
        server.load_schedules()   # must not raise
        self.assertEqual(server.S.schedules, [])

    def test_unblocking_during_a_bedtime_schedule_adds_no_permanent_allow(self):
        self.schedule(scope="all", start="00:00", end="23:59", off=True)   # whole house off, in force now
        server.block("news.example.com")
        server.unblock("news.example.com")
        self.assertEqual(server.S.allowed, set())                          # no stray whitelist left behind

    def test_pause_still_honours_an_explicit_allow_over_a_service_block(self):
        server.block("a.tracker.example")
        server.unblock("a.tracker.example")        # no effect (not on the ad list), but harmless
        server.sql("INSERT OR REPLACE INTO allowed VALUES(?,?)", ("tracker.example", 0), commit=True)
        server.S.allowed.add("tracker.example")
        server.block("a.tracker.example")
        server.S.paused_until = time.time() + 600
        # Paused ignores the own-block on a.tracker.example; the explicit allow on tracker.example must still win.
        self.assertFalse(is_blocked("a.tracker.example", KID))

    def test_editing_keeps_the_same_schedule(self):
        x = self.schedule()
        self.assertIsNone(server.save_schedule(dict(x, name="Lights out", start="20:30")))
        self.assertEqual([(s["name"], s["start"]) for s in server.S.schedules], [("Lights out", "20:30")])


class Answers(Base):
    def test_long_memories_are_shortened(self):
        resp = server.answer_query(query("www.bbc.co.uk"), KID, fake_answer)
        ttl = struct.unpack(">I", resp[-10:-6])[0]
        self.assertEqual(ttl, server.MAX_TTL)
        self.assertEqual(resp[-4:], bytes([93, 184, 216, 34]))              # the address itself is untouched

    def test_short_memories_are_left_alone(self):
        resp = server.cap_ttls(fake_answer(query("www.bbc.co.uk"), ttl=30))
        self.assertEqual(struct.unpack(">I", resp[-10:-6])[0], 30)

    def test_garbled_answers_pass_through_unchanged(self):
        good = fake_answer(query("www.bbc.co.uk"))
        for bad in (good[:20], good[:-3], b"", b"\x00" * 11, good[:6] + b"\xff\xff" + good[8:]):
            self.assertEqual(server.cap_ttls(bad), bad)

    def test_a_lying_record_length_is_left_untouched(self):
        # A record that understates its data length, with extra bytes after it, must not be rewritten.
        data = query("www.bbc.co.uk")
        head = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        rec = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">IH", 86400, 0) + bytes([93, 184, 216, 34]) + b"PADDINGPAD"
        self.assertEqual(server.cap_ttls(head + data[12:] + rec), head + data[12:] + rec)

    def test_blocked_answer_is_well_formed(self):
        resp = server.answer_query(query("ads.doubleclick.net"), KID, fake_answer)
        self.assertEqual(resp[:2], b"\x42\x42")
        self.assertEqual(struct.unpack(">HHHH", resp[4:12]), (1, 1, 0, 0))

    def test_when_the_internet_is_unreachable(self):
        resp = server.answer_query(query("www.bbc.co.uk"), KID, lambda data: None)
        self.assertEqual(resp[3] & 15, 2)                                    # "server failure"


class EnforcerLogic(unittest.TestCase):
    def test_arp_reply_frame_layout(self):
        f = enforcer.build_arp_reply("192.168.1.254", "aa:bb:cc:dd:ee:ff", "192.168.1.23", "11:22:33:44:55:66")
        self.assertEqual(f[0:6], bytes.fromhex("112233445566"))         # addressed to the victim
        self.assertEqual(f[6:12], bytes.fromhex("aabbccddeeff"))        # from us (claimed sender)
        self.assertEqual(f[12:14], b"\x08\x06")                         # ARP
        self.assertEqual(f[20:22], b"\x00\x02")                         # opcode = reply
        self.assertEqual(f[28:32], socket.inet_aton("192.168.1.254"))   # sender = the gateway's address
        self.assertEqual(f[38:42], socket.inet_aton("192.168.1.23"))    # target = the victim

    def test_bad_mac_is_rejected(self):
        self.assertRaises(ValueError, enforcer.mac_to_bytes, "not-a-mac")

    def test_nft_ruleset_surgical_vs_full_cut(self):
        plan = {"192.168.1.23": {"off": False, "ips": {"1.2.3.4", "5.6.7.8"}},
                "192.168.1.24": {"off": True, "ips": set()}}
        text = enforcer.nft_ruleset(plan, "192.168.1.60")
        self.assertIn("ip saddr 192.168.1.23 ip daddr { 1.2.3.4, 5.6.7.8 } drop", text)
        self.assertIn("ip saddr 192.168.1.24 ip daddr != 192.168.1.60 drop", text)
        self.assertIn("hook forward", text)

    def test_nothing_blocked_means_no_drop_lines(self):
        text = enforcer.nft_ruleset({"192.168.1.23": {"off": False, "ips": set()}}, "192.168.1.60")
        self.assertNotIn("drop", text)

    def test_iptables_rules(self):
        cmds = enforcer.iptables_rules({"192.168.1.23": {"off": False, "ips": {"1.2.3.4"}}}, "192.168.1.60")
        self.assertIn(["-A", "QUIETNET", "-s", "192.168.1.23", "-d", "1.2.3.4", "-j", "DROP"], cmds)


class EnforcementPlan(Base):
    def _answer(self, name, ip):
        q = query(name)
        head = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        return head + q[12:] + b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">IH", 300, 4) + socket.inet_aton(ip)

    def test_resolved_ips_are_extracted(self):
        self.assertEqual(server.answer_ips(self._answer("www.disneyplus.com", "203.0.113.5")), ["203.0.113.5"])

    def test_plan_drops_a_blocked_services_addresses_for_the_enforced_device(self):
        server.record_resolved("www.disneyplus.com", self._answer("www.disneyplus.com", "203.0.113.5"))
        server.record_resolved("www.bbc.co.uk", self._answer("www.bbc.co.uk", "151.101.0.81"))
        server.set_service_block("device:" + KID, "disneyplus", True)
        server.S.enforced = {KID}
        plan = server.enforcement_plan()
        self.assertIn(KID, plan)
        self.assertFalse(plan[KID]["off"])
        self.assertIn("203.0.113.5", plan[KID]["ips"])       # Disney's address is dropped
        self.assertNotIn("151.101.0.81", plan[KID]["ips"])   # the BBC's is not

    def test_plan_is_full_cut_when_device_internet_is_off(self):
        server.record_resolved("www.bbc.co.uk", self._answer("www.bbc.co.uk", "151.101.0.81"))
        server.set_internet_off("device:" + KID, True)
        server.S.enforced = {KID}
        self.assertTrue(server.enforcement_plan()[KID]["off"])

    def test_no_enforced_devices_means_empty_plan(self):
        server.S.enforced = set()
        self.assertEqual(server.enforcement_plan(), {})

    def test_advert_list_addresses_are_not_cut_by_address(self):
        # Advert names often share addresses with ordinary sites, so they stay a DNS-only block.
        server.record_resolved("ads.doubleclick.net", self._answer("ads.doubleclick.net", "142.250.1.1"))
        self.assertTrue(server.decision("ads.doubleclick.net", KID)[0])
        server.S.enforced = {KID}
        self.assertNotIn("142.250.1.1", server.enforcement_plan()[KID]["ips"])

    def test_an_all_internet_schedule_is_a_full_cut(self):
        body = {"name": "Bedtime", "scope": "device:" + KID, "days": [0, 1, 2, 3, 4, 5, 6],
                "start": "00:00", "end": "23:59", "off": True, "services": []}
        self.assertIsNone(server.save_schedule(body))
        server.S.sched_cache = (0.0, [])
        server.S.enforced = {KID}
        self.assertTrue(server.enforcement_plan()[KID]["off"])

    def test_pausing_also_pauses_your_own_blocks_in_the_plan(self):
        server.block("example.org")
        server.record_resolved("example.org", self._answer("example.org", "198.51.100.7"))
        server.S.enforced = {KID}
        self.assertIn("198.51.100.7", server.enforcement_plan()[KID]["ips"])
        server.S.paused_until = time.time() + 600
        self.assertNotIn("198.51.100.7", server.enforcement_plan()[KID]["ips"])

    def test_the_plan_says_which_device_it_means(self):
        server.S.enforced, server.S.enforced_mac = {KID}, {KID: "aa:bb:cc:dd:ee:ff"}
        self.assertEqual(server.enforcement_plan()[KID]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_the_plan_does_not_ask_again_about_names_it_has_already_worked_out(self):
        # It runs every two seconds; re-checking thousands of unchanged names each time wastes the Pi.
        server.record_resolved("www.bbc.co.uk", self._answer("www.bbc.co.uk", "151.101.0.81"))
        server.S.enforced = {KID}
        server.enforcement_plan()
        with mock.patch.object(server, "decision", wraps=server.decision) as asked:
            server.enforcement_plan()
        self.assertEqual(asked.call_count, 0)

    def test_a_rule_change_is_seen_by_the_next_plan(self):
        server.record_resolved("example.org", self._answer("example.org", "198.51.100.7"))
        server.S.enforced = {KID}
        self.assertNotIn("198.51.100.7", server.enforcement_plan()[KID]["ips"])
        server.block("example.org")
        self.assertIn("198.51.100.7", server.enforcement_plan()[KID]["ips"])

    def test_a_new_address_for_a_blocked_name_is_added_to_the_next_plan(self):
        server.block("example.org")
        server.record_resolved("example.org", self._answer("example.org", "198.51.100.7"))
        server.S.enforced = {KID}
        server.enforcement_plan()
        server.record_resolved("example.org", self._answer("example.org", "198.51.100.8"))
        self.assertIn("198.51.100.8", server.enforcement_plan()[KID]["ips"])

    def test_a_name_seen_after_the_last_plan_is_added_to_the_next_one(self):
        server.block("example.org")
        server.S.enforced = {KID}
        server.enforcement_plan()
        server.record_resolved("example.org", self._answer("example.org", "198.51.100.7"))
        self.assertIn("198.51.100.7", server.enforcement_plan()[KID]["ips"])

    def test_recording_a_lookups_addresses_does_not_wait_for_the_database_lock(self):
        # Every allowed answer records its addresses before it is sent; a slow database query
        # elsewhere must not hold it up.
        done = threading.Event()
        server.db_lock.acquire()
        try:
            t = threading.Thread(target=lambda: (server.record_resolved(
                "www.bbc.co.uk", self._answer("www.bbc.co.uk", "151.101.0.81")), done.set()))
            t.start()
            finished = done.wait(5)
        finally:
            server.db_lock.release()
        t.join()
        self.assertTrue(finished)

    def test_addresses_a_name_no_longer_uses_are_forgotten(self):
        server.record_resolved("x.example.com", self._answer("x.example.com", "198.51.100.1"))
        server.S.resolved["x.example.com"]["198.51.100.1"] = time.time() - 7 * 3600
        server.record_resolved("x.example.com", self._answer("x.example.com", "198.51.100.2"))
        self.assertEqual(set(server.S.resolved["x.example.com"]), {"198.51.100.2"})


class HistoryLimits(Base):
    def fill(self, rows, ts=None):
        now = time.time()
        server.sql("DELETE FROM queries", commit=True)
        with server.db_lock:
            server.db.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)",
                                  [(ts or now, KID, "n%d.example.com" % i) for i in range(rows)])
            server.db.commit()

    def test_history_is_capped_by_size_as_well_as_age(self):
        self.fill(50)
        with mock.patch.object(server, "MAX_HISTORY_ROWS", 20):
            server.prune_history()
        names = [r[0] for r in server.sql("SELECT domain FROM queries ORDER BY id")]
        self.assertEqual(len(names), 20)
        self.assertEqual(names[-1], "n49.example.com")              # the newest are the ones kept

    def test_old_history_is_deleted(self):
        self.fill(10, ts=time.time() - (server.KEEP_DAYS + 1) * 86400)
        server.prune_history()
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries")[0][0], 0)

    def test_a_big_trim_lets_go_of_the_lock_between_steps(self):
        # So DNS answers, which need the same lock, aren't held up behind millions of deletions.
        self.fill(50)
        steps = []

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
            steps.append(got[0])
        with mock.patch.object(server, "MAX_HISTORY_ROWS", 5), mock.patch.object(server, "PRUNE_BATCH", 10), \
                mock.patch.object(server.time, "sleep", lock_free_for_another_thread):
            server.prune_history()
        self.assertGreaterEqual(len(steps), 4)                      # 45 rows in steps of 10
        self.assertTrue(all(steps))                                 # the lock was free at every pause
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries")[0][0], 5)

    def explain(self, statement, args):
        return " | ".join(row[-1] for row in server.sql("EXPLAIN QUERY PLAN " + statement, args))

    def test_trimming_old_history_finds_the_rows_through_the_time_index(self):
        # It runs every ten minutes; reading the whole table each time would hold the lock for long.
        plan = self.explain(server.PRUNE_OLD_SQL, (0, 10))
        self.assertIn("INDEX q_ts (ts<?)", plan)
        self.assertNotIn("SCAN queries", plan)

    def test_trimming_surplus_history_finds_the_rows_by_row_number(self):
        plan = self.explain(server.PRUNE_SURPLUS_SQL, (0, 10))
        self.assertIn("INTEGER PRIMARY KEY (rowid<?)", plan)
        self.assertNotIn("SCAN queries", plan)

    def test_history_is_trimmed_by_age_and_size_in_the_same_pass(self):
        now = time.time()
        old = now - (server.KEEP_DAYS + 1) * 86400
        server.sql("DELETE FROM queries", commit=True)
        with server.db_lock:
            server.db.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,0)",
                                  [(old if i < 5 else now, KID, "n%d.example.com" % i) for i in range(30)])
            server.db.commit()
        with mock.patch.object(server, "MAX_HISTORY_ROWS", 20):
            server.prune_history()
        names = [r[0] for r in server.sql("SELECT domain FROM queries ORDER BY id")]
        self.assertEqual(names, ["n%d.example.com" % i for i in range(10, 30)])

    def test_an_older_database_gains_the_hardware_address_column(self):
        server.db.execute("DROP TABLE enforced")
        server.db.execute("CREATE TABLE enforced(ip TEXT PRIMARY KEY)")      # as 0.5 made it
        server.db.execute("INSERT INTO enforced VALUES(?)", (KID,))
        server.db.commit()
        server.init_db()
        self.assertEqual(server.S.enforced, {KID})
        self.assertEqual(server.S.enforced_mac, {KID: ""})

    def test_at_most_64_addresses_are_kept_per_name(self):
        for i in range(80):
            server.record_resolved("cdn.example.com", EnforcementPlan._answer(self, "cdn.example.com", "198.51.100.%d" % i))
            server.S.resolved["cdn.example.com"]["198.51.100.%d" % i] = time.time() - 80 + i
        kept = server.S.resolved["cdn.example.com"]
        self.assertEqual(len(kept), 64)
        self.assertIn("198.51.100.79", kept)                         # the newest are the ones kept
        self.assertNotIn("198.51.100.0", kept)


class ThisComputersAddress(Base):
    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        self.addCleanup(setattr, server, "ENF", server.ENF)
        server.ENF = None
        p = mock.patch("builtins.print")                    # the 'address is now' notice
        p.start()
        self.addCleanup(p.stop)

    def test_a_new_address_for_this_computer_is_picked_up(self):
        server.S.local_ip = "127.0.0.1"                     # started before the network was ready
        with mock.patch.object(server, "find_local_ip", return_value="192.168.1.60"):
            self.assertTrue(server.refresh_local_ip())
        self.assertEqual(server.S.local_ip, "192.168.1.60")

    def test_losing_the_network_keeps_the_last_known_address(self):
        server.S.local_ip = "192.168.1.60"
        with mock.patch.object(server, "find_local_ip", return_value="127.0.0.1"):
            self.assertFalse(server.refresh_local_ip())
        self.assertEqual(server.S.local_ip, "192.168.1.60")

    def test_the_enforcer_is_told_this_computers_new_address(self):
        server.S.local_ip = "192.168.1.60"
        server.ENF = mock.Mock(local_ip="192.168.1.60")
        with mock.patch.object(server, "find_local_ip", return_value="192.168.1.61"):
            server.refresh_local_ip()
        self.assertEqual(server.ENF.local_ip, "192.168.1.61")

    def test_this_computers_new_address_is_exempt_from_the_kill_switch(self):
        server.S.local_ip = "127.0.0.1"
        server.set_internet_off("all", True)
        with mock.patch.object(server, "find_local_ip", return_value="192.168.1.60"):
            server.refresh_local_ip()
        self.assertFalse(is_blocked("relay.example.com", "192.168.1.60"))


class AdvertCount(Base):
    def test_the_advert_count_includes_a_newly_downloaded_list(self):
        self.addCleanup(server.count_junk)                  # runs last: cleanups run in reverse order
        self.addCleanup(setattr, server.S, "junk_community", server.S.junk_community)
        before = server.api_status()["junk_count"]
        lines = "\n".join("0.0.0.0 new%d.example.net" % i for i in range(1500)).encode()
        reply = mock.MagicMock()
        reply.__enter__.return_value.read.return_value = lines
        path = os.path.join(server.DATA, "test-community.txt")
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        with mock.patch.object(server.urllib.request, "urlopen", return_value=reply), \
                mock.patch.object(server, "COMMUNITY_FILE", path):
            server.update_community_list()
        self.assertEqual(server.api_status()["junk_count"], len(server.S.junk_builtin | server.S.junk_community))
        self.assertGreater(server.api_status()["junk_count"], before)

    def test_the_status_summary_does_not_rebuild_the_advert_lists_to_count_them(self):
        server.S.junk_count = 12345                         # whatever was worked out when the lists last changed
        self.addCleanup(server.count_junk)
        self.assertEqual(server.api_status()["junk_count"], 12345)


class ScanTargets(unittest.TestCase):
    def test_a_scan_covers_the_whole_of_a_bigger_home_network(self):
        # eero's usual network is a /22: four times the 254 addresses a /24 has.
        targets, capped = server.scan_targets("192.168.4.20", server.ipaddress.IPv4Network("192.168.4.0/22"))
        self.assertEqual(len(targets), 1022)
        self.assertIn("192.168.5.37", targets)
        self.assertIn("192.168.5.255", targets)             # an ordinary address on a /22
        self.assertNotIn("192.168.7.255", targets)          # the network's own broadcast address
        self.assertFalse(capped)

    def test_a_scan_of_a_very_big_network_is_capped_around_this_computer(self):
        targets, capped = server.scan_targets("10.0.37.5", server.ipaddress.IPv4Network("10.0.0.0/16"))
        self.assertTrue(capped)
        self.assertLessEqual(len(targets), server.MAX_SCAN)
        self.assertIn("10.0.37.5", targets)

    def test_without_a_known_network_size_the_usual_home_size_is_assumed(self):
        with mock.patch.object(server.enforcer, "interface_and_gateway", return_value=(None, None)):
            self.assertEqual(str(server.home_subnet("192.168.1.60")), "192.168.1.0/24")

    def test_the_network_size_is_read_from_the_routing_table_when_known(self):
        with mock.patch.object(server.enforcer, "interface_and_gateway", return_value=("wlan0", "192.168.4.1")), \
                mock.patch.object(server.enforcer, "local_subnet",
                                  return_value=server.ipaddress.IPv4Network("192.168.4.0/22")):
            self.assertEqual(str(server.home_subnet("192.168.4.20")), "192.168.4.0/22")


if __name__ == "__main__":
    unittest.main()
