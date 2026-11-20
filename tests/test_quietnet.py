"""Checks for QuietNet's rules engine. Run with:  python3 -m unittest discover tests

Uses only Python's standard library, and a throwaway data folder - it never
touches your real history or rules, and never sends anything to the network.
"""
import calendar
import os
import struct
import sys
import tempfile
import time
import unittest

os.environ["QUIETNET_DATA"] = tempfile.mkdtemp(prefix="quietnet-test-")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402

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
        for table in ("blocked", "allowed", "groups", "device_group", "service_blocks", "internet_off", "schedules", "queries"):
            server.sql("DELETE FROM %s" % table, commit=True)
        server.init_db()
        server.S.junk_on, server.S.paused_until = True, 0

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
        for client in (KID, ADULT, "127.0.0.1"):
            self.assertTrue(is_blocked("www.bbc.co.uk", client))
        self.assertEqual(server.decision("www.bbc.co.uk", KID)[1], "kill")
        self.assertTrue(server.api_status()["kill"])

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


if __name__ == "__main__":
    unittest.main()
