"""Checks for the dashboard's web API (the `Web` class in server.py), driven over real
HTTP on a spare port on this computer.

Run with:  python3 -m unittest discover tests

Standard library only; throwaway data folder; nothing leaves this machine.
"""
import http.client
import json
import os
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_quietnet import ADULT, KID, Base, is_blocked, query, server


class Api(Base):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Web)
        cls.httpd.daemon_threads = True
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        super().setUp()
        for table in ("devices", "seen", "settings"):
            server.sql("DELETE FROM %s" % table, commit=True)
        server.S.junk_on, server.S.paused_until = True, 0
        # A stand-in for the computer's neighbour table, so no test reads the real one.
        self.neighbours_now = {}
        p = mock.patch.object(server, "neighbours", lambda: dict(self.neighbours_now))
        p.start()
        self.addCleanup(p.stop)

    def call(self, method, path, body=None, host="localhost", ctype="application/json", raw=None):
        headers = {"Host": host}
        data = raw
        if body is not None:
            data = json.dumps(body)
        if data is not None and ctype:
            headers["Content-Type"] = ctype
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=data, headers=headers)
            r = conn.getresponse()
            text = r.read().decode("utf-8", "replace")
        finally:
            conn.close()
        try:
            return r.status, json.loads(text)
        except ValueError:
            return r.status, text

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.call("POST", path, body={} if body is None and "raw" not in kw else body, **kw)

    def ok(self, path, body=None):
        status, out = self.post(path, body)
        self.assertEqual(status, 200, out)
        return out


class Guards(Api):
    def test_the_dashboard_page_is_served(self):
        status, text = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("QuietNet", text)

    def test_localhost_names_are_accepted_with_or_without_a_port(self):
        for host in ("localhost", "localhost:8377", "127.0.0.1", "127.0.0.1:8377"):
            self.assertEqual(self.get("/api/status", host=host)[0], 200, host)

    def test_any_other_host_name_is_refused(self):
        # A hostile web page can point its own name at 127.0.0.1 and have your browser call
        # this dashboard. The browser still sends the page's name as Host, so refusing on
        # that stops it. (It also means the dashboard cannot be opened by the Pi's network
        # address - see docs/KNOWN_ISSUES.md.)
        for host in ("evil.example", "evil.example:8377", "192.168.1.60:8377", "localhost.evil.example", ""):
            self.assertEqual(self.get("/api/status", host=host)[0], 403, host)
            self.assertEqual(self.post("/api/kill", {"on": True}, host=host)[0], 403, host)
        self.assertNotIn("all", server.S.off)

    def test_changes_must_be_sent_as_json(self):
        # A plain web form on another site cannot send JSON without the browser asking this
        # server's permission first, which it never grants. So a forged form post gets nowhere.
        for ctype in ("application/x-www-form-urlencoded", "text/plain", None):
            status, _ = self.post("/api/kill", raw='{"on": true}', ctype=ctype)
            self.assertEqual(status, 415, ctype)
        self.assertNotIn("all", server.S.off)

    def test_plain_text_that_mentions_json_in_its_type_is_refused(self):
        # Browsers send 'text/plain; application/json' from any page without asking first,
        # so a check that only looked for the words 'application/json' could be fooled.
        for ctype in ("text/plain; application/json", "text/plain;application/json", "application/jsonx"):
            self.assertEqual(self.post("/api/kill", raw='{"on": true}', ctype=ctype)[0], 415, ctype)
        self.assertNotIn("all", server.S.off)

    def test_json_with_a_charset_is_accepted(self):
        self.assertEqual(self.post("/api/kill", raw='{"on": false}', ctype="application/json; charset=utf-8")[0], 200)

    def changed_from(self, origin):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", "/api/kill", body='{"on": true}',
                         headers={"Host": "localhost", "Content-Type": "application/json", "Origin": origin})
            return conn.getresponse().status
        finally:
            conn.close()

    def test_a_change_sent_by_another_website_is_refused(self):
        self.assertEqual(self.changed_from("https://evil.example"), 415)
        self.assertEqual(self.changed_from("null"), 415)
        self.assertNotIn("all", server.S.off)

    def test_a_change_sent_from_this_computer_on_any_port_is_accepted(self):
        # An SSH tunnel to a Pi may put the dashboard on a different local port.
        self.assertEqual(self.changed_from("http://localhost:9000"), 200)
        server.set_internet_off("all", False)

    def test_unreadable_json_is_refused(self):
        self.assertEqual(self.post("/api/kill", raw="{not json")[0], 400)
        self.assertNotIn("all", server.S.off)

    def test_every_answer_carries_the_protective_headers(self):
        # Without the frame headers, another website could show this dashboard inside itself,
        # invisibly, and trick someone into clicking the kill switch.
        wanted = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
                  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
        for method, path, host in (("GET", "/", "localhost"), ("GET", "/api/status", "localhost"),
                                   ("GET", "/api/nope", "localhost"), ("GET", "/api/status", "evil.example"),
                                   ("POST", "/api/kill", "localhost")):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request(method, path, headers={"Host": host})
            r = conn.getresponse()
            r.read()
            conn.close()
            for name, value in wanted.items():
                self.assertEqual(r.getheader(name), value, "%s on %s %s (%d)" % (name, method, path, r.status))

    def test_an_oversized_body_is_refused_unread(self):
        status, _ = self.post("/api/block", {"domain": "x" * (server.MAX_BODY + 1)})
        self.assertEqual(status, 413)
        self.assertEqual(server.S.blocked, set())

    def test_a_nonsense_length_is_refused(self):
        for length in ("-1", "lots"):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.putrequest("POST", "/api/kill", skip_host=True)
            for name, value in (("Host", "localhost"), ("Content-Type", "application/json"), ("Content-Length", length)):
                conn.putheader(name, value)
            conn.endheaders()
            status = conn.getresponse().status
            conn.close()
            self.assertIn(status, (400, 413), length)
        self.assertNotIn("all", server.S.off)

    def test_json_that_is_not_an_object_is_refused(self):
        for raw in ("[1, 2]", '"text"', "5", "null"):
            self.assertEqual(self.post("/api/kill", raw=raw)[0], 400, raw)
        self.assertNotIn("all", server.S.off)

    def test_values_of_the_wrong_kind_get_a_clean_refusal(self):
        # Each of these used to make the server drop the connection with no answer.
        for path, body in (("/api/group", {"name": "Kids", "id": [1]}),
                           ("/api/group-delete", {"id": {"a": 1}}),
                           ("/api/device-group", {"ip": "192.168.1.23", "group": [1]}),
                           ("/api/schedule-delete", {"id": {"a": 1}}),
                           ("/api/schedule-enable", {"id": [1], "on": True}),
                           ("/api/pause", {"minutes": "soon"}), ("/api/pause", {"minutes": [10]}),
                           ("/api/pause", {"minutes": "nan"})):
            status, _ = self.post(path, body)
            self.assertEqual(status, 400, (path, body))
        self.assertEqual(server.S.paused_until, 0)

    def test_unknown_addresses_are_not_found(self):
        self.assertEqual(self.get("/api/nope")[0], 404)
        self.assertEqual(self.post("/api/nope")[0], 404)
        self.assertEqual(self.get("/server.py")[0], 404)
        self.assertEqual(self.get("/../server.py")[0], 404)


class BlockingAddresses(Api):
    def test_block_then_unblock(self):
        self.assertEqual(self.ok("/api/block", {"domain": "example.com"}), {"ok": True, "domain": "example.com"})
        self.assertTrue(is_blocked("shop.example.com", KID))
        self.ok("/api/unblock", {"domain": "example.com"})
        self.assertFalse(is_blocked("shop.example.com", KID))

    def test_whatever_is_typed_is_tidied_first(self):
        out = self.ok("/api/block", {"domain": "https://WWW.Example.com/some/page"})
        self.assertEqual(out["domain"], "example.com")
        self.assertEqual(server.S.blocked, {"example.com"})

    def test_nonsense_is_refused_with_a_plain_message(self):
        for domain in ("", "not an address", None, "localhost"):
            status, out = self.post("/api/block", {"domain": domain})
            self.assertEqual(status, 400, domain)
            self.assertEqual(out, {"error": "That doesn't look like a web address."})
        self.assertEqual(server.S.blocked, set())

    def test_a_domain_that_is_not_text_is_refused_politely(self):
        # These used to make the server drop the connection with no answer at all.
        for path in ("/api/block", "/api/unblock", "/api/forget"):
            for domain in (42, 4.2, True, ["example.com"], {"d": "example.com"}):
                self.assertEqual(self.post(path, {"domain": domain})[0], 400, (path, domain))
        self.assertEqual((server.S.blocked, server.S.allowed), (set(), set()))

    def test_the_rules_page_lists_blocks_and_allows_with_owners(self):
        self.ok("/api/block", {"domain": "tiktok.com"})
        self.ok("/api/unblock", {"domain": "doubleclick.net"})         # on the advert list, so it becomes an allow
        _, rules = self.get("/api/rules")
        self.assertEqual([(r["d"], r["owner"]) for r in rules["blocked"]], [("tiktok.com", "TikTok")])
        self.assertEqual([(r["d"], r["owner"]) for r in rules["allowed"]], [("doubleclick.net", "Google adverts")])

    def test_blocking_an_address_removes_allows_beneath_it(self):
        self.ok("/api/unblock", {"domain": "ads.doubleclick.net"})
        self.assertEqual(server.S.allowed, {"ads.doubleclick.net"})
        self.ok("/api/block", {"domain": "doubleclick.net"})
        self.assertEqual(server.S.allowed, set())

    def test_forget_removes_both_kinds_of_rule(self):
        self.ok("/api/block", {"domain": "example.com"})
        self.ok("/api/unblock", {"domain": "doubleclick.net"})
        self.ok("/api/forget", {"domain": "example.com"})
        self.ok("/api/forget", {"domain": "doubleclick.net"})
        self.assertEqual((server.S.blocked, server.S.allowed), (set(), set()))
        self.assertTrue(is_blocked("ads.doubleclick.net", KID))         # back to the advert list's verdict

    @unittest.skipIf(os.name == "nt", "file permissions work differently on Windows")
    def test_the_data_folder_is_private_to_its_owner(self):
        # It holds the household's browsing history.
        self.assertEqual(os.stat(server.DATA).st_mode & 0o777, 0o700)

    def test_rules_survive_a_restart(self):
        self.ok("/api/block", {"domain": "example.com"})
        server.S.blocked = set()
        server.init_db()                                                # what start-up does
        self.assertEqual(server.S.blocked, {"example.com"})


class Switches(Api):
    def test_kill_switch_on_and_off(self):
        self.ok("/api/kill", {"on": True})
        self.assertTrue(self.get("/api/status")[1]["kill"])
        self.assertTrue(is_blocked("www.bbc.co.uk", ADULT))
        self.ok("/api/kill", {"on": False})
        self.assertFalse(self.get("/api/status")[1]["kill"])

    def test_the_internet_switch_cannot_be_used_for_the_whole_house(self):
        # Whole-house off is the kill switch's job, so it can't be flipped by accident from a device page.
        self.assertEqual(self.post("/api/internet", {"scope": "all", "off": True})[0], 400)
        self.assertNotIn("all", server.S.off)

    def test_internet_off_for_one_device(self):
        self.ok("/api/internet", {"scope": "device:" + KID, "off": True})
        self.assertTrue(is_blocked("www.bbc.co.uk", KID))
        self.assertFalse(is_blocked("www.bbc.co.uk", ADULT))
        _, controls = self.get("/api/controls?scope=device:" + KID)
        self.assertTrue(controls["off"])
        self.ok("/api/internet", {"scope": "device:" + KID, "off": False})
        self.assertFalse(is_blocked("www.bbc.co.uk", KID))

    def test_the_internet_switch_is_refused_for_this_computer(self):
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        server.S.local_ip = "192.168.1.60"
        status, out = self.post("/api/internet", {"scope": "device:192.168.1.60", "off": True})
        self.assertEqual(status, 400)
        self.assertIn("computer it runs on", out["error"])
        self.assertNotIn("device:192.168.1.60", server.S.off)

    def test_badly_formed_scopes_are_refused(self):
        for scope in ("", "everyone", "group:x", "device:", "device:1.2.3.4; drop table"):
            self.assertEqual(self.post("/api/internet", {"scope": scope, "off": True})[0], 400, scope)
            self.assertEqual(self.post("/api/service-block", {"scope": scope, "service": "youtube", "on": True})[0], 400)
        self.assertEqual(self.get("/api/controls?scope=nonsense")[0], 400)
        self.assertEqual(self.get("/api/controls")[0], 400)
        self.assertEqual((server.S.off, server.S.svc_blocks), (set(), {}))

    def test_blocking_a_service(self):
        self.ok("/api/service-block", {"scope": "device:" + KID, "service": "youtube", "on": True})
        self.assertTrue(is_blocked("www.youtube.com", KID))
        self.assertFalse(is_blocked("www.youtube.com", ADULT))
        _, controls = self.get("/api/controls?scope=device:" + KID)
        self.assertEqual(controls["services"]["youtube"], {"on": True, "from": ""})
        self.assertEqual(controls["services"]["netflix"], {"on": False, "from": ""})
        self.ok("/api/service-block", {"scope": "device:" + KID, "service": "youtube", "on": False})
        self.assertFalse(is_blocked("www.youtube.com", KID))

    def test_unknown_services_are_refused(self):
        for service in ("not-a-service", None, 5):
            status, _ = self.post("/api/service-block", {"scope": "all", "service": service, "on": True})
            self.assertEqual(status, 400, service)

    def test_a_device_page_explains_blocks_it_inherits(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/device-group", {"ip": KID, "group": gid})
        self.ok("/api/service-block", {"scope": "all", "service": "tiktok", "on": True})
        self.ok("/api/service-block", {"scope": "group:%d" % gid, "service": "fortnite", "on": True})
        self.ok("/api/internet", {"scope": "group:%d" % gid, "off": True})
        _, c = self.get("/api/controls?scope=device:" + KID)
        self.assertEqual(c["services"]["tiktok"], {"on": False, "from": "for the whole house"})
        self.assertEqual(c["services"]["fortnite"], {"on": False, "from": "for the Kids group"})
        self.assertEqual((c["off"], c["off_from"]), (False, "for the Kids group"))
        self.ok("/api/kill", {"on": True})
        self.assertEqual(self.get("/api/controls?scope=device:" + KID)[1]["off_from"], "by the kill switch")

    def test_the_service_catalogue_hides_the_address_lists(self):
        _, services = self.get("/api/services")
        self.assertGreater(len(services), 20)
        self.assertEqual(set(services[0]), {"id", "name", "cat"})

    def test_advert_blocking_can_be_switched_off_and_stays_off_after_a_restart(self):
        self.ok("/api/junk-switch", {"on": False})
        self.assertFalse(is_blocked("ads.doubleclick.net", KID))
        self.assertFalse(self.get("/api/status")[1]["junk_on"])
        server.S.junk_on = True
        server.init_db()
        self.assertFalse(server.S.junk_on)

    def test_pause_for_ten_minutes_then_resume(self):
        self.ok("/api/pause", {"minutes": 10})
        left = self.get("/api/status")[1]["paused_for"]
        self.assertTrue(590 <= left <= 600, left)
        self.assertFalse(is_blocked("ads.doubleclick.net", KID))
        self.ok("/api/pause", {"minutes": 0})
        self.assertEqual(self.get("/api/status")[1]["paused_for"], 0)
        self.assertTrue(is_blocked("ads.doubleclick.net", KID))

    def test_a_pause_can_never_run_longer_than_a_day(self):
        self.ok("/api/pause", {"minutes": 10 ** 9})
        self.assertLessEqual(self.get("/api/status")[1]["paused_for"], 24 * 3600)
        self.ok("/api/pause", {"minutes": -5})
        self.assertEqual(self.get("/api/status")[1]["paused_for"], 0)


class Groups(Api):
    def test_create_rename_and_list(self):
        gid = self.ok("/api/group", {"name": "  Kids  "})["id"]
        self.ok("/api/device-group", {"ip": KID, "group": gid})
        self.ok("/api/group", {"id": gid, "name": "Children"})
        _, groups = self.get("/api/groups")
        self.assertEqual(groups, [{"id": gid, "name": "Children", "off": False, "members": [KID],
                                   "devices": [self.device(KID)], "services": 0}])

    def test_a_group_needs_a_name(self):
        status, out = self.post("/api/group", {"name": "   "})
        self.assertEqual((status, out), (400, {"error": "Please give the group a name."}))
        self.assertEqual(server.S.group_names, {})

    def test_long_names_are_cut_to_forty_characters(self):
        self.ok("/api/group", {"name": "x" * 200})
        self.assertEqual([len(n) for n in server.S.group_names.values()], [40])

    def test_a_device_is_in_one_group_at_a_time(self):
        kids = self.ok("/api/group", {"name": "Kids"})["id"]
        tvs = self.ok("/api/group", {"name": "TVs"})["id"]
        self.ok("/api/device-group", {"ip": KID, "group": kids})
        self.ok("/api/device-group", {"ip": KID, "group": tvs})
        self.assertEqual(server.S.dev_group, {self.device(KID): tvs})

    def test_choosing_no_group_takes_the_device_out(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/device-group", {"ip": KID, "group": gid})
        self.ok("/api/device-group", {"ip": KID, "group": None})
        self.assertEqual(server.S.dev_group, {})
        self.ok("/api/device-group", {"ip": KID, "group": 9999})        # a group that doesn't exist
        self.assertEqual(server.S.dev_group, {})

    def test_deleting_a_group_takes_its_rules_and_schedules_with_it(self):
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        scope = "group:%d" % gid
        self.ok("/api/device-group", {"ip": KID, "group": gid})
        self.ok("/api/internet", {"scope": scope, "off": True})
        self.ok("/api/service-block", {"scope": scope, "service": "youtube", "on": True})
        self.ok("/api/schedule", {"name": "Bedtime", "scope": scope, "days": [0], "start": "21:00", "end": "07:00", "off": True})
        self.ok("/api/group-delete", {"id": gid})
        self.assertEqual(self.get("/api/groups")[1], [])
        self.assertEqual(self.get("/api/schedules")[1], [])
        self.assertFalse(is_blocked("www.youtube.com", KID))
        server.init_db()                                                # nothing comes back after a restart
        self.assertEqual((server.S.group_names, server.S.dev_group, server.S.off, server.S.svc_blocks), ({}, {}, set(), {}))

    def test_deleting_a_group_that_is_not_there_is_harmless(self):
        self.ok("/api/group-delete", {"id": 12345})


class ScheduleApi(Api):
    GOOD = {"name": "Homework", "scope": "all", "days": [0, 1, 2, 3, 4], "start": "00:00", "end": "23:59",
            "off": False, "services": ["youtube"]}

    def test_a_bad_schedule_comes_back_with_a_plain_message(self):
        status, out = self.post("/api/schedule", dict(self.GOOD, days=[]))
        self.assertEqual((status, out), (400, {"error": "Please choose at least one day."}))
        status, out = self.post("/api/schedule", dict(self.GOOD, end="00:00"))
        self.assertEqual(out, {"error": "The start and end times can't be the same."})
        self.assertEqual(self.get("/api/schedules")[1], [])

    def test_a_saved_schedule_is_listed_with_whether_it_is_on_right_now(self):
        every_day = dict(self.GOOD, days=[0, 1, 2, 3, 4, 5, 6])
        self.ok("/api/schedule", every_day)
        _, schedules = self.get("/api/schedules")
        self.assertEqual(len(schedules), 1)
        x = schedules[0]
        self.assertEqual((x["name"], x["scope"], x["services"], x["off"], x["enabled"]),
                         ("Homework", "all", ["youtube"], False, True))
        self.assertEqual(x["active"], time.strftime("%H:%M") != "23:59")

    def test_switching_a_schedule_off_and_on(self):
        self.ok("/api/schedule", dict(self.GOOD, days=[0, 1, 2, 3, 4, 5, 6], start="00:00", end="23:59"))
        sid = self.get("/api/schedules")[1][0]["id"]
        self.ok("/api/schedule-enable", {"id": sid, "on": False})
        x = self.get("/api/schedules")[1][0]
        self.assertEqual((x["enabled"], x["active"]), (False, False))
        self.assertFalse(is_blocked("www.youtube.com", KID))
        self.ok("/api/schedule-enable", {"id": sid, "on": True})
        self.assertTrue(self.get("/api/schedules")[1][0]["enabled"])

    def test_deleting_a_schedule(self):
        self.ok("/api/schedule", self.GOOD)
        sid = self.get("/api/schedules")[1][0]["id"]
        self.ok("/api/schedule-delete", {"id": sid})
        self.assertEqual(self.get("/api/schedules")[1], [])

    def test_an_all_internet_schedule_ignores_any_service_list(self):
        self.ok("/api/schedule", dict(self.GOOD, off=True, services=["youtube", "netflix"]))
        x = self.get("/api/schedules")[1][0]
        self.assertEqual((x["off"], x["services"]), (True, []))

    def test_a_schedule_for_a_group_that_does_not_exist_is_refused(self):
        status, out = self.post("/api/schedule", dict(self.GOOD, scope="group:77"))
        self.assertEqual((status, out), (400, {"error": "Please choose who the schedule is for."}))


class Devices(Api):
    def log(self, client, domain, blocked=0, ago=60):
        server.sql("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,?)",
                   (time.time() - ago, client, domain, blocked), commit=True)

    def test_a_device_appears_once_it_has_looked_something_up(self):
        self.log(KID, "www.bbc.co.uk")
        self.log(KID, "ads.doubleclick.net", blocked=1)
        self.log(KID, "old.example.com", ago=2 * 86400)                 # more than a day ago: not in today's count
        _, devices = self.get("/api/devices")
        self.assertEqual(len(devices), 1)
        d = devices[0]
        self.assertEqual((d["ip"], d["n"], d["nb"], d["name"], d["off"], d["enforced"]), (KID, 2, 1, "", False, False))

    def test_a_device_that_tried_another_dns_service_is_flagged_in_the_device_list(self):
        self.log(KID, "www.bbc.co.uk")
        server.set_service_block("device:" + KID, "tiktok", True)
        server.answer_query(query("dns.google"), KID, lambda d: None)
        d = self.get("/api/devices")[1][0]
        self.assertGreater(d["other_dns"], time.time() - 60)

    def test_a_device_that_never_tried_another_dns_service_is_not_flagged(self):
        self.log(KID, "www.bbc.co.uk")
        self.assertEqual(self.get("/api/devices")[1][0]["other_dns"], 0)

    def test_a_dns_service_lookup_is_flagged_in_the_devices_activity(self):
        self.log(KID, "abc.dns.nextdns.io", blocked=1)
        server.set_service_block("device:" + KID, "tiktok", True)
        g = self.get("/api/activity?ip=%s&hours=24" % KID)[1][0]
        self.assertTrue(g["other_dns"])
        self.assertEqual((g["hosts"][0]["b"], g["hosts"][0]["why"]), (True, "other_dns"))

    def test_a_dns_service_lookup_is_not_flagged_for_a_device_with_no_rules(self):
        self.log(KID, "abc.dns.nextdns.io")
        g = self.get("/api/activity?ip=%s&hours=24" % KID)[1][0]
        self.assertFalse(g["other_dns"])

    def test_the_other_dns_switch_is_saved_and_shown_in_the_status(self):
        self.ok("/api/other-dns-switch", {"on": True})
        self.assertTrue(self.get("/api/status")[1]["other_dns_all"])
        server.init_db()
        self.assertTrue(server.S.other_dns_all)
        self.ok("/api/other-dns-switch", {"on": False})
        self.assertFalse(server.S.other_dns_all)

    def test_the_no_ipv6_switch_is_off_until_the_owner_turns_it_on(self):
        self.assertIs(self.get("/api/status")[1]["no_ipv6_all"], False)

    def test_the_no_ipv6_switch_is_saved_and_shown_in_the_status(self):
        self.ok("/api/no-ipv6-switch", {"on": True})
        self.assertTrue(self.get("/api/status")[1]["no_ipv6_all"])
        server.init_db()
        self.assertTrue(server.S.no_ipv6_all)
        self.ok("/api/no-ipv6-switch", {"on": False})
        self.assertFalse(server.S.no_ipv6_all)
        server.init_db()
        self.assertFalse(server.S.no_ipv6_all)

    def test_the_no_ipv6_switch_bites_on_the_very_next_lookup_and_lets_go_as_fast(self):
        v6 = bytes.fromhex("2a001450400908000000000000000200")
        internet = lambda d: d[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + d[12:] \
            + b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10" + v6
        self.assertIn(v6, server.answer_query(query("www.bbc.co.uk", 28), KID, internet))
        self.ok("/api/no-ipv6-switch", {"on": True})
        self.assertNotIn(v6, server.answer_query(query("www.bbc.co.uk", 28), KID, internet))
        self.ok("/api/no-ipv6-switch", {"on": False})
        self.assertIn(v6, server.answer_query(query("www.bbc.co.uk", 28), KID, internet))

    def test_every_device_is_marked_as_able_to_bypass_over_ipv6_while_the_network_has_ipv6(self):
        self.log(KID, "www.bbc.co.uk")
        self.log(ADULT, "www.bbc.co.uk")
        server.S.ra_heard = time.time()
        self.assertEqual([d["v6_bypass"] for d in self.get("/api/devices")[1]], [True, True])

    def test_a_device_with_cut_live_connections_is_still_marked_as_able_to_bypass_over_ipv6(self):
        self.log(KID, "www.bbc.co.uk")
        server.set_live_cut(self.device(KID), True)
        server.S.v6_prefixes = [server.ipaddress.IPv6Network("2001:db8:1:2::/64")]
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["enforced"], d["v6_bypass"]), (True, True))

    def test_a_device_stays_marked_while_an_announcement_with_router_lifetime_0_names_another_ipv6_dns_server(self):
        # A router with no IPv6 internet but a private range still names itself as IPv6 DNS server.
        self.log(KID, "www.bbc.co.uk")
        server.note_router_dns([("fd12:3456:789a::1", 1800)], time.time(), router_lifetime=0)
        self.assertIs(self.get("/api/status")[1]["ipv6"]["in_use"], False)
        self.assertIs(self.get("/api/devices")[1][0]["v6_bypass"], True)

    def test_a_device_is_not_marked_when_the_only_ipv6_dns_server_named_is_quietnet(self):
        self.log(KID, "www.bbc.co.uk")
        server.S.v6_own = {"fd12:3456:789a::60"}
        server.note_router_dns([("fd12:3456:789a::60", 1800)], time.time(), router_lifetime=0)
        with mock.patch.object(server.S, "dns_ipv6", True):
            self.assertIs(self.get("/api/devices")[1][0]["v6_bypass"], False)

    def test_no_device_is_marked_as_able_to_bypass_over_ipv6_on_an_ipv4_only_network(self):
        self.log(KID, "www.bbc.co.uk")
        self.assertIs(self.get("/api/devices")[1][0]["v6_bypass"], False)

    def test_quietnets_own_machine_is_never_marked_as_able_to_bypass_over_ipv6(self):
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        server.S.local_ip = ADULT
        self.log(ADULT, "www.bbc.co.uk")
        server.S.ra_heard = time.time()
        self.assertIs(self.get("/api/devices")[1][0]["v6_bypass"], False)

    def test_the_status_says_whether_the_filter_is_taking_lookups_over_ipv6(self):
        with mock.patch.object(server.S, "dns_ipv6", True):
            self.assertIs(self.get("/api/status")[1]["ipv6"]["taking_lookups"], True)
        with mock.patch.object(server.S, "dns_ipv6", False):
            self.assertIs(self.get("/api/status")[1]["ipv6"]["taking_lookups"], False)

    def test_the_status_carries_the_ipv6_confirmation_and_what_it_rests_on(self):
        ipv6 = self.get("/api/status")[1]["ipv6"]
        self.assertEqual((ipv6["hub_off"], ipv6["listening_for"], ipv6["routers"], ipv6["neighbours_ok"]),
                         (False, 0, [], None))

    def test_the_status_says_whether_this_computer_could_hear_the_router_over_ipv6(self):
        self.assertIsNone(self.get("/api/status")[1]["ipv6"]["can_hear"])
        for known in (False, True):
            server.S.v6_can_hear = known
            self.assertIs(self.get("/api/status")[1]["ipv6"]["can_hear"], known)

    def test_ordinary_activity_is_not_flagged_as_another_dns_service(self):
        self.log(KID, "www.bbc.co.uk")
        g = self.get("/api/activity?ip=%s&hours=24" % KID)[1][0]
        self.assertFalse(g["other_dns"])

    def test_naming_a_device(self):
        self.log(KID, "www.bbc.co.uk")
        self.ok("/api/device-name", {"ip": KID, "name": "  Gabe's tablet  "})
        self.assertEqual(self.get("/api/devices")[1][0]["name"], "Gabe's tablet")
        self.ok("/api/device-name", {"ip": KID, "name": "y" * 100})
        self.assertEqual(len(self.get("/api/devices")[1][0]["name"]), 40)

    def test_devices_found_by_a_scan_are_listed_even_before_they_use_quietnet(self):
        server.sql("INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)", (ADULT, "aa:bb:cc:dd:ee:ff", "laptop", time.time()),
                   commit=True)
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["ip"], d["mac"], d["hint"], d["n"], d["last"]), (ADULT, "aa:bb:cc:dd:ee:ff", "laptop", 0, 0))

    def test_a_suggested_name_comes_with_where_it_was_found_and_the_model(self):
        self.log(KID, "www.bbc.co.uk")
        self.addCleanup(setattr, server.S, "hints", {})
        server.S.hints = {KID: {"name": "Lewis's MacBook Pro", "source": "Bonjour", "detail": "Model: MacBookPro18,3"}}
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["hint"], d["hint_source"], d["hint_detail"]), ("Lewis's MacBook Pro", "Bonjour", "Model: MacBookPro18,3"))

    def test_a_name_found_by_a_scan_is_marked_as_coming_from_the_router(self):
        server.sql("INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)", (ADULT, "00:1b:63:00:00:01", "Lewiss-iPad", time.time()),
                   commit=True)
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["hint"], d["hint_source"], d["hint_detail"]), ("Lewiss iPad", "router", ""))

    def test_a_name_found_now_beats_one_remembered_from_a_scan(self):
        server.sql("INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)", (ADULT, "", "old-name", time.time()), commit=True)
        self.addCleanup(setattr, server.S, "hints", {})
        server.S.hints = {ADULT: {"name": "Den TV", "source": "UPnP", "detail": ""}}
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["hint"], d["hint_source"]), ("Den TV", "UPnP"))

    def test_an_unnamed_device_with_a_private_wifi_address_is_noted_as_probably_a_phone_or_laptop(self):
        server.sql("INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)", (ADULT, "da:a1:19:00:00:01", "", time.time()), commit=True)
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["hint"], d["hint_detail"]), ("", "Private Wi-Fi address, so probably a phone, tablet or laptop"))

    def test_a_device_with_no_suggestion_has_empty_suggestion_fields(self):
        self.log(KID, "www.bbc.co.uk")
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["hint"], d["hint_source"], d["hint_detail"]), ("", "", ""))

    def test_most_recently_active_devices_come_first(self):
        self.log(KID, "www.bbc.co.uk", ago=500)
        self.log(ADULT, "www.bbc.co.uk", ago=5)
        server.sql("INSERT INTO seen(ip,mac,host,ts) VALUES('192.168.1.9','','',0)", commit=True)
        self.assertEqual([d["ip"] for d in self.get("/api/devices")[1]], [ADULT, KID, "192.168.1.9"])

    def test_a_device_shows_its_group_and_whether_its_internet_is_off(self):
        self.log(KID, "www.bbc.co.uk")
        gid = self.ok("/api/group", {"name": "Kids"})["id"]
        self.ok("/api/device-group", {"ip": KID, "group": gid})
        self.ok("/api/internet", {"scope": "group:%d" % gid, "off": True})
        d = self.get("/api/devices")[1][0]
        self.assertEqual((d["group"], d["off"]), (gid, True))

    def test_activity_is_grouped_by_company(self):
        for name in ("www.bbc.co.uk", "www.bbc.co.uk", "news.bbc.co.uk"):
            self.log(KID, name)
        self.log(KID, "stats.g.doubleclick.net", blocked=1)
        self.log(ADULT, "www.netflix.com")
        _, groups = self.get("/api/activity?ip=%s&hours=24" % KID)
        self.assertEqual([g["base"] for g in groups], ["bbc.co.uk", "doubleclick.net"])      # busiest first
        bbc, ads = groups
        self.assertEqual((bbc["owner"], bbc["n"], bbc["nb"], bbc["v"], bbc["b"]), ("BBC", 3, 0, "ok", False))
        self.assertEqual([(h["d"], h["n"]) for h in bbc["hosts"]], [("www.bbc.co.uk", 2), ("news.bbc.co.uk", 1)])
        self.assertEqual((ads["owner"], ads["v"], ads["b"], ads["why"], ads["nb"]),
                         ("Google adverts", "junk", True, "list", 1))

    def test_activity_shows_why_something_is_blocked_for_this_device(self):
        self.log(KID, "www.youtube.com")
        self.ok("/api/service-block", {"scope": "device:" + KID, "service": "youtube", "on": True})
        g = self.get("/api/activity?ip=%s" % KID)[1][0]
        self.assertEqual((g["b"], g["why"], g["svc"], g["some_blocked"]), (True, "service", "YouTube", True))

    def test_activity_respects_the_time_window(self):
        self.log(KID, "old.example.com", ago=3 * 3600)
        self.log(KID, "new.example.com", ago=60)
        _, groups = self.get("/api/activity?ip=%s&hours=1" % KID)
        self.assertEqual([h["d"] for g in groups for h in g["hosts"]], ["new.example.com"])
        self.assertEqual(self.get("/api/activity?ip=%s&hours=banana" % KID)[0], 200)      # falls back to a day

    def test_clearing_one_devices_history_leaves_the_others(self):
        self.log(KID, "www.bbc.co.uk")
        self.log(ADULT, "www.bbc.co.uk")
        self.ok("/api/clear-history", {"ip": KID})
        server.last_clear.join(5)
        self.assertEqual([d["ip"] for d in self.get("/api/devices")[1]], [ADULT])
        self.ok("/api/clear-history", {})
        self.assertEqual(self.get("/api/devices")[1], [])

    def test_history_questions_are_answered_from_an_index(self):
        # With 30 days of a household's lookups, a question that reads every row makes the dashboard
        # crawl. Ask the database how it would answer each one and check it names an index.
        def plan(statement, args):
            return " | ".join(row[-1] for row in server.sql("EXPLAIN QUERY PLAN " + statement, args))
        today = plan("SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM queries WHERE ts>?", (0,))
        self.assertIn("COVERING INDEX q_ts", today)
        counts = plan("""SELECT client, COUNT(*), COALESCE(SUM(blocked), 0) FROM queries INDEXED BY q_ts
                         WHERE ts>? GROUP BY client""", (0,))
        self.assertIn("COVERING INDEX q_ts", counts)
        last = plan(server.LAST_SEEN_SQL, ())
        self.assertIn("COVERING INDEX q_client_ts", last)
        activity = plan("SELECT domain, COUNT(*), MAX(ts), SUM(blocked) FROM queries WHERE client=? AND ts>? GROUP BY domain",
                        (KID, 0))
        self.assertIn("INDEX q_client_ts (client=? AND ts>?)", activity)

    def test_each_devices_last_lookup_is_found_without_walking_the_whole_history(self):
        # The device list refreshes every 4 seconds; walking a month of history each time is too slow.
        plan = " | ".join(row[-1] for row in server.sql("EXPLAIN QUERY PLAN " + server.LAST_SEEN_SQL))
        self.assertNotIn("SCAN queries", plan)
        self.assertIn("q_client_ts (client=?)", plan)

    def test_a_devices_last_lookup_is_its_newest(self):
        self.log(KID, "a.example.com", ago=500)
        self.log(KID, "b.example.com", ago=5)
        self.log(KID, "c.example.com", ago=50)
        last = self.get("/api/devices")[1][0]["last"]
        self.assertAlmostEqual(last, time.time() - 5, delta=3)

    # ----- the read-only connection for history questions (known issue 82)

    def answered_while_db_lock_is_held(self, ask):
        """Run `ask` in another thread while this thread holds db_lock; True if it finished."""
        done = threading.Event()
        server.db_lock.acquire()
        try:
            t = threading.Thread(target=lambda: (ask(), done.set()), daemon=True)
            t.start()
            finished = done.wait(2)
        finally:
            server.db_lock.release()
        t.join(2)
        return finished

    def test_the_activity_list_does_not_wait_for_the_database_lock(self):
        self.log(KID, "www.bbc.co.uk")
        self.assertTrue(self.answered_while_db_lock_is_held(lambda: server.api_activity(KID, 24)))

    def test_the_status_summary_does_not_wait_for_the_database_lock(self):
        self.log(KID, "www.bbc.co.uk")
        self.assertTrue(self.answered_while_db_lock_is_held(server.api_status))

    def test_the_device_list_history_questions_do_not_wait_for_the_database_lock(self):
        self.log(KID, "www.bbc.co.uk")
        names = server.sql("SELECT ip, name FROM devices")     # the one small question still on the main connection
        with mock.patch.object(server, "sql", lambda *a, **k: names):
            self.assertTrue(self.answered_while_db_lock_is_held(server.api_devices))

    def test_the_read_only_connection_refuses_changes(self):
        with self.assertRaises(server.sqlite3.Error):
            server.read_sql("DELETE FROM queries")

    def test_history_saved_on_the_main_connection_is_seen_by_the_dashboard_at_once(self):
        self.log(KID, "www.bbc.co.uk")
        self.assertEqual(self.get("/api/activity?ip=%s" % KID)[1][0]["base"], "bbc.co.uk")

    def test_clearing_a_busy_devices_history_lets_go_of_the_lock_between_steps(self):
        for i in range(25):
            self.log(KID, "n%d.example.com" % i)
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
        with mock.patch.object(server, "PRUNE_BATCH", 10), \
                mock.patch.object(server.time, "sleep", lock_free_for_another_thread):
            server.clear_history(KID)
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries")[0][0], 0)
        self.assertEqual(free, [True, True])

    def test_clearing_a_devices_history_in_steps_leaves_other_devices_alone(self):
        for i in range(25):
            self.log(KID, "n%d.example.com" % i)
        self.log(ADULT, "www.bbc.co.uk")
        with mock.patch.object(server, "PRUNE_BATCH", 10), mock.patch.object(server.time, "sleep", lambda s: None):
            server.clear_history(KID)
        self.assertEqual(server.sql("SELECT client FROM queries"), [(ADULT,)])

    def test_the_clear_history_request_answers_without_waiting_for_the_steps_to_finish(self):
        self.log(KID, "www.bbc.co.uk")
        may_finish = threading.Event()

        def slow_clear(ip=None):
            """Stands in for a long clear: holds on until the test lets it go."""
            may_finish.wait(5)

        with mock.patch.object(server, "clear_history", slow_clear):
            started = time.monotonic()
            self.ok("/api/clear-history", {"ip": KID})
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(server.last_clear.is_alive())
            may_finish.set()
            server.last_clear.join(5)

    def test_clearing_everyones_history_is_done_before_the_answer(self):
        self.log(KID, "www.bbc.co.uk")
        self.ok("/api/clear-history", {})
        self.assertEqual(server.sql("SELECT COUNT(*) FROM queries")[0][0], 0)

    def test_clearing_a_devices_history_is_answered_from_an_index(self):
        plan = " | ".join(row[-1] for row in server.sql("EXPLAIN QUERY PLAN " + server.CLEAR_DEVICE_SQL, (KID, 0, 1)))
        self.assertIn("q_client_ts (client=?", plan)

    # ----- "unchanged" answers for the activity list (known issue 83)

    def activity(self, since, hours=24):
        """Ask for KID's activity with a marker ('' for the first ask)."""
        status, out = self.get("/api/activity?ip=%s&hours=%s&since=%s" % (KID, hours, since))
        self.assertEqual(status, 200)
        return out

    def test_activity_without_a_marker_is_the_plain_list_as_before(self):
        self.log(KID, "www.bbc.co.uk")
        _, out = self.get("/api/activity?ip=%s" % KID)
        self.assertIsInstance(out, list)

    def test_activity_asked_for_with_an_empty_marker_carries_the_list_and_a_marker(self):
        self.log(KID, "www.bbc.co.uk")
        out = self.activity("")
        self.assertEqual((out["unchanged"], [g["base"] for g in out["groups"]]), (False, ["bbc.co.uk"]))
        self.assertTrue(out["marker"])

    def test_activity_with_the_same_marker_is_answered_unchanged_without_the_list(self):
        self.log(KID, "www.bbc.co.uk")
        marker = self.activity("")["marker"]
        self.assertEqual(self.activity(marker), {"unchanged": True, "marker": marker})

    def test_an_unchanged_activity_answer_does_not_build_the_list(self):
        self.log(KID, "www.bbc.co.uk")
        marker = self.activity("")["marker"]
        with mock.patch.object(server, "activity_groups", side_effect=AssertionError("built the list")):
            self.assertTrue(server.api_activity(KID, 24, marker)["unchanged"])

    def test_a_new_lookup_changes_the_activity_marker(self):
        self.log(KID, "www.bbc.co.uk")
        marker = self.activity("")["marker"]
        self.log(KID, "news.bbc.co.uk", ago=1)
        out = self.activity(marker)
        self.assertEqual((out["unchanged"], out["groups"][0]["n"]), (False, 2))

    def test_another_devices_lookup_does_not_change_the_activity_marker(self):
        self.log(KID, "www.bbc.co.uk")
        marker = self.activity("")["marker"]
        self.log(ADULT, "www.netflix.com", ago=1)
        self.assertTrue(self.activity(marker)["unchanged"])

    def test_a_rule_change_changes_the_activity_marker(self):
        self.log(KID, "www.bbc.co.uk")
        marker = self.activity("")["marker"]
        self.ok("/api/block", {"domain": "bbc.co.uk"})
        out = self.activity(marker)
        self.assertEqual((out["unchanged"], out["groups"][0]["b"]), (False, True))

    def test_pausing_changes_the_activity_marker(self):
        self.log(KID, "stats.g.doubleclick.net", blocked=1)
        marker = self.activity("")["marker"]
        server.S.paused_until = time.time() + 600
        self.assertFalse(self.activity(marker)["unchanged"])

    def test_switching_advert_blocking_changes_the_activity_marker(self):
        self.log(KID, "stats.g.doubleclick.net", blocked=1)
        marker = self.activity("")["marker"]
        self.ok("/api/junk-switch", {"on": False})
        self.assertFalse(self.activity(marker)["unchanged"])

    def test_clearing_a_devices_history_changes_its_activity_marker(self):
        self.log(KID, "www.bbc.co.uk")
        marker = self.activity("")["marker"]
        self.ok("/api/clear-history", {"ip": KID})
        server.last_clear.join(5)
        out = self.activity(marker)
        self.assertEqual((out["unchanged"], out["groups"]), (False, []))

    def test_a_lookup_leaving_the_time_window_changes_the_activity_marker(self):
        self.log(KID, "old.example.com", ago=3000)
        self.log(KID, "new.example.com", ago=60)
        marker = self.activity("", hours=1)["marker"]
        server.sql("UPDATE queries SET ts=ts-1000 WHERE domain='old.example.com'", commit=True)  # as if time passed
        out = self.activity(marker, hours=1)
        self.assertEqual([h["d"] for g in out["groups"] for h in g["hosts"]], ["new.example.com"])

    def test_a_different_time_window_has_a_different_activity_marker(self):
        self.log(KID, "www.bbc.co.uk")
        self.assertNotEqual(self.activity("", hours=24)["marker"], self.activity("", hours=48)["marker"])

    def test_an_out_of_date_marker_gets_the_full_list(self):
        self.log(KID, "www.bbc.co.uk")
        out = self.activity("not-a-real-marker")
        self.assertEqual((out["unchanged"], len(out["groups"])), (False, 1))

    def test_the_activity_markers_questions_are_answered_from_an_index(self):
        def plan(statement, args):
            return " | ".join(row[-1] for row in server.sql("EXPLAIN QUERY PLAN " + statement, args))
        self.assertIn("q_client_ts (client=?)", plan(server.NEWEST_FOR_DEVICE_SQL, (KID,)))
        self.assertIn("q_client_ts (client=? AND ts>?)", plan(server.OLDEST_IN_WINDOW_SQL, (KID, 0)))

    def test_the_status_summary_counts_today(self):
        self.log(KID, "www.bbc.co.uk")
        self.log(KID, "ads.doubleclick.net", blocked=1)
        self.log(KID, "old.example.com", blocked=1, ago=2 * 86400)
        _, st = self.get("/api/status")
        self.assertEqual(st["today"], {"total": 2, "blocked": 1})
        self.assertGreater(st["junk_count"], 100)
        self.assertRegex(st["clock"], r"^\d\d:\d\d$")
        self.assertEqual(st["enforcer"]["active"], False)


class Scanning(Api):
    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        self.addCleanup(setattr, server.S, "scan_info", server.S.scan_info)
        server.S.local_ip = "192.168.4.20"
        # A stand-in for the home network's size, and for the names devices report.
        self.subnet = server.ipaddress.IPv4Network("192.168.4.0/22")
        for name, stand_in in (("home_subnet", lambda ip: self.subnet), ("reverse_name", lambda ip: "")):
            p = mock.patch.object(server, name, stand_in)
            p.start()
            self.addCleanup(p.stop)

    def scan(self):
        """Run a scan with a socket that sends nothing and no pauses. The socket is replaced only
        for the scan itself: the tests' own web requests need the real one."""
        with mock.patch.object(server.socket, "socket", mock.MagicMock()), \
                mock.patch.object(server.time, "sleep", lambda s: None):
            server.scan_network()

    def test_a_scan_lists_devices_anywhere_on_the_home_network(self):
        self.neighbours_now = {"192.168.5.37": "aa:aa:aa:aa:aa:01", "192.168.5.255": "aa:aa:aa:aa:aa:02",
                               "10.0.0.5": "aa:aa:aa:aa:aa:03", "192.168.7.255": "ff:ff:ff:ff:ff:fe"}
        self.scan()
        seen = {r[0] for r in server.sql("SELECT ip FROM seen")}
        self.assertEqual(seen, {"192.168.4.20", "192.168.5.37", "192.168.5.255"})

    def test_a_scan_waits_for_device_names_without_holding_the_database_lock(self):
        # Name lookups can take seconds; the dashboard and history writer must not wait behind them.
        self.neighbours_now = {"192.168.5.37": "aa:aa:aa:aa:aa:01"}
        free = []

        def lock_is_free():
            ok = server.db_lock.acquire(blocking=False)     # released by the thread that took it
            if ok:
                server.db_lock.release()
            free.append(ok)

        def name_of(ip):
            t = threading.Thread(target=lock_is_free)
            t.start()
            t.join()
            return "tv"
        server.reverse_name = name_of
        self.scan()
        self.assertTrue(free and all(free))

    def test_a_finished_scan_asks_for_device_names_straight_away(self):
        self.neighbours_now = {"192.168.5.37": "aa:aa:aa:aa:aa:01"}
        server.NAMES_WANTED.clear()
        self.addCleanup(server.NAMES_WANTED.clear)
        self.scan()
        self.assertTrue(server.NAMES_WANTED.is_set())

    def test_the_scan_answer_says_when_the_network_was_too_big_to_scan_in_full(self):
        self.subnet = server.ipaddress.IPv4Network("192.168.0.0/16")
        with mock.patch.object(server, "scan_network", lambda: None):
            out = self.ok("/api/scan")
        server.S.scan_state = "idle"
        self.assertEqual((out["capped"], out["network"]), (True, "192.168.0.0/16"))
        self.assertLessEqual(out["addresses"], server.MAX_SCAN)

    def test_the_status_summary_says_what_the_last_scan_covered(self):
        with mock.patch.object(server, "scan_network", lambda: None):
            self.ok("/api/scan")
        server.S.scan_state = "idle"
        scan = self.get("/api/status")[1]["scan"]
        self.assertEqual((scan["network"], scan["addresses"], scan["capped"]), ("192.168.4.0/22", 1022, False))


class EnforceAndCloud(Api):
    def test_cut_live_connections_is_remembered_per_device(self):
        self.ok("/api/enforce", {"ip": KID, "on": True})
        kid = self.device(KID)
        self.assertEqual(server.S.enforced, {kid})
        server.S.enforced = set()
        server.init_db()
        self.assertEqual(server.S.enforced, {kid})                      # survives a restart
        self.ok("/api/enforce", {"ip": KID, "on": False})
        self.assertEqual(server.S.enforced, set())

    def test_cut_live_connections_can_be_switched_by_the_devices_number(self):
        kid = self.device(KID)
        self.ok("/api/enforce", {"device": kid, "on": True})
        self.assertEqual(server.S.enforced, {kid})
        self.ok("/api/enforce", {"device": kid, "on": False})
        self.assertEqual(server.S.enforced, set())

    def test_switching_cut_live_connections_off_for_an_address_nothing_is_known_at_makes_no_device(self):
        self.ok("/api/enforce", {"ip": KID, "on": False})
        self.assertEqual((server.S.enforced, server.S.addr_only), (set(), {}))

    def test_only_a_plain_ipv4_address_can_be_enforced(self):
        # This value ends up inside a firewall rule, so nothing else may get through.
        for ip in ("", "not-an-ip", "192.168.1", "192.168.1.23/24", "192.168.1.23 drop", "fe80::1",
                   "192.168.1.23\n192.168.1.24", None, "999.999.999.999", "192.168.1.256", 3232235799, ["192.168.1.23"]):
            self.assertEqual(self.post("/api/enforce", {"ip": ip, "on": True})[0], 400, ip)
        self.assertEqual(server.S.enforced, set())

    def test_this_computer_cannot_be_enforced(self):
        self.addCleanup(setattr, server.S, "local_ip", server.S.local_ip)
        server.S.local_ip = "192.168.1.60"
        status, out = self.post("/api/enforce", {"ip": "192.168.1.60", "on": True})
        self.assertEqual(status, 400)
        self.assertIn("router or itself", out["error"])

    def test_the_router_and_other_networks_are_refused_when_the_enforcer_knows_the_network(self):
        real = server.ENF
        server.ENF = mock.Mock(available=lambda: True, can_target=lambda ip: "QuietNet can't steer the router or itself.")
        try:
            status, out = self.post("/api/enforce", {"ip": "192.168.1.254", "on": True})
        finally:
            server.ENF = real
        self.assertEqual((status, out["error"]), (400, "QuietNet can't steer the router or itself."))
        self.assertEqual(server.S.enforced, set())

    def test_enforcing_remembers_which_device_it_is_from_the_live_table_first(self):
        server.sql("INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?)", (KID, "a4:aa:aa:aa:aa:01", "", 0), commit=True)
        self.neighbours_now = {KID: "b8:27:eb:00:00:02"}                 # the old scan is out of date
        self.ok("/api/enforce", {"ip": KID, "on": True})
        there_now = server.S.hw_device["b8:27:eb:00:00:02"]
        self.assertEqual(server.S.enforced, {there_now})                 # the device there now, not the scan's
        self.assertNotIn("a4:aa:aa:aa:aa:01", server.S.hw_device)
        server.init_db()
        self.assertEqual(server.S.enforced, {there_now})                 # kept across a restart
        self.assertEqual(self.device(KID), there_now)                    # and its card is that device's

    def test_an_unknown_hardware_address_is_filled_in_when_first_seen(self):
        self.ok("/api/enforce", {"ip": KID, "on": True})
        kid = self.device(KID)
        self.assertEqual(server.S.enforced_mac[kid], "")
        extender = "cc:cc:cc:cc:cc:02"                                   # a range extender answers at that number
        with mock.patch.object(server.S, "shared_macs", {extender}):
            server.note_ipv4_addresses({KID: (extender, "fresh")})
            with server.db_lock:
                self.assertEqual(server.live_cut_devices({KID: (extender, "fresh")}), {KID: (extender, kid)})
                # A different hardware address there later is not steered, and only the first is kept.
                self.assertEqual(server.live_cut_devices({KID: ("dd:dd:dd:dd:dd:04", "fresh")}), {})
        server.init_db()
        self.assertEqual(server.S.enforced_mac[kid], extender)

    def test_remote_access_reports_off_when_the_link_is_not_running(self):
        real = server.CA
        server.CA = None
        try:
            self.assertEqual(self.get("/api/cloud")[1], {"configured": False, "paired": False, "state": "off"})
            status, out = self.post("/api/cloud", {"relay": "x", "code": "y"})
            self.assertEqual((status, out), (400, {"error": "Remote access isn't available."}))
        finally:
            server.CA = real

    def test_pairing_and_forgetting_go_through_to_the_cloud_link(self):
        class Link:
            asked, forgotten = [], 0

            def pair(self, relay, code):
                self.asked.append((relay, code))
                return None if code == "GOOD" else "That pairing code is wrong or already used."

            def forget(self):
                Link.forgotten += 1

            def status(self):
                return {"configured": True, "paired": True, "state": "online"}

        real = server.CA
        server.CA = Link()
        try:
            self.ok("/api/cloud", {"relay": "relay.example", "code": "GOOD"})
            status, out = self.post("/api/cloud", {"relay": "relay.example", "code": "BAD"})
            self.assertEqual((status, out["error"]), (400, "That pairing code is wrong or already used."))
            self.ok("/api/cloud", {"action": "forget"})
            self.assertEqual(self.get("/api/cloud")[1]["state"], "online")
            self.assertEqual((Link.asked, Link.forgotten), ([("relay.example", "GOOD"), ("relay.example", "BAD")], 1))
        finally:
            server.CA = real

    def test_the_enforcer_reports_unavailable_when_it_was_never_started(self):
        real = server.ENF
        server.ENF = None
        try:
            self.assertEqual(self.get("/api/enforcer")[1], {"available": False, "reason": "not started", "active": False, "shared": {}})
        finally:
            server.ENF = real


if __name__ == "__main__":
    unittest.main()
