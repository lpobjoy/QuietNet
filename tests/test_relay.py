"""Checks for the relay (cloud/relay.py): accounts, sessions, pairing, and the
bridge that carries a browser's request down to a Pi and the answer back up.

Run with:  python3 -m unittest discover tests

Standard library only. The relay is started on a spare port on this computer with
a throwaway data folder, and a pretend Pi answers its calls. Nothing leaves this machine.
"""
import http.client
import json
import socket
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

os.environ["QUIETNET_RELAY_DATA"] = tempfile.mkdtemp(prefix="quietnet-relay-test-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "cloud"))
import relay  # noqa: E402

PASSWORD = "correct horse battery"


class Browser:
    """A very small web browser: remembers its cookie, never follows redirects."""

    def __init__(self, port):
        self.port, self.cookie = port, ""

    def request(self, method, path, form=None, data=None, headers=None):
        headers = dict(headers or {})
        body = None
        if form is not None:
            body = urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if data is not None:
            body = json.dumps(data)
            headers["Content-Type"] = "application/json"
        if self.cookie:
            headers["Cookie"] = self.cookie
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            text = r.read().decode("utf-8", "replace")
        finally:
            conn.close()
        cookie = r.getheader("Set-Cookie")
        if cookie:
            self.cookie = cookie.split(";")[0]
            self.cookie_flags = cookie
        return r.status, text, r

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


class RelayCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if relay.db is None:
            relay.init_db()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), relay.Relay)
        cls.httpd.daemon_threads = True
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        relay.sql("DELETE FROM users", commit=True)
        relay.sql("DELETE FROM pis", commit=True)
        with relay.bridge.lock:
            relay.bridge.queues.clear()
            relay.bridge.waiting.clear()
        relay.throttle.failures.clear()

    def limit(self, name, value):
        """Change one of the relay's limits for the length of a test."""
        self.addCleanup(setattr, relay, name, getattr(relay, name))
        setattr(relay, name, value)

    def signed_in(self, email="lewis@example.com"):
        b = Browser(self.port)
        status, _, r = b.post("/signup", form={"email": email, "password": PASSWORD})
        self.assertEqual(status, 303)
        self.assertEqual(r.getheader("Location"), "/")
        return b

    def paired_pi(self, browser, name="Home Pi"):
        """Create a Pi on the website and pair it, the way the real Pi does. Returns (id, token)."""
        browser.post("/pis/new", form={"name": name})
        pid, code = relay.sql("SELECT id, code FROM pis WHERE name=?", (name,), one=True)
        status, text, _ = Browser(self.port).post("/agent/pair", data={"code": code})
        self.assertEqual(status, 200)
        return pid, json.loads(text)["token"]

    def pretend_pi(self, token, status=200, body='{"ok": true}'):
        """Answer exactly one relayed call, as the Pi's agent would. Returns the thread and what it saw."""
        seen = {}

        def work():
            pi = Browser(self.port)
            _, text, _ = pi.get("/agent/poll", headers={"X-QuietNet-Token": token})
            seen.update(json.loads(text))
            pi.post("/agent/respond", data={"id": seen.get("id"), "status": status, "body": body},
                    headers={"X-QuietNet-Token": token, "X-QuietNet-Call": str(seen.get("id"))})

        t = threading.Thread(target=work, daemon=True)
        t.start()
        return t, seen


# ------------------------------------------------------------------ passwords and sessions

class Passwords(unittest.TestCase):
    def test_right_password_passes_wrong_one_fails(self):
        stored = relay.hash_pw(PASSWORD, rounds=1000)
        self.assertTrue(relay.check_pw(PASSWORD, stored))
        self.assertFalse(relay.check_pw(PASSWORD + "x", stored))

    def test_the_password_itself_is_never_stored(self):
        stored = relay.hash_pw(PASSWORD, rounds=1000)
        self.assertNotIn(PASSWORD, stored)
        self.assertTrue(stored.startswith("pbkdf2$1000$"))

    def test_same_password_twice_gives_different_records(self):
        self.assertNotEqual(relay.hash_pw(PASSWORD, rounds=1000), relay.hash_pw(PASSWORD, rounds=1000))

    def test_a_damaged_record_never_matches(self):
        for stored in ("", "nonsense", "pbkdf2$abc$salt$key", "pbkdf2$1000$!!!$key"):
            self.assertFalse(relay.check_pw(PASSWORD, stored), stored)

    def test_default_strength(self):
        self.assertGreaterEqual(relay.PBKDF2_ROUNDS, 200000)


class Sessions(RelayCase):
    def test_a_fresh_session_names_its_user(self):
        self.assertEqual(relay.read_session(relay.make_session(7)), 7)

    def test_changing_the_user_number_breaks_the_signature(self):
        uid, exp, sig = relay.make_session(7).split(".")
        self.assertIsNone(relay.read_session("8.%s.%s" % (exp, sig)))

    def test_extending_the_expiry_breaks_the_signature(self):
        uid, exp, sig = relay.make_session(7).split(".")
        self.assertIsNone(relay.read_session("%s.%d.%s" % (uid, int(exp) + 999999, sig)))

    def test_an_expired_session_is_refused(self):
        real = relay.SESSION_HOURS
        relay.SESSION_HOURS = -1
        try:
            old = relay.make_session(7)
        finally:
            relay.SESSION_HOURS = real
        self.assertIsNone(relay.read_session(old))

    def test_rubbish_cookies_are_refused(self):
        for cookie in ("", "7", "7.9999999999", "a.b.c", "7.9999999999.deadbeef", "....", None):
            self.assertIsNone(relay.read_session(cookie), cookie)


# ------------------------------------------------------------------ the bridge

class BridgeLogic(unittest.TestCase):
    def setUp(self):
        self.bridge = relay.Bridge()

    def test_a_call_reaches_the_pi_and_the_answer_comes_back(self):
        got = {}

        def pi():
            call = self.bridge.poll("pi-1")
            got.update(call)
            self.bridge.respond("pi-1", call["id"], {"status": 200, "body": "hello"})

        t = threading.Thread(target=pi, daemon=True)
        t.start()
        resp = self.bridge.call("pi-1", {"method": "GET", "path": "/api/status"})
        t.join(5)
        self.assertEqual(resp, {"status": 200, "body": "hello"})
        self.assertEqual((got["method"], got["path"]), ("GET", "/api/status"))

    def test_calls_are_handed_out_in_the_order_they_arrived(self):
        with self.bridge.lock:
            self.bridge.queues["pi-1"] = [{"id": "a"}, {"id": "b"}]
        self.assertEqual(self.bridge.poll("pi-1")["id"], "a")
        self.assertEqual(self.bridge.poll("pi-1")["id"], "b")

    def test_one_pi_never_receives_another_pis_call(self):
        with self.bridge.lock:
            self.bridge.queues["pi-1"] = [{"id": "a"}]
        real = relay.POLL_TIMEOUT
        relay.POLL_TIMEOUT = 0.1
        try:
            self.assertIsNone(self.bridge.poll("pi-2"))
        finally:
            relay.POLL_TIMEOUT = real
        self.assertEqual(self.bridge.poll("pi-1")["id"], "a")

    def test_an_idle_poll_gives_up_empty_handed(self):
        real = relay.POLL_TIMEOUT
        relay.POLL_TIMEOUT = 0.1
        try:
            started = time.time()
            self.assertIsNone(self.bridge.poll("pi-1"))
            self.assertLess(time.time() - started, 3)
        finally:
            relay.POLL_TIMEOUT = real

    def test_an_unanswered_call_times_out_and_is_cleared_away(self):
        real = relay.CALL_TIMEOUT
        relay.CALL_TIMEOUT = 0.1
        try:
            self.assertIsNone(self.bridge.call("pi-1", {"method": "GET", "path": "/"}))
        finally:
            relay.CALL_TIMEOUT = real
        self.assertEqual(self.bridge.queues["pi-1"], [])       # a late Pi must not pick up a dead call
        self.assertEqual(self.bridge.waiting, {})

    def test_an_answer_to_an_unknown_call_is_ignored(self):
        self.bridge.respond("pi-1", "no-such-call", {"status": 200, "body": ""})   # must not raise
        self.assertEqual(self.bridge.waiting, {})

    def test_a_pi_cannot_answer_a_call_sent_to_another_pi(self):
        got = {}

        def pis():
            call = self.bridge.poll("pi-1")
            self.bridge.respond("pi-2", call["id"], {"status": 200, "body": "forged"})   # the wrong Pi
            self.bridge.respond("pi-1", call["id"], {"status": 200, "body": "real"})
            got["done"] = True

        t = threading.Thread(target=pis, daemon=True)
        t.start()
        resp = self.bridge.call("pi-1", {"method": "GET", "path": "/api/status"})
        t.join(5)
        self.assertEqual(resp, {"status": 200, "body": "real"})


# ------------------------------------------------------------------ accounts

class Accounts(RelayCase):
    def test_health_check(self):
        status, text, _ = Browser(self.port).get("/healthz")
        self.assertEqual((status, json.loads(text)), (200, {"ok": True}))

    def test_signed_out_visitors_are_sent_to_the_login_page(self):
        status, _, r = Browser(self.port).get("/")
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_signing_up_signs_you_in(self):
        b = self.signed_in()
        status, text, _ = b.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Your QuietNets", text)

    def test_the_session_cookie_is_hidden_from_page_scripts(self):
        b = self.signed_in()
        self.assertIn("HttpOnly", b.cookie_flags)
        self.assertIn("SameSite=Lax", b.cookie_flags)

    def test_the_cookie_is_marked_secure_behind_https(self):
        b = Browser(self.port)
        b.post("/signup", form={"email": "a@example.com", "password": PASSWORD},
               headers={"X-Forwarded-Proto": "https"})
        self.assertIn("Secure", b.cookie_flags)

    def test_the_same_email_cannot_sign_up_twice(self):
        self.signed_in()
        status, text, _ = Browser(self.port).post("/signup", form={"email": "LEWIS@example.com", "password": PASSWORD})
        self.assertEqual(status, 200)
        self.assertIn("already has an account", text)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM users", one=True)[0], 1)

    def test_weak_or_malformed_sign_ups_are_refused(self):
        for form in ({"email": "a@example.com", "password": "short"},
                     {"email": "not-an-email", "password": PASSWORD},
                     {"email": "", "password": PASSWORD}, {}):
            status, text, _ = Browser(self.port).post("/signup", form=form)
            self.assertIn("Enter a valid email", text, form)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM users", one=True)[0], 0)

    def test_login_needs_the_right_password(self):
        self.signed_in()
        b = Browser(self.port)
        status, text, _ = b.post("/login", form={"email": "lewis@example.com", "password": "wrong password"})
        self.assertIn("Wrong email or password", text)
        self.assertEqual(b.cookie, "")
        status, _, r = b.post("/login", form={"email": "lewis@example.com", "password": PASSWORD})
        self.assertEqual((status, r.getheader("Location")), (303, "/"))
        self.assertEqual(b.get("/")[0], 200)

    def test_unknown_email_gets_the_same_message_as_a_wrong_password(self):
        status, text, _ = Browser(self.port).post("/login", form={"email": "nobody@example.com", "password": PASSWORD})
        self.assertIn("Wrong email or password", text)

    def test_signing_out_ends_the_session(self):
        b = self.signed_in()
        b.get("/logout")
        status, _, r = b.get("/")
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_a_forged_cookie_does_not_sign_you_in(self):
        self.signed_in()
        b = Browser(self.port)
        b.cookie = "qn_session=1.9999999999.%s" % ("0" * 32)
        self.assertEqual(b.get("/")[0], 303)

    def test_unknown_pages_are_not_found(self):
        self.assertEqual(Browser(self.port).get("/nope")[0], 404)
        self.assertEqual(Browser(self.port).post("/nope")[0], 404)


# ------------------------------------------------------------------ pairing

class Pairing(RelayCase):
    def test_adding_a_quietnet_shows_a_pairing_code(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        self.assertRegex(code, r"^[0-9A-F]{4}-[0-9A-F]{4}$")
        text = b.get("/")[1]
        self.assertIn(code, text)
        self.assertIn("Waiting to be paired", text)

    def test_you_must_be_signed_in_to_add_one(self):
        status, _, r = Browser(self.port).post("/pis/new", form={"name": "Sneaky"})
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis", one=True)[0], 0)

    def test_pairing_hands_the_pi_a_secret_token(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        self.assertEqual(len(token), 48)
        paired, code = relay.sql("SELECT paired, code FROM pis WHERE id=?", (pid,), one=True)
        self.assertEqual((paired, code), (1, ""))
        self.assertIn('href="/pi/%s/"' % pid, b.get("/")[1])

    def test_a_code_is_matched_whatever_its_letter_case(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        status, _, _ = Browser(self.port).post("/agent/pair", data={"code": "  " + code.lower() + " "})
        self.assertEqual(status, 200)

    def test_a_code_works_only_once(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        self.assertEqual(Browser(self.port).post("/agent/pair", data={"code": code})[0], 200)
        status, text, _ = Browser(self.port).post("/agent/pair", data={"code": code})
        self.assertEqual(status, 400)
        self.assertIn("already used", json.loads(text)["error"])

    def test_wrong_and_empty_codes_are_refused(self):
        b = self.signed_in()
        self.paired_pi(b)                      # a paired Pi has an empty code: "" must not match it
        for code in ("0000-0000", "", None, 5):
            self.assertEqual(Browser(self.port).post("/agent/pair", data={"code": code})[0], 400, code)

    def test_the_pi_name_cannot_carry_html_onto_the_page(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "<script>alert(1)</script>"})
        text = b.get("/")[1]
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertIn("&lt;script&gt;", text)

    def test_only_the_owner_can_remove_a_pi(self):
        owner, other = self.signed_in(), self.signed_in("mallory@example.com")
        pid, token = self.paired_pi(owner)
        other.post("/pis/%s/delete" % pid)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis", one=True)[0], 1)
        owner.post("/pis/%s/delete" % pid)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis", one=True)[0], 0)

    def test_a_removed_pi_is_locked_out(self):
        owner = self.signed_in()
        pid, token = self.paired_pi(owner)
        owner.post("/pis/%s/delete" % pid)
        self.assertEqual(Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": token})[0], 401)


# ------------------------------------------------------------------ the Pi's side

class AgentSide(RelayCase):
    def test_polling_needs_a_valid_token(self):
        self.assertEqual(Browser(self.port).get("/agent/poll")[0], 401)
        self.assertEqual(Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": "guess"})[0], 401)

    def test_responding_needs_a_valid_token(self):
        status, _, _ = Browser(self.port).post("/agent/respond", data={"id": "x", "status": 200, "body": ""})
        self.assertEqual(status, 401)

    def test_an_idle_poll_returns_an_empty_answer_and_marks_the_pi_as_seen(self):
        pid, token = self.paired_pi(self.signed_in())
        relay.sql("UPDATE pis SET last_seen=0 WHERE id=?", (pid,), commit=True)
        real = relay.POLL_TIMEOUT
        relay.POLL_TIMEOUT = 0.1
        try:
            status, text, _ = Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": token})
        finally:
            relay.POLL_TIMEOUT = real
        self.assertEqual((status, json.loads(text)), (200, {}))
        self.assertGreater(relay.sql("SELECT last_seen FROM pis WHERE id=?", (pid,), one=True)[0], time.time() - 60)


# ------------------------------------------------------------------ browser -> Pi

class Relaying(RelayCase):
    API = {"X-QuietNet": "1"}

    def test_a_request_travels_to_the_pi_and_its_answer_comes_back(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        t, seen = self.pretend_pi(token, body='{"ip": "192.168.1.60"}')
        status, text, r = b.get("/pi/%s/api/status" % pid, headers=self.API)
        t.join(5)
        self.assertEqual((status, json.loads(text)), (200, {"ip": "192.168.1.60"}))
        self.assertEqual(r.getheader("Content-Type"), "application/json")
        self.assertEqual((seen["method"], seen["path"]), ("GET", "/api/status"))

    def test_the_query_string_is_passed_on(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        t, seen = self.pretend_pi(token)
        b.get("/pi/%s/api/activity?ip=192.168.1.23&hours=24" % pid, headers=self.API)
        t.join(5)
        self.assertEqual(seen["path"], "/api/activity?ip=192.168.1.23&hours=24")

    def test_a_posted_body_is_passed_on_unchanged(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        t, seen = self.pretend_pi(token)
        b.post("/pi/%s/api/block" % pid, data={"domain": "example.com"}, headers=self.API)
        t.join(5)
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(json.loads(seen["body"]), {"domain": "example.com"})

    def test_the_pis_error_status_is_passed_back(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        t, _ = self.pretend_pi(token, status=400, body='{"error": "That doesn\'t look like a web address."}')
        status, text, _ = b.post("/pi/%s/api/block" % pid, data={"domain": "??"}, headers=self.API)
        t.join(5)
        self.assertEqual(status, 400)
        self.assertIn("web address", json.loads(text)["error"])

    def test_calls_without_the_dashboard_header_are_refused(self):
        # A hostile website can make your browser send a request with your cookie, but it
        # cannot add this header. Refusing without it stops such forged requests.
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        self.assertEqual(b.get("/pi/%s/api/status" % pid)[0], 403)
        self.assertEqual(b.post("/pi/%s/api/kill" % pid, data={"on": True})[0], 403)
        self.assertEqual(relay.bridge.queues.get(pid, []), [])       # nothing was queued for the Pi

    def test_another_account_cannot_reach_your_pi(self):
        owner, other = self.signed_in(), self.signed_in("mallory@example.com")
        pid, token = self.paired_pi(owner)
        self.assertEqual(other.get("/pi/%s/api/status" % pid, headers=self.API)[0], 404)
        self.assertEqual(other.post("/pi/%s/api/kill" % pid, data={"on": True}, headers=self.API)[0], 404)
        status, _, r = other.get("/pi/%s/" % pid)
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))
        self.assertEqual(relay.bridge.queues.get(pid, []), [])

    def test_signed_out_visitors_cannot_reach_any_pi(self):
        pid, token = self.paired_pi(self.signed_in())
        self.assertEqual(Browser(self.port).get("/pi/%s/api/status" % pid, headers=self.API)[0], 404)

    def test_only_api_paths_are_relayed(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        self.assertEqual(b.get("/pi/%s/secret-file" % pid, headers=self.API)[0], 404)

    def test_an_unpaired_pi_reports_offline(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        pid = relay.sql("SELECT id FROM pis", one=True)[0]
        status, text, _ = b.get("/pi/%s/api/status" % pid, headers=self.API)
        self.assertEqual(status, 503)
        self.assertIn("offline", json.loads(text)["error"])

    def test_a_pi_not_heard_from_recently_reports_offline(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        relay.sql("UPDATE pis SET last_seen=? WHERE id=?", (time.time() - relay.OFFLINE_AFTER - 5, pid), commit=True)
        self.assertEqual(b.get("/pi/%s/api/status" % pid, headers=self.API)[0], 503)

    def test_a_pi_that_never_answers_gives_a_timeout(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        real = relay.CALL_TIMEOUT
        relay.CALL_TIMEOUT = 0.2
        try:
            status, text, _ = b.get("/pi/%s/api/status" % pid, headers=self.API)
        finally:
            relay.CALL_TIMEOUT = real
        self.assertEqual(status, 504)
        self.assertIn("didn't answer", json.loads(text)["error"])

    def test_the_remote_dashboard_is_pointed_at_this_pi(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b, name="Home <Pi>")
        status, text, _ = b.get("/pi/%s/" % pid)
        self.assertEqual(status, 200)
        self.assertIn('window.QN_API_BASE="/pi/%s";' % pid, text)
        self.assertIn("Home &lt;Pi&gt; &mdash; remote", text)
        self.assertNotIn("Home <Pi>", text)


# ------------------------------------------------------------------ hardening

class Headers(RelayCase):
    WANTED = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
              "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}

    def check(self, r, where):
        for name, value in self.WANTED.items():
            self.assertEqual(r.getheader(name), value, "%s on %s" % (name, where))

    def test_every_kind_of_answer_carries_the_protective_headers(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        self.check(Browser(self.port).get("/login")[2], "a page")
        self.check(Browser(self.port).get("/healthz")[2], "json")
        self.check(Browser(self.port).get("/")[2], "a redirect")
        self.check(Browser(self.port).get("/nope")[2], "an error")
        self.check(b.get("/pi/%s/" % pid)[2], "the remote dashboard")
        t, _ = self.pretend_pi(token)
        self.check(b.get("/pi/%s/api/status" % pid, headers={"X-QuietNet": "1"})[2], "a relayed answer")
        t.join(5)


class Storage(RelayCase):
    @unittest.skipIf(os.name == "nt", "file permissions work differently on Windows")
    def test_the_data_folder_is_private_to_its_owner(self):
        # It holds the accounts, every Pi's token and the secret that signs sessions.
        self.assertEqual(os.stat(relay.DATA).st_mode & 0o777, 0o700)


class ThrottleLogic(unittest.TestCase):
    def test_blocks_only_after_the_limit_is_reached(self):
        t = relay.Throttle()
        for _ in range(3):
            self.assertFalse(t.blocked("x", (3, 60)))
            t.fail("x")
        self.assertTrue(t.blocked("x", (3, 60)))
        self.assertFalse(t.blocked("y", (3, 60)))             # other names are unaffected

    def test_old_failures_stop_counting(self):
        t = relay.Throttle()
        t.failures["x"] = [time.time() - 120] * 5
        self.assertFalse(t.blocked("x", (3, 60)))
        self.assertEqual(t.failures, {})                      # and are tidied away

    def test_clear_forgets_a_name(self):
        t = relay.Throttle()
        t.fail("x")
        t.clear("x")
        self.assertFalse(t.blocked("x", (1, 60)))

    def test_memory_stays_bounded_under_a_flood_of_names(self):
        t = relay.Throttle()
        for i in range(10050):
            t.fail("login:made-up-%d@example.com" % i)
        self.assertLessEqual(len(t.failures), 10001)


class GuessLimits(RelayCase):
    def login(self, email="lewis@example.com", password="wrong password"):
        return Browser(self.port).post("/login", form={"email": email, "password": password})

    def test_repeated_wrong_passwords_lock_that_account_for_a_while(self):
        self.signed_in()
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0]):
            self.assertEqual(self.login()[0], 200)
        status, text, _ = self.login(password=PASSWORD)       # even the right password must now wait
        self.assertEqual(status, 429)
        self.assertIn("Too many attempts", text)

    def known_marker(self, email="lewis@example.com"):
        """Sign in properly once and return the 'signed in here before' cookie it set."""
        _, _, r = Browser(self.port).post("/login", form={"email": email, "password": PASSWORD})
        for name, value in r.getheaders():
            if name.lower() == "set-cookie" and value.startswith("qn_known="):
                return value.split(";")[0]
        self.fail("no qn_known cookie was set")

    def test_a_browser_that_signed_in_before_is_not_locked_out_by_strangers(self):
        self.signed_in()
        marker = self.known_marker()
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0]):
            self.login()                                         # a stranger, guessing on purpose
        self.assertEqual(self.login(password=PASSWORD)[0], 429)  # an unknown browser still has to wait...
        status, _, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": PASSWORD},
                                               headers={"Cookie": marker})
        self.assertEqual(status, 303)                            # ...but the owner's own browser gets in

    def test_the_known_browser_marker_still_needs_the_right_password(self):
        self.signed_in()
        marker = self.known_marker()
        status, text, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": "wrong"},
                                                  headers={"Cookie": marker})
        self.assertEqual(status, 200)
        self.assertIn("Wrong email or password", text)

    def test_one_accounts_marker_does_not_help_with_another_account(self):
        self.signed_in()
        self.signed_in("hannah@example.com")
        marker = self.known_marker()                             # lewis's
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0]):
            self.login("hannah@example.com")
        status, _, _ = Browser(self.port).post("/login", form={"email": "hannah@example.com", "password": PASSWORD},
                                               headers={"Cookie": marker})
        self.assertEqual(status, 429)

    def test_a_known_browser_has_its_own_cap_on_wrong_guesses(self):
        self.signed_in()
        marker = self.known_marker()
        self.limit("LOGIN_LIMIT_KNOWN_BROWSER", (3, 600))
        for _ in range(3):
            Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": "wrong"},
                                    headers={"Cookie": marker})
        status, _, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": PASSWORD},
                                               headers={"Cookie": marker})
        self.assertEqual(status, 429)

    def test_changing_the_password_makes_old_markers_useless(self):
        self.signed_in()
        marker = self.known_marker()
        relay.sql("UPDATE users SET pw=? WHERE email=?", (relay.hash_pw("a new password", rounds=1000),
                                                          "lewis@example.com"), commit=True)
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0]):
            self.login()
        status, _, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": "a new password"},
                                               headers={"Cookie": marker})
        self.assertEqual(status, 429)            # the old marker no longer lets it past the limit

    def test_signing_out_forgets_the_browser(self):
        b = self.signed_in()
        _, _, r = b.get("/logout")
        cleared = [v for k, v in r.getheaders() if k.lower() == "set-cookie" and v.startswith("qn_known=;")]
        self.assertTrue(cleared)
        self.assertIn("Max-Age=0", cleared[0])

    def test_one_accounts_lock_does_not_affect_another(self):
        self.signed_in()
        self.signed_in("hannah@example.com")
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0]):
            self.login()
        self.assertEqual(self.login("hannah@example.com", PASSWORD)[0], 303)

    def test_a_successful_login_wipes_the_slate(self):
        self.signed_in()
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0] - 1):
            self.login()
        self.assertEqual(self.login(password=PASSWORD)[0], 303)
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0] - 1):
            self.assertEqual(self.login()[0], 200)
        self.assertEqual(self.login(password=PASSWORD)[0], 303)

    def test_guessing_across_many_emails_is_capped_too(self):
        self.signed_in()
        self.limit("LOGIN_LIMIT_OVERALL", (4, 600))
        for i in range(4):
            self.login("nobody%d@example.com" % i)
        self.assertEqual(self.login("someone-new@example.com")[0], 429)

    def test_an_unknown_email_costs_the_same_work_as_a_wrong_password(self):
        # If unknown emails were answered instantly, timing would reveal which emails have accounts.
        self.signed_in()
        real, calls = relay.check_pw, []
        self.addCleanup(setattr, relay, "check_pw", real)
        relay.check_pw = lambda password, stored: calls.append(1) or real(password, stored)
        self.login("nobody@example.com")
        self.assertEqual(len(calls), 1)

    def test_wrong_pairing_codes_are_capped(self):
        self.limit("PAIR_LIMIT_OVERALL", (3, 600))
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        for i in range(3):
            self.assertEqual(Browser(self.port).post("/agent/pair", data={"code": "0000-000%d" % i})[0], 400)
        status, text, _ = Browser(self.port).post("/agent/pair", data={"code": code})
        self.assertEqual(status, 429)
        self.assertIn("Too many attempts", json.loads(text)["error"])
        self.assertEqual(relay.sql("SELECT paired FROM pis", one=True)[0], 0)      # the real code was not used up

    def test_new_accounts_are_capped_per_hour(self):
        self.limit("SIGNUP_LIMIT_OVERALL", (2, 3600))
        self.signed_in("a@example.com")
        self.signed_in("b@example.com")
        status, text, _ = Browser(self.port).post("/signup", form={"email": "c@example.com", "password": PASSWORD})
        self.assertEqual(status, 429)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM users", one=True)[0], 2)


class PairingCodeExpiry(RelayCase):
    def test_a_code_stops_working_after_fifteen_minutes(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        relay.sql("UPDATE pis SET code_ts=?", (time.time() - relay.PAIR_CODE_MINUTES * 60 - 5,), commit=True)
        status, text, _ = Browser(self.port).post("/agent/pair", data={"code": code})
        self.assertEqual(status, 400)
        self.assertIn("expired", json.loads(text)["error"])

    def test_opening_the_page_issues_a_fresh_code_that_works(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        old = relay.sql("SELECT code FROM pis", one=True)[0]
        relay.sql("UPDATE pis SET code_ts=0", commit=True)
        page = b.get("/")[1]
        new = relay.sql("SELECT code FROM pis", one=True)[0]
        self.assertNotEqual(new, old)
        self.assertIn(new, page)
        self.assertIn("15 minutes", page)
        self.assertEqual(Browser(self.port).post("/agent/pair", data={"code": old})[0], 400)
        self.assertEqual(Browser(self.port).post("/agent/pair", data={"code": new})[0], 200)

    def test_a_code_still_in_date_is_left_alone_when_the_page_is_reloaded(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        b.get("/")
        b.get("/")
        self.assertEqual(relay.sql("SELECT code FROM pis", one=True)[0], code)

    def test_a_database_from_version_0_5_is_upgraded_in_place(self):
        import sqlite3
        folder = tempfile.mkdtemp(prefix="quietnet-relay-old-")
        old = sqlite3.connect(os.path.join(folder, "relay.db"))
        old.executescript("""
            CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL);
            CREATE TABLE pis(id TEXT PRIMARY KEY, user_id INTEGER, name TEXT, token TEXT,
                code TEXT, paired INTEGER, created REAL, last_seen REAL);
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO pis VALUES('abc', 1, 'Home Pi', 'tok', '', 1, 1.0, 2.0);
        """)
        old.commit()
        old.close()
        keep = (relay.db, relay.SECRET, relay.DATA)
        try:
            relay.DATA = folder
            relay.init_db()
            self.assertEqual(relay.sql("SELECT id, token, paired, code_ts FROM pis"), [("abc", "tok", 1, 0)])
            relay.init_db()                                   # starting a second time must not fail
            relay.db.close()
        finally:
            relay.db, relay.SECRET, relay.DATA = keep


class SignupSwitch(RelayCase):
    def signup(self, email):
        return Browser(self.port).post("/signup", form={"email": email, "password": PASSWORD})

    def test_open_by_default(self):
        self.assertEqual(relay.SIGNUP, "open")
        self.assertIn("Create an account", Browser(self.port).get("/login")[1])

    def test_closed_means_nobody_can_create_an_account(self):
        self.limit("SIGNUP", "closed")
        status, text, _ = self.signup("a@example.com")
        self.assertEqual(status, 403)
        self.assertIn("switched off", text)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM users", one=True)[0], 0)
        self.assertIn("switched off", Browser(self.port).get("/signup")[1])
        self.assertNotIn("Create an account", Browser(self.port).get("/login")[1])

    def test_first_lets_in_one_account_then_shuts_the_door(self):
        self.limit("SIGNUP", "first")
        self.assertEqual(self.signup("lewis@example.com")[0], 303)
        self.assertEqual(self.signup("stranger@example.com")[0], 403)
        self.assertEqual(relay.sql("SELECT email FROM users"), [("lewis@example.com",)])
        self.assertNotIn("Create an account", Browser(self.port).get("/login")[1])

    def test_existing_accounts_can_still_sign_in_when_sign_up_is_closed(self):
        self.signed_in()
        self.limit("SIGNUP", "closed")
        status, _, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": PASSWORD})
        self.assertEqual(status, 303)


class OversizedAndOddInput(RelayCase):
    API = {"X-QuietNet": "1"}

    def test_a_connection_that_stalls_is_dropped(self):
        # Otherwise anyone could tie up the relay's threads by sending a request very slowly.
        self.addCleanup(setattr, relay.Relay, "timeout", relay.Relay.timeout)
        relay.Relay.timeout = 0.5
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nemail=")
            started = time.time()
            try:
                while s.recv(4096):
                    pass
            except OSError:
                pass
        self.assertLess(time.time() - started, 4)

    def test_an_oversized_body_is_not_read_or_relayed(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        big = {"domain": "x" * (relay.MAX_BODY + 1)}
        self.assertEqual(b.post("/pi/%s/api/block" % pid, data=big, headers=self.API)[0], 413)
        self.assertEqual(relay.bridge.queues.get(pid, []), [])

    def test_a_paired_pi_may_send_back_a_large_answer(self):
        # A week of a busy device's history is far bigger than the 64 KB limit on everything else.
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        big = json.dumps({"hosts": ["n%d.example.com" % i for i in range(20000)]})
        self.assertGreater(len(big), relay.MAX_BODY)
        t, _ = self.pretend_pi(token, body=big)
        status, text, _ = b.get("/pi/%s/api/activity" % pid, headers=self.API)
        t.join(5)
        self.assertEqual(status, 200)
        self.assertEqual(text, big)

    def test_a_large_answer_is_only_read_for_a_call_that_is_waiting(self):
        # Anyone can pair a Pi of their own, so a valid token alone mustn't open the 16 MB door.
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        payload = {"id": "not-a-real-call", "status": 200, "body": "x" * (relay.MAX_BODY + 1)}
        try:
            status = Browser(self.port).post("/agent/respond", data=payload,
                                             headers={"X-QuietNet-Token": token, "X-QuietNet-Call": "not-a-real-call"})[0]
        except OSError:
            status = 413                         # refused before the upload finished: also a refusal
        self.assertEqual(status, 413)

    def test_a_stranger_cannot_send_a_large_answer(self):
        payload = {"id": "x", "status": 200, "body": "x" * (relay.MAX_BODY + 1)}
        status, _, _ = Browser(self.port).post("/agent/respond", data=payload, headers={"X-QuietNet-Token": "nope"})
        self.assertEqual(status, 401)

    def test_an_oversized_form_is_treated_as_empty(self):
        status, text, _ = Browser(self.port).post(
            "/signup", form={"email": "a@example.com", "password": "p" * (relay.MAX_BODY + 1)})
        self.assertIn("Enter a valid email", text)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM users", one=True)[0], 0)

    def test_json_that_is_not_an_object_is_treated_as_empty(self):
        for data in ([1, 2], "text", 5):
            self.assertEqual(Browser(self.port).post("/agent/pair", data=data)[0], 400)

    def test_a_pi_cannot_make_the_relay_send_a_strange_status(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        for odd in (99, 700, "abc", None):
            t, _ = self.pretend_pi(token, status=odd)
            self.assertEqual(b.get("/pi/%s/api/status" % pid, headers=self.API)[0], 502, odd)
            t.join(5)

    def test_an_overlong_email_is_refused(self):
        email = "a" * 250 + "@example.com"
        status, text, _ = Browser(self.port).post("/signup", form={"email": email, "password": PASSWORD})
        self.assertIn("Enter a valid email", text)


if __name__ == "__main__":
    unittest.main()
