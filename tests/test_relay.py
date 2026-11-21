"""Checks for the relay (cloud/relay.py): accounts, sessions, pairing, and the
bridge that carries a browser's request down to a Pi and the answer back up.

Run with:  python3 -m unittest discover tests

Standard library only. The relay is started on a spare port on this computer with
a throwaway data folder, and a pretend Pi answers its calls. Nothing leaves this machine.
"""
import http.client
import json
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
                    headers={"X-QuietNet-Token": token})

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
            self.bridge.respond(call["id"], {"status": 200, "body": "hello"})

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
        self.bridge.respond("no-such-call", {"status": 200, "body": ""})   # must not raise
        self.assertEqual(self.bridge.waiting, {})


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
        self.assertIn("wrong or already used", json.loads(text)["error"])

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


if __name__ == "__main__":
    unittest.main()
