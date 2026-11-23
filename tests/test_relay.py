"""Checks for the relay (cloud/relay.py): accounts, sessions, pairing, and the
bridge that carries a browser's request down to a Pi and the answer back up.

Run with:  python3 -m unittest discover tests

Standard library only. The relay is started on a spare port on this computer with
a throwaway data folder, and a pretend Pi answers its calls. Nothing leaves this machine.
"""
import http.client
import json
import re
import socket
import stat
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
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
        cls.httpd = relay.RelayServer(("127.0.0.1", 0), relay.Relay)
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
            relay.bridge.pollers.clear()
        relay.throttle.failures.clear()
        relay.sql("DELETE FROM throttle", commit=True)
        self.limit("big_answers", relay.BigAnswers(relay.BIG_ANSWER_BUDGET))
        self.limit("SIGNUP", "open")        # most tests make several accounts; SignupSwitch tests the others

    def limit(self, name, value):
        """Change one of the relay's limits for the length of a test."""
        self.addCleanup(setattr, relay, name, getattr(relay, name))
        setattr(relay, name, value)

    def signed_in(self, email="lewis@example.com"):
        """Create an account and sign in to it, as a person would. Returns the signed-in browser."""
        b = Browser(self.port)
        status, text, _ = b.post("/signup", form={"email": email, "password": PASSWORD})
        self.assertEqual(status, 200)
        self.assertIn("Now sign in", text)
        status, _, r = b.post("/login", form={"email": email, "password": PASSWORD})
        self.assertEqual(status, 303)
        self.assertEqual(r.getheader("Location"), "/")
        return b

    def make_account(self, email="lewis@example.com"):
        """Add an account straight to the database (quickly) and return its user id."""
        relay.sql("INSERT INTO users(email,pw,created) VALUES(?,?,?)",
                  (email, relay.hash_pw(PASSWORD, rounds=1000), time.time()), commit=True)
        return relay.sql("SELECT id FROM users WHERE email=?", (email,), one=True)[0]

    def sign_out(self, browser, page="/"):
        """Press the sign-out button on a page, as the browser would: post its form, token and all."""
        token = re.search(r'name="token" value="([0-9a-f]+)"', browser.get(page)[1]).group(1)
        return browser.post("/logout", form={"token": token})

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
        uid = self.make_account()
        self.assertEqual(relay.read_session(relay.make_session(uid)), uid)

    def test_changing_the_user_number_breaks_the_signature(self):
        uid = self.make_account()
        other = self.make_account("hannah@example.com")
        _, gen, exp, sig = relay.make_session(uid).split(".")
        self.assertIsNone(relay.read_session("%d.%s.%s.%s" % (other, gen, exp, sig)))

    def test_extending_the_expiry_breaks_the_signature(self):
        uid, gen, exp, sig = relay.make_session(self.make_account()).split(".")
        self.assertIsNone(relay.read_session("%s.%s.%d.%s" % (uid, gen, int(exp) + 999999, sig)))

    def test_an_expired_session_is_refused(self):
        uid = self.make_account()
        real = relay.SESSION_HOURS
        relay.SESSION_HOURS = -1
        try:
            old = relay.make_session(uid)
        finally:
            relay.SESSION_HOURS = real
        self.assertIsNone(relay.read_session(old))

    def test_a_session_from_before_signing_out_everywhere_is_refused(self):
        uid = self.make_account()
        old = relay.make_session(uid)
        relay.end_sessions(uid)
        self.assertIsNone(relay.read_session(old))

    def test_a_session_made_after_signing_out_everywhere_works(self):
        uid = self.make_account()
        relay.end_sessions(uid)
        self.assertEqual(relay.read_session(relay.make_session(uid)), uid)

    def test_changing_the_password_ends_every_session(self):
        uid = self.make_account()
        old = relay.make_session(uid)
        relay.sql("UPDATE users SET pw=? WHERE id=?", (relay.hash_pw("a new password", rounds=1000), uid), commit=True)
        self.assertIsNone(relay.read_session(old))

    def test_a_cookie_made_before_session_numbers_counts_as_signed_out(self):
        # The old form was 'user.expiry.signature'; it must be refused quietly, not cause an error.
        uid = self.make_account()
        old_style = "%d.9999999999.%s" % (uid, "0" * 32)
        self.assertIsNone(relay.read_session(old_style))
        b = Browser(self.port)
        b.cookie = "qn_session=" + old_style
        status, _, r = b.get("/")
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_a_session_for_a_removed_account_is_refused(self):
        uid = self.make_account()
        cookie = relay.make_session(uid)
        relay.sql("DELETE FROM users WHERE id=?", (uid,), commit=True)
        self.assertIsNone(relay.read_session(cookie))

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

    def test_after_signing_up_you_can_sign_in(self):
        b = self.signed_in()
        status, text, _ = b.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Your QuietNets", text)

    def test_signing_up_does_not_sign_you_in_by_itself(self):
        b = Browser(self.port)
        status, text, r = b.post("/signup", form={"email": "a@example.com", "password": PASSWORD})
        self.assertEqual(status, 200)
        self.assertIsNone(r.getheader("Set-Cookie"))
        self.assertEqual(relay.sql("SELECT email FROM users"), [("a@example.com",)])

    def test_the_session_cookie_is_hidden_from_page_scripts(self):
        b = self.signed_in()
        self.assertIn("HttpOnly", b.cookie_flags)
        self.assertIn("SameSite=Lax", b.cookie_flags)

    def test_the_cookie_is_marked_secure_behind_https(self):
        self.make_account("a@example.com")
        b = Browser(self.port)
        b.post("/login", form={"email": "a@example.com", "password": PASSWORD},
               headers={"X-Forwarded-Proto": "https"})
        self.assertIn("Secure", b.cookie_flags)

    def test_the_same_email_cannot_sign_up_twice(self):
        self.signed_in()
        record = relay.sql("SELECT pw FROM users", one=True)[0]
        Browser(self.port).post("/signup", form={"email": "LEWIS@example.com", "password": "another password"})
        self.assertEqual(relay.sql("SELECT pw FROM users"), [(record,)])     # one account, password unchanged

    def test_sign_up_gives_the_same_answer_whether_or_not_the_email_has_an_account(self):
        self.make_account("lewis@example.com")
        taken = Browser(self.port).post("/signup", form={"email": "lewis@example.com", "password": PASSWORD})
        new = Browser(self.port).post("/signup", form={"email": "hannah@example.com", "password": PASSWORD})
        self.assertEqual((taken[0], taken[1]), (new[0], new[1]))
        self.assertNotIn("already has an account", taken[1])

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
        self.sign_out(b)
        status, _, r = b.get("/")
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_signing_out_ends_a_copy_of_the_cookie_too(self):
        b = self.signed_in()
        copy = Browser(self.port)
        copy.cookie = b.cookie
        self.sign_out(b)
        self.assertEqual(copy.get("/")[0], 303)

    def test_signing_out_ends_the_sessions_in_other_browsers(self):
        laptop = self.signed_in()
        phone = Browser(self.port)
        phone.post("/login", form={"email": "lewis@example.com", "password": PASSWORD})
        self.sign_out(laptop)
        self.assertEqual(phone.get("/")[0], 303)

    def test_a_sign_in_sent_from_another_website_is_refused(self):
        self.make_account()
        b = Browser(self.port)
        status, text, r = b.post("/login", form={"email": "lewis@example.com", "password": PASSWORD},
                                 headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        self.assertIn("another website", text)
        self.assertIsNone(r.getheader("Set-Cookie"))

    def test_a_sign_in_from_the_relays_own_page_works(self):
        self.make_account()
        status, _, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": PASSWORD},
                                               headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 303)

    def test_a_sign_up_sent_from_another_website_is_refused(self):
        status, _, _ = Browser(self.port).post("/signup", form={"email": "a@example.com", "password": PASSWORD},
                                               headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM users", one=True)[0], 0)

    def test_adding_a_quietnet_from_another_website_is_refused(self):
        b = self.signed_in()
        status, _, _ = b.post("/pis/new", form={"name": "Theirs"}, headers={"Sec-Fetch-Site": "same-site"})
        self.assertEqual(status, 403)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis", one=True)[0], 0)

    def test_the_sign_out_button_on_the_remote_dashboard_works(self):
        b = self.signed_in()
        pid, _ = self.paired_pi(b)
        self.sign_out(b, "/pi/%s/" % pid)
        self.assertEqual(b.get("/")[0], 303)

    def test_opening_the_sign_out_address_only_offers_a_button(self):
        # Any website can send your browser to an address, so a plain visit must not sign you out.
        b = self.signed_in()
        status, text, r = b.get("/logout")
        self.assertEqual(status, 200)
        self.assertIn('action="/logout"', text)
        self.assertIsNone(r.getheader("Set-Cookie"))
        self.assertEqual(b.get("/")[0], 200)

    def test_a_sign_out_without_the_pages_token_changes_nothing(self):
        # A form on another website can post to /logout, but it can't know the token.
        b = self.signed_in()
        for form in ({}, {"token": "0" * 32}, {"token": "\u00e9" * 32}):
            status, _, r = b.post("/logout", form=form)
            self.assertEqual((status, r.getheader("Location")), (303, "/"), form)
            self.assertIsNone(r.getheader("Set-Cookie"), form)
        self.assertEqual(b.get("/")[0], 200)

    def test_one_sessions_sign_out_token_does_not_work_for_another(self):
        mine, theirs = self.signed_in(), self.signed_in("mallory@example.com")
        token = re.search(r'name="token" value="([0-9a-f]+)"', theirs.get("/")[1]).group(1)
        _, _, r = mine.post("/logout", form={"token": token})
        self.assertIsNone(r.getheader("Set-Cookie"))
        self.assertEqual(mine.get("/")[0], 200)

    def test_a_forged_cookie_does_not_sign_you_in(self):
        self.signed_in()
        b = Browser(self.port)
        b.cookie = "qn_session=1.0.9999999999.%s" % ("0" * 32)
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


class Onboarding(RelayCase):
    """The home page's one-line install command for a new Pi, and its getting-started text."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("QUIETNET_RELAY_URL", None)
        os.environ.pop("RAILWAY_PUBLIC_DOMAIN", None)

    def waiting_page(self, headers=None):
        """Sign in, add a Pi waiting to be paired, and return (its code, the home page's text)."""
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        return code, b.get("/", headers=headers)[1]

    def test_the_install_command_shows_the_code_and_the_relay_address(self):
        code, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertIn("curl -fsSL %s | sh -s -- --relay https://relay.example.com --code %s"
                      % (relay.INSTALL_URL, code), text)

    def test_the_install_command_is_offered_for_a_new_pi(self):
        _, text = self.waiting_page()
        self.assertIn("New Pi?", text)

    def test_the_manual_pairing_instructions_are_still_shown(self):
        _, text = self.waiting_page()
        self.assertIn("open <b>Remote access</b>", text)

    def test_a_plain_host_header_with_a_port_is_used(self):
        _, text = self.waiting_page(headers={"Host": "relay.example.com:8443"})
        self.assertIn("--relay https://relay.example.com:8443 --code", text)

    def test_a_hostile_host_header_is_not_shown_and_the_placeholder_is_used(self):
        for host in ('evil.com"><b>x', "evil.com <b>", "evil.com';rm"):
            _, text = self.waiting_page(headers={"Host": host})
            self.assertNotIn("evil.com", text, host)
            self.assertIn("--relay %s --code" % relay.RELAY_PLACEHOLDER, text, host)
            self.assertIn("Replace %s with this relay" % relay.RELAY_PLACEHOLDER, text, host)
            relay.sql("DELETE FROM users", commit=True)
            relay.sql("DELETE FROM pis", commit=True)

    def test_the_placeholder_note_is_not_shown_when_the_address_is_known(self):
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertNotIn("Replace ", text)

    def test_the_configured_relay_address_wins(self):
        os.environ["QUIETNET_RELAY_URL"] = "https://quietnet.example.org/"
        os.environ["RAILWAY_PUBLIC_DOMAIN"] = "app.up.railway.app"
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertIn("--relay https://quietnet.example.org --code", text)

    def test_a_configured_relay_address_with_odd_characters_is_not_used(self):
        os.environ["QUIETNET_RELAY_URL"] = "https://x.example.org/$(reboot)"
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertNotIn("reboot", text)
        self.assertIn("--relay https://relay.example.com --code", text)

    def test_a_configured_plain_http_address_on_another_computer_is_not_used(self):
        os.environ["QUIETNET_RELAY_URL"] = "http://relay.lan:8080"
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertNotIn("relay.lan", text)
        self.assertIn("--relay https://relay.example.com --code", text)

    def test_a_configured_plain_http_address_on_this_computer_is_used(self):
        os.environ["QUIETNET_RELAY_URL"] = "http://127.0.0.1:8080"
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertIn("--relay http://127.0.0.1:8080 --code", text)

    def test_a_configured_plain_http_localhost_address_is_used(self):
        os.environ["QUIETNET_RELAY_URL"] = "http://localhost:8080"
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertIn("--relay http://localhost:8080 --code", text)

    def test_a_configured_plain_http_localhost_address_in_capitals_is_not_used(self):
        os.environ["QUIETNET_RELAY_URL"] = "http://LocalHost:8080"
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertIn("--relay https://relay.example.com --code", text)

    def test_the_railway_public_address_is_used(self):
        os.environ["RAILWAY_PUBLIC_DOMAIN"] = "app.up.railway.app"
        _, text = self.waiting_page(headers={"Host": "relay.example.com"})
        self.assertIn("--relay https://app.up.railway.app --code", text)

    def test_the_install_command_is_escaped_on_the_page(self):
        self.limit("INSTALL_URL", "https://example.com/i.sh?a=1&b=<x>")
        _, text = self.waiting_page()
        self.assertNotIn("<x>", text)
        self.assertIn("https://example.com/i.sh?a=1&amp;b=&lt;x&gt;", text)

    def test_an_account_with_no_quietnets_is_shown_how_to_start(self):
        text = self.signed_in().get("/")[1]
        self.assertIn("To get started", text)
        self.assertIn("Create pairing code", text)


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
        _, _, r = self.sign_out(b)
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
            self.assertEqual(relay.sql("SELECT id, token, paired, code_ts FROM pis"),
                             [("abc", relay.token_record("tok"), 1, 0)])
            relay.init_db()                                   # starting a second time must not fail
            relay.db.close()
        finally:
            relay.db, relay.SECRET, relay.DATA = keep


class SignupSwitch(RelayCase):
    def signup(self, email):
        return Browser(self.port).post("/signup", form={"email": email, "password": PASSWORD})

    def test_only_the_first_account_by_default(self):
        self.assertEqual(relay.read_signup_setting({}), "first")
        self.assertEqual(relay.read_signup_setting({"QUIETNET_SIGNUP": ""}), "first")

    def test_open_can_still_be_chosen(self):
        self.assertEqual(relay.read_signup_setting({"QUIETNET_SIGNUP": " Open "}), "open")
        self.limit("SIGNUP", "open")
        self.assertIn("Create an account", Browser(self.port).get("/login")[1])

    def test_the_start_up_log_says_which_sign_up_setting_is_in_force(self):
        for mode, words in (("first", "first account only"), ("open", "open"), ("closed", "closed"),
                            ("frist", "closed")):
            self.limit("SIGNUP", mode)
            self.assertIn(words, relay.signup_status(), mode)

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
        self.assertEqual(self.signup("lewis@example.com")[0], 200)
        self.assertEqual(self.signup("stranger@example.com")[0], 403)
        self.assertEqual(relay.sql("SELECT email FROM users"), [("lewis@example.com",)])
        self.assertNotIn("Create an account", Browser(self.port).get("/login")[1])

    def test_a_second_sign_up_that_passed_the_check_before_the_first_finished_makes_no_account(self):
        self.limit("SIGNUP", "first")
        real_hash = relay.hash_pw

        def someone_else_signs_up_meanwhile(password, *a, **kw):
            """Another sign-up finishes while this one is still working out its password record."""
            relay.sql("INSERT INTO users(email,pw,created) VALUES(?,?,?)",
                      ("lewis@example.com", real_hash("another password"), time.time()), commit=True)
            return real_hash(password, *a, **kw)

        with mock.patch.object(relay, "hash_pw", someone_else_signs_up_meanwhile):
            status, text, _ = self.signup("stranger@example.com")
        self.assertEqual(status, 200)
        self.assertIn("Thank you", text)
        self.assertEqual(relay.sql("SELECT email FROM users"), [("lewis@example.com",)])

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



# ------------------------------------------------------------------ cookies the relay didn't make

class OddCookies(RelayCase):
    def test_a_session_cookie_with_non_ascii_letters_is_not_valid(self):
        self.assertIsNone(relay.read_session("\xc3\xa9.9999999999.%s" % ("0" * 32)))
        self.assertIsNone(relay.read_session("1.9999999999.\xc3\xa9"))

    def test_a_session_cookie_with_an_enormous_user_number_counts_as_signed_out(self):
        self.assertIsNone(relay.read_session("99999999999999999999999.0.9999999999.abc"))
        self.assertIsNone(relay.read_session("1.99999999999999999999999.9999999999.abc"))

    def test_an_enormous_user_number_in_a_cookie_gets_the_signed_out_answer(self):
        b = Browser(self.port)
        b.cookie = "qn_session=99999999999999999999999.0.9999999999.abc"
        status, _, r = b.get("/")
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_a_non_ascii_session_cookie_gets_the_signed_out_answer(self):
        # Another site on the same domain could set such a cookie; the relay must still answer.
        b = Browser(self.port)
        b.cookie = "qn_session=\xc3\xa9.1.x"
        status, _, r = b.get("/")
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_a_non_ascii_known_browser_cookie_does_not_stop_signing_in(self):
        self.signed_in()
        status, _, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": PASSWORD},
                                               headers={"Cookie": "qn_known=1.\xc3\xa9"})
        self.assertEqual(status, 303)


# ------------------------------------------------------------------ the sign-up setting

class SignupSetting(RelayCase):
    def test_an_unrecognised_setting_keeps_sign_up_closed(self):
        self.limit("SIGNUP", "close")               # a typo for "closed"
        status, _, _ = Browser(self.port).post("/signup", form={"email": "a@example.com", "password": PASSWORD})
        self.assertEqual(status, 403)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM users", one=True)[0], 0)

    def test_an_unrecognised_setting_is_warned_about(self):
        self.limit("SIGNUP", "frist")
        self.assertIn("frist", relay.signup_warning())
        self.assertIn("switched off", relay.signup_warning())

    def test_the_known_settings_give_no_warning(self):
        for mode in ("open", "first", "closed"):
            self.limit("SIGNUP", mode)
            self.assertIsNone(relay.signup_warning(), mode)


# ------------------------------------------------------------------ pairing limits

class PairingLimits(RelayCase):
    def pair(self, code, address):
        return Browser(self.port).post("/agent/pair", data={"code": code}, headers={"X-Forwarded-For": address})

    def new_code(self, browser, name="Home Pi"):
        browser.post("/pis/new", form={"name": name})
        return relay.sql("SELECT code FROM pis WHERE name=?", (name,), one=True)[0]

    def test_bad_codes_from_one_address_are_capped(self):
        self.limit("PAIR_LIMIT_PER_ADDRESS", (3, 600))
        code = self.new_code(self.signed_in())
        for i in range(3):
            self.assertEqual(self.pair("0000-000%d" % i, "203.0.113.9")[0], 400)
        self.assertEqual(self.pair(code, "203.0.113.9")[0], 429)

    def test_bad_codes_from_one_address_do_not_stop_another_address_pairing(self):
        self.limit("PAIR_LIMIT_PER_ADDRESS", (3, 600))
        code = self.new_code(self.signed_in())
        for i in range(5):
            self.pair("0000-000%d" % i, "203.0.113.9")
        self.assertEqual(self.pair(code, "198.51.100.7")[0], 200)

    def test_the_address_added_last_by_the_proxy_is_the_one_counted(self):
        # Earlier entries in X-Forwarded-For are whatever the sender wrote, so they can't dodge the limit.
        self.limit("PAIR_LIMIT_PER_ADDRESS", (3, 600))
        code = self.new_code(self.signed_in())
        for i in range(3):
            self.pair("0000-000%d" % i, "10.0.0.%d, 203.0.113.9" % i)
        self.assertEqual(self.pair(code, "10.9.9.9, 203.0.113.9")[0], 429)

    def test_ipv6_addresses_in_one_block_share_a_limit(self):
        self.limit("PAIR_LIMIT_PER_ADDRESS", (3, 600))
        code = self.new_code(self.signed_in())
        for i in range(3):
            self.pair("0000-000%d" % i, "2001:db8:1:2::%d" % (i + 1))
        self.assertEqual(self.pair(code, "2001:db8:1:2::99")[0], 429)

    def test_successful_pairings_are_capped_per_account(self):
        self.limit("PAIR_LIMIT_PER_ACCOUNT", (2, 3600))
        b = self.signed_in()
        self.paired_pi(b, "One")
        self.paired_pi(b, "Two")
        code = self.new_code(b, "Three")
        status, text, _ = self.pair(code, "198.51.100.7")
        self.assertEqual(status, 429)
        self.assertIn("too many", json.loads(text)["error"])
        self.assertEqual(relay.sql("SELECT paired FROM pis WHERE name='Three'", one=True)[0], 0)


# ------------------------------------------------------------------ how many QuietNets, and finding them fast

class QuietNetsPerAccount(RelayCase):
    def test_an_account_can_hold_at_most_the_set_number_of_quietnets(self):
        self.limit("MAX_PIS_PER_ACCOUNT", 2)
        b = self.signed_in()
        b.post("/pis/new", form={"name": "One"})
        b.post("/pis/new", form={"name": "Two"})
        status, text, _ = b.post("/pis/new", form={"name": "Three"})
        self.assertEqual(status, 403)
        self.assertIn("Remove one before adding another", text)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis", one=True)[0], 2)

    def test_one_accounts_quietnets_do_not_count_against_another(self):
        self.limit("MAX_PIS_PER_ACCOUNT", 1)
        self.signed_in().post("/pis/new", form={"name": "One"})
        status, _, _ = self.signed_in("hannah@example.com").post("/pis/new", form={"name": "Two"})
        self.assertEqual(status, 303)

    def test_removing_a_pi_forgets_it_in_the_bridge(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        self.limit("POLL_TIMEOUT", 0.1)
        Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": token})
        self.assertIn(pid, relay.bridge.cond)
        b.post("/pis/%s/delete" % pid)
        self.assertNotIn(pid, relay.bridge.cond)

    def plan(self, query, args):
        """How SQLite would run a query, as one line of text."""
        return " ".join(str(row[-1]) for row in relay.sql("EXPLAIN QUERY PLAN " + query, args))

    def test_a_pis_lookup_by_token_uses_an_index(self):
        self.assertIn("USING INDEX pis_token", self.plan("SELECT id FROM pis WHERE token=? AND paired=1", ("x",)))

    def test_a_lookup_by_pairing_code_uses_an_index(self):
        self.assertIn("USING INDEX pis_code", self.plan(
            "SELECT id, user_id FROM pis WHERE code=? AND paired=0 AND code_ts>?", ("x", 0)))

    def test_an_existing_database_gains_the_lookup_indexes(self):
        import sqlite3
        folder = tempfile.mkdtemp(prefix="quietnet-relay-old-")
        old = sqlite3.connect(os.path.join(folder, "relay.db"))
        old.executescript("""
            CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL);
            CREATE TABLE pis(id TEXT PRIMARY KEY, user_id INTEGER, name TEXT, token TEXT,
                code TEXT, paired INTEGER, created REAL, last_seen REAL, code_ts REAL DEFAULT 0);
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        """)
        old.commit()
        old.close()
        keep = (relay.db, relay.SECRET, relay.DATA)
        try:
            relay.DATA = folder
            relay.init_db()
            names = {row[0] for row in relay.sql("SELECT name FROM sqlite_master WHERE type='index'")}
            relay.db.close()
        finally:
            relay.db, relay.SECRET, relay.DATA = keep
        self.assertTrue({"pis_token", "pis_code", "pis_user"} <= names, names)


# ------------------------------------------------------------------ the cost of signing in

class SignInCost(RelayCase):
    def login(self, email="lewis@example.com", password=PASSWORD, headers=None):
        return Browser(self.port).post("/login", form={"email": email, "password": password}, headers=headers)

    def test_signing_in_correctly_over_and_over_is_capped(self):
        self.make_account()
        self.limit("LOGIN_TRIES_PER_EMAIL", (3, 600))
        for _ in range(3):
            self.assertEqual(self.login()[0], 303)
        self.assertEqual(self.login()[0], 429)

    def test_sign_in_attempts_from_one_address_are_capped(self):
        self.signed_in()
        self.signed_in("hannah@example.com")
        self.limit("LOGIN_TRIES_PER_ADDRESS", (3, 600))
        here = {"X-Forwarded-For": "203.0.113.9"}
        for _ in range(3):
            self.login(headers=here)
        self.assertEqual(self.login("hannah@example.com", headers=here)[0], 429)

    def test_sign_in_attempts_from_one_address_do_not_block_another(self):
        self.signed_in()
        self.limit("LOGIN_TRIES_PER_ADDRESS", (3, 600))
        for _ in range(3):
            self.login(headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(self.login(headers={"X-Forwarded-For": "198.51.100.7"})[0], 303)

    def test_a_known_browser_signing_in_over_and_over_is_capped(self):
        self.signed_in()
        _, _, r = self.login()
        marker = [v for k, v in r.getheaders() if k.lower() == "set-cookie" and v.startswith("qn_known=")][0]
        self.limit("LOGIN_TRIES_KNOWN_BROWSER", (3, 600))
        for _ in range(3):
            self.assertEqual(self.login(headers={"Cookie": marker.split(";")[0]})[0], 303)
        self.assertEqual(self.login(headers={"Cookie": marker.split(";")[0]})[0], 429)

    def test_only_a_few_passwords_are_checked_at_once(self):
        self.signed_in()
        self.limit("password_checks", threading.BoundedSemaphore(1))
        self.limit("PASSWORD_CHECK_WAIT", 0.1)
        relay.password_checks.acquire()                 # another sign-in is checking a password right now
        self.addCleanup(relay.password_checks.release)
        status, text, _ = self.login()
        self.assertEqual(status, 503)
        self.assertIn("busy", text)


# ------------------------------------------------------------------ connections and threads

class ConnectionLimits(RelayCase):
    def busy_server(self):
        """A second relay server that handles only one connection at a time."""
        httpd = relay.RelayServer(("127.0.0.1", 0), relay.Relay, max_connections=1)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return httpd

    def test_connections_beyond_the_cap_are_told_the_relay_is_busy(self):
        httpd = self.busy_server()
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5):   # holds the only place
            time.sleep(0.2)
            status, text, _ = Browser(httpd.server_address[1]).get("/healthz")
        self.assertEqual(status, 503)
        self.assertIn("busy", text)

    def test_the_busy_answer_carries_the_protective_headers(self):
        httpd = self.busy_server()
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5):
            time.sleep(0.2)
            r = Browser(httpd.server_address[1]).get("/healthz")[2]
        for name, value in Headers.WANTED.items():
            self.assertEqual(r.getheader(name), value, name)

    def test_a_place_is_freed_when_a_connection_ends(self):
        httpd = self.busy_server()
        self.assertEqual(Browser(httpd.server_address[1]).get("/healthz")[0], 200)
        time.sleep(0.2)
        self.assertEqual(Browser(httpd.server_address[1]).get("/healthz")[0], 200)

    def test_waiting_pis_beyond_their_cap_are_told_to_try_again(self):
        pid, token = self.paired_pi(self.signed_in())
        self.limit("poll_slots", threading.BoundedSemaphore(1))
        relay.poll_slots.acquire()                      # another Pi is waiting in the only place
        self.addCleanup(relay.poll_slots.release)
        status, _, _ = Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": token})
        self.assertEqual(status, 503)

    def test_a_body_that_trickles_in_too_slowly_is_dropped(self):
        # Each wait for more data is short, but the whole body still has to arrive in time.
        self.limit("BODY_SECONDS", 1)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n")
            started = time.time()
            try:
                while time.time() - started < 6:
                    s.sendall(b"e")
                    time.sleep(0.2)
                    s.setblocking(False)
                    try:
                        if s.recv(4096) == b"":
                            break
                    except BlockingIOError:
                        pass
                    finally:
                        s.setblocking(True)
            except OSError:
                pass
        self.assertLess(time.time() - started, 4)


    def test_a_request_whose_headers_trickle_in_too_slowly_is_dropped(self):
        # Each wait for more data is short, but the first line and headers still have to arrive in time.
        self.limit("HEADER_SECONDS", 1)
        httpd = self.busy_server()
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5) as s:
            s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
            started = time.time()
            try:
                while time.time() - started < 6:
                    s.sendall(b"X")
                    time.sleep(0.2)
                    s.setblocking(False)
                    try:
                        if s.recv(4096) == b"":
                            break
                    except BlockingIOError:
                        pass
                    finally:
                        s.setblocking(True)
            except OSError:
                pass
            self.assertLess(time.time() - started, 4)
        time.sleep(0.2)
        self.assertEqual(Browser(httpd.server_address[1]).get("/healthz")[0], 200)     # its place was freed

    def test_a_request_whose_headers_arrive_in_time_is_answered(self):
        self.limit("HEADER_SECONDS", 1)
        httpd = self.busy_server()
        self.assertEqual(Browser(httpd.server_address[1]).get("/healthz")[0], 200)
        time.sleep(1.5)                                 # the clock is stopped once the headers are in
        self.assertEqual(Browser(httpd.server_address[1]).get("/healthz")[0], 200)


class BridgePolls(unittest.TestCase):
    def test_a_new_poll_from_a_pi_ends_its_older_one(self):
        bridge = relay.Bridge()
        real = relay.POLL_TIMEOUT
        relay.POLL_TIMEOUT = 5
        self.addCleanup(setattr, relay, "POLL_TIMEOUT", real)
        ended = {}

        def first():
            started = time.time()
            ended["result"] = bridge.poll("pi-1")
            ended["after"] = time.time() - started

        t1 = threading.Thread(target=first, daemon=True)
        t1.start()
        time.sleep(0.2)
        t2 = threading.Thread(target=bridge.poll, args=("pi-1",), daemon=True)
        t2.start()
        t1.join(3)
        bridge.forget("pi-1")                           # ends the second poll too
        t2.join(3)
        self.assertIsNone(ended["result"])
        self.assertLess(ended["after"], 2)


# ------------------------------------------------------------------ memory held by large answers

class BigAnswerRoom(unittest.TestCase):
    def test_one_account_holds_at_most_one_large_answers_worth_of_room(self):
        # The room is kept per account, so pairing more Pis of your own doesn't get you more of it.
        room = relay.BigAnswers(1000)
        self.assertIsNotNone(room.take(7, 100, 0))      # account 7's first Pi
        self.assertIsNone(room.take(7, 100, 0.05))      # account 7's second Pi must wait its turn
        self.assertIsNotNone(room.take(8, 100, 0))      # another account still gets room

    def test_large_answers_together_stay_within_the_budget(self):
        room = relay.BigAnswers(1000)
        self.assertIsNotNone(room.take("pi-1", 600, 0))
        self.assertIsNone(room.take("pi-2", 600, 0.05))

    def test_giving_back_frees_the_room(self):
        room = relay.BigAnswers(1000)
        ticket = room.take("pi-1", 600, 0)
        room.give_back(ticket)
        self.assertEqual(room.used, 0)
        self.assertIsNotNone(room.take("pi-1", 600, 0))

    def test_giving_back_a_ticket_twice_does_not_free_someone_elses_room(self):
        room = relay.BigAnswers(1000)
        old = room.take("pi-1", 600, 0)
        room.give_back(old)
        room.take("pi-1", 600, 0)
        room.give_back(old)
        self.assertEqual(room.used, 600)


class BigAnswersOverTheWire(RelayCase):
    API = {"X-QuietNet": "1"}
    BIG = json.dumps({"hosts": ["n%d.example.com" % i for i in range(20000)]})

    def test_room_for_a_large_answer_is_given_back_once_the_browser_has_it(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        t, _ = self.pretend_pi(token, body=self.BIG)
        self.assertEqual(b.get("/pi/%s/api/activity" % pid, headers=self.API)[0], 200)
        t.join(5)
        self.assertEqual((relay.big_answers.used, relay.big_answers.held), (0, {}))

    def test_a_large_answer_with_no_room_is_refused_and_the_browser_told_at_once(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        self.limit("big_answers", relay.BigAnswers(relay.MAX_BODY * 2))
        self.limit("BIG_ANSWER_WAIT", 0.1)
        t, _ = self.pretend_pi(token, body=self.BIG)
        started = time.time()
        status, text, _ = b.get("/pi/%s/api/activity" % pid, headers=self.API)
        t.join(5)
        self.assertEqual(status, 503)
        self.assertIn("too large", json.loads(text)["error"])
        self.assertLess(time.time() - started, 5)

    def test_a_large_answer_stops_being_read_when_the_browser_gives_up(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        self.limit("CALL_TIMEOUT", 0.5)
        most = {"used": 0}
        done = threading.Event()

        def watch():
            while not done.is_set():
                most["used"] = max(most["used"], relay.big_answers.used)
                time.sleep(0.02)

        def slow_pi():
            _, text, _ = Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": token})
            call_id = json.loads(text)["id"]
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
                s.sendall(("POST /agent/respond HTTP/1.1\r\nHost: x\r\nX-QuietNet-Token: %s\r\n"
                           "X-QuietNet-Call: %s\r\nContent-Length: 1000000\r\n\r\n" % (token, call_id)).encode())
                try:
                    for _ in range(40):
                        s.sendall(b"x" * 100)
                        time.sleep(0.1)
                except OSError:
                    pass

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        pi = threading.Thread(target=slow_pi, daemon=True)
        pi.start()
        self.assertEqual(b.get("/pi/%s/api/activity" % pid, headers=self.API)[0], 504)
        deadline = time.time() + 3
        while relay.big_answers.used and time.time() < deadline:
            time.sleep(0.05)
        freed = relay.big_answers.used == 0 and pi.is_alive()     # freed while the Pi was still sending
        done.set()
        pi.join(6)
        self.assertEqual(most["used"], 1000000)
        self.assertTrue(freed)


# ------------------------------------------------------------------ Pi tokens are stored hashed

class TokenStorage(RelayCase):
    def test_the_pis_token_is_not_stored_as_plain_text(self):
        pid, token = self.paired_pi(self.signed_in())
        stored = relay.sql("SELECT token FROM pis WHERE id=?", (pid,), one=True)[0]
        self.assertNotIn(token, stored)
        self.assertEqual(stored, relay.token_record(token))

    def test_a_paired_pi_still_gets_in_with_its_token(self):
        pid, token = self.paired_pi(self.signed_in())
        self.limit("POLL_TIMEOUT", 0.05)
        self.assertEqual(Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": token})[0], 200)

    def test_the_stored_record_does_not_work_as_a_token(self):
        pid, token = self.paired_pi(self.signed_in())
        stored = relay.sql("SELECT token FROM pis WHERE id=?", (pid,), one=True)[0]
        self.assertEqual(Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": stored})[0], 401)

    def old_database(self, token):
        """A relay.db from before tokens were hashed, holding one paired Pi with a plain-text token."""
        import sqlite3
        folder = tempfile.mkdtemp(prefix="quietnet-relay-old-")
        old = sqlite3.connect(os.path.join(folder, "relay.db"))
        old.executescript("""
            CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL);
            CREATE TABLE pis(id TEXT PRIMARY KEY, user_id INTEGER, name TEXT, token TEXT,
                code TEXT, paired INTEGER, created REAL, last_seen REAL, code_ts REAL DEFAULT 0);
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        """)
        old.execute("INSERT INTO pis VALUES('abc', 1, 'Home Pi', ?, '', 1, 1.0, 2.0, 0)", (token,))
        old.commit()
        old.close()
        return folder

    def start_on(self, folder):
        """Point the relay at another data folder and start it there, putting things back afterwards."""
        keep = (relay.db, relay.SECRET, relay.DATA)

        def put_back():
            relay.db.close()
            relay.db, relay.SECRET, relay.DATA = keep
        self.addCleanup(put_back)
        relay.DATA = folder
        relay.init_db()

    def test_plain_text_tokens_in_an_old_database_are_hashed_at_start_up(self):
        self.start_on(self.old_database("a" * 48))
        self.assertEqual(relay.sql("SELECT token FROM pis", one=True)[0], relay.token_record("a" * 48))

    def test_starting_again_does_not_hash_a_token_twice(self):
        self.start_on(self.old_database("a" * 48))
        relay.init_db()
        self.assertEqual(relay.sql("SELECT token FROM pis", one=True)[0], relay.token_record("a" * 48))

    def test_a_pi_paired_before_the_change_still_gets_in(self):
        self.start_on(self.old_database("b" * 48))
        self.limit("POLL_TIMEOUT", 0.05)
        relay.sql("UPDATE pis SET last_seen=?", (time.time(),), commit=True)
        self.assertEqual(Browser(self.port).get("/agent/poll", headers={"X-QuietNet-Token": "b" * 48})[0], 200)


# ------------------------------------------------------------------ limits survive a restart

class LimitsSurviveARestart(RelayCase):
    def test_failures_are_still_counted_after_a_restart(self):
        before = relay.Throttle(persist=True)
        for _ in range(3):
            before.fail("x")
        after = relay.Throttle(persist=True)
        after.load()
        self.assertTrue(after.blocked("x", (3, 60)))

    def test_a_cleared_name_stays_cleared_after_a_restart(self):
        before = relay.Throttle(persist=True)
        before.fail("x")
        before.clear("x")
        after = relay.Throttle(persist=True)
        after.load()
        self.assertFalse(after.blocked("x", (1, 60)))

    def test_failures_too_old_to_count_are_dropped_at_start_up(self):
        relay.sql("INSERT INTO throttle(name, times) VALUES('x', ?)",
                  (json.dumps([time.time() - relay.Throttle.KEEP_SECONDS - 60]),), commit=True)
        relay.Throttle(persist=True).load()
        self.assertEqual(relay.sql("SELECT name FROM throttle"), [])

    def test_damaged_stored_failures_are_ignored(self):
        relay.sql("INSERT INTO throttle(name, times) VALUES('x', 'not a list')", commit=True)
        t = relay.Throttle(persist=True)
        t.load()
        self.assertFalse(t.blocked("x", (1, 60)))

    def test_a_locked_account_is_still_locked_after_a_restart(self):
        self.signed_in()
        for _ in range(relay.LOGIN_LIMIT_PER_EMAIL[0]):
            Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": "wrong password"})
        restarted = relay.Throttle(persist=True)
        restarted.load()
        self.limit("throttle", restarted)
        status, _, _ = Browser(self.port).post("/login", form={"email": "lewis@example.com", "password": PASSWORD})
        self.assertEqual(status, 429)

    def test_the_times_kept_for_one_name_are_bounded(self):
        t = relay.Throttle(persist=True)
        for _ in range(relay.Throttle.MAX_TIMES + 10):
            t.fail("x")
        stored = json.loads(relay.sql("SELECT times FROM throttle WHERE name='x'", one=True)[0])
        self.assertEqual((len(t.failures["x"]), len(stored)), (relay.Throttle.MAX_TIMES, relay.Throttle.MAX_TIMES))

    def test_names_forgotten_under_a_flood_are_removed_from_the_database_too(self):
        self.limit_throttle_names(4)
        t = relay.Throttle(persist=True)
        for i in range(6):
            t.fail("n%d" % i)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM throttle", one=True)[0], len(t.failures))

    def limit_throttle_names(self, most):
        """Make Throttle remember at most `most` names for the length of a test."""
        self.addCleanup(setattr, relay.Throttle, "MAX_NAMES", relay.Throttle.MAX_NAMES)
        relay.Throttle.MAX_NAMES = most


# ------------------------------------------------------------------ not running as root

class StandInSystem:
    """Stands in for the os module's user and file-owner calls, recording what was asked of it."""

    def __init__(self, euid=0, files=("relay.db",), chown_fails=False, links=(), fail_on=None):
        self.euid, self.uid, self.files, self.chown_fails = euid, euid, list(files), chown_fails
        self.links, self.fail_on = set(links), fail_on   # names that are links; a call that raises
        self.calls = []

    def geteuid(self):
        return self.euid

    def getuid(self):
        return self.uid

    def listdir(self, folder):
        return list(self.files)

    def lstat(self, path):
        name = os.path.basename(path)
        if name in self.links:
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        if name in self.files:
            return os.stat_result((stat.S_IFREG | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        raise FileNotFoundError(path)

    def chown(self, path, uid, gid, follow_symlinks=True):
        if self.chown_fails:
            raise PermissionError("not allowed")
        self.calls.append(("chown", path, uid, gid))
        if follow_symlinks:
            self.calls.append(("followed links", path))

    def setgroups(self, groups):
        if self.fail_on == "setgroups":
            raise PermissionError("not allowed in this container")
        self.calls.append(("setgroups", groups))

    def setgid(self, gid):
        if self.fail_on == "setgid":
            raise PermissionError("not allowed in this container")
        self.calls.append(("setgid", gid))

    def setuid(self, uid):
        self.calls.append(("setuid", uid))
        self.euid = self.uid = uid


class NotRoot(unittest.TestCase):
    def test_started_as_root_it_becomes_nobody(self):
        system = StandInSystem()
        relay.drop_privileges("/data", "", system)
        self.assertEqual((system.euid, system.uid), (65534, 65534))
        self.assertIn(("setgid", 65534), system.calls)

    def test_the_data_folder_and_its_files_are_handed_over_first(self):
        system = StandInSystem(files=["relay.db", "relay.db-wal"])
        relay.drop_privileges("/data", "", system)
        self.assertEqual(system.calls[:3], [("chown", "/data", 65534, 65534),
                                            ("chown", os.path.join("/data", "relay.db"), 65534, 65534),
                                            ("chown", os.path.join("/data", "relay.db-wal"), 65534, 65534)])

    def test_extra_groups_and_the_group_are_dropped_before_the_user(self):
        system = StandInSystem()
        relay.drop_privileges("/data", "", system)
        order = [c[0] for c in system.calls if c[0] != "chown"]
        self.assertEqual(order, ["setgroups", "setgid", "setuid"])
        self.assertIn(("setgroups", []), system.calls)

    def test_quietnet_run_as_chooses_the_user_and_group(self):
        system = StandInSystem()
        relay.drop_privileges("/data", "1000:1001", system)
        self.assertIn(("setgid", 1001), system.calls)
        self.assertEqual(system.euid, 1000)

    def test_an_unreadable_run_as_setting_falls_back_to_nobody_with_a_warning(self):
        system = StandInSystem()
        note = relay.drop_privileges("/data", "lewis", system)
        self.assertEqual(system.euid, 65534)
        self.assertIn("Warning", note)

    def test_an_ordinary_user_changes_nothing(self):
        system = StandInSystem(euid=501)
        self.assertIsNone(relay.drop_privileges("/data", "", system))
        self.assertEqual(system.calls, [])

    def test_if_the_folder_cannot_be_handed_over_it_stays_root_and_says_so(self):
        system = StandInSystem(chown_fails=True)
        note = relay.drop_privileges("/data", "", system)
        self.assertEqual(system.euid, 0)
        self.assertIn("still running as root", note)

    def test_a_link_in_the_data_folder_is_not_followed_when_handing_it_over(self):
        system = StandInSystem(files=["relay.db"], links=["relay.db-wal"])
        relay.drop_privileges("/data", "", system)
        handed = [c[1] for c in system.calls if c[0] == "chown"]
        self.assertEqual(handed, ["/data", os.path.join("/data", "relay.db")])
        self.assertNotIn("followed links", [c[0] for c in system.calls])

    def test_only_the_relays_own_files_are_handed_over(self):
        system = StandInSystem(files=["relay.db", "passwd"])
        relay.drop_privileges("/data", "", system)
        self.assertNotIn(("chown", os.path.join("/data", "passwd"), 65534, 65534), system.calls)

    def test_a_refused_change_of_group_stops_the_relay_with_a_plain_message(self):
        system = StandInSystem(fail_on="setgid")
        with self.assertRaises(SystemExit) as caught:
            relay.drop_privileges("/data", "", system)
        self.assertIn("could not stop running as root", str(caught.exception))
        self.assertIn("QUIETNET_RUN_AS", str(caught.exception))

    def test_a_user_number_too_big_for_the_system_is_not_accepted(self):
        self.assertIsNone(relay.run_as_ids("99999999999:1"))
        self.assertIsNone(relay.run_as_ids("1:4294967295"))
        self.assertEqual(relay.run_as_ids("4294967294:1"), (4294967294, 1))

    def test_it_refuses_to_carry_on_if_root_could_not_be_given_up(self):
        system = StandInSystem()
        system.setuid = lambda uid: None            # pretends to work but changes nothing
        with self.assertRaises(SystemExit):
            relay.drop_privileges("/data", "", system)


class NoEmoji(unittest.TestCase):
    """The owner does not want emoji anywhere in the app's pages."""

    EMOJI = re.compile("[\U0001F000-\U0001FAFF☀-➿⬀-⯿️]")

    def test_the_relay_pages_carry_no_emoji(self):
        """The relay's own page template, and the relay program as a whole, hold no emoji."""
        with open(relay.__file__, encoding="utf-8") as f:
            source = f.read()
        self.assertEqual(self.EMOJI.findall(relay.PAGE), [])
        self.assertEqual(self.EMOJI.findall(source), [])

    def test_the_dashboard_carries_no_emoji(self):
        """The dashboard page holds no emoji."""
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "static", "index.html"), encoding="utf-8") as f:
            self.assertEqual(self.EMOJI.findall(f.read()), [])


if __name__ == "__main__":
    unittest.main()
