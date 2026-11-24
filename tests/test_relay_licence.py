"""Checks for licences on the relay (cloud/relay.py): working out a licence's state, the off switch
and its log, the legacy licences given on the first start, the gates on remote access, adding and
pairing Pis, seats and install ids, the licence in poll answers, the two rescue calls, and the
owner's command line.

Run with:  python3 -m unittest discover tests

Standard library only. It reuses the relay test helpers in test_relay.py: the relay runs on a
spare port on this computer with a throwaway data folder, and pretend Pis answer its calls.
Nothing leaves this machine, and no real user ids are ever changed.
"""
import calendar
import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_relay import PASSWORD, Browser, RelayCase, StandInSystem, relay  # noqa: E402

JAN4 = calendar.timegm((2027, 1, 4, 12, 0, 0))      # 4 January 2027, midday UTC
NOW = calendar.timegm((2026, 12, 1, 12, 0, 0))      # a fixed "now" for the state tests
DAY = 86400
INSTALL = "0123456789abcdef0123456789abcdef"


def row(state="active", period_end=0, grace_until=0, cancel=0, seats=2, plan="owner"):
    """A stored licence as licence_row() returns it, for the state tests."""
    return {"id": "L-ABC123", "user_id": 1, "state": state, "plan": plan, "seats": seats,
            "period_end": period_end, "grace_until": grace_until, "cancel_at_period_end": cancel,
            "reason": "", "created": 0, "updated": 0}


# ------------------------------------------------------------------ working out the state

class LicenceState(unittest.TestCase):
    def test_an_account_with_no_licence_is_state_none_and_allowed_nothing(self):
        info = relay.licence_state(None, NOW)
        self.assertEqual((info["state"], info["remote"], info["updates"], info["pair"]), ("none", False, False, False))

    def test_an_active_licence_allows_remote_access_updates_and_pairing(self):
        info = relay.licence_state(row(period_end=NOW + 30 * DAY), NOW)
        self.assertEqual((info["state"], info["remote"], info["updates"], info["pair"]), ("active", True, True, True))

    def test_an_active_licence_with_no_end_date_never_expires(self):
        self.assertEqual(relay.licence_state(row(period_end=0), NOW + 3650 * DAY)["state"], "active")

    def test_an_active_licence_still_works_up_to_three_days_after_its_end(self):
        info = relay.licence_state(row(period_end=NOW - 3 * DAY + 60), NOW)
        self.assertEqual((info["state"], info["remote"]), ("active", True))

    def test_an_active_licence_three_days_past_its_end_is_expired(self):
        info = relay.licence_state(row(period_end=NOW - 3 * DAY), NOW)
        self.assertEqual((info["state"], info["remote"], info["pair"]), ("expired", False, False))

    def test_a_trial_allows_everything_before_its_end(self):
        info = relay.licence_state(row(state="trial", period_end=NOW + DAY), NOW)
        self.assertEqual((info["state"], info["remote"], info["pair"]), ("trial", True, True))

    def test_a_trial_three_days_past_its_end_is_expired(self):
        self.assertEqual(relay.licence_state(row(state="trial", period_end=NOW - 4 * DAY), NOW)["state"], "expired")

    def test_an_active_licence_set_to_end_shows_as_cancelling_and_still_works(self):
        info = relay.licence_state(row(period_end=NOW + DAY, cancel=1), NOW)
        self.assertEqual((info["state"], info["remote"], info["pair"]), ("cancelling", True, True))

    def test_a_cancelling_licence_is_expired_from_its_end_date_itself(self):
        self.assertEqual(relay.licence_state(row(period_end=NOW - 60, cancel=1), NOW)["state"], "expired")

    def test_past_due_keeps_remote_access_and_updates_but_not_pairing(self):
        info = relay.licence_state(row(state="past_due", period_end=NOW - DAY, grace_until=NOW + DAY), NOW)
        self.assertEqual((info["state"], info["remote"], info["updates"], info["pair"]), ("past_due", True, True, False))

    def test_past_due_is_expired_once_its_grace_date_passes(self):
        info = relay.licence_state(row(state="past_due", period_end=NOW - 20 * DAY, grace_until=NOW - 1), NOW)
        self.assertEqual((info["state"], info["remote"]), ("expired", False))

    def test_past_due_without_a_grace_date_lasts_fourteen_days_from_the_period_end(self):
        within = relay.licence_state(row(state="past_due", period_end=NOW - 13 * DAY), NOW)
        after = relay.licence_state(row(state="past_due", period_end=NOW - 14 * DAY), NOW)
        self.assertEqual((within["state"], within["grace_until"]), ("past_due", NOW + DAY))
        self.assertEqual(after["state"], "expired")

    def test_a_grace_date_is_given_only_while_past_due(self):
        self.assertEqual(relay.licence_state(row(period_end=NOW + DAY, grace_until=NOW + 5 * DAY), NOW)["grace_until"], 0)

    def test_an_expired_licence_allows_nothing(self):
        info = relay.licence_state(row(state="expired", period_end=NOW + 30 * DAY), NOW)
        self.assertEqual((info["state"], info["remote"], info["updates"], info["pair"]), ("expired", False, False, False))

    def test_a_revoked_licence_allows_nothing_whatever_its_dates(self):
        info = relay.licence_state(row(state="revoked", period_end=0), NOW)
        self.assertEqual((info["state"], info["remote"], info["updates"], info["pair"]), ("revoked", False, False, False))

    def test_a_stored_state_the_relay_does_not_know_counts_as_none(self):
        info = relay.licence_state(row(state="platinum"), NOW)
        self.assertEqual((info["state"], info["remote"]), ("none", False))

    def test_the_licence_carries_its_seats_and_end_date(self):
        info = relay.licence_state(row(seats=5, period_end=JAN4), NOW)
        self.assertEqual((info["seats"], info["until"], info["id"]), (5, JAN4, "L-ABC123"))


class Settings(unittest.TestCase):
    def test_the_licence_gate_is_off_unless_set_to_on(self):
        self.assertEqual(relay.read_gate_setting({}), "off")
        for value in ("", "off", "yes", "true", "1", "onn"):
            self.assertNotEqual(relay.read_gate_setting({"QUIETNET_LICENCE_GATE": value}), "on", value)
        self.assertEqual(relay.read_gate_setting({"QUIETNET_LICENCE_GATE": " On "}), "on")

    def test_only_a_plain_version_number_is_taken_as_the_latest(self):
        self.assertEqual(relay.read_latest_setting({"QUIETNET_LATEST": "0.6"}), "0.6")
        self.assertEqual(relay.read_latest_setting({"QUIETNET_LATEST": "0.6.1"}), "0.6.1")
        for value in ("", "v0.6", "0.6 beta", "0.6.1.2", "<b>0.7</b>", "1"):
            self.assertEqual(relay.read_latest_setting({"QUIETNET_LATEST": value}), "", value)

    def test_a_latest_setting_that_is_not_a_version_is_warned_about(self):
        self.assertIn("QUIETNET_LATEST", relay.latest_warning({"QUIETNET_LATEST": "soon"}))
        self.assertIsNone(relay.latest_warning({"QUIETNET_LATEST": "0.6"}))
        self.assertIsNone(relay.latest_warning({}))

    def test_the_start_up_log_says_whether_the_gate_is_on(self):
        with mock.patch.object(relay, "LICENCE_GATE", "off"):
            self.assertIn("Licence gate: off", relay.gate_status())
        with mock.patch.object(relay, "LICENCE_GATE", "on"):
            self.assertIn("Licence gate: on", relay.gate_status())

    def test_dates_are_written_out_in_full(self):
        self.assertEqual(relay.long_date(JAN4), "4 January 2027")


# ------------------------------------------------------------------ the legacy licences on first start

class FirstStart(unittest.TestCase):
    """Each test opens its own relay.db in a throwaway folder, then puts the shared one back."""

    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="quietnet-relay-licence-")
        keep = (relay.db, relay.SECRET, relay.DATA)

        def put_back():
            """Close this test's database and restore the shared one."""
            if relay.db is not keep[0]:
                relay.db.close()
            relay.db, relay.SECRET, relay.DATA = keep
        self.addCleanup(put_back)
        relay.DATA = self.folder

    def old_database(self, accounts):
        """A relay.db as the relay before licences left it: `accounts` maps email to its number of Pis."""
        old = sqlite3.connect(os.path.join(self.folder, "relay.db"))
        old.executescript("""
            CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL, session_gen INTEGER DEFAULT 0);
            CREATE TABLE pis(id TEXT PRIMARY KEY, user_id INTEGER, name TEXT, token TEXT,
                code TEXT, paired INTEGER, created REAL, last_seen REAL, code_ts REAL DEFAULT 0);
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        """)
        for n, (email, pis) in enumerate(sorted(accounts.items()), 1):
            old.execute("INSERT INTO users(id,email,pw,created) VALUES(?,?,?,1.0)", (n, email, "x"))
            for i in range(pis):
                old.execute("INSERT INTO pis VALUES(?,?,?,?,?,1,1.0,2.0,0)", ("p%d-%d" % (n, i), n, "Pi", "", ""))
        old.commit()
        old.close()

    def licences(self):
        """Every licence as (email, state, plan, seats, period_end)."""
        return relay.sql("SELECT u.email, l.state, l.plan, l.seats, l.period_end FROM licences l "
                         "JOIN users u ON u.id = l.user_id ORDER BY u.email")

    def test_every_existing_account_gets_an_active_legacy_licence_for_ninety_days(self):
        self.old_database({"a@example.com": 1, "b@example.com": 0})
        before = time.time()
        relay.init_db()
        got = self.licences()
        self.assertEqual([r[:3] for r in got], [("a@example.com", "active", "legacy"), ("b@example.com", "active", "legacy")])
        for r in got:
            self.assertAlmostEqual(r[4], before + 90 * DAY, delta=60)

    def test_legacy_seats_are_the_accounts_pi_count_but_at_least_two(self):
        self.old_database({"a@example.com": 1, "b@example.com": 3})
        relay.init_db()
        self.assertEqual([(r[0], r[3]) for r in self.licences()], [("a@example.com", 2), ("b@example.com", 3)])

    def test_each_legacy_licence_is_written_to_the_licence_log(self):
        self.old_database({"a@example.com": 0})
        relay.init_db()
        self.assertEqual(len(relay.sql("SELECT what FROM licence_log WHERE what LIKE 'Legacy licence%'")), 1)

    def test_restarting_never_grants_or_extends_the_legacy_licences_again(self):
        self.old_database({"a@example.com": 0})
        relay.init_db()
        relay.sql("UPDATE licences SET period_end=123, state='expired'", commit=True)
        relay.db.close()
        relay.init_db()
        self.assertEqual([r[1:] for r in self.licences()], [("expired", "legacy", 2, 123)])
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM licences", one=True)[0], 1)

    def test_an_account_made_after_the_first_start_has_no_licence(self):
        self.old_database({"a@example.com": 0})
        relay.init_db()
        relay.sql("INSERT INTO users(email,pw,created) VALUES('new@example.com','x',1.0)", commit=True)
        relay.db.close()
        relay.init_db()
        uid = relay.sql("SELECT id FROM users WHERE email='new@example.com'", one=True)[0]
        self.assertIsNone(relay.licence_row(uid))
        self.assertEqual(relay.account_licence(uid)["state"], "none")

    def test_a_brand_new_relay_grants_nothing(self):
        relay.init_db()
        self.assertEqual(self.licences(), [])

    def test_an_older_database_gains_the_install_id_and_agent_columns(self):
        self.old_database({"a@example.com": 1})
        relay.init_db()
        self.assertEqual(relay.sql("SELECT install_id, agent FROM pis"), [("", 1)])


# ------------------------------------------------------------------ shared helpers for the live tests

class LicenceCase(RelayCase):
    """A RelayCase with helpers for licences, the gate and Pis that send the agent header. RelayCase
    already switches the gate off and clears QUIETNET_LATEST for each test."""

    def gate(self, on=True):
        """Switch the licence gate on (or off) for the rest of the test."""
        relay.LICENCE_GATE = "on" if on else "off"

    def uid(self, email="lewis@example.com"):
        """The account number for an email."""
        return relay.sql("SELECT id FROM users WHERE email=?", (email,), one=True)[0]

    def licence(self, email="lewis@example.com", state="active", seats=2, period_end=0, grace_until=0,
                plan="owner", cancel=0):
        """Give an account a licence straight in the database (replacing any it had)."""
        uid = self.uid(email)
        relay.sql("DELETE FROM licences WHERE user_id=?", (uid,), commit=True)
        relay.sql("INSERT INTO licences(id,user_id,state,plan,seats,period_end,grace_until,cancel_at_period_end,"
                  "created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  ("L-%06X" % uid, uid, state, plan, seats, period_end, grace_until, cancel, time.time(), time.time()),
                  commit=True)

    def pair(self, browser, name="Home Pi", install=None):
        """Create a Pi on the website and send its code as a Pi would. Returns (status, answer, pi id)."""
        browser.post("/pis/new", form={"name": name})
        pid, code = relay.sql("SELECT id, code FROM pis WHERE name=? ORDER BY created DESC", (name,), one=True)
        data = {"code": code}
        if install is not None:
            data["install"] = install
        status, text, _ = Browser(self.port).post("/agent/pair", data=data)
        return status, json.loads(text), pid

    def poll(self, token, agent=None, wait=0.1):
        """One poll as a Pi makes it, with the relay's wait shortened. Returns (status, answer)."""
        self.limit("POLL_TIMEOUT", wait)
        headers = {"X-QuietNet-Token": token}
        if agent is not None:
            headers["X-QuietNet-Agent"] = agent
        status, text, _ = Browser(self.port).get("/agent/poll", headers=headers)
        return status, json.loads(text) if text.startswith("{") else text

    def pi_answers(self, token, agent="2", status=200, body='{"ok": true}'):
        """Answer exactly one relayed call, as the Pi's agent would, sending X-QuietNet-Agent.
        Returns the thread and the call it saw."""
        seen = {}

        def work():
            """Poll once, remember the call, and answer it."""
            pi = Browser(self.port)
            headers = {"X-QuietNet-Token": token}
            if agent:
                headers["X-QuietNet-Agent"] = agent
            _, text, _ = pi.get("/agent/poll", headers=headers)
            seen.update(json.loads(text))
            if seen.get("id"):
                pi.post("/agent/respond", data={"id": seen["id"], "status": status, "body": body},
                        headers={"X-QuietNet-Token": token, "X-QuietNet-Call": str(seen["id"])})

        t = threading.Thread(target=work, daemon=True)
        t.start()
        return t, seen

    def log_lines(self, email="lewis@example.com"):
        """The licence log for an account, oldest first."""
        return [r[0] for r in relay.sql("SELECT what FROM licence_log WHERE user_id=? ORDER BY at", (self.uid(email),))]

    def bridge_unused(self):
        """A stand-in for the bridge's call, to check that a request never reached the Pi: use it as
        `with self.bridge_unused() as call:`, then `call.assert_not_called()`."""
        return mock.patch.object(relay.bridge, "call", return_value=None)


# ------------------------------------------------------------------ the off switch and its log

class GateSwitch(LicenceCase):
    def test_with_the_gate_off_an_unlicensed_account_still_opens_its_dashboard(self):
        b = self.signed_in()
        pid, _ = self.paired_pi(b)
        status, text, _ = b.get("/pi/%s/" % pid)
        self.assertEqual(status, 200)
        self.assertIn("QN_API_BASE", text)
        self.assertNotIn("Remote access is paused", text)

    def test_with_the_gate_off_an_unlicensed_api_call_still_reaches_the_pi(self):
        b = self.signed_in()
        pid, token = self.paired_pi(b)
        t, seen = self.pi_answers(token)
        status, _, _ = b.get("/pi/%s/api/status" % pid, headers={"X-QuietNet": "1"})
        t.join(5)
        self.assertEqual((status, seen.get("path")), (200, "/api/status"))

    def test_with_the_gate_off_a_would_be_refusal_is_logged_in_both_places(self):
        b = self.signed_in()
        pid, _ = self.paired_pi(b)
        b.get("/pi/%s/" % pid)
        remote = [line for line in self.log_lines() if "remote access" in line]
        self.assertEqual(len(remote), 1)
        self.assertIn("Would have refused remote access to a Pi: licence state none", remote[0])
        self.assertTrue(any("Would have refused remote access" in line for line in self.said))

    def test_the_gate_notes_a_refusal_at_most_once_an_hour_for_each_account_and_gate(self):
        b = self.signed_in()
        pid, _ = self.paired_pi(b)
        for _ in range(5):
            b.get("/pi/%s/" % pid)
            b.get("/pi/%s/api/status" % pid)        # no dashboard header: refused later, but the gate ran first
        self.assertEqual(len([line for line in self.log_lines() if "remote access" in line]), 1)
        self.assertEqual(len([line for line in self.said if "remote access" in line]), 1)

    def test_different_gates_are_noted_separately(self):
        b = self.signed_in()
        pid, _ = self.paired_pi(b)                  # notes "adding a Pi" and "pairing a Pi"
        b.get("/pi/%s/" % pid)                      # notes "remote access"
        lines = self.log_lines()
        for words in ("adding a Pi", "pairing a Pi", "remote access to a Pi"):
            self.assertEqual(len([line for line in lines if words in line]), 1, words)

    def test_a_refusal_is_noted_again_after_an_hour(self):
        uid = self.make_account()
        info = relay.account_licence(uid)
        relay.licence_gate(uid, "remote", False, info, now=1000.0)
        relay.licence_gate(uid, "remote", False, info, now=1000.0 + 3599)
        relay.licence_gate(uid, "remote", False, info, now=1000.0 + 3600)
        self.assertEqual(len(self.log_lines()), 2)

    def test_the_licence_log_keeps_only_the_newest_lines_an_account_caused(self):
        self.limit("LICENCE_LOG_KEEP", 3)
        uid = self.make_account()
        for n in range(6):
            relay.log_licence(uid, "", "Rescue %d." % n, now=1000.0 + n)
        self.assertEqual(self.log_lines(), ["Rescue 3.", "Rescue 4.", "Rescue 5."])

    def test_the_licence_log_never_drops_the_owners_own_lines(self):
        self.limit("LICENCE_LOG_KEEP", 2)
        uid = self.make_account()
        relay.sql("INSERT INTO licence_log(licence_id,user_id,at,what) VALUES('',?,1.0,'Owner granted the licence.')",
                  (uid,), commit=True)
        relay.sql("INSERT INTO licence_log(licence_id,user_id,at,what) VALUES('',?,2.0,'Legacy licence given.')",
                  (uid,), commit=True)
        for n in range(5):
            relay.log_licence(uid, "", "Rescue %d." % n, now=1000.0 + n)
        self.assertEqual(self.log_lines(), ["Owner granted the licence.", "Legacy licence given.",
                                            "Rescue 3.", "Rescue 4."])

    def test_with_the_gate_on_refusals_are_noted_too(self):
        self.gate(on=True)
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        self.assertIn("Refused adding a Pi: licence state none.", self.log_lines())

    def test_an_allowed_request_notes_nothing(self):
        b = self.signed_in()
        self.licence()
        pid, _ = self.paired_pi(b)
        b.get("/pi/%s/" % pid)
        self.assertEqual(self.log_lines(), [])


# ------------------------------------------------------------------ remote access (pi_request)

class RemoteGate(LicenceCase):
    def setUp(self):
        super().setUp()
        self.gate(on=True)
        self.b = self.signed_in()
        self.licence()
        self.pid, self.token = self.paired_pi(self.b)

    def test_an_unlicensed_dashboard_shows_the_paused_page(self):
        relay.sql("DELETE FROM licences", commit=True)
        status, text, _ = self.b.get("/pi/%s/" % self.pid)
        self.assertEqual(status, 200)
        self.assertIn("Remote access is paused", text)
        self.assertNotIn("QN_API_BASE", text)

    def test_an_expired_licence_shows_the_paused_page_with_its_end_date(self):
        self.licence(state="expired", period_end=JAN4)
        text = self.b.get("/pi/%s/" % self.pid)[1]
        self.assertIn("Your QuietNet licence ended on 4 January 2027. Your Pi is still filtering and blocking at "
                      "home as normal.", text)

    def test_a_paused_api_call_gets_402_with_a_plain_sentence(self):
        self.licence(state="expired", period_end=JAN4)
        status, text, r = self.b.get("/pi/%s/api/status" % self.pid, headers={"X-QuietNet": "1"})
        self.assertEqual(status, 402)
        self.assertEqual(r.getheader("Content-Type"), "application/json")
        self.assertEqual(json.loads(text), {"error": "Remote access is paused because the licence ended on "
                                                     "4 January 2027. Your Pi is still blocking at home."})

    def test_a_revoked_licence_says_remote_access_was_switched_off(self):
        self.licence(state="revoked")
        text = self.b.get("/pi/%s/api/status" % self.pid, headers={"X-QuietNet": "1"})[1]
        self.assertIn("switched off for this licence", json.loads(text)["error"])

    def test_a_paused_call_never_reaches_the_pi(self):
        self.licence(state="expired")
        with self.bridge_unused() as call:
            status = self.b.post("/pi/%s/api/kill" % self.pid, data={"on": True}, headers={"X-QuietNet": "1"})[0]
        self.assertEqual(status, 402)
        call.assert_not_called()

    def test_another_accounts_pi_is_still_not_found_whatever_the_licences(self):
        relay.sql("DELETE FROM licences", commit=True)
        stranger = self.signed_in("hannah@example.com")
        status, text, _ = stranger.get("/pi/%s/api/status" % self.pid, headers={"X-QuietNet": "1"})
        self.assertEqual(status, 404)
        status, text, r = stranger.get("/pi/%s/" % self.pid)
        self.assertNotIn("Remote access is paused", text)
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_a_licensed_account_reaches_its_pi_with_the_gate_on(self):
        t, seen = self.pi_answers(self.token)
        status, _, _ = self.b.get("/pi/%s/api/status" % self.pid, headers={"X-QuietNet": "1"})
        t.join(5)
        self.assertEqual((status, seen.get("path")), (200, "/api/status"))

    def test_a_past_due_licence_still_reaches_its_pi(self):
        self.licence(state="past_due", period_end=time.time() - DAY, grace_until=time.time() + DAY)
        status, text, _ = self.b.get("/pi/%s/" % self.pid)
        self.assertIn("QN_API_BASE", text)

    def test_the_paused_page_escapes_the_pi_name(self):
        relay.sql("UPDATE pis SET name='<b>x</b>' WHERE id=?", (self.pid,), commit=True)
        self.licence(state="expired")
        text = self.b.get("/pi/%s/" % self.pid)[1]
        self.assertNotIn("<b>x</b>", text)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", text)

    def test_the_paused_page_offers_the_two_rescue_buttons_as_forms(self):
        self.licence(state="revoked")
        text = self.b.get("/pi/%s/" % self.pid)[1]
        self.assertEqual(text.count('action="/pi/%s/rescue"' % self.pid), 2)
        self.assertIn('name="what" value="internet-on"', text)
        self.assertIn('name="what" value="pause-hour"', text)
        self.assertIn("Turn the internet back on for every device", text)
        self.assertIn("Pause blocking for an hour", text)

    def test_the_paused_page_and_402_carry_the_protective_headers(self):
        self.licence(state="expired")
        for r in (self.b.get("/pi/%s/" % self.pid)[2],
                  self.b.get("/pi/%s/api/status" % self.pid, headers={"X-QuietNet": "1"})[2]):
            self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
            self.assertEqual(r.getheader("Referrer-Policy"), "no-referrer")

    def test_no_answer_a_pi_or_its_dashboard_sees_is_ever_401_for_a_licence_reason(self):
        self.licence(state="revoked")
        relay.sql("INSERT INTO pis(id,user_id,name,token,code,paired,created,last_seen,code_ts) "
                  "VALUES('second',?,'Second','','AAAA-BBBB',0,?,0,?)", (self.uid(), time.time(), time.time()),
                  commit=True)
        statuses = [self.poll(self.token)[0],
                    self.b.get("/pi/%s/" % self.pid)[0],
                    self.b.get("/pi/%s/api/status" % self.pid, headers={"X-QuietNet": "1"})[0],
                    Browser(self.port).post("/agent/pair", data={"code": "AAAA-BBBB"})[0]]
        self.assertEqual(statuses, [200, 200, 402, 403])


# ------------------------------------------------------------------ the home page

class HomePage(LicenceCase):
    def test_the_licence_card_shows_the_states_sentence_and_the_seats_in_use(self):
        b = self.signed_in()
        end = time.time() + 40 * DAY
        self.licence(plan="gift", seats=3, period_end=end)
        self.paired_pi(b)
        text = b.get("/")[1]
        self.assertIn("Licence active until %s." % relay.long_date(end), text)
        self.assertIn("Pis: 1 of 3", text)

    def test_an_account_with_no_licence_is_told_so_on_its_licence_card(self):
        text = self.signed_in().get("/")[1]
        self.assertIn("This account has no QuietNet licence yet.", text)

    def test_the_licence_card_shows_no_seat_limit_without_a_licence(self):
        text = self.signed_in().get("/")[1]
        self.assertIn("Pis: 0</p>", text)
        self.assertNotIn("Pis: 0 of", text)

    def test_the_licence_card_wording_follows_each_state(self):
        later = time.time() + 20 * DAY
        expected = {
            ("active", 0, 0, "owner"): "Licence active, with no end date.",
            ("active", later, 0, "home-monthly"): "Licence active. Renews on %s." % relay.long_date(later),
            ("active", later, 1, "home-monthly"): "Your licence is cancelled. Remote access works until %s." % relay.long_date(later),
            ("trial", later, 0, ""): "Free trial: remote access works until %s." % relay.long_date(later),
            ("past_due", time.time() - DAY, 0, "home-monthly"): "Your last payment didn&#x27;t go through.",
            ("expired", JAN4, 0, "gift"): "Remote access is paused because the licence ended on 4 January 2027.",
            ("revoked", 0, 0, "gift"): "Remote access has been switched off for this licence.",
        }
        b = self.signed_in()
        for (state, end, cancel, plan), words in expected.items():
            self.licence(state=state, period_end=end, cancel=cancel, plan=plan)
            self.assertIn(words, b.get("/")[1], state)

    def test_a_paused_pi_says_so_only_while_the_gate_is_on(self):
        b = self.signed_in()
        self.paired_pi(b)
        self.licence(state="expired")
        self.assertNotIn("Remote access paused", b.get("/")[1])
        self.gate(on=True)
        text = b.get("/")[1]
        self.assertIn("Remote access paused", text)
        self.assertNotIn(">Online<", text)

    def test_with_the_gate_on_and_no_licence_the_add_form_is_replaced(self):
        self.gate(on=True)
        text = self.signed_in().get("/")[1]
        self.assertIn("Adding a Pi needs a current licence.", text)
        self.assertNotIn('action="/pis/new"', text)

    def test_with_every_seat_taken_the_add_form_gives_way_to_the_seats_sentence(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(seats=2)
        self.paired_pi(b, "One")
        self.paired_pi(b, "Two")
        text = b.get("/")[1]
        self.assertIn("Your licence covers 2 Pis and both are in use. Remove one to add another.", text)
        self.assertNotIn('action="/pis/new"', text)

    def test_with_the_gate_off_the_add_form_is_always_shown(self):
        text = self.signed_in().get("/")[1]
        self.assertIn('action="/pis/new"', text)

    def waiting_pi(self, name="Waiting", age=16 * 60):
        """Add a Pi waiting to be paired straight to the database, its code `age` seconds old.
        Returns (id, code, code time)."""
        pid, code, ts = "w" + name.lower(), relay.new_pair_code(), time.time() - age
        relay.sql("INSERT INTO pis(id,user_id,name,token,code,paired,created,last_seen,code_ts) "
                  "VALUES(?,?,?,'',?,0,?,0,?)", (pid, self.uid(), name, code, time.time(), ts), commit=True)
        return pid, code, ts

    def test_a_seat_held_by_a_waiting_pi_is_named_as_waiting_not_in_use(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(seats=2)
        self.paired_pi(b, "One")
        self.waiting_pi()
        text = b.get("/")[1]
        self.assertIn("Your licence covers 2 Pis: 1 is paired and 1 is waiting to be paired. Remove one to add "
                      "another.", text)
        self.assertNotIn("both are in use", text)
        self.assertIn("Pis: 1 of 2 (1 waiting to be paired)", text)

    def test_adding_a_pi_gives_the_same_waiting_sentence_as_the_home_page(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(seats=2)
        self.paired_pi(b, "One")
        self.waiting_pi(age=0)
        status, text, _ = b.post("/pis/new", form={"name": "Three"})
        self.assertEqual(status, 403)
        self.assertIn("1 is paired and 1 is waiting to be paired.", text)

    def check_waiting_pi_shows(self, words, b):
        """Load the home page and check a waiting Pi with an old code shows `words` in place of a code,
        and that its code was not renewed."""
        pid, code, ts = self.waiting_pi()
        text = b.get("/")[1]
        self.assertIn(words, text)
        self.assertIn("Waiting to be paired", text)
        self.assertNotIn('class="bigcode"', text)
        self.assertNotIn("install.sh", text)
        self.assertEqual(relay.sql("SELECT code, code_ts FROM pis WHERE id=?", (pid,), one=True), (code, ts))

    def test_with_the_gate_on_and_no_current_licence_a_waiting_pi_shows_why_instead_of_a_code(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(state="revoked")
        self.check_waiting_pi_shows("Adding a Pi needs a current licence.", b)

    def test_with_the_gate_on_and_every_seat_paired_a_waiting_pi_shows_why_instead_of_a_code(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(seats=1)
        self.paired_pi(b, "One")
        self.check_waiting_pi_shows("Your licence covers 1 Pi and it is in use. Remove one to pair this one.", b)

    def test_with_the_gate_off_a_waiting_pi_always_gets_a_fresh_code(self):
        b = self.signed_in()
        self.licence(state="revoked")
        pid, code, _ = self.waiting_pi()
        text = b.get("/")[1]
        self.assertIn('class="bigcode"', text)
        self.assertIn("install.sh", text)
        self.assertNotEqual(relay.sql("SELECT code FROM pis WHERE id=?", (pid,), one=True)[0], code)

    def test_a_licence_ending_within_seven_days_is_warned_about(self):
        b = self.signed_in()
        end = time.time() + 3 * DAY
        self.licence(plan="gift", period_end=end)
        self.assertIn("Your QuietNet licence ends on %s. Filtering at home carries on; remote access and updates "
                      "stop unless it&#x27;s renewed." % relay.long_date(end), b.get("/")[1])

    def test_a_licence_ending_later_than_seven_days_is_not_warned_about(self):
        b = self.signed_in()
        self.licence(plan="gift", period_end=time.time() + 30 * DAY)
        self.assertNotIn("Your QuietNet licence ends on", b.get("/")[1])

    def test_a_cancelling_licence_is_warned_about_in_its_last_week(self):
        b = self.signed_in()
        self.licence(plan="home-monthly", period_end=time.time() + 3 * DAY, cancel=1)
        self.assertIn("Your QuietNet licence ends on", b.get("/")[1])

    def test_a_licence_that_renews_by_itself_is_not_warned_about(self):
        b = self.signed_in()
        self.licence(plan="home-monthly", period_end=time.time() + 3 * DAY)
        self.assertNotIn("Your QuietNet licence ends on", b.get("/")[1])


# ------------------------------------------------------------------ adding Pis and seats

class AddingPis(LicenceCase):
    def test_adding_a_pi_without_a_licence_is_refused_with_the_gate_on(self):
        self.gate(on=True)
        b = self.signed_in()
        status, text, _ = b.post("/pis/new", form={"name": "Home Pi"})
        self.assertEqual(status, 403)
        self.assertIn("Adding a Pi needs a current licence.", text)
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis", one=True)[0], 0)

    def test_adding_a_pi_while_past_due_is_refused_with_the_gate_on(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(state="past_due", period_end=time.time() - DAY)
        self.assertEqual(b.post("/pis/new", form={"name": "Home Pi"})[0], 403)

    def test_paired_and_waiting_pis_together_fill_the_seats(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(seats=2)
        self.paired_pi(b, "One")
        b.post("/pis/new", form={"name": "Waiting"})
        status, text, _ = b.post("/pis/new", form={"name": "Three"})
        self.assertEqual(status, 403)
        self.assertIn("Your licence covers 2 Pis: 1 is paired and 1 is waiting to be paired.", text)

    def test_a_waiting_pi_whose_code_has_expired_does_not_take_a_seat(self):
        self.gate(on=True)
        b = self.signed_in()
        self.licence(seats=1)
        b.post("/pis/new", form={"name": "Waiting"})
        relay.sql("UPDATE pis SET code_ts=?", (time.time() - 16 * 60,), commit=True)
        self.assertEqual(b.post("/pis/new", form={"name": "Another"})[0], 303)

    def test_with_the_gate_off_adding_without_a_licence_is_let_through_and_noted(self):
        b = self.signed_in()
        self.assertEqual(b.post("/pis/new", form={"name": "Home Pi"})[0], 303)
        self.assertTrue(any("Would have refused adding a Pi" in line for line in self.log_lines()))


# ------------------------------------------------------------------ pairing, seats and install ids

class PairingGate(LicenceCase):
    def test_pairing_without_a_licence_is_refused_with_403_and_the_state(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})       # made while the gate was off
        self.gate(on=True)
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        status, text, _ = Browser(self.port).post("/agent/pair", data={"code": code})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(text), {"error": "Remote access needs a QuietNet licence. Your Pi is still "
                                                     "filtering at home. Visit q3n.net to renew.", "licence": "none"})

    def test_pairing_beyond_the_seats_is_refused_with_403(self):
        b = self.signed_in()
        self.licence(seats=1)
        self.paired_pi(b, "One")
        b.post("/pis/new", form={"name": "Two"})             # let through: the gate is off
        self.gate(on=True)
        code = relay.sql("SELECT code FROM pis WHERE name='Two'", one=True)[0]
        status, text, _ = Browser(self.port).post("/agent/pair", data={"code": code})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(text), {"error": "Your licence covers 1 Pi and it is in use. Remove one at "
                                                     "q3n.net, then pair again.", "licence": "active"})

    def live_codes(self, n):
        """Add `n` Pis waiting to be paired, each with a code still in date, straight to the database
        (as several old entries renewed on the home page could leave them). Returns the codes."""
        codes = []
        for i in range(n):
            code = relay.new_pair_code()
            relay.sql("INSERT INTO pis(id,user_id,name,token,code,paired,created,last_seen,code_ts) "
                      "VALUES(?,?,?,'',?,0,?,0,?)", ("live%d" % i, self.uid(), "Pi %d" % i, code, time.time(),
                                                     time.time()), commit=True)
            codes.append(code)
        return codes

    def pair_at_once(self, codes):
        """Send one pairing request per code, all released at the same moment. Returns the statuses."""
        start, statuses = threading.Barrier(len(codes)), []

        def send(code):
            """Wait for the others, then pair with `code`."""
            pi = Browser(self.port)
            start.wait(5)
            statuses.append(pi.post("/agent/pair", data={"code": code})[0])

        threads = [threading.Thread(target=send, args=(code,), daemon=True) for code in codes]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        return sorted(statuses)

    def test_pairing_several_codes_at_once_never_goes_over_the_seats(self):
        self.signed_in()
        self.licence(seats=2)
        self.gate(on=True)
        statuses = self.pair_at_once(self.live_codes(4))
        self.assertEqual(statuses, [200, 200, 403, 403])
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis WHERE paired=1", one=True)[0], 2)

    def test_one_code_sent_twice_at_once_pairs_only_once(self):
        self.signed_in()
        self.licence(seats=2)
        code = self.live_codes(1)[0]
        self.assertEqual(self.pair_at_once([code, code]), [200, 400])

    def test_two_seats_are_described_as_both_in_use(self):
        self.assertEqual(relay.seats_full(2, "Remove one at q3n.net, then pair again."),
                         "Your licence covers 2 Pis and both are in use. Remove one at q3n.net, then pair again.")

    def test_a_refused_pairing_leaves_the_code_to_work_once_the_licence_is_sorted(self):
        b = self.signed_in()
        b.post("/pis/new", form={"name": "Home Pi"})
        self.gate(on=True)
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        self.assertEqual(Browser(self.port).post("/agent/pair", data={"code": code})[0], 403)
        self.licence()
        self.assertEqual(Browser(self.port).post("/agent/pair", data={"code": code})[0], 200)

    def test_pairing_while_past_due_is_refused(self):
        b = self.signed_in()
        self.licence(state="past_due", period_end=time.time() - DAY)
        b.post("/pis/new", form={"name": "Home Pi"})
        self.gate(on=True)
        code = relay.sql("SELECT code FROM pis", one=True)[0]
        status, text, _ = Browser(self.port).post("/agent/pair", data={"code": code})
        self.assertEqual((status, json.loads(text)["licence"]), (403, "past_due"))

    def test_with_the_gate_off_pairing_without_a_licence_is_let_through_and_noted(self):
        status, answer, _ = self.pair(self.signed_in())
        self.assertEqual(status, 200)
        self.assertTrue(any("Would have refused pairing a Pi" in line for line in self.log_lines()))

    def test_the_install_id_is_stored_on_the_pi(self):
        status, _, pid = self.pair(self.signed_in(), install=INSTALL)
        self.assertEqual(status, 200)
        self.assertEqual(relay.sql("SELECT install_id FROM pis WHERE id=?", (pid,), one=True)[0], INSTALL)

    def test_an_install_id_that_is_not_32_lower_case_hex_is_ignored_and_the_pi_still_pairs(self):
        b = self.signed_in()
        for n, bad in enumerate((INSTALL.upper(), INSTALL[:31], INSTALL + "0", "x" * 32, 12345, ["a"])):
            status, _, pid = self.pair(b, "Pi %d" % n, install=bad)
            self.assertEqual(status, 200, bad)
            self.assertEqual(relay.sql("SELECT install_id FROM pis WHERE id=?", (pid,), one=True)[0], "", bad)

    def test_pairing_again_with_the_same_install_id_replaces_an_offline_entry(self):
        b = self.signed_in()
        _, _, first = self.pair(b, "Old", install=INSTALL)
        relay.sql("UPDATE pis SET last_seen=? WHERE id=?", (time.time() - 60, first), commit=True)
        status, _, second = self.pair(b, "New", install=INSTALL)
        self.assertEqual(status, 200)
        self.assertEqual(relay.sql("SELECT id FROM pis"), [(second,)])

    def test_the_replaced_entry_is_forgotten_by_the_bridge(self):
        b = self.signed_in()
        _, answer, first = self.pair(b, "Old", install=INSTALL)
        relay.sql("UPDATE pis SET last_seen=0 WHERE id=?", (first,), commit=True)
        relay.bridge._cond(first)
        self.pair(b, "New", install=INSTALL)
        self.assertNotIn(first, relay.bridge.cond)
        self.assertEqual(self.poll(answer["token"])[0], 401)      # the old entry's token is gone with it

    def test_pairing_again_with_the_same_install_id_reuses_its_seat(self):
        b = self.signed_in()
        self.licence(seats=1)
        _, _, first = self.pair(b, "Old", install=INSTALL)
        relay.sql("UPDATE pis SET last_seen=0 WHERE id=?", (first,), commit=True)
        b.post("/pis/new", form={"name": "New"})            # a code for the same Pi, made with the gate off
        self.gate(on=True)
        code = relay.sql("SELECT code FROM pis WHERE name='New'", one=True)[0]
        status, _, _ = Browser(self.port).post("/agent/pair", data={"code": code, "install": INSTALL})
        self.assertEqual(status, 200)

    def test_a_copied_sd_card_is_refused_while_the_first_pi_is_online(self):
        b = self.signed_in()
        _, _, first = self.pair(b, "Old", install=INSTALL)
        status, answer, second = self.pair(b, "Copy", install=INSTALL)
        self.assertEqual(status, 403)
        self.assertEqual(answer, {"error": "Another Pi with the same identity is online. This usually means the SD "
                                           "card was copied. On this Pi, run the installer with --new-identity, then "
                                           "pair again."})
        self.assertEqual(relay.sql("SELECT paired FROM pis WHERE id=?", (first,), one=True)[0], 1)
        self.assertEqual(relay.sql("SELECT paired FROM pis WHERE id=?", (second,), one=True)[0], 0)

    def test_the_same_install_id_on_another_account_replaces_nothing(self):
        _, _, first = self.pair(self.signed_in(), "Mine", install=INSTALL)
        relay.sql("UPDATE pis SET last_seen=0 WHERE id=?", (first,), commit=True)
        status, _, _ = self.pair(self.signed_in("hannah@example.com"), "Theirs", install=INSTALL)
        self.assertEqual(status, 200)
        self.assertEqual(relay.sql("SELECT paired FROM pis WHERE id=?", (first,), one=True)[0], 1)

    def test_a_pi_without_an_install_id_never_replaces_another(self):
        b = self.signed_in()
        _, _, first = self.pair(b, "Old")
        relay.sql("UPDATE pis SET last_seen=0 WHERE id=?", (first,), commit=True)
        self.pair(b, "New")
        self.assertEqual(relay.sql("SELECT COUNT(*) FROM pis WHERE paired=1", one=True)[0], 2)


# ------------------------------------------------------------------ poll answers

class PollAnswers(LicenceCase):
    def setUp(self):
        super().setUp()
        self.b = self.signed_in()
        self.pid, self.token = self.paired_pi(self.b)

    def test_an_idle_poll_answer_carries_the_licence_and_no_call(self):
        end = time.time() + 30 * DAY
        self.licence(seats=3, period_end=end)
        status, answer = self.poll(self.token)
        self.assertEqual(status, 200)
        self.assertNotIn("id", answer)
        lic = answer["licence"]
        self.assertEqual({k: lic[k] for k in ("v", "state", "remote", "updates", "until", "seats", "used")},
                         {"v": 1, "state": "active", "remote": True, "updates": True, "until": int(end),
                          "seats": 3, "used": 1})
        self.assertAlmostEqual(lic["now"], time.time(), delta=60)
        self.assertNotIn("grace_until", lic)

    def test_a_real_call_carries_the_licence_too(self):
        self.licence()
        t, seen = self.pi_answers(self.token)
        self.b.get("/pi/%s/api/status" % self.pid, headers={"X-QuietNet": "1"})
        t.join(5)
        self.assertEqual((seen.get("path"), seen["licence"]["state"]), ("/api/status", "active"))
        self.assertTrue(seen.get("id"))

    def test_with_the_gate_off_remote_and_updates_are_true_but_the_state_is_the_real_one(self):
        self.licence(state="expired", period_end=JAN4)
        lic = self.poll(self.token)[1]["licence"]
        self.assertEqual((lic["state"], lic["remote"], lic["updates"]), ("expired", True, True))

    def test_with_the_gate_on_an_expired_licence_says_remote_and_updates_are_off(self):
        self.gate(on=True)
        self.licence(state="expired", period_end=JAN4)
        status, answer = self.poll(self.token)
        self.assertEqual(status, 200)
        self.assertEqual((answer["licence"]["remote"], answer["licence"]["updates"], answer["licence"]["until"]),
                         (False, False, JAN4))

    def test_a_poll_answer_has_no_seats_without_a_licence(self):
        lic = self.poll(self.token)[1]["licence"]
        self.assertEqual((lic["state"], lic["used"]), ("none", 1))
        self.assertNotIn("seats", lic)

    def test_an_unlicensed_poll_is_answered_200_and_the_token_keeps_working(self):
        self.gate(on=True)
        for _ in range(2):
            status, answer = self.poll(self.token)
            self.assertEqual((status, answer["licence"]["state"]), (200, "none"))
        self.assertEqual(relay.sql("SELECT paired FROM pis WHERE id=?", (self.pid,), one=True)[0], 1)

    def test_an_unlicensed_pi_waits_for_work_like_a_licensed_one(self):
        self.gate(on=True)
        self.licence(state="revoked")
        started = time.time()
        self.poll(self.token, wait=0.5)
        self.assertGreaterEqual(time.time() - started, 0.45)

    def test_an_unlicensed_pi_waits_in_a_poll_slot_like_a_licensed_one(self):
        self.gate(on=True)
        self.licence(state="expired")
        self.limit("poll_slots", threading.BoundedSemaphore(1))
        relay.poll_slots.acquire()                       # another Pi is waiting in the only place
        self.addCleanup(relay.poll_slots.release)
        self.assertEqual(self.poll(self.token)[0], 503)  # the existing "busy" answer, not about licences

    def test_past_due_answers_carry_the_grace_date(self):
        grace = time.time() + 5 * DAY
        self.licence(state="past_due", period_end=time.time() - DAY, grace_until=grace)
        lic = self.poll(self.token)[1]["licence"]
        self.assertEqual((lic["state"], lic["grace_until"]), ("past_due", int(grace)))

    def test_the_latest_version_is_added_only_when_one_is_set(self):
        self.assertNotIn("latest", self.poll(self.token)[1])
        relay.LATEST = "0.6.1"
        self.assertEqual(self.poll(self.token)[1]["latest"], "0.6.1")

    def test_the_agent_header_is_recorded_on_the_pi(self):
        self.poll(self.token, agent="2")
        self.assertEqual(relay.sql("SELECT agent FROM pis WHERE id=?", (self.pid,), one=True)[0], 2)

    def test_any_agent_header_but_2_counts_as_agent_1(self):
        for value in ("3", "two", "", " 2x", "22", None):
            with self.subTest(agent=value):
                relay.sql("UPDATE pis SET agent=2 WHERE id=?", (self.pid,), commit=True)
                self.poll(self.token, agent=value)
                self.assertEqual(relay.sql("SELECT agent FROM pis WHERE id=?", (self.pid,), one=True)[0], 1)

    def test_the_agent_kind_is_written_only_when_it_changes(self):
        self.poll(self.token, agent="2")
        before = relay.db.total_changes
        self.poll(self.token, agent="2")
        self.assertEqual(relay.db.total_changes - before, 1)    # only the "last seen" time


# ------------------------------------------------------------------ rescue

class Rescue(LicenceCase):
    def setUp(self):
        super().setUp()
        self.gate(on=True)
        self.b = self.signed_in()
        self.licence()
        self.pid, self.token = self.paired_pi(self.b)

    def new_pi(self):
        """Mark this Pi as a 0.6 agent, which has /api/rescue."""
        relay.sql("UPDATE pis SET agent=2 WHERE id=?", (self.pid,), commit=True)

    def rescue(self, what, browser=None, pid=None, headers=None, agent="2", form=None):
        """Press a rescue button with a pretend Pi ready to answer. Returns (status, page, call seen)."""
        t, seen = self.pi_answers(self.token, agent=agent)
        status, text, _ = (browser or self.b).post("/pi/%s/rescue" % (pid or self.pid),
                                                   form=form if form is not None else {"what": what},
                                                   headers=headers)
        if status != 200:
            relay.bridge.forget(self.pid)              # end the pretend Pi's poll
        t.join(5)
        return status, text, seen

    def test_turning_the_internet_back_on_reaches_an_expired_pi(self):
        self.licence(state="expired", period_end=JAN4)
        self.new_pi()
        status, text, seen = self.rescue("internet-on")
        self.assertEqual(status, 200)
        self.assertEqual((seen["method"], seen["path"], json.loads(seen["body"])),
                         ("POST", "/api/rescue", {"what": "internet-on"}))
        self.assertIn("Done. Every device&#x27;s internet switch is back on.", text)

    def test_pausing_blocking_reaches_an_expired_pi(self):
        self.licence(state="expired")
        self.new_pi()
        status, text, seen = self.rescue("pause-hour")
        self.assertEqual((status, seen["path"], json.loads(seen["body"])), (200, "/api/pause", {"minutes": 60}))
        self.assertIn("Blocking is paused for an hour.", text)

    def test_both_rescue_buttons_reach_a_revoked_pi(self):
        self.licence(state="revoked")
        self.new_pi()
        self.assertEqual(self.rescue("internet-on")[2]["path"], "/api/rescue")
        self.assertEqual(self.rescue("pause-hour")[2]["path"], "/api/pause")

    def test_both_rescue_buttons_reach_a_pi_with_no_licence(self):
        relay.sql("DELETE FROM licences", commit=True)
        self.assertEqual(self.rescue("internet-on")[0], 200)
        self.assertEqual(self.rescue("pause-hour")[0], 200)

    def test_rescue_works_with_the_gate_off_too(self):
        self.gate(on=False)
        self.licence(state="expired")
        self.assertEqual(self.rescue("pause-hour")[0], 200)

    def test_a_pi_older_than_0_6_gets_only_the_kill_switch_call(self):
        self.licence(state="expired")
        status, text, seen = self.rescue("internet-on", agent=None)
        self.assertEqual((seen["method"], seen["path"], json.loads(seen["body"])), ("POST", "/api/kill", {"on": False}))
        self.assertIn("The household kill switch is off.", text)

    def test_the_rescue_call_is_built_the_same_way_as_a_dashboard_call(self):
        self.new_pi()
        seen = self.rescue("pause-hour")[2]
        self.assertEqual(set(seen) - {"licence", "latest"}, {"id", "method", "path", "body"})
        self.assertIsInstance(seen["body"], str)

    def test_an_unknown_rescue_choice_is_refused_with_400_and_nothing_is_sent(self):
        with self.bridge_unused() as call:
            for what in ("", "kill", "internet-off", "/api/enforce", "pause-day"):
                status, _, _ = self.b.post("/pi/%s/rescue" % self.pid, form={"what": what})
                self.assertEqual(status, 400, what)
        call.assert_not_called()

    def test_nothing_from_the_browser_reaches_the_rescue_call(self):
        self.new_pi()
        seen = self.rescue(None, form={"what": "pause-hour", "path": "/api/enforce", "body": '{"ip": "1.2.3.4"}',
                                       "minutes": "1440", "method": "GET"})[2]
        self.assertEqual((seen["method"], seen["path"], seen["body"]), ("POST", "/api/pause", '{"minutes": 60}'))

    def test_another_accounts_pi_gives_404_for_a_rescue(self):
        stranger = self.signed_in("hannah@example.com")
        with self.bridge_unused() as call:
            status, _, _ = stranger.post("/pi/%s/rescue" % self.pid, form={"what": "internet-on"})
        self.assertEqual(status, 404)
        call.assert_not_called()

    def test_a_signed_out_rescue_is_sent_to_sign_in(self):
        status, _, r = Browser(self.port).post("/pi/%s/rescue" % self.pid, form={"what": "internet-on"})
        self.assertEqual((status, r.getheader("Location")), (303, "/login"))

    def test_a_rescue_sent_from_another_website_is_refused(self):
        with self.bridge_unused() as call:
            status, text, _ = self.b.post("/pi/%s/rescue" % self.pid, form={"what": "internet-on"},
                                          headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        self.assertIn("another website", text)
        call.assert_not_called()

    def test_a_rescue_to_a_pi_that_is_not_connected_says_so(self):
        relay.sql("UPDATE pis SET last_seen=? WHERE id=?", (time.time() - 120, self.pid), commit=True)
        with self.bridge_unused() as call:
            status, text, _ = self.b.post("/pi/%s/rescue" % self.pid, form={"what": "internet-on"})
        self.assertEqual(status, 503)
        self.assertIn("Your Pi isn&#x27;t connected to q3n.net right now, so this couldn&#x27;t be sent. "
                      "Is it switched on?", text)
        call.assert_not_called()

    def test_each_rescue_is_written_to_the_licence_log(self):
        self.new_pi()
        self.rescue("internet-on")
        self.rescue("pause-hour")
        rescues = [line for line in self.log_lines() if line.startswith("Rescue")]
        self.assertEqual(len(rescues), 2)
        self.assertIn("Rescue internet-on (POST /api/rescue) for Pi %s: done." % self.pid, rescues)

    def test_only_the_two_fixed_calls_get_through_to_a_paused_pi(self):
        self.licence(state="expired")
        api = {"X-QuietNet": "1"}
        with self.bridge_unused() as call:
            tries = [self.b.post("/pi/%s/api/rescue" % self.pid, data={"what": "internet-on"}, headers=api),
                     self.b.post("/pi/%s/api/kill" % self.pid, data={"on": False}, headers=api),
                     self.b.post("/pi/%s/api/pause" % self.pid, data={"minutes": 60}, headers=api),
                     self.b.post("/pi/%s/api/enforce" % self.pid, data={"ip": "1.2.3.4", "on": True}, headers=api),
                     self.b.post("/pi/%s/rescue/api/kill" % self.pid, form={"what": "internet-on"}),
                     self.b.post("/pi/%s/rescue/" % self.pid, form={"what": "internet-on"}),
                     self.b.get("/pi/%s/rescue" % self.pid),
                     self.b.get("/pi/%s/api/status" % self.pid, headers=api)]
        self.assertEqual([t[0] for t in tries], [402, 402, 402, 402, 404, 404, 404, 402])
        call.assert_not_called()

    def test_rescue_presses_are_capped_per_account_and_the_extra_ones_are_not_logged(self):
        relay.sql("UPDATE pis SET last_seen=0 WHERE id=?", (self.pid,), commit=True)      # offline: answered at once
        for n in range(20):
            status = self.b.post("/pi/%s/rescue" % self.pid, form={"what": "pause-hour"})[0]
            self.assertEqual(status, 503, n)
            self.assertEqual(len([line for line in self.log_lines() if line.startswith("Rescue")]), n + 1)
        with self.bridge_unused() as call:
            status, text, _ = self.b.post("/pi/%s/rescue" % self.pid, form={"what": "pause-hour"})
        self.assertEqual(status, 429)
        self.assertIn("a lot of rescue presses", text)
        call.assert_not_called()
        self.assertEqual(len([line for line in self.log_lines() if line.startswith("Rescue")]), 20)

    def test_the_rescue_page_carries_the_protective_headers(self):
        relay.sql("UPDATE pis SET last_seen=0 WHERE id=?", (self.pid,), commit=True)
        r = self.b.post("/pi/%s/rescue" % self.pid, form={"what": "internet-on"})[2]
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.getheader("Referrer-Policy"), "no-referrer")

    def test_the_rescue_calls_are_fixed_text(self):
        self.assertEqual(relay.rescue_call("internet-on", 2),
                         {"method": "POST", "path": "/api/rescue", "body": '{"what": "internet-on"}'})
        self.assertEqual(relay.rescue_call("internet-on", 1), {"method": "POST", "path": "/api/kill", "body": '{"on": false}'})
        self.assertEqual(relay.rescue_call("pause-hour", 1)["path"], "/api/pause")
        self.assertIsNone(relay.rescue_call("anything", 2))


# ------------------------------------------------------------------ the owner's command line

class CommandLine(unittest.TestCase):
    """Runs licence_command against a throwaway data folder, as an ordinary user (a stand-in), then
    puts the shared database back."""

    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="quietnet-relay-cli-")
        keep = (relay.db, relay.SECRET, relay.DATA)
        self.shared = keep[0]

        def put_back():
            """Close this test's database and restore the shared one."""
            if relay.db is not keep[0]:
                relay.db.close()
            relay.db, relay.SECRET, relay.DATA = keep
        self.addCleanup(put_back)
        relay.DATA = self.folder
        relay.init_db()
        relay.sql("INSERT INTO users(email,pw,created) VALUES('owner@example.com',?,1.0)",
                  (relay.hash_pw(PASSWORD, rounds=1000),), commit=True)
        self.uid = relay.sql("SELECT id FROM users", one=True)[0]

    def run_command(self, *words, system=None):
        """Run the command line with `words`. Returns (exit status, what it printed, what it complained)."""
        out, err = io.StringIO(), io.StringIO()
        if relay.db is not self.shared:
            relay.db.close()                # the command opens its own, as it would in a new process
        code = relay.licence_command(list(words), system=system or StandInSystem(euid=501), out=out, err=err)
        try:
            relay.db.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            relay.init_db()                 # the command stopped before opening one; reopen it to look
        return code, out.getvalue(), err.getvalue()

    def stored(self):
        """The account's stored licence."""
        return relay.licence_row(self.uid)

    def test_grant_makes_an_active_licence_with_no_end_date_by_default(self):
        code, out, _ = self.run_command("grant", "owner@example.com", "--plan", "owner")
        lic = self.stored()
        self.assertEqual((code, lic["state"], lic["plan"], lic["period_end"], lic["seats"]), (0, "active", "owner", 0, 2))
        self.assertIn("no end date", out)

    def test_grant_with_days_sets_the_end_date(self):
        self.run_command("grant", "owner@example.com", "--plan", "gift", "--days", "30", "--seats", "4")
        lic = self.stored()
        self.assertAlmostEqual(lic["period_end"], time.time() + 30 * DAY, delta=60)
        self.assertEqual((lic["plan"], lic["seats"]), ("gift", 4))

    def test_grant_with_zero_days_means_no_end(self):
        self.run_command("grant", "owner@example.com", "--plan", "gift", "--days", "0")
        self.assertEqual(self.stored()["period_end"], 0)

    def test_grant_keeps_the_seats_it_had_unless_given(self):
        self.run_command("grant", "owner@example.com", "--plan", "legacy", "--seats", "5")
        self.run_command("grant", "owner@example.com", "--plan", "owner")
        self.assertEqual((self.stored()["seats"], self.stored()["plan"]), (5, "owner"))

    def test_grant_brings_back_a_revoked_licence(self):
        self.run_command("grant", "owner@example.com", "--plan", "owner")
        self.run_command("revoke", "owner@example.com", "--reason", "test")
        self.run_command("grant", "owner@example.com", "--plan", "owner")
        self.assertEqual((self.stored()["state"], self.stored()["reason"]), ("active", ""))

    def test_revoke_keeps_the_plan_and_records_the_reason(self):
        self.run_command("grant", "owner@example.com", "--plan", "gift", "--days", "10")
        end = self.stored()["period_end"]
        code, _, _ = self.run_command("revoke", "owner@example.com", "--reason", "Shared the account")
        lic = self.stored()
        self.assertEqual((code, lic["state"], lic["plan"], lic["reason"], lic["period_end"]),
                         (0, "revoked", "gift", "Shared the account", end))

    def test_restore_sets_the_licence_active_again_and_keeps_its_end_date(self):
        self.run_command("grant", "owner@example.com", "--plan", "gift", "--days", "10")
        end = self.stored()["period_end"]
        self.run_command("revoke", "owner@example.com", "--reason", "Mistake")
        code, out, _ = self.run_command("restore", "owner@example.com")
        lic = self.stored()
        self.assertEqual((code, lic["state"], lic["reason"], lic["period_end"]), (0, "active", "", end))
        self.assertIn("State now: active", out)

    def test_seats_changes_how_many_pis_the_licence_covers(self):
        self.run_command("grant", "owner@example.com", "--plan", "owner")
        code, out, _ = self.run_command("seats", "owner@example.com", "6")
        self.assertEqual((code, self.stored()["seats"]), (0, 6))
        self.assertIn("covers 6 Pis", out)

    def test_each_change_writes_a_licence_log_line(self):
        for words in (("grant", "owner@example.com", "--plan", "owner"), ("seats", "owner@example.com", "3"),
                      ("revoke", "owner@example.com", "--reason", "x"), ("restore", "owner@example.com")):
            self.run_command(*words)
        lines = [r[0] for r in relay.sql("SELECT what FROM licence_log WHERE user_id=? ORDER BY at", (self.uid,))]
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith("Owner granted the licence"))
        self.assertEqual(lines[1:], ["Owner set the seats to 3.", "Owner revoked the licence: x",
                                     "Owner restored the licence."])

    def test_show_prints_the_licence_and_its_log(self):
        self.run_command("grant", "owner@example.com", "--plan", "owner")
        code, out, _ = self.run_command("show", "owner@example.com")
        self.assertEqual(code, 0)
        for words in ("Account: owner@example.com", "State now: active (stored as active)", "Plan: owner",
                      "Ends: no end date", "Pis: 0 of 2", "Licence gate:", "Owner granted the licence"):
            self.assertIn(words, out)

    def test_show_for_an_account_with_no_licence_says_so(self):
        code, out, _ = self.run_command("show", "owner@example.com")
        self.assertEqual(code, 0)
        self.assertIn("Licence: none.", out)

    def test_licence_show_gives_no_seat_limit_without_a_licence(self):
        out = self.run_command("show", "owner@example.com")[1]
        self.assertIn("Pis: 0\n", out)
        self.assertNotIn("Pis: 0 of", out)

    def add_pi(self, uid, pid="pi-1"):
        """Put one paired Pi on account `uid` straight in the database."""
        relay.sql("INSERT INTO pis(id,user_id,name,paired,created) VALUES(?,?,'Home Pi',1,1.0)", (pid, uid), commit=True)

    def everything_stored(self):
        """Every row of the tables the command line could change, to compare before and after."""
        return {t: relay.sql("SELECT * FROM %s ORDER BY rowid" % t) for t in ("users", "pis", "licences", "licence_log")}

    def test_licence_list_shows_every_account_with_its_licence_and_pis(self):
        relay.sql("INSERT INTO users(email,pw,created) VALUES('stranger@example.com','x',2.0)", commit=True)
        other = relay.sql("SELECT id FROM users WHERE email='stranger@example.com'", one=True)[0]
        self.run_command("grant", "owner@example.com", "--plan", "legacy", "--days", "90", "--seats", "3")
        self.add_pi(self.uid)
        lid, end = self.stored()["id"], self.stored()["period_end"]
        code, out, _ = self.run_command("list")
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines(), [
            "owner@example.com (number %d): licence %s, active, plan legacy, until %s. Pis: 1 of 3"
            % (self.uid, lid, relay.long_date(end)),
            "stranger@example.com (number %d): no licence. Pis: 0" % other,
            "2 accounts"])

    def test_licence_list_on_an_empty_relay_says_so_and_exits_zero(self):
        relay.sql("DELETE FROM users", commit=True)
        code, out, err = self.run_command("list")
        self.assertEqual((code, out, err), (0, "No accounts on this relay yet.\n", ""))

    def test_licence_list_changes_nothing(self):
        self.run_command("grant", "owner@example.com", "--plan", "owner")
        self.add_pi(self.uid)
        before = self.everything_stored()
        self.assertEqual(self.run_command("list")[0], 0)
        self.assertEqual(self.everything_stored(), before)

    def test_the_account_is_found_by_its_current_email_whatever_its_letter_case(self):
        relay.sql("UPDATE users SET email='new@example.com'", commit=True)
        self.assertEqual(self.run_command("grant", " NEW@example.com ", "--plan", "owner")[0], 0)
        self.assertEqual(self.run_command("show", "owner@example.com")[0], 1)

    def test_an_unknown_email_exits_non_zero_with_a_plain_message(self):
        code, _, err = self.run_command("grant", "nobody@example.com", "--plan", "owner")
        self.assertEqual(code, 1)
        self.assertIn("No account on this relay has the email nobody@example.com.", err)

    def test_a_bad_argument_exits_non_zero_with_a_plain_message_and_changes_nothing(self):
        for words in (("grant", "owner@example.com", "--plan", "platinum"),
                      ("grant", "owner@example.com", "--plan", "owner", "--days", "-1"),
                      ("grant", "owner@example.com", "--plan", "owner", "--seats", "0"),
                      ("grant", "owner@example.com"),
                      ("seats", "owner@example.com", "many"),
                      ("delete", "owner@example.com"), ()):
            code, _, err = self.run_command(*words)
            self.assertEqual(code, 2, words)
            self.assertIn("That command isn't right", err)
        self.assertIsNone(self.stored())

    def test_changing_a_licence_the_account_does_not_have_exits_non_zero(self):
        for words in (("revoke", "owner@example.com", "--reason", "x"), ("restore", "owner@example.com"),
                      ("seats", "owner@example.com", "3")):
            code, _, err = self.run_command(*words)
            self.assertEqual(code, 1, words)
            self.assertIn("has no licence yet", err)

    def test_revoke_needs_a_reason(self):
        self.run_command("grant", "owner@example.com", "--plan", "owner")
        self.assertEqual(self.run_command("revoke", "owner@example.com")[0], 2)
        self.assertEqual(self.run_command("revoke", "owner@example.com", "--reason", "  ")[0], 2)
        self.assertEqual(self.stored()["state"], "active")

    def test_the_command_line_gives_up_root_before_it_opens_the_database(self):
        system = StandInSystem(euid=0)
        seen = []
        real = relay.init_db
        with mock.patch.object(relay, "init_db", lambda: (seen.append(system.euid), real())):
            code, _, _ = self.run_command("show", "owner@example.com", system=system)
        self.assertEqual((code, seen), (0, [65534]))
        self.assertIn(("chown", self.folder, 65534, 65534), system.calls)

    def test_a_bad_command_is_refused_before_anything_else_happens(self):
        system = StandInSystem(euid=0)
        self.run_command("grant", "owner@example.com", "--plan", "platinum", system=system)
        self.assertEqual(system.calls, [])

    def test_the_relay_runs_the_command_line_when_started_with_licence(self):
        with mock.patch.object(relay, "licence_command", return_value=0) as command:
            with self.assertRaises(SystemExit) as stopped:
                relay.main(["licence", "show", "owner@example.com"])
        command.assert_called_once_with(["show", "owner@example.com"])
        self.assertEqual(stopped.exception.code, 0)

    def test_the_relay_refuses_words_it_does_not_know(self):
        with self.assertRaises(SystemExit) as stopped:
            relay.main(["licenses"])
        self.assertIn("doesn't know", str(stopped.exception.code))


# ------------------------------------------------------------------ start-up

class FlushRecorder:
    """A stand-in for standard output that keeps apart what was written and what was flushed, as a
    pipe's buffer would."""

    def __init__(self):
        """Start with nothing written and nothing flushed."""
        self.waiting, self.flushed = "", ""

    def write(self, text):
        """Hold `text` until the next flush, as a buffer does."""
        self.waiting += text
        return len(text)

    def flush(self):
        """Pass on everything held so far."""
        self.flushed, self.waiting = self.flushed + self.waiting, ""


class StartUp(unittest.TestCase):
    def test_start_up_lines_are_flushed_before_serving(self):
        out = FlushRecorder()
        at_serve = {}
        server = mock.Mock()
        server.serve_forever.side_effect = lambda: at_serve.update(flushed=out.flushed, waiting=out.waiting)
        folder = tempfile.TemporaryDirectory(prefix="quietnet-relay-start-")
        self.addCleanup(folder.cleanup)
        with mock.patch.object(relay, "RelayServer", return_value=server), \
                mock.patch.object(relay, "drop_privileges", return_value=None), \
                mock.patch.object(relay, "init_db"), mock.patch.object(relay, "DATA", folder.name), \
                mock.patch.object(relay, "LICENCE_GATE", "on"), mock.patch.object(sys, "stdout", out):
            relay.main([])
        self.assertEqual(at_serve["waiting"], "")
        self.assertIn("Licence gate: on.", at_serve["flushed"])
        self.assertIn("QuietNet relay listening on port", at_serve["flushed"])


if __name__ == "__main__":
    unittest.main()
