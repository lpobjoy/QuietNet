"""Checks for the Pi's outbound link to the relay (cloud_agent.py).

Run with:  python3 -m unittest discover tests

Standard library only. A pretend relay and a pretend local dashboard are started on
spare ports on this computer; nothing leaves this machine.
"""
import http.client
import json
import os
import shutil
import ssl
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cloud_agent  # noqa: E402
import urllib.error  # noqa: E402


class PretendRelay(BaseHTTPRequestHandler):
    """Behaves like cloud/relay.py as far as the Pi can tell."""
    good_code = "AB12-CD34"
    token = "t" * 48
    calls = []          # calls waiting to be handed to the Pi
    answers = []        # what the Pi sent back
    seen_tokens = []
    poll_status = 200

    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        cls = PretendRelay
        cls.seen_tokens.append(self.headers.get("X-QuietNet-Token"))
        if cls.poll_status != 200:
            return self.reply(cls.poll_status, {})
        time.sleep(0.02)
        self.reply(200, cls.calls.pop(0) if cls.calls else {})

    def do_POST(self):
        cls = PretendRelay
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path == "/agent/pair":
            if body.get("code") == cls.good_code:
                return self.reply(200, {"ok": True, "id": "pi-1", "token": cls.token})
            return self.reply(400, {"error": "That pairing code is wrong or already used."})
        cls.seen_tokens.append(self.headers.get("X-QuietNet-Token"))
        cls.answers.append(body)
        self.reply(200, {"ok": True})


class PretendDashboard(BaseHTTPRequestHandler):
    """Stands in for the Pi's own dashboard on 127.0.0.1."""
    requests = []

    def log_message(self, *a):
        pass

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        PretendDashboard.requests.append({
            "method": self.command, "path": self.path, "host": self.headers.get("Host"),
            "content_type": self.headers.get("Content-Type"), "marker": self.headers.get("X-QuietNet"),
            "body": self.rfile.read(n).decode()})
        code = 400 if self.path == "/api/refuse" else 200
        data = json.dumps({"path": self.path}).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = handle_any


def serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def closed_port():
    """A port number on this computer that nothing is listening on."""
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AgentCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.relay, cls.dash = serve(PretendRelay), serve(PretendDashboard)
        cls.relay_url = "http://127.0.0.1:%d" % cls.relay.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for httpd in (cls.relay, cls.dash):
            httpd.shutdown()
            httpd.server_close()

    def setUp(self):
        PretendRelay.calls, PretendRelay.answers, PretendRelay.seen_tokens = [], [], []
        PretendRelay.poll_status = 200
        PretendDashboard.requests = []
        self.data = tempfile.mkdtemp(prefix="quietnet-agent-test-")
        self.addCleanup(shutil.rmtree, self.data, True)
        self.log = []
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("QUIETNET_CLOUD", None)
        os.environ.pop("QUIETNET_PAIR", None)

    def agent(self):
        return cloud_agent.CloudAgent(self.dash.server_address[1], self.data, log=self.log.append)

    def saved(self):
        with open(os.path.join(self.data, "cloud.json")) as f:
            return json.load(f)

    def run_until(self, agent, done, seconds=5):
        t = threading.Thread(target=agent._run, daemon=True)
        t.start()
        deadline = time.time() + seconds
        while not done() and time.time() < deadline:
            time.sleep(0.02)
        agent.stop()
        t.join(5)
        self.assertFalse(t.is_alive(), "the agent's loop did not stop when asked")
        self.assertTrue(done(), "the agent never got there")


class Setup(AgentCase):
    def test_a_fresh_pi_is_not_configured(self):
        st = self.agent().status()
        self.assertEqual((st["configured"], st["paired"], st["state"]), (False, False, "off"))

    def test_a_damaged_settings_file_is_treated_as_unpaired(self):
        with open(os.path.join(self.data, "cloud.json"), "w") as f:
            f.write("{not json")
        self.assertFalse(self.agent().status()["paired"])

    def test_pairing_saves_the_token_so_it_survives_a_restart(self):
        a = self.agent()
        self.assertIsNone(a.pair(self.relay_url, "ab12-cd34 "))        # tidied up and upper-cased before sending
        self.assertEqual(self.saved(), {"relay": self.relay_url, "token": PretendRelay.token, "id": "pi-1"})
        again = self.agent()
        self.assertTrue(again.status()["paired"])
        self.assertEqual(again.status()["relay"], self.relay_url)

    @unittest.skipIf(os.name == "nt", "file permissions work differently on Windows")
    def test_the_saved_token_is_readable_only_by_its_owner(self):
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        path = os.path.join(self.data, "cloud.json")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "file permissions work differently on Windows")
    def test_a_file_left_open_by_an_older_version_is_tightened(self):
        path = os.path.join(self.data, "cloud.json")
        with open(path, "w") as f:
            f.write("{}")
        os.chmod(path, 0o644)
        self.agent().pair(self.relay_url, PretendRelay.good_code)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_a_trailing_slash_on_the_relay_address_is_dropped(self):
        a = self.agent()
        self.assertIsNone(a.pair(self.relay_url + "/", PretendRelay.good_code))
        self.assertEqual(self.saved()["relay"], self.relay_url)

    def test_an_address_without_https_gets_it_added(self):
        a = self.agent()
        asked = []
        a._http = lambda method, url, obj, timeout, token=False: asked.append(url) or {"token": "x"}
        a.pair("my-relay.up.railway.app", "AB12-CD34")
        self.assertEqual(asked, ["https://my-relay.up.railway.app/agent/pair"])

    def pair_asking(self, relay):
        """Pair with `relay` through a stand-in for the network; returns (message, addresses asked)."""
        a = self.agent()
        asked = []
        a._http = lambda method, url, obj, timeout, token=False: asked.append(url) or {"token": "x"}
        return a.pair(relay, "AB12-CD34"), asked

    def test_a_plain_http_relay_on_another_computer_is_refused(self):
        message, asked = self.pair_asking("http://my-relay.up.railway.app")
        self.assertEqual(asked, [])
        self.assertIn("https://", message)

    def test_a_refused_plain_http_relay_saves_nothing(self):
        self.pair_asking("http://my-relay.up.railway.app")
        self.assertFalse(os.path.exists(os.path.join(self.data, "cloud.json")))

    def test_a_plain_http_relay_is_refused_whatever_the_capital_letters(self):
        message, asked = self.pair_asking("HTTP://my-relay.up.railway.app")
        self.assertEqual(asked, [])
        self.assertIn("https://", message)

    def test_a_host_name_that_only_starts_with_localhost_is_refused_over_http(self):
        message, asked = self.pair_asking("http://localhost.example.com")
        self.assertEqual(asked, [])

    def test_plain_http_is_allowed_for_a_relay_named_localhost(self):
        message, asked = self.pair_asking("http://localhost:8080")
        self.assertIsNone(message)
        self.assertEqual(asked, ["http://localhost:8080/agent/pair"])

    def test_plain_http_is_allowed_for_a_relay_at_127_0_0_1(self):
        message, asked = self.pair_asking("http://127.0.0.1:8080")
        self.assertIsNone(message)
        self.assertEqual(asked, ["http://127.0.0.1:8080/agent/pair"])

    def test_plain_http_is_allowed_for_a_relay_at_the_ipv6_loopback_address(self):
        message, asked = self.pair_asking("http://[::1]:8080")
        self.assertIsNone(message)
        self.assertEqual(asked, ["http://[::1]:8080/agent/pair"])

    def test_an_https_relay_on_another_computer_is_allowed(self):
        message, asked = self.pair_asking("https://my-relay.up.railway.app")
        self.assertIsNone(message)
        self.assertEqual(asked, ["https://my-relay.up.railway.app/agent/pair"])

    def test_a_wrong_code_gives_the_relays_own_message_and_saves_nothing(self):
        a = self.agent()
        self.assertEqual(a.pair(self.relay_url, "0000-0000"), "That pairing code is wrong or already used.")
        self.assertFalse(os.path.exists(os.path.join(self.data, "cloud.json")))
        self.assertFalse(a.status()["paired"])

    def test_an_unreachable_relay_gives_a_plain_message(self):
        a = self.agent()
        self.assertEqual(a.pair("http://127.0.0.1:%d" % closed_port(), "AB12-CD34"),
                         "Couldn't reach the relay at that address.")

    def test_forgetting_wipes_the_pairing(self):
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        a.forget()
        self.assertEqual(self.saved(), {})
        self.assertEqual((a.status()["paired"], a.status()["state"]), (False, "off"))

    def test_headless_setup_from_environment_variables(self):
        os.environ["QUIETNET_CLOUD"] = self.relay_url + "/"
        os.environ["QUIETNET_PAIR"] = PretendRelay.good_code
        a = self.agent()
        self.assertEqual(a.status()["relay"], self.relay_url)
        a._run = lambda: None                   # pair only; don't start the loop
        a.start()
        self.assertTrue(a.status()["paired"])
        self.assertEqual(self.log, ["Cloud pairing: success"])

    def test_environment_variables_do_not_override_an_existing_pairing(self):
        self.agent().pair(self.relay_url, PretendRelay.good_code)
        os.environ["QUIETNET_CLOUD"] = "https://somewhere-else.example"
        self.assertEqual(self.agent().status()["relay"], self.relay_url)


class LocalCalls(AgentCase):
    def test_a_get_is_run_against_the_local_dashboard(self):
        status, body = self.agent()._local("GET", "/api/status", None)
        self.assertEqual((status, json.loads(body)), (200, {"path": "/api/status"}))
        req = PretendDashboard.requests[0]
        self.assertEqual((req["method"], req["path"], req["body"]), ("GET", "/api/status", ""))

    def test_it_presents_itself_as_a_local_browser(self):
        # The dashboard only answers requests addressed to "localhost", and only takes JSON.
        self.agent()._local("POST", "/api/block", '{"domain": "example.com"}')
        req = PretendDashboard.requests[0]
        self.assertEqual(req["host"], "localhost")
        self.assertEqual(req["content_type"], "application/json")
        self.assertEqual(json.loads(req["body"]), {"domain": "example.com"})

    def test_a_refusal_from_the_dashboard_is_passed_back_with_its_status(self):
        status, body = self.agent()._local("POST", "/api/refuse", "{}")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"path": "/api/refuse"})

    def test_a_path_without_a_leading_slash_still_goes_to_this_computer(self):
        self.agent()._local("GET", "api/status", None)
        self.assertEqual(PretendDashboard.requests[0]["path"], "/api/status")

    def test_a_dead_dashboard_gives_a_502(self):
        a = cloud_agent.CloudAgent(closed_port(), self.data, log=self.log.append)
        status, body = a._local("GET", "/api/status", None)
        self.assertEqual(status, 502)
        self.assertIn("error", json.loads(body))


class RunLoop(AgentCase):
    def test_unpaired_it_waits_and_contacts_nobody(self):
        a = self.agent()
        t = threading.Thread(target=a._run, daemon=True)
        t.start()
        time.sleep(0.2)
        a.stop()
        t.join(5)
        self.assertFalse(t.is_alive())
        self.assertEqual(PretendRelay.seen_tokens, [])
        self.assertEqual(a.state, "off")

    def test_a_relayed_call_is_run_locally_and_the_answer_sent_back(self):
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        PretendRelay.calls = [{"id": "call-1", "method": "POST", "path": "/api/kill", "body": '{"on": true}'}]
        self.run_until(a, lambda: PretendRelay.answers)
        self.assertEqual(PretendRelay.answers[0]["id"], "call-1")
        self.assertEqual(PretendRelay.answers[0]["status"], 200)
        self.assertEqual(json.loads(PretendRelay.answers[0]["body"]), {"path": "/api/kill"})
        self.assertEqual(json.loads(PretendDashboard.requests[0]["body"]), {"on": True})
        self.assertEqual(set(PretendRelay.seen_tokens), {PretendRelay.token})      # every call carried the token

    def test_a_slow_call_does_not_hold_up_the_next_one(self):
        # A dashboard page makes several calls at once; they shouldn't queue behind each other.
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        release = threading.Event()
        self.addCleanup(release.set)

        def local(method, path, body):
            if path == "/api/slow":
                release.wait(5)
            return 200, json.dumps({"path": path})
        a._local = local
        PretendRelay.calls = [{"id": "slow", "method": "GET", "path": "/api/slow"},
                              {"id": "quick", "method": "GET", "path": "/api/quick"}]
        self.run_until(a, lambda: any(x["id"] == "quick" for x in PretendRelay.answers))
        self.assertNotIn("slow", [x["id"] for x in PretendRelay.answers])     # still waiting, yet quick got through
        release.set()
        deadline = time.time() + 5                     # let the slow one finish before the next test starts
        while "slow" not in [x["id"] for x in PretendRelay.answers] and time.time() < deadline:
            time.sleep(0.02)

    def test_an_answer_too_big_to_relay_is_replaced_by_a_short_message(self):
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        a._local = lambda method, path, body: (200, "x" * (cloud_agent.MAX_ANSWER + 1))
        PretendRelay.calls = [{"id": "big", "method": "GET", "path": "/api/activity"}]
        self.run_until(a, lambda: PretendRelay.answers)
        self.assertEqual(PretendRelay.answers[0]["status"], 502)
        self.assertIn("too much to send remotely", PretendRelay.answers[0]["body"])

    def test_it_reports_online_once_the_relay_answers(self):
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        self.run_until(a, lambda: a.state == "online")

    def test_being_unpaired_on_the_relay_drops_the_token(self):
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        PretendRelay.poll_status = 401
        self.run_until(a, lambda: not a.cfg.get("token"))
        self.assertNotIn("token", self.saved())
        self.assertIn("Pair it again", a.detail)

    def test_a_relay_fault_is_reported_but_the_pairing_is_kept(self):
        a = self.agent()
        a.pair(self.relay_url, PretendRelay.good_code)
        PretendRelay.poll_status = 500
        self.run_until(a, lambda: a.state == "error")
        self.assertEqual(a.detail, "Relay error 500")
        self.assertEqual(a.cfg["token"], PretendRelay.token)

    def test_an_unreachable_relay_is_reported_but_the_pairing_is_kept(self):
        a = self.agent()
        a.cfg = {"relay": "http://127.0.0.1:%d" % closed_port(), "token": "kept"}
        self.run_until(a, lambda: a.state == "error")
        self.assertIn("Can't reach the relay", a.detail)
        self.assertEqual(a.cfg["token"], "kept")


def cert_failure():
    """The error urllib raises when a certificate can't be checked."""
    return urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed"))


class InsecureSavedRelay(AgentCase):
    """A plain http:// relay on another computer saved by an older version is never contacted."""

    def test_a_saved_plain_http_relay_is_not_sent_the_token(self):
        a = self.agent()
        a.cfg = {"relay": "http://relay.example", "token": "kept"}
        asked = []
        a._http = lambda *args, **kwargs: asked.append(args) or {}
        self.run_until(a, lambda: a.state == "error")
        self.assertEqual(asked, [])

    def test_a_saved_plain_http_relay_tells_the_person_to_use_https(self):
        a = self.agent()
        a.cfg = {"relay": "http://relay.example", "token": "kept"}
        a._http = lambda *args, **kwargs: {}
        self.run_until(a, lambda: a.state == "error")
        self.assertIn("https://", a.detail)


class LinkSurvives(AgentCase):
    """The link thread must keep going whatever the relay sends."""

    def paired_agent(self, answers):
        """An agent paired to a stand-in relay whose poll answers come from `answers` in turn:
        an exception is raised, anything else is returned. After the list runs out it returns {}."""
        a = self.agent()
        a.cfg = {"relay": "https://relay.invalid", "token": "kept"}
        answers = list(answers)
        self.polls = 0

        def fake_http(method, url, obj, timeout, token=False, headers=None):
            self.polls += 1
            item = answers.pop(0) if answers else {}
            if isinstance(item, BaseException):
                raise item
            return item
        a._http = fake_http
        return a

    def test_a_cut_off_answer_from_the_relay_does_not_stop_the_link(self):
        a = self.paired_agent([http.client.IncompleteRead(b"par")])
        self.run_until(a, lambda: self.polls >= 2 and a.state == "online")

    def test_an_answer_that_is_not_json_does_not_stop_the_link(self):
        a = self.paired_agent([ValueError("Expecting value")])
        self.run_until(a, lambda: self.polls >= 2 and a.state == "online")

    def test_an_answer_that_is_not_an_object_is_ignored(self):
        a = self.paired_agent([["not", "a", "call"]])
        self.run_until(a, lambda: self.polls >= 2 and a.state == "online")

    def test_a_garbled_answer_is_reported_in_plain_english(self):
        a = self.paired_agent([http.client.BadStatusLine("junk")] * 50)
        self.run_until(a, lambda: a.state == "error")
        self.assertEqual(a.detail, "The relay sent an answer QuietNet couldn't read. Trying again.")

    def test_an_unexpected_error_does_not_stop_the_link(self):
        a = self.paired_agent([KeyError("surprise")])
        self.run_until(a, lambda: self.polls >= 2 and a.state == "online")

    def test_an_unexpected_error_is_reported_and_logged(self):
        a = self.paired_agent([KeyError("surprise")] * 50)
        self.run_until(a, lambda: a.state == "error" and self.log)
        self.assertIn("Something unexpected went wrong", a.detail)
        self.assertIn("surprise", self.log[0])

    def test_a_garbled_reply_while_sending_an_answer_is_ignored(self):
        a = self.agent()
        a.cfg = {"relay": "https://relay.invalid", "token": "kept"}
        a._local = lambda method, path, body: (200, "{}")

        def fake_http(*args, **kwargs):
            raise http.client.IncompleteRead(b"")
        a._http = fake_http
        a._handle({"id": "c1", "method": "GET", "path": "/api/status"})     # must not raise


class Certificates(AgentCase):
    """Secure calls work on a Python with no certificate list of its own, and never skip the check."""

    def setUp(self):
        super().setUp()
        cloud_agent._tls = None
        self.addCleanup(setattr, cloud_agent, "_tls", None)

    def fake_context(self, authorities):
        """A stand-in for ssl.create_default_context() reporting `authorities` trusted ones."""
        ctx = mock.Mock()
        ctx.cert_store_stats.return_value = {"x509_ca": authorities}
        return ctx

    def test_a_python_without_certificates_borrows_the_systems_own_list(self):
        ctx = self.fake_context(0)
        wanted = cloud_agent.SYSTEM_CA_FILES[1]
        with mock.patch.object(cloud_agent.ssl, "create_default_context", return_value=ctx), \
                mock.patch.object(cloud_agent.os.path, "isfile", side_effect=lambda p: p == wanted):
            self.assertIs(cloud_agent.tls_context(), ctx)
        ctx.load_verify_locations.assert_called_once_with(cafile=wanted)

    def test_a_python_with_certificates_is_left_as_it_is(self):
        ctx = self.fake_context(120)
        with mock.patch.object(cloud_agent.ssl, "create_default_context", return_value=ctx):
            cloud_agent.tls_context()
        ctx.load_verify_locations.assert_not_called()

    def test_certificate_checks_are_never_turned_off(self):
        ctx = cloud_agent.tls_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_the_checked_settings_are_made_once_and_shared(self):
        self.assertIs(cloud_agent.tls_context(), cloud_agent.tls_context())

    def test_the_checked_settings_are_shared_safely_between_threads(self):
        made, seen = [], []
        real = cloud_agent.ssl.create_default_context

        def counting():
            made.append(1)
            return real()
        with mock.patch.object(cloud_agent.ssl, "create_default_context", counting):
            threads = [threading.Thread(target=lambda: seen.append(cloud_agent.tls_context())) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(5)
        self.assertEqual((len(made), len(set(map(id, seen)))), (1, 1))

    def test_secure_relay_calls_use_the_checked_settings(self):
        seen = {}

        def fake_urlopen(req, timeout, context=None):
            seen["context"] = context
            raise urllib.error.URLError("stop here")
        with mock.patch.object(cloud_agent.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(urllib.error.URLError):
                self.agent()._http("GET", "https://relay.example/agent/poll", None, timeout=1)
        self.assertIs(seen["context"], cloud_agent.tls_context())

    def test_a_certificate_failure_when_pairing_names_the_fix(self):
        a = self.agent()

        def fake_http(*args, **kwargs):
            raise cert_failure()
        a._http = fake_http
        self.assertIn("Install Certificates.command", a.pair("https://relay.example", "AB12-CD34"))

    def test_a_certificate_failure_on_the_link_names_the_fix(self):
        a = self.agent()
        a.cfg = {"relay": "https://relay.example", "token": "kept"}

        def fake_http(*args, **kwargs):
            raise cert_failure()
        a._http = fake_http
        self.run_until(a, lambda: a.state == "error")
        self.assertIn("Install Certificates.command", a.detail)


class HeadlessPairingRetry(AgentCase):
    """A QUIETNET_PAIR code is tried again while the relay is busy or out of reach."""

    def agent_with_answers(self, answers):
        """An unpaired agent set up from the environment, whose pairing calls get `answers` in turn."""
        os.environ["QUIETNET_CLOUD"] = "https://relay.invalid"
        os.environ["QUIETNET_PAIR"] = "AB12-CD34"
        a = self.agent()
        answers = list(answers)
        self.tries = 0

        def fake_http(method, url, obj, timeout, token=False, headers=None):
            if url.endswith("/agent/poll"):
                return {}
            self.tries += 1
            item = answers.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        a._http = fake_http
        a._run = lambda: None                   # first try only; tests drive the loop themselves
        a._save = lambda: None                  # keep the test's data folder untouched
        return a

    def busy(self):
        """The relay's answer when too many wrong codes have been tried lately."""
        import io
        return urllib.error.HTTPError("https://relay.invalid/agent/pair", 429, "Too Many Requests", {},
                                      io.BytesIO(b'{"error": "Too many attempts."}'))

    def refused(self):
        """The relay's answer to a wrong, used or expired code."""
        import io
        return urllib.error.HTTPError("https://relay.invalid/agent/pair", 400, "Bad Request", {},
                                      io.BytesIO(b'{"error": "That pairing code is wrong."}'))

    def test_a_headless_plain_http_relay_on_another_computer_is_not_tried_again(self):
        os.environ["QUIETNET_CLOUD"] = "http://relay.example"
        a = self.agent_with_answers([])
        a.cfg["relay"] = "http://relay.example"
        a.start()
        a._next_pair_try = 0
        a._retry_pairing()
        self.assertEqual((self.tries, a._pending_code), (0, ""))

    def test_a_busy_relay_is_tried_again_until_pairing_works(self):
        a = self.agent_with_answers([self.busy(), {"token": "new", "id": "pi-1"}])
        a.start()
        self.assertFalse(a.status()["paired"])
        a._next_pair_try = 0                    # don't wait the real five seconds
        a._retry_pairing()
        self.assertTrue(a.status()["paired"])
        self.assertEqual(self.tries, 2)

    def test_an_unreachable_relay_is_tried_again(self):
        a = self.agent_with_answers([urllib.error.URLError("refused"), {"token": "new"}])
        a.start()
        a._next_pair_try = 0
        a._retry_pairing()
        self.assertTrue(a.status()["paired"])

    def test_a_refused_code_is_not_tried_again(self):
        a = self.agent_with_answers([self.refused()])
        a.start()
        a._next_pair_try = 0
        a._retry_pairing()                      # would fail if it asked the relay a second time
        self.assertEqual(self.tries, 1)
        self.assertEqual(a.detail, "That pairing code is wrong.")

    def test_the_wait_between_tries_grows_up_to_a_minute(self):
        a = self.agent_with_answers([self.busy() for _ in range(8)])
        a.start()
        waits = []
        for _ in range(7):
            waits.append(a._pair_wait)
            a._next_pair_try = 0
            a._retry_pairing()
        self.assertEqual(waits, [10, 20, 40, 60, 60, 60, 60])

    def test_a_retry_waits_until_it_is_due(self):
        a = self.agent_with_answers([self.busy()])
        a.start()
        a._retry_pairing()                      # too soon: must not ask the relay again
        self.assertEqual(self.tries, 1)

    def test_the_loop_retries_the_code_and_then_connects(self):
        a = self.agent_with_answers([self.busy(), {"token": "new"}])
        a.start()
        a._next_pair_try = 0
        del a._run                              # use the real loop again
        self.run_until(a, lambda: a.state == "online")
        self.assertEqual(self.tries, 2)

    def test_forgetting_stops_the_retries(self):
        a = self.agent_with_answers([self.busy()])
        a.start()
        a.forget()
        a._next_pair_try = 0
        a._retry_pairing()
        self.assertEqual(self.tries, 1)


if __name__ == "__main__":
    unittest.main()
