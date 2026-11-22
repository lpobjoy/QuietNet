"""Checks for the Pi's outbound link to the relay (cloud_agent.py).

Run with:  python3 -m unittest discover tests

Standard library only. A pretend relay and a pretend local dashboard are started on
spare ports on this computer; nothing leaves this machine.
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cloud_agent  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
