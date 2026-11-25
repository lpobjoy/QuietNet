"""Checks that the real program shuts down cleanly when asked to stop.

Run with:  python3 -m unittest discover tests

These are the tests that start the whole of QuietNet, as a separate program on spare ports
with a throwaway data folder, and then stop it the way `docker stop` or Ctrl-C does: once it
is serving, while it is still starting up, and while its dashboard is busy taking connections.
They are skipped where the live-connection enforcer could really start (Linux, admin rights
and a firewall tool), so that a test run never touches the real network settings.

How the program handles a stop request is tested piece by piece, with stand-ins, in
tests/test_start_stop.py.
"""
import http.client
import os
import random
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import enforcer  # noqa: E402


# How many times the busy-dashboard test starts and stops the program, how many clients keep
# opening connections to its dashboard while it does, and how many answers they must have had
# between them, as the sign that the dashboard really is busy, before the stop request is sent.
#
# Three clients and the one more connection the test opens make four at once, which is fewer
# than the five that Python's web server lets wait their turn. More than that and a Mac resets
# some of the connections; the dashboard then prints a traceback for each ("Broken pipe"), stop
# request or no stop request, and the test could not ask for an output free of tracebacks.
BUSY_ROUNDS = 20
BUSY_CLIENTS = 3
BUSY_ANSWERS = 30


def spare_port(kind=socket.SOCK_STREAM):
    """A port number that nothing is using at the moment."""
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipIf(os.name == "nt", "signals work differently on Windows")
@unittest.skipIf(enforcer.Enforcer("127.0.0.1", dict, dict, log=lambda m: None).available(),
                 "the enforcer could start for real here; not touching the network from a test")
class Shutdown(unittest.TestCase):
    def start(self, ready="answered"):
        """Start the real program on spare ports with a throwaway data folder, and return it at
        the moment named by `ready`:

        "answered"    its dashboard has answered a request in full, so it is up and serving
        "port open"   its dashboard's port takes a connection, which it does a few lines before
                      the program starts serving
        "first line"  it has printed its first line. Everything the program prints comes from
                      its start-up, and where these tests run the first line is the enforcer
                      saying it is off, so this is the middle of start-up: after the point where
                      a real enforcer would have started, before the dashboard's port is open

        What the program printed while this waited is kept in self.printed_so_far."""
        env = dict(os.environ, QUIETNET_DATA=tempfile.mkdtemp(prefix="quietnet-shutdown-test-"), PYTHONUNBUFFERED="1")
        env.pop("QUIETNET_CLOUD", None)
        env.pop("QUIETNET_PAIR", None)
        self.web_port = spare_port()
        self.printed_so_far = b""
        proc = subprocess.Popen(
            # --no-device-names: the program must not send name questions onto the real network.
            [sys.executable, os.path.join(ROOT, "server.py"), "--no-browser", "--no-device-names",
             "--dns-port", str(spare_port(socket.SOCK_DGRAM)), "--web-port", str(self.web_port)],
            # bufsize=0: what this test reads itself and what communicate() reads later then
            # come straight from the one pipe, and nothing is left behind in a buffer between.
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.addCleanup(proc.stdout.close)
        if ready == "first line":
            self.wait_until_the_first_line_is_printed(proc)
        elif ready == "port open":
            self.wait_until_the_port_is_open(proc)
        else:
            self.wait_until_the_dashboard_answers(proc)
        return proc

    def wait_until_the_first_line_is_printed(self, proc):
        """Wait until the program has printed one whole line, and keep it in self.printed_so_far."""
        deadline = time.time() + 30
        while b"\n" not in self.printed_so_far:
            readable, _, _ = select.select([proc.stdout], [], [], max(deadline - time.time(), 0))
            if not readable:
                self.give_up(proc, "QuietNet printed nothing within 30 seconds")
            more = os.read(proc.stdout.fileno(), 4096)
            if not more:
                self.give_up(proc, "QuietNet closed its output before printing a line")
            self.printed_so_far += more

    def wait_until_the_port_is_open(self, proc):
        """Wait only until the dashboard's port takes a connection, and close that connection
        without asking anything."""
        deadline = time.time() + 30
        while True:
            try:
                socket.create_connection(("127.0.0.1", self.web_port), timeout=1).close()
                return
            except OSError:
                if proc.poll() is not None:
                    self.give_up(proc, "QuietNet stopped during start-up")
                if time.time() > deadline:
                    self.give_up(proc, "QuietNet did not open its dashboard's port within 30 seconds")
                time.sleep(0.01)

    def wait_until_the_dashboard_answers(self, proc):
        """Wait until the program has answered one request to its dashboard, in full.

        The dashboard's port takes connections from the moment the web server is made, a few
        lines before the program starts serving. An answer can only come from the serving loop,
        so this is the wait for "up and running". The stop request that follows is sent the
        moment the answer arrives, with no pause: the program's main thread may then still be
        tidying that connection away, which is one of the two moments at which a stop request
        used to go wrong (known issue 12, fixed). The other, during start-up, has tests below.

        The request is sent once and then waited for: a request given up on would be found
        later by the program, answered to nobody, and could put an error into its output."""
        deadline = time.time() + 30
        while True:
            conn = http.client.HTTPConnection("127.0.0.1", self.web_port, timeout=max(deadline - time.time(), 1))
            try:
                conn.connect()
            except OSError:                                 # the port is not open yet
                conn.close()
                if proc.poll() is not None:
                    self.give_up(proc, "QuietNet stopped during start-up")
                if time.time() > deadline:
                    self.give_up(proc, "QuietNet did not open its dashboard's port within 30 seconds")
                time.sleep(0.05)
                continue
            try:
                # The dashboard refuses any Host but this computer's own name.
                conn.request("GET", "/api/services", headers={"Host": "localhost"})
                answer = conn.getresponse()
                answer.read()
            except socket.timeout:
                self.give_up(proc, "QuietNet's dashboard did not answer within 30 seconds")
            except (OSError, http.client.HTTPException) as e:
                # Most often the program has died: its end closes the connection, and that
                # reaches this test a moment before the program can be seen to have ended.
                self.give_up(proc, "QuietNet's dashboard dropped the connection without answering (%r)" % (e,))
            finally:
                conn.close()
            if answer.status != 200:
                self.give_up(proc, "QuietNet's dashboard answered %s, not 200" % answer.status)
            return

    def give_up(self, proc, why):
        """Fail the test because the program did not get as far as it should have, and show
        what the program printed, which is the only clue to why.

        A program that has just died may not look ended yet, so it is given a few seconds to
        finish; then the failure says it stopped during start-up. One still running after that
        is ended here, so that all it printed can be read, and the failure says `why`."""
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            self.fail("%s. It was still running, and was ended. What it had printed:\n%s" % (why, self.all_printed(out)))
        self.fail("QuietNet stopped during start-up (exit code %s):\n%s" % (proc.returncode, self.all_printed(out)))

    def all_printed(self, rest):
        """Everything the program printed, as text: what a wait read, then the rest."""
        return (self.printed_so_far + rest).decode("utf-8", "replace")

    def ended(self, proc):
        """Wait for a program that has been asked to stop, and return its exit code and all it
        printed. Fail if it is still running 20 seconds later."""
        try:
            out, _ = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            # End the program so that what it printed can be shown.
            proc.kill()
            out, _ = proc.communicate()
            self.fail("QuietNet ignored the request to stop: still running 20 seconds later, "
                      "and ended by this test. What it had printed:\n" + self.all_printed(out))
        return proc.returncode, self.all_printed(out)

    def stopped_with(self, signum, ready="answered"):
        """Start the program, send it the signal at the moment named by `ready` (see start()),
        and return its exit code and all it printed."""
        proc = self.start(ready)
        proc.send_signal(signum)
        return self.ended(proc)

    def assert_clean(self, code, out):
        """The three marks of a clean stop: exit code 0, the last line, and no Python traceback."""
        self.assertEqual(code, 0, out)
        self.assertIn("QuietNet stopped.", out)
        self.assertNotIn("Traceback", out)

    def test_docker_stop_ends_the_program_cleanly(self):
        code, out = self.stopped_with(signal.SIGTERM)
        self.assert_clean(code, out)
        self.assertIn("QuietNet is running.", out)

    def test_the_program_can_be_started_without_asking_the_network_for_device_names(self):
        code, out = self.stopped_with(signal.SIGTERM)
        self.assertEqual(code, 0, out)
        self.assertNotIn("Device names:", out)

    def test_ctrl_c_ends_the_program_cleanly(self):
        code, out = self.stopped_with(signal.SIGINT)
        self.assert_clean(code, out)

    def test_docker_stop_during_start_up_ends_the_program_cleanly(self):
        """The start-up gap of known issue 12: the request used to end the program on the
        spot, with no clean-up, although the enforcer could already be steering devices."""
        code, out = self.stopped_with(signal.SIGTERM, ready="first line")
        self.assert_clean(code, out)

    def test_ctrl_c_during_start_up_ends_the_program_cleanly(self):
        code, out = self.stopped_with(signal.SIGINT, ready="first line")
        self.assert_clean(code, out)

    def test_a_stop_request_the_moment_the_port_opens_ends_the_program_cleanly(self):
        """The last lines of start-up: the port is open and the program is not yet serving."""
        code, out = self.stopped_with(signal.SIGTERM, ready="port open")
        self.assert_clean(code, out)

    def keep_asking(self, done, answers):
        """One client of the busy dashboard: open a connection, ask, read the answer, note it
        in `answers`, close, and again, until told it is done. Errors are expected once the
        program is stopping."""
        while not done.is_set():
            conn = http.client.HTTPConnection("127.0.0.1", self.web_port, timeout=5)
            try:
                conn.request("GET", "/api/services", headers={"Host": "localhost"})
                conn.getresponse().read()
                answers.append(1)
            except (OSError, http.client.HTTPException):
                done.wait(0.001)
            finally:
                conn.close()

    def wait_until_the_dashboard_is_busy(self, proc, answers):
        """Wait until the clients have had BUSY_ANSWERS answers between them."""
        deadline = time.time() + 30
        while len(answers) < BUSY_ANSWERS:
            if proc.poll() is not None or time.time() > deadline:
                self.give_up(proc, "QuietNet's dashboard gave only %d answers in 30 seconds" % len(answers))
            time.sleep(0.001)

    def stop_as_a_connection_is_taken(self, proc, signum):
        """Open one more connection and send the stop request at a moment picked at random
        around it: just as the connection is made, as the request has gone, or as the answer
        has come back. Those are the moments at which the program's main thread is starting
        the thread that answers this connection, or tidying it away."""
        moment = random.choice(("connected", "asked", "answered"))
        conn = http.client.HTTPConnection("127.0.0.1", self.web_port, timeout=5)
        sent = False
        try:
            conn.connect()
            if moment != "connected":
                conn.request("GET", "/api/services", headers={"Host": "localhost"})
            if moment == "answered":
                conn.getresponse().read()
            spin_until = time.perf_counter() + random.uniform(0, 0.0002)
            while time.perf_counter() < spin_until:
                pass
            proc.send_signal(signum)
            sent = True
            if moment == "connected":
                conn.request("GET", "/api/services", headers={"Host": "localhost"})
            if moment != "answered":
                conn.getresponse().read()
        except (OSError, http.client.HTTPException):
            pass                            # the program stopping can cut this very connection off
        finally:
            conn.close()
        if not sent:
            proc.send_signal(signum)

    def test_a_stop_request_while_the_dashboard_is_busy_taking_connections_is_acted_on(self):
        """The lost request of known issue 12: a stop request that arrived in the instant the
        dashboard was taking a connection could vanish, and the program carried on serving.

        Each round starts the program, keeps a few clients opening connections to its
        dashboard as fast as they can, and sends the stop request (docker stop's signal and
        Ctrl-C's by turns) just as one more connection is opened. Every round must end cleanly.

        This is a guard, not a proof. The instant is a few millionths of a second long, and the
        program as it was before the fix lost the request, or stopped with a traceback, in
        about one such round in 150 on a Mac and one in 400 in a Linux container; so these
        rounds would have caught it only now and then (about one run of this test in ten). The fix was measured over thousands of
        rounds with the same steps (docs/KNOWN_ISSUES.md has the numbers)."""
        for n in range(BUSY_ROUNDS):
            signum = (signal.SIGTERM, signal.SIGINT)[n % 2]
            proc = self.start()
            done, answers = threading.Event(), []
            clients = [threading.Thread(target=self.keep_asking, args=(done, answers), daemon=True)
                       for _ in range(BUSY_CLIENTS)]
            for client in clients:
                client.start()
            try:
                self.wait_until_the_dashboard_is_busy(proc, answers)
                self.stop_as_a_connection_is_taken(proc, signum)
                code, out = self.ended(proc)
            finally:
                done.set()
                for client in clients:
                    client.join(30)
            with self.subTest(round=n + 1, signal=signum.name):
                self.assert_clean(code, out)


if __name__ == "__main__":
    unittest.main()
