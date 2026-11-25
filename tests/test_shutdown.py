"""Checks that the real program shuts down cleanly when asked to stop.

Run with:  python3 -m unittest discover tests

This is the one test that starts the whole of QuietNet, as a separate program on spare
ports with a throwaway data folder, and then stops it the way `docker stop` does. It is
skipped where the live-connection enforcer could really start (Linux, admin rights and
a firewall tool), so that a test run never touches the real network settings.
"""
import http.client
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import enforcer  # noqa: E402


# How long to leave the program alone, in seconds, between its first answer and the request
# to stop. See wait_until_the_dashboard_answers() for why a fixed pause is used here.
SETTLE = 0.5


def spare_port(kind=socket.SOCK_STREAM):
    """A port number that nothing is using at the moment."""
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipIf(os.name == "nt", "signals work differently on Windows")
@unittest.skipIf(enforcer.Enforcer("127.0.0.1", dict, dict, log=lambda m: None).available(),
                 "the enforcer could start for real here; not touching the network from a test")
class Shutdown(unittest.TestCase):
    def start(self):
        """Start the real program on spare ports with a throwaway data folder, and return it
        once it is ready to be asked to stop."""
        env = dict(os.environ, QUIETNET_DATA=tempfile.mkdtemp(prefix="quietnet-shutdown-test-"), PYTHONUNBUFFERED="1")
        env.pop("QUIETNET_CLOUD", None)
        env.pop("QUIETNET_PAIR", None)
        self.web_port = spare_port()
        proc = subprocess.Popen(
            # --no-device-names: the program must not send name questions onto the real network.
            [sys.executable, os.path.join(ROOT, "server.py"), "--no-browser", "--no-device-names",
             "--dns-port", str(spare_port(socket.SOCK_DGRAM)), "--web-port", str(self.web_port)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.addCleanup(proc.stdout.close)
        self.wait_until_the_dashboard_answers(proc)
        # A fixed pause, the one place where nothing better can be had. See the docstring below.
        time.sleep(SETTLE)
        return proc

    def wait_until_the_dashboard_answers(self, proc):
        """Wait until the program has answered one request to its dashboard, in full.

        This is the first of two waits before the program is asked to stop; the second is the
        short pause in start(). Each covers a moment in which the program does not handle a
        stop request properly. Both are faults in the program, listed under known issue 12 in
        docs/KNOWN_ISSUES.md, and neither is cured there yet.

        1. The dashboard's port takes connections from the moment the web server is made, which
           is a few lines before the program sets up its handling of a stop request and starts
           serving. A stop request sent in between ends the program at once, with no clean-up.
           On a slow machine a test that only waited for the port to open sent it there now and
           then. An answer can only come from the serving loop, which starts after all of that
           is in place, so this wait is past that gap.

        2. A stop request that arrives in the instant the program is taking a new connection
           can be lost altogether: the program carries on as if nothing had been asked. The
           answer to this very request reaches the test while the program's main thread may
           still be finishing that work, so a stop request sent the moment the answer arrives
           lands exactly there (about one start in 500 on a busy Linux machine). Nothing
           outside the program shows when its main thread is back to waiting, so start()
           pauses for SETTLE seconds after the answer. With a pause of 0.3 seconds none was
           lost in about 17,000 starts.

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
                    self.fail("QuietNet stopped during start-up:\n" + proc.stdout.read())
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
        """Fail the test because the program did not get as far as answering, and show what
        the program printed, which is the only clue to why.

        A program that has just died may not look ended yet, so it is given a few seconds to
        finish; then the failure says it stopped during start-up. One still running after that
        is ended here, so that all it printed can be read, and the failure says `why`."""
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            self.fail("%s. It was still running, and was ended. What it had printed:\n%s" % (why, out))
        self.fail("QuietNet stopped during start-up (exit code %s):\n%s" % (proc.returncode, out))

    def stopped_with(self, signum):
        """Start the program, send it the signal, and return its exit code and all it printed."""
        proc = self.start()
        proc.send_signal(signum)
        try:
            out, _ = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            # Known issue 12: a stop request can be lost. End the program so that what it
            # printed can be shown; a lost request leaves a line or two there that say so.
            proc.kill()
            out, _ = proc.communicate()
            self.fail("QuietNet ignored the request to stop: still running 20 seconds later, "
                      "and ended by this test. What it had printed:\n" + out)
        return proc.returncode, out

    def test_docker_stop_ends_the_program_cleanly(self):
        code, out = self.stopped_with(signal.SIGTERM)
        self.assertEqual(code, 0, out)
        self.assertIn("QuietNet is running.", out)
        self.assertIn("QuietNet stopped.", out)
        self.assertNotIn("Traceback", out)

    def test_the_program_can_be_started_without_asking_the_network_for_device_names(self):
        code, out = self.stopped_with(signal.SIGTERM)
        self.assertEqual(code, 0, out)
        self.assertNotIn("Device names:", out)

    def test_ctrl_c_ends_the_program_cleanly(self):
        code, out = self.stopped_with(signal.SIGINT)
        self.assertEqual(code, 0, out)
        self.assertIn("QuietNet stopped.", out)
        self.assertNotIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
