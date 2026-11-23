"""Checks that the real program shuts down cleanly when asked to stop.

Run with:  python3 -m unittest discover tests

This is the one test that starts the whole of QuietNet, as a separate program on spare
ports with a throwaway data folder, and then stops it the way `docker stop` does. It is
skipped where the live-connection enforcer could really start (Linux, admin rights and
a firewall tool), so that a test run never touches the real network settings.
"""
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


def spare_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipIf(os.name == "nt", "signals work differently on Windows")
@unittest.skipIf(enforcer.Enforcer("127.0.0.1", dict, dict, log=lambda m: None).available(),
                 "the enforcer could start for real here; not touching the network from a test")
class Shutdown(unittest.TestCase):
    def start(self):
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
        deadline = time.time() + 15
        while time.time() < deadline:                       # wait until the dashboard answers
            try:
                socket.create_connection(("127.0.0.1", self.web_port), timeout=0.5).close()
                return proc
            except OSError:
                if proc.poll() is not None:
                    self.fail("QuietNet stopped during start-up:\n" + proc.stdout.read())
                time.sleep(0.1)
        self.fail("QuietNet did not start within 15 seconds")

    def stopped_with(self, signum):
        proc = self.start()
        proc.send_signal(signum)
        try:
            out, _ = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("QuietNet ignored the request to stop")
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
