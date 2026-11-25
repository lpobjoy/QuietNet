"""Checks that the real program shuts down cleanly when asked to stop.

Run with:  python3 -m unittest discover tests

These are the tests that start the whole of QuietNet, as a separate program on spare ports
with a throwaway data folder, and then stop it the way `docker stop` or Ctrl-C does: once it
is serving, while it is still starting up, while its dashboard is busy taking connections, and
while it has lookups in hand that the internet is not answering.
They are skipped where the live-connection enforcer could really start (Linux, admin rights
and a firewall tool), so that a test run never touches the real network settings.

How the program handles a stop request is tested piece by piece, with stand-ins, in
tests/test_start_stop.py.
"""
import http.client
import os
import random
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

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


# Starts the program just as `python server.py` does, but with the internet's DNS servers
# replaced by a stand-in on this computer, tried 24 times over. Each try waits two and a half
# seconds for an answer, so a lookup the stand-in never answers stays in hand for a minute.
# Run with: the repository's folder, the stand-in's port, then the program's own arguments.
WITH_A_STAND_IN_INTERNET = ("import sys; sys.path.insert(0, sys.argv.pop(1)); import server; "
                            "server.UPSTREAMS = [('127.0.0.1', int(sys.argv.pop(1)))] * 24; server.main()")


def spare_port(kind=socket.SOCK_STREAM):
    """A port number that nothing is using at the moment."""
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def spare_dns_port():
    """A port number that nothing is using for UDP or for TCP: the DNS filter opens both on
    the one number, and a port that is spare for one is now and then taken for the other."""
    for _ in range(50):
        port = spare_port(socket.SOCK_DGRAM)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))               # just as the filter opens it; nothing listens
            return port
        except OSError:
            continue
    return port


def question(name):
    """A DNS question for the IPv4 address of `name`, as a device would send it."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"


class SomethingElse(BaseHTTPRequestHandler):
    """Another program's web server, for the test of a port that is taken: it answers every
    request "not found"."""

    def do_GET(self):
        """Answer "not found"."""
        self.send_error(404)

    def log_message(self, *args):
        """Keep the test output free of request lines."""


class PortTaken(AssertionError):
    """The program could not start because a port found free for it a moment earlier was in
    use by the time it came to open it. Nothing is wrong with the program: see start()."""


@unittest.skipIf(os.name == "nt", "signals work differently on Windows")
@unittest.skipIf(enforcer.Enforcer("127.0.0.1", dict, dict, log=lambda m: None).available(),
                 "the enforcer could start for real here; not touching the network from a test")
class Shutdown(unittest.TestCase):
    def setUp(self):
        """See ctrl_c_not_ignored()."""
        self.ctrl_c_not_ignored()

    def ctrl_c_not_ignored(self):
        """Make sure the program is started as it would be from a terminal, able to hear Ctrl-C.

        A program inherits "ignore Ctrl-C's signal" from the one that starts it, and QuietNet,
        like Python itself, leaves the signal ignored if it starts that way. A test run has it
        ignored when a script or a shell without a terminal starts it in the background (with
        "&"); the Ctrl-C tests then failed with "QuietNet ignored the request to stop", which
        was true and no fault. A signal that this test program handles itself is not inherited
        as ignored, so for the length of a test it is given Python's usual handler."""
        if signal.getsignal(signal.SIGINT) == signal.SIG_IGN:
            signal.signal(signal.SIGINT, signal.default_int_handler)
            self.addCleanup(signal.signal, signal.SIGINT, signal.SIG_IGN)

    def start(self, ready="answered", internet=None):
        """Start the real program on spare ports with a throwaway data folder, and return it at
        the moment named by `ready` (see launch() for `internet`):

        "answered"    its dashboard has answered a request in full, so it is up and serving
        "port open"   its dashboard's port takes a connection, which it does a few lines before
                      the program starts serving
        "loading"     Python is part of the way through loading the program: it has finished
                      loading `argparse`, the first of the many parts of Python that server.py
                      asks for after the lines at its top that begin the listening. Python is
                      told to print a line as it loads each part (-X importtime), which is how
                      the moment is seen from outside. The program has run none of its own
                      start-up yet
        "first line"  it has printed its first line. Everything the program prints comes from
                      its start-up, and where these tests run the first line is the enforcer
                      saying it is off, so this is the middle of start-up: after the point where
                      a real enforcer would have started, before the dashboard's port is open

        What the program printed while this waited is kept in self.printed_so_far.

        A spare port is found by opening one and closing it again, and the program opens it a
        moment later. Now and then something else on the computer has taken it in between
        (seen on a Mac that was short of spare ports, with several test runs going at once),
        and the program stops with "Address already in use". Such a start is tried once more,
        on fresh ports. So is one that needs its DNS filter (a start with `internet`) and found
        the filter's port taken, which the program reports and carries on without."""
        for another_try in (True, False):
            proc = self.launch(internet, python_options=["-X", "importtime"] if ready == "loading" else [])
            try:
                if ready == "loading":
                    self.wait_until_it_has_printed(proc, rb"\| +argparse\n")
                elif ready == "first line":
                    self.wait_until_the_first_line_is_printed(proc)
                elif ready == "port open":
                    self.wait_until_the_port_is_open(proc)
                else:
                    self.wait_until_the_dashboard_answers(proc)
                if internet:
                    self.the_filter_must_have_started(proc)
                return proc
            except PortTaken:
                if not another_try:
                    raise

    def the_filter_must_have_started(self, proc):
        """Read what the program has printed so far, without waiting for more, and fail with
        PortTaken if it says the DNS filter's port could not be opened. Everything the program
        prints comes from its start-up, so by the time its dashboard answers it is all there
        to be read. The program is ended first, since start() will start another."""
        while select.select([proc.stdout], [], [], 0)[0]:
            more = os.read(proc.stdout.fileno(), 4096)
            if not more:
                break
            self.printed_so_far += more
        if b"Could not start the filter on port" in self.printed_so_far:
            proc.kill()
            out, _ = proc.communicate()
            raise PortTaken("QuietNet could not open its DNS filter's port:\n" + self.all_printed(out))

    def launch(self, internet=None, python_options=()):
        """Start the real program on spare ports with a throwaway data folder, which is removed
        again when the test is over, and return it without waiting for anything.

        `internet` is the port of a stand-in, on this computer, for the internet's DNS servers.
        Without it the program is started exactly as it is by hand; these tests then send it
        no lookups, so it never asks the real ones. `python_options` are extra options for
        Python itself."""
        self.data_folder = tempfile.mkdtemp(prefix="quietnet-shutdown-test-")
        self.addCleanup(shutil.rmtree, self.data_folder, True)      # runs after the program has been ended
        env = dict(os.environ, QUIETNET_DATA=self.data_folder, PYTHONUNBUFFERED="1")
        env.pop("QUIETNET_CLOUD", None)
        env.pop("QUIETNET_PAIR", None)
        self.web_port, self.dns_port = spare_port(), spare_dns_port()
        self.printed_so_far = b""
        program = [sys.executable] + list(python_options) + [os.path.join(ROOT, "server.py")]
        if internet:
            program = [sys.executable, "-c", WITH_A_STAND_IN_INTERNET, ROOT, str(internet)]
        proc = subprocess.Popen(
            # --no-device-names: the program must not send name questions onto the real network.
            program + ["--no-browser", "--no-device-names",
                       "--dns-port", str(self.dns_port), "--web-port", str(self.web_port)],
            # bufsize=0: what this test reads itself and what communicate() reads later then
            # come straight from the one pipe, and nothing is left behind in a buffer between.
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.addCleanup(proc.stdout.close)
        return proc

    def wait_until_the_first_line_is_printed(self, proc):
        """Wait until the program has printed one whole line, and keep it in self.printed_so_far."""
        self.wait_until_it_has_printed(proc, rb"\n")

    def wait_until_it_has_printed(self, proc, pattern):
        """Wait until what the program has printed holds a match for `pattern`, keeping all of
        it in self.printed_so_far."""
        deadline = time.time() + 30
        while not re.search(pattern, self.printed_so_far):
            readable, _, _ = select.select([proc.stdout], [], [], max(deadline - time.time(), 0))
            if not readable:
                self.give_up(proc, "QuietNet had not printed %r within 30 seconds" % pattern)
            more = os.read(proc.stdout.fileno(), 4096)
            if not more:
                self.give_up(proc, "QuietNet closed its output before printing %r" % pattern)
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
        is ended here, so that all it printed can be read, and the failure says `why`.

        A program that stopped because a port was in use fails with PortTaken, which start()
        answers with one more try."""
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            self.fail("%s. It was still running, and was ended. What it had printed:\n%s" % (why, self.all_printed(out)))
        printed = self.all_printed(out)
        kind = PortTaken if "Address already in use" in printed else self.failureException
        raise kind("QuietNet stopped during start-up (exit code %s):\n%s" % (proc.returncode, printed))

    def all_printed(self, rest):
        """Everything the program printed, as text: what a wait read, then the rest."""
        return (self.printed_so_far + rest).decode("utf-8", "replace")

    def ended(self, proc, complaint="QuietNet ignored the request to stop"):
        """Wait for a program that has been asked to stop, and return its exit code and all it
        printed. Fail with the `complaint` if it is still running 20 seconds later."""
        try:
            out, _ = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            # End the program so that what it printed can be shown.
            proc.kill()
            out, _ = proc.communicate()
            self.fail(complaint + ": still running 20 seconds later, "
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

    def test_docker_stop_while_the_program_is_still_loading_ends_it_cleanly(self):
        """The program listens from the top of its file, before it loads the parts of Python it
        uses, which takes most of the time before its own start-up begins. Until it did, a
        request in that time ended it on the spot; in its container, where it is the first
        process, Linux dropped the request altogether and Docker killed it 20 seconds later.

        The request is sent part of the way through the loading. Should this test be held up
        for a tenth of a second at that moment the request arrives during start-up instead,
        which must be just as clean; so that is all that is asked here."""
        code, out = self.stopped_with(signal.SIGTERM, ready="loading")
        self.assert_clean(code, out)

    def test_ctrl_c_while_the_program_is_still_loading_ends_it_cleanly(self):
        """Left to Python, Ctrl-C at this moment is raised as an exception inside whatever was
        being loaded: a traceback, or with Python 3.9 sometimes nothing at all, the request
        swallowed by Python's own library and the program carrying on."""
        code, out = self.stopped_with(signal.SIGINT, ready="loading")
        self.assert_clean(code, out)

    def test_a_stop_request_the_moment_the_port_opens_ends_the_program_cleanly(self):
        """The last lines of start-up: the port is open and the program is about to serve, or
        has just begun to.

        A plain check that a stop at this moment is clean, and no more. It cannot be relied on
        to land before the serving begins, and it did not show the fault that was fixed: the
        program as it was failed it once in 1,080 runs. The test that pins the moment down is
        in tests/test_start_stop.py (a stop request just as the dashboard's port opens)."""
        code, out = self.stopped_with(signal.SIGTERM, ready="port open")
        self.assert_clean(code, out)

    def test_ctrl_c_ends_the_program_when_the_test_run_itself_has_ctrl_c_ignored(self):
        """As when a script starts the tests in the background: see ctrl_c_not_ignored()."""
        self.addCleanup(signal.signal, signal.SIGINT, signal.getsignal(signal.SIGINT))
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.ctrl_c_not_ignored()
        code, out = self.stopped_with(signal.SIGINT)
        self.assert_clean(code, out)

    def test_the_throwaway_data_folder_is_removed_when_the_test_is_over(self):
        """Each start makes a folder of about a quarter of a megabyte, and these tests make
        thirty starts a run. They used to be left behind in the computer's temporary folder."""
        code, out = self.stopped_with(signal.SIGTERM)
        self.assertTrue(os.path.isdir(self.data_folder))
        self.doCleanups()
        self.assertFalse(os.path.exists(self.data_folder))

    def test_a_start_that_finds_its_port_taken_is_tried_once_more_on_fresh_ports(self):
        """See start(). The first port found for the dashboard is taken here by another web
        server, run by this test, before the program can open it."""
        other = HTTPServer(("127.0.0.1", 0), SomethingElse)
        self.addCleanup(other.server_close)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        self.addCleanup(other.shutdown)
        taken = [other.server_address[1]]
        asked_for = []

        def taken_the_first_time(kind=socket.SOCK_STREAM):
            """The held port for the first dashboard, and truly spare ports after that."""
            asked_for.append(kind)
            return taken.pop() if taken and kind == socket.SOCK_STREAM else really_spare(kind)
        really_spare = spare_port
        with mock.patch.object(sys.modules[__name__], "spare_port", taken_the_first_time):
            proc = self.start()
        proc.send_signal(signal.SIGTERM)
        code, out = self.ended(proc)
        self.assert_clean(code, out)
        self.assertEqual(len(asked_for), 4)                 # two ports for each of two starts
        self.assertNotEqual(self.web_port, other.server_address[1])

    def test_a_start_that_needs_the_dns_filter_is_tried_once_more_when_the_filters_port_was_taken(self):
        """See start(). The first port found for the filter is taken here, for TCP, by another
        web server made by this test; the program says so and carries on without its filter,
        which would leave a test that sends it lookups waiting for ever.

        The other web server takes the port on every address of this computer, as the filter
        does, because a Mac lets the filter open a port that is taken on one address only. It
        is never set serving."""
        other = HTTPServer(("0.0.0.0", 0), SomethingElse)
        self.addCleanup(other.server_close)
        taken = [other.server_address[1]]
        ports = []

        def taken_the_first_time():
            """The held port for the first filter, and a truly spare one after that."""
            ports.append(taken.pop() if taken else really_spare())
            return ports[-1]
        really_spare = spare_dns_port
        internet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(internet.close)
        internet.bind(("127.0.0.1", 0))
        with mock.patch.object(sys.modules[__name__], "spare_dns_port", taken_the_first_time):
            proc = self.start(internet=internet.getsockname()[1])
        proc.send_signal(signal.SIGTERM)
        code, out = self.ended(proc)
        self.assert_clean(code, out)
        self.assertEqual(len(ports), 2)
        self.assertNotIn("Could not start the filter", out)

    def test_lookups_still_in_hand_do_not_hold_up_the_end_of_the_program(self):
        """With the internet down, a lookup waits in the program for an answer that is not
        coming. Python used to wait, as the program ended, for every such lookup to give up:
        up to 20 seconds after "QuietNet stopped." had been printed, which is as long as Docker
        waits before it kills a program, and with a traceback if another lookup arrived
        meanwhile.

        Here the internet is a stand-in that never answers, and each lookup would wait a minute
        for it. Three are sent, and once the stand-in has been asked all three, so that each
        is in hand, the program is asked to stop. It must end within the usual 20 seconds,
        with nothing printed after its last line."""
        internet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(internet.close)
        internet.bind(("127.0.0.1", 0))
        internet.settimeout(30)
        proc = self.start(internet=internet.getsockname()[1])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as device:
            for n in range(3):
                device.sendto(question("lookup-%d.quietnet-test.example.com" % n), ("127.0.0.1", self.dns_port))
            for n in range(3):
                try:
                    internet.recvfrom(512)
                except socket.timeout:
                    self.give_up(proc, "QuietNet passed only %d of 3 lookups on within 30 seconds" % n)
            proc.send_signal(signal.SIGTERM)
            code, out = self.ended(proc, "QuietNet did not end while it had lookups in hand")
        self.assert_clean(code, out)
        self.assertTrue(out.endswith("QuietNet stopped.\n"), out)

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
