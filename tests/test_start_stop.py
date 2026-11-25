"""Checks for how server.py starts and stops: the handling of a stop request (StopRequest), and
the order of start_up(), serving and clean_up() in run().

Run with:  python3 -m unittest discover tests

Everything here runs inside the test program, with stand-ins for the enforcer, the cloud link
and the listeners, so nothing touches the network or its settings. A stop request is sent the
way `docker stop` and Ctrl-C send one, as a signal, but to the test program itself and only
while QuietNet's own handling is in place; the handling that was there before is put back
after every test. tests/test_shutdown.py does the same from outside, with the whole program.
"""
import contextlib
import http.client
import io
import os
import signal
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_quietnet import Base, server

STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)


def nothing(*args, **kwargs):
    """Stands in for a part of start-up that these tests have no use for."""


def ask_to_stop(signum=signal.SIGTERM):
    """Send this test program the signal and return once Python has run QuietNet's handler for it.

    Refuses unless QuietNet's handler is the one in place: with Python's own handling, SIGTERM
    would end the whole test run and Ctrl-C's signal would raise KeyboardInterrupt in it."""
    handler = signal.getsignal(signum)
    if getattr(handler, "__func__", None) is not server.StopRequest.note:
        raise AssertionError("QuietNet is not listening for %s: %r is in place" % (signum.name, handler))
    try:
        signal.raise_signal(signum)
        # Python runs the handler at the main thread's next pause between instructions, which is
        # almost always before the line above returns. Wait for the thing itself all the same.
        deadline = time.monotonic() + 10
        while not handler.__self__.asked and time.monotonic() < deadline:
            time.sleep(0.001)
    except BaseException as e:          # KeyboardInterrupt too: it would end the whole test run
        raise AssertionError("the handler raised %r" % (e,))
    if not handler.__self__.asked:
        raise AssertionError("the handler did not run within 10 seconds")


class SignalsPutBack(unittest.TestCase):
    """Shared steps for tests that let QuietNet set its handling of stop requests in the test
    program: start from Python's ordinary handling, and put back what was there afterwards."""

    def setUp(self):
        """Remember how both signals are handled now, and give Ctrl-C Python's usual handler, so
        the tests behave the same when the run was started in the background (where a shell has
        Ctrl-C's signal ignored)."""
        super().setUp()
        for signum in STOP_SIGNALS:
            self.addCleanup(signal.signal, signum, signal.getsignal(signum))
        signal.signal(signal.SIGINT, signal.default_int_handler)


class Handler(SignalsPutBack):
    """StopRequest alone: what its handler does, and how serving ends."""

    def setUp(self):
        """A StopRequest whose pipe is closed again after the test."""
        super().setUp()
        self.stop = server.StopRequest()
        self.addCleanup(self.close_pipe)

    def close_pipe(self):
        """Close both ends of the StopRequest's pipe. A test may have closed one already."""
        for end in (self.stop._read, self.stop._write):
            try:
                os.close(end)
            except OSError:
                pass

    def note(self):
        """Call the handler as Python would for a signal. Anything it raises fails the test
        here: left alone, a KeyboardInterrupt from it would end the whole test run."""
        try:
            return self.stop.note(signal.SIGTERM, None)
        except BaseException as e:
            self.fail("the handler raised %r" % (e,))

    def web_server(self):
        """A real web server on a spare port that answers every GET with 200, not yet serving."""
        class Hello(server.BaseHTTPRequestHandler):
            """Answers "hello" to anything."""

            def do_GET(self):
                """Send the one answer."""
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"hello")

            def log_message(self, *args):
                """Keep the test output free of request lines."""

        web = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
        web.daemon_threads = True
        self.addCleanup(web.server_close)
        return web

    def serve_with_a_time_limit(self, web):
        """Run stop.serve(web) in this thread. Should it still be serving 30 seconds later, end
        it from outside and fail, so that a fault here cannot hang the whole test run."""
        gave_up = []

        def give_up():
            """End the serving loop and note that it had to be done."""
            gave_up.append(True)
            web.shutdown()
        limit = threading.Timer(30, give_up)
        limit.daemon = True
        limit.start()
        try:
            self.stop.serve(web)
        finally:
            limit.cancel()
        self.assertFalse(gave_up, "serving did not end within 30 seconds of the stop request")

    def test_nothing_is_asked_until_a_request_arrives(self):
        self.assertFalse(self.stop.asked)

    def test_a_stop_request_is_remembered_and_the_handler_raises_nothing(self):
        self.assertIsNone(self.note())
        self.assertTrue(self.stop.asked)

    def test_the_handler_raises_nothing_when_its_pipe_cannot_be_written(self):
        os.close(self.stop._write)
        self.assertIsNone(self.note())
        self.assertTrue(self.stop.asked)

    def test_the_handler_calls_nothing_but_one_write_to_its_pipe(self):
        """The handler runs in the main thread, in between two steps of whatever that thread was
        doing. A call to almost anything else (print, a log, threading.Event.set) can take a
        lock the main thread is already holding, and then wait for ever. So: every call made
        while the handler runs is recorded, and there must be the one write and nothing more."""
        calls = []

        def record(frame, event, arg):
            """Note each Python function entered and each built-in function called."""
            if event == "call":
                calls.append(frame.f_code.co_name)
            elif event == "c_call":
                calls.append(arg.__name__)
        sys.setprofile(record)
        try:
            self.stop.note(signal.SIGTERM, None)
        except BaseException as e:
            self.fail("the handler raised %r" % (e,))
        finally:
            sys.setprofile(None)
        self.assertEqual([c for c in calls if c != "setprofile"], ["note", "write"])

    def test_the_handler_refers_to_nothing_that_could_take_a_lock(self):
        """The same guard from the other side, for what a recording of calls can miss (a "with"
        on a lock is not a call): the names the handler's code uses are these and no others."""
        self.assertEqual(set(server.StopRequest.note.__code__.co_names), {"asked", "os", "write", "_write", "OSError"})

    def test_a_request_made_again_writes_no_second_byte(self):
        """So the pipe can never fill up, however many times someone asks."""
        for _ in range(3):
            self.note()
        os.set_blocking(self.stop._read, False)
        self.assertEqual(os.read(self.stop._read, 10), b"!")

    def test_listening_notes_the_signal_docker_stop_sends(self):
        self.stop.listen()
        ask_to_stop(signal.SIGTERM)
        self.assertTrue(self.stop.asked)

    def test_listening_notes_ctrl_c(self):
        self.stop.listen()
        ask_to_stop(signal.SIGINT)
        self.assertTrue(self.stop.asked)

    def test_ctrl_c_stays_ignored_if_it_was_ignored_when_the_program_started(self):
        """A shell has Ctrl-C's signal ignored in a program it puts in the background."""
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.stop.listen()
        self.assertEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
        self.assertEqual(signal.getsignal(signal.SIGTERM), self.stop.note)

    def test_ignoring_turns_both_signals_off(self):
        self.stop.listen()
        self.stop.ignore()
        for signum in STOP_SIGNALS:
            self.assertEqual(signal.getsignal(signum), signal.SIG_IGN, signum.name)

    def test_serving_ends_when_a_stop_is_asked_for(self):
        web = self.web_server()
        answers = []

        def ask_then_stop():
            """Wait for the dashboard's answer, which shows it is serving, then ask it to stop."""
            conn = http.client.HTTPConnection("127.0.0.1", web.server_address[1], timeout=30)
            conn.request("GET", "/")
            answers.append(conn.getresponse().read())
            conn.close()
            self.note()
        client = threading.Thread(target=ask_then_stop, daemon=True)
        client.start()
        self.serve_with_a_time_limit(web)
        client.join(30)
        self.assertEqual(answers, [b"hello"])

    def test_there_is_no_serving_at_all_when_the_stop_was_asked_for_before_it_began(self):
        """Once the serving loop has begun it can take a moment to notice that it should finish,
        so a request already noted must mean that it never begins."""
        web = mock.Mock()
        self.note()
        self.stop.serve(web)
        web.serve_forever.assert_not_called()

    def test_serving_still_ends_when_the_request_comes_before_the_loop_has_begun(self):
        """The instant between serve() finding nothing asked and the serving loop starting: the
        request's byte waits in the pipe for the helper thread, which ends the loop."""
        web = self.web_server()
        begin = web.serve_forever

        def asked_just_before_the_loop_begins(**how):
            """Note a stop request, as the handler would, then start the real serving loop."""
            self.note()
            begin(**how)
        web.serve_forever = asked_just_before_the_loop_begins
        self.serve_with_a_time_limit(web)

    def test_an_idle_dashboard_looks_for_the_request_to_finish_at_least_ten_times_a_second(self):
        """Python's serving loop notices that it has been told to finish only when it next looks,
        and left alone it looks twice a second: a stop with nobody using the dashboard then took
        up to half a second, where before the fix it had taken a hundredth."""
        web = mock.Mock()
        self.stop.serve(web)
        web.serve_forever.assert_called_once()
        self.assertLessEqual(web.serve_forever.call_args[1]["poll_interval"], 0.1)
        # Let the helper thread go before the pipe it is reading is closed.
        self.note()
        deadline = time.monotonic() + 30
        while not web.shutdown.called and time.monotonic() < deadline:
            time.sleep(0.001)
        web.shutdown.assert_called_once_with()


class StandIn:
    """A stand-in for the enforcer or the cloud link: writes down, in a list shared with the
    test, that it was made, started and stopped, and runs anything the test gave it to do at
    each of those moments (`during`, keyed by "start" or "stop")."""

    def __init__(self, name, diary, during):
        """Note the making."""
        self.name, self.diary, self.during = name, diary, during
        self.reason = "a stand-in"
        diary.append(name + " made")

    def available(self):
        """The enforcer is asked this for the start-up lines; say no, as on a Mac."""
        return False

    def start(self):
        """Do what the test asked for at this moment, then note the start."""
        self.during.get("start", lambda: None)()
        self.diary.append(self.name + " started")

    def stop(self):
        """Do what the test asked for at this moment, then note the stop."""
        self.during.get("stop", lambda: None)()
        self.diary.append(self.name + " stopped")


class BrowserTimer:
    """A stand-in for the timer that opens the dashboard in a browser half a second after
    start-up: it opens nothing, and writes in the diary that it was set and that it was called
    off."""

    def __init__(self, url, diary):
        """Note that the timer was set, and for which address."""
        self.diary = diary
        diary.append("browser set to open " + url)

    def cancel(self):
        """Note that the timer was called off."""
        self.diary.append("browser called off")


class Dashboard(ThreadingHTTPServer):
    """The real dashboard web server, on a spare port, that writes in the diary when its
    serving loop begins."""
    daemon_threads = True

    def serve_forever(self, poll_interval=0.5):
        """Note that serving has begun, then serve as usual."""
        self.diary.append("dashboard serving")
        super().serve_forever(poll_interval)


# The names start_up() and clean_up() use that start nothing by themselves: the program's
# settings and what it holds in memory, the modules whose classes have stand-ins, and the methods
# called on the stand-ins. Every other name those two functions use must have a stand-in in
# WholeLife.setUp (see the test near the end of WholeLife).
STARTS_NOTHING = {
    "S", "local_ip", "dns_error", "dns_port", "DATA", "enforcement_plan", "neighbours", "learn_enforced_mac",
    "web_port", "no_browser", "no_device_names", "asked", "print", "Web",
    "threading", "Thread", "enforcer", "cloud_agent",
    "start", "stop", "cancel", "available", "reason", "start_listeners",
}


class WholeLife(SignalsPutBack, Base):
    """run() with the real start_up() and clean_up(), and stand-ins for everything they start.

    `self.diary` lists what happened, in order. A test says what should happen while a stand-in
    starts or stops, or as the dashboard's port is opened, such as a stop request arriving, by
    filling `self.enforcer_does`, `self.cloud_does`, `self.listeners_do` or `self.dashboard_does`.

    Whatever start_up() starts needs a stand-in here, or these tests start the real thing
    inside the test program. `self.stood_in` holds the names replaced; a test checks them
    against the names start_up() and clean_up() use."""

    def setUp(self):
        """Put the stand-ins in place for the length of the test."""
        super().setUp()
        self.diary, self.enforcer_does, self.cloud_does, self.listeners_do = [], {}, {}, {}
        self.dashboard_does = {}
        self.webs, self.answers, self.stood_in = [], [], set()
        self.printed = io.StringIO()
        for name in ("init_db", "load_lists", "log_writer", "router_advert_listener", "address_watcher",
                     "hint_refresher"):
            self.patch(server, name, nothing)
        self.patch(server, "NAMER", mock.Mock())
        self.patch(server, "find_local_ip", lambda: "192.168.1.2")
        self.patch(server, "start_dns", lambda port: self.listeners_do.get("start", nothing)())
        self.patch(server.enforcer, "Enforcer", lambda *a, **k: StandIn("enforcer", self.diary, self.enforcer_does))
        self.patch(server.cloud_agent, "CloudAgent", lambda *a, **k: StandIn("cloud link", self.diary, self.cloud_does))
        self.patch(server, "ThreadingHTTPServer", self.make_web_server)
        self.patch(server, "open_browser_soon", lambda url: BrowserTimer(url, self.diary))
        # What start_up() keeps for clean_up(): put back after each test, so that no test stops
        # something an earlier test left behind.
        for name in ("ENF", "CA", "BROWSER"):
            self.patch(server, name, None)

    def patch(self, where, name, stand_in):
        """Replace where.name with the stand-in until the test is over."""
        patcher = mock.patch.object(where, name, stand_in)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.stood_in.add(name)

    def make_web_server(self, address, handler):
        """A real dashboard web server on a spare port, noted in the diary and kept in
        self.webs, so that a test can reach it and the time limit can end it."""
        web = Dashboard(("127.0.0.1", 0), handler)
        web.diary = self.diary
        self.addCleanup(web.server_close)
        self.webs.append(web)
        self.diary.append("dashboard port opened")
        self.dashboard_does.get("opened", nothing)()
        return web

    def run_it(self, stop_once_serving=None, browser=False, listening_already=None):
        """Run the whole life in this thread, and return the error that ended it, if one did.

        `stop_once_serving` is a signal to send once the dashboard has answered a request (the
        diary then says "dashboard answered"). `browser` says whether the program is to open
        the dashboard in a browser, as it does when started by hand. `listening_already` is a
        StopRequest to hand to run(), as the program does with the one it makes at the top of
        its file. Should run() still be
        going 30 seconds on, the dashboard is ended from outside and the test fails, so that a
        fault here cannot hang the whole test run."""
        gave_up, helpers = [], []

        def give_up():
            """End the serving loop from outside and note that it had to be done."""
            gave_up.append(True)
            for web in self.webs:
                web.shutdown()

        def ask_then_stop():
            """Wait for the dashboard's answer, which shows it is serving, then send the signal
            to this program. Python runs the handler in the main thread, which is serving.

            If start-up never gets as far as a dashboard, give up after 30 seconds and send
            nothing. And send nothing unless QuietNet is listening for the signal: left to
            Python, it would end the whole test run. The dashboard is then ended from here, and
            the diary says why."""
            deadline = time.monotonic() + 30
            while not self.webs:
                if time.monotonic() > deadline:
                    return
                time.sleep(0.001)
            conn = http.client.HTTPConnection("127.0.0.1", self.webs[0].server_address[1], timeout=30)
            conn.request("GET", "/api/services", headers={"Host": "localhost"})
            self.answers.append(conn.getresponse().status)
            conn.close()
            self.diary.append("dashboard answered")
            handler = signal.getsignal(stop_once_serving)
            if getattr(handler, "__func__", None) is server.StopRequest.note:
                signal.raise_signal(stop_once_serving)
            else:
                self.diary.append("QuietNet was not listening for %s: %r was in place" % (stop_once_serving.name, handler))
                self.webs[0].shutdown()
        limit = threading.Timer(30, give_up)
        limit.daemon = True
        limit.start()
        if stop_once_serving:
            helpers.append(threading.Thread(target=ask_then_stop, daemon=True))
            helpers[0].start()
        args = mock.Mock(dns_port=0, web_port=0, no_browser=not browser, no_device_names=True)
        error = None
        try:
            with contextlib.redirect_stdout(self.printed):
                server.run(args, listening_already)
        except BaseException as e:      # KeyboardInterrupt too: it must not end the test run
            error = e
        finally:
            limit.cancel()
        for helper in helpers:
            helper.join(30)
        self.assertFalse(gave_up, "QuietNet was still running 30 seconds on. The diary: %r" % self.diary)
        return error

    def test_an_ordinary_life_starts_everything_serves_and_stops_everything(self):
        self.assertIsNone(self.run_it(stop_once_serving=signal.SIGTERM))
        self.assertEqual(self.diary, ["enforcer made", "enforcer started", "cloud link made", "cloud link started",
                                      "dashboard port opened", "dashboard serving", "dashboard answered",
                                      "enforcer stopped", "cloud link stopped"])
        self.assertEqual(self.answers, [200])
        self.assertIn("QuietNet is running.", self.printed.getvalue())
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_ctrl_c_while_serving_stops_everything_too(self):
        self.assertIsNone(self.run_it(stop_once_serving=signal.SIGINT))
        self.assertEqual(self.diary[-3:], ["dashboard answered", "enforcer stopped", "cloud link stopped"])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_a_stop_request_noted_while_the_program_was_still_loading_means_nothing_is_started(self):
        """Run as the program, server.py listens from its first lines, before its imports, and
        hands that StopRequest to run(). A request noted by then must not be forgotten."""
        early = server.StopRequest()
        self.addCleanup(os.close, early._read)
        self.addCleanup(os.close, early._write)
        early.listen()
        ask_to_stop()
        self.assertIsNone(self.run_it(listening_already=early))
        self.assertEqual(self.diary, [])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_nothing_is_listened_for_just_because_the_file_was_imported(self):
        """Only the program itself listens from the top of the file. Imported, as it is here,
        it must leave the handling of signals alone until run() is called."""
        self.assertIsNone(server.STOP_FROM_THE_TOP)

    def test_a_stop_request_before_the_enforcer_starts_means_nothing_more_is_started(self):
        self.listeners_do["start"] = ask_to_stop
        self.assertIsNone(self.run_it())
        self.assertEqual(self.diary, [])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_a_stop_request_while_the_enforcer_starts_still_stops_the_enforcer(self):
        """The start-up gap of known issue 12: the enforcer may already be steering devices, so
        the clean-up must run for it. The cloud link and the dashboard are never started."""
        self.enforcer_does["start"] = ask_to_stop
        self.assertIsNone(self.run_it())
        self.assertEqual(self.diary, ["enforcer made", "enforcer started", "enforcer stopped"])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_ctrl_c_while_the_enforcer_starts_still_stops_the_enforcer(self):
        self.enforcer_does["start"] = lambda: ask_to_stop(signal.SIGINT)
        self.assertIsNone(self.run_it())
        self.assertEqual(self.diary, ["enforcer made", "enforcer started", "enforcer stopped"])

    def test_a_stop_request_while_the_cloud_link_starts_means_the_dashboard_is_never_served(self):
        """Too late for start-up to be cut short, so the request has to be remembered: the rest
        of start-up is finished, there is no serving, and everything is stopped."""
        self.cloud_does["start"] = ask_to_stop
        self.assertIsNone(self.run_it())
        self.assertEqual(self.diary, ["enforcer made", "enforcer started", "cloud link made", "cloud link started",
                                      "dashboard port opened", "enforcer stopped", "cloud link stopped"])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_a_stop_request_just_as_the_dashboards_port_opens_means_it_is_never_served(self):
        """The last lines of start-up, after its last look at the request: the port is open
        and the program is not yet serving. Before the fix, the request ended the program on
        the spot here, with no clean-up."""
        self.dashboard_does["opened"] = ask_to_stop
        self.assertIsNone(self.run_it())
        self.assertEqual(self.diary[-3:], ["dashboard port opened", "enforcer stopped", "cloud link stopped"])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_a_program_started_by_hand_sets_its_browser_to_open_and_the_clean_up_calls_it_off(self):
        """The browser opens half a second after start-up. Calling it off does nothing once it
        has opened; if the stop request came first, it stops a browser opening on a dashboard
        that has gone."""
        self.assertIsNone(self.run_it(stop_once_serving=signal.SIGTERM, browser=True))
        self.assertEqual(self.diary[4:], ["dashboard port opened", "browser set to open http://localhost:0",
                                          "dashboard serving", "dashboard answered", "browser called off",
                                          "enforcer stopped", "cloud link stopped"])

    def test_no_browser_is_set_to_open_when_the_program_was_told_not_to(self):
        self.assertIsNone(self.run_it(stop_once_serving=signal.SIGTERM))
        self.assertEqual([line for line in self.diary if "browser" in line], [])

    def test_a_stop_request_while_the_cloud_link_starts_means_no_browser_is_opened(self):
        """Before this was fixed the browser opened after "QuietNet stopped." had been printed."""
        self.cloud_does["start"] = ask_to_stop
        self.assertIsNone(self.run_it(browser=True))
        self.assertEqual([line for line in self.diary if "browser" in line], [])
        self.assertEqual(self.diary[-3:], ["dashboard port opened", "enforcer stopped", "cloud link stopped"])

    def test_a_start_up_that_fails_still_stops_what_it_had_started(self):
        """The dashboard's port being in use is the usual cause. The error still ends the
        program, but not before the enforcer has handed the network back."""
        def port_in_use(address, handler):
            """What Python's web server does when something else has the port."""
            raise OSError(48, "Address already in use")
        self.patch(server, "ThreadingHTTPServer", port_in_use)
        error = self.run_it()
        self.assertIsInstance(error, OSError)
        self.assertEqual(self.diary[-2:], ["enforcer stopped", "cloud link stopped"])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_a_second_stop_request_during_the_clean_up_does_not_interrupt_it(self):
        """The enforcer's stop() is where the network is handed back, and it takes a few seconds
        on a Pi. Both signals arrive again while it runs; it must finish, and so must the rest."""
        seen = []

        def asked_again():
            """Note how each signal is handled at this moment, then send it to this program if
            that is safe: one that is neither ignored nor noted would end the test run."""
            for signum in STOP_SIGNALS:
                handler = signal.getsignal(signum)
                seen.append(handler)
                if handler == signal.SIG_IGN or getattr(handler, "__func__", None) is server.StopRequest.note:
                    signal.raise_signal(signum)
        self.enforcer_does["stop"] = asked_again
        self.assertIsNone(self.run_it(stop_once_serving=signal.SIGTERM))
        self.assertEqual(seen, [signal.SIG_IGN, signal.SIG_IGN])
        self.assertEqual(self.diary[-2:], ["enforcer stopped", "cloud link stopped"])
        self.assertTrue(self.printed.getvalue().endswith("QuietNet stopped.\n"))

    def test_a_signal_is_not_sent_to_the_test_program_unless_quietnet_is_listening_for_it(self):
        """A guard on these tests themselves. Should run() ever stop listening, the test must
        fail with a reason; a signal sent regardless would end the whole test run on the spot,
        with no report at all."""
        self.patch(server.StopRequest, "listen", nothing)
        self.assertIsNone(self.run_it(stop_once_serving=signal.SIGTERM))
        self.assertIn("QuietNet was not listening for SIGTERM", " ".join(self.diary))

    def test_everything_start_up_and_clean_up_use_has_a_stand_in_here_or_starts_nothing(self):
        """These tests run the real start_up() and clean_up() inside the test program. So the
        next thing added to them (a thread, a listener, something that sends onto the home
        network) would be started for real by every test above, with nothing to show for it,
        unless it is given a stand-in in setUp. This fails until it has one, or until its name
        is added to STARTS_NOTHING because it truly starts nothing."""
        used = set(server.start_up.__code__.co_names) | set(server.clean_up.__code__.co_names)
        self.assertEqual(used - self.stood_in - STARTS_NOTHING, set(),
                         "start_up() or clean_up() in server.py uses these names, which WholeLife.setUp in "
                         "tests/test_start_stop.py does not replace with a stand-in")


class CleanUp(Base):
    """clean_up() alone, for the states start-up can be left in."""

    def cleaned_up(self, enforcer, cloud, browser=None):
        """Run clean_up() with these in place of the real ones; return what it printed."""
        printed = io.StringIO()
        with mock.patch.object(server, "ENF", enforcer), mock.patch.object(server, "CA", cloud), \
                mock.patch.object(server, "BROWSER", browser), contextlib.redirect_stdout(printed):
            server.clean_up()
        return printed.getvalue()

    def test_with_nothing_started_it_only_says_that_quietnet_has_stopped(self):
        self.assertEqual(self.cleaned_up(None, None), "\nQuietNet stopped.\n")

    def test_with_only_the_enforcer_started_it_stops_the_enforcer(self):
        enforcer = mock.Mock()
        self.assertIn("QuietNet stopped.", self.cleaned_up(enforcer, None))
        enforcer.stop.assert_called_once_with()

    def test_an_enforcer_that_was_made_but_never_started_can_be_stopped(self):
        """A stop request can land between the making and the starting. The real class is used
        here; it never runs a command or opens a socket unless it is started."""
        enforcer = server.enforcer.Enforcer("127.0.0.1", dict, dict, log=lambda m: None)
        self.assertIn("QuietNet stopped.", self.cleaned_up(enforcer, None))

    def test_a_cloud_link_that_was_made_but_never_started_can_be_stopped(self):
        """The real class again: made with a throwaway folder, it contacts nothing until started."""
        cloud = server.cloud_agent.CloudAgent(0, server.DATA, log=lambda m: None)
        self.assertIn("QuietNet stopped.", self.cleaned_up(None, cloud))

    def test_a_browser_that_has_not_opened_yet_is_called_off(self):
        browser = mock.Mock()
        self.assertIn("QuietNet stopped.", self.cleaned_up(None, None, browser))
        browser.cancel.assert_called_once_with()

    def test_the_real_browser_timer_can_be_called_off_and_never_holds_up_the_end_of_the_program(self):
        """The real timer, with a stand-in for the opening itself and an hour to run in place of
        half a second, so that this test cannot be too slow for it: it is set for the address
        given, is a daemon thread (which Python does not wait for at exit), and once called off
        it ends without opening anything."""
        opened = []
        with mock.patch.object(server.webbrowser, "open", opened.append):
            timer = server.open_browser_soon("http://localhost:1", after=3600)
            self.assertEqual(self.cleaned_up(None, None, timer), "\nQuietNet stopped.\n")
            timer.join(30)
        self.assertFalse(timer.is_alive())
        self.assertTrue(timer.daemon)
        self.assertEqual(timer.args, ("http://localhost:1",))
        self.assertEqual(opened, [])

    def test_the_enforcer_is_stopped_before_the_cloud_link(self):
        order = []
        enforcer, cloud = mock.Mock(), mock.Mock()
        enforcer.stop.side_effect = lambda: order.append("enforcer")
        cloud.stop.side_effect = lambda: order.append("cloud link")
        self.cleaned_up(enforcer, cloud)
        self.assertEqual(order, ["enforcer", "cloud link"])


if __name__ == "__main__":
    unittest.main()
