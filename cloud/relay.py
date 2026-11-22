#!/usr/bin/env python3
"""QuietNet relay - reach your home QuietNet from anywhere, safely.

The problem: a QuietNet on a Raspberry Pi at home sits behind a router you often
can't change, so nothing on the internet can connect *in* to it. The solution:
the Pi makes an outbound connection *out* to this relay and holds it open. When
you open this website and sign in, your browser's requests are handed down that
open line to your own Pi, and its answers come back the same way. No router
changes, and only you can reach your Pi.

This is meant to run on a host like Railway, which provides the public HTTPS
address. It uses only the Python standard library - nothing is installed.

What it keeps: your account (email + a PBKDF2-hashed password) and a list of your
Pis. It never stores your browsing history or rules - those stay on the Pi.
"""
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# MAP OF THIS FILE:
#   settings              timeouts, limits, who may sign up
#   storage               relay.db: users, pis, and the secret that signs session cookies
#   passwords & sessions  PBKDF2 password records; signed "user.expiry.signature" cookies
#   limits on guessing    Throttle: caps wrong passwords, sign-in attempts and wrong pairing codes
#   the relay bridge      Bridge: hands a browser's request to the right Pi and waits for its answer;
#                         BigAnswers: caps the memory held by large Pi answers
#   small HTML pages      the page layout
#   web server            Relay: accounts, pairing, the Pi-side calls, and browser -> Pi relaying
#
# THREADS: one per connection (RelayServer), at most MAX_CONNECTIONS at once, of which at most MAX_POLLS
# may be Pis waiting for work. A Pi's poll and a browser's relayed call are both threads that sleep
# inside Bridge until the other arrives. All shared state is in Bridge, BigAnswers, Throttle and the
# database, each guarded by its own lock.
#
# Fuller explanation: docs/ARCHITECTURE.md (Remote access, Security model). Every call: docs/API.md.

DATA = os.environ.get("QUIETNET_RELAY_DATA") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
PORT = int(os.environ.get("PORT", "8080"))
SESSION_HOURS = 24 * 14
CALL_TIMEOUT = 30          # how long a browser request waits for the Pi to answer
POLL_TIMEOUT = 25          # how long the Pi's long-poll waits before returning empty
OFFLINE_AFTER = 40         # a Pi not seen for this many seconds is treated as offline
MAX_BODY = 64 * 1024       # the largest request body the relay will read; real ones are a few hundred bytes
MAX_ANSWER = 16 * 1024 * 1024   # ...except a paired Pi's answers, which can be large (a week of a busy device's history)
BIG_ANSWER_BUDGET = 48 * 1024 * 1024   # the most large-answer bytes held at once, across every Pi (see BigAnswers)
BIG_ANSWER_WAIT = 10       # how long a large answer may wait for room before it is refused
BODY_SECONDS = 30          # the longest a request body may take to arrive, however slowly it trickles in
HEADER_SECONDS = 10        # the longest a request's first line and headers may take to arrive (see Relay.handle_one_request)
MAX_CONNECTIONS = 300      # connections handled at once; more are turned away with "busy"
MAX_POLLS = 150            # of those, how many may be Pis waiting for work, so browsers always have room
MAX_PIS_PER_ACCOUNT = 10   # QuietNets one account may have, paired or waiting
PASSWORD_CHECKS_AT_ONCE = 4     # sign-ins checking a password at the same moment (each takes real processor time)
PASSWORD_CHECK_WAIT = 5    # how long a sign-in waits for its turn to have its password checked
KNOWN_DEVICE_DAYS = 365    # how long a browser is remembered as having signed in to an account before
PAIR_CODE_MINUTES = 15     # how long a pairing code stays valid after it is shown
# Who may create an account, set with the QUIETNET_SIGNUP environment variable:
#   open   - anyone who finds the address (the default)
#   first  - only while no account exists yet, i.e. the person who set the relay up
#   closed - nobody
# Any other value is treated as closed, with a warning at start-up, so a typo never leaves it open.
SIGNUP = os.environ.get("QUIETNET_SIGNUP", "open").strip().lower()
SIGNUP_MODES = ("open", "first", "closed")
# Limits on wrong guesses: (how many failures, within how many seconds). See Throttle below.
LOGIN_LIMIT_PER_EMAIL = (5, 15 * 60)
LOGIN_LIMIT_OVERALL = (60, 5 * 60)
LOGIN_LIMIT_KNOWN_BROWSER = (20, 15 * 60)   # a browser that signed in before has its own, looser cap
# Limits on sign-in attempts of any outcome, right or wrong, so that signing in over and over with a
# correct password can't keep the processor busy checking passwords.
LOGIN_TRIES_PER_EMAIL = (30, 15 * 60)
LOGIN_TRIES_PER_ADDRESS = (60, 15 * 60)
LOGIN_TRIES_KNOWN_BROWSER = (30, 15 * 60)
# Wrong pairing codes: per network address, and a higher limit across everyone. Codes are 32 bits,
# so even the overall limit leaves guessing a live code hopeless; the per-address limit means one
# stranger sending bad codes can't stop everyone else pairing.
PAIR_LIMIT_PER_ADDRESS = (20, 10 * 60)
PAIR_LIMIT_OVERALL = (200, 10 * 60)
PAIR_LIMIT_PER_ACCOUNT = (20, 24 * 3600)    # successful pairings per account per day
SIGNUP_LIMIT_OVERALL = (10, 60 * 60)
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def find_dashboard():
    """Locate the dashboard page (static/index.html): from QUIETNET_STATIC, beside this
    file (in the container), or one folder up (in the repository). None if not found."""
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.environ.get("QUIETNET_STATIC", ""), os.path.join(here, "static", "index.html"),
                 os.path.join(here, "..", "static", "index.html")):
        if path and os.path.exists(path):
            return path
    return None


DASHBOARD = find_dashboard()


# ------------------------------------------------------------------ storage

db = None
db_lock = threading.RLock()


def sql(statement, args=(), commit=False, one=False):
    """Run one SQL statement, holding the lock that guards the single shared connection.
    one=True returns the first row (or None) in place of a list of rows."""
    with db_lock:
        cur = db.execute(statement, args)
        rows = cur.fetchall()
        if commit:
            db.commit()
        return (rows[0] if rows else None) if one else rows


def init_db():
    """Open (or create) relay.db, make sure the tables exist, and load or create the secret
    used to sign session cookies. Deleting the 'secret' row signs everyone out."""
    global db, SECRET
    os.makedirs(DATA, exist_ok=True)
    try:
        os.chmod(DATA, 0o700)       # the folder holds accounts, Pi tokens and the signing secret: owner only
    except OSError:
        pass                        # e.g. a mounted volume that does not allow it; carry on
    db = sqlite3.connect(os.path.join(DATA, "relay.db"), check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL);
        CREATE TABLE IF NOT EXISTS pis(id TEXT PRIMARY KEY, user_id INTEGER, name TEXT, token TEXT,
            code TEXT, paired INTEGER, created REAL, last_seen REAL);
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
    """)
    # Added after 0.5: when the current pairing code was issued, so that codes can expire.
    # Databases made by 0.5 lack the column, so add it if it is missing.
    if "code_ts" not in [row[1] for row in db.execute("PRAGMA table_info(pis)")]:
        db.execute("ALTER TABLE pis ADD COLUMN code_ts REAL DEFAULT 0")
    # Pis look themselves up by token on every poll and answer, and by code when pairing; the home
    # page lists an account's Pis. Without these, each would read the whole table.
    db.executescript("""
        CREATE INDEX IF NOT EXISTS pis_token ON pis(token);
        CREATE INDEX IF NOT EXISTS pis_code ON pis(code);
        CREATE INDEX IF NOT EXISTS pis_user ON pis(user_id);
    """)
    db.commit()
    row = sql("SELECT value FROM meta WHERE key='secret'", one=True)
    if row:
        SECRET = base64.b64decode(row[0])
    else:
        SECRET = secrets.token_bytes(32)
        sql("INSERT INTO meta VALUES('secret', ?)", (base64.b64encode(SECRET).decode(),), commit=True)


# ------------------------------------------------------------------ passwords & sessions

PBKDF2_ROUNDS = 240000


def hash_pw(password, salt=None, rounds=PBKDF2_ROUNDS):
    """Turn a password into the record that is stored: 'pbkdf2$rounds$salt$key'.
    A fresh random salt is used unless one is given (check_pw gives the stored one)."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return "pbkdf2$%d$%s$%s" % (rounds, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_pw(password, stored):
    """Does this password match the stored record? Re-derives the key with the record's own
    salt and rounds and compares in constant time. A damaged record never matches."""
    try:
        _, rounds, salt_b64, _ = stored.split("$")
        return hmac.compare_digest(hash_pw(password, base64.b64decode(salt_b64), int(rounds)), stored)
    except (ValueError, TypeError):
        return False


def make_session(user_id):
    """A session cookie value for a user: 'user.expiry.signature'. The signature is an
    HMAC over the first two parts, so neither can be altered without the relay's secret."""
    exp = str(int(time.time() + SESSION_HOURS * 3600))
    msg = "%d.%s" % (user_id, exp)
    sig = hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()[:32]
    return msg + "." + sig


def read_session(cookie):
    """The user id a session cookie belongs to, or None if it is forged, altered or expired.
    A cookie with letters outside plain ASCII (which another site on the same domain could set)
    is simply not valid; it must not be passed to compare_digest, which refuses such text."""
    try:
        uid, exp, sig = cookie.split(".")
        if not cookie.isascii():
            return None
        msg = "%s.%s" % (uid, exp)
        good = hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()[:32]
        if hmac.compare_digest(sig, good) and int(exp) > time.time():
            return int(uid)
    except (ValueError, AttributeError, TypeError):
        pass
    return None


def sign_out_token(session):
    """The token the sign-out button must send back, worked out from the session cookie.

    Another website can make your browser send a request to /logout, but it can't read our pages,
    so it can't know this token. Without it, any site could sign you out and remove the 'signed in
    here before' marker, which is what keeps strangers from locking you out with wrong guesses."""
    return hmac.new(SECRET, b"sign-out." + session.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:32]


# ------------------------------------------------------------------ limits on guessing

class Throttle:
    """Counts recent failures under a name, and says when there have been too many.

    The relay sits on the public internet, where anyone can try passwords or pairing codes
    all day. This keeps a short memory of failures (in memory only; it resets on restart)
    so that guessing is cut off long before it could succeed.

    Names used for wrong guesses: "login:<email>" (per account), "login" (all accounts together),
    "login-known:<email>" (a browser that signed in before), "pair-from:<address>" and "pair"
    (overall). Names that count every attempt, right or wrong: "login-tries:<email>",
    "login-from:<address>", "login-known-tries:<email>", "paired:<user id>" (successful pairings)
    and "signup". The overall limits cannot be dodged by changing network address, because they do
    not depend on the caller's address at all."""

    def __init__(self):
        """Starts with no failures recorded."""
        self.lock = threading.Lock()
        self.failures = {}      # name -> [time of each recent failure]

    def blocked(self, name, limit):
        """True if `name` has already failed `limit[0]` times within the last `limit[1]` seconds."""
        most, window = limit
        cutoff = time.time() - window
        with self.lock:
            recent = [t for t in self.failures.get(name, ()) if t > cutoff]
            if recent:
                self.failures[name] = recent
            else:
                self.failures.pop(name, None)
            return len(recent) >= most

    def fail(self, name):
        """Record one failure under `name`."""
        with self.lock:
            if len(self.failures) > 10000:          # under a flood of made-up emails, forget the oldest half
                for key in sorted(self.failures, key=lambda k: self.failures[k][-1])[:5000]:
                    del self.failures[key]
            self.failures.setdefault(name, []).append(time.time())

    def clear(self, name):
        """Forget the failures under `name` (after a successful login)."""
        with self.lock:
            self.failures.pop(name, None)


throttle = Throttle()
TOO_MANY = "Too many attempts. Please wait a few minutes and try again."


def new_pair_code():
    """A fresh pairing code, like 'A1B2-C3D4'."""
    return "%s-%s" % (secrets.token_hex(2).upper(), secrets.token_hex(2).upper())


def signup_mode():
    """The sign-up setting in force: SIGNUP if it is one QuietNet knows, otherwise 'closed', so a
    misspelt setting shuts the door rather than leaving it open."""
    return SIGNUP if SIGNUP in SIGNUP_MODES else "closed"


def signup_warning():
    """A warning to print at start-up if QUIETNET_SIGNUP holds a value QuietNet doesn't know, else None."""
    if SIGNUP in SIGNUP_MODES:
        return None
    return ("Warning: QUIETNET_SIGNUP is set to %r, which QuietNet doesn't recognise. Use open, first or "
            "closed. New accounts are switched off until it is corrected." % SIGNUP)


def signup_allowed():
    """Whether a new account may be created right now (see SIGNUP at the top of the file)."""
    mode = signup_mode()
    if mode == "closed":
        return False
    if mode == "first":
        return sql("SELECT COUNT(*) FROM users", one=True)[0] == 0
    return True


# A real password record for a password nobody has. Checked when a login names an unknown email,
# so that "no such account" takes as long to answer as "wrong password" and the two can't be told apart.
_DUMMY_PW = None


def known_device_token(uid, pw_record):
    """A long-lived signed marker for a browser that has signed in to this account before.

    The limits on wrong guesses would otherwise let a stranger who knows your email keep you
    locked out, just by getting the password wrong on purpose. A browser carrying this marker gets
    its own, looser limit instead of the shared ones (it still needs the right password). The marker
    can only be had by signing in successfully, so it is no help to someone guessing. It is signed
    over the account's password record too, so changing the password makes every old marker
    useless; and signing out removes it from that browser."""
    msg = b"known-device.%d.%s" % (uid, pw_record.encode())
    return "%d.%s" % (uid, hmac.new(SECRET, msg, hashlib.sha256).hexdigest()[:32])


def is_known_device(value, uid, pw_record):
    """True if `value` (the qn_known cookie) is the marker for this account and its current password."""
    if not value or not value.isascii():         # compare_digest refuses text outside plain ASCII
        return False
    return hmac.compare_digest(value, known_device_token(uid, pw_record))


password_checks = threading.BoundedSemaphore(PASSWORD_CHECKS_AT_ONCE)
poll_slots = threading.BoundedSemaphore(MAX_POLLS)


def dummy_check(password):
    """Do the work of checking a password without any account to check it against."""
    global _DUMMY_PW
    if _DUMMY_PW is None:
        _DUMMY_PW = hash_pw(secrets.token_hex(16))
    check_pw(password, _DUMMY_PW)


# ------------------------------------------------------------------ the relay bridge

class Bridge:
    """Holds each Pi's open long-poll and shuttles calls/replies across it."""

    def __init__(self):
        """Starts with no Pis and no calls waiting."""
        self.lock = threading.Lock()
        self.queues = {}      # pi_id -> [call, ...] waiting to be picked up by the Pi
        self.waiting = {}     # call_id -> {"event": Event, "resp": dict}
        self.cond = {}        # pi_id -> Condition, so the Pi's poll can sleep until work arrives
        self.pollers = {}     # pi_id -> number of the newest poll; an older poll sees it change and ends

    def _cond(self, pi_id):
        """The wake-up signal for one Pi's waiting poll, created on first use. It shares the
        bridge's lock, so 'check the queue' and 'go to sleep' happen as one step and no call is missed."""
        with self.lock:
            return self.cond.setdefault(pi_id, threading.Condition(self.lock))

    def call(self, pi_id, payload):
        """Browser side: queue a call for the Pi and wait for its reply. A reply that arrives in the
        moment between giving up and tidying away is still returned, so whoever called this always
        receives (and must release) any large answer that was handed over."""
        call_id = secrets.token_hex(16)
        slot = {"event": threading.Event(), "resp": None, "pi": pi_id}
        cond = self._cond(pi_id)
        with self.lock:
            self.waiting[call_id] = slot
            self.queues.setdefault(pi_id, []).append(dict(payload, id=call_id))
            cond.notify_all()
        slot["event"].wait(CALL_TIMEOUT)
        with self.lock:
            self.waiting.pop(call_id, None)
            if pi_id in self.queues:
                self.queues[pi_id] = [c for c in self.queues[pi_id] if c["id"] != call_id]
            return slot["resp"]          # after the pop above, respond() can no longer change it

    def poll(self, pi_id):
        """Pi side: wait for the next call, or return None after POLL_TIMEOUT.

        Only one poll per Pi waits at a time: a new one ends the one before it (which returns None).
        A real Pi polls one at a time, and an old poll left behind after a network drop would
        otherwise hold a relay thread for nothing; it also means one token can't tie up many threads."""
        cond = self._cond(pi_id)
        deadline = time.time() + POLL_TIMEOUT
        with self.lock:
            turn = self.pollers.get(pi_id, 0) + 1
            self.pollers[pi_id] = turn
            cond.notify_all()
            while True:
                if self.pollers.get(pi_id) != turn:
                    return None             # a newer poll from this Pi has taken over
                q = self.queues.get(pi_id)
                if q:
                    return q.pop(0)
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                cond.wait(remaining)

    def expects(self, pi_id, call_id):
        """Is a browser request waiting for this Pi to answer `call_id`?"""
        with self.lock:
            slot = self.waiting.get(call_id)
            return bool(slot) and slot["pi"] == pi_id

    def respond(self, pi_id, call_id, resp):
        """Pi side: deliver the answer to the browser request waiting on `call_id`. True if it was
        delivered. An answer to a call that has already timed out (or never existed) is dropped, and
        so is one from a Pi the call wasn't sent to: one Pi can never answer for another. Only the
        first answer to a call counts."""
        with self.lock:
            slot = self.waiting.get(call_id)
            if slot and slot["pi"] == pi_id and slot["resp"] is None:
                slot["resp"] = resp
                slot["event"].set()
                return True
            return False

    def forget(self, pi_id):
        """Drop everything held for a Pi that has been removed, so removed Pis don't build up in
        memory. A poll still waiting for it ends at once."""
        with self.lock:
            self.queues.pop(pi_id, None)
            self.pollers.pop(pi_id, None)
            cond = self.cond.pop(pi_id, None)
            if cond:
                cond.notify_all()


class BigAnswers:
    """Keeps count of the large Pi answers the relay is holding in memory, and refuses more than it
    can afford.

    Anyone can pair a 'Pi' of their own, and a large answer can be 16 MB. An answer is counted from
    the moment it starts arriving until the browser has been sent it, or the call is given up, so the
    time spent waiting for the browser to collect it counts too. Two limits: one large answer per
    account at a time, across all its Pis (so one person, even with several Pis of their own, can't
    take all the room), and BIG_ANSWER_BUDGET bytes across every account."""

    def __init__(self, budget):
        """Starts empty, able to hold `budget` bytes of large answers at once."""
        self.cond = threading.Condition()
        self.budget = budget
        self.used = 0
        self.held = {}          # owner (the account's user id) -> (ticket, size)

    def take(self, owner, size, wait):
        """Make room for an answer of `size` bytes from a Pi belonging to the account `owner`,
        waiting up to `wait` seconds for it. Returns a ticket to hand to give_back() later, or None
        if there is no room."""
        deadline = time.time() + wait
        with self.cond:
            while owner in self.held or self.used + size > self.budget:
                left = deadline - time.time()
                if left <= 0 or size > self.budget:
                    return None
                self.cond.wait(left)
            ticket = (owner, object())
            self.held[owner] = (ticket, size)
            self.used += size
            return ticket

    def give_back(self, ticket):
        """Release the room a ticket holds. Harmless if called twice, or with None."""
        if not ticket:
            return
        with self.cond:
            held = self.held.get(ticket[0])
            if held and held[0] is ticket:
                del self.held[ticket[0]]
                self.used -= held[1]
                self.cond.notify_all()


bridge = Bridge()
big_answers = BigAnswers(BIG_ANSWER_BUDGET)


# ------------------------------------------------------------------ small HTML pages

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>QuietNet</title>
<style>:root{{color-scheme:light dark}}body{{margin:0;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#f4f6f5;color:#17231f}}@media(prefers-color-scheme:dark){{body{{background:#111715;color:#e8efec}}
.card{{background:#1b2421!important;border-color:#2e3a36!important}}input{{background:#111715;color:#e8efec;border-color:#2e3a36}}}}
.wrap{{max-width:560px;margin:0 auto;padding:40px 16px}}.brand{{font-weight:700;font-size:22px;color:#0f766e;margin-bottom:20px}}
.card{{background:#fff;border:1px solid #dfe5e2;border-radius:14px;padding:24px;margin-bottom:16px}}
h1{{font-size:22px;margin:0 0 4px}}label{{display:block;font-weight:650;margin:14px 0 4px}}
input{{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #dfe5e2;border-radius:10px;font:inherit}}
.btn{{display:inline-block;margin-top:18px;background:#0f766e;color:#fff;border:0;border-radius:10px;padding:11px 18px;font:inherit;font-weight:650;cursor:pointer;text-decoration:none}}
.muted{{color:#5d6b66;font-size:14px}}.err{{background:#fde8e6;color:#b42318;border-radius:10px;padding:10px 14px;margin:12px 0}}
.dev{{display:flex;align-items:center;gap:12px;border:1px solid #dfe5e2;border-radius:12px;padding:14px;margin:10px 0;text-decoration:none;color:inherit}}
.dev:hover{{border-color:#0f766e}}.dot{{width:10px;height:10px;border-radius:50%;background:#9aa9a3;flex:none}}.dot.on{{background:#0f766e}}
.linkbtn{{background:none;border:0;padding:0;font:inherit;color:#5d6b66;font-size:14px;text-decoration:underline;cursor:pointer}}
.row{{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}}.code{{font:700 26px ui-monospace,Menlo,monospace;letter-spacing:3px;background:#e0f2ef;color:#0f766e;padding:10px 16px;border-radius:10px;display:inline-block}}
a{{color:#0f766e}}</style></head><body><div class="wrap"><div class="brand">\U0001F6E1 QuietNet</div>{body}</div></body></html>"""


def page(body):
    """Wrap a fragment of HTML in the site's page layout."""
    return PAGE.format(body=body)


# ------------------------------------------------------------------ web server

class Relay(BaseHTTPRequestHandler):
    """The relay's web server. Three kinds of caller:

      browser, signed out - /login, /signup
      browser, signed in  - /, /pis/..., and /pi/<id>/... which is passed through to that Pi
      a Pi                - /agent/pair, /agent/poll, /agent/respond (token in a header)

    Every handler that acts for a signed-in person starts by calling user() or my_pi(). Keep it so:
    there is no other check between a request and someone's home network."""
    server_version = "QuietNet"
    raw_body = None         # the body of the POST being handled; set by do_POST
    ticket = None           # the room held in big_answers for a large answer being handled, if any
    big_refused = False     # set when a large answer was turned away because there was no room for it
    timeout = 30            # drop a connection that stalls mid-request, so slow senders can't tie up threads

    def log_message(self, *a):
        """Say nothing: the host keeps its own request log."""
        pass

    def end_headers(self):
        # Sent with every answer, including errors:
        #  - the two frame lines stop another website showing these pages inside itself and
        #    tricking a signed-in person into clicking buttons;
        #  - nosniff stops a browser treating a Pi's JSON answer as a web page, whatever it contains;
        #  - no-referrer keeps Pi ids out of links followed from here;
        #  - no-store keeps pages showing your home's activity out of shared caches.
        """Add the protective headers to every answer, then finish the headers as usual."""
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    # -- helpers --------------------------------------------------------

    def handle_one_request(self):
        """Handle one request, but drop the connection if its first line and headers have not all
        arrived within HEADER_SECONDS. Each connection holds one of the server's few places, and the
        connection's own timeout only limits each wait for more data, so without this a sender
        trickling a header byte every few seconds could hold a place for ever. The wait for the next
        request on a kept-open connection counts too. The body has its own limit (read_body)."""
        lock, state = threading.Lock(), {"done": False, "cut": False}

        def too_slow():
            """Shut the connection, unless the headers arrived just in time."""
            with lock:
                if state["done"]:
                    return
                state["done"] = state["cut"] = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        def headers_in():
            """Stop the clock: the headers have arrived (or the request is over). True if the
            clock had already run out and the connection was shut."""
            with lock:
                state["done"] = True
            timer.cancel()
            return state["cut"]

        timer = threading.Timer(HEADER_SECONDS, too_slow)
        timer.daemon = True
        self.headers_in = headers_in
        timer.start()
        try:
            super().handle_one_request()
        finally:
            headers_in()

    def parse_request(self):
        """Read the request's first line and headers as usual, then stop the header clock. If the
        clock ran out while they were arriving, the headers read are cut short, so the request is
        dropped unanswered rather than handled."""
        ok = super().parse_request()
        stop = getattr(self, "headers_in", None)
        if stop and stop():
            self.close_connection = True
            return False
        return ok

    def body_length(self):
        """The request body's stated length, or None if it is missing a number or negative."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        return n if n >= 0 else None

    def read_body(self, cap=MAX_BODY, still_wanted=None):
        """Read the request body from the connection: bytes, or None if its stated length is
        nonsense or over `cap`, or if `still_wanted()` (checked as the body arrives) turns false.
        Called once per POST, by do_POST, which keeps the result in self.raw_body for the handlers.

        The whole body must arrive within BODY_SECONDS. The connection's own timeout only limits each
        wait for more data, so without this a sender trickling one byte at a time could hold a
        thread (and any room it took for a large answer) for hours. Too slow raises socket.timeout."""
        n = self.body_length()
        if n is None or n > cap:
            return None
        deadline = time.time() + BODY_SECONDS
        chunks, got = [], 0
        try:
            while got < n:
                left = deadline - time.time()
                if left <= 0:
                    raise socket.timeout("the request took too long to arrive")
                if still_wanted is not None and not still_wanted():
                    self.close_connection = True        # the rest of the body is left unread
                    return None
                self.connection.settimeout(min(left, self.timeout))
                chunk = self.rfile.read1(min(n - got, 65536))
                if not chunk:
                    raise ConnectionError("the connection closed before the whole request arrived")
                chunks.append(chunk)
                got += len(chunk)
        finally:
            try:
                self.connection.settimeout(self.timeout)
            except OSError:
                pass
        return b"".join(chunks)

    def read_big_answer(self):
        """Read a Pi's answer, allowing up to MAX_ANSWER - but only for a paired Pi answering a call
        that is really waiting for it (named in the X-QuietNet-Call header), and only when
        big_answers has room for it. Anyone can pair a Pi of their own, so without these checks
        anyone could make the relay take in many 16 MB bodies and run it out of memory.

        The room taken is kept in self.ticket, and passes with the answer to the browser's request,
        which gives it back once the answer is sent. If the browser stops waiting while the answer
        is still arriving, reading stops and the room is given back at once."""
        row = self.agent()
        call_id = self.headers.get("X-QuietNet-Call", "")
        n = self.body_length()
        if not (row and bridge.expects(row[0], call_id)) or n is None or n <= MAX_BODY or n > MAX_ANSWER:
            return self.read_body()
        ticket = big_answers.take(row[1], n, BIG_ANSWER_WAIT)       # one large answer per account
        if not ticket:
            self.big_refused = True
            self.close_connection = True                # the body is left unread
            return None
        try:
            data = self.read_body(MAX_ANSWER, still_wanted=lambda: bridge.expects(row[0], call_id))
        except BaseException:
            big_answers.give_back(ticket)
            raise
        if data is None:
            big_answers.give_back(ticket)
        else:
            self.ticket = ticket
        return data

    def source_address(self):
        """The network address the request came from, for limits that count per caller.

        Behind the host's proxy every connection comes from the proxy, so the address the proxy
        adds to the end of X-Forwarded-For is used when there is one. (Earlier entries can be made
        up by the sender, the last one can't.) IPv6 addresses are grouped by their first half, since
        one home is usually handed a whole block of them. Each limit counted this way sits alongside
        an overall limit, so a caller who fakes addresses gains nothing beyond that."""
        forwarded = self.headers.get("X-Forwarded-For", "")
        addr = forwarded.split(",")[-1].strip() if forwarded.strip() else self.client_address[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return addr[:64]
        if ip.version == 6:
            return str(ipaddress.ip_network("%s/64" % ip, strict=False))
        return str(ip)

    def secure(self):
        """Did this request reach the host over HTTPS? (The host handles HTTPS and tells us.)"""
        return self.headers.get("X-Forwarded-Proto", "http") == "https"

    def cookie(self, name):
        """The value of one cookie the browser sent, or None."""
        m = re.search(r"(?:^|;\s*)%s=([^;]+)" % re.escape(name), self.headers.get("Cookie", ""))
        return m.group(1) if m else None

    def user(self):
        """The signed-in user's id, read from the session cookie, or None."""
        token = self.cookie("qn_session")
        return read_session(token) if token else None

    def set_cookie(self, token, name="qn_session", seconds=SESSION_HOURS * 3600):
        """Queue a cookie to go out with this answer. An empty session token signs out.
        HttpOnly keeps page scripts from reading it; SameSite=Lax keeps other sites from sending it
        with their own form posts; Secure is added whenever the request came over HTTPS."""
        flags = "HttpOnly; SameSite=Lax; Path=/; Max-Age=%d" % seconds
        if self.secure():
            flags += "; Secure"
        self._cookies = getattr(self, "_cookies", []) + ["%s=%s; %s" % (name, token, flags)]

    def signed_in_as(self, uid):
        """Queue the cookies for a successful sign-in: the session, and the 'signed in here before' marker."""
        pw_record = sql("SELECT pw FROM users WHERE id=?", (uid,), one=True)[0]
        self.set_cookie(make_session(uid))
        self.set_cookie(known_device_token(uid, pw_record), name="qn_known", seconds=KNOWN_DEVICE_DAYS * 86400)

    def sign_out_form(self, label="Sign out", css="linkbtn"):
        """A sign-out button: a form that posts to /logout with this session's sign-out token."""
        token = sign_out_token(self.cookie("qn_session") or "")
        return ('<form method="post" action="/logout" style="margin:0"><input type="hidden" name="token" value="%s">'
                '<button class="%s" type="submit">%s</button></form>') % (
            html.escape(token), html.escape(css), html.escape(label))

    def sign_out_page(self):
        """GET /logout: a page with a sign-out button, rather than signing out straight away, since
        any website can send a browser to an address."""
        if not self.user():
            return self.redirect("/login")
        return self.send_html('<div class="card"><h1>Sign out?</h1><p class="muted">You will need your password '
                              'to sign in again.</p>%s<p class="muted" style="margin-top:16px"><a href="/">Back to '
                              'your QuietNets</a></p></div>' % self.sign_out_form("Sign out", "btn"))

    def sign_out(self):
        """POST /logout: end the session and forget that this browser signed in here (it may be a
        shared computer). Only done when the form carries this session's sign-out token, so another
        website can't sign you out; otherwise nothing is changed."""
        session = self.cookie("qn_session")
        token = self.body_form().get("token", "")
        if not (session and self.user()):
            return self.redirect("/login")
        if not (token.isascii() and hmac.compare_digest(token, sign_out_token(session))):
            return self.redirect("/")
        self.set_cookie("")
        self.set_cookie("", name="qn_known", seconds=0)
        return self.redirect("/login")

    def send_cookies(self):
        """Add every queued cookie to the answer being sent."""
        for c in getattr(self, "_cookies", []):
            self.send_header("Set-Cookie", c)

    def send_html(self, body, code=200):
        """Send a page (the fragment is wrapped in the site layout), with any queued cookies."""
        data = page(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_cookies()
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, code=200):
        """Send `obj` as a JSON answer with the given status."""
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to):
        """Send the browser to another page, with any queued cookies."""
        self.send_response(303)
        self.send_header("Location", to)
        self.send_cookies()
        self.end_headers()

    def body_json(self):
        """The request body as a JSON object. Anything unreadable, oversized or not an
        object counts as empty."""
        try:
            obj = json.loads(self.raw_body or b"{}")
        except (ValueError, TypeError):
            return {}
        return obj if isinstance(obj, dict) else {}

    def body_form(self):
        """The request body as form fields (first value of each). Oversized counts as empty."""
        raw = self.raw_body or b""
        return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "ignore")).items()}

    def my_pi(self, pi_id):
        """The row for Pi `pi_id` if the signed-in user owns it, otherwise None.
        This is the check that keeps one account away from another's Pi."""
        uid = self.user()
        if not uid:
            return None
        return sql("SELECT id,user_id,name,token,paired,last_seen FROM pis WHERE id=? AND user_id=?",
                   (pi_id, uid), one=True)

    # -- routing --------------------------------------------------------

    def do_GET(self):
        """Route every GET to its handler."""
        url = urlparse(self.path)
        p = url.path
        if p == "/healthz":
            return self.send_json({"ok": True})
        if p == "/agent/poll":
            return self.agent_poll()
        if p.startswith("/pi/"):
            return self.pi_request("GET", p, url.query)
        if p == "/signup" and not signup_allowed():
            return self.send_html(self.auth_form("login", "New accounts are switched off on this relay."))
        if p in ("/login", "/signup"):
            return self.send_html(self.auth_form(p[1:]))
        if p == "/logout":
            return self.sign_out_page()
        if p == "/" :
            return self.home()
        self.send_error(404)

    def do_POST(self):
        """Route every POST to its handler.

        The body is read here, first, whichever handler runs and even if it will be refused.
        Answering and closing while the sender's data is still unread makes some systems reset
        the connection, and the browser then never sees the answer."""
        p = urlparse(self.path).path
        try:
            self.raw_body = self.read_big_answer() if p == "/agent/respond" else self.read_body()
        except OSError:
            self.close_connection = True        # too slow, or the sender went away: nothing to answer
            return
        if p == "/agent/pair":
            return self.agent_pair()
        if p == "/agent/respond":
            return self.agent_respond()
        if p.startswith("/pi/"):
            return self.pi_request("POST", p, "")
        if p == "/login":
            return self.do_login()
        if p == "/signup":
            return self.do_signup()
        if p == "/logout":
            return self.sign_out()
        if p == "/pis/new":
            return self.new_pi()
        if p.startswith("/pis/") and p.endswith("/delete"):
            return self.delete_pi(p.split("/")[2])
        self.send_error(404)

    # -- accounts -------------------------------------------------------

    def auth_form(self, mode, error=""):
        """The sign-in or sign-up form (`mode` is 'login' or 'signup'), with an optional error."""
        other = "signup" if mode == "login" else "login"
        title = "Sign in" if mode == "login" else "Create your account"
        switch = ('Already have an account? <a href="/login">Sign in</a>' if mode != "login"
                  else 'New here? <a href="/signup">Create an account</a>' if signup_allowed() else "")
        err = '<div class="err">%s</div>' % html.escape(error) if error else ""
        return """<div class="card"><h1>%s</h1><p class="muted">Reach your home QuietNet from anywhere.</p>%s
            <form method="post" action="/%s">
            <label>Email</label><input name="email" type="email" autocomplete="email" required>
            <label>Password</label><input name="password" type="password" autocomplete="%s" minlength="8" required>
            <button class="btn" type="submit">%s</button></form>
            <p class="muted" style="margin-top:16px">%s</p></div>""" % (
            title, err, mode, "current-password" if mode == "login" else "new-password", title, switch)

    def do_signup(self):
        """Create an account and sign in, if sign-up is allowed and the details are acceptable."""
        f = self.body_form()
        email, pw = f.get("email", "").strip().lower(), f.get("password", "")
        if not signup_allowed():
            return self.send_html(self.auth_form("login", "New accounts are switched off on this relay."), 403)
        if throttle.blocked("signup", SIGNUP_LIMIT_OVERALL):
            return self.send_html(self.auth_form("signup", TOO_MANY), 429)
        if not EMAIL_RE.fullmatch(email) or len(email) > 254 or len(pw) < 8:
            return self.send_html(self.auth_form("signup", "Enter a valid email and a password of at least 8 characters."))
        if sql("SELECT 1 FROM users WHERE email=?", (email,), one=True):
            return self.send_html(self.auth_form("signup", "That email already has an account."))
        throttle.fail("signup")         # every new account counts towards the hourly limit
        sql("INSERT INTO users(email,pw,created) VALUES(?,?,?)", (email, hash_pw(pw), time.time()), commit=True)
        uid = sql("SELECT id FROM users WHERE email=?", (email,), one=True)[0]
        self.signed_in_as(uid)
        self.redirect("/")

    def do_login(self):
        """Check an email and password and sign in. Wrong guesses are counted, per account
        and overall, and an unknown email is made to take as long as a wrong password.
        A browser that has signed in to this account before is let past the limits (see
        known_device_token), so strangers can't lock the owner out by guessing on purpose."""
        f = self.body_form()
        email, pw = f.get("email", "").strip().lower(), f.get("password", "")
        email = email[:254]
        row = sql("SELECT id,pw FROM users WHERE email=?", (email,), one=True)
        trusted = bool(row) and is_known_device(self.cookie("qn_known"), row[0], row[1])
        address = self.source_address()
        if trusted:
            blocked = (throttle.blocked("login-known:" + email, LOGIN_LIMIT_KNOWN_BROWSER)
                       or throttle.blocked("login-known-tries:" + email, LOGIN_TRIES_KNOWN_BROWSER))
        else:
            blocked = (throttle.blocked("login:" + email, LOGIN_LIMIT_PER_EMAIL)
                       or throttle.blocked("login", LOGIN_LIMIT_OVERALL)
                       or throttle.blocked("login-tries:" + email, LOGIN_TRIES_PER_EMAIL)
                       or throttle.blocked("login-from:" + address, LOGIN_TRIES_PER_ADDRESS))
        if blocked:
            return self.send_html(self.auth_form("login", TOO_MANY), 429)
        # Every attempt counts here, right or wrong: checking a password costs real processor time,
        # and anyone can make an account and sign in to it correctly over and over.
        if trusted:
            throttle.fail("login-known-tries:" + email)
        else:
            throttle.fail("login-tries:" + email)
            throttle.fail("login-from:" + address)
        if not password_checks.acquire(timeout=PASSWORD_CHECK_WAIT):
            return self.send_html(self.auth_form("login", "The relay is busy. Please try again in a moment."), 503)
        try:
            if row:
                good = check_pw(pw, row[1])
            else:
                dummy_check(pw)         # spend the same time as a real check, so unknown emails can't be spotted
                good = False
        finally:
            password_checks.release()
        if not good:
            if trusted:
                throttle.fail("login-known:" + email)
            else:
                throttle.fail("login:" + email)
                throttle.fail("login")
            return self.send_html(self.auth_form("login", "Wrong email or password."))
        throttle.clear("login:" + email)
        throttle.clear("login-known:" + email)
        self.signed_in_as(row[0])
        self.redirect("/")

    # -- device list / pairing -----------------------------------------

    def home(self):
        """The signed-in home page: your QuietNets, with a pairing code for each one not yet
        paired. A code that has expired is replaced here, so the page never shows a dead one."""
        uid = self.user()
        if not uid:
            return self.redirect("/login")
        pis = sql("SELECT id,name,paired,last_seen FROM pis WHERE user_id=? ORDER BY created", (uid,))
        rows = ""
        now = time.time()
        for pid, name, paired, seen in pis:
            if not paired:
                code, code_ts = sql("SELECT code, code_ts FROM pis WHERE id=?", (pid,), one=True)
                if now - (code_ts or 0) > PAIR_CODE_MINUTES * 60:
                    # The old code has expired. Looking at this page is what issues a new one,
                    # so the code on screen is always one that works.
                    code = new_pair_code()
                    sql("UPDATE pis SET code=?, code_ts=? WHERE id=? AND paired=0", (code, now, pid), commit=True)
                rows += """<div class="card"><div class="row"><div><b>%s</b><div class="muted">Waiting to be paired</div></div>
                    <form method="post" action="/pis/%s/delete"><button class="btn" style="background:#b42318">Remove</button></form></div>
                    <p class="muted" style="margin-top:12px">On the Pi's own QuietNet page, open <b>Remote access</b>, enter this relay's
                    web address and this code:</p><div class="code">%s</div>
                    <p class="muted" style="margin-top:8px">The code works once and for %d minutes. Reload this page for a new one.</p></div>""" % (
                    html.escape(name), pid, html.escape(code), PAIR_CODE_MINUTES)
            else:
                online = seen and (now - seen) < OFFLINE_AFTER
                rows += """<a class="dev" href="/pi/%s/"><span class="dot %s"></span>
                    <span style="flex:1"><b>%s</b><div class="muted">%s</div></span><span class="muted">Open &rsaquo;</span></a>""" % (
                    pid, "on" if online else "", html.escape(name), "Online" if online else "Offline")
        return self.send_html("""<div class="row"><h1 style="margin:0">Your QuietNets</h1>
            %s</div>%s
            <form method="post" action="/pis/new"><label>Add a QuietNet</label>
            <input name="name" placeholder="e.g. Home Pi" required>
            <button class="btn" type="submit">Create pairing code</button></form>""" % (
            self.sign_out_form(), rows or '<p class="muted">No QuietNets yet.</p>'))

    def new_pi(self):
        """Create a QuietNet entry for the signed-in user, with a fresh pairing code. Each account
        may have at most MAX_PIS_PER_ACCOUNT, so no one account can fill the relay's disk."""
        uid = self.user()
        if not uid:
            return self.redirect("/login")
        if sql("SELECT COUNT(*) FROM pis WHERE user_id=?", (uid,), one=True)[0] >= MAX_PIS_PER_ACCOUNT:
            return self.send_html('<div class="card"><h1>No room for another QuietNet</h1><p>This account already '
                                  'has %d QuietNets, the most it can hold. Remove one before adding another.</p>'
                                  '<p><a href="/">Back to your QuietNets</a></p></div>'
                                  % int(MAX_PIS_PER_ACCOUNT), 403)
        name = (self.body_form().get("name", "").strip() or "My QuietNet")[:40]
        pid = secrets.token_hex(8)
        now = time.time()
        sql("INSERT INTO pis(id,user_id,name,token,code,paired,created,last_seen,code_ts) VALUES(?,?,?,?,?,0,?,0,?)",
            (pid, uid, name, "", new_pair_code(), now, now), commit=True)
        self.redirect("/")

    def delete_pi(self, pid):
        """Remove one of the signed-in user's QuietNets. Its token stops working at once."""
        uid = self.user()
        if uid and sql("SELECT 1 FROM pis WHERE id=? AND user_id=?", (pid, uid), one=True):
            sql("DELETE FROM pis WHERE id=? AND user_id=?", (pid, uid), commit=True)
            bridge.forget(pid)
        self.redirect("/")

    # -- the agent (Pi) side -------------------------------------------

    def agent_pair(self):
        """A Pi presents a pairing code. If it is current and unused, mark the entry paired,
        clear the code and hand back a new secret token.

        Wrong codes are counted per network address and, with a higher limit, overall, so one
        stranger sending bad codes can't stop everyone else pairing. Successful pairings are counted
        per account too, so an account can't pair, remove and pair again without end."""
        body = self.body_json()
        code = str(body.get("code", "")).strip().upper()
        address = self.source_address()
        if (throttle.blocked("pair-from:" + address, PAIR_LIMIT_PER_ADDRESS)
                or throttle.blocked("pair", PAIR_LIMIT_OVERALL)):
            return self.send_json({"error": TOO_MANY}, 429)
        row = code and sql("SELECT id, user_id FROM pis WHERE code=? AND paired=0 AND code_ts>?",
                           (code, time.time() - PAIR_CODE_MINUTES * 60), one=True)
        if not row:
            throttle.fail("pair-from:" + address)
            throttle.fail("pair")
            return self.send_json({"error": "That pairing code is wrong, already used, or has expired."}, 400)
        if throttle.blocked("paired:%d" % row[1], PAIR_LIMIT_PER_ACCOUNT):
            return self.send_json({"error": "This account has paired too many QuietNets today. "
                                            "Please try again tomorrow."}, 429)
        throttle.fail("paired:%d" % row[1])
        token = secrets.token_hex(24)
        sql("UPDATE pis SET paired=1, token=?, code='', last_seen=? WHERE id=?",
            (token, time.time(), row[0]), commit=True)
        self.send_json({"ok": True, "id": row[0], "token": token})

    def agent(self):
        """The Pi matching the token in the request header, as (pi id, owner's user id), or None."""
        token = self.headers.get("X-QuietNet-Token", "")
        if not token:
            return None
        return sql("SELECT id, user_id FROM pis WHERE token=? AND paired=1", (token,), one=True)

    def agent_poll(self):
        """A Pi asks for work. Notes that it is alive, then waits (up to POLL_TIMEOUT seconds)
        for a browser request to pass down. An empty object means 'nothing yet, ask again'.
        At most MAX_POLLS wait at once, so waiting Pis can never take every thread from browsers;
        beyond that the Pi is told the relay is busy, and tries again."""
        row = self.agent()
        if not row:
            return self.send_error(401)
        sql("UPDATE pis SET last_seen=? WHERE id=?", (time.time(), row[0]), commit=True)
        if not poll_slots.acquire(blocking=False):
            return self.send_json({"error": "The relay is busy. Try again shortly."}, 503)
        try:
            call = bridge.poll(row[0])
        finally:
            poll_slots.release()
        self.send_json(call or {})      # {} means "nothing to do"; a real call always carries an id

    def agent_respond(self):
        """A Pi returns the answer to a call. Only ordinary status codes are passed on. An answer
        too big to read (see read_big_answer) is refused with 413. A large answer turned away because
        the relay is holding too many already is refused with 503, and the browser is told at once
        rather than left waiting.

        The answer is passed on as bytes, and the raw body and parsed copy are dropped straight
        away, so only one copy of a large answer stays in memory while the browser collects it."""
        ticket, self.ticket = self.ticket, None
        try:
            row = self.agent()
            if not row:
                return self.send_error(401)
            if self.raw_body is None:
                if self.big_refused:
                    busy = json.dumps({"error": "Your QuietNet's answer was too large for the relay to pass on "
                                                "right now. Please try again in a moment."}).encode()
                    bridge.respond(row[0], self.headers.get("X-QuietNet-Call", ""), {"status": 503, "body": busy})
                    return self.send_json({"error": "The relay is holding too many large answers. Try again shortly."}, 503)
                return self.send_error(413)
            body = self.body_json()
            self.raw_body = None
            try:
                status = int(body.get("status", 502))
            except (TypeError, ValueError):
                status = 502
            if not 200 <= status <= 599:        # only ordinary answer codes are passed back to the browser
                status = 502
            call_id = str(body.get("id", ""))
            text = body.get("body", "")
            body = None
            data = text.encode() if isinstance(text, str) else b""
            text = None
            if bridge.respond(row[0], call_id, {"status": status, "body": data, "ticket": ticket}):
                ticket = None                   # the browser's request now gives it back
            self.send_json({"ok": True})
        finally:
            big_answers.give_back(ticket)

    # -- browser -> Pi relay -------------------------------------------

    def pi_request(self, method, path, query):
        """A signed-in browser's request for one of its Pis.

        '/pi/<id>/' serves the dashboard page. '/pi/<id>/api/...' is passed to the Pi through the
        bridge and the Pi's answer is returned. Checks, in order: the Pi is yours; the path is an API
        path; the request carries the dashboard's own header; the Pi is online."""
        parts = path.split("/", 3)          # ['', 'pi', '<id>', 'rest...']
        if len(parts) < 3:
            return self.send_error(404)
        pid = parts[2]
        rest = "/" + (parts[3] if len(parts) > 3 else "")
        pi = self.my_pi(pid)
        if not pi:
            return self.redirect("/login") if method == "GET" and rest == "/" else self.send_error(404)

        if rest == "/" and method == "GET":        # serve the dashboard, pointed at this Pi
            return self.serve_dashboard(pid, pi[2])
        if not rest.startswith("/api/"):
            return self.send_error(404)
        # Only our own dashboard sends this header; browsers won't add it cross-site. Blocks CSRF.
        if self.headers.get("X-QuietNet") != "1":
            return self.send_error(403)
        if not pi[4] or (pi[5] and time.time() - pi[5] > OFFLINE_AFTER):
            return self.send_json({"error": "Your QuietNet looks offline. Is the Pi switched on?"}, 503)

        payload = {"method": method, "path": rest + (("?" + query) if query else "")}
        if method == "POST":
            if self.raw_body is None:
                return self.send_error(413)
            payload["body"] = self.raw_body.decode("utf-8", "ignore")
        resp = bridge.call(pid, payload)
        if resp is None:
            return self.send_json({"error": "Your QuietNet didn't answer in time."}, 504)
        try:
            data = resp.get("body") or b""
            if isinstance(data, str):
                data = data.encode()
            self.send_response(resp.get("status", 200))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            big_answers.give_back(resp.get("ticket"))     # the answer has gone (or never will): free its room

    def serve_dashboard(self, pid, name):
        """Send the dashboard page, with two additions: a script telling it to send its API
        calls to '/pi/<id>/...', and a bar across the top with the Pi's name and a way back."""
        if not DASHBOARD:
            return self.send_error(500)
        with open(DASHBOARD, encoding="utf-8") as f:
            html_text = f.read()
        inject = ('<script>window.QN_API_BASE=%s;</script>' % json.dumps("/pi/" + pid)
                  + '<style>#qnbar{position:sticky;top:0;z-index:50;background:#0f766e;color:#fff;'
                    'padding:8px 16px;font:600 14px -apple-system,sans-serif;display:flex;gap:14px;align-items:center}'
                    '#qnbar a{color:#fff}#qnbar button{background:none;border:0;padding:0;color:#fff;'
                    'font:inherit;text-decoration:underline;cursor:pointer}</style>')
        bar = ('<div id="qnbar"><a href="/">&lsaquo; My QuietNets</a>'
               '<span style="flex:1">%s &mdash; remote</span>%s</div>') % (
            html.escape(name), self.sign_out_form(css="qnsignout"))
        html_text = html_text.replace("<head>", "<head>" + inject, 1).replace("<body>", "<body>" + bar, 1)
        data = html_text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class RelayServer(ThreadingHTTPServer):
    """The web server: one thread per connection, but at most MAX_CONNECTIONS at once.

    Without a cap, anyone could open thousands of slow connections and run the relay out of threads
    or memory. A connection beyond the cap is answered at once with a short 'busy' reply and closed."""
    daemon_threads = True

    BUSY = (b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"X-Frame-Options: DENY\r\nContent-Security-Policy: frame-ancestors 'none'\r\n"
            b"X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n"
            b"Content-Length: 50\r\nConnection: close\r\n\r\n"
            b"The relay is busy. Please try again in a moment.\r\n")

    def __init__(self, address, handler, max_connections=None):
        """Listen on `address`, allowing `max_connections` at once (MAX_CONNECTIONS if not given)."""
        self.slots = threading.BoundedSemaphore(max_connections or MAX_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        """Start a thread for the connection if there is room, otherwise say 'busy' and close it."""
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(self.BUSY)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        """Handle the connection in its thread, then free its place for the next."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    """Open the database and serve until stopped."""
    init_db()
    if not DASHBOARD:
        print("Warning: dashboard file not found; remote dashboard pages won't render.")
    warning = signup_warning()
    if warning:
        print(warning)
    print("QuietNet relay listening on port %d" % PORT)
    RelayServer(("0.0.0.0", PORT), Relay).serve_forever()


if __name__ == "__main__":
    main()
