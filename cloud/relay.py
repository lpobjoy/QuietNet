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
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# MAP OF THIS FILE:
#   settings              timeouts, limits, who may sign up
#   storage               relay.db: users, pis (tokens stored hashed), guess counts, and the cookie-signing secret
#   passwords & sessions  PBKDF2 password records; signed "user.number.expiry.signature" cookies
#   limits on guessing    Throttle: caps wrong passwords, sign-in attempts and wrong pairing codes;
#                         kept in relay.db too, so a restart doesn't reset them
#   the relay bridge      Bridge: hands a browser's request to the right Pi and waits for its answer;
#                         BigAnswers: caps the memory held by large Pi answers
#   small HTML pages      the page layout
#   web server            Relay: accounts, pairing, the Pi-side calls, and browser -> Pi relaying
#   not running as root   drop_privileges: hands the data folder to an ordinary user and becomes it
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
#   first  - only while no account exists yet, i.e. the person who set the relay up (the default)
#   open   - anyone who finds the address
#   closed - nobody
# Any other value is treated as closed, with a warning at start-up, so a typo never leaves it open.
SIGNUP_MODES = ("open", "first", "closed")
SIGNUP_DEFAULT = "first"


def read_signup_setting(environ=None):
    """The QUIETNET_SIGNUP setting from the environment, tidied (lower case, no spaces), or the
    default ('first') when it is not set or empty."""
    environ = os.environ if environ is None else environ
    return (environ.get("QUIETNET_SIGNUP") or SIGNUP_DEFAULT).strip().lower() or SIGNUP_DEFAULT


SIGNUP = read_signup_setting()
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

# The one-line installer shown on the home page for a new Pi. It is fetched from GitHub by the Pi,
# never by the relay.
INSTALL_URL = os.environ.get("QUIETNET_INSTALL_URL") or "https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh"
RELAY_PLACEHOLDER = "https://your-relay-address"
GETTING_STARTED = ('<p class="muted">No QuietNets yet. To get started: name your Pi below and press '
                   '<b>Create pairing code</b>, then run the one line shown here on the Pi. It installs '
                   'QuietNet and links it to this account.</p>')
# A plain host name or address, with an optional port: letters, digits, dots and dashes only.
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$")
# A web address made only of a scheme and such a host (an optional trailing slash is dropped).
RELAY_URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$")
# The only hosts a plain http:// relay address may name. The installer and the Pi's link refuse
# http:// anywhere else, because it would send the Pi's key unprotected.
LOCAL_RELAY_HOSTS = ("localhost", "127.0.0.1")


def usable_relay_url(url):
    """True when `url` is a plain relay address the installer on a Pi will accept.

    It must be https:// (or http:// naming only localhost or 127.0.0.1) followed by a plain host
    and an optional port, so the install line shown never names an address the installer refuses."""
    if not RELAY_URL_RE.match(url):
        return False
    if url.startswith("https://"):
        return True
    # Compared exactly, in lower case, as install.sh does: it would refuse "http://LocalHost".
    host = url.split("://", 1)[1].split(":", 1)[0]
    return host in LOCAL_RELAY_HOSTS


def relay_address(host_header=None, environ=None):
    """Work out this relay's public web address, for the install command on the home page.

    In order: QUIETNET_RELAY_URL if set and usable (see usable_relay_url), then https:// plus RAILWAY_PUBLIC_DOMAIN if set, then
    https:// plus the request's Host header. Each is used only if it is a plain address (letters,
    digits, dots, dashes and a port), because the result is pasted into a shell on someone's Pi;
    the Host header in particular comes from whoever sent the request. Returns (address, guessed),
    where guessed is True when nothing usable was found and RELAY_PLACEHOLDER is returned instead."""
    env = os.environ if environ is None else environ
    configured = (env.get("QUIETNET_RELAY_URL") or "").strip().rstrip("/")
    if configured and usable_relay_url(configured):
        return configured, False
    for host in ((env.get("RAILWAY_PUBLIC_DOMAIN") or "").strip(), (host_header or "").strip()):
        if host and HOST_RE.match(host):
            return "https://" + host, False
    return RELAY_PLACEHOLDER, True


def install_command(relay_url, code):
    """The full one-line command that installs QuietNet on a new Pi and pairs it with this relay."""
    return "curl -fsSL %s | sh -s -- --relay %s --code %s" % (INSTALL_URL, relay_url, code)


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
    # Added in the fourth review: each account's session number, which is signed into its session
    # cookies. Signing out adds one to it, so every copy of that account's cookie stops working.
    if "session_gen" not in [row[1] for row in db.execute("PRAGMA table_info(users)")]:
        db.execute("ALTER TABLE users ADD COLUMN session_gen INTEGER DEFAULT 0")
    # Recent wrong guesses and attempts (see Throttle), so the limits on guessing survive a restart.
    db.execute("CREATE TABLE IF NOT EXISTS throttle(name TEXT PRIMARY KEY, times TEXT)")
    hash_old_tokens()
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
    throttle.load()


TOKEN_MARK = "sha256$"      # the start of a stored Pi token record, as opposed to an old plain-text token


def token_record(token):
    """What is stored for a Pi's token: 'sha256$' and the token's SHA-256 digest, never the token itself.
    A copy of relay.db is then no use for posing as someone's Pi. Tokens are 48 random letters, so a
    plain hash (without a slow password-style hash) is enough: nobody can guess one from its digest."""
    return TOKEN_MARK + hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()


def hash_old_tokens():
    """Replace any Pi token still stored as plain text (from before tokens were hashed) with its
    record. Records already start with 'sha256$', and a real token is only letters 0-9 and a-f, so
    running this again changes nothing: a token is never hashed twice. Paired Pis keep working,
    since they still send the same token."""
    rows = db.execute("SELECT id, token FROM pis WHERE token != '' AND substr(token, 1, 7) != ?",
                      (TOKEN_MARK,)).fetchall()
    for pid, token in rows:
        db.execute("UPDATE pis SET token=? WHERE id=?", (token_record(token), pid))


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


def session_signature(msg, pw_record):
    """The signature on a session cookie: an HMAC, with the relay's secret, over 'user.number.expiry'
    and the account's password record. Signing over the password record means changing the password
    ends every session at once, just as signing out does."""
    return hmac.new(SECRET, msg.encode() + b"." + pw_record.encode(), hashlib.sha256).hexdigest()[:32]


def make_session(user_id):
    """A session cookie value for an account: 'user.number.expiry.signature', where 'number' is the
    account's current session number (see end_sessions). None if there is no such account."""
    row = sql("SELECT session_gen, pw FROM users WHERE id=?", (user_id,), one=True)
    if not row:
        return None
    exp = str(int(time.time() + SESSION_HOURS * 3600))
    msg = "%d.%d.%s" % (user_id, row[0] or 0, exp)
    return msg + "." + session_signature(msg, row[1] or "")


def read_session(cookie):
    """The user id a session cookie belongs to, or None if it is forged, altered, expired, from before
    the account last signed out or changed its password, or for an account that no longer exists.
    Cookies made before session numbers existed have one part fewer, and simply count as signed out.
    A cookie with letters outside plain ASCII (which another site on the same domain could set)
    is simply not valid; it must not be passed to compare_digest, which refuses such text."""
    try:
        if not cookie.isascii():
            return None
        uid, gen, exp, sig = cookie.split(".")
        if int(exp) <= time.time():
            return None
        row = sql("SELECT session_gen, pw FROM users WHERE id=?", (int(uid),), one=True)
        if not row or int(gen) != (row[0] or 0):
            return None
        if hmac.compare_digest(sig, session_signature("%s.%s.%s" % (uid, gen, exp), row[1] or "")):
            return int(uid)
    except (ValueError, AttributeError, TypeError, OverflowError):
        pass                        # OverflowError: a forged number too big for the database
    return None


def end_sessions(user_id):
    """Sign an account out everywhere: add one to its session number, so every session cookie made
    for it so far, in any browser, stops working. Called when someone signs out."""
    sql("UPDATE users SET session_gen = COALESCE(session_gen, 0) + 1 WHERE id=?", (user_id,), commit=True)


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
    all day. This keeps a short memory of failures so that guessing is cut off long before it
    could succeed. With persist=True (the relay's own) every change is also written to the
    'throttle' table, and load() reads it back at start-up, so restarting the relay does not
    wipe the slate clean for someone guessing.

    Names used for wrong guesses: "login:<email>" (per account), "login" (all accounts together),
    "login-known:<email>" (a browser that signed in before), "pair-from:<address>" and "pair"
    (overall). Names that count every attempt, right or wrong: "login-tries:<email>",
    "login-from:<address>", "login-known-tries:<email>", "paired:<user id>" (successful pairings)
    and "signup". The overall limits cannot be dodged by changing network address, because they do
    not depend on the caller's address at all."""

    MAX_NAMES = 10000           # names remembered at once; beyond this the oldest half are forgotten
    MAX_TIMES = 1000            # times remembered per name; every limit is far below this
    KEEP_SECONDS = 24 * 3600    # the longest window any limit uses; older times never count again

    def __init__(self, persist=False):
        """Starts with no failures recorded. persist=True keeps a copy in the relay database."""
        self.lock = threading.Lock()
        self.failures = {}      # name -> [time of each recent failure]
        self.persist = persist

    def _save(self, names):
        """Write the current times for `names` to the database (removing names with none).
        Called with self.lock held, so the stored copy always matches memory. Does nothing for a
        throttle that isn't persistent, or before the database is open."""
        if not self.persist or db is None or not names:
            return
        with db_lock:
            for name in names:
                times = self.failures.get(name)
                if times:
                    db.execute("INSERT OR REPLACE INTO throttle(name, times) VALUES(?, ?)",
                               (name, json.dumps([round(t, 3) for t in times])))
                else:
                    db.execute("DELETE FROM throttle WHERE name=?", (name,))
            db.commit()

    def load(self):
        """Read the stored failures back from the database (at start-up), dropping any too old to
        count against any limit and removing those from the database too."""
        if not self.persist or db is None:
            return
        cutoff = time.time() - self.KEEP_SECONDS
        with self.lock:
            stale = []
            for name, text in sql("SELECT name, times FROM throttle"):
                try:
                    times = [float(t) for t in json.loads(text)]
                except (ValueError, TypeError):
                    times = []
                times = sorted(t for t in times if t > cutoff)[-self.MAX_TIMES:]
                if times:
                    self.failures[name] = times
                else:
                    stale.append(name)
            self._save(stale)

    def blocked(self, name, limit):
        """True if `name` has already failed `limit[0]` times within the last `limit[1]` seconds."""
        most, window = limit
        cutoff = time.time() - window
        with self.lock:
            before = self.failures.get(name, ())
            recent = [t for t in before if t > cutoff]
            if recent:
                self.failures[name] = recent
            else:
                self.failures.pop(name, None)
            if len(recent) != len(before):
                self._save([name])
            return len(recent) >= most

    def fail(self, name):
        """Record one failure under `name`."""
        with self.lock:
            forgotten = []
            if len(self.failures) > self.MAX_NAMES:     # under a flood of made-up emails, forget the oldest half
                forgotten = sorted(self.failures, key=lambda k: self.failures[k][-1])[:self.MAX_NAMES // 2]
                for key in forgotten:
                    del self.failures[key]
            times = self.failures.setdefault(name, [])
            times.append(time.time())
            del times[:-self.MAX_TIMES]
            self._save(forgotten + [name])

    def clear(self, name):
        """Forget the failures under `name` (after a successful login)."""
        with self.lock:
            if self.failures.pop(name, None) is not None:
                self._save([name])


throttle = Throttle(persist=True)
TOO_MANY = "Too many attempts. Please wait a few minutes and try again."
SIGNUP_DONE = ("Thank you. Now sign in with that email and password. If the email already had an account, "
               "use that account's password.")


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


def signup_status():
    """One line for the start-up log saying who may create an account on this relay."""
    mode = signup_mode()
    if mode == "open":
        return "Sign-up: open. Anyone who finds this relay can create an account (QUIETNET_SIGNUP=open)."
    if mode == "first":
        return ("Sign-up: first account only. Once one account exists, nobody else can create one "
                "(QUIETNET_SIGNUP=first, the default). Set QUIETNET_SIGNUP=open to let anyone sign up.")
    return "Sign-up: closed. No new accounts can be created (QUIETNET_SIGNUP=%s)." % SIGNUP


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
.muted{{color:#5d6b66;font-size:14px}}.note{{background:#e0f2ef;color:#0f5f58;border-radius:10px;padding:10px 14px;margin:12px 0}}.err{{background:#fde8e6;color:#b42318;border-radius:10px;padding:10px 14px;margin:12px 0}}
.dev{{display:flex;align-items:center;gap:12px;border:1px solid #dfe5e2;border-radius:12px;padding:14px;margin:10px 0;text-decoration:none;color:inherit}}
.dev:hover{{border-color:#0f766e}}.dot{{width:10px;height:10px;border-radius:50%;background:#9aa9a3;flex:none}}.dot.on{{background:#0f766e}}
.linkbtn{{background:none;border:0;padding:0;font:inherit;color:#5d6b66;font-size:14px;text-decoration:underline;cursor:pointer}}
.row{{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}}.code{{font:700 26px ui-monospace,Menlo,monospace;letter-spacing:3px;background:#e0f2ef;color:#0f766e;padding:10px 16px;border-radius:10px;display:inline-block}}
.cmd{{font:600 13px/1.5 ui-monospace,Menlo,monospace;letter-spacing:0;display:block;word-break:break-all;user-select:all;-webkit-user-select:all}}
a{{color:#0f766e}}</style></head><body><div class="wrap"><div class="brand">QuietNet</div>{body}</div></body></html>"""


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
        """POST /logout: sign the account out everywhere (every browser holding one of its session
        cookies, and any copied cookie) and forget that this browser signed in here (it may be a
        shared computer). Only done when the form carries this session's sign-out token, so another
        website can't sign you out; otherwise nothing is changed."""
        session = self.cookie("qn_session")
        token = self.body_form().get("token", "")
        if not (session and self.user()):
            return self.redirect("/login")
        if not (token.isascii() and hmac.compare_digest(token, sign_out_token(session))):
            return self.redirect("/")
        end_sessions(self.user())       # every copy of this account's session cookie stops working
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

    FORM_POSTS = ("/login", "/signup", "/logout", "/pis/new")      # and /pis/<id>/delete
    CROSS_SITE = ("That form was sent from another website, so it was refused. Open this relay's own page "
                  "and try again.")

    def from_another_site(self):
        """True if the browser says this request was started by a page on another website.

        Browsers add a Sec-Fetch-Site header to every request, which pages can't change or remove;
        'cross-site' or 'same-site' means a page outside this relay sent it. That stops another site
        signing a visitor in to an account of its choosing ('login forgery') with a hidden form, and
        is a second guard on the relay's other forms. Requests without the header (older browsers and
        programs) are let through, as before. An Origin check would not do: with
        'Referrer-Policy: no-referrer', browsers send 'Origin: null' even from the relay's own pages."""
        return self.headers.get("Sec-Fetch-Site", "").strip().lower() in ("cross-site", "same-site")

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
        if p in self.FORM_POSTS or (p.startswith("/pis/") and p.endswith("/delete")):
            if self.from_another_site():
                return self.send_html(self.auth_form("login", self.CROSS_SITE) if p in ("/login", "/signup")
                                      else '<div class="card"><h1>Refused</h1><p>%s</p><p><a href="/">Back to '
                                           'your QuietNets</a></p></div>' % html.escape(self.CROSS_SITE), 403)
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

    def auth_form(self, mode, error="", note=""):
        """The sign-in or sign-up form (`mode` is 'login' or 'signup'), with an optional error or note."""
        other = "signup" if mode == "login" else "login"
        title = "Sign in" if mode == "login" else "Create your account"
        switch = ('Already have an account? <a href="/login">Sign in</a>' if mode != "login"
                  else 'New here? <a href="/signup">Create an account</a>' if signup_allowed() else "")
        err = '<div class="err">%s</div>' % html.escape(error) if error else ""
        err += '<div class="note">%s</div>' % html.escape(note) if note else ""
        return """<div class="card"><h1>%s</h1><p class="muted">Reach your home QuietNet from anywhere.</p>%s
            <form method="post" action="/%s">
            <label>Email</label><input name="email" type="email" autocomplete="email" required>
            <label>Password</label><input name="password" type="password" autocomplete="%s" minlength="8" required>
            <button class="btn" type="submit">%s</button></form>
            <p class="muted" style="margin-top:16px">%s</p></div>""" % (
            title, err, mode, "current-password" if mode == "login" else "new-password", title, switch)

    def do_signup(self):
        """Create an account, if sign-up is allowed, the details are acceptable and the email is new,
        then show the sign-in form. The answer is the same if the email already has an account (which
        is left untouched), so sign-up can't be used to find out whether someone has one."""
        f = self.body_form()
        email, pw = f.get("email", "").strip().lower(), f.get("password", "")
        if not signup_allowed():
            return self.send_html(self.auth_form("login", "New accounts are switched off on this relay."), 403)
        if throttle.blocked("signup", SIGNUP_LIMIT_OVERALL):
            return self.send_html(self.auth_form("signup", TOO_MANY), 429)
        if not EMAIL_RE.fullmatch(email) or len(email) > 254 or len(pw) < 8:
            return self.send_html(self.auth_form("signup", "Enter a valid email and a password of at least 8 characters."))
        throttle.fail("signup")         # every try counts towards the hourly limit, new email or not
        record = hash_pw(pw)            # done either way, so both answers take as long
        # In 'first' mode the check above and this insert are far apart (the hash takes a moment), so
        # two sign-ups could both pass the check. The insert itself therefore adds the row only while
        # there are still no accounts; a sign-up that loses the race gets the same answer as any other.
        only_if_none = " WHERE NOT EXISTS (SELECT 1 FROM users)" if signup_mode() == "first" else ""
        try:
            sql("INSERT INTO users(email,pw,created) SELECT ?,?,?" + only_if_none,
                (email, record, time.time()), commit=True)
        except sqlite3.IntegrityError:
            pass                        # the email already has an account: leave it exactly as it is
        # The same answer whether or not the email already had an account, so this form can't be used
        # to find out who has one. Nobody is signed in here; signing in proves the password.
        return self.send_html(self.auth_form("login", note=SIGNUP_DONE))

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
        address, guessed = relay_address(self.headers.get("Host"))
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
                    <p style="margin:12px 0 6px"><b>New Pi?</b> Run this one line on it:</p>
                    <div class="code cmd">%s</div>%s
                    <p class="muted" style="margin-top:8px">It needs Raspberry Pi OS or another Debian-style Linux, and installs
                    Docker if it is missing (it asks first). The code works once and for %d minutes.</p>
                    <p class="muted" style="margin-top:12px"><b>Pi already running QuietNet?</b> On the Pi's own QuietNet page,
                    open <b>Remote access</b>, enter this relay's web address and this code:</p><div class="code">%s</div>
                    <p class="muted" style="margin-top:8px">Reload this page for a new code.</p></div>""" % (
                    html.escape(name), pid, html.escape(install_command(address, code)),
                    ('<p class="muted" style="margin-top:6px">Replace %s with this relay\'s web address.</p>'
                     % html.escape(address)) if guessed else "",
                    PAIR_CODE_MINUTES, html.escape(code))
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
            self.sign_out_form(), rows or GETTING_STARTED))

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
            (token_record(token), time.time(), row[0]), commit=True)
        self.send_json({"ok": True, "id": row[0], "token": token})      # the only time the token itself is sent

    def agent(self):
        """The Pi matching the token in the request header, as (pi id, owner's user id), or None.
        Only the token's record is stored (see token_record), so the record is worked out from the
        header, found by its index, and compared again in constant time."""
        token = self.headers.get("X-QuietNet-Token", "")
        if not token or not token.isascii():
            return None
        record = token_record(token)
        row = sql("SELECT id, user_id, token FROM pis WHERE token=? AND paired=1", (record,), one=True)
        if not row or not hmac.compare_digest(row[2], record):
            return None
        return row[0], row[1]

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


# ------------------------------------------------------------------ not running as root

NOBODY = (65534, 65534)     # the usual unprivileged "nobody" user and group
MAX_ID = 2 ** 32 - 2        # the largest user or group number the system accepts (one more means "none")


def run_as_ids(setting):
    """The (user, group) numbers to run as, from a QUIETNET_RUN_AS value like '1000:1000'.
    An empty setting means 'nobody'. None if the setting can't be read."""
    if not setting or not setting.strip():
        return NOBODY
    try:
        uid, gid = (int(part) for part in setting.strip().split(":"))
    except ValueError:
        return None
    return (uid, gid) if 0 <= uid <= MAX_ID and 0 <= gid <= MAX_ID else None


# The files the relay keeps in its data folder: the database and the files SQLite keeps beside it.
DATA_FILES = ("relay.db", "relay.db-wal", "relay.db-shm", "relay.db-journal")


def hand_over(folder, uid, gid, system=os):
    """Give the data folder, and the relay's own files in it, to user `uid` and group `gid`.

    Links are never followed, and only the known names (DATA_FILES) are touched, and only when each
    is a plain file with no other names. Otherwise a fault in the relay, once it runs as an ordinary
    user, could leave a link in the folder pointing at a system file (such as /etc/shadow), and the
    next start, still as root, would hand that system file over. Raises OSError if a change fails."""
    system.chown(folder, uid, gid, follow_symlinks=False)
    for name in DATA_FILES:
        path = os.path.join(folder, name)
        try:
            info = system.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            system.chown(path, uid, gid, follow_symlinks=False)


def drop_privileges(folder, setting=None, system=os):
    """If the relay was started as root (the admin user), hand the data folder and the files in it
    to an ordinary user, then become that user for good. Returns a line for the start-up log.

    Containers start as root, and Railway's storage volume is owned by root, so the relay begins as
    root to be able to use it. Nothing after start-up needs root, and a fault in a program running as
    root could do far more harm, so this gives it up before any request is handled. The user is
    'nobody' (65534:65534) unless QUIETNET_RUN_AS says 'user:group'. If the folder can't be handed
    over, the relay carries on as root (with a warning) rather than be unable to use its database.
    `system` is the os module; tests pass a stand-in."""
    if system.geteuid() != 0:
        return None
    setting = os.environ.get("QUIETNET_RUN_AS", "") if setting is None else setting
    ids, warning = run_as_ids(setting), ""
    if ids is None:
        ids = NOBODY
        warning = ("Warning: QUIETNET_RUN_AS is set to %r, which isn't 'user:group' as two numbers. "
                   "Using nobody (65534:65534). " % setting)
    uid, gid = ids
    if uid == 0:
        return warning + "Running as root, because QUIETNET_RUN_AS asks for user 0."
    try:
        hand_over(folder, uid, gid, system)
    except OSError as e:
        return warning + ("Warning: couldn't hand the data folder %s to user %d (%s), so the relay is still "
                          "running as root. Check the folder or volume allows a change of owner." % (folder, uid, e))
    # The order matters: the extra groups and the group can only be changed while still root.
    try:
        system.setgroups([])
        system.setgid(gid)
        system.setuid(uid)
    except (OSError, OverflowError) as e:
        raise SystemExit("The relay could not stop running as root (%s), so it will not start. "
                         "Check QUIETNET_RUN_AS, or that the host allows a change of user." % e)
    if uid != 0 and (system.geteuid() == 0 or system.getuid() == 0):
        raise SystemExit("The relay could not stop running as root, so it will not start.")
    return warning + "Running as user %d, group %d, not root." % (uid, gid)


def main():
    """Open the listening port, stop being root, open the database and serve until stopped.

    The port is opened first, while still root, so a low port number (below 1024) still works."""
    server = RelayServer(("0.0.0.0", PORT), Relay)
    os.makedirs(DATA, exist_ok=True)
    note = drop_privileges(DATA)
    if note:
        print(note)
    init_db()
    if not DASHBOARD:
        print("Warning: dashboard file not found; remote dashboard pages won't render.")
    warning = signup_warning()
    if warning:
        print(warning)
    print(signup_status())
    print("QuietNet relay listening on port %d" % PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
