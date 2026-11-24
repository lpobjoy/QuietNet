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

What it keeps: your account (email + a PBKDF2-hashed password), a list of your
Pis, and your account's licence. It never stores your browsing history or rules -
those stay on the Pi.

The owner manages licences from a command line on the same computer (see
licence_command): python relay.py licence show|grant|revoke|restore|seats ...
"""
import argparse
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
import sys
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
#   licences              licence_state: what an account's licence allows right now; licence_gate: the
#                         off switch (QUIETNET_LICENCE_GATE) and the log of what it refused or would have;
#                         seats; the wording shown for each state; the two fixed rescue calls
#   small HTML pages      the page layout
#   web server            Relay: accounts, pairing, the Pi-side calls, and browser -> Pi relaying
#   not running as root   drop_privileges: hands the data folder to an ordinary user and becomes it
#   owner's command line  licence_command: python relay.py licence show|grant|revoke|restore|seats
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

# Licences (see the "licences" section below).
DEFAULT_SEATS = 2          # Pis a licence covers unless the owner says otherwise
LEGACY_DAYS = 90           # how long the licence given to accounts that existed before licences lasts
PAST_DUE_DAYS = 14         # after a failed renewal payment, how long everything keeps working
RENEWAL_LAG_DAYS = 3       # an active licence past its end date counts as expired only this long after it
GATE_LOG_SECONDS = 3600    # the gate notes a refusal for one account and one gate at most this often
# A version number as release names use: 0.6 or 0.6.1. Used to check QUIETNET_LATEST.
VERSION_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$")
# A Pi's install id: exactly 32 lower-case hex characters. Anything else sent at pairing is ignored.
INSTALL_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def read_gate_setting(environ=None):
    """The QUIETNET_LICENCE_GATE setting, tidied (lower case, no spaces). Only 'on' switches the
    licence gate on; anything else, including nothing, leaves it off."""
    environ = os.environ if environ is None else environ
    return (environ.get("QUIETNET_LICENCE_GATE") or "off").strip().lower()


def read_latest_setting(environ=None):
    """The newest QuietNet version, from QUIETNET_LATEST, if it is a plain version number such as
    0.6 or 0.6.1; otherwise ''. It is told to paired Pis in their poll answers, so nothing else
    (no words, no addresses) may pass through it."""
    environ = os.environ if environ is None else environ
    value = (environ.get("QUIETNET_LATEST") or "").strip()
    return value if VERSION_RE.match(value) else ""


LICENCE_GATE = read_gate_setting()
LATEST = read_latest_setting()
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
# Rescue presses per account per hour, whatever their outcome. Each one writes a licence log line,
# so without a limit one account could fill the relay's disk by pressing in a loop.
RESCUE_LIMIT_PER_ACCOUNT = (20, 60 * 60)
LICENCE_LOG_KEEP = 1000     # licence log lines kept per account besides the owner's own (see log_licence)
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

# The one-line installer shown on the home page for a new Pi. It is fetched from GitHub by the Pi,
# never by the relay.
INSTALL_URL = os.environ.get("QUIETNET_INSTALL_URL") or "https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh"
RELAY_PLACEHOLDER = "https://your-relay-address"
GETTING_STARTED = ('<p>No QuietNets yet. To get started: name your Pi below and press '
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
    # Added with licences: the random install id a Pi sent when it paired ('' for Pis that sent
    # none), and which kind of agent it is (1 before 0.6, 2 from 0.6; from the X-QuietNet-Agent
    # header on its polls), which decides which rescue call it can take.
    pis_columns = [row[1] for row in db.execute("PRAGMA table_info(pis)")]
    if "install_id" not in pis_columns:
        db.execute("ALTER TABLE pis ADD COLUMN install_id TEXT DEFAULT ''")
    if "agent" not in pis_columns:
        db.execute("ALTER TABLE pis ADD COLUMN agent INTEGER DEFAULT 1")
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
    add_licence_tables()
    row = sql("SELECT value FROM meta WHERE key='secret'", one=True)
    if row:
        SECRET = base64.b64decode(row[0])
    else:
        SECRET = secrets.token_bytes(32)
        sql("INSERT INTO meta VALUES('secret', ?)", (base64.b64encode(SECRET).decode(),), commit=True)
    throttle.load()


def add_licence_tables():
    """Make the licence tables if they are missing. The first time they are made in a database that
    already has accounts, give every one of those accounts a 'legacy' licence (see
    grant_legacy_licences), so that nobody already using the relay is paused by the deploy.

    It all happens in one transaction: the check that the licences table is missing, making it,
    and the grants. So the grants happen exactly once. A restart finds the table and grants
    nothing, and a crash part way leaves no table, so the next start does the whole step again."""
    with db_lock:
        db.execute("BEGIN")
        try:
            new = not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='licences'").fetchone()
            db.execute("""CREATE TABLE IF NOT EXISTS licences(
                id TEXT PRIMARY KEY, user_id INTEGER UNIQUE NOT NULL, key TEXT UNIQUE, key_hint TEXT DEFAULT '',
                state TEXT NOT NULL DEFAULT 'none', plan TEXT DEFAULT '', seats INTEGER NOT NULL DEFAULT 2,
                period_end REAL DEFAULT 0, grace_until REAL DEFAULT 0, cancel_at_period_end INTEGER DEFAULT 0,
                trial_used INTEGER DEFAULT 0, stripe_customer TEXT DEFAULT '', stripe_subscription TEXT DEFAULT '',
                reason TEXT DEFAULT '', created REAL, updated REAL)""")
            db.execute("CREATE INDEX IF NOT EXISTS licences_sub ON licences(stripe_subscription)")
            # What happened to each licence, newest last: grants, changes, rescues, and what the gate
            # refused (or would have refused while it is off). user_id is there too, so an account with
            # no licence yet still has its history. No addresses or household data.
            db.execute("CREATE TABLE IF NOT EXISTS licence_log(licence_id TEXT, user_id INTEGER, at REAL, what TEXT)")
            db.execute("CREATE INDEX IF NOT EXISTS licence_log_user ON licence_log(user_id, at)")
            if new:
                grant_legacy_licences(time.time())
            db.commit()
        except BaseException:
            db.rollback()
            raise


def grant_legacy_licences(now):
    """Give every existing account a licence: plan 'legacy', state 'active', ending LEGACY_DAYS from
    now, with as many seats as it has Pis (paired or waiting), and at least DEFAULT_SEATS. Called
    only by add_licence_tables, inside its transaction, the one time the licences table is made."""
    for (uid,) in db.execute("SELECT id FROM users").fetchall():
        count = db.execute("SELECT COUNT(*) FROM pis WHERE user_id=?", (uid,)).fetchone()[0]
        seats, end = max(DEFAULT_SEATS, count), now + LEGACY_DAYS * 86400
        lid = new_licence_id()
        db.execute("INSERT INTO licences(id,user_id,state,plan,seats,period_end,created,updated) "
                   "VALUES(?,?,'active','legacy',?,?,?,?)", (lid, uid, seats, end, now, now))
        db.execute("INSERT INTO licence_log(licence_id,user_id,at,what) VALUES(?,?,?,?)",
                   (lid, uid, now, "Legacy licence given on the first start with licences: active until %s, "
                                   "%d seats." % (long_date(end), seats)))


def new_licence_id():
    """A fresh public licence id, 'L-' and six capital hex digits, not already used by another licence.
    It is shown to people and will go on the licence label, so it is short; it proves nothing."""
    with db_lock:
        while True:
            lid = "L-" + secrets.token_hex(3).upper()
            if not db.execute("SELECT 1 FROM licences WHERE id=?", (lid,)).fetchone():
                return lid


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
    "login-from:<address>", "login-known-tries:<email>", "paired:<user id>" (successful pairings),
    "rescue:<user id>" (rescue presses) and "signup". The overall limits cannot be dodged by changing network address, because they do
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


# ------------------------------------------------------------------ licences
#
# One licence per account decides three things here: whether a browser is passed through to the
# account's Pis ('remote'), whether downloads and updates are allowed ('updates'; nothing uses it
# yet), and whether a Pi may be added or paired ('pair'). licence_state() works that out; every gate
# calls it, and nothing else reads the stored state.
#
# What never happens, whatever the licence: nothing here reaches the Pi's blocking (the Pi is only
# told the state in its poll answer); no answer to a Pi is ever 401 for a licence reason (today's
# Pis take 401 to mean "unpaired" and delete their token); a lapsed Pi stays paired and keeps
# polling as before; and the two fixed rescue calls (RESCUE_CALLS) work in every state.

LICENCE_STATES = ("none", "trial", "active", "past_due", "expired", "revoked")
GRANT_PLANS = ("owner", "gift", "legacy")       # the plans the owner can grant from the command line
LICENCE_COLUMNS = ("id", "user_id", "state", "plan", "seats", "period_end", "grace_until",
                   "cancel_at_period_end", "reason", "created", "updated")
MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August", "September",
          "October", "November", "December")


def gate_on():
    """True when the licence gate is switched on (QUIETNET_LICENCE_GATE=on). While it is off,
    every gate lets requests through and only notes what it would have refused."""
    return LICENCE_GATE == "on"


def gate_status():
    """One line for the start-up log saying whether the licence gate is on."""
    if gate_on():
        return "Licence gate: on. Remote access and adding Pis need a current licence (QUIETNET_LICENCE_GATE=on)."
    return ("Licence gate: off. Nothing is refused for a licence reason; what would have been refused is "
            "logged. Set QUIETNET_LICENCE_GATE=on to enforce licences.")


def latest_warning(environ=None):
    """A warning for the start-up log if QUIETNET_LATEST is set but is not a plain version number,
    else None. Such a value is never sent to Pis."""
    environ = os.environ if environ is None else environ
    value = (environ.get("QUIETNET_LATEST") or "").strip()
    if value and not VERSION_RE.match(value):
        return ("Warning: QUIETNET_LATEST is set to %r, which isn't a version number like 0.6 or 0.6.1. "
                "Pis are not told about a new version until it is corrected." % value)
    return None


def say(line):
    """Write one line to the relay's log (the host keeps what the program prints). Tests replace it."""
    print(line, flush=True)


def long_date(ts):
    """A date written out for people, like '4 January 2027', in UTC (the relay's own clock)."""
    t = time.gmtime(ts)
    return "%d %s %d" % (t.tm_mday, MONTHS[t.tm_mon - 1], t.tm_year)


def licence_row(uid):
    """The stored licence for account `uid`, as a dict of LICENCE_COLUMNS, or None if it has none.
    Only licence_state() should look at what this holds about the state."""
    row = sql("SELECT %s FROM licences WHERE user_id=?" % ",".join(LICENCE_COLUMNS), (uid,), one=True)
    return dict(zip(LICENCE_COLUMNS, row)) if row else None


def licence_state(row, now):
    """Work out what a licence is right now, and what it allows. `row` is from licence_row() (None
    for an account with no licence, which is state 'none'); `now` is the relay's clock.

    Returns a dict: 'state' (none, trial, active, cancelling, past_due, expired or revoked), 'remote'
    (a browser may reach the account's Pis), 'updates' (downloads and updates), 'pair' (a Pi may be
    added or paired, within the seats), 'until' (the end of the paid period, 0 for no end),
    'grace_until' (past_due only: when it stops), 'seats', 'plan' and 'id' (the public licence id).

    The steps that depend on time are applied here, not stored:
      - active or trial with an end date counts as expired RENEWAL_LAG_DAYS after that date (a
        renewal may simply not have been heard yet);
      - active set to end at the period end ('cancelling') counts as expired from the end date itself;
      - past_due counts as expired once its grace ends: grace_until if set, else PAST_DUE_DAYS after
        the period end (with neither, it has no end until the state is changed).
    A stored state this relay doesn't know counts as 'none', so nothing is allowed by mistake."""
    info = {"state": "none", "remote": False, "updates": False, "pair": False, "until": 0,
            "grace_until": 0, "seats": DEFAULT_SEATS, "plan": "", "id": ""}
    if not row:
        return info
    until = float(row.get("period_end") or 0)
    seats = row.get("seats")
    info.update(until=until, seats=DEFAULT_SEATS if seats is None else int(seats),
                plan=row.get("plan") or "", id=row.get("id") or "")
    state = row.get("state") if row.get("state") in LICENCE_STATES else "none"
    if state in ("active", "trial") and until > 0:
        if row.get("cancel_at_period_end"):
            if now >= until:
                state = "expired"
            elif state == "active":
                state = "cancelling"
        elif now >= until + RENEWAL_LAG_DAYS * 86400:
            state = "expired"
    elif state == "past_due":
        grace = float(row.get("grace_until") or 0) or (until + PAST_DUE_DAYS * 86400 if until > 0 else 0)
        if grace and now >= grace:
            state = "expired"
        else:
            info["grace_until"] = grace
    info["state"] = state
    if state in ("trial", "active", "cancelling"):
        info.update(remote=True, updates=True, pair=True)
    elif state == "past_due":
        info.update(remote=True, updates=True)          # no new Pis while a payment is owed
    return info


def account_licence(uid, now=None):
    """licence_state() for account `uid` at `now` (the relay's clock if not given)."""
    return licence_state(licence_row(uid), time.time() if now is None else now)


def seats_used(uid, leave_out=()):
    """Seats an account is using: its paired Pis, not counting any whose id is in `leave_out`."""
    return sum(1 for (pid,) in sql("SELECT id FROM pis WHERE user_id=? AND paired=1", (uid,))
               if pid not in leave_out)


def seats_promised(uid, now):
    """Seats in use plus seats promised: paired Pis, and Pis waiting with a pairing code still in
    date. A new Pi may be added only while this is below the licence's seats."""
    return sql("SELECT COUNT(*) FROM pis WHERE user_id=? AND (paired=1 OR code_ts>?)",
               (uid, now - PAIR_CODE_MINUTES * 60), one=True)[0]


def log_licence(uid, lid, what, now=None):
    """Add one line to the licence log for account `uid` (licence `lid`, '' if it has none).

    Lines written because of what an account's own browser or Pi did (gate notes, rescues) are kept
    to the newest LICENCE_LOG_KEEP per account, so no account can grow the log without end. The
    owner's own lines (grants and changes from the command line, and the legacy grant) are few and
    always kept: they start with 'Owner ' or 'Legacy licence' and are never written here."""
    with db_lock:
        db.execute("INSERT INTO licence_log(licence_id,user_id,at,what) VALUES(?,?,?,?)",
                   (lid or "", uid, time.time() if now is None else now, what))
        db.execute("DELETE FROM licence_log WHERE user_id=? AND what NOT LIKE 'Owner %' AND what NOT LIKE "
                   "'Legacy licence%' AND rowid NOT IN (SELECT rowid FROM licence_log WHERE user_id=? AND what "
                   "NOT LIKE 'Owner %' AND what NOT LIKE 'Legacy licence%' ORDER BY at DESC, rowid DESC LIMIT ?)",
                   (uid, uid, LICENCE_LOG_KEEP))
        db.commit()


# What each gate guards, for the log.
GATE_WORDS = {"remote": "remote access to a Pi", "add": "adding a Pi", "add-seats": "adding a Pi beyond the seats",
              "pair": "pairing a Pi", "pair-seats": "pairing a Pi beyond the seats"}
_gate_lock = threading.Lock()
_gate_noted = {}            # (user id, gate) -> when a refusal was last noted


def licence_gate(uid, gate, allowed, info, now=None):
    """The one place a licence check says yes or no. Returns True if the request may go ahead.

    When `allowed` is false: with the gate on, the answer is no; with it off (the default), the
    answer is still yes. Either way the refusal, or the refusal that would have been, is noted in
    the log and the licence log, at most once per GATE_LOG_SECONDS for each account and gate, so a
    dashboard's many calls and a Pi's polls can't flood either."""
    if allowed:
        return True
    on = gate_on()
    now = time.time() if now is None else now
    with _gate_lock:
        last = _gate_noted.get((uid, gate))
        note = last is None or now - last >= GATE_LOG_SECONDS
        if note:
            if len(_gate_noted) > 10000:        # forget old notes rather than grow without end
                for key in [k for k, t in _gate_noted.items() if now - t >= GATE_LOG_SECONDS]:
                    del _gate_noted[key]
            _gate_noted[(uid, gate)] = now
    if note:
        what = ("Refused %s: licence state %s." if on else
                "Would have refused %s: licence state %s. Let through because the licence gate is off.") % (
            GATE_WORDS.get(gate, gate), info["state"])
        say("Licence gate: account %d, licence %s. %s" % (uid, info["id"] or "none", what))
        log_licence(uid, info["id"], what, now)
    return not on


def licence_for_pi(info, used, now):
    """The 'licence' object added to every poll answer (version 1). 'remote' and 'updates' say what
    the relay will actually allow, so with the gate off both are true whatever the state; 'state'
    is always the real state. Only numbers, fixed words and true or false: the Pi shows its own
    wording, never text from the relay."""
    out = {"v": 1, "state": info["state"], "remote": bool(info["remote"] or not gate_on()),
           "updates": bool(info["updates"] or not gate_on()), "until": int(info["until"]),
           "seats": int(info["seats"]), "used": int(used), "now": int(now)}
    if info["state"] == "past_due" and info["grace_until"]:
        out["grace_until"] = int(info["grace_until"])
    return out


# -- wording (section 4.7 of the licensing design; the Pi's own sentences match these)

PAIR_NEEDS_LICENCE = "Remote access needs a QuietNet licence. Your Pi is still filtering at home. Visit q3n.net to renew."
ADD_NEEDS_LICENCE = "Adding a Pi needs a current licence."
SAME_IDENTITY = ("Another Pi with the same identity is online. This usually means the SD card was copied. "
                 "On this Pi, run the installer with --new-identity, then pair again.")


def seats_full(seats, then):
    """'Your licence covers 2 Pis and both are in use.' followed by `then`, for any number of seats."""
    if seats <= 0:
        words = "Your licence doesn't cover any Pis."
    elif seats == 1:
        words = "Your licence covers 1 Pi and it is in use."
    elif seats == 2:
        words = "Your licence covers 2 Pis and both are in use."
    else:
        words = "Your licence covers %d Pis and all of them are in use." % seats
    return words + " " + then


def pis_are(n, what):
    """'1 is paired', '2 are paired' or 'none are paired', for the seat sentences."""
    if n <= 0:
        return "none are " + what
    return "%d %s %s" % (n, "is" if n == 1 else "are", what)


def no_free_seat(seats, paired, promised, then):
    """Why a new Pi can't be added: every seat is taken. When paired Pis alone fill the seats, the
    seats_full() sentence; when Pis waiting to be paired (with a code still in date) make up the
    rest, a sentence that names them, so it agrees with 'Pis: 1 of 2' on the Licence card. Followed
    by `then`."""
    if paired >= seats:
        return seats_full(seats, then)
    covers = "1 Pi" if seats == 1 else "%d Pis" % seats
    return "Your licence covers %s: %s and %s. %s" % (
        covers, pis_are(paired, "paired"), pis_are(promised - paired, "waiting to be paired"), then)


def ending_soon(info, now):
    """The warning shown in a licence's last 7 days, or '' when none is due. Given for active
    (with an end date), trial and cancelling licences, but not for plans that renew by themselves
    (names starting 'home-'), whose sentence already says when they renew."""
    until = info["until"]
    if info["state"] not in ("active", "trial", "cancelling") or not until or not 0 < until - now <= 7 * 86400:
        return ""
    if info["state"] == "active" and info["plan"].startswith("home-"):
        return ""
    return ("Your QuietNet licence ends on %s. Filtering at home carries on; remote access and updates stop "
            "unless it's renewed." % long_date(until))


def ended_on(info):
    """'ended on 4 January 2027', or 'has ended' when the licence has no end date to name."""
    return "ended on " + long_date(info["until"]) if info["until"] else "has ended"


def licence_sentence(info):
    """The sentence for the Licence card on the account page, one per state, matching the Pi's own."""
    state, until = info["state"], info["until"]
    if state == "trial":
        return ("Free trial: remote access works until %s." % long_date(until)) if until else "Free trial."
    if state == "active":
        if not until:
            return "Licence active, with no end date."
        if info["plan"].startswith("home-"):
            return "Licence active. Renews on %s." % long_date(until)
        return "Licence active until %s." % long_date(until)
    if state == "cancelling":
        return ("Your licence is cancelled. Remote access works until %s. Filtering at home carries on "
                "after that." % long_date(until))
    if state == "past_due":
        stop = (" on " + long_date(info["grace_until"])) if info["grace_until"] else ""
        return ("Your last payment didn't go through. Remote access will stop%s unless it's sorted at "
                "q3n.net. Filtering at home is not affected." % stop)
    if state == "expired":
        return ("Remote access is paused because the licence %s. Your Pi is still filtering and blocking at "
                "home as normal. Renew at q3n.net to turn remote access back on." % ended_on(info))
    if state == "revoked":
        return ("Remote access has been switched off for this licence. Your Pi is still filtering at home. "
                "Contact the seller through q3n.net.")
    return "This account has no QuietNet licence yet. Remote access needs one; filtering at home doesn't."


def paused_api_sentence(info):
    """The 'error' sentence in the 402 answer to a dashboard call made while remote access is paused."""
    if info["state"] == "revoked":
        return "Remote access has been switched off for this licence. Your Pi is still blocking at home."
    if info["state"] == "expired":
        return "Remote access is paused because the licence %s. Your Pi is still blocking at home." % ended_on(info)
    return "Remote access needs a QuietNet licence. Your Pi is still blocking at home."


def paused_lead(info):
    """The first lines of the paused page, saying why remote access is paused."""
    if info["state"] == "revoked":
        return ("Remote access has been switched off for this licence. Your Pi is still filtering and blocking "
                "at home as normal. Contact the seller through q3n.net.")
    if info["state"] == "expired":
        return ("Your QuietNet licence %s. Your Pi is still filtering and blocking at home as normal. "
                "Renewing turns remote access back on within a minute, with nothing to pair again." % ended_on(info))
    return ("This account has no QuietNet licence, so remote access is paused. Your Pi is still filtering "
            "and blocking at home as normal.")


# -- rescue: the only calls that reach a Pi whatever the licence

# The two buttons on the paused page, and the calls they send. Each call is fixed text: nothing from
# the browser goes into its path or body. A Pi older than 0.6 (agent 1) has no /api/rescue, so for it
# "internet back on" can only turn off the household kill switch.
RESCUE_CALLS = {
    ("internet-on", 2): {"method": "POST", "path": "/api/rescue", "body": '{"what": "internet-on"}'},
    ("internet-on", 1): {"method": "POST", "path": "/api/kill", "body": '{"on": false}'},
    ("pause-hour", 2): {"method": "POST", "path": "/api/pause", "body": '{"minutes": 60}'},
    ("pause-hour", 1): {"method": "POST", "path": "/api/pause", "body": '{"minutes": 60}'},
}
RESCUE_DONE = {
    ("internet-on", 2): "Done. Every device's internet switch is back on. It can take a minute or two for devices to notice.",
    ("internet-on", 1): "Done. The household kill switch is off. It can take a minute or two for devices to notice.",
    ("pause-hour", 2): "Done. Blocking is paused for an hour.",
    ("pause-hour", 1): "Done. Blocking is paused for an hour.",
}
RESCUE_OFFLINE = "Your Pi isn't connected to q3n.net right now, so this couldn't be sent. Is it switched on?"
RESCUE_PATH = re.compile(r"^/pi/([^/]+)/rescue$")


def rescue_call(what, agent):
    """A fresh copy of the fixed call for rescue `what` ('internet-on' or 'pause-hour') on a Pi whose
    agent is `agent` (2 from 0.6, anything else counts as 1). None for any other `what`."""
    call = RESCUE_CALLS.get((what, 2 if agent == 2 else 1))
    return dict(call) if call else None


# ------------------------------------------------------------------ looks (themes)

# The looks a person can pick for these pages; the first is the default. The choice is kept in a
# 'qn_theme' cookie, which is shared with the dashboard opened through this relay (same website).
# It is a display preference only: it is checked against this list wherever it is read, and never
# used for anything else.
THEMES = ("calm", "household", "control")
THEME_COOKIE_DAYS = 365
# (id, name shown, one-line description). The dashboard's Appearance section uses the same words.
THEME_CHOICES = (
    ("calm", "Calm", "Plain and quiet, with the sections down the side. Follows your device's light or dark setting."),
    ("household", "Household", "Warmer and roomier, with devices and groups shown as large cards. Follows light or dark."),
    ("control", "Control room", "Dark and compact, with the day's figures across the top. Always dark."),
)


def theme_name(value):
    """The theme to use for a cookie or form value: the value itself if it is one of THEMES, else
    'calm'. The value comes from the browser, so nothing else is ever done with it."""
    return value if value in THEMES else THEMES[0]


# Small line drawings used on the pages. Each is decorative (the words beside it say the same),
# so it is hidden from screen readers.
ICON_PATHS = {
    "logo": '<path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "monitor": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "moon": '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
    "chip": ('<rect x="6" y="6" width="12" height="12" rx="2"/>'
             '<path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>'),
    "right": '<path d="M9 6l6 6-6 6"/>',
    "left": '<path d="M15 6l-6 6 6 6"/>',
}


def icon(name, css="ico"):
    """One of ICON_PATHS as an inline drawing, hidden from screen readers, sized by its CSS class."""
    return ('<svg class="%s" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">%s</svg>'
            % (html.escape(css), ICON_PATHS[name]))


# ------------------------------------------------------------------ small HTML pages

# The style sheet for every relay page, holding all three looks. It is written against colour
# names (custom properties such as --accent) that each look sets; the dashboard uses the same names.
# Calm is also the look when no theme is named. Calm and Household follow the device's light or dark
# setting; Control room is always dark. Text colours were chosen to give at least 4.5:1 contrast.
RELAY_CSS = """
:root,[data-theme="calm"]{color-scheme:light dark;
--bg:#f4f3ef;--surface:#ffffff;--surface-2:#f4f3ef;--chip-bg:#efede7;--field-bg:#ffffff;--top-bg:#ffffff;
--ink:#1d1c1a;--ink-2:#3d3a35;--body-2:#3d3a35;--muted:#5e5a53;--line:#e0ddd5;--line-2:#e0ddd5;--line-strong:#e0ddd5;
--field-line:#8a857b;--accent:#0e6b62;--accent-hover:#0a4f48;--on-accent:#ffffff;--accent-soft:#e1eeeb;
--accent-soft-ink:#0a524b;--accent-line:#b9d6d1;--ok:#0e6b62;--ok-ink:#0a524b;--ok-soft:#e1eeeb;
--warn:#7a4a07;--warn-dot:#b7791f;--warn-soft:#fbf1dc;--danger:#a33222;--danger-soft:#fbf3f1;
--danger-soft-ink:#a33222;--danger-line:#e9cfc8;--focus:#0e6b62;--focus-halo:#cfe5e1;
--code-bg:#f4f3ef;--code-ink:#1d1c1a;--code-line:#e0ddd5;--shadow-card:none;--shadow-raise:0 8px 24px rgba(29,28,26,.12);
--font-body:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;--font-head:var(--font-body);
--font-mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
--fs-body:15px;--fs-small:13px;--fs-xs:12.5px;--fs-h1:24px;--fs-h2:15px;--fs-h3:13px;--head-weight:600;--head-track:-0.02em;
--r-sm:4px;--r-md:8px;--r-lg:12px;--r-btn:8px;--r-pill:999px;--gap:12px;--pad-card:20px;--focus-w:2px;
--wrap:800px;--wrap-wide:1040px}
@media (prefers-color-scheme:dark){:root,[data-theme="calm"]{
--bg:#161513;--surface:#1f1e1b;--surface-2:#2a2925;--chip-bg:#2a2925;--field-bg:#161513;--top-bg:#1f1e1b;
--ink:#ecebe6;--ink-2:#d2cfc7;--body-2:#d2cfc7;--muted:#a9a49a;--line:#3a3832;--line-2:#3a3832;--line-strong:#48453e;
--field-line:#7a756b;--accent:#5fc4b6;--accent-hover:#7dd3c7;--on-accent:#0b2522;--accent-soft:#1d3633;
--accent-soft-ink:#9fded4;--accent-line:#2f5a54;--ok:#5fc4b6;--ok-ink:#9fded4;--ok-soft:#1d3633;
--warn:#e6b25a;--warn-dot:#e6b25a;--warn-soft:#3a2d12;--danger:#f0907f;--danger-soft:#3a1f1b;
--danger-soft-ink:#f0907f;--danger-line:#5c2e27;--focus:#5fc4b6;--focus-halo:#234541;
--code-bg:#161513;--code-ink:#ecebe6;--code-line:#3a3832;--shadow-raise:0 8px 24px rgba(0,0,0,.5)}}
[data-theme="household"]{color-scheme:light dark;
--bg:#FAF7F2;--surface:#FFFFFF;--surface-2:#FBF8F4;--chip-bg:#F3EDE7;--field-bg:#FFFFFF;--top-bg:transparent;
--ink:#2A2125;--ink-2:#2A2125;--body-2:#2A2125;--muted:#5E5156;--line:#E8E0D8;--line-2:#EFE8E1;--line-strong:#E0D6CD;
--field-line:#94878D;--accent:#6B2E5F;--accent-hover:#4A1F42;--on-accent:#FFFFFF;--accent-soft:#F3E8F0;
--accent-soft-ink:#4A1F42;--accent-line:#D9B8D1;--ok:#0F766E;--ok-ink:#0F766E;--ok-soft:#E1F2EF;
--warn:#7A4B2A;--warn-dot:#B7791F;--warn-soft:#F4ECE4;--danger:#A3302A;--danger-soft:#FBEDEC;
--danger-soft-ink:#A3302A;--danger-line:#E6C9C6;--focus:#6B2E5F;--focus-halo:#D9B8D1;
--code-bg:#2A2125;--code-ink:#F6EFE9;--code-line:#2A2125;--shadow-card:0 1px 2px rgba(42,33,37,.04);
--shadow-raise:0 1px 2px rgba(42,33,37,.04),0 8px 24px rgba(42,33,37,.06);
--font-head:ui-rounded,"SF Pro Rounded",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--fs-body:16px;--fs-small:14px;--fs-xs:13px;--fs-h1:32px;--fs-h2:20px;--fs-h3:15px;--head-weight:600;--head-track:-0.02em;
--r-sm:6px;--r-md:12px;--r-lg:20px;--r-btn:999px;--r-pill:999px;--gap:16px;--pad-card:20px 24px;--focus-w:3px;
--wrap:880px;--wrap-wide:1040px}
@media (prefers-color-scheme:dark){[data-theme="household"]{
--bg:#1C1619;--surface:#261E22;--surface-2:#2F262A;--chip-bg:#33282E;--field-bg:#1C1619;--top-bg:transparent;
--ink:#F6EFE9;--ink-2:#F6EFE9;--body-2:#F6EFE9;--muted:#C2B4BA;--line:#3D3237;--line-2:#362C31;--line-strong:#4A3D43;
--field-line:#857479;--accent:#E3B5D8;--accent-hover:#EDC8E3;--on-accent:#2A1025;--accent-soft:#3E2639;
--accent-soft-ink:#F0D3E8;--accent-line:#5A3A52;--ok:#5EC4B6;--ok-ink:#8FD9CE;--ok-soft:#1E3532;
--warn:#E8B48C;--warn-dot:#E8B48C;--warn-soft:#3A2A1E;--danger:#F2948C;--danger-soft:#3A1F1E;
--danger-soft-ink:#F2948C;--danger-line:#5C3431;--focus:#E3B5D8;--focus-halo:#5A3A52;
--code-bg:#120E10;--code-ink:#F6EFE9;--code-line:#3D3237;--shadow-card:none;--shadow-raise:0 8px 24px rgba(0,0,0,.5)}}
[data-theme="control"]{color-scheme:dark;
--bg:#0E1116;--surface:#151A21;--surface-2:#11151B;--chip-bg:#1B222B;--field-bg:#0B0E12;--top-bg:#0A0C10;
--ink:#E6EAF0;--ink-2:#C9D2DC;--body-2:#B4BFCC;--muted:#9AA6B5;--line:#2A333F;--line-2:#222A35;--line-strong:#2F3946;
--field-line:#5C6878;--accent:#F5B83D;--accent-hover:#FFD27A;--on-accent:#14110A;--accent-soft:#2A2210;
--accent-soft-ink:#F5B83D;--accent-line:#5C4A1E;--ok:#4ADE80;--ok-ink:#7EE2A8;--ok-soft:#10241A;
--warn:#F5B83D;--warn-dot:#F5B83D;--warn-soft:#2A2210;--danger:#FF8A80;--danger-soft:#1E1415;
--danger-soft-ink:#FFB4AC;--danger-line:#5A2E2A;--focus:#F5B83D;--focus-halo:transparent;
--code-bg:#0B0E12;--code-ink:#E6EAF0;--code-line:#2A333F;--shadow-card:none;--shadow-raise:0 12px 32px rgba(0,0,0,.6);
--font-head:var(--font-body);
--fs-body:15px;--fs-small:13px;--fs-xs:11px;--fs-h1:22px;--fs-h2:15px;--fs-h3:14px;--head-weight:600;--head-track:-0.01em;
--r-sm:4px;--r-md:6px;--r-lg:10px;--r-btn:6px;--r-pill:999px;--gap:16px;--pad-card:16px;--focus-w:2px;--wrap:72rem;--wrap-wide:60rem}

*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);
font-family:var(--font-body);font-size:var(--fs-body);line-height:1.5;-webkit-font-smoothing:antialiased}
h1,h2,h3{margin:0;font-family:var(--font-head);font-weight:var(--head-weight);letter-spacing:var(--head-track);color:var(--ink)}
h1{font-size:var(--fs-h1);line-height:1.2}h2{font-size:var(--fs-h2);line-height:1.3}h3{font-size:var(--fs-h3);line-height:1.35}
p{margin:0}b{font-weight:600}
a{color:var(--accent);text-underline-offset:2px}a:hover{color:var(--accent-hover)}
:focus-visible{outline:var(--focus-w) solid var(--focus);outline-offset:2px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.ico{width:18px;height:18px;flex:none}
.wrap{width:100%;max-width:var(--wrap);margin:0 auto;padding:0 16px}
.wrap.wide{max-width:var(--wrap-wide)}
main.wrap{flex:1 0 auto;padding-top:28px;padding-bottom:40px}
.mt{margin-top:16px}
p.mt a{display:inline-flex;align-items:center;min-height:44px}
.top{background:var(--top-bg);border-bottom:1px solid var(--line)}
.topin{display:flex;align-items:center;flex-wrap:wrap;gap:8px 10px;min-height:56px}
.topin .grow{flex:1 1 auto}
.logo-mark{width:24px;height:24px;color:var(--accent)}
.brand{font-family:var(--font-head);font-weight:600;font-size:17px;letter-spacing:-0.01em;color:var(--ink)}
.foot{border-top:1px solid var(--line);color:var(--muted);font-size:13px;padding:18px 0 28px}
.meta{font-size:var(--fs-small);color:var(--muted)}
.grow{flex:1 1 220px;min-width:0}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;padding:0 16px;margin:0;
border:1px solid var(--line-strong);border-radius:var(--r-btn);background:var(--surface);color:var(--ink-2);
font:inherit;font-size:14px;font-weight:500;line-height:1.2;text-decoration:none;cursor:pointer}
.btn:hover{border-color:var(--field-line);color:var(--ink)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent);font-weight:600}
.btn.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover);color:var(--on-accent)}
.btn.danger-outline{border-color:var(--danger);color:var(--danger)}
.btn.danger-outline:hover{background:var(--danger-soft);color:var(--danger)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--ink-2)}
.btn.ghost:hover{background:var(--chip-bg);color:var(--ink)}
.btn.full{width:100%}
form.inline{margin:0}
.btnrow{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.rescue h2{margin-top:20px}
.rescue .meta{margin-top:8px}

.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-lg);padding:var(--pad-card);
box-shadow:var(--shadow-card);margin:0 0 var(--gap)}
.card.narrow{max-width:480px}
.card.narrow h1{margin-bottom:8px}
.card.empty{color:var(--muted)}
.notice{border:1px solid transparent;border-radius:var(--r-md);padding:10px 14px;margin:14px 0;font-size:14px}
.notice.info{background:var(--accent-soft);color:var(--accent-soft-ink);border-color:var(--accent-line)}
.notice.danger{background:var(--danger-soft);color:var(--danger-soft-ink);border-color:var(--danger-line)}
.notice.warn{background:var(--warn-soft);color:var(--warn);border-color:var(--warn-dot)}

.fld{margin:0 0 16px}
.fld label{display:block;font-size:14px;font-weight:600;color:var(--ink);margin:0 0 6px}
.lblrow{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:4px 8px}
input[type=email],input[type=password],input[type=text],input:not([type]){display:block;width:100%;min-height:44px;
padding:10px 12px;margin:0;border:1px solid var(--field-line);border-radius:var(--r-md);background:var(--field-bg);
color:var(--ink);font:inherit}
input::placeholder{color:var(--muted);opacity:1}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--focus-halo)}

.auth{display:flex;flex-wrap:wrap;gap:48px;align-items:flex-start;justify-content:space-between;padding:8px 0 24px}
.intro{flex:1 1 340px;max-width:440px}
.intro h1{font-size:28px;line-height:1.2;margin-bottom:12px}
.lead{font-size:15px;color:var(--muted);margin-bottom:22px}
.points{list-style:none;margin:0;padding:0;display:grid;gap:14px}
.points li{display:flex;gap:12px;align-items:flex-start;font-size:14px;color:var(--ink-2)}
.pt-ico{display:inline-flex;align-items:center;justify-content:center;flex:none;color:var(--accent)}
.authcard{flex:1 1 320px;max-width:400px;padding:28px 24px}
.authcard h2{font-size:20px;margin-bottom:4px}
.authcard form{margin-top:20px}
.switch-auth{margin-top:12px}
.switch-auth a{display:inline-flex;align-items:center;min-height:44px}

.pagehead{margin:0 0 20px}
.pagehead h1{margin-bottom:4px}
.eyebrow{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.thead{display:none}
.pis{background:none;border:0;padding:0;box-shadow:none;border-radius:0}
.pirow{display:flex;align-items:center;gap:12px;min-height:64px;padding:12px 16px;margin:0 0 8px;background:var(--surface);
border:1px solid var(--line);border-radius:10px;color:var(--ink);text-decoration:none}
.pirow:hover{border-color:var(--accent);color:var(--ink)}
.avatar{display:inline-flex;align-items:center;justify-content:center;flex:none;width:36px;height:36px;border-radius:8px;
background:var(--accent-soft);color:var(--accent)}
.pi-main{flex:1 1 auto;min-width:0;display:flex;flex-direction:column}
.name{font-weight:600;overflow-wrap:anywhere}
.status{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.status.wait{color:var(--warn)}
.go{display:inline-flex;align-items:center;gap:2px;flex:none;font-size:14px;font-weight:500;color:var(--accent)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex:none;background:var(--muted)}
.dot.on{background:var(--ok)}
.dot.wait{background:transparent;border:2px solid var(--warn-dot)}

.pending{padding:0;overflow:hidden;border-radius:10px}
.pending-head{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--line)}
.pending-head .avatar{background:var(--chip-bg);color:var(--muted)}
.pending-head h2{overflow-wrap:anywhere}
.pending-body{padding:16px}
.paircode{display:flex;flex-direction:column;align-items:flex-start;gap:4px;margin:0 0 18px}
.label{font-size:12px;color:var(--muted)}
.bigcode{font-family:var(--font-mono);font-size:24px;font-weight:600;letter-spacing:.12em;line-height:1.3;color:var(--ink);
font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.steps h3{margin:20px 0 4px}.steps h3:first-child{margin-top:0}
.steps p{margin:0 0 8px}
.cmd{display:block;margin:10px 0;padding:12px 14px;background:var(--code-bg);color:var(--code-ink);border:1px solid var(--code-line);
border-radius:var(--r-md);font:13px/1.6 var(--font-mono);white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-all;
user-select:all;-webkit-user-select:all}
.pairvals{margin:10px 0 0;display:grid;gap:6px}
.pairvals div{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 12px}
.pairvals dt{min-width:9rem;font-size:13px;color:var(--muted)}
.pairvals dd{margin:0;min-width:0}
code.inline{font-family:var(--font-mono);font-size:13px;background:var(--chip-bg);color:var(--ink);padding:2px 6px;
border-radius:var(--r-sm);overflow-wrap:anywhere}

.add{border-top:1px solid var(--line);padding-top:24px;margin:24px 0}
.add h2{margin-bottom:4px}
.addform{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px;margin-top:14px}
.addform .fld{margin:0;max-width:360px}
.appearance h2{margin-bottom:4px}
.themes{border:0;margin:16px 0;padding:0;min-width:0;display:grid;gap:8px}
.theme-opt{display:flex;align-items:center;gap:12px;min-height:56px;padding:10px 14px;border:1px solid var(--line-strong);
border-radius:var(--r-md);background:var(--surface);cursor:pointer}
.theme-opt:hover{border-color:var(--field-line)}
.theme-opt input{accent-color:var(--accent);width:20px;height:20px;flex:none;margin:0}
.theme-text{display:flex;flex-direction:column;min-width:0}
.theme-text b{color:var(--ink)}
.theme-opt input:checked~.theme-text b{color:var(--accent)}
.swatch{display:inline-flex;flex:none;border:1px solid var(--line);border-radius:6px;overflow:hidden}
.swatch i{display:block;width:14px;height:28px}
.swatch-calm i:nth-child(1){background:#f4f3ef}.swatch-calm i:nth-child(2){background:#0e6b62}.swatch-calm i:nth-child(3){background:#1d1c1a}
.swatch-household i:nth-child(1){background:#FAF7F2}.swatch-household i:nth-child(2){background:#6B2E5F}.swatch-household i:nth-child(3){background:#0F766E}
.swatch-control i:nth-child(1){background:#0E1116}.swatch-control i:nth-child(2){background:#F5B83D}.swatch-control i:nth-child(3){background:#E6EAF0}

[data-theme="household"] .top{border-bottom:0}
[data-theme="household"] .topin{padding:20px 16px 4px;min-height:0}
[data-theme="household"] .brand{font-size:20px}
[data-theme="household"] .logo-mark{width:28px;height:28px}
[data-theme="household"] .foot{border-top:0}
[data-theme="household"] .btn{font-size:15px}
[data-theme="household"] .btn.danger-outline{border-color:var(--danger-line)}
[data-theme="household"] .btn.full,[data-theme="household"] .addform .btn{border-radius:12px;min-height:48px}
[data-theme="household"] input[type=email],[data-theme="household"] input[type=password],
[data-theme="household"] input[type=text],[data-theme="household"] input:not([type]){min-height:48px;border-radius:12px}
[data-theme="household"] .intro h1{font-size:40px;line-height:1.1;max-width:14ch;margin-bottom:16px}
[data-theme="household"] .lead{font-size:17px}
[data-theme="household"] .points li{align-items:center;font-size:15px}
[data-theme="household"] .pt-ico{width:32px;height:32px;border-radius:50%;background:var(--ok-soft);color:var(--ok-ink)}
[data-theme="household"] .points li:nth-child(2) .pt-ico{background:var(--accent-soft);color:var(--accent)}
[data-theme="household"] .points li:nth-child(3) .pt-ico{background:var(--warn-soft);color:var(--warn)}
[data-theme="household"] .authcard{max-width:440px;padding:32px;box-shadow:var(--shadow-raise)}
[data-theme="household"] .card h2,[data-theme="household"] .add h2{font-size:20px}
[data-theme="household"] .pirow{border-radius:var(--r-lg);padding:16px 20px;gap:16px;box-shadow:var(--shadow-card);margin-bottom:12px}
[data-theme="household"] .pirow .avatar{width:48px;height:48px;border-radius:14px;background:var(--ok-soft);color:var(--ok-ink)}
[data-theme="household"] .pirow .name{font-family:var(--font-head);font-size:20px;letter-spacing:-0.01em}
[data-theme="household"] .status{font-size:14px}
[data-theme="household"] .status.on{color:var(--ok-ink);font-weight:600}
[data-theme="household"] .status.wait{font-weight:600}
[data-theme="household"] .go{min-height:44px;padding:0 18px;border-radius:var(--r-pill);background:var(--accent);color:var(--on-accent);font-weight:600}
[data-theme="household"] .pirow:hover .go{background:var(--accent-hover)}
[data-theme="household"] .pending{border-radius:var(--r-lg)}
[data-theme="household"] .pending-head{padding:18px 24px;border-bottom-color:var(--line-2)}
[data-theme="household"] .pending-head .avatar{width:48px;height:48px;border-radius:14px;background:var(--warn-soft);color:var(--warn)}
[data-theme="household"] .pending-body{padding:20px 24px 24px}
[data-theme="household"] .paircode{background:var(--accent-soft);border-radius:14px;padding:16px 20px}
[data-theme="household"] .paircode .label{color:var(--accent-soft-ink);font-weight:600;font-size:13px}
[data-theme="household"] .paircode .meta{color:var(--accent-soft-ink)}
[data-theme="household"] .bigcode{font-size:26px;letter-spacing:.08em}
[data-theme="household"] .cmd{font-size:14px;border-radius:12px;padding:14px 16px}
[data-theme="household"] .add{border:1px dashed var(--field-line);border-radius:var(--r-lg);padding:24px}
[data-theme="household"] .theme-opt{border-radius:16px}

[data-theme="control"] .top{border-bottom-color:var(--line-2)}
[data-theme="control"] .topin{min-height:52px}
[data-theme="control"] .brand{font-size:15px}
[data-theme="control"] .foot{border-top-color:var(--line-2)}
[data-theme="control"] .btn{background:transparent;font-size:13px}
[data-theme="control"] .btn:hover{background:#1B222B;border-color:#3A4553}
[data-theme="control"] .btn.primary{background:var(--accent);border-color:var(--accent)}
[data-theme="control"] .btn.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
[data-theme="control"] .btn.danger-outline{border-color:var(--danger-line)}
[data-theme="control"] .btn.danger-outline:hover{background:#2A1715;border-color:#FF6B5E}
[data-theme="control"] input::placeholder{color:#8A95A3}
[data-theme="control"] .intro h1{font-size:28px}
[data-theme="control"] .lead{color:var(--body-2)}
[data-theme="control"] .points{gap:0;border-top:1px solid var(--line-2)}
[data-theme="control"] .points li{border-bottom:1px solid var(--line-2);padding:12px 0;color:var(--body-2)}
[data-theme="control"] .pt-ico{display:none}
[data-theme="control"] .authcard{max-width:26rem}
[data-theme="control"] .eyebrow,[data-theme="control"] .thead{font:500 var(--fs-xs)/1.4 var(--font-mono);text-transform:uppercase;
letter-spacing:.08em;color:var(--muted)}
[data-theme="control"] .pis .eyebrow{position:static;width:auto;height:auto;margin:0;overflow:visible;clip:auto;white-space:normal;
display:block;padding:10px 16px;background:var(--surface-2);border-bottom:1px solid var(--line-2)}
[data-theme="control"] .pis{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-lg);overflow:hidden}
[data-theme="control"] .thead{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr) 6rem;gap:12px;
padding:8px 16px 8px 44px;border-bottom:1px solid var(--line-2)}
[data-theme="control"] .pirow{display:grid;grid-template-columns:16px minmax(0,2fr) minmax(0,1fr) 6rem;gap:12px;
min-height:52px;padding:8px 16px;margin:0;border:0;border-radius:0;background:none}
[data-theme="control"] .pirow+.pirow{border-top:1px solid var(--line-2)}
[data-theme="control"] .pirow:hover{background:#1B222B}
[data-theme="control"] .pirow:focus-visible{outline-offset:-4px}
[data-theme="control"] .pirow .avatar{width:16px;height:16px;background:none;color:var(--muted)}
[data-theme="control"] .pirow .avatar .ico{width:16px;height:16px}
[data-theme="control"] .pi-main{display:contents}
[data-theme="control"] .status.on{color:var(--ok-ink)}
[data-theme="control"] .dot.on{box-shadow:0 0 0 3px rgba(74,222,128,.18)}
[data-theme="control"] .go{justify-content:flex-end}
[data-theme="control"] .pending-head{border-bottom-color:var(--line-2)}
[data-theme="control"] .pending-head .avatar{width:32px;height:32px;border-radius:var(--r-md)}
[data-theme="control"] .pending-body{display:flex;flex-wrap:wrap;padding:0}
[data-theme="control"] .paircode{flex:1 1 16rem;margin:0;padding:16px;border-right:1px solid var(--line-2);background:#0F1318}
[data-theme="control"] .paircode .label{font:500 var(--fs-xs)/1.4 var(--font-mono);text-transform:uppercase;letter-spacing:.08em}
[data-theme="control"] .bigcode{font-size:32px;font-weight:500;color:var(--accent)}
[data-theme="control"] .steps{flex:3 1 26rem;min-width:0;padding:16px}
[data-theme="control"] .steps p{color:var(--body-2)}
[data-theme="control"] .steps p.meta{color:var(--muted)}
[data-theme="control"] .pairvals{gap:0;border:1px solid var(--line);border-radius:6px;overflow:hidden}
[data-theme="control"] .pairvals div{padding:8px 12px}
[data-theme="control"] .pairvals div+div{border-top:1px solid var(--line-2)}
[data-theme="control"] .pairvals code.inline{background:none;padding:0}
[data-theme="control"] .add{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-lg);padding:var(--pad-card)}
[data-theme="control"] .swatch{border-radius:4px}

@media (max-width:760px){
input[type=email],input[type=password],input[type=text],input:not([type]){font-size:16px}
.auth{gap:28px}
[data-theme="household"] .intro h1{font-size:32px}
[data-theme="household"] .pirow{flex-wrap:wrap}
[data-theme="control"] .paircode{border-right:0;border-bottom:1px solid var(--line-2)}
[data-theme="control"] .thead{display:none}
[data-theme="control"] .pirow{grid-template-columns:16px minmax(0,1fr) auto;row-gap:0}
[data-theme="control"] .pirow .status{grid-column:2;grid-row:2}
[data-theme="control"] .pirow .go{grid-column:3;grid-row:1/span 2}
}
"""

# The page layout. The relay's pages carry no scripts at all. The look comes from data-theme,
# which page() fills from the visitor's validated theme choice.
PAGE = """<!doctype html><html lang="en" data-theme="{theme}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>QuietNet</title>
<style>{css}</style></head><body>
<header class="top"><div class="{wrap} topin">{logo}<span class="brand">QuietNet</span><span class="grow"></span>{header_extra}</div></header>
<main class="{wrap}">{body}</main>
<footer class="foot"><div class="{wrap}">QuietNet relay. Pages showing your home's activity are never cached.</div></footer>
</body></html>"""


def page(body, theme="calm", header_extra="", wide=False):
    """Wrap a fragment of HTML in the site's page layout.

    `theme` must be one of THEMES; anything else is treated as calm (it is checked here as well as
    where it is read, since it comes from the browser). `header_extra` is HTML for the right of the
    header (the sign-out button). `wide` gives the sign-in pages their wider, two-column layout."""
    return PAGE.format(theme=theme_name(theme), css=RELAY_CSS, wrap="wrap wide" if wide else "wrap",
                       logo=icon("logo", "ico logo-mark"), header_extra=header_extra, body=body)


# ------------------------------------------------------------------ web server

class Relay(BaseHTTPRequestHandler):
    """The relay's web server. Three kinds of caller:

      browser, signed out - /login, /signup
      browser, signed in  - /, /pis/..., /pi/<id>/rescue (the two fixed rescue calls), and
                            /pi/<id>/... which is passed through to that Pi
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

    def theme(self):
        """The look this browser asked for, from its 'qn_theme' cookie: one of THEMES, else calm."""
        return theme_name(self.cookie("qn_theme") or "")

    def set_cookie(self, token, name="qn_session", seconds=SESSION_HOURS * 3600, http_only=True):
        """Queue a cookie to go out with this answer. An empty session token signs out.
        HttpOnly keeps page scripts from reading it; SameSite=Lax keeps other sites from sending it
        with their own form posts; Secure is added whenever the request came over HTTPS.
        The theme cookie is the one exception to HttpOnly: the dashboard's own script reads it to
        pick its look, and it holds nothing secret (only 'calm', 'household' or 'control')."""
        flags = ("HttpOnly; " if http_only else "") + "SameSite=Lax; Path=/; Max-Age=%d" % seconds
        if self.secure():
            flags += "; Secure"
        self._cookies = getattr(self, "_cookies", []) + ["%s=%s; %s" % (name, token, flags)]

    def signed_in_as(self, uid):
        """Queue the cookies for a successful sign-in: the session, and the 'signed in here before' marker."""
        pw_record = sql("SELECT pw FROM users WHERE id=?", (uid,), one=True)[0]
        self.set_cookie(make_session(uid))
        self.set_cookie(known_device_token(uid, pw_record), name="qn_known", seconds=KNOWN_DEVICE_DAYS * 86400)

    def sign_out_form(self, label="Sign out", css="btn ghost"):
        """A sign-out button: a form that posts to /logout with this session's sign-out token."""
        token = sign_out_token(self.cookie("qn_session") or "")
        return ('<form class="inline" method="post" action="/logout"><input type="hidden" name="token" value="%s">'
                '<button class="%s" type="submit">%s</button></form>') % (
            html.escape(token), html.escape(css), html.escape(label))

    def sign_out_page(self):
        """GET /logout: a page with a sign-out button, rather than signing out straight away, since
        any website can send a browser to an address."""
        if not self.user():
            return self.redirect("/login")
        return self.send_html('<div class="card narrow"><h1>Sign out?</h1><p class="meta">You will need your '
                              'password to sign in again.</p><div class="mt">%s</div><p class="mt"><a href="/">Back '
                              'to your QuietNets</a></p></div>' % self.sign_out_form("Sign out", "btn primary"))

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

    def send_html(self, body, code=200, header_extra="", wide=False):
        """Send a page (the fragment is wrapped in the site layout, in this browser's chosen look),
        with any queued cookies. `header_extra` and `wide` are as for page()."""
        data = page(body, self.theme(), header_extra, wide).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_cookies()
        self.end_headers()
        self.wfile.write(data)

    def send_auth(self, body, code=200):
        """Send a sign-in or create-account page (from auth_form), in the wider layout it needs."""
        return self.send_html(body, code, wide=True)

    ERROR_TEXT = {404: ("Page not found", "There is nothing at this address.")}

    def send_error(self, code, message=None, explain=None):
        """Send an error answer as a page in the relay's own look, rather than the plain one Python
        gives. The words are escaped by Python's own send_error, as before. An error can come before
        the request's headers have been read, so the look falls back to calm then."""
        if message is None and explain is None and code in self.ERROR_TEXT:
            message, explain = self.ERROR_TEXT[code]
        theme = self.theme() if getattr(self, "headers", None) is not None else THEMES[0]
        body = ('<div class="card narrow"><h1>%(message)s</h1><p class="meta">%(explain)s (Error %(code)d.)</p>'
                '<p class="mt"><a href="/">Go to your QuietNets</a></p></div>')
        # The page's style sheet holds % signs, which the format Python fills in would misread.
        self.error_message_format = page("QN-ERROR-BODY", theme).replace("%", "%%").replace("QN-ERROR-BODY", body)
        super().send_error(code, message, explain)

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

    FORM_POSTS = ("/login", "/signup", "/logout", "/pis/new", "/theme")      # and /pis/<id>/delete, /pi/<id>/rescue
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
            return self.send_auth(self.auth_form("login", "New accounts are switched off on this relay."))
        if p in ("/login", "/signup"):
            return self.send_auth(self.auth_form(p[1:]))
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
        rescue = RESCUE_PATH.match(p)
        if p in self.FORM_POSTS or (p.startswith("/pis/") and p.endswith("/delete")) or rescue:
            if self.from_another_site():
                if p in ("/login", "/signup"):
                    return self.send_auth(self.auth_form("login", self.CROSS_SITE), 403)
                return self.send_html('<div class="card narrow"><h1>Refused</h1><div class="notice danger" '
                                      'role="alert">%s</div><p class="mt"><a href="/">Back to your QuietNets</a>'
                                      '</p></div>' % html.escape(self.CROSS_SITE), 403)
        if p == "/agent/pair":
            return self.agent_pair()
        if p == "/agent/respond":
            return self.agent_respond()
        if rescue:                  # before the general /pi/ route, which would pass it to the Pi
            return self.rescue(rescue.group(1))
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
        if p == "/theme":
            return self.choose_theme()
        if p.startswith("/pis/") and p.endswith("/delete"):
            return self.delete_pi(p.split("/")[2])
        self.send_error(404)

    # -- accounts -------------------------------------------------------

    def auth_form(self, mode, error="", note=""):
        """The sign-in or sign-up page (`mode` is 'login' or 'signup'), with an optional error or note:
        a short description of QuietNet beside the form."""
        login = mode == "login"
        title = "Sign in" if login else "Create your account"
        help_line = ("Use the email and password for your relay account." if login
                     else "Choose your email and a password of at least 8 characters.")
        switch = ('Already have an account? <a href="/login">Sign in</a>' if not login
                  else 'New here? <a href="/signup">Create an account</a>' if signup_allowed() else "")
        err = '<div class="notice danger" role="alert">%s</div>' % html.escape(error) if error else ""
        err += '<div class="notice info" role="status">%s</div>' % html.escape(note) if note else ""
        points = "".join('<li><span class="pt-ico" aria-hidden="true">%s</span><span>%s</span></li>' % (icon(i), t) for i, t in (
            ("lock", "Your household's activity stays on your Pi. The relay only passes your pages through."),
            ("monitor", "One account can reach several QuietNets, such as home and a relative's house."),
            ("moon", "Bedtimes switch things off by themselves.")))
        return """<div class="auth">
  <section class="intro">
    <h1>Reach your home QuietNet from anywhere.</h1>
    <p class="lead">QuietNet runs on a Raspberry Pi at home. It shows what each device looks up, blocks adverts and trackers, and lets you switch off chosen apps and services for each device or group, with bedtimes and a household kill switch.</p>
    <ul class="points">%s</ul>
  </section>
  <section class="card authcard" aria-labelledby="authTitle">
    <h2 id="authTitle">%s</h2>
    <p class="meta">%s</p>%s
    <form method="post" action="/%s">
      <div class="fld"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required></div>
      <div class="fld"><div class="lblrow"><label for="password">Password</label><span class="meta">At least 8 characters</span></div>
        <input id="password" name="password" type="password" autocomplete="%s" minlength="8" required></div>
      <button class="btn primary full" type="submit">%s</button>
    </form>
    %s
  </section>
</div>""" % (points, title, help_line, err, mode, "current-password" if login else "new-password", title,
             '<p class="switch-auth meta">%s</p>' % switch if switch else "")

    def do_signup(self):
        """Create an account, if sign-up is allowed, the details are acceptable and the email is new,
        then show the sign-in form. The answer is the same if the email already has an account (which
        is left untouched), so sign-up can't be used to find out whether someone has one."""
        f = self.body_form()
        email, pw = f.get("email", "").strip().lower(), f.get("password", "")
        if not signup_allowed():
            return self.send_auth(self.auth_form("login", "New accounts are switched off on this relay."), 403)
        if throttle.blocked("signup", SIGNUP_LIMIT_OVERALL):
            return self.send_auth(self.auth_form("signup", TOO_MANY), 429)
        if not EMAIL_RE.fullmatch(email) or len(email) > 254 or len(pw) < 8:
            return self.send_auth(self.auth_form("signup", "Enter a valid email and a password of at least 8 characters."))
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
        return self.send_auth(self.auth_form("login", note=SIGNUP_DONE))

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
            return self.send_auth(self.auth_form("login", TOO_MANY), 429)
        # Every attempt counts here, right or wrong: checking a password costs real processor time,
        # and anyone can make an account and sign in to it correctly over and over.
        if trusted:
            throttle.fail("login-known-tries:" + email)
        else:
            throttle.fail("login-tries:" + email)
            throttle.fail("login-from:" + address)
        if not password_checks.acquire(timeout=PASSWORD_CHECK_WAIT):
            return self.send_auth(self.auth_form("login", "The relay is busy. Please try again in a moment."), 503)
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
            return self.send_auth(self.auth_form("login", "Wrong email or password."))
        throttle.clear("login:" + email)
        throttle.clear("login-known:" + email)
        self.signed_in_as(row[0])
        self.redirect("/")

    # -- device list / pairing -----------------------------------------

    def theme_form(self):
        """The Appearance card on the home page: the three looks as radio buttons, the current one
        ticked, in a form that posts to /theme (the relay's pages have no scripts, so it has a button)."""
        current = self.theme()
        options = "".join(
            '<label class="theme-opt"><input type="radio" name="theme" value="%s"%s>'
            '<span class="swatch swatch-%s" aria-hidden="true"><i></i><i></i><i></i></span>'
            '<span class="theme-text"><b>%s</b><span class="meta">%s</span></span></label>' % (
                html.escape(tid), " checked" if tid == current else "", html.escape(tid),
                html.escape(name), html.escape(words))
            for tid, name, words in THEME_CHOICES)
        return ('<section class="card appearance" id="appearance" aria-labelledby="appearanceTitle">'
                '<h2 id="appearanceTitle">Appearance</h2>'
                '<p class="meta">How these pages, and your QuietNets\' pages opened from here, look in this browser.</p>'
                '<form method="post" action="/theme"><fieldset class="themes"><legend class="sr-only">Choose a look'
                '</legend>%s</fieldset><button class="btn" type="submit">Use this look</button></form></section>'
                % options)

    def licence_card(self, uid, info, now):
        """The Licence card on the home page: one sentence for the licence's state, a warning in its
        last 7 days (see ending_soon), and how many of its seats are in use, with any Pis waiting to
        be paired (with a code still in date) named after it."""
        lid = ('<p class="meta">Licence %s</p>' % html.escape(info["id"])) if info["id"] else ""
        soon = ending_soon(info, now)
        warn = ('<div class="notice warn" role="status">%s</div>' % html.escape(soon)) if soon else ""
        used = seats_used(uid)
        waiting = seats_promised(uid, now) - used
        more = (" (%d waiting to be paired)" % waiting) if waiting > 0 else ""
        return ('<section class="card licence" aria-labelledby="licenceTitle"><h2 id="licenceTitle">Licence</h2>'
                '<p class="mt">%s</p>%s<p class="meta mt">Pis: %s of %s%s</p>%s</section>') % (
            html.escape(licence_sentence(info)), warn, html.escape(str(used)),
            html.escape(str(info["seats"])), html.escape(more), lid)

    def add_pi_section(self, uid, info, now):
        """The 'Add a QuietNet' part of the home page: the form, or, when the licence gate is on and
        a new Pi isn't allowed, a plain sentence saying why in its place. With the gate off the form
        is always shown (adding is then let through, and noted, by new_pi). The same checks as
        new_pi, with the same wording, but nothing is logged: this only decides what to show."""
        refusal = ""
        if gate_on():
            promised = seats_promised(uid, now)
            if not info["pair"]:
                refusal = ADD_NEEDS_LICENCE
            elif promised >= info["seats"]:
                refusal = no_free_seat(info["seats"], seats_used(uid), promised, "Remove one to add another.")
        if refusal:
            return ('<section class="add" aria-labelledby="addTitle"><h2 id="addTitle">Add a QuietNet</h2>'
                    '<p class="mt">%s</p></section>' % html.escape(refusal))
        return """<section class="add" aria-labelledby="addTitle"><h2 id="addTitle">Add a QuietNet</h2>
  <p class="meta">Give it a name and you will get a pairing code for it.</p>
  <form method="post" action="/pis/new" class="addform"><div class="fld grow"><label for="piname">Name</label><input id="piname" name="name" placeholder="e.g. Home Pi" required maxlength="40"></div>
  <button class="btn primary" type="submit">Create pairing code</button></form></section>"""

    def home(self):
        """The signed-in home page: your QuietNets, with a pairing code for each one not yet
        paired, and the Licence card. A code that has expired is replaced here, so the page never
        shows a dead one. With the licence gate on and remote access not allowed, a paired Pi says
        'Remote access paused' instead of Online or Offline, and opens the paused page.

        With the gate on and pairing not allowed (no current licence, or paired Pis already fill the
        seats), a Pi waiting to be paired shows why in place of its code and install line, and its
        code is not renewed: a code that pairing would refuse must not look as if it works."""
        uid = self.user()
        if not uid:
            return self.redirect("/login")
        pis = sql("SELECT id,name,paired,last_seen FROM pis WHERE user_id=? ORDER BY created", (uid,))
        paired_rows, waiting = "", ""
        now = time.time()
        info = account_licence(uid, now)
        paused = gate_on() and not info["remote"]
        no_pairing = ""
        if gate_on():
            if not info["pair"]:
                no_pairing = ADD_NEEDS_LICENCE
            elif seats_used(uid) >= info["seats"]:
                no_pairing = seats_full(info["seats"], "Remove one to pair this one.")
        address, guessed = relay_address(self.headers.get("Host"))
        for pid, name, paired, seen in pis:
            if not paired:
                head = """<section class="card pending" aria-labelledby="pi-%(pid)s">
  <div class="pending-head"><span class="avatar" aria-hidden="true">%(chip)s</span>
    <div class="grow"><h2 id="pi-%(pid)s">%(name)s</h2><div class="status wait"><span class="dot wait" aria-hidden="true"></span>Waiting to be paired</div></div>
    <form class="inline" method="post" action="/pis/%(pid)s/delete"><button class="btn danger-outline" type="submit">Remove</button></form></div>
""" % {"pid": html.escape(pid), "chip": icon("chip"), "name": html.escape(name)}
                if no_pairing:
                    waiting += head + '  <p class="mt">%s</p>\n</section>' % html.escape(no_pairing)
                    continue
                code, code_ts = sql("SELECT code, code_ts FROM pis WHERE id=?", (pid,), one=True)
                if now - (code_ts or 0) > PAIR_CODE_MINUTES * 60:
                    # The old code has expired. Looking at this page is what issues a new one,
                    # so the code on screen is always one that works.
                    code = new_pair_code()
                    sql("UPDATE pis SET code=?, code_ts=? WHERE id=? AND paired=0", (code, now, pid), commit=True)
                waiting += head + """  <div class="pending-body">
    <div class="paircode"><span class="label">Pairing code</span><span class="bigcode">%(code)s</span>
      <span class="meta">Works once, for %(minutes)d minutes. Reload this page for a new code.</span></div>
    <div class="steps">
      <h3>New Pi? Run this one line on it</h3>
      <p class="meta">It needs Raspberry Pi OS or another Debian-style Linux, and installs Docker if it is missing (it asks first).</p>
      <pre class="cmd">%(command)s</pre>%(guessed)s
      <h3>Pi already running QuietNet?</h3>
      <p>On the Pi's own QuietNet page, open <b>Remote access</b>, enter this relay's web address and this code:</p>
      <dl class="pairvals"><div><dt>Relay web address</dt><dd><code class="inline">%(address)s</code></dd></div><div><dt>Pairing code</dt><dd><code class="inline">%(code)s</code></dd></div></dl>
    </div>
  </div>
</section>""" % {
                    "code": html.escape(code), "minutes": PAIR_CODE_MINUTES,
                    "command": html.escape(install_command(address, code)), "address": html.escape(address),
                    "guessed": ('<p class="meta">Replace %s with this relay\'s web address.</p>'
                                % html.escape(address)) if guessed else ""}
            else:
                online = bool(seen) and (now - seen) < OFFLINE_AFTER
                look, words = ("wait", "Remote access paused") if paused else (
                    ("on", "Online") if online else ("off", "Offline"))
                paired_rows += ('<a class="pirow" href="/pi/%s/"><span class="avatar" aria-hidden="true">%s</span>'
                                '<span class="pi-main"><b class="name">%s</b><span class="status %s"><span class="dot %s" '
                                'aria-hidden="true"></span>%s</span></span><span class="go">Open%s</span></a>') % (
                    html.escape(pid), icon("chip"), html.escape(name), look, look, html.escape(words), icon("right"))
        listed = ""
        if paired_rows:
            listed += ('<section class="card flush pis" aria-labelledby="pairedTitle"><h2 id="pairedTitle" '
                       'class="eyebrow">Paired</h2><div class="thead" aria-hidden="true"><span>Name</span>'
                       '<span>Status</span><span></span></div>%s</section>' % paired_rows)
        listed += waiting
        body = """<div class="pagehead"><h1>Your QuietNets</h1><p class="meta">Open one to see its devices, groups and schedules.</p></div>
%s
%s
%s
%s""" % (listed or '<div class="card empty">%s</div>' % GETTING_STARTED, self.licence_card(uid, info, now),
         self.add_pi_section(uid, info, now), self.theme_form())
        return self.send_html(body, header_extra=self.sign_out_form("Sign out", "btn ghost"))

    def new_pi(self):
        """Create a QuietNet entry for the signed-in user, with a fresh pairing code. Each account
        may have at most MAX_PIS_PER_ACCOUNT, so no one account can fill the relay's disk. The licence
        must allow pairing, and paired Pis plus Pis waiting with a code still in date must be fewer
        than its seats (both through licence_gate, so with the gate off they are only noted)."""
        uid = self.user()
        if not uid:
            return self.redirect("/login")
        if sql("SELECT COUNT(*) FROM pis WHERE user_id=?", (uid,), one=True)[0] >= MAX_PIS_PER_ACCOUNT:
            return self.send_html('<div class="card narrow"><h1>No room for another QuietNet</h1><p>This account '
                                  'already has %d QuietNets, the most it can hold. Remove one before adding another.'
                                  '</p><p class="mt"><a href="/">Back to your QuietNets</a></p></div>'
                                  % int(MAX_PIS_PER_ACCOUNT), 403)
        now = time.time()
        info = account_licence(uid, now)
        refusal = ""
        if not licence_gate(uid, "add", info["pair"], info, now):
            refusal = ADD_NEEDS_LICENCE
        elif info["pair"]:
            promised = seats_promised(uid, now)
            if not licence_gate(uid, "add-seats", promised < info["seats"], info, now):
                refusal = no_free_seat(info["seats"], seats_used(uid), promised, "Remove one to add another.")
        if refusal:
            return self.send_html('<div class="card narrow"><h1>Can\'t add a QuietNet</h1><p>%s</p>'
                                  '<p class="mt"><a href="/">Back to your QuietNets</a></p></div>'
                                  % html.escape(refusal), 403)
        name = (self.body_form().get("name", "").strip() or "My QuietNet")[:40]
        pid = secrets.token_hex(8)
        sql("INSERT INTO pis(id,user_id,name,token,code,paired,created,last_seen,code_ts) VALUES(?,?,?,?,?,0,?,0,?)",
            (pid, uid, name, "", new_pair_code(), now, now), commit=True)
        self.redirect("/")

    def choose_theme(self):
        """POST /theme: remember which look this browser wants (a cookie only; nothing is stored
        here), then go back to the home page. Only for a signed-in person; an unknown value saves
        calm. The page to go back to is always the home page, never one named in the form."""
        if not self.user():
            return self.redirect("/login")
        self.set_cookie(theme_name(self.body_form().get("theme", "")), name="qn_theme",
                        seconds=THEME_COOKIE_DAYS * 86400, http_only=False)
        return self.redirect("/")

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
        per account too, so an account can't pair, remove and pair again without end.

        After the code, in order:
          - the same identity: the body may carry "install", the Pi's random install id (exactly 32
            lower-case hex characters; anything else is ignored, so older Pis still pair). If another
            paired Pi of this account has the same install id, it is this Pi paired again, and its old
            entry is replaced, but only if that entry is offline. If it is online, the SD card was
            most likely copied, and pairing is refused (403) so the copy can't take over.
          - the licence must allow pairing, and paired Pis (not counting one being replaced) must be
            fewer than its seats. Both go through licence_gate, so with the gate off they are only
            noted. A refusal is a 403 with 'error' and the licence state, never 401."""
        body = self.body_json()
        code = str(body.get("code", "")).strip().upper()
        install = body.get("install")
        install = install if isinstance(install, str) and INSTALL_ID_RE.match(install) else ""
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
        uid, now = row[1], time.time()
        if throttle.blocked("paired:%d" % uid, PAIR_LIMIT_PER_ACCOUNT):
            return self.send_json({"error": "This account has paired too many QuietNets today. "
                                            "Please try again tomorrow."}, 429)
        replaced = []
        if install:
            for old_id, seen in sql("SELECT id, last_seen FROM pis WHERE user_id=? AND paired=1 AND install_id=? "
                                    "AND id!=?", (uid, install, row[0])):
                if seen and now - seen < OFFLINE_AFTER:
                    return self.send_json({"error": SAME_IDENTITY}, 403)
                replaced.append(old_id)
        info = account_licence(uid, now)
        if not licence_gate(uid, "pair", info["pair"], info, now):
            return self.send_json({"error": PAIR_NEEDS_LICENCE, "licence": info["state"]}, 403)
        token = secrets.token_hex(24)
        # The seat count and the write happen together, holding db_lock (which every use of the
        # database takes), so several codes paired at the same moment can't each see a free seat,
        # and one code sent twice at once pairs only once.
        outcome = "paired"
        with db_lock:
            still = []
            for old_id in replaced:     # look again: the old entry may have come back online, or gone
                old = db.execute("SELECT last_seen FROM pis WHERE id=? AND user_id=? AND paired=1",
                                 (old_id, uid)).fetchone()
                if old and old[0] and now - old[0] < OFFLINE_AFTER:
                    outcome = "same identity"
                elif old:
                    still.append(old_id)
            replaced = still
            if outcome == "paired" and info["pair"] and not licence_gate(
                    uid, "pair-seats", seats_used(uid, replaced) < info["seats"], info, now):
                outcome = "seats"
            if outcome == "paired":
                done = db.execute("UPDATE pis SET paired=1, token=?, code='', last_seen=?, install_id=? "
                                  "WHERE id=? AND paired=0 AND code_ts>?",
                                  (token_record(token), now, install, row[0], now - PAIR_CODE_MINUTES * 60))
                if done.rowcount != 1:
                    db.rollback()
                    outcome = "used"
                else:
                    for old_id in replaced:
                        db.execute("DELETE FROM pis WHERE id=? AND user_id=?", (old_id, uid))
                    db.commit()
        if outcome == "same identity":
            return self.send_json({"error": SAME_IDENTITY}, 403)
        if outcome == "seats":
            return self.send_json({"error": seats_full(info["seats"], "Remove one at q3n.net, then pair again."),
                                   "licence": info["state"]}, 403)
        if outcome == "used":
            return self.send_json({"error": "That pairing code is wrong, already used, or has expired."}, 400)
        throttle.fail("paired:%d" % uid)
        for old_id in replaced:
            bridge.forget(old_id)
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
        """A Pi asks for work. Notes that it is alive, and which kind of agent it is, then waits (up
        to POLL_TIMEOUT seconds) for a browser request to pass down. An answer without an 'id' means
        'nothing yet, ask again'. At most MAX_POLLS wait at once, so waiting Pis can never take every
        thread from browsers; beyond that the Pi is told the relay is busy, and tries again.

        Every answer, idle or a real call, also carries 'licence' (see licence_for_pi), and 'latest'
        when QUIETNET_LATEST holds a version. Polling is exactly the same whatever the licence: the
        same poll slots, the same wait, and always 200 for a licence reason. That is safe for the
        Pis already in homes: their agent hands on only an answer whose 'id' is set, uses only the
        call's id, method, path and body, and ignores every other key; an idle answer with extra keys
        has no 'id', so it is still 'nothing to do'.

        The agent kind comes from the X-QuietNet-Agent header: '2' means a 0.6 or later agent, which
        has /api/rescue; anything else, or none, means 1. It is written only when it changes."""
        row = self.agent()
        if not row:
            return self.send_error(401)
        kind = 2 if self.headers.get("X-QuietNet-Agent", "").strip() == "2" else 1
        sql("UPDATE pis SET last_seen=? WHERE id=?", (time.time(), row[0]), commit=True)
        sql("UPDATE pis SET agent=? WHERE id=? AND agent IS NOT ?", (kind, row[0], kind), commit=True)
        if not poll_slots.acquire(blocking=False):
            return self.send_json({"error": "The relay is busy. Try again shortly."}, 503)
        try:
            call = bridge.poll(row[0])
        finally:
            poll_slots.release()
        answer = dict(call or {})       # a real call always carries an id; without one, "nothing to do"
        answer.update(self.poll_extras(row[1]))
        self.send_json(answer)

    def poll_extras(self, uid):
        """What a poll answer carries besides any call: the account's licence, and the newest version
        if QUIETNET_LATEST holds one. Worked out when the answer is sent (after the wait), so a
        renewal shows on the next answer. A fault here leaves them out rather than lose a call."""
        try:
            now = time.time()
            extras = {"licence": licence_for_pi(account_licence(uid, now), seats_used(uid), now)}
        except (sqlite3.Error, ValueError, TypeError) as e:
            say("Licence: couldn't work out the licence for a poll answer (%s)." % e)
            extras = {}
        if LATEST:
            extras["latest"] = LATEST
        return extras

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
        bridge and the Pi's answer is returned. Checks, in order: the Pi is yours; the licence allows
        remote access; the path is an API path; the request carries the dashboard's own header; the
        Pi is online.

        The licence check comes after my_pi(), so someone else's Pi is still 'not found' whatever its
        licence. When remote access is not allowed (and the gate is on), the page becomes the paused
        page and an API call gets a 402 with an 'error' sentence. Nothing here answers 401."""
        parts = path.split("/", 3)          # ['', 'pi', '<id>', 'rest...']
        if len(parts) < 3:
            return self.send_error(404)
        pid = parts[2]
        rest = "/" + (parts[3] if len(parts) > 3 else "")
        pi = self.my_pi(pid)
        if not pi:
            return self.redirect("/login") if method == "GET" and rest == "/" else self.send_error(404)
        info = account_licence(pi[1])
        if not licence_gate(pi[1], "remote", info["remote"], info):
            if rest == "/" and method == "GET":
                return self.paused_page(pi, info)
            if rest.startswith("/api/"):
                return self.send_json({"error": paused_api_sentence(info)}, 402)
            return self.send_error(404)

        if rest == "/" and method == "GET":        # serve the dashboard, pointed at this Pi
            return self.serve_dashboard(pid, pi[2], bool(pi[4]) and bool(pi[5])
                                        and time.time() - pi[5] < OFFLINE_AFTER)
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

    def back_links(self, pid=None, name=""):
        """Links at the foot of the paused and rescue pages: back to the Pi (when given) and home."""
        pi_link = ('<a href="/pi/%s/">Back to %s</a><br>' % (html.escape(pid), html.escape(name))) if pid else ""
        return '<p class="mt">%s<a href="/">Back to your QuietNets</a></p>' % pi_link

    def paused_page(self, pi, info):
        """The page shown at /pi/<id>/ in place of the dashboard while remote access is paused: why,
        that the Pi is still filtering at home, and the two rescue buttons, each a form posting to
        /pi/<id>/rescue. They stay in every licence state, so a lapse never leaves someone's internet
        switched off with no way to put it right."""
        pid = pi[0]
        kind = sql("SELECT agent FROM pis WHERE id=?", (pid,), one=True)
        old_pi = not (kind and kind[0] == 2)

        def button(what, label, css):
            """One rescue button: a form posting `what` to this Pi's rescue address."""
            return ('<form class="inline" method="post" action="/pi/%s/rescue"><input type="hidden" name="what" '
                    'value="%s"><button class="btn %s" type="submit">%s</button></form>') % (
                html.escape(pid), html.escape(what), html.escape(css), html.escape(label))

        note = (" This Pi runs a QuietNet older than 0.6, so the first button can only turn off the household "
                "kill switch.") if old_pi else ""
        body = ('<div class="card rescue"><p class="meta">%s</p><h1>Remote access is paused</h1><p class="mt">%s</p>'
                '<h2>If someone\'s internet is switched off, you can still put it right from here:</h2>'
                '<div class="btnrow">%s%s</div>'
                '<p class="meta">Pausing blocking stops the advert list and your own blocked addresses for an hour. '
                'Blocked services and schedules stay on, as they do on the dashboard.%s</p>'
                '<p class="mt">The full dashboard opens only on the Pi itself. From a computer at home you can still '
                'reach it with an SSH tunnel (the line the installer printed). To stop using QuietNet altogether, set '
                'your router\'s DNS back to its old setting, then unplug the Pi; devices go back to normal within a '
                'few minutes.</p>%s</div>') % (
            html.escape(pi[2]), html.escape(paused_lead(info)),
            button("internet-on", "Turn the internet back on for every device", "primary"),
            button("pause-hour", "Pause blocking for an hour", ""), html.escape(note), self.back_links())
        return self.send_html(body, header_extra=self.sign_out_form("Sign out", "btn ghost"))

    def rescue(self, pid):
        """POST /pi/<id>/rescue: send one of the two fixed rescue calls to a Pi, whatever its licence
        and whether or not the gate is on. A signed-in form post (refused from other websites in
        do_POST), starting with user() then my_pi(), so another account's Pi is 'not found'.

        The form's 'what' must be 'internet-on' or 'pause-hour'; anything else is refused with 400.
        The call itself comes only from RESCUE_CALLS, picked by 'what' and the Pi's agent kind:
        nothing from the browser goes into its path or body. Each rescue is written to the licence
        log, and the page says what happened, including when the Pi isn't connected. An account may
        press at most RESCUE_LIMIT_PER_ACCOUNT times an hour; beyond that the answer is 429, with
        nothing sent and nothing logged."""
        uid = self.user()
        if not uid:
            return self.redirect("/login")
        pi = self.my_pi(pid)
        if not pi:
            return self.send_error(404)
        what = self.body_form().get("what", "")
        kind = sql("SELECT agent FROM pis WHERE id=?", (pid,), one=True)
        agent = 2 if kind and kind[0] == 2 else 1
        call = rescue_call(what, agent)
        if not call:
            return self.send_html('<div class="card narrow"><h1>Not sent</h1><p>That isn\'t one of the rescue '
                                  'buttons, so nothing was sent to your Pi.</p>%s</div>'
                                  % self.back_links(pid, pi[2]), 400)
        name = "rescue:%d" % uid
        if throttle.blocked(name, RESCUE_LIMIT_PER_ACCOUNT):
            # Over the limit: nothing is sent and nothing is logged, so pressing in a loop can't
            # grow the licence log.
            return self.send_html('<div class="card narrow"><h1>Not sent</h1><p>%s</p>%s</div>' % (
                html.escape("That's a lot of rescue presses in the last hour, so this one wasn't sent. Please wait "
                            "a few minutes and try again."), self.back_links(pid, pi[2])), 429,
                header_extra=self.sign_out_form("Sign out", "btn ghost"))
        throttle.fail(name)
        now = time.time()
        online = bool(pi[4]) and bool(pi[5]) and now - pi[5] < OFFLINE_AFTER
        if not online:
            code, title, words, outcome = 503, "Not sent", RESCUE_OFFLINE, "not sent, the Pi isn't connected"
        else:
            resp = bridge.call(pid, call)
            if resp is None:
                code, title, outcome = 504, "No answer", "sent, no answer in time"
                words = "Your Pi didn't answer in time, so this may not have worked. Try again in a minute."
            else:
                big_answers.give_back(resp.get("ticket"))
                status = resp.get("status", 502)
                if 200 <= status < 300:
                    code, title, words, outcome = 200, "Done", RESCUE_DONE[(what, agent)], "done"
                else:
                    code, title, outcome = 502, "Not done", "the Pi answered %d" % status
                    words = "Your Pi couldn't do that just now. Try again in a minute."
        info = account_licence(uid, now)
        log_licence(uid, info["id"], "Rescue %s (%s %s) for Pi %s: %s." % (
            what, call["method"], call["path"], pid, outcome), now)
        return self.send_html('<div class="card narrow"><h1>%s</h1><p>%s</p>%s</div>' % (
            html.escape(title), html.escape(words), self.back_links(pid, pi[2])), code,
            header_extra=self.sign_out_form("Sign out", "btn ghost"))

    def serve_dashboard(self, pid, name, online=False):
        """Send the dashboard page, with two additions: a script telling it to send its API
        calls to '/pi/<id>/...', and a bar across the top with the Pi's name, whether it is online,
        and a way back. The bar's colours come from the dashboard's own look (its --bar- colours),
        with calm's as the fallback."""
        if not DASHBOARD:
            return self.send_error(500)
        with open(DASHBOARD, encoding="utf-8") as f:
            html_text = f.read()
        inject = ('<script>window.QN_API_BASE=%s;</script>' % json.dumps("/pi/" + pid)
                  + '<style>#qnbar{position:sticky;top:0;z-index:50;background:var(--bar-bg,#23221f);color:var(--bar-ink,#f4f3ef);'
                    'border-bottom:1px solid var(--bar-line,#4a4842);padding:0 16px;font:500 13px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;'
                    'display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center;min-height:44px}'
                    '#qnbar a{color:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:4px;min-height:44px}'
                    '#qnbar a:hover{text-decoration:underline}#qnbar svg{width:16px;height:16px;flex:none}'
                    '#qnbar .qnsep{width:1px;height:16px;background:var(--bar-line,#4a4842)}'
                    '#qnbar .qnhere{display:inline-flex;align-items:center;gap:8px;min-width:0;overflow-wrap:anywhere}'
                    '#qnbar .qnst{color:var(--bar-muted,#c9c5bc);display:inline-flex;align-items:center;gap:5px}'
                    '#qnbar .qndot{width:7px;height:7px;border-radius:50%;background:var(--bar-dot,#5fc4b6)}'
                    '#qnbar .qndot.off{background:var(--bar-muted,#c9c5bc)}'
                    '#qnbar .qngrow{flex:1}#qnbar form{margin:0}#qnbar button{min-height:44px;background:none;border:0;padding:0 8px;color:inherit;'
                    'font:inherit;text-decoration:underline;text-underline-offset:2px;cursor:pointer}'
                    '#qnbar :focus-visible{outline:2px solid currentColor;outline-offset:2px}</style>')
        bar = ('<div id="qnbar"><a href="/">%s Your QuietNets</a><span class="qnsep" aria-hidden="true"></span>'
               '<span class="qnhere"><b>%s</b><span class="qnst"><span class="qndot%s" aria-hidden="true"></span>%s</span></span>'
               '<span class="qngrow"></span>%s</div>') % (
            icon("left"), html.escape(name), "" if online else " off", "Online" if online else "Offline",
            self.sign_out_form(css="qnsignout"))
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


# ------------------------------------------------------------------ owner's command line
#
#   python relay.py licence show <email>
#   python relay.py licence grant <email> --plan owner|gift|legacy [--days N] [--seats N]
#   python relay.py licence revoke <email> --reason "..."
#   python relay.py licence restore <email>
#   python relay.py licence seats <email> N
#
# On Railway it is run inside the relay's own container, reached with `railway ssh` (`railway run`
# would run it on your own computer, against nothing). There is no web page for this on purpose: it
# would be the most valuable thing on the relay to break into.

class CommandProblem(Exception):
    """A plain-English reason the owner's command can't be carried out."""


class LicenceParser(argparse.ArgumentParser):
    """The standard argument reader, except that a mistake raises CommandProblem with a plain message
    (so licence_command can print it and return), instead of ending the program itself."""

    def error(self, message):
        """Turn argparse's complaint into a CommandProblem."""
        raise CommandProblem("That command isn't right: %s. Run python relay.py licence --help to see how "
                             "to use it." % message)


def whole_number(low, high):
    """An argument type that accepts a whole number from `low` to `high`, and says so plainly otherwise."""
    def check(text):
        """Read `text` as a whole number in range."""
        try:
            value = int(text)
        except ValueError:
            value = None
        if value is None or not low <= value <= high:
            raise argparse.ArgumentTypeError("%r should be a whole number from %d to %d" % (text, low, high))
        return value
    return check


def some_text(text):
    """An argument type that accepts any text except a blank one (so a blank --reason is a wrong
    command, exit status 2, like a missing one)."""
    if not text.strip():
        raise argparse.ArgumentTypeError("the reason can't be blank, so the log says why")
    return text


def licence_parser():
    """The arguments the licence command line takes (see the box above)."""
    parser = LicenceParser(prog="python relay.py licence", description="Look at or change one account's licence.")
    actions = parser.add_subparsers(dest="action", metavar="show|grant|revoke|restore|seats")
    actions.required = True
    show = actions.add_parser("show", help="show an account's licence and its recent log")
    show.add_argument("email")
    grant = actions.add_parser("grant", help="give an account an active licence")
    grant.add_argument("email")
    grant.add_argument("--plan", required=True, choices=GRANT_PLANS)
    grant.add_argument("--days", type=whole_number(0, 36500), default=0,
                       help="how many days it lasts; leave out, or 0, for no end")
    grant.add_argument("--seats", type=whole_number(1, MAX_PIS_PER_ACCOUNT),
                       help="how many Pis it covers (default: as it was, or %d)" % DEFAULT_SEATS)
    revoke = actions.add_parser("revoke", help="switch an account's licence off")
    revoke.add_argument("email")
    revoke.add_argument("--reason", required=True, type=some_text)
    restore = actions.add_parser("restore", help="switch a revoked licence back on")
    restore.add_argument("email")
    seats = actions.add_parser("seats", help="change how many Pis a licence covers")
    seats.add_argument("email")
    seats.add_argument("number", type=whole_number(1, MAX_PIS_PER_ACCOUNT))
    return parser


def account_by_email(email):
    """(user id, email) for the account whose current email is `email`, or CommandProblem."""
    email = email.strip().lower()
    row = sql("SELECT id, email FROM users WHERE email=?", (email,), one=True)
    if not row:
        raise CommandProblem("No account on this relay has the email %s. Nothing was changed." % email)
    return row


def licence_needed(uid, email):
    """The stored licence for account `uid`, or CommandProblem if it has none."""
    row = licence_row(uid)
    if not row:
        raise CommandProblem("%s has no licence yet, so nothing was changed. Give it one with: python relay.py "
                             "licence grant %s --plan owner" % (email, email))
    return row


def end_words(period_end):
    """'no end date' or 'until 4 January 2027', for the command line's messages."""
    return "until " + long_date(period_end) if period_end else "no end date"


def cmd_show(args, out):
    """licence show: the account's licence as it stands, and its last ten log lines."""
    uid, email = account_by_email(args.email)
    row = licence_row(uid)
    info = licence_state(row, time.time())
    lines = ["Account: %s (number %d)" % (email, uid)]
    if not row:
        lines.append("Licence: none. Remote access and adding Pis need one: python relay.py licence grant "
                     "%s --plan owner" % email)
    else:
        lines += ["Licence: %s" % info["id"],
                  "State now: %s (stored as %s)" % (info["state"], row["state"]),
                  "Plan: %s" % (row["plan"] or "none"),
                  "Ends: %s" % end_words(info["until"])]
        if info["grace_until"]:
            lines.append("Payment grace until: %s" % long_date(info["grace_until"]))
        if row["reason"]:
            lines.append("Reason: %s" % row["reason"])
    lines.append("Pis: %d of %d" % (seats_used(uid), info["seats"]))
    lines.append("Allows: remote access %s, updates %s, adding Pis %s" % tuple(
        "yes" if info[k] else "no" for k in ("remote", "updates", "pair")))
    lines.append(gate_status())
    log = sql("SELECT at, what FROM licence_log WHERE user_id=? ORDER BY at DESC LIMIT 10", (uid,))
    lines.append("Recent log:" if log else "Recent log: nothing yet.")
    for at, what in reversed(log):
        lines.append("  %s UTC  %s" % (time.strftime("%Y-%m-%d %H:%M", time.gmtime(at)), what))
    print("\n".join(lines), file=out)
    return 0


def cmd_grant(args, out):
    """licence grant: make the account's licence active on the chosen plan, for --days (none or 0
    means no end), with --seats (or the seats it had, or DEFAULT_SEATS). Any reason, payment grace
    and cancellation are cleared."""
    uid, email = account_by_email(args.email)
    now = time.time()
    row = licence_row(uid)
    end = now + args.days * 86400 if args.days else 0
    seats = args.seats if args.seats is not None else (row["seats"] if row else DEFAULT_SEATS)
    with db_lock:
        lid = row["id"] if row else new_licence_id()
        if row:
            db.execute("UPDATE licences SET state='active', plan=?, seats=?, period_end=?, grace_until=0, "
                       "cancel_at_period_end=0, reason='', updated=? WHERE user_id=?", (args.plan, seats, end, now, uid))
        else:
            db.execute("INSERT INTO licences(id,user_id,state,plan,seats,period_end,created,updated) "
                       "VALUES(?,?,'active',?,?,?,?,?)", (lid, uid, args.plan, seats, end, now, now))
        what = "Owner granted the licence: plan %s, active, %s, %d seats." % (args.plan, end_words(end), seats)
        db.execute("INSERT INTO licence_log(licence_id,user_id,at,what) VALUES(?,?,?,?)", (lid, uid, now, what))
        db.commit()
    print("%s: licence %s is now active on plan %s, %s, covering %d Pis." % (email, lid, args.plan, end_words(end), seats),
          file=out)
    return 0


def change_licence(uid, lid, sets, args_tuple, what):
    """Apply one UPDATE to an account's licence and write its log line, together."""
    now = time.time()
    with db_lock:
        db.execute("UPDATE licences SET %s, updated=? WHERE user_id=?" % sets, args_tuple + (now, uid))
        db.execute("INSERT INTO licence_log(licence_id,user_id,at,what) VALUES(?,?,?,?)", (lid, uid, now, what))
        db.commit()


def cmd_revoke(args, out):
    """licence revoke: switch the licence off (state revoked) with a reason, keeping its plan and dates.
    The account's Pis stay paired and keep filtering; the rescue buttons still work."""
    uid, email = account_by_email(args.email)
    reason = args.reason.strip()[:200]      # never blank: some_text refused that already
    row = licence_needed(uid, email)
    change_licence(uid, row["id"], "state='revoked', reason=?", (reason,), "Owner revoked the licence: %s" % reason)
    print("%s: licence %s is revoked. Remote access is paused while the licence gate is on; the Pis keep filtering "
          "at home." % (email, row["id"]), file=out)
    return 0


def cmd_restore(args, out):
    """licence restore: set the licence back to active, keeping its end date, and clear the reason."""
    uid, email = account_by_email(args.email)
    row = licence_needed(uid, email)
    change_licence(uid, row["id"], "state='active', reason=''", (), "Owner restored the licence.")
    info = account_licence(uid)
    print("%s: licence %s is restored, %s. State now: %s." % (email, row["id"], end_words(info["until"]), info["state"]),
          file=out)
    return 0


def cmd_seats(args, out):
    """licence seats: change how many Pis the licence covers. Pis already paired stay paired."""
    uid, email = account_by_email(args.email)
    row = licence_needed(uid, email)
    change_licence(uid, row["id"], "seats=?", (args.number,), "Owner set the seats to %d." % args.number)
    print("%s: licence %s now covers %d Pis (%d paired)." % (email, row["id"], args.number, seats_used(uid)), file=out)
    return 0


LICENCE_COMMANDS = {"show": cmd_show, "grant": cmd_grant, "revoke": cmd_revoke, "restore": cmd_restore,
                    "seats": cmd_seats}


def licence_command(argv, system=os, out=None, err=None):
    """Run `python relay.py licence ...` with the words after 'licence' in `argv`. Returns the exit
    status: 0 when done, 1 when the account or licence isn't there, 2 when the command is wrong.

    The command is checked first, then root is given up exactly as the server does (drop_privileges)
    before relay.db is opened: run as root, SQLite could leave files the running relay can't write,
    and every sign-in and poll would then fail. `system` is the os module; tests pass a stand-in."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        args = licence_parser().parse_args(argv)
    except CommandProblem as e:
        print(e, file=err)
        return 2
    except SystemExit as e:             # --help, which argparse answers itself
        return e.code if isinstance(e.code, int) else 0
    os.makedirs(DATA, exist_ok=True)
    note = drop_privileges(DATA, system=system)
    if note and "Warning" in note:
        print(note, file=err)
    init_db()
    try:
        return LICENCE_COMMANDS[args.action](args, out)
    except CommandProblem as e:
        print(e, file=err)
        return 1


def main(argv=None):
    """Run the relay: open the listening port, stop being root, open the database and serve until
    stopped. With 'licence' as the first word, run the owner's licence command line instead.

    The port is opened first, while still root, so a low port number (below 1024) still works."""
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "licence":
        raise SystemExit(licence_command(argv[1:]))
    if argv:
        raise SystemExit("relay.py doesn't know %r. Run it with no words to serve, or with 'licence' to look "
                         "at or change a licence (python relay.py licence --help)." % argv[0])
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
    print(gate_status())
    warning = latest_warning()
    if warning:
        print(warning)
    print("QuietNet relay listening on port %d" % PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
