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

What it keeps: your account (email + a scrypt-hashed password) and a list of your
Pis. It never stores your browsing history or rules - those stay on the Pi.
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA = os.environ.get("QUIETNET_RELAY_DATA") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
PORT = int(os.environ.get("PORT", "8080"))
SESSION_HOURS = 24 * 14
CALL_TIMEOUT = 30          # how long a browser request waits for the Pi to answer
POLL_TIMEOUT = 25          # how long the Pi's long-poll waits before returning empty
OFFLINE_AFTER = 40         # a Pi not seen for this many seconds is treated as offline
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def find_dashboard():
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
    with db_lock:
        cur = db.execute(statement, args)
        rows = cur.fetchall()
        if commit:
            db.commit()
        return (rows[0] if rows else None) if one else rows


def init_db():
    global db, SECRET
    os.makedirs(DATA, exist_ok=True)
    db = sqlite3.connect(os.path.join(DATA, "relay.db"), check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL);
        CREATE TABLE IF NOT EXISTS pis(id TEXT PRIMARY KEY, user_id INTEGER, name TEXT, token TEXT,
            code TEXT, paired INTEGER, created REAL, last_seen REAL);
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
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
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return "pbkdf2$%d$%s$%s" % (rounds, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_pw(password, stored):
    try:
        _, rounds, salt_b64, _ = stored.split("$")
        return hmac.compare_digest(hash_pw(password, base64.b64decode(salt_b64), int(rounds)), stored)
    except (ValueError, TypeError):
        return False


def make_session(user_id):
    exp = str(int(time.time() + SESSION_HOURS * 3600))
    msg = "%d.%s" % (user_id, exp)
    sig = hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()[:32]
    return msg + "." + sig


def read_session(cookie):
    try:
        uid, exp, sig = cookie.split(".")
        msg = "%s.%s" % (uid, exp)
        good = hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()[:32]
        if hmac.compare_digest(sig, good) and int(exp) > time.time():
            return int(uid)
    except (ValueError, AttributeError):
        pass
    return None


# ------------------------------------------------------------------ the relay bridge

class Bridge:
    """Holds each Pi's open long-poll and shuttles calls/replies across it."""

    def __init__(self):
        self.lock = threading.Lock()
        self.queues = {}      # pi_id -> [call, ...] waiting to be picked up by the Pi
        self.waiting = {}     # call_id -> {"event": Event, "resp": dict}
        self.cond = {}        # pi_id -> Condition, so the Pi's poll can sleep until work arrives

    def _cond(self, pi_id):
        with self.lock:
            return self.cond.setdefault(pi_id, threading.Condition(self.lock))

    def call(self, pi_id, payload):
        """Browser side: queue a call for the Pi and wait for its reply."""
        call_id = secrets.token_hex(8)
        slot = {"event": threading.Event(), "resp": None}
        cond = self._cond(pi_id)
        with self.lock:
            self.waiting[call_id] = slot
            self.queues.setdefault(pi_id, []).append(dict(payload, id=call_id))
            cond.notify_all()
        ok = slot["event"].wait(CALL_TIMEOUT)
        with self.lock:
            self.waiting.pop(call_id, None)
            if pi_id in self.queues:
                self.queues[pi_id] = [c for c in self.queues[pi_id] if c["id"] != call_id]
        return slot["resp"] if ok else None

    def poll(self, pi_id):
        """Pi side: wait for the next call, or return None after POLL_TIMEOUT."""
        cond = self._cond(pi_id)
        deadline = time.time() + POLL_TIMEOUT
        with self.lock:
            while True:
                q = self.queues.get(pi_id)
                if q:
                    return q.pop(0)
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                cond.wait(remaining)

    def respond(self, call_id, resp):
        with self.lock:
            slot = self.waiting.get(call_id)
            if slot:
                slot["resp"] = resp
                slot["event"].set()


bridge = Bridge()


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
.row{{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}}.code{{font:700 26px ui-monospace,Menlo,monospace;letter-spacing:3px;background:#e0f2ef;color:#0f766e;padding:10px 16px;border-radius:10px;display:inline-block}}
a{{color:#0f766e}}</style></head><body><div class="wrap"><div class="brand">\U0001F6E1 QuietNet</div>{body}</div></body></html>"""


def page(body):
    return PAGE.format(body=body)


# ------------------------------------------------------------------ web server

class Relay(BaseHTTPRequestHandler):
    server_version = "QuietNet"

    def log_message(self, *a):
        pass

    # -- helpers --------------------------------------------------------

    def secure(self):
        return self.headers.get("X-Forwarded-Proto", "http") == "https"

    def user(self):
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"qn_session=([^;]+)", cookie)
        return read_session(m.group(1)) if m else None

    def set_cookie(self, token):
        flags = "HttpOnly; SameSite=Lax; Path=/; Max-Age=%d" % (SESSION_HOURS * 3600)
        if self.secure():
            flags += "; Secure"
        self._cookie = "qn_session=%s; %s" % (token, flags)

    def send_html(self, body, code=200):
        data = page(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if getattr(self, "_cookie", None):
            self.send_header("Set-Cookie", self._cookie)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to):
        self.send_response(303)
        self.send_header("Location", to)
        if getattr(self, "_cookie", None):
            self.send_header("Set-Cookie", self._cookie)
        self.end_headers()

    def body_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, TypeError):
            return {}

    def body_form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode("utf-8", "ignore")).items()}

    def my_pi(self, pi_id):
        uid = self.user()
        if not uid:
            return None
        return sql("SELECT id,user_id,name,token,paired,last_seen FROM pis WHERE id=? AND user_id=?",
                   (pi_id, uid), one=True)

    # -- routing --------------------------------------------------------

    def do_GET(self):
        url = urlparse(self.path)
        p = url.path
        if p == "/healthz":
            return self.send_json({"ok": True})
        if p == "/agent/poll":
            return self.agent_poll()
        if p.startswith("/pi/"):
            return self.pi_request("GET", p, url.query)
        if p in ("/login", "/signup"):
            return self.send_html(self.auth_form(p[1:]))
        if p == "/logout":
            self.set_cookie("")
            return self.redirect("/login")
        if p == "/" :
            return self.home()
        self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path).path
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
            self.set_cookie("")
            return self.redirect("/login")
        if p == "/pis/new":
            return self.new_pi()
        if p.startswith("/pis/") and p.endswith("/delete"):
            return self.delete_pi(p.split("/")[2])
        self.send_error(404)

    # -- accounts -------------------------------------------------------

    def auth_form(self, mode, error=""):
        other = "signup" if mode == "login" else "login"
        title = "Sign in" if mode == "login" else "Create your account"
        switch = ('New here? <a href="/signup">Create an account</a>' if mode == "login"
                  else 'Already have an account? <a href="/login">Sign in</a>')
        err = '<div class="err">%s</div>' % html.escape(error) if error else ""
        return """<div class="card"><h1>%s</h1><p class="muted">Reach your home QuietNet from anywhere.</p>%s
            <form method="post" action="/%s">
            <label>Email</label><input name="email" type="email" autocomplete="email" required>
            <label>Password</label><input name="password" type="password" autocomplete="%s" minlength="8" required>
            <button class="btn" type="submit">%s</button></form>
            <p class="muted" style="margin-top:16px">%s</p></div>""" % (
            title, err, mode, "current-password" if mode == "login" else "new-password", title, switch)

    def do_signup(self):
        f = self.body_form()
        email, pw = f.get("email", "").strip().lower(), f.get("password", "")
        if not EMAIL_RE.fullmatch(email) or len(pw) < 8:
            return self.send_html(self.auth_form("signup", "Enter a valid email and a password of at least 8 characters."))
        if sql("SELECT 1 FROM users WHERE email=?", (email,), one=True):
            return self.send_html(self.auth_form("signup", "That email already has an account."))
        sql("INSERT INTO users(email,pw,created) VALUES(?,?,?)", (email, hash_pw(pw), time.time()), commit=True)
        uid = sql("SELECT id FROM users WHERE email=?", (email,), one=True)[0]
        self.set_cookie(make_session(uid))
        self.redirect("/")

    def do_login(self):
        f = self.body_form()
        email, pw = f.get("email", "").strip().lower(), f.get("password", "")
        row = sql("SELECT id,pw FROM users WHERE email=?", (email,), one=True)
        if not row or not check_pw(pw, row[1]):
            return self.send_html(self.auth_form("login", "Wrong email or password."))
        self.set_cookie(make_session(row[0]))
        self.redirect("/")

    # -- device list / pairing -----------------------------------------

    def home(self):
        uid = self.user()
        if not uid:
            return self.redirect("/login")
        pis = sql("SELECT id,name,paired,last_seen FROM pis WHERE user_id=? ORDER BY created", (uid,))
        rows = ""
        now = time.time()
        for pid, name, paired, seen in pis:
            if not paired:
                code = sql("SELECT code FROM pis WHERE id=?", (pid,), one=True)[0]
                rows += """<div class="card"><div class="row"><div><b>%s</b><div class="muted">Waiting to be paired</div></div>
                    <form method="post" action="/pis/%s/delete"><button class="btn" style="background:#b42318">Remove</button></form></div>
                    <p class="muted" style="margin-top:12px">On the Pi's own QuietNet page, open <b>Remote access</b>, enter this relay's
                    web address and this code:</p><div class="code">%s</div></div>""" % (html.escape(name), pid, html.escape(code))
            else:
                online = seen and (now - seen) < OFFLINE_AFTER
                rows += """<a class="dev" href="/pi/%s/"><span class="dot %s"></span>
                    <span style="flex:1"><b>%s</b><div class="muted">%s</div></span><span class="muted">Open &rsaquo;</span></a>""" % (
                    pid, "on" if online else "", html.escape(name), "Online" if online else "Offline")
        return self.send_html("""<div class="row"><h1 style="margin:0">Your QuietNets</h1>
            <a class="muted" href="/logout">Sign out</a></div>%s
            <form method="post" action="/pis/new"><label>Add a QuietNet</label>
            <input name="name" placeholder="e.g. Home Pi" required>
            <button class="btn" type="submit">Create pairing code</button></form>""" % (rows or '<p class="muted">No QuietNets yet.</p>'))

    def new_pi(self):
        uid = self.user()
        if not uid:
            return self.redirect("/login")
        name = (self.body_form().get("name", "").strip() or "My QuietNet")[:40]
        pid = secrets.token_hex(8)
        code = "%s-%s" % (secrets.token_hex(2).upper(), secrets.token_hex(2).upper())
        sql("INSERT INTO pis(id,user_id,name,token,code,paired,created,last_seen) VALUES(?,?,?,?,?,0,?,0)",
            (pid, uid, name, "", code, time.time()), commit=True)
        self.redirect("/")

    def delete_pi(self, pid):
        uid = self.user()
        if uid:
            sql("DELETE FROM pis WHERE id=? AND user_id=?", (pid, uid), commit=True)
        self.redirect("/")

    # -- the agent (Pi) side -------------------------------------------

    def agent_pair(self):
        body = self.body_json()
        code = str(body.get("code", "")).strip().upper()
        row = sql("SELECT id FROM pis WHERE code=? AND paired=0", (code,), one=True)
        if not row:
            return self.send_json({"error": "That pairing code is wrong or already used."}, 400)
        token = secrets.token_hex(24)
        sql("UPDATE pis SET paired=1, token=?, code='', last_seen=? WHERE id=?",
            (token, time.time(), row[0]), commit=True)
        self.send_json({"ok": True, "id": row[0], "token": token})

    def agent(self):
        token = self.headers.get("X-QuietNet-Token", "")
        if not token:
            return None
        return sql("SELECT id FROM pis WHERE token=? AND paired=1", (token,), one=True)

    def agent_poll(self):
        row = self.agent()
        if not row:
            return self.send_error(401)
        sql("UPDATE pis SET last_seen=? WHERE id=?", (time.time(), row[0]), commit=True)
        call = bridge.poll(row[0])
        self.send_json(call or {})      # {} means "nothing to do"; a real call always carries an id

    def agent_respond(self):
        row = self.agent()
        if not row:
            return self.send_error(401)
        body = self.body_json()
        bridge.respond(str(body.get("id", "")),
                       {"status": int(body.get("status", 502)), "body": body.get("body", "")})
        self.send_json({"ok": True})

    # -- browser -> Pi relay -------------------------------------------

    def pi_request(self, method, path, query):
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
            payload["body"] = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "ignore")
        resp = bridge.call(pid, payload)
        if resp is None:
            return self.send_json({"error": "Your QuietNet didn't answer in time."}, 504)
        data = (resp.get("body") or "").encode()
        self.send_response(resp.get("status", 200))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_dashboard(self, pid, name):
        if not DASHBOARD:
            return self.send_error(500)
        with open(DASHBOARD, encoding="utf-8") as f:
            html_text = f.read()
        inject = ('<script>window.QN_API_BASE=%s;</script>' % json.dumps("/pi/" + pid)
                  + '<style>#qnbar{position:sticky;top:0;z-index:50;background:#0f766e;color:#fff;'
                    'padding:8px 16px;font:600 14px -apple-system,sans-serif;display:flex;gap:14px;align-items:center}'
                    '#qnbar a{color:#fff}</style>')
        bar = ('<div id="qnbar"><a href="/">&lsaquo; My QuietNets</a>'
               '<span style="flex:1">%s &mdash; remote</span><a href="/logout">Sign out</a></div>') % html.escape(name)
        html_text = html_text.replace("<head>", "<head>" + inject, 1).replace("<body>", "<body>" + bar, 1)
        data = html_text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    init_db()
    if not DASHBOARD:
        print("Warning: dashboard file not found; remote dashboard pages won't render.")
    print("QuietNet relay listening on port %d" % PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Relay).serve_forever()


if __name__ == "__main__":
    main()
