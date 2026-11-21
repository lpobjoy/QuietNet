#!/usr/bin/env python3
"""QuietNet - see what the devices in your home are talking to, and block the junk.

How it works: this program acts as the "phone book" (DNS server) for any device
you point at it. Every time a device wants to reach an address (for example
ads.example.com) it asks QuietNet first. QuietNet writes the request down,
and either passes it on to the real internet phone book or, if the address is
blocked, answers "that doesn't exist".

No extra software is needed - just Python 3.
"""
import argparse
import ipaddress
import json
import os
import queue
import re
import signal
import socket
import socketserver
import sqlite3
import subprocess
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import enforcer
import cloud_agent

# MAP OF THIS FILE (each part starts with a "# ----- name" banner):
#   settings and State   the values you might tune, and S, everything held in memory
#   database             the SQLite connection, the tables, saved settings, the history writer
#   rules                the lists, schedules and decision(): is this name blocked for this device, and why
#   DNS                  reading questions, building answers, asking the real servers, the UDP/TCP listeners
#   helpers              this computer's address, the neighbour table, the network scan, and the
#                        api_...() functions that build each dashboard answer
#   dashboard web server the Web class (every HTTP call) and main()
#
# HOW A CHANGE TO A RULE WORKS: the rule sets live in S for speed and in the database so they
# survive a restart. Every function that changes one updates both while holding db_lock.
# The DNS path only reads S, without a lock, and never waits on the database.
#
# Fuller explanation: docs/ARCHITECTURE.md. Every HTTP call: docs/API.md. Open faults: docs/KNOWN_ISSUES.md.

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("QUIETNET_DATA") or os.path.join(HERE, "data")   # where history and rules are kept
STATIC = os.path.join(HERE, "static")
COMMUNITY_FILE = os.path.join(DATA, "community_list.txt")
COMMUNITY_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
UPSTREAMS = [("1.1.1.1", 53), ("8.8.8.8", 53)]
KEEP_DAYS = 30
MAX_BODY = 64 * 1024   # the largest request body the dashboard API will read; real ones are a few hundred bytes
MAX_TTL = 120   # seconds a device may remember an answer, so new blocks and schedules bite within ~2 minutes
CLOCK = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
VALID_NAME = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")
IGNORED_ENDINGS = (".arpa", ".local", ".lan", ".home", ".internal")
# The system's own tool for listing network neighbours. Look in the usual places
# because the program isn't always started with those folders on its search path.
ARP = next((p for p in ("/usr/sbin/arp", "/sbin/arp", "/usr/bin/arp") if os.path.exists(p)), "arp")
SCOPE = re.compile(r"all|device:[0-9a-f.:]{3,45}|group:\d+")

# Words that often appear in advert / tracking addresses. These are only
# flagged as "possibly junk" for a human to decide on - never blocked on their own.
SUSPECT = re.compile(
    r"(^|[.-])(ads?|adserver|adservice|adtech|advert\w*|analytics|tracking|tracker|track|"
    r"telemetry|metrics|pixel|beacon|stats|banner|sponsor|affiliate|tagmanager|"
    r"crashlytics|app-measurement|adsystem|adsrv|logs?|events?)\d*([.-]|$)"
)

# Friendly names so people can tell who an address belongs to.
OWNERS = {
    "apple.com": "Apple", "icloud.com": "Apple iCloud", "mzstatic.com": "Apple", "apple-dns.net": "Apple",
    "aaplimg.com": "Apple", "cdn-apple.com": "Apple", "icloud-content.com": "Apple iCloud",
    "google.com": "Google", "googleapis.com": "Google", "gstatic.com": "Google", "google.co.uk": "Google",
    "googleusercontent.com": "Google", "gvt1.com": "Google", "gvt2.com": "Google", "ggpht.com": "Google",
    "youtube.com": "YouTube", "ytimg.com": "YouTube", "googlevideo.com": "YouTube video",
    "microsoft.com": "Microsoft", "windows.com": "Microsoft Windows", "live.com": "Microsoft",
    "office.com": "Microsoft Office", "office365.com": "Microsoft Office", "msftconnecttest.com": "Microsoft Windows",
    "windowsupdate.com": "Windows Update", "xboxlive.com": "Xbox", "skype.com": "Skype", "bing.com": "Bing",
    "amazon.com": "Amazon", "amazon.co.uk": "Amazon", "amazonaws.com": "Amazon cloud (used by many apps)",
    "media-amazon.com": "Amazon", "amazonvideo.com": "Prime Video", "primevideo.com": "Prime Video",
    "cloudfront.net": "Amazon cloud (used by many apps)", "amazonalexa.com": "Amazon Alexa",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix video", "nflximg.net": "Netflix", "nflxso.net": "Netflix",
    "facebook.com": "Facebook", "fbcdn.net": "Facebook", "instagram.com": "Instagram", "cdninstagram.com": "Instagram",
    "whatsapp.com": "WhatsApp", "whatsapp.net": "WhatsApp", "messenger.com": "Messenger",
    "tiktok.com": "TikTok", "tiktokcdn.com": "TikTok", "tiktokv.com": "TikTok", "bytedance.com": "TikTok",
    "twitter.com": "X / Twitter", "x.com": "X / Twitter", "twimg.com": "X / Twitter",
    "spotify.com": "Spotify", "scdn.co": "Spotify", "spotifycdn.com": "Spotify",
    "bbc.co.uk": "BBC", "bbci.co.uk": "BBC", "bbc.com": "BBC", "itv.com": "ITV", "channel4.com": "Channel 4",
    "sky.com": "Sky", "disneyplus.com": "Disney+", "disney-plus.net": "Disney+", "bamgrid.com": "Disney+",
    "roku.com": "Roku", "samsung.com": "Samsung", "samsungcloud.com": "Samsung", "samsungcloudsolution.com": "Samsung TV",
    "lgtvsdp.com": "LG TV", "lge.com": "LG", "sonos.com": "Sonos", "ring.com": "Ring", "nest.com": "Google Nest",
    "playstation.com": "PlayStation", "playstation.net": "PlayStation", "nintendo.net": "Nintendo",
    "nintendo.com": "Nintendo", "steampowered.com": "Steam", "epicgames.com": "Epic Games", "roblox.com": "Roblox",
    "akamai.net": "Akamai (delivers content for many sites)", "akamaiedge.net": "Akamai (delivers content for many sites)",
    "akamaihd.net": "Akamai (delivers content for many sites)", "fastly.net": "Fastly (delivers content for many sites)",
    "cloudflare.com": "Cloudflare", "cloudflare.net": "Cloudflare", "wikipedia.org": "Wikipedia",
    "zoom.us": "Zoom", "slack.com": "Slack", "dropbox.com": "Dropbox", "github.com": "GitHub",
    "paypal.com": "PayPal", "ebay.co.uk": "eBay", "ebay.com": "eBay", "reddit.com": "Reddit", "redd.it": "Reddit",
    "linkedin.com": "LinkedIn", "pinterest.com": "Pinterest", "snapchat.com": "Snapchat", "sc-cdn.net": "Snapchat",
    "doubleclick.net": "Google adverts", "googlesyndication.com": "Google adverts",
    "googleadservices.com": "Google adverts", "google-analytics.com": "Google tracking",
    "googletagmanager.com": "Google tracking", "app-measurement.com": "Google tracking",
    "adnxs.com": "Advert network (Xandr)", "criteo.com": "Advert network (Criteo)",
    "taboola.com": "Advert network (Taboola)", "outbrain.com": "Advert network (Outbrain)",
    "amazon-adsystem.com": "Amazon adverts", "scorecardresearch.com": "Tracking (Comscore)",
}

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc", "me", "sch", "nhs"}


class State:
    """Everything QuietNet holds in memory while running. There is one instance, `S`.

    The rule sets here mirror tables in the database: init_db() fills them at start-up, and every
    function that changes one writes the database in the same step, holding db_lock. Reads on the
    DNS path take no lock - they only look things up in sets and dicts, which is safe in Python."""
    blocked = set()         # addresses you chose to block
    allowed = set()         # addresses you chose to always allow
    junk_builtin = set()
    junk_community = set()
    junk_on = True
    paused_until = 0.0
    dns_error = None
    dns_port = 53
    local_ip = "127.0.0.1"
    list_state = "idle"     # idle | downloading | error
    list_error = ""
    hints = {}              # ip -> name the network reports
    services = []           # the catalogue from services.json
    svc_names = {}          # service id -> friendly name
    dom2svc = {}            # address -> service id
    svc_blocks = {}         # scope -> set of blocked service ids
    off = set()             # scopes whose internet is switched off
    enforced = set()        # device ips we actively enforce (cut live connections for)
    resolved = {}           # domain -> {ip: last-seen} : the addresses we've handed out
    dev_group = {}          # device ip -> group id
    group_names = {}        # group id -> name
    schedules = []          # timed rules, e.g. bedtime (see load_schedules)
    sched_cache = (0.0, [])  # (when worked out, schedules in force at that moment)
    scan_state = "idle"     # idle | scanning
    scan_ts = 0.0


S = State()
ENF = None
CA = None
db = None
db_lock = threading.RLock()
log_q = queue.Queue()


# ------------------------------------------------------------------ database

def sql(statement, args=(), commit=False):
    """Run one SQL statement and return all its rows. Holds db_lock, since one connection is
    shared by every thread. Pass commit=True for a change that should be saved at once."""
    with db_lock:
        rows = db.execute(statement, args).fetchall()
        if commit:
            db.commit()
        return rows


def init_db():
    """Open (or create) the database, make sure every table exists, and load the saved rules
    into S. Called once at start-up; the tests call it again to mimic a restart."""
    global db
    os.makedirs(DATA, exist_ok=True)
    try:
        os.chmod(DATA, 0o700)       # the folder holds the household's browsing history: owner only
    except OSError:
        pass                        # e.g. a mounted volume that does not allow it; carry on
    db = sqlite3.connect(os.path.join(DATA, "quietnet.db"), check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    # With the write-ahead log, NORMAL is safe against corruption and avoids forcing the disk after
    # every batch of history - which matters on a Raspberry Pi's SD card. The worst a power cut can
    # lose is the last second or so of history.
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY, ts REAL, client TEXT, domain TEXT, blocked INTEGER);
        -- Two indexes, one per question the dashboard asks of the history:
        --   q_client_ts: "what did THIS device look up recently?" (the device page) and "when was each device last active?"
        --   q_ts:        "what happened in the last 24 hours, across all devices?" (the status summary and device counts).
        --                It carries client and blocked too, so those counts are answered from the index alone.
        CREATE INDEX IF NOT EXISTS q_client_ts ON queries(client, ts);
        CREATE INDEX IF NOT EXISTS q_ts ON queries(ts, client, blocked);
        CREATE TABLE IF NOT EXISTS blocked(domain TEXT PRIMARY KEY, ts REAL);
        CREATE TABLE IF NOT EXISTS allowed(domain TEXT PRIMARY KEY, ts REAL);
        CREATE TABLE IF NOT EXISTS devices(ip TEXT PRIMARY KEY, name TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS groups(id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE IF NOT EXISTS schedules(id INTEGER PRIMARY KEY, name TEXT, scope TEXT, days TEXT,
            t_from TEXT, t_to TEXT, off INTEGER, services TEXT, enabled INTEGER);
        CREATE TABLE IF NOT EXISTS seen(ip TEXT PRIMARY KEY, mac TEXT, host TEXT, ts REAL);
        CREATE TABLE IF NOT EXISTS device_group(ip TEXT PRIMARY KEY, gid INTEGER);
        CREATE TABLE IF NOT EXISTS service_blocks(scope TEXT, service TEXT, PRIMARY KEY(scope, service));
        CREATE TABLE IF NOT EXISTS internet_off(scope TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS enforced(ip TEXT PRIMARY KEY);
    """)
    db.commit()
    S.blocked = {r[0] for r in sql("SELECT domain FROM blocked")}
    S.allowed = {r[0] for r in sql("SELECT domain FROM allowed")}
    S.group_names = dict(sql("SELECT id, name FROM groups"))
    S.dev_group = dict(sql("SELECT ip, gid FROM device_group"))
    S.off = {r[0] for r in sql("SELECT scope FROM internet_off")}
    S.enforced = {r[0] for r in sql("SELECT ip FROM enforced")}
    S.svc_blocks = {}
    for scope, service in sql("SELECT scope, service FROM service_blocks"):
        S.svc_blocks.setdefault(scope, set()).add(service)
    load_schedules()
    S.junk_on = get_setting("junk_on", "1") == "1"
    S.paused_until = float(get_setting("paused_until", "0"))


def get_setting(key, default):
    """Read one saved setting (a text value), or `default` if it was never set."""
    rows = sql("SELECT value FROM settings WHERE key=?", (key,))
    return rows[0][0] if rows else default


def set_setting(key, value):
    """Save one setting, replacing any earlier value."""
    sql("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)), commit=True)


def log_writer():
    """Background thread: move recorded lookups from the queue into the database.

    The DNS path only puts a tuple on log_q, so answering a lookup never waits for the disk.
    This thread gathers a second's worth and saves them in one go. Once an hour it also deletes
    history older than KEEP_DAYS."""
    last_prune = 0
    while True:
        batch = [log_q.get()]
        time.sleep(1)
        while not log_q.empty():
            batch.append(log_q.get_nowait())
        try:
            with db_lock:
                db.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,?)", batch)
                if time.time() - last_prune > 3600:
                    db.execute("DELETE FROM queries WHERE ts<?", (time.time() - KEEP_DAYS * 86400,))
                    last_prune = time.time()
                db.commit()
        except sqlite3.Error as e:
            print("Could not save history:", e)


# ------------------------------------------------------------------ rules

def load_lists():
    """Load the built-in advert list, the downloaded community list (if present) and the
    service catalogue from their files into S."""
    path = os.path.join(HERE, "junk_domains.txt")
    with open(path) as f:
        S.junk_builtin = {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}
    if os.path.exists(COMMUNITY_FILE):
        with open(COMMUNITY_FILE) as f:
            S.junk_community = {l.strip() for l in f if l.strip()}
    with open(os.path.join(HERE, "services.json")) as f:
        S.services = json.load(f)
    S.svc_names = {v["id"]: v["name"] for v in S.services}
    S.dom2svc = {d: v["id"] for v in S.services for d in v["domains"]}


def suffixes(domain):
    """The name and each of its parents, most specific first, stopping before the last part.
    'a.b.example.com' -> ['a.b.example.com', 'b.example.com', 'example.com'].
    A rule on any of these applies to the name, which is how one entry covers everything beneath it."""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def is_junk(domain):
    """Is this name, or a parent of it, on the built-in or community advert list?"""
    return any(s in S.junk_builtin or s in S.junk_community for s in suffixes(domain))


def load_schedules():
    """Reload every schedule from the database into S.schedules, and clear the short-lived
    cache of which ones are in force."""
    S.schedules = [
        {"id": r[0], "name": r[1], "scope": r[2], "days": [int(c) for c in r[3]], "start": r[4], "end": r[5],
         "off": bool(r[6]), "services": json.loads(r[7]), "enabled": bool(r[8])}
        for r in sql("SELECT id,name,scope,days,t_from,t_to,off,services,enabled FROM schedules ORDER BY id")]
    S.sched_cache = (0.0, [])


def clock_minutes(hhmm):
    """'21:30' -> 1290: minutes since midnight. The text must already match CLOCK."""
    return int(hhmm[:2]) * 60 + int(hhmm[3:])


def schedule_in_force(x, now=None):
    """Is this schedule's time window open right now (by this computer's clock)?"""
    t = time.localtime(now)
    mins, day = t.tm_hour * 60 + t.tm_min, t.tm_wday      # Monday is day 0
    start, end = clock_minutes(x["start"]), clock_minutes(x["end"])
    if start < end:
        return day in x["days"] and start <= mins < end
    # Overnight, e.g. 21:00 to 07:00: the evening belongs to today, the early morning to yesterday's schedule.
    return (day in x["days"] and mins >= start) or ((day - 1) % 7 in x["days"] and mins < end)


def active_schedules():
    """The enabled schedules whose time window is open right now.

    Worked out at most once every 5 seconds and remembered, because decision() calls this for
    every single lookup."""
    stamp, active = S.sched_cache
    now = time.time()
    if now - stamp > 5:
        active = [x for x in S.schedules if x["enabled"] and schedule_in_force(x, now)]
        S.sched_cache = (now, active)
    return active


def scopes_for(client):
    """Every set of rules that applies to a device: the whole house, itself, and its group."""
    out = ["all"]
    if client:
        out.append("device:" + client)
        if client in S.dev_group:
            out.append("group:%d" % S.dev_group[client])
    return out


def internet_off_for(client):
    """Is all internet off for this device right now - by its own switch, its group's,
    or an all-internet schedule? (The kill switch is checked separately, as 'all' in S.off.)"""
    scopes = scopes_for(client)
    return any(sc in S.off for sc in scopes) or any(x["off"] for x in active_schedules() if x["scope"] in scopes)


def scope_label(scope):
    """A scope in plain words for the dashboard: 'whole house', 'Kids group' or 'this device'."""
    if scope == "all":
        return "whole house"
    if scope.startswith("group:"):
        return S.group_names.get(int(scope[6:]), "group") + " group"
    return "this device"


def decision(domain, client=None, paused=False):
    """Returns (blocked?, why, detail).

    why is 'kill', 'off', 'schedule', 'you', 'allowed', 'service', 'list' or None.
    'paused' only pauses advert blocking and your own address blocks -
    the kill switch, schedules, blocked services and switched-off devices stay in force."""
    if "all" in S.off:
        return True, "kill", ""
    scopes = scopes_for(client)
    if any(sc in S.off for sc in scopes):
        return True, "off", ""
    timed = [x for x in active_schedules() if x["scope"] in scopes]
    for x in timed:
        if x["off"]:
            return True, "schedule", x["name"]
    names = suffixes(domain)
    for s in names:
        if s in S.blocked and not paused:
            return True, "you", ""
        if s in S.allowed:
            return False, "allowed", ""
    for s in names:
        svc = S.dom2svc.get(s)
        if not svc:
            continue
        if any(svc in S.svc_blocks.get(sc, ()) for sc in scopes):
            return True, "service", S.svc_names[svc]
        for x in timed:
            if svc in x["services"]:
                return True, "schedule", x["name"]
    if not paused and S.junk_on and is_junk(domain):
        return True, "list", ""
    return False, None, ""


def verdict(domain):
    """The label the dashboard shows beside a name: 'junk' (on the advert list), 'suspect'
    (the name contains a word such as 'tracking'; shown for a person to judge, never blocked on
    its own) or 'ok'. The last part of the name (.com, .net) is ignored when looking for words."""
    if is_junk(domain):
        return "junk"
    if SUSPECT.search(domain.rsplit(".", 1)[0]):
        return "suspect"
    return "ok"


def base_of(domain):
    """The part of a name that identifies its owner, used to group activity by company:
    'cdn.example.com' -> 'example.com', and 'news.bbc.co.uk' -> 'bbc.co.uk' (three parts are kept
    when the ending is a two-letter country after 'co', 'org', 'ac' and the like)."""
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def clean_domain(text):
    """Turn whatever a person typed or pasted into a bare address, or None if it isn't one.
    Drops any 'https://', path, port, trailing dot and leading 'www.', then checks the result.
    This is the only gate on addresses entering the blocked and allowed lists."""
    if not isinstance(text, str):
        return None
    text = text.strip().lower()
    text = re.sub(r"^[a-z]+://", "", text).split("/")[0].split(":")[0].strip(".")
    if text.startswith("www."):
        text = text[4:]
    return text if VALID_NAME.fullmatch(text) else None


def block(domain):
    """Add an address to your blocked list, and remove any 'always allow' on it or beneath
    it, which would otherwise defeat the block."""
    with db_lock:
        for a in [a for a in S.allowed if a == domain or a.endswith("." + domain)]:
            S.allowed.discard(a)
            db.execute("DELETE FROM allowed WHERE domain=?", (a,))
        S.blocked.add(domain)
        db.execute("INSERT OR REPLACE INTO blocked VALUES(?,?)", (domain, time.time()))
        db.commit()


def unblock(domain):
    """Remove an address from your blocked list. If the advert list would still block it,
    also add an 'always allow' so that the unblock has an effect."""
    with db_lock:
        S.blocked.discard(domain)
        db.execute("DELETE FROM blocked WHERE domain=?", (domain,))
        if decision(domain)[1] == "list":  # the advert list still blocks it: keep it allowed from now on
            S.allowed.add(domain)
            db.execute("INSERT OR REPLACE INTO allowed VALUES(?,?)", (domain, time.time()))
        db.commit()


def forget(domain):
    """Remove an address from both your blocked list and your allowed list."""
    with db_lock:
        S.blocked.discard(domain)
        S.allowed.discard(domain)
        db.execute("DELETE FROM blocked WHERE domain=?", (domain,))
        db.execute("DELETE FROM allowed WHERE domain=?", (domain,))
        db.commit()


def update_community_list():
    """Download the community advert list, check it, save it and start using it.

    Runs in its own thread (started from the dashboard). Progress and errors are reported through
    S.list_state and S.list_error. A download with fewer than 1,000 usable lines is treated as
    broken and thrown away, so a bad download can never replace a good list."""
    S.list_state, S.list_error = "downloading", ""
    try:
        req = urllib.request.Request(COMMUNITY_URL, headers={"User-Agent": "QuietNet"})
        with urllib.request.urlopen(req, timeout=45) as r:
            text = r.read().decode("utf-8", "ignore")
        found = set()
        for line in text.splitlines():
            if line.startswith("0.0.0.0 "):
                d = line.split()[1].lower()
                if VALID_NAME.fullmatch(d) and not d.replace(".", "").isdigit():   # skip the list's own "0.0.0.0 0.0.0.0" line
                    found.add(d)
        if len(found) < 1000:
            raise ValueError("the list looked incomplete")
        with open(COMMUNITY_FILE, "w") as f:
            f.write("\n".join(sorted(found)))
        S.junk_community = found
        S.list_state = "idle"
    except Exception as e:
        S.list_state, S.list_error = "error", str(e)


# ------------------------------------------------------------------ DNS

def parse_question(data):
    """Read the question out of a DNS packet. Returns (name, record type, where the question
    ends), or None if the packet is malformed.

    The name is a run of length-prefixed labels ending in a zero byte. A label byte with its top
    bits set would be a pointer or a reserved type; questions never legitimately contain those,
    so such packets are refused outright - nothing here can be made to loop."""
    if len(data) < 17 or int.from_bytes(data[4:6], "big") < 1:
        return None
    pos, labels = 12, []
    while True:
        if pos >= len(data):
            return None
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0:
            return None
        labels.append(data[pos + 1:pos + 1 + n])
        pos += 1 + n
    if pos + 4 > len(data):
        return None
    qtype = int.from_bytes(data[pos:pos + 2], "big")
    name = b".".join(labels).decode("ascii", "replace").lower()
    return name, qtype, pos + 4


def reply(data, qend, rcode=0, answer=b""):
    """Build a DNS reply to the packet `data`: same id and question, the given result code,
    and at most one answer record (already encoded in `answer`)."""
    head = data[:2] + bytes([0x80 | (data[2] & 0x79), 0x80 | rcode])
    head += b"\x00\x01" + (b"\x00\x01" if answer else b"\x00\x00") + b"\x00\x00\x00\x00"
    return head + data[12:qend] + answer


def blocked_reply(data, qtype, qend):
    """The reply for a blocked name. For an address question the answer is 0.0.0.0 (or ::
    for IPv6), which devices give up on at once; any other kind of question gets 'no error, no
    records'. The answer may be remembered for 60 seconds."""
    answer = b""
    if qtype == 1:      # A: answer with 0.0.0.0 so the device gives up straight away
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(4)
    elif qtype == 28:   # AAAA
        answer = b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + bytes(16)
    return reply(data, qend, 0, answer)


def answer_ips(resp):
    """Pull the IPv4/IPv6 addresses out of a DNS answer, so the enforcer knows
    which addresses belong to a name. Best-effort: returns [] if it can't parse."""
    out = []
    try:
        buf = memoryview(resp)
        counts = [int.from_bytes(buf[i:i + 2], "big") for i in (4, 6, 8, 10)]

        def skip_name(pos):
            """Step past one encoded name starting at `pos`; return the position just after it."""
            while True:
                n = buf[pos]
                if n == 0:
                    return pos + 1
                if n & 0xC0:
                    return pos + 2
                pos += 1 + n

        pos = 12
        for _ in range(counts[0]):
            pos = skip_name(pos) + 4
        for _ in range(counts[1]):
            pos = skip_name(pos)
            rtype = int.from_bytes(buf[pos:pos + 2], "big")
            rdlen = int.from_bytes(buf[pos + 8:pos + 10], "big")
            rdata = buf[pos + 10:pos + 10 + rdlen]
            if rtype == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(bytes(rdata)))
            elif rtype == 28 and rdlen == 16:
                out.append(socket.inet_ntop(socket.AF_INET6, bytes(rdata)))
            pos += 10 + rdlen
    except (IndexError, ValueError, OSError):
        return []
    return out


def record_resolved(domain, resp):
    """Remember which addresses a name was just given, with the time. The enforcer uses
    this to know which addresses to drop when a name is blocked. Capped at 4,000 names; when
    full, the 1,000 least recently seen are forgotten."""
    ips = answer_ips(resp)
    if not ips:
        return
    now = time.time()
    with db_lock:
        m = S.resolved.setdefault(domain, {})
        for ip in ips:
            m[ip] = now
        if len(S.resolved) > 4000:                     # keep memory bounded: drop the stalest names
            for d in sorted(S.resolved, key=lambda d: max(S.resolved[d].values()))[:1000]:
                S.resolved.pop(d, None)


def enforcement_plan():
    """What the enforcer should drop, per enforced device: reuses the normal rules.
    {victim_ip: {"off": all-internet?, "ips": {addresses to drop}}}"""
    if not S.enforced:
        return {}
    now = time.time()
    plan = {}
    for victim in list(S.enforced):                    # a copy: the dashboard may change the set while we loop
        if internet_off_for(victim) or "all" in S.off:
            plan[victim] = {"off": True, "ips": set()}
            continue
        ips = set()
        for domain, ipmap in list(S.resolved.items()):
            if decision(domain, victim)[0]:
                ips.update(ip for ip, ts in ipmap.items() if now - ts < 6 * 3600 and ":" not in ip)
        plan[victim] = {"off": False, "ips": ips}
    return plan


def cap_ttls(resp, limit=MAX_TTL):
    """Shorten how long a device may remember an answer.

    Without this a device can keep using an address for hours after it has been
    blocked, which would make bedtime schedules and the kill switch very slow to bite."""
    try:
        buf = bytearray(resp)
        counts = [int.from_bytes(buf[i:i + 2], "big") for i in (4, 6, 8, 10)]

        def skip_name(pos):
            """Step past one encoded name starting at `pos`; return the position just after it.
            Unlike the copy in answer_ips, this one refuses reserved label types, because cap_ttls
            rewrites the packet and must not guess."""
            while True:
                n = buf[pos]
                if n == 0:
                    return pos + 1
                if n & 0xC0 == 0xC0:          # a compression pointer ends the name
                    return pos + 2
                if n & 0xC0:                  # reserved label type: this isn't a name we understand
                    raise ValueError("reserved label byte")
                pos += 1 + n

        pos = 12
        for _ in range(counts[0]):
            pos = skip_name(pos) + 4
        for _ in range(sum(counts[1:])):
            pos = skip_name(pos)
            if pos + 10 > len(buf):
                raise ValueError("record header runs off the end")
            rtype = int.from_bytes(buf[pos:pos + 2], "big")
            if rtype != 41 and int.from_bytes(buf[pos + 4:pos + 8], "big") > limit:   # 41 = settings record, not an answer
                buf[pos + 4:pos + 8] = limit.to_bytes(4, "big")
            pos += 10 + int.from_bytes(buf[pos + 8:pos + 10], "big")
        # Only trust the rewrite if every record lined up and we landed exactly at the end.
        # Anything else means we misread the packet, so hand back the untouched original.
        if pos != len(buf):
            return resp
        return bytes(buf)
    except (IndexError, ValueError):
        return resp


def forward_udp(data):
    """Ask the real DNS servers over UDP, first one then the spare. Returns the reply, or
    None if neither answered within 2.5 seconds."""
    for up in UPSTREAMS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.5)
                # connect() makes the system discard packets from any other sender, so only the
                # server we asked can answer. Without it, anyone who guessed the port and the
                # two-byte id could slip in a forged answer.
                s.connect(up)
                s.send(data)
                while True:
                    resp = s.recv(4096)
                    if resp[:2] == data[:2]:
                        return resp
        except OSError:
            continue
    return None


def forward_tcp(data):
    """The same as forward_udp but over TCP, where each message is preceded by its length
    as two bytes. Used for lookups that arrived over TCP."""
    for up in UPSTREAMS:
        try:
            with socket.create_connection(up, timeout=4) as s:
                s.sendall(len(data).to_bytes(2, "big") + data)
                head = recv_exact(s, 2)
                return recv_exact(s, int.from_bytes(head, "big"))
        except (OSError, ValueError):
            continue
    return None


def recv_exact(s, n):
    """Read exactly n bytes from a connection, or raise ValueError if it closes first."""
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ValueError("connection closed")
        buf += chunk
    return buf


def answer_query(data, client, forwarder):
    """The whole life of one lookup: read it, decide, record it, answer it.

    `forwarder` is forward_udp or forward_tcp (or a stand-in, in tests). Returns the reply bytes,
    or None when the packet was unreadable and the upstream server did not answer either.
    The steps are described in docs/ARCHITECTURE.md under 'What happens to one lookup'."""
    q = parse_question(data)
    if not q:
        return forwarder(data)
    name, qtype, qend = q
    loggable = bool(VALID_NAME.fullmatch(name)) and not name.endswith(IGNORED_ENDINGS)
    if client == "127.0.0.1":
        client = S.local_ip
    blocked = loggable and decision(name, client, time.time() < S.paused_until)[0]
    if loggable:
        log_q.put((time.time(), client, name, 1 if blocked else 0))
    if blocked:
        return blocked_reply(data, qtype, qend)
    resp = forwarder(data)
    if resp and loggable:
        record_resolved(name, resp)
    return cap_ttls(resp) if resp else reply(data, qend, 2)


def udp_server(sock):
    """Receive lookups on the UDP socket for ever, handing each to a pool of 64 worker
    threads so that one slow upstream answer does not hold up the rest."""
    pool = ThreadPoolExecutor(max_workers=64)

    def work(data, addr):
        """Answer one lookup and send the reply back to the device that asked."""
        try:
            resp = answer_query(data, addr[0], forward_udp)
            if resp:
                sock.sendto(resp, addr)
        except Exception as e:
            print("Lookup problem:", e)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            continue
        pool.submit(work, data, addr)


class TCPHandler(socketserver.BaseRequestHandler):
    """Handles one DNS lookup that arrived over TCP (one lookup per connection)."""
    def handle(self):
        """Read the two-byte length and the question, answer it, send the reply the same way.
        A connection that stalls for 5 seconds is dropped."""
        try:
            self.request.settimeout(5)
            n = int.from_bytes(recv_exact(self.request, 2), "big")
            data = recv_exact(self.request, n)
            resp = answer_query(data, self.client_address[0], forward_tcp)
            if resp:
                self.request.sendall(len(resp).to_bytes(2, "big") + resp)
        except (OSError, ValueError):
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    """The TCP side of the DNS filter: one short-lived thread per connection."""
    allow_reuse_address = True
    daemon_threads = True


def start_dns(port):
    """Open the DNS port for UDP and TCP and start serving. If the port cannot be opened
    (usually because something else is using it) the reason is kept in S.dns_error for the
    dashboard to show, and the rest of QuietNet carries on."""
    S.dns_port = port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        tcp = TCPServer(("0.0.0.0", port), TCPHandler)
    except OSError as e:
        S.dns_error = str(e)
        print("Could not start the filter on port %d: %s" % (port, e))
        return
    threading.Thread(target=udp_server, args=(sock,), daemon=True).start()
    threading.Thread(target=tcp.serve_forever, daemon=True).start()


# ------------------------------------------------------------------ helpers

def find_local_ip():
    """This computer's address on the home network (e.g. 192.168.1.60), found by asking the
    system which address it would use to reach the outside. Nothing is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))  # no data is sent; this just asks which address we'd use
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def neighbours():
    """Which devices this computer currently knows about: {ip: mac}.

    Reads the operating system's own neighbour table. On Linux (e.g. a Raspberry Pi)
    that's /proc/net/arp - no extra tools needed, so it works in a plain container.
    On macOS it reads the built-in `arp` command."""
    out = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 4 and re.fullmatch(r"[0-9a-f:]{17}", cols[3]) and cols[3] != "00:00:00:00:00:00":
                        out[cols[0]] = cols[3]
        except OSError:
            pass
        return out
    try:
        text = subprocess.run([ARP, "-an"], capture_output=True, text=True, timeout=20).stdout
        for line in text.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})", line)
            if m:
                mac = ":".join(part.zfill(2) for part in m.group(2).lower().split(":"))
                if mac != "ff:ff:ff:ff:ff:ff":
                    out[m.group(1)] = mac
    except (OSError, ValueError):
        pass
    return out


def hint_refresher():
    """Background thread: every two minutes, look up the host name of each device this
    computer knows about, so the dashboard can suggest names for them."""
    while True:
        try:
            hints = {}
            for ip, mac in neighbours().items():
                name = reverse_name(ip)
                if name:
                    hints[ip] = name
            S.hints = hints
        except Exception:
            pass
        time.sleep(120)


def reverse_name(ip):
    """The host name the network reports for an address, without its domain, or '' if none."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name.split(".")[0]
    except OSError:
        return ""


def scan_network():
    """Find every device on the home network (the 254 addresses next to this computer's)."""
    S.scan_state = "scanning"
    try:
        prefix = S.local_ip.rsplit(".", 1)[0] + "."
        # Knock on every address. Any device that is switched on has to reveal its
        # hardware address to this computer in order to receive the knock.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(2):
                for i in range(1, 255):
                    try:
                        sock.sendto(b"\0", (prefix + str(i), 9))
                    except OSError:
                        pass
                time.sleep(1.2)
        found = {ip: mac for ip, mac in neighbours().items()
                 if ip.startswith(prefix) and not ip.endswith(".255")}
        found.setdefault(S.local_ip, "")
        pool = ThreadPoolExecutor(max_workers=32)
        jobs = {ip: pool.submit(reverse_name, ip) for ip in found}
        deadline = time.time() + 8
        now = time.time()
        with db_lock:
            for ip, job in jobs.items():
                try:
                    host = job.result(timeout=max(0.1, deadline - time.time()))
                except Exception:
                    host = ""
                db.execute("""INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                              mac=excluded.mac, ts=excluded.ts,
                              host=CASE WHEN excluded.host='' THEN seen.host ELSE excluded.host END""",
                           (ip, found[ip], host, now))
            db.commit()
        pool.shutdown(wait=False)
    except Exception as e:
        print("Scan problem:", e, flush=True)
    finally:
        S.scan_ts = time.time()
        S.scan_state = "idle"


def api_status():
    """GET /api/status: the summary shown at the top of every dashboard page."""
    now = time.time()
    total, blocked = sql("SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM queries WHERE ts>?", (now - 86400,))[0]
    return {
        "ip": S.local_ip, "dns_ok": S.dns_error is None, "dns_error": S.dns_error, "dns_port": S.dns_port,
        "paused_for": max(0, int(S.paused_until - now)), "junk_on": S.junk_on,
        "kill": "all" in S.off, "clock": time.strftime("%H:%M"),
        "junk_count": len(S.junk_builtin | S.junk_community),
        "community": {"installed": bool(S.junk_community), "count": len(S.junk_community),
                      "updated": os.path.getmtime(COMMUNITY_FILE) if os.path.exists(COMMUNITY_FILE) else None,
                      "state": S.list_state, "error": S.list_error},
        "today": {"total": total, "blocked": blocked},
        "scan": {"state": S.scan_state, "ts": S.scan_ts},
        "enforcer": ENF.status() if ENF else {"available": False, "reason": "", "active": False},
    }


def api_devices():
    """GET /api/devices: every device that has used QuietNet or been found by a scan,
    with its name, group, switches and today's counts."""
    since = time.time() - 86400
    names = dict(sql("SELECT ip, name FROM devices"))
    out = {}

    def entry(ip):
        """The dict for one device, created with empty defaults the first time it is asked for."""
        return out.setdefault(ip, {
            "ip": ip, "name": names.get(ip) or "", "hint": S.hints.get(ip, ""), "mac": "",
            "this_computer": ip == S.local_ip, "last": 0, "n": 0, "nb": 0, "on_network": 0,
            "group": S.dev_group.get(ip), "off": internet_off_for(ip),
            "enforced": ip in S.enforced})

    # Two small questions, each answered straight from an index, in place of one that read every
    # row of up to 30 days of history on every dashboard refresh.
    for ip, last in sql("SELECT client, MAX(ts) FROM queries GROUP BY client"):                  # uses q_client_ts
        entry(ip)["last"] = last
    for ip, n, nb in sql("""SELECT client, COUNT(*), COALESCE(SUM(blocked), 0) FROM queries INDEXED BY q_ts
                            WHERE ts>? GROUP BY client""", (since,)):
        entry(ip).update(n=n, nb=nb)
    for ip, mac, host, ts in sql("SELECT ip, mac, host, ts FROM seen"):
        d = entry(ip)
        d.update(mac=mac, on_network=ts)
        if host:
            d["hint"] = host
    # Devices using QuietNet first (most recent at the top), then the rest in address order.
    return sorted(out.values(), key=lambda d: (-d["last"], [int(x) if x.isdigit() else 0 for x in d["ip"].split(".")]))


def api_activity(ip, hours):
    """GET /api/activity: what one device looked up in the last `hours`, grouped by owner
    (see base_of), with the label and the current block decision for every name and group."""
    since = time.time() - hours * 3600
    rows = sql("""SELECT domain, COUNT(*), MAX(ts), SUM(blocked) FROM queries
                  WHERE client=? AND ts>? GROUP BY domain""", (ip, since))
    groups = {}
    for domain, n, last, nb in rows:
        base = base_of(domain)
        g = groups.setdefault(base, {"base": base, "owner": OWNERS.get(base, ""), "n": 0, "nb": 0, "last": 0, "hosts": []})
        b, why, svc = decision(domain, ip)
        g["hosts"].append({"d": domain, "n": n, "nb": nb, "last": last, "v": verdict(domain),
                           "b": b, "why": why, "svc": svc})
        g["n"] += n
        g["nb"] += nb
        g["last"] = max(g["last"], last)
    for g in groups.values():
        g["hosts"].sort(key=lambda h: -h["n"])
        vs = {h["v"] for h in g["hosts"]}
        g["v"] = "junk" if vs == {"junk"} else ("suspect" if vs & {"junk", "suspect"} else "ok")
        g["b"], g["why"], g["svc"] = decision(g["base"], ip)
        g["some_blocked"] = any(h["b"] for h in g["hosts"])
    return sorted(groups.values(), key=lambda g: -g["n"])


def api_rules():
    """GET /api/rules: your own blocked and allowed addresses, newest first."""
    def rows(table):
        """One of the two lists. `table` is only ever the fixed text 'blocked' or 'allowed'."""
        return [{"d": d, "ts": ts, "owner": OWNERS.get(base_of(d), "")} for d, ts in
                sql("SELECT domain, ts FROM %s ORDER BY ts DESC" % table)]
    return {"blocked": rows("blocked"), "allowed": rows("allowed")}


def api_groups():
    """GET /api/groups: every group with its members and switches, in name order."""
    out = []
    for gid, name in sorted(S.group_names.items(), key=lambda x: x[1].lower()):
        scope = "group:%d" % gid
        out.append({"id": gid, "name": name, "off": scope in S.off,
                    "members": sorted(ip for ip, g in S.dev_group.items() if g == gid),
                    "services": len(S.svc_blocks.get(scope, ()))})
    return out


def api_controls(scope):
    """What is switched off / blocked for one device, one group, or the whole house, and why."""
    inherited = []
    if scope != "all":
        inherited.append("all")
    if scope.startswith("device:") and scope[7:] in S.dev_group:
        inherited.append("group:%d" % S.dev_group[scope[7:]])
    own = S.svc_blocks.get(scope, ())
    timed = [x for x in active_schedules() if x["scope"] == scope or x["scope"] in inherited]
    services = {}
    for v in S.services:
        via = next((sc for sc in inherited if v["id"] in S.svc_blocks.get(sc, ())), None)
        why = "for the " + scope_label(via) if via else ""
        if not why:
            sch = next((x for x in timed if not x["off"] and v["id"] in x["services"]), None)
            if sch:
                why = 'by the "%s" schedule' % sch["name"]
        services[v["id"]] = {"on": v["id"] in own, "from": why}
    off_from = ""
    off_via = next((sc for sc in inherited if sc in S.off), None)
    sch = next((x for x in timed if x["off"]), None)
    if "all" in S.off:
        off_from = "by the kill switch"
    elif off_via:
        off_from = "for the " + scope_label(off_via)
    elif sch:
        off_from = 'by the "%s" schedule' % sch["name"]
    return {"off": scope in S.off and scope != "all", "off_from": off_from, "services": services}


def api_schedules():
    """GET /api/schedules: every schedule, each marked with whether it is in force now."""
    return [dict(x, active=x["enabled"] and schedule_in_force(x)) for x in S.schedules]


def save_schedule(body):
    """Create or change a schedule. Returns an error message, or None when saved."""
    name = str(body.get("name", "")).strip()[:40] or "Schedule"
    scope = str(body.get("scope", ""))
    days = body.get("days")
    start, end = str(body.get("start", "")), str(body.get("end", ""))
    off = bool(body.get("off"))
    raw_services = body.get("services")
    services = [v for v in raw_services if v in S.svc_names] if (not off and isinstance(raw_services, list)) else []
    if not SCOPE.fullmatch(scope) or (scope.startswith("group:") and int(scope[6:]) not in S.group_names):
        return "Please choose who the schedule is for."
    # A day must be a whole number 0-6. Guard against bool (True == 1) and float (1.0 == 1), which pass a naive range test.
    if (not isinstance(days, list) or not days
            or any(not isinstance(d, int) or isinstance(d, bool) or d not in range(7) for d in days)):
        return "Please choose at least one day."
    if not CLOCK.fullmatch(start) or not CLOCK.fullmatch(end):
        return "Please fill in both times."
    if start == end:
        return "The start and end times can't be the same."
    if not off and not services:
        return "Please choose what to block."
    row = (name, scope, "".join(str(d) for d in sorted(set(days))), start, end, int(off), json.dumps(services))
    with db_lock:
        if any(x["id"] == body.get("id") for x in S.schedules):
            db.execute("UPDATE schedules SET name=?,scope=?,days=?,t_from=?,t_to=?,off=?,services=? WHERE id=?",
                       row + (body["id"],))
        else:
            db.execute("INSERT INTO schedules(name,scope,days,t_from,t_to,off,services,enabled) VALUES(?,?,?,?,?,?,?,1)", row)
        db.commit()
        load_schedules()
    return None


def set_service_block(scope, service, on):
    """Block or unblock one service for one scope, in memory and in the database."""
    with db_lock:
        if on:
            S.svc_blocks.setdefault(scope, set()).add(service)
            db.execute("INSERT OR IGNORE INTO service_blocks VALUES(?,?)", (scope, service))
        else:
            S.svc_blocks.get(scope, set()).discard(service)
            db.execute("DELETE FROM service_blocks WHERE scope=? AND service=?", (scope, service))
        db.commit()


def set_internet_off(scope, off):
    """Switch all internet off or on for one scope. The scope 'all' is the kill switch."""
    with db_lock:
        if off:
            S.off.add(scope)
            db.execute("INSERT OR IGNORE INTO internet_off VALUES(?)", (scope,))
        else:
            S.off.discard(scope)
            db.execute("DELETE FROM internet_off WHERE scope=?", (scope,))
        db.commit()


def delete_group(gid):
    """Delete a group and everything that hangs off it: its members' membership, its
    service blocks, its internet switch and its schedules."""
    scope = "group:%d" % gid
    with db_lock:
        S.group_names.pop(gid, None)
        S.dev_group = {ip: g for ip, g in S.dev_group.items() if g != gid}
        S.svc_blocks.pop(scope, None)
        S.off.discard(scope)
        db.execute("DELETE FROM groups WHERE id=?", (gid,))
        db.execute("DELETE FROM device_group WHERE gid=?", (gid,))
        db.execute("DELETE FROM service_blocks WHERE scope=?", (scope,))
        db.execute("DELETE FROM internet_off WHERE scope=?", (scope,))
        db.execute("DELETE FROM schedules WHERE scope=?", (scope,))
        db.commit()
        load_schedules()


# ------------------------------------------------------------------ dashboard web server

class Web(BaseHTTPRequestHandler):
    """The dashboard's web server: serves the page and the JSON API described in docs/API.md.

    It has no login. What protects it is where it listens (this computer only) and the checks in
    local_only() and do_POST(). Read those before loosening anything here."""
    def log_message(self, *a):
        """Say nothing: the default would print a line for every request."""
        pass

    def end_headers(self):
        # Sent with every answer, including errors:
        #  - the two frame lines stop another website showing this dashboard inside itself and
        #    tricking someone into clicking its buttons (the kill switch, say);
        #  - nosniff stops a browser guessing that a JSON answer is really a web page;
        #  - no-referrer keeps this computer's address out of links followed from the dashboard.
        """Add the protective headers to every answer, then finish the headers as usual."""
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def local_only(self):
        # Only answer when the browser really is talking to this computer by its own name.
        """True if the request is addressed to localhost; otherwise answers 403 and returns False.

        This defeats 'DNS rebinding': a hostile site can make its own name point at 127.0.0.1 so that
        your browser calls this server, but the browser still sends that site's name as Host."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if host in ("localhost", "127.0.0.1"):
            return True
        self.send_error(403)
        return False

    def send_json(self, obj, code=200):
        """Send `obj` as a JSON answer with the given status."""
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Every read: the dashboard page and the GET calls in docs/API.md."""
        if not self.local_only():
            return
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        if url.path == "/":
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif url.path == "/api/status":
            self.send_json(api_status())
        elif url.path == "/api/devices":
            self.send_json(api_devices())
        elif url.path == "/api/activity":
            try:
                hours = min(max(float(qs.get("hours", ["24"])[0]), 0.1), KEEP_DAYS * 24)
            except ValueError:
                hours = 24
            self.send_json(api_activity(qs.get("ip", [""])[0], hours))
        elif url.path == "/api/rules":
            self.send_json(api_rules())
        elif url.path == "/api/services":
            self.send_json([{"id": v["id"], "name": v["name"], "cat": v["cat"]} for v in S.services])
        elif url.path == "/api/groups":
            self.send_json(api_groups())
        elif url.path == "/api/schedules":
            self.send_json(api_schedules())
        elif url.path == "/api/cloud":
            self.send_json(CA.status() if CA else {"configured": False, "paired": False, "state": "off"})
        elif url.path == "/api/enforcer":
            self.send_json(ENF.status() if ENF else {"available": False, "reason": "not started", "active": False})
        elif url.path == "/api/controls":
            scope = qs.get("scope", [""])[0]
            if not SCOPE.fullmatch(scope):
                return self.send_error(400)
            self.send_json(api_controls(scope))
        else:
            self.send_error(404)

    def do_POST(self):
        """Every change. This method only checks the request (host, content type, size, shape);
        handle_post() does the work.

        Requiring 'application/json' is the defence against forged cross-site requests: a web form on
        another site cannot send that type without first asking this server's permission, which it
        never gives. Do not accept form-encoded or plain-text bodies here."""
        # Read the body before anything else, even if the request is about to be refused.
        # Answering and closing while the sender's data is still unread makes some systems
        # reset the connection, and the browser then never sees the answer.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        raw = self.rfile.read(length) if 0 <= length <= MAX_BODY else None
        if not self.local_only():
            return
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self.send_error(415)
        if raw is None:
            return self.send_error(413 if length > MAX_BODY else 400)
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return self.send_error(400)
        if not isinstance(body, dict):
            return self.send_error(400)
        try:
            self.handle_post(urlparse(self.path).path, body)
        except (TypeError, ValueError, AttributeError, KeyError, sqlite3.Error):
            # A value of the wrong kind (a list where a number belongs, say) that a handler did not
            # expect. Nothing has been sent yet at this point, so answer with a clean refusal
            # where the connection would otherwise just drop.
            self.send_error(400)

    def handle_post(self, path, body):

        """Carry out one change. `body` is already known to be a JSON object. Each branch
        checks its own values, makes the change and answers; anything unmatched is a 404."""
        if path in ("/api/block", "/api/unblock", "/api/forget"):
            domain = clean_domain(body.get("domain"))
            if not domain:
                return self.send_json({"error": "That doesn't look like a web address."}, 400)
            {"/api/block": block, "/api/unblock": unblock, "/api/forget": forget}[path](domain)
            return self.send_json({"ok": True, "domain": domain})
        if path == "/api/device-name":
            ip, name = str(body.get("ip", ""))[:64], str(body.get("name", "")).strip()[:40]
            sql("INSERT INTO devices(ip,name) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name",
                (ip, name), commit=True)
            return self.send_json({"ok": True})
        if path in ("/api/service-block", "/api/internet"):
            scope = str(body.get("scope", ""))
            if not SCOPE.fullmatch(scope):
                return self.send_error(400)
            if path == "/api/internet":
                if scope == "all":
                    return self.send_error(400)
                set_internet_off(scope, bool(body.get("off")))
            else:
                if body.get("service") not in S.svc_names:
                    return self.send_error(400)
                set_service_block(scope, body["service"], bool(body.get("on")))
            return self.send_json({"ok": True})
        if path == "/api/cloud":
            if not CA:
                return self.send_json({"error": "Remote access isn't available."}, 400)
            if body.get("action") == "forget":
                CA.forget()
                return self.send_json({"ok": True})
            err = CA.pair(body.get("relay", ""), body.get("code", ""))
            return self.send_json({"error": err}, 400) if err else self.send_json({"ok": True})
        if path == "/api/enforce":
            # This address is written into a firewall rule, so it must be a real IPv4 address and
            # nothing else. (A pattern of digits and dots would let 999.999.999.999 through, which
            # the firewall rejects - and that would stop every other rule loading too.)
            try:
                if not isinstance(body.get("ip"), str):
                    raise ValueError
                ip = str(ipaddress.IPv4Address(body["ip"]))
            except ValueError:
                return self.send_error(400)
            with db_lock:
                if body.get("on"):
                    S.enforced.add(ip)
                    db.execute("INSERT OR IGNORE INTO enforced VALUES(?)", (ip,))
                else:
                    S.enforced.discard(ip)
                    db.execute("DELETE FROM enforced WHERE ip=?", (ip,))
                db.commit()
            return self.send_json({"ok": True})
        if path == "/api/kill":             # the kill switch: stop the internet for every device
            set_internet_off("all", bool(body.get("on")))
            return self.send_json({"ok": True})
        if path == "/api/schedule":
            error = save_schedule(body)
            return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True})
        if path in ("/api/schedule-enable", "/api/schedule-delete"):
            with db_lock:
                if path.endswith("delete"):
                    db.execute("DELETE FROM schedules WHERE id=?", (body.get("id"),))
                else:
                    db.execute("UPDATE schedules SET enabled=? WHERE id=?", (int(bool(body.get("on"))), body.get("id")))
                db.commit()
                load_schedules()
            return self.send_json({"ok": True})
        if path == "/api/group":            # create, or rename when an id is given
            name = str(body.get("name", "")).strip()[:40]
            if not name:
                return self.send_json({"error": "Please give the group a name."}, 400)
            gid = body.get("id")
            with db_lock:
                if gid in S.group_names:
                    db.execute("UPDATE groups SET name=? WHERE id=?", (name, gid))
                else:
                    gid = db.execute("INSERT INTO groups(name) VALUES(?)", (name,)).lastrowid
                db.commit()
                S.group_names[gid] = name
            return self.send_json({"ok": True, "id": gid})
        if path == "/api/group-delete":
            if body.get("id") in S.group_names:
                delete_group(body["id"])
            return self.send_json({"ok": True})
        if path == "/api/device-group":
            ip, gid = str(body.get("ip", ""))[:64], body.get("group")
            with db_lock:
                if gid in S.group_names:
                    S.dev_group[ip] = gid
                    db.execute("INSERT OR REPLACE INTO device_group VALUES(?,?)", (ip, gid))
                else:
                    S.dev_group.pop(ip, None)
                    db.execute("DELETE FROM device_group WHERE ip=?", (ip,))
                db.commit()
            return self.send_json({"ok": True})
        if path == "/api/junk-switch":
            S.junk_on = bool(body.get("on"))
            set_setting("junk_on", "1" if S.junk_on else "0")
            return self.send_json({"ok": True})
        if path == "/api/pause":
            try:
                minutes = float(body.get("minutes", 0))
            except (TypeError, ValueError):
                return self.send_error(400)
            if minutes != minutes:                      # "not a number" compares unequal to itself
                return self.send_error(400)
            minutes = min(max(minutes, 0), 24 * 60)
            S.paused_until = time.time() + minutes * 60 if minutes else 0
            set_setting("paused_until", S.paused_until)
            return self.send_json({"ok": True})
        if path == "/api/scan":
            if S.scan_state != "scanning":
                S.scan_state = "scanning"
                threading.Thread(target=scan_network, daemon=True).start()
            return self.send_json({"ok": True})
        if path == "/api/update-list":
            if S.list_state != "downloading":
                threading.Thread(target=update_community_list, daemon=True).start()
            return self.send_json({"ok": True})
        if path == "/api/clear-history":
            ip = body.get("ip")
            if ip:
                sql("DELETE FROM queries WHERE client=?", (str(ip),), commit=True)
            else:
                sql("DELETE FROM queries", commit=True)
            return self.send_json({"ok": True})
        self.send_error(404)


def _stop_requested(signum, frame):
    """`docker stop` and a system shutdown ask politely with SIGTERM. Treat it like Ctrl-C,
    so the enforcer gets to restore the network before the program exits."""
    raise KeyboardInterrupt


def main():
    """Start everything: database, lists, DNS filter, enforcer, cloud link, then the dashboard,
    which runs until Ctrl-C or a stop request and then shuts the others down cleanly."""
    ap = argparse.ArgumentParser(description="QuietNet home advert and tracker blocker")
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--web-port", type=int, default=8377)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    init_db()
    load_lists()
    S.local_ip = find_local_ip()
    threading.Thread(target=log_writer, daemon=True).start()
    threading.Thread(target=hint_refresher, daemon=True).start()
    start_dns(args.dns_port)

    global ENF
    ENF = enforcer.Enforcer(S.local_ip, enforcement_plan, neighbours)
    ENF.start()
    global CA
    CA = cloud_agent.CloudAgent(args.web_port, DATA)
    CA.start()
    if not ENF.available():
        print("  Live-connection enforcer: off (%s)" % ENF.reason)
    else:
        print("  Live-connection enforcer: ready")

    web = ThreadingHTTPServer(("127.0.0.1", args.web_port), Web)
    url = "http://localhost:%d" % args.web_port
    print("\nQuietNet is running.")
    print("  Dashboard:        %s" % url)
    print("  This computer is: %s  (type this into a device's DNS setting)" % S.local_ip)
    print("\nLeave this window open. Close it to stop QuietNet.\n")
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, (url,)).start()
    signal.signal(signal.SIGTERM, _stop_requested)
    try:
        web.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)     # a second request must not interrupt the clean-up
        if ENF:
            ENF.stop()                                    # waits until the network is restored
        if CA:
            CA.stop()
        print("\nQuietNet stopped.", flush=True)


if __name__ == "__main__":
    main()
