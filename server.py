#!/usr/bin/env python3
"""QuietNet - see what the devices in your home are talking to, and block the junk.

How it works: this program acts as the "phone book" (DNS server) for any device
you point at it. Every time a device wants to reach an address (for example
ads.example.com) it asks QuietNet first. QuietNet writes the request down,
and either passes it on to the real internet phone book or, if the address is
blocked, answers with the address 0.0.0.0 (or :: for an IPv6 address), which
devices treat as "can't be reached".

No extra software is needed - just Python 3.
"""
import os
import signal


class StopRequest:
    """Remembers that the program has been asked to stop, and ends the dashboard's serving loop
    when it has.

    `docker stop` and a system shutdown ask with the signal SIGTERM; Ctrl-C sends SIGINT. Python
    runs the handler for a signal in the main thread, in between two steps of whatever that
    thread was doing at the time. That rules out the two obvious ways of handling one:

    - Raising an exception, which is what Python does for Ctrl-C if left alone. It comes up at
      whatever line the main thread had reached. Inside Python's web server, in the instant it
      takes a new connection, the exception is swallowed and the request to stop is lost; during
      start-up it flies past the clean-up. Both used to happen (known issue 12).
    - Setting a threading.Event. That takes a lock, and the main thread may have been stopped
      while it held that very lock, in which case the handler would wait for it for ever.

    So the handler, note(), raises nothing and takes no lock. It sets a plain flag, `asked`,
    which start_up() reads between its steps, and writes one byte into a pipe. A helper thread
    started by serve() waits for that byte and then stops the web server in the proper way, with
    its shutdown(), which has to be called from a thread other than the one that is serving.

    A request that arrives before serving has begun, when there is no helper thread yet, is not
    lost either: serve() looks at the flag and does not serve at all, and should the request
    come in the instant after that look, its byte is still in the pipe for the helper thread.

    A pipe written by the handler was chosen over Python's signal.set_wakeup_fd() because it
    keeps the whole of this in one class: set_wakeup_fd is a single setting for the whole
    process, reports every signal and not just these two, and still needs a handler.

    The class stands above the file's other imports, and needs nothing but `os` and `signal`
    until serve() is called, so that the program can listen from its first moment: see the
    lines that follow the class."""

    def __init__(self):
        """Not yet asked. Nothing is listened for until listen() is called."""
        self.asked = False
        self._read, self._write = os.pipe()

    def listen(self):
        """From now on, note SIGTERM and Ctrl-C with note(). Call it from the main thread (Python
        lets nothing else set a handler) before starting anything that needs cleaning up.

        If Ctrl-C's signal was already being ignored when the program started, it is left
        ignored: that is how a shell protects a program it has put in the background from a
        Ctrl-C meant for something else."""
        signal.signal(signal.SIGTERM, self.note)
        if signal.getsignal(signal.SIGINT) != signal.SIG_IGN:
            signal.signal(signal.SIGINT, self.note)

    def note(self, signum=None, frame=None):
        """The handler itself: note that a stop has been asked for. See the class for why it
        must raise nothing and take no lock. It does nothing but set the flag and write a byte:
        no print, no log, no call into anything else. Only the first request writes, so the
        pipe can never fill up and make a later write wait."""
        if not self.asked:
            self.asked = True
            try:
                os.write(self._write, b"!")
            except OSError:
                pass                    # nothing useful can be done about it here; the flag is set

    # How often, in seconds, the serving loop looks whether it has been told to finish while no
    # connection arrives (after one, it looks at once). Python's own figure is half a second,
    # which made a stop with the dashboard idle take up to half a second where it had taken a
    # hundredth; a twentieth cannot be noticed, and the looks themselves cost next to nothing.
    LOOK_EVERY = 0.05

    def serve(self, web):
        """Run the web server in this thread until a stop is asked for, then return. If one has
        been asked for already, during start-up, do not serve at all."""
        if self.asked:
            return
        threading.Thread(target=self._shut_when_asked, args=(web,), daemon=True).start()
        web.serve_forever(poll_interval=self.LOOK_EVERY)

    def _shut_when_asked(self, web):
        """The helper thread: wait for the byte that note() writes, then tell the web server to
        finish. Being an ordinary thread, it may take the locks that shutdown() needs. The
        serving loop acts on it at its next look: within LOOK_EVERY seconds, and at once after
        a connection."""
        os.read(self._read, 1)
        web.shutdown()

    def ignore(self):
        """From now on, ignore SIGTERM and Ctrl-C altogether. Called as the clean-up begins:
        someone asking twice must not cut short the enforcer's handing back of the network.

        The signals are ignored outright, and not just left to note(), because a Ctrl-C in a
        terminal goes to every program started from it, and a program started while a signal is
        ignored ignores it too. So the commands the enforcer runs to put the firewall and the
        network settings back are not ended by a second Ctrl-C either."""
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)


# When this file is run as the program, a request to stop is listened for from this line on,
# before the rest of the imports. They take most of the time that passes before QuietNet's own
# start-up can begin (a tenth of a second on a fast computer, far more on a slow one), and for
# as long as nothing of QuietNet's is listening, Python's own handling of the two signals is in
# place. That is harmless in one way, since nothing has been started yet, but not in two others.
# In its container QuietNet is the first process, and Linux drops a signal sent to a first
# process that has not asked for it: a `docker stop` then does nothing at all, QuietNet starts
# up, and Docker kills it 20 seconds later with no clean-up (known issue 12). And Ctrl-C is
# raised as an exception inside whichever import is running, where Python's own library can
# swallow it. run() carries on with this same StopRequest. When the tests import this file,
# nothing is listened for here.
STOP_FROM_THE_TOP = None
if __name__ == "__main__":
    STOP_FROM_THE_TOP = StopRequest()
    STOP_FROM_THE_TOP.listen()

import argparse
import collections
import functools
import hashlib
import ipaddress
import json
import queue
import re
import shutil
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import enforcer
import cloud_agent
import names

# MAP OF THIS FILE (each part starts with a "# ----- name" banner):
#   at the very top      StopRequest, which notes a request to stop. It comes before the imports
#                        so that the program can listen for one while they are still loading
#   settings and State   the values you might tune, and S, everything held in memory
#   database             the SQLite connection, the tables, saved settings, the history writer
#   devices              one device is one hardware address: the device tables, which device has which
#                        address now (S.addr_device), the history filed against it, and the one-off
#                        move of an older household's data into those tables
#   rules                the lists, schedules and decision(): is this name blocked for this device, and why
#   DNS                  reading questions, building answers, asking the real servers, the UDP/TCP listeners
#                        and Workers, the team of background threads that answers lookups
#   helpers              this computer's address, the neighbour table, device names (the work is in
#                        names.py), the network scan, and the api_...() functions that build each
#                        dashboard answer
#   dashboard web server the Web class (every HTTP call); then starting and stopping: start_up(),
#                        clean_up(), run() and main()
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
MAX_HISTORY_ROWS = 2_000_000   # history is also capped by size, so a chatty device can't fill the SD card
MAX_DNS_WAITING = 256          # lookups being answered at once; beyond this new ones are dropped (devices retry)
MAX_DNS_PER_DEVICE = 16        # of those, how many one device may have in hand, so one device can't take them all
MAX_TCP_CLIENTS = 64           # DNS-over-TCP connections open at once
MAX_TCP_PER_DEVICE = 8         # of those, how many one device may hold, so one device can't take them all
MAX_CACHED_ANSWERS = 5000      # answers kept in memory to save a trip to the internet; oldest go first
TCP_DEADLINE = 8               # seconds a TCP client gets to send its whole question
RESOLVED_HOURS = 6             # how long we remember which addresses a name pointed to
MAX_BODY = 64 * 1024   # the largest request body the dashboard API will read; real ones are a few hundred bytes
MAX_TTL = 120   # seconds a device may remember an answer, so new blocks and schedules bite within ~2 minutes
CLOCK = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
VALID_NAME = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")
IGNORED_ENDINGS = (".arpa", ".local", ".lan", ".home", ".internal")
# Names only the home router can answer. They are sent to it, never to the public servers.
HOME_ENDINGS = (".local", ".lan", ".home", ".internal", ".home.arpa")
# Names that devices look up to ask "does this network want me to use its own DNS?". Answering them
# this way keeps those devices' lookups coming to QuietNet (known issue 8):
#  - Firefox switches off its built-in "secure DNS" if this name does not exist.
#  - Apple devices switch off iCloud Private Relay for the network if these names are blocked.
NO_SUCH_NAME_SIGNALS = ("use-application-dns.net",)
BLOCKED_SIGNALS = ("mask.icloud.com", "mask-h2.icloud.com")
# Other DNS services that a phone, a computer or a browser can be set to use instead of QuietNet,
# over an encrypted connection ("secure DNS" in a browser, "Private DNS" on Android). Each name, and
# every name beneath it (NextDNS and others give each customer a name of their own), gets the
# blocked answer for every device the owner controls (see other_dns_blocked_for), whatever the
# rules say, so the device can't reach the service and falls back to ordinary DNS, which comes to
# QuietNet. Other devices are left alone unless the owner switches this on for every device: a
# device set up to use one of these strictly does not fall back, and would lose all names. The
# lookup is kept in the history and shown on the device's page as "tried to use another DNS
# service" (known issue 8).
# To add a service, add its name here.
OTHER_DNS_SERVICES = frozenset((
    "dns.google", "dns.google.com", "8888.google",                                  # Google
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "security.cloudflare-dns.com", "family.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com", "one.one.one.one",                           # Cloudflare
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",        # Quad9
    "doh.opendns.com",                                                              # OpenDNS
    "dns.nextdns.io",                                                               # NextDNS
    "doh.cleanbrowsing.org",                                                        # CleanBrowsing
    "dns.adguard.com", "dns.adguard-dns.com",                                       # AdGuard
    "doh.mullvad.net", "dns.mullvad.net",                                           # Mullvad
    "doh.dns.sb",                                                                   # DNS.SB
    "dns.controld.com", "freedns.controld.com",                                     # Control D
))
MAX_OTHER_DNS_DEVICES = 1024   # devices remembered as having tried another DNS service (see S.other_dns)
ROUTER_RECHECK = 300           # seconds between looks at which router this computer uses
IPV6_RECHECK = 60              # seconds between looks at this computer's IPv6 addresses and its IPv6 neighbours
# A lookup from an IPv6 address no device is matched to yet (a phone makes itself a new one about
# daily) asks for a look straight away, so the gap is seconds, not a minute (see matched_ipv6_device).
V6_QUICK_GAP = 2               # seconds: the least time between two such looks, however many lookups ask
V6_ANSWER_WAIT = 0.4           # seconds: the most one lookup waits for a look that is about to happen
V6_MAX_WAITING = 8             # lookups that may wait like that at once; any more are not held up at all
V6_ASKS_PER_ADDRESS = 3        # looks one unmatched address may set off in each IPV6_RECHECK seconds
V6_MAX_ASKERS = 512            # unmatched addresses whose asks are counted at once
# Listening for the router's IPv6 announcements, to spot it naming its own DNS server (see router_advert_listener).
RA_READ_BYTES = 2048           # the most of one announcement read; real ones are well under 1500
RA_MAX_PER_SECOND = 20         # announcements looked at each second; any more are read and ignored
RA_MAX_SERVERS = 16            # IPv6 DNS servers remembered at once; the router normally names one or two
# Kinds of DNS question that can hand a device IPv6 addresses: AAAA (28), and HTTPS (65) and SVCB (64),
# which may carry IPv6 hints. Devices with "Cut live connections" on get no records for these (answer_query).
NO_IPV6_TYPES = (28, 64, 65)
RA_HOLD_MAX = 3600             # seconds a named server is remembered without being named again
MAX_CACHED_SIZE = 4096         # bytes; a bigger answer is never remembered (it would tie up memory)
# Record types a device that checks DNS signatures itself asks about a bare top-level name such as
# 'com' (NS, SOA, DS, RRSIG, NSEC, DNSKEY, NSEC3). These go to the internet, not the home router.
SIGNATURE_TYPES = (2, 6, 43, 46, 47, 48, 50)
# IPv6 addresses that can only come from the home network: this computer, link-local, unique-local.
HOME_ONLY_V6 = [ipaddress.IPv6Network(n) for n in ("::1/128", "fe80::/10", "fc00::/7")]
# The system's own tool for listing network neighbours. Look in the usual places
# because the program isn't always started with those folders on its search path.
ARP = next((p for p in ("/usr/sbin/arp", "/sbin/arp", "/usr/bin/arp") if os.path.exists(p)), "arp")
# The same for IPv6 neighbours: `ip` on Linux, `ndp` on a Mac. And `ifconfig`, for a Mac's own addresses.
IP_TOOL = next((p for p in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip") if os.path.exists(p)), "ip")
NDP = next((p for p in ("/usr/sbin/ndp", "/sbin/ndp") if os.path.exists(p)), "ndp")
IFCONFIG = next((p for p in ("/sbin/ifconfig", "/usr/sbin/ifconfig") if os.path.exists(p)), "ifconfig")
SCOPE = re.compile(r"all|device:[0-9a-f.:]{3,45}|group:\d+")
# One device is one hardware address (see the "devices" part of this file). These say how the
# record of which device has which address is kept, and how history is filed against the device.
# Nothing compares the saved version or the time of the move on a later start yet: the warning and
# the offer to move the data again that the design asks for when an older QuietNet has been run on
# a moved database (4.7 step 7) belong with the move of rules to the device, and are listed as
# open in KNOWN_ISSUES 97.
DEVICES_VERSION = 1            # the shape of the device tables, saved with the data when it is moved over
BEFORE_DEVICES = "quietnet.db.before-devices"   # the copy of the database kept from just before that move
NO_DEVICE = 0                  # filed against no device at all (no real device ever has this number)
ADDRESS_LOOK = 5               # seconds between looks at the neighbour table that keep S.addr_device right
ADDRESS_GRACE = 90             # seconds: a lookup made this long before a device was first confirmed at an
                               # address still counts as that device's (it had to join before it was seen)
ADDRESS_WAIT = 180             # seconds a lookup no device could be matched to waits for one, before it
                               # is filed under the address itself
TIDY_EVERY = 60                # seconds between passes that file waiting lookups against their device
TIDY_BATCH = 500               # lookups filed per step of that pass
FILL_BATCH = 2000              # rows of older history given their device per step, after the move
FILL_PAUSE = 0.05              # seconds between those steps, so everything else gets a turn at the database
FILL_SETTLE = 10               # seconds after the move before that work may call itself finished: the history
                               # writer holds each lookup for a second before saving it, so one made just
                               # before the move is saved just after it, and must still be given its device
ADDRESS_RECENT = 86400         # seconds: an address a device used this recently is listed with it
MAX_DEVICES = 5000             # the most devices remembered; the longest unseen are forgotten first
MAX_ADDRESS_USE = 20000        # the most "who used which address" rows kept
MAX_LISTED_ADDRESSES = 32      # the most addresses listed with one device in GET /api/devices

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
    "samsungcloudsolution.net": "Samsung TV", "samsungqbe.com": "Samsung TV",
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

# Names that a device's own system depends on: its sign-in, app shop, "am I online?" check, clock
# or updates. Blocking the WHOLE name is known to break those, so the dashboard never labels such a
# name "Possibly junk", says who needs it instead, and the block call asks first (see needed_by and
# Web.handle_post). Each value is who needs the name, as a plural that fits "... need this address".
#
# Keep this list short and sure. A wrong entry costs only a needless question, but a long or sloppy
# list teaches people to ignore the question. Rules for an entry:
#  - a whole owner name, exactly as the activity list groups it (see base_of), never a sub-name;
#  - a common household device needs it for its own system, not for one app or one streaming service;
#  - not a name that is mainly adverts or tracking. Those belong on the advert list.
# This table changes labels and adds a question. It never changes what decision() blocks.
NEEDED = {
    # Samsung TVs: the app system ("Smart Hub") and its clock; the TV's online check, first set-up
    # and app shop (several owners report each failing with samsungqbe.com blocked); Samsung
    # account sign-in.
    "samsungcloudsolution.com": "Samsung TVs", "samsungcloudsolution.net": "Samsung TVs",
    "samsungqbe.com": "Samsung TVs", "samsungosp.com": "Samsung TVs and phones",
    # LG TVs: the TV's service platform and clock; the app shop ("Content Store"); the TV's system
    # updates and the app shop's downloads (blocking the whole of lge.com is reported to stop the
    # Content Store; blocking one sub-name such as snu.lge.com, to hold back updates, does not ask).
    "lgtvsdp.com": "LG TVs", "lgappstv.com": "LG TVs", "lge.com": "LG TVs",
    # Apple: sign-in, the online check, clock, activation and updates; iCloud sign-in;
    # the App Store's pages; update downloads.
    "apple.com": "Apple devices", "icloud.com": "Apple devices", "mzstatic.com": "Apple devices",
    "cdn-apple.com": "Apple devices",
    # Android, Chromecast and Google TV: sign-in, the Play shop and the online check; a second
    # online check; sign-in and Play services; the clock; app and update downloads.
    "google.com": "Android and Google devices", "gstatic.com": "Android and Google devices",
    "googleapis.com": "Android and Google devices", "android.com": "Android and Google devices",
    "gvt1.com": "Android and Google devices",
    # Amazon: sign-in, registration and updates for Fire TV and Echo; the Fire online check.
    "amazon.com": "Amazon Fire TVs and Echo speakers", "fireoscaptiveportal.com": "Amazon Fire TVs and tablets",
    # Roku: sign-in, the channel shop and updates all sit under this one name.
    "roku.com": "Roku players and TVs",
    # Windows: the two online checks; updates; the clock; updates and the Store; Microsoft sign-in.
    "msftconnecttest.com": "Windows computers", "msftncsi.com": "Windows computers",
    "windowsupdate.com": "Windows computers", "windows.com": "Windows computers",
    "microsoft.com": "Windows computers and Xbox consoles", "live.com": "Windows computers and Xbox consoles",
    # PlayStation: sign-in, the online check and updates; the PlayStation Store; account sign-in.
    "playstation.net": "PlayStation consoles", "playstation.com": "PlayStation consoles",
    "sonyentertainmentnetwork.com": "PlayStation consoles",
    # Xbox: sign-in and the console's own services.
    "xboxlive.com": "Xbox consoles",
    # Nintendo Switch: the online check, the eShop and updates; Nintendo Account sign-in.
    "nintendo.net": "Nintendo Switch consoles", "nintendo.com": "Nintendo Switch consoles",
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
    junk_count = 0          # names on both advert lists together, worked out when either list changes
    junk_on = True
    paused_until = 0.0
    dns_error = None
    dns_port = 53
    dns_ipv6 = False        # also listening for lookups over IPv6?
    local_ip = "127.0.0.1"
    list_state = "idle"     # idle | downloading | error
    list_error = ""
    hints = {}              # ip -> {"name", "source", "detail"}: the name suggested for it (see names.py)
    services = []           # the catalogue from services.json
    svc_names = {}          # service id -> friendly name
    dom2svc = {}            # address -> service id
    svc_blocks = {}         # scope -> set of blocked service ids
    off = set()             # scopes whose internet is switched off
    enforced = set()        # device ips we actively enforce (cut live connections for)
    enforced_mac = {}       # device ip -> its hardware address when enforcing was switched on ('' = not yet known)
    resolved = {}           # domain -> {ip: last-seen} : the addresses we've handed out
    dev_group = {}          # device ip -> group id
    group_names = {}        # group id -> name
    schedules = []          # timed rules, e.g. bedtime (see load_schedules)
    sched_cache = (0.0, [])  # (when worked out, schedules in force at that moment)
    scan_state = "idle"     # idle | scanning
    scan_ts = 0.0
    scan_info = {}          # what the last scan covered: {"network", "addresses", "capped"}
    rules_version = 0       # goes up whenever a rule changes; the enforcer's plan cache watches it
    plan_cache = {}         # see enforcement_plan
    shared_left = {}        # enforced device ip -> {"count", "names"}: addresses left to the name block (see enforcement_plan)
    router = ""           # the home router's address, for home-network names ('' = not known)
    router_checked = None   # when (time.monotonic()) the router's address was last looked up
    v6_own = set()          # this computer's own IPv6 addresses (see refresh_ipv6_view)
    v6_prefixes = []        # the home network's public IPv6 ranges, from this computer's own addresses
    v6_devices = {}         # a device's IPv6 address -> its IPv4 address, matched by hardware address
    v6_shared = frozenset()  # IPv6 addresses behind a range extender (S.shared_macs): each keeps its own share of lookups
    v6_dns = ""             # the IPv6 address to give devices as their DNS server ('' = none suitable)
    v6_neighbours_ok = None  # could the IPv6 neighbour table be read at the last look? (None = not looked yet)
    v6_checked = None       # when (time.monotonic()) the IPv6 view was last worked out without a fault
    v6_can_hear = None      # does this computer's home network card have working IPv6 (can_hear_router)? None = not known
    v6_hear_since = None    # when (time.monotonic()) a look first found that it does; None while it doesn't
    v6_looked_at = None     # when (time.monotonic()) ipv6_watcher last finished a look, good or bad
    v6_round = 0            # how many looks ipv6_watcher has finished (a waiting lookup watches this change)
    v6_watching = False     # is ipv6_watcher running?
    v6_looking = False      # is ipv6_watcher in the middle of a look right now?
    ra_listening = False    # is router_advert_listener hearing the router's IPv6 announcements?
    ra_heard = None         # when (time.time()) the router last announced IPv6 on the home network
    ra_heard_at = None      # the same moment by time.monotonic(), which a change of the clock can't move
    ra_since = None         # when (time.monotonic()) router_advert_listener began listening (None = it isn't)
    routers_v6 = {}         # real routers heard announcing: link-local address -> {"mac", "heard" (time.time())}
    router_v6_dns = {}      # IPv6 DNS servers the router names -> when to forget each (time.time())
    other_dns = {}          # device address -> when (time.time()) it last looked up another DNS service
    dev_mac = {}            # device ip with rules or a name -> the hardware address those belong to (see refresh_devices)
    paused_ips = set()      # device ips whose own rules are paused: a different device has that address now
    device_warnings = {}    # device ip -> a plain-English warning for its page (rules that could not be moved)
    device_notices = []     # possible moves for the owner to confirm: see device_notices_now
    new_device_group = None  # group id that a device seen for the first time is put in (None = no group)
    guest_group = {}        # paused device ip -> (hardware address, group id) of a new device there now (see refresh_devices)
    follow = {}             # device ip -> the ip its own rules are kept under, while they can't be moved there
    shared_macs = set()     # hardware addresses seen at several addresses at once: range extenders, not devices
    other_dns_all = False   # block other DNS services for every device, not just those with rules?
    no_ipv6_all = False     # give no device IPv6 addresses in answers? (the optional whole-house switch)
    router_prefixes = {}    # IPv6 ranges announced by a real router -> when to forget each (time.time())
    # One device is one hardware address: see the "devices" part of this file.
    devices_ready = False   # are the device tables in use? False for an older database not moved over yet
    devices_state = "old"   # "ready", "moving", "waiting" (too little free space), "failed", or "old" (not tried yet)
    devices_notice = ""     # what to tell the owner about that move ('' = nothing)
    devices_moved_at = 0.0  # when (time.time()) the device tables were made: older history gets its device from the move
    moved_steady = None     # when (time.monotonic()) this run of QuietNet finished the move; None if it did not
    copy_unwanted = False   # was everyone's history forgotten while the move was making its copy? (forget_old_copy)
    history_fill = False    # is older history still being given its device (fill_old_history)?
    history_filed = 0       # goes up whenever waiting or older history is filed against devices (see activity_marker)
    addr_device = {}        # address, IPv4 or IPv6 -> device number, for addresses confirmed at the last look
    map4 = {}               # the IPv4 half of addr_device, from the last look at the neighbour table
    map6 = {}               # the IPv6 half, from the last look at the IPv6 neighbours
    addr_use = {}           # address -> [device, first, last, row number, last as saved]: who used it most recently
    hw_device = {}          # hardware address -> device number
    addr_only = {}          # address -> the number of the device known only by that address
    device_kind = {}        # device number -> "hw", "addr", "pi" (this computer) or "hub" (the home router)
    pi_device = None        # the number of the fixed device that is this computer
    hub_device = None       # the number of the fixed device that is the home router
    hub_mac = ""            # the home router's hardware address, as last seen at its IPv4 address
    hw_unsettled = frozenset()  # hardware addresses found at two live IPv4 addresses at the last look
    v6_table = {}           # the IPv6 neighbour table as last read by refresh_ipv6_view
    device_seen = {}        # device number -> when it was last seen, waiting to be saved (save_address_use)
    hw_seen = {}            # hardware address -> the same


S = State()
ENF = None
CA = None
BROWSER = None      # the timer that opens the dashboard in a browser just after start-up, if one was set
db = None
db_lock = threading.RLock()
# A second, read-only connection for the dashboard's questions about the history, with its own
# lock. The write-ahead log lets it read while the main connection writes, so a slow history
# question never holds up the history writer, a rule change or another dashboard call waiting
# for db_lock. One connection is used by one thread at a time, hence the lock.
read_db = None
read_lock = threading.Lock()
# S.resolved has a small lock of its own, not db_lock: every allowed lookup records its addresses
# there before the answer goes back, and it must never wait behind a slow database query.
resolved_lock = threading.Lock()
log_q = queue.Queue()
# Answers from the internet kept for their (shortened) lifetime, so a name asked for again soon is
# answered here without a round trip. (name, record type, class) -> (expires, stored, reply bytes),
# both times from time.monotonic(). Oldest first, so the oldest is the one dropped when full.
# It has its own small lock, for the same reason as resolved_lock.
answer_cache = collections.OrderedDict()
answer_cache_lock = threading.Lock()
# Questions QuietNet is waiting on the home router for, as (name, record type) -> how many. Used to
# spot a router that sends lookups back here, so the two can't ask each other for ever.
router_waiting = {}
router_waiting_lock = threading.Lock()
# Guards S.router_v6_dns, S.ra_heard, S.ra_heard_at, S.router_prefixes and S.routers_v6, written by
# router_advert_listener and read by the dashboard.
router_dns_lock = threading.Lock()
# The quick look at the IPv6 neighbours (see matched_ipv6_device and ipv6_watcher). v6_wanted is set
# by a lookup from an unmatched IPv6 address to wake the watcher; v6_looked is told each time a look
# finishes; v6_waiting caps how many lookups wait for one; v6_askers counts each address's asks as
# address -> [asks, when the count began (time.monotonic())].
v6_wanted = threading.Event()
v6_looked = threading.Condition()
v6_waiting = threading.BoundedSemaphore(V6_MAX_WAITING)
v6_askers = {}
v6_askers_lock = threading.Lock()
# The thread clearing one device's history, started by the last POST /api/clear-history that named
# a device (None before any). Kept so the tests can wait for it to finish.
last_clear = None


def rules_changed():
    """Note that a rule has changed, so the enforcer's remembered plan is worked out afresh, and
    forget every remembered answer. (Blocking is decided afresh for every lookup before the
    remembered answers are looked at, so this is a precaution, not what makes a block bite.)"""
    S.rules_version += 1
    with answer_cache_lock:
        answer_cache.clear()


# ------------------------------------------------------------------ database

def sql(statement, args=(), commit=False):
    """Run one SQL statement and return all its rows. Holds db_lock, since one connection is
    shared by every thread. Pass commit=True for a change that should be saved at once."""
    with db_lock:
        rows = db.execute(statement, args).fetchall()
        if commit:
            db.commit()
        return rows


def read_sql(statement, args=()):
    """Run one question about the history on the read-only connection and return all its rows.
    Holds read_lock, never db_lock. It sees everything the main connection has saved (committed)."""
    with read_lock:
        return read_db.execute(statement, args).fetchall()


def open_read_db():
    """Open (or reopen) the read-only connection used by read_sql. 'query_only' makes the
    database itself refuse any change sent through it."""
    global read_db
    with read_lock:
        if read_db is not None:
            read_db.close()
        read_db = sqlite3.connect(os.path.join(DATA, "quietnet.db"), check_same_thread=False)
        read_db.execute("PRAGMA query_only=1")


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
    # A database with no history table is a new household's: it gets the device tables straight away
    # (see the "devices" part of this file). One that has a history table but no device tables is an
    # older household's. Its device tables are NOT made here, because this runs before the filter
    # is answering and they can take a while; move_to_devices moves it over afterwards, and until
    # then (or if that fails) everything works on the old tables as before.
    new_household = not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='queries'").fetchone()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY, ts REAL, client TEXT, domain TEXT, blocked INTEGER,
            device INTEGER);
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
        -- Which device (hardware address) the rules and name kept under an address belong to, and
        -- whether they are paused because a different device has that address now. See refresh_devices.
        CREATE TABLE IF NOT EXISTS device_mac(ip TEXT PRIMARY KEY, mac TEXT, paused INTEGER DEFAULT 0);
        -- Every hardware address ever seen on the network: where and when it was first and last seen.
        CREATE TABLE IF NOT EXISTS known_macs(mac TEXT PRIMARY KEY, ip TEXT, first REAL, last REAL);
        CREATE INDEX IF NOT EXISTS known_macs_last ON known_macs(last);
        -- Hardware addresses seen at two or more addresses at the same moment, and how many times:
        -- a Wi-Fi range extender that shows every device behind it with its own hardware address.
        CREATE TABLE IF NOT EXISTS shared_macs(mac TEXT PRIMARY KEY, hits INTEGER, last REAL);
        -- Plain-English notes of what QuietNet did by itself to a device's rules, newest last.
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, ip TEXT, text TEXT);
    """)
    db.commit()
    S.blocked = {r[0] for r in sql("SELECT domain FROM blocked")}
    S.allowed = {r[0] for r in sql("SELECT domain FROM allowed")}
    S.group_names = dict(sql("SELECT id, name FROM groups"))
    S.dev_group = dict(sql("SELECT ip, gid FROM device_group"))
    S.off = {r[0] for r in sql("SELECT scope FROM internet_off")}
    try:
        db.execute("ALTER TABLE enforced ADD COLUMN mac TEXT")    # added after 0.5; older databases lack it
        db.commit()
    except sqlite3.OperationalError:
        pass                                                       # already there
    S.enforced_mac = {ip: mac or "" for ip, mac in sql("SELECT ip, mac FROM enforced")}
    S.enforced = set(S.enforced_mac)
    for column in ("guest_mac TEXT", "guest_gid INTEGER"):     # added later; older databases lack them
        try:
            db.execute("ALTER TABLE device_mac ADD COLUMN " + column)
            db.commit()
        except sqlite3.OperationalError:
            pass                                                   # already there
    S.dev_mac, S.paused_ips, S.guest_group, S.follow = {}, set(), {}, {}
    for ip, mac, paused, guest_mac, guest_gid in sql("SELECT ip, mac, paused, guest_mac, guest_gid FROM device_mac"):
        S.dev_mac[ip] = mac
        if paused:
            S.paused_ips.add(ip)
            if guest_mac and guest_gid in S.group_names:
                S.guest_group[ip] = (guest_mac, guest_gid)
    S.shared_macs = {mac for (mac,) in sql("SELECT mac FROM shared_macs WHERE hits>=?", (SHARED_AFTER,))}
    S.other_dns_all = get_setting("other_dns_all", "0") == "1"
    S.no_ipv6_all = get_setting("no_ipv6_all", "0") == "1"
    if not sql("SELECT 1 FROM known_macs LIMIT 1"):
        # First start with this table: every device a scan has already found counts as known, so
        # none of them is mistaken for a new device and put in the new-device group.
        for ip, mac, ts in sql("SELECT ip, mac, ts FROM seen"):
            if clean_mac(mac):
                db.execute("INSERT OR IGNORE INTO known_macs VALUES(?,?,?,?)", (clean_mac(mac), ip, ts, ts))
        db.commit()
    gid = get_setting("new_device_group", "")
    S.new_device_group = int(gid) if gid.isdigit() and int(gid) in S.group_names else None
    S.device_warnings, S.device_notices = {}, []
    S.svc_blocks = {}
    for scope, service in sql("SELECT scope, service FROM service_blocks"):
        S.svc_blocks.setdefault(scope, set()).add(service)
    load_schedules()
    S.junk_on = get_setting("junk_on", "1") == "1"
    S.paused_until = float(get_setting("paused_until", "0"))
    if new_household:
        make_device_tables()
        db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('devices_version', ?)", (str(DEVICES_VERSION),))
        db.commit()
    S.devices_state, S.devices_notice = "old", ""
    S.moved_steady, S.copy_unwanted = None, False
    load_devices()
    open_read_db()                  # after the tables exist, so it never sees a half-made database
    rules_changed()


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
    This thread gathers a second's worth and saves them in one go (save_history), each against the
    device that made it where that is known. Every ten minutes it also trims the history (see
    prune_history)."""
    last_prune = 0
    while True:
        batch = [log_q.get()]
        time.sleep(1)
        while not log_q.empty():
            batch.append(log_q.get_nowait())
        try:
            with db_lock:
                save_history(batch)
            if time.time() - last_prune > 600:
                prune_history()
                last_prune = time.time()
        except sqlite3.Error as e:
            print("Could not save history:", e)


def history_row(item):
    """One recorded lookup from log_q, ready to save: (time, address it was judged under, name,
    blocked, device number or None). The item carries the device if the map knew it when the lookup
    was made (note_lookup); if it did not, the map is tried once more here, a second or so later,
    by which time a look at the neighbours has often confirmed who has that address. A lookup still
    without a device is saved without one, and tidy_history files it within a few minutes."""
    ts, client, name, blocked = item[:4]
    device = item[4] if len(item) > 4 else None
    if device is None:
        device = device_of_lookup(item[5] if len(item) > 5 else None, client)
    return ts, client, name, blocked, device


def save_history(batch):
    """Save a batch of recorded lookups. With the device tables in use each row carries its device;
    on an older database not moved over yet (S.devices_ready is False) rows are saved as they
    always were. Call holding db_lock; this commits."""
    if S.devices_ready:
        db.executemany("INSERT INTO queries(ts,client,domain,blocked,device) VALUES(?,?,?,?,?)",
                       [history_row(item) for item in batch])
    else:
        db.executemany("INSERT INTO queries(ts,client,domain,blocked) VALUES(?,?,?,?)",
                       [tuple(item[:4]) for item in batch])
    db.commit()


PRUNE_BATCH = 5000      # rows deleted per step when trimming history
# One step of the trim each: rows older than a time (found through q_ts), and rows at or below a
# row number (found by row number). See prune_history.
PRUNE_OLD_SQL = "DELETE FROM queries WHERE id IN (SELECT id FROM queries WHERE ts<? LIMIT ?)"
PRUNE_SURPLUS_SQL = "DELETE FROM queries WHERE id IN (SELECT id FROM queries WHERE id<=? ORDER BY id LIMIT ?)"


def prune_history():
    """Delete history older than KEEP_DAYS, and the oldest rows beyond MAX_HISTORY_ROWS - so one
    device making endless made-up lookups can't fill the SD card.

    Deletes PRUNE_BATCH rows at a time, letting go of db_lock between steps. The first trim after
    an upgrade can mean millions of rows; done in one go on an SD card, that would hold the lock
    for many seconds, and the dashboard and the history writer would wait. Call it without
    holding db_lock.

    The two limits are asked separately so each question is answered from an index: old rows
    through q_ts, surplus rows by their row number. Asked together (with OR) the database would
    read the whole table every time, even when nothing is due."""
    cutoff_ts = time.time() - KEEP_DAYS * 86400
    for statement, limit in ((PRUNE_OLD_SQL, lambda: cutoff_ts), (PRUNE_SURPLUS_SQL, oldest_to_drop)):
        while True:
            with db_lock:
                n = db.execute(statement, (limit(), PRUNE_BATCH)).rowcount
                db.commit()
            if n < PRUNE_BATCH:
                break
            time.sleep(0.05)                 # give the dashboard and the history writer a turn at the lock


# One step of clearing a device's history: up to a number of its rows at or below a row number,
# found through q_client_ts.
CLEAR_DEVICE_SQL = ("DELETE FROM queries WHERE id IN "
                    "(SELECT id FROM queries WHERE client=? AND id<=? LIMIT ?)")


# The same for a device's history by its number, found through q_device_ts, and for lookups from
# one address that are still waiting to be filed against a device.
CLEAR_BY_NUMBER_SQL = ("DELETE FROM queries WHERE id IN "
                       "(SELECT id FROM queries WHERE device=? AND id<=? LIMIT ?)")
CLEAR_UNFILED_SQL = ("DELETE FROM queries WHERE id IN "
                     "(SELECT id FROM queries INDEXED BY q_client_ts WHERE client=? AND device IS NULL AND id<=? LIMIT ?)")


def clear_history(ip=None, device=None):
    """Delete one device's history, or everyone's when neither `ip` nor `device` is given.

    `device` is a device number: everything filed against that device goes, at whatever address it
    was made, and so do the lookups from the addresses it has now that are still waiting to be
    filed (the dashboard shows those as its own). `ip` alone deletes what was recorded under that
    address, as it always did.

    Everyone's is one statement, which the database does quickly by emptying the table. The copy
    of the database kept from before the move to the device tables holds the household's history
    from that time, so it is deleted with it (forget_old_copy). One device's history does not
    touch that copy: its older lookups stay in the copy until the copy is KEEP_DAYS old. One
    device's is deleted PRUNE_BATCH rows at a time, letting go of db_lock between steps as
    prune_history does, so clearing a busy device's month of history does not hold up the history
    writer or other dashboard calls. Only rows already there when the clear began are deleted.
    Call it without holding db_lock."""
    if device is not None:
        steps = [(CLEAR_BY_NUMBER_SQL, device)] + [(CLEAR_UNFILED_SQL, addr) for addr in device_addresses(device)]
    elif ip:
        steps = [(CLEAR_DEVICE_SQL, str(ip))]
    else:
        sql("DELETE FROM queries", commit=True)
        forget_old_copy(at_once=True)
        return
    top = sql("SELECT MAX(id) FROM queries")[0][0] or 0
    for statement, whose in steps:
        while True:
            with db_lock:
                n = db.execute(statement, (whose, top, PRUNE_BATCH)).rowcount
                db.commit()
            if n < PRUNE_BATCH:
                break
            time.sleep(0.05)                 # give the history writer and the dashboard a turn at the lock


def oldest_to_drop():
    """The row number at and below which history is over MAX_HISTORY_ROWS and should go.
    Each new row gets a higher row number than any row already there, so the newest
    MAX_HISTORY_ROWS rows are the ones above it."""
    top = sql("SELECT MAX(id) FROM queries")[0][0] or 0
    return top - MAX_HISTORY_ROWS


# ------------------------------------------------------------------ devices

# One device is one hardware address, where one is known and it isn't shared. An IPv4 or IPv6
# address is something a device uses for a while, not who it is: a TV can move from .65 to .67, a
# phone holds several IPv6 addresses and makes a new one about daily, and an address a device
# gave up can be handed to another.
#
#   device        one row per device. kind: "hw" (known by its hardware address), "addr" (known
#                 only by a network address: no hardware address is known for it, or it sits behind a
#                 Wi-Fi range extender that shows several devices under one hardware address), "pi"
#                 (this computer) or "hub" (the home router). Numbers are never used twice.
#   device_hw     which hardware address belongs to which device.
#   address_use   a dated record of which device used which address. When an address turns up with
#                 another device a new row is opened, and the old one is no longer added to. It is
#                 for the history and for showing the owner. It never decides whose rules apply.
#   moved_address for a household moved over from an older version: which device each address in
#                 its old history was given to, and whether that rests on certain evidence.
#   queries.device  the device each lookup belonged to WHEN IT WAS MADE, so a device keeps its
#                 history across every address it has had, and an address handed to another device
#                 does not hand over the history with it.
#
# In memory, S.addr_device says which device has each address now. It is kept by looking at the
# neighbour tables (note_ipv4_addresses every ADDRESS_LOOK seconds, note_ipv6_addresses after each
# look at the IPv6 neighbours), so a lookup finds its device with one dictionary lookup and never
# touches the database. The safeguards that keep the wrong device out of it are in those two.
#
# Rules, names and groups are still kept under IPv4 addresses (see refresh_devices); only the
# history is filed against the device so far.
DEVICE_TABLES_SQL = (
    "CREATE TABLE IF NOT EXISTS device(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, key TEXT UNIQUE, "
    "name TEXT, first REAL, last REAL)",
    "CREATE TABLE IF NOT EXISTS device_hw(mac TEXT PRIMARY KEY, device INTEGER, first REAL, last REAL)",
    "CREATE TABLE IF NOT EXISTS address_use(addr TEXT, device INTEGER, first REAL, last REAL)",
    "CREATE INDEX IF NOT EXISTS address_use_device ON address_use(device, last)",
    "CREATE INDEX IF NOT EXISTS address_use_addr ON address_use(addr, first)",
    "CREATE TABLE IF NOT EXISTS moved_address(addr TEXT PRIMARY KEY, device INTEGER, certain INTEGER)",
    # "What did THIS device look up?", whatever address it had. It carries `blocked` too, so each
    # device's count for today is answered from the index alone.
    "CREATE INDEX IF NOT EXISTS q_device_ts ON queries(device, ts, blocked)",
)


def devices_made():
    """Does this database have the device tables? They are made in one step with everything else
    the move does (move_to_devices), so if the table is there, the whole move was done."""
    return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device'").fetchone())


def make_device_tables():
    """Make the device tables, and give the history its `device` column and index if it lacks them.
    Quick on an empty database; on a big history the index takes a while to build, which is why an
    older household's database gets this from move_to_devices, after the filter is answering, and
    not from init_db. Call holding db_lock; the caller commits (or rolls back)."""
    if "device" not in {row[1] for row in db.execute("PRAGMA table_info(queries)")}:
        db.execute("ALTER TABLE queries ADD COLUMN device INTEGER")
    for statement in DEVICE_TABLES_SQL:
        db.execute(statement)


def load_devices():
    """Load the device tables into S, and make sure the two fixed devices exist: this computer
    ("pi") and the home router ("hub"). On an older database that has no device tables yet,
    S.devices_ready is left False and everything carries on as it did before them. Called at
    start-up and when the move finishes."""
    with db_lock:
        S.addr_device, S.map4, S.map6, S.addr_use = {}, {}, {}, {}
        S.hw_device, S.addr_only, S.device_kind = {}, {}, {}
        S.hw_unsettled, S.device_seen, S.hw_seen = frozenset(), {}, {}
        S.pi_device, S.hub_device, S.hub_mac = None, None, ""
        S.history_fill = False
        S.devices_ready = devices_made()
        if not S.devices_ready:
            return
        load_device_rows()
        if db.in_transaction:
            db.commit()
        S.devices_moved_at = float(get_setting("devices_moved_at", "0") or 0)
        S.history_fill = get_setting("devices_fill", "") == "pending"
        S.devices_state, S.devices_notice = "ready", ""
        rebuild_address_map()


def load_device_rows():
    """Read the device tables into S.device_kind, S.addr_only, S.hw_device, S.hub_mac and
    S.addr_use (the newest row for each address), making the two fixed devices if they are
    missing. Call holding db_lock; the caller commits."""
    now = time.time()
    kinds, only, hw, use = {}, {}, {}, {}
    for number, kind, key in db.execute("SELECT id, kind, key FROM device"):
        kinds[number] = kind
        if kind == "addr":
            only[key[5:]] = number
    S.device_kind, S.addr_only = kinds, only
    S.pi_device = new_device("pi", "pi", now)
    S.hub_device = new_device("hub", "hub", now)
    hub_mac = ""
    for mac, number in db.execute("SELECT mac, device FROM device_hw"):
        hw[mac] = number
        if number == S.hub_device:
            hub_mac = mac
    for row, addr, number, first, last in db.execute(
            "SELECT rowid, addr, device, first, last FROM address_use ORDER BY first, rowid"):
        use[addr] = [number, first, last, row, last]
    S.hw_device, S.hub_mac, S.addr_use = hw, hub_mac, use


def new_device(kind, key, now):
    """The number of the device with this key ('hw:<hardware address>', 'addr:<address>', 'pi' or
    'hub'), making it if it is not there. None when a new one can't be made because twice
    MAX_DEVICES are remembered already (forget_old_devices trims them each hour), so a device
    making up hardware addresses can't fill the SD card. Call holding db_lock; the caller commits."""
    row = db.execute("SELECT id FROM device WHERE key=?", (key,)).fetchone()
    if row:
        return row[0]
    if kind in ("hw", "addr") and len(S.device_kind) >= 2 * MAX_DEVICES:
        return None
    number = db.execute("INSERT INTO device(kind, key, name, first, last) VALUES(?,?,?,?,?)",
                        (kind, key, "", now, now)).lastrowid
    S.device_kind[number] = kind
    return number


def device_of_hw(mac, now):
    """The number of the device with this hardware address, making it the first time the address
    is seen (None if no more can be made: see new_device). A new hardware address is always a new
    device: nothing is ever merged automatically, however alike two devices look. Call holding
    db_lock; the caller commits."""
    number = S.hw_device.get(mac)
    if number is None:
        number = new_device("hw", "hw:" + mac, now)
        if number is not None:
            db.execute("INSERT OR REPLACE INTO device_hw(mac, device, first, last) VALUES(?,?,?,?)",
                       (mac, number, now, now))
            S.hw_device[mac] = number
    return number


def device_of_address(addr, now):
    """The number of the device known only by this network address, making it if need be (None if
    no more can be made). Used where no hardware address tells devices apart: an address behind a
    Wi-Fi range extender, or one no hardware address was ever seen for. Call holding db_lock; the
    caller commits."""
    number = S.addr_only.get(addr)
    if number is None:
        number = new_device("addr", "addr:" + addr, now)
        if number is not None:
            S.addr_only[addr] = number
    return number


def set_hub_mac(mac, now):
    """Note the home router's hardware address: the one seen at the router's own IPv4 address. It
    belongs to the fixed "hub" device and to no other, so if it was listed as an ordinary device
    before (the router was not known then) it is taken from that one, and a hardware address the
    router had before is let go. Call holding db_lock; the caller commits."""
    db.execute("DELETE FROM device_hw WHERE device=? OR mac=?", (S.hub_device, mac))
    for old in [m for m, number in S.hw_device.items() if number == S.hub_device]:
        del S.hw_device[old]
    db.execute("INSERT INTO device_hw(mac, device, first, last) VALUES(?,?,?,?)", (mac, S.hub_device, now, now))
    S.hw_device[mac] = S.hub_device
    S.hub_mac = mac


def use_address(addr, device, now, confirmed=True):
    """Record that this device has this address now. If it is the device that had it most recently
    its row just runs on (`last` moves forward when the device was confirmed there just now; the
    database is caught up each minute by save_address_use). If another device had it, that row is
    finished with and a new one opens: who used an address, and when, is kept, never overwritten.
    At most MAX_ADDRESS_USE addresses are followed. Call holding db_lock; the caller commits."""
    use = S.addr_use.get(addr)
    if use and use[0] == device:
        if confirmed and now > use[2]:
            use[2] = now
        return
    if use is None and len(S.addr_use) >= MAX_ADDRESS_USE:
        return
    if use and use[2] > use[4]:
        db.execute("UPDATE address_use SET last=? WHERE rowid=?", (use[2], use[3]))
    row = db.execute("INSERT INTO address_use(addr, device, first, last) VALUES(?,?,?,?)",
                     (addr, device, now, now)).lastrowid
    S.addr_use[addr] = [device, now, now, row, now]


def rebuild_address_map():
    """Put S.addr_device together from its two halves (S.map4, S.map6) and this computer's own
    addresses, which always belong to the fixed "pi" device. The finished dictionary replaces the
    old one in a single step, so a lookup reading it never sees it half made."""
    known = dict(S.map6)
    known.update(S.map4)
    for addr in ["127.0.0.1", "::1", S.local_ip] + list(S.v6_own):
        if addr:
            known[addr] = S.pi_device
    S.addr_device = known


def note_ipv4_addresses(table=None, now=None):
    """Work out which device has which IPv4 address now, from the neighbour table, and keep
    S.addr_device and the address record up to date. Run every ADDRESS_LOOK seconds by
    device_keeper and each minute by refresh_devices, never on a lookup. `table` is {ip: (hardware
    address, freshness)} or {ip: hardware address} (the neighbour table when not given).

    The safeguards, so that one device's lookups are never filed as another's:
      - Only an address confirmed just now counts (its neighbour entry is fresh, or its freshness
        can't be known on this system). Linux keeps an entry for a device that left for a long
        time, and that address may since have gone to another device. A lookup from an address
        that is not confirmed is saved without a device, and filed once a later look has confirmed
        who was there (tidy_history).
      - An address that turns up with a different hardware address belongs to that device from
        then on: the old device's record of it stops, and its history stays its own.
      - One hardware address at two confirmed addresses at once may be a Wi-Fi range extender
        standing in for several devices. The address the device already had stays its own; the
        other gets no device until the first is no longer confirmed, so a second device behind an
        extender is never taken for the first. While that lasts the hardware address is unsettled
        (S.hw_unsettled) and its IPv6 addresses are not matched either. If no address was its own
        before, neither is given to it.
      - A hardware address known to be a range extender's (S.shared_macs) gives each of its
        addresses a device of its own, known by that address.
      - A new hardware address is a new device. A phone that makes itself a new private Wi-Fi
        address shows as a new device; nothing is merged automatically.
    This computer and the home router are the two fixed devices and are never mixed with others."""
    if not S.devices_ready:
        return
    now = time.time() if now is None else now
    if table is None:
        table = neighbour_table()
    router = home_router() or S.router
    seen_at = {}
    for ip, entry in (table or {}).items():
        mac, fresh = entry if isinstance(entry, tuple) and len(entry) == 2 else (entry, "")
        try:
            ip = str(ipaddress.IPv4Address(str(ip)))
        except ValueError:
            continue
        mac = clean_mac(mac)
        if mac and ip != S.local_ip:
            seen_at[ip] = (mac, fresh)
    with db_lock:
        if not S.devices_ready:
            return
        if router and router in seen_at and seen_at[router][0] != S.hub_mac:
            set_hub_mac(seen_at[router][0], now)
        mapped, by_mac = {}, {}                 # mapped: address -> (device, confirmed just now?)
        for ip, (mac, fresh) in seen_at.items():
            if ip == router or mac == S.hub_mac:
                mapped[ip] = (S.hub_device, fresh != "stale")
            else:
                by_mac.setdefault(mac, []).append((ip, fresh))
        unsettled = set()
        for mac, spots in by_mac.items():
            live = [ip for ip, fresh in spots if fresh == "fresh"] or [ip for ip, fresh in spots if fresh == ""]
            if mac in S.shared_macs:
                for ip in live:
                    mapped[ip] = (device_of_address(ip, now), True)
                continue
            if len(live) > 1:
                unsettled.add(mac)
                number = S.hw_device.get(mac)
                own = [ip for ip in live if number is not None and ip in S.addr_use and S.addr_use[ip][0] == number]
                newest = max([S.addr_use[ip][2] for ip in own], default=None)
                own = [ip for ip in own if S.addr_use[ip][2] == newest]
                live = own if len(own) == 1 else []
            for ip in live:
                mapped[ip] = (device_of_hw(mac, now), True)
                S.hw_seen[mac] = now
        known = {}
        for ip, (number, confirmed) in mapped.items():
            if number is None:
                continue
            known[ip] = number
            use_address(ip, number, now, confirmed)
            if confirmed:
                S.device_seen[number] = now
        S.hw_unsettled = frozenset(unsettled)
        S.map4 = known
        rebuild_address_map()
        if db.in_transaction:
            db.commit()


def note_ipv6_addresses(table=None, now=None):
    """Work out which device has which IPv6 address now, from the IPv6 neighbour table as last
    read (S.v6_table; `table` in its place for the tests), and keep S.addr_device and the address
    record up to date. Run after each look at the IPv6 neighbours (ipv6_look), never on a lookup.

    An IPv6 address belongs to the device with the hardware address the neighbour table gives it,
    so a phone's four or more addresses, and the new one it makes about daily, all come to one
    device. A stale entry still counts: a device's own IPv6 address is not handed on to another.
    Never matched: an address whose hardware address is a range extender's (S.shared_macs), or is
    unsettled because it is at two live IPv4 addresses at once (S.hw_unsettled). Those lookups are
    filed under whatever address they were judged under. An address built from a hardware address
    (eui64_mac) proves nothing and is not looked at here."""
    if not S.devices_ready:
        return
    now = time.time() if now is None else now
    table = S.v6_table if table is None else table
    with db_lock:
        if not S.devices_ready:
            return
        known = {}
        for addr, entry in (table or {}).items():
            mac, fresh = entry if isinstance(entry, tuple) and len(entry) == 2 else (entry, "")
            mac = clean_mac(mac)
            if not mac or addr in S.v6_own:
                continue
            if mac == S.hub_mac:
                number = S.hub_device
            elif mac in S.shared_macs or mac in S.hw_unsettled:
                continue
            else:
                number = device_of_hw(mac, now)
                if fresh != "stale":
                    S.hw_seen[mac] = now
            if number is None:
                continue
            known[addr] = number
            use_address(addr, number, now, fresh != "stale")
            if fresh != "stale":
                S.device_seen[number] = now
        S.map6 = known
        rebuild_address_map()
        if db.in_transaction:
            db.commit()


def device_of_lookup(source, client):
    """The number of the device a lookup belongs to, or None if the map can't say yet. `source` is
    the address the lookup really came from; `client` the address it was judged under (a device
    asking over IPv6 is judged under its IPv4 address: see answer_query). This computer is always
    the fixed "pi" device. Otherwise the address it came from decides, and failing that the address
    it was judged under. One or two dictionary lookups, no database: cheap enough for every lookup."""
    if is_this_computer(client):
        return S.pi_device
    known = S.addr_device
    number = known.get(source) if source else None
    return number if number is not None else known.get(client)


def note_lookup(client, name, blocked, source=None):
    """Hand one lookup to the history writer (log_q), with the device it belongs to if the map
    knows (device_of_lookup) and the address it really came from, so the writer can ask the map
    again. Only dictionary lookups and a queue: answering never waits for the database."""
    device = device_of_lookup(source, client) if S.devices_ready else None
    log_q.put((time.time(), client, name, blocked, device, source))


def save_address_use():
    """Catch the database up with what the looks have seen since the last time: how recently each
    address was confirmed with its device, and when each device and hardware address was last
    seen. Done each minute (tidy_history), not on every look, to spare the SD card."""
    with db_lock:
        for use in list(S.addr_use.values()):
            if use[2] > use[4]:
                db.execute("UPDATE address_use SET last=? WHERE rowid=?", (use[2], use[3]))
                use[4] = use[2]
        seen, S.device_seen = S.device_seen, {}
        for number, last in seen.items():
            db.execute("UPDATE device SET last=? WHERE id=? AND last<?", (last, number, last))
        seen, S.hw_seen = S.hw_seen, {}
        for mac, last in seen.items():
            db.execute("UPDATE device_hw SET last=? WHERE mac=? AND last<?", (last, mac, last))
        if db.in_transaction:
            db.commit()


# Lookups saved without a device since the device tables were made, oldest first, found through
# q_device_ts: the first step of a pass, and each step after it.
UNFILED_SQL = "SELECT id, ts, client FROM queries WHERE device IS NULL AND ts>=? ORDER BY ts LIMIT ?"
UNFILED_NEXT_SQL = "SELECT id, ts, client FROM queries WHERE device IS NULL AND ts>? ORDER BY ts LIMIT ?"


def holder_at(client, ts, now, spans):
    """Which device had the address `client` at the time `ts`, going by the address record: its
    number, or None if that can't be said yet. `spans` remembers each address's rows for the
    length of one pass.

    The lookup is given to the device whose record covers that moment: it was confirmed at the
    address before the lookup and again after. A lookup made up to ADDRESS_GRACE seconds before a
    device was first confirmed there is that device's too, since a device must join the network
    and ask for something before it can be seen. Otherwise the answer waits for a later look. A
    lookup still unplaced after ADDRESS_WAIT seconds is filed under the address itself (an "addr"
    device), which keeps it apart from every device that has had that address. This computer's
    own lookups are always its own."""
    if not client:
        return NO_DEVICE
    if is_this_computer(client):
        return S.pi_device
    if client not in spans:
        spans[client] = db.execute("SELECT device, first, last FROM address_use WHERE addr=? ORDER BY first, rowid",
                                   (client,)).fetchall()
    for number, first, last in spans[client]:
        if last >= ts:
            if first - ts <= ADDRESS_GRACE:
                return number
            break
    if now - ts > ADDRESS_WAIT:
        number = device_of_address(client, now)
        if number is None:
            return NO_DEVICE
        S.device_seen[number] = max(S.device_seen.get(number, 0), ts)
        return number
    return None


def tidy_history(now=None):
    """The clean-up pass, run each minute by device_keeper: file the lookups that were saved
    without a device against the device that had their address at the time (holder_at). Returns
    how many it filed.

    Most lookups get their device as they are made. The rest came from an address not confirmed at
    that moment: a device whose neighbour entry had gone stale, an address new to the network, or
    one whose hardware address was unsettled. Works TIDY_BATCH rows at a time and lets go of
    db_lock between steps, because the history writer needs that lock and its queue has no limit.
    Call it without holding db_lock."""
    if not S.devices_ready:
        return 0
    now = time.time() if now is None else now
    save_address_use()
    filed, spans = 0, {}
    statement, after = UNFILED_SQL, S.devices_moved_at
    while True:
        with db_lock:
            rows = db.execute(statement, (after, TIDY_BATCH)).fetchall()
            placed = []
            for row, ts, client in rows:
                number = holder_at(client, ts, now, spans)
                if number is not None:
                    placed.append((number, row))
            if placed:
                db.executemany("UPDATE queries SET device=? WHERE id=? AND device IS NULL", placed)
                S.history_filed += 1
            if db.in_transaction:
                db.commit()
        filed += len(placed)
        if len(rows) < TIDY_BATCH:
            return filed
        statement, after = UNFILED_NEXT_SQL, rows[-1][1]
        time.sleep(0.05)                     # give the history writer and the dashboard a turn at the lock


def forget_old_devices(now=None):
    """Keep the device tables small, each hour: forget address records and devices not seen for
    KEEP_DAYS (as long as history is kept, so a forgotten device has no history left), and beyond
    MAX_ADDRESS_USE and MAX_DEVICES the longest unseen. The two fixed devices are never forgotten.
    A forgotten device that comes back is a new device with a new number. (Rules are not kept
    against devices yet. When they are, a device with a name or rules must be spared here.)"""
    if not S.devices_ready:
        return
    now = time.time() if now is None else now
    cutoff = now - KEEP_DAYS * 86400
    save_address_use()
    with db_lock:
        db.execute("DELETE FROM address_use WHERE last<?", (cutoff,))
        db.execute("DELETE FROM address_use WHERE rowid IN "
                   "(SELECT rowid FROM address_use ORDER BY last DESC LIMIT -1 OFFSET ?)", (MAX_ADDRESS_USE,))
        db.execute("DELETE FROM device WHERE kind IN ('hw', 'addr') AND name='' AND last<?", (cutoff,))
        db.execute("DELETE FROM device WHERE id IN (SELECT id FROM device WHERE kind IN ('hw', 'addr') "
                   "ORDER BY last DESC LIMIT -1 OFFSET ?)", (MAX_DEVICES,))
        for table in ("device_hw", "address_use", "moved_address"):
            db.execute("DELETE FROM %s WHERE device NOT IN (SELECT id FROM device)" % table)
        load_device_rows()
        db.commit()
        S.map4 = {addr: number for addr, number in S.map4.items() if number in S.device_kind}
        S.map6 = {addr: number for addr, number in S.map6.items() if number in S.device_kind}
        rebuild_address_map()


def device_addresses(number):
    """The addresses a device has now, or was the last device seen at: IPv4 first, the most
    recently confirmed first, MAX_LISTED_ADDRESSES at most. This computer's are its own (and never
    another device's, even one that had the address before), and a device known only by an
    address has that address unless another device has been seen there since. Reads S only,
    without a lock."""
    kind = S.device_kind.get(number)
    if kind == "pi":
        return [S.local_ip] + sorted(S.v6_own)[:MAX_LISTED_ADDRESSES - 1]
    uses, current = dict(S.addr_use), S.addr_device
    mine = [(":" in addr, -use[2], addr) for addr, use in uses.items()
            if use[0] == number and current.get(addr, number) == number]
    if kind == "addr":
        mine += [(":" in addr, 0, addr) for addr, n in list(S.addr_only.items())
                 if n == number and addr not in uses and current.get(addr, number) == number]
    return [addr for _, _, addr in sorted(mine)[:MAX_LISTED_ADDRESSES]]


def device_number(value):
    """The device number in a request, or None if it isn't the number of a device QuietNet knows
    (or the device tables are not in use). Text of digits and whole numbers both count."""
    if isinstance(value, bool) or not S.devices_ready:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None                         # OverflowError: a number too large to be a whole number (1e999 in JSON)
    return number if number in S.device_kind else None


# ----- moving an older household's data into the device tables

MOVE_RETRY = 3600              # seconds before the move is tried again after too little free space
MOVE_ADDRESS_WAIT = 120        # seconds the move waits for this computer to learn its own address on the home
                               # network (a Pi can start before its Wi-Fi is connected). The move decides once
                               # which old history is this computer's and which the router's.
# Every address in the old history, found by hopping through the q_client_ts index from one address
# to the next (as LAST_SEEN_SQL does), not by reading every row.
OLD_CLIENTS_SQL = """
    WITH RECURSIVE c(x) AS (
        SELECT MIN(client) FROM queries
        UNION ALL
        SELECT (SELECT MIN(client) FROM queries WHERE client>x) FROM c WHERE x IS NOT NULL)
    SELECT x FROM c WHERE x IS NOT NULL"""
# One step of giving older history its device: the newest rows still without one, found through
# q_device_ts. Newest first, so the dashboard's last day is right within moments.
FILL_SQL = "SELECT id, client FROM queries WHERE device IS NULL AND ts<? ORDER BY ts DESC LIMIT ?"


def space_for_move():
    """Is there room to move the household's data? Returns (enough?, megabytes wanted, megabytes
    free). Wanted is twice the size of the database: once for the copy kept from before the move,
    and as much again for the new index and the work of making it."""
    path = os.path.join(DATA, "quietnet.db")
    size = sum(os.path.getsize(p) for p in (path, path + "-wal") if os.path.exists(p))
    free = shutil.disk_usage(DATA).free
    return free >= 2 * size, (2 * size) // 1000000 + 1, free // 1000000


def copy_database(dest):
    """Copy the whole database to the file `dest`, as it stands at this moment, while QuietNet
    carries on using it. Done by the database's own copying tool on a connection of its own, in a
    single step, so the copy is complete and consistent and nothing waits for it. It is written
    under another name first and forced onto the disk before it takes its real name, so a power
    cut can't leave a half-written file that looks like a good copy."""
    part = dest + ".part"
    for leftover in (part, part + "-wal", part + "-shm", part + "-journal"):
        if os.path.exists(leftover):
            os.remove(leftover)
    source = sqlite3.connect(os.path.join(DATA, "quietnet.db"))
    try:
        copy = sqlite3.connect(part)
        try:
            source.backup(copy)
        finally:
            copy.close()
    finally:
        source.close()
    with open(part, "rb") as f:
        os.fsync(f.fileno())
    os.replace(part, dest)
    try:
        folder = os.open(DATA, os.O_RDONLY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    except OSError:
        pass                                # some systems can't do this for a folder; the copy is still there


def forget_old_copy(now=None, at_once=False):
    """Delete the copy of the database kept from just before the move to the device tables
    (BEFORE_DEVICES in the data folder), once it is KEEP_DAYS old, or straight away when `at_once`
    is true. Returns True if the copy is gone or was never there.

    The copy holds every lookup the household made before the move. History is promised to be
    kept for KEEP_DAYS and no longer, and "forget everyone's history" is promised to forget it, so
    the copy must not outlive either: device_keeper calls this each hour, and clear_history calls
    it with `at_once` when everyone's history is cleared. After KEEP_DAYS the copy is no use as a
    way back in any case: every history row in it would have been trimmed by then, and its rules
    are a month out of date.

    Its age is counted from the time of the move when the move finished, otherwise (a copy left
    by a move that failed) from when the file was written. A part-written copy left by an
    interrupted move goes the same way. While a move is under way its files are left alone, and a
    request to delete at once is remembered (S.copy_unwanted) and carried out when the move ends.
    Only these fixed names in the data folder are ever touched. A missing file is not an error,
    and nothing here raises: a file that can't be deleted is reported and tried again later."""
    now = time.time() if now is None else now
    if S.devices_state == "moving":
        if at_once:
            S.copy_unwanted = True
        return False
    path = os.path.join(DATA, BEFORE_DEVICES)
    gone = True
    for name in (path, path + ".part", path + ".part-wal", path + ".part-shm", path + ".part-journal"):
        try:
            if not os.path.exists(name):
                continue
            moved = name == path and S.devices_ready and S.devices_moved_at
            made = S.devices_moved_at if moved else os.path.getmtime(name)
            if at_once or now - made >= KEEP_DAYS * 86400:
                os.remove(name)
                continue
        except OSError as e:
            print("Could not delete the copy of the data kept from before the device tables (%s):" % name, e,
                  flush=True)
        if name == path:
            gone = False                        # still there: not old enough yet, or it could not be deleted
    return gone


def build_devices(now):
    """The data part of the move, inside move_to_devices' one transaction: make a device for every
    hardware address the old tables know, and decide which device each address in the old history
    is given to. Returns {"devices", "addresses", "uncertain"}: how many of each. Rules, names and
    groups are not touched: they stay under their addresses.

      1. A "hw" device for every hardware address in known_macs, device_mac and seen, leaving out
         range extenders' (shared_macs) and the router's own, which goes to the fixed "hub" device.
      2. Each address is given to a device: the device its rules were recorded as belonging to
         (device_mac), unless they are paused because a different device has that address now;
         then the hardware address most recently seen there (known_macs); then the one the last
         scan found there (seen). Only the first is certain evidence and is marked so
         (moved_address.certain); the others are the best guess.
      5. An address with no hardware address to go by, among them IPv6 addresses in the old
         history, becomes a device known only by that address (kind "addr"): MAX_DEVICES of them
         at most. A history holding more such addresses than that was filled by something making
         addresses up, and the rest are filed against no device (NO_DEVICE).
      7. The version of the tables and the time of the move are saved with the settings. (Nothing
         compares them on a later start yet: see the note above DEVICES_VERSION.)
    Old history rows are given their device afterwards, in small steps (fill_old_history): the old
    tables do not say when an address changed hands, so every row goes to the address's device as
    decided here, and a few rows from before a change will sit with the wrong device until they
    are 30 days old."""
    shared = {mac for (mac,) in db.execute("SELECT mac FROM shared_macs WHERE hits>=?", (SHARED_AFTER,))}
    router = home_router() or S.router
    this_computer = {"127.0.0.1", "::1", S.local_ip}
    numbers = {}

    def make(kind, key, first):
        """The number of the device with this key, made on first use."""
        if key not in numbers:
            numbers[key] = db.execute("INSERT INTO device(kind, key, name, first, last) VALUES(?,?,?,?,?)",
                                      (kind, key, "", first, now)).lastrowid
        return numbers[key]

    pi, hub = make("pi", "pi", now), make("hub", "hub", now)
    known = {}                                  # hardware address -> (first seen, last seen, the address it was last at)
    for mac, ip, first, last in db.execute("SELECT mac, ip, first, last FROM known_macs ORDER BY last"):
        if clean_mac(mac):
            known[clean_mac(mac)] = (first or now, last or now, ip)
    owner, paused = {}, set()                   # address -> the hardware address its rules belong to
    for ip, mac, is_paused in db.execute("SELECT ip, mac, paused FROM device_mac"):
        if clean_mac(mac):
            owner[ip] = clean_mac(mac)
            if is_paused:
                paused.add(ip)
    scanned = {}                                # address -> (hardware address, when the scan saw it)
    for ip, mac, ts in db.execute("SELECT ip, mac, ts FROM seen"):
        scanned[ip] = (clean_mac(mac), ts or now)
    hub_mac = scanned.get(router, ("", 0))[0] if router else ""
    latest = {}                                 # address -> the hardware address most recently seen there
    for mac, (_, _, ip) in sorted(known.items(), key=lambda item: item[1][1]):
        latest[ip] = mac
    macs = set(known) | set(owner.values()) | {mac for mac, _ in scanned.values() if mac}
    for mac in sorted(macs):
        if mac in shared:
            continue
        first, last = known.get(mac, (now, now, ""))[:2]
        if mac == hub_mac:
            db.execute("INSERT OR REPLACE INTO device_hw(mac, device, first, last) VALUES(?,?,?,?)", (mac, hub, first, last))
            continue
        db.execute("INSERT OR REPLACE INTO device_hw(mac, device, first, last) VALUES(?,?,?,?)",
                   (mac, make("hw", "hw:" + mac, first), first, last))
    addresses = set(owner) | set(latest) | set(scanned)
    addresses.update(x for (x,) in db.execute(OLD_CLIENTS_SQL))
    for table in ("devices", "device_group", "enforced"):
        addresses.update(ip for (ip,) in db.execute("SELECT ip FROM %s" % table))
    uncertain = by_address = 0
    for addr in sorted(a for a in addresses if a and isinstance(a, str)):
        mac, certain = "", 1
        if addr in this_computer:
            number = pi
        elif router and addr == router:
            number = hub
        else:
            choices = ((owner.get(addr) if addr not in paused else "", 1), (latest.get(addr), 0),
                       (scanned.get(addr, ("", 0))[0], 0))
            mac, certain = next(((m, sure) for m, sure in choices if m and m not in shared), ("", 1))
            if mac == hub_mac and mac:
                number = hub
            elif mac:
                number = numbers["hw:" + mac]
            elif by_address < MAX_DEVICES:
                number, by_address = make("addr", "addr:" + addr, now), by_address + 1
            else:
                number = NO_DEVICE
        uncertain += not certain
        db.execute("INSERT OR REPLACE INTO moved_address(addr, device, certain) VALUES(?,?,?)", (addr, number, certain))
        if mac:
            # When the device was at this address, as far as the old tables say: the times it was
            # seen on the network if this is where it was last seen, else when a scan found it here.
            first, last, at = known.get(mac, (now, now, ""))
            if at != addr:
                seen_here = scanned[addr][1] if scanned.get(addr, ("", 0))[0] == mac else first
                first, last = min(first, seen_here), seen_here
            db.execute("INSERT INTO address_use(addr, device, first, last) VALUES(?,?,?,?)", (addr, number, first, last))
    for key, value in (("devices_version", DEVICES_VERSION), ("devices_moved_at", repr(now)), ("devices_fill", "pending")):
        db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, str(value)))
    add_event("", "QuietNet now keeps each device's history with the device itself, whatever address it has. "
                  "A copy of your data from just before this change, with the history up to then, is kept beside "
                  "it as %s for %d days and then deleted. Forgetting everyone's history deletes it too."
                  % (BEFORE_DEVICES, KEEP_DAYS), now)
    return {"devices": sum(1 for key in numbers if key.startswith("hw:")), "addresses": len(addresses),
            "uncertain": uncertain}


def move_to_devices():
    """Move an older household's data into the device tables. Run by device_keeper AFTER the filter
    and the enforcer have started, never from init_db: on a big history it takes a while, and a
    slow or failing start would leave the house without DNS. Returns S.devices_state afterwards.

      - Too little free space (space_for_move): nothing is touched, the owner is told, and it is
        tried again later ("waiting").
      - A copy of the database is kept first, as BEFORE_DEVICES in the data folder (copy_database).
        It is deleted when it is KEEP_DAYS old, or when everyone's history is forgotten
        (forget_old_copy), because it holds the household's history from before the move.
      - Everything else is ONE transaction: the new tables, the history's new column and index,
        the devices (build_devices). Any error rolls all of it back, so the database is exactly as
        it was, QuietNet carries on with the old tables as before, and the owner is told
        ("failed"). It is tried again at the next start.
      - db_lock is held for that transaction, so the dashboard and the history writer wait while
        the index is built (some seconds on a big history). Lookups are still answered: they never
        take that lock, and neither does the look that matches a new IPv6 address to its device.
    Going back to an older QuietNet afterwards means putting the kept copy back in place of
    quietnet.db, which loses what was recorded after the move (see docs/ARCHITECTURE.md)."""
    if S.devices_ready:
        return S.devices_state
    try:
        enough, wanted, free = space_for_move()
        if not enough:
            S.devices_state = "waiting"
            S.devices_notice = ("QuietNet needs about %d MB of free space to bring your household's history up to "
                                "date, and there is only %d MB. Nothing has been changed and everything works as "
                                "before. Free some space on this computer and QuietNet will try again within the "
                                "hour." % (wanted, free))
            return S.devices_state
        S.devices_state, S.devices_notice = "moving", ""
        started = time.monotonic()
        copy_database(os.path.join(DATA, BEFORE_DEVICES))
        with db_lock:
            if db.in_transaction:
                db.commit()
            db.execute("BEGIN IMMEDIATE")
            try:
                make_device_tables()
                report = build_devices(time.time())
                db.commit()
            except BaseException:
                db.rollback()
                raise
            S.moved_steady = time.monotonic()   # the fill waits FILL_SETTLE from here before it may finish
            load_devices()
        print("Moved the household's data to the device tables in %.1f seconds: %d devices, %d addresses "
              "(%d matched on a best guess)." % (time.monotonic() - started, report["devices"], report["addresses"],
                                                 report["uncertain"]), flush=True)
    except Exception as e:
        S.devices_ready = False
        S.devices_state = "failed"
        S.devices_notice = ("QuietNet could not bring your household's history up to date (%s). Nothing has been "
                            "changed and everything works as before. It will try again the next time it starts."
                            % (str(e) or type(e).__name__))
        print("Could not move the household's data to the device tables:", e, flush=True)
    if S.copy_unwanted:
        # Everyone's history was forgotten while the copy was being made: the copy may hold it.
        S.copy_unwanted = False
        forget_old_copy(at_once=True)
    return S.devices_state


def fill_step(moved, now=None, finish=True):
    """Give one batch of older history rows (from before the move) their device: each row goes to
    the device its address was given to in the move (`moved`, from moved_address). An address the
    move did not see gets a device of its own, known by that address. Returns how many rows it
    did. 0 means no row is waiting; with `finish` true the fill is then finished, which is saved
    so it is not started again. With `finish` false nothing is marked: more rows may still arrive
    (see fill_old_history)."""
    now = time.time() if now is None else now
    with db_lock:
        rows = db.execute(FILL_SQL, (S.devices_moved_at, FILL_BATCH)).fetchall()
        if not rows:
            if not finish:
                return 0
            S.history_fill = False
            db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('devices_fill', 'done')")
            db.commit()
            return 0
        placed = []
        for row, client in rows:
            number = moved.get(client) if client else NO_DEVICE
            if number is None:
                number = device_of_address(client, now)
                number = NO_DEVICE if number is None else number
                moved[client] = number
                db.execute("INSERT OR REPLACE INTO moved_address(addr, device, certain) VALUES(?,?,1)", (client, number))
            placed.append((number, row))
        db.executemany("UPDATE queries SET device=? WHERE id=?", placed)
        db.commit()
        S.history_filed += 1
    return len(rows)


def fill_old_history():
    """Background thread, started by device_keeper after the move (and again after a restart, until
    it has finished): give every older history row its device, FILL_BATCH rows at a time, newest
    first, letting go of db_lock and pausing between steps so lookups, the history writer and the
    dashboard are not held up. Until a row is done the dashboard shows it under the device that
    has its address now.

    The fill does not call itself finished until FILL_SETTLE seconds after the move. The history
    writer holds each lookup for a second before saving it, so lookups made in the last moments
    before the move (or while it held the database) are saved just after it, with a time from
    before it and no device. Only the fill handles such rows, so on a small history, done in a
    blink, it looks again each second until the writer has surely caught up. After a restart
    there is nothing to wait for: the writer's queue starts empty. A restart during the wait is
    safe too: the fill is still marked as to do, and runs once more."""
    moved = dict(sql("SELECT addr, device FROM moved_address"))
    while S.devices_ready and S.history_fill:
        settled = S.moved_steady is None or time.monotonic() - S.moved_steady >= FILL_SETTLE
        if fill_step(moved, finish=settled):
            time.sleep(FILL_PAUSE)
        elif settled:
            print("Every older history row now has its device.", flush=True)
            return
        else:
            time.sleep(1)                       # nothing waiting just now; the history writer may still bring some


def device_keeper():
    """Background thread, started once the filter and the enforcer are running. First it moves an
    older household's data into the device tables if that is still to do (move_to_devices; after
    too little free space it tries again every MOVE_RETRY seconds, after a failure not until the
    next start). Then, every ADDRESS_LOOK seconds, it looks at the neighbour table to keep
    S.addr_device right (note_ipv4_addresses); each minute it files waiting lookups against their
    device (tidy_history); each hour it forgets devices long gone (forget_old_devices) and the
    copy of the data from before the move once that is old enough (forget_old_copy; this one also
    while the move is still to do or has failed). The first look comes ADDRESS_LOOK seconds after
    starting.

    The move waits, up to MOVE_ADDRESS_WAIT seconds, until this computer knows its own address on
    the home network. A Pi can start QuietNet before its Wi-Fi is connected (after a power cut,
    say), and the move decides once and for all which old history is this computer's and which
    the router's: done with no address, both would be filed under ordinary devices that are not
    shown. It comes round every ADDRESS_LOOK seconds, so the move starts within moments of the
    address being found (address_watcher looks for it every 10 seconds). After the wait it goes
    ahead regardless: a computer with no network must still get its device tables. Just before
    the move the router is looked for afresh, so that "no router", found while the network was
    down and trusted for ROUTER_RECHECK seconds, is not what the move goes by."""
    retry_at, filling = 0.0, None
    started = tidied = forgot = time.monotonic()
    while True:
        try:
            if (not S.devices_ready and S.devices_state != "failed" and time.monotonic() >= retry_at
                    and (S.local_ip != "127.0.0.1" or time.monotonic() - started >= MOVE_ADDRESS_WAIT)):
                S.router_checked = None             # look for the router again now (home_router)
                move_to_devices()
                retry_at = time.monotonic() + MOVE_RETRY
            if S.devices_ready and S.history_fill and (filling is None or not filling.is_alive()):
                filling = threading.Thread(target=fill_old_history, daemon=True)
                filling.start()
        except Exception as e:
            print("Could not move the household's data to the device tables:", e, flush=True)
        time.sleep(ADDRESS_LOOK)
        try:
            if S.devices_ready:
                note_ipv4_addresses()
                if time.monotonic() - tidied >= TIDY_EVERY:
                    tidied = time.monotonic()
                    tidy_history()
            if time.monotonic() - forgot >= 3600:
                forgot = time.monotonic()
                forget_old_copy()                   # whether or not the move has been done
                forget_old_devices()                # does nothing until the device tables are in use
        except Exception as e:
            print("Could not keep the record of which device has which address:", e, flush=True)


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
    count_junk()
    with open(os.path.join(HERE, "services.json")) as f:
        S.services = json.load(f)
    S.svc_names = {v["id"]: v["name"] for v in S.services}
    S.dom2svc = {d: v["id"] for v in S.services for d in v["domains"]}


def count_junk():
    """Work out how many names the two advert lists hold between them, for the dashboard.

    Done once when a list is loaded or downloaded, not on every status request: counting means
    joining the two lists, which with a community list of 100,000+ names is a big set to build."""
    S.junk_count = len(S.junk_builtin | S.junk_community)


def suffixes(domain):
    """The name and each of its parents, most specific first, stopping before the last part.
    'a.b.example.com' -> ['a.b.example.com', 'b.example.com', 'example.com'].
    A rule on any of these applies to the name, which is how one entry covers everything beneath it."""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def is_other_dns_service(name):
    """Is this name, or a name it sits beneath, one of the other DNS services in OTHER_DNS_SERVICES?
    Capitals and a final dot are ignored ('DNS.Google.' counts). Only a few set lookups, so it is
    cheap enough to ask for every lookup."""
    name = (name or "").strip().rstrip(".").lower()
    return bool(name) and any(s in OTHER_DNS_SERVICES for s in suffixes(name))


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
    rules_changed()


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
    """Every set of rules that applies to a device: the whole house, itself, and its group.
    Three exceptions, all set by refresh_devices:
      - a device whose own rules are still kept under its old address, because they could not be
        moved to its new one (S.follow), gets the rules kept under the old address;
      - a device at an address whose rules are paused, because they belong to a different device
        (S.paused_ips), gets the whole house's rules, plus the new-device group if it is a device
        never seen before (S.guest_group);
      - otherwise, the rules kept under its own address."""
    out = ["all"]
    if not client:
        return out
    home = S.follow.get(client)
    if home is None and client in S.paused_ips:
        guest = S.guest_group.get(client)
        if guest:
            out.append("group:%d" % guest[1])
        return out
    home = home or client
    out.append("device:" + home)
    if home in S.dev_group:
        out.append("group:%d" % S.dev_group[home])
    return out


def other_dns_blocked_for(client):
    """Is this device kept away from other DNS services (OTHER_DNS_SERVICES)? Yes when the owner
    chose that for every device (S.other_dns_all), and otherwise only for devices the owner
    controls: "cut live connections" is on, it is in a group, or it has an internet switch, a
    blocked service or a schedule of its own. Devices with none of these are left alone, because
    a device set to use one of these services strictly (Android's Private DNS set to a name, an
    encrypted DNS profile on an iPhone or a Mac) does not fall back: it would lose all names.
    Reads S only, so it is cheap enough for a lookup."""
    if S.other_dns_all or client in S.enforced:
        return True
    scopes = scopes_for(client)[1:]
    if any(sc.startswith("group:") for sc in scopes):
        return True
    return (any(sc in S.off or S.svc_blocks.get(sc) for sc in scopes)
            or any(x["scope"] in scopes for x in S.schedules))


def internet_off_for(client):
    """Is all internet off for this device right now - by its own switch, its group's,
    or an all-internet schedule? (The kill switch is checked separately, as 'all' in S.off.)
    Never for QuietNet's own machine, which internet_cut() never cuts off either."""
    if is_this_computer(client):
        return False
    scopes = scopes_for(client)
    return any(sc in S.off for sc in scopes) or any(x["off"] for x in active_schedules() if x["scope"] in scopes)


def scope_label(scope):
    """A scope in plain words for the dashboard: 'whole house', 'Kids group' or 'this device'."""
    if scope == "all":
        return "whole house"
    if scope.startswith("group:"):
        return S.group_names.get(int(scope[6:]), "group") + " group"
    return "this device"


def is_this_computer(client):
    """Is this address QuietNet's own machine? Its lookups (the relay link, the clock, list
    downloads) are not a household device's, so the kill switch and 'internet off' never apply."""
    return client in ("127.0.0.1", "::1") or (client is not None and client == S.local_ip)


def internet_cut(client):
    """Is all internet off for this device right now? Returns (why, detail) - why is 'kill' (the
    kill switch), 'off' (its own, its group's or the house's switch) or 'schedule' (an all-internet
    schedule; detail is its name) - or None if not. QuietNet's own machine is never cut off,
    or it would lose the relay and could not be switched back on from outside."""
    if is_this_computer(client):
        return None
    if "all" in S.off:
        return "kill", ""
    scopes = scopes_for(client)
    if any(sc in S.off for sc in scopes):
        return "off", ""
    for x in active_schedules():
        if x["off"] and x["scope"] in scopes:
            return "schedule", x["name"]
    return None


def decision(domain, client=None, paused=False):
    """Returns (blocked?, why, detail).

    why is 'kill', 'off', 'schedule', 'you', 'allowed', 'service', 'list' or None.
    'paused' only pauses advert blocking and your own address blocks -
    the kill switch, schedules, blocked services and switched-off devices stay in force."""
    cut = internet_cut(client)
    if cut:
        return (True,) + cut
    scopes = scopes_for(client)
    timed = [x for x in active_schedules() if x["scope"] in scopes]
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


def needed_by(domain):
    """Who needs this name for their own system to work, as a short phrase such as 'Samsung TVs',
    or '' when nobody is known to (see NEEDED). Only the whole name counts: a sub-name beneath a
    needed name gives '', because blocking one sub-name is the right, narrow way to block a tracker.
    Used for labels and for the question asked before a block; decision() never reads it."""
    return NEEDED.get(domain, "")


def needed_refusal(who):
    """The sentence sent with the 409 when a needed name is blocked without the person's say-so.
    The dashboard asks its own question from the phrase alone; this is for anything else that
    shows the 'error' text, such as a dashboard page loaded before this question existed.
    Reloading brings the new page from this computer, but not always through the relay: the relay
    serves its own copy of the page, which stays old until the relay itself is updated. So the
    sentence does not promise that a reload is enough, and says what to do when it is not."""
    return ("%s need this address for their own system to work. Blocking it may stop them opening "
            "apps, signing in or updating. It has not been blocked. Reload this page and try again "
            "to be asked first. If you are still not asked and you are using QuietNet away from "
            "home, remote access needs updating too: until then, block it from QuietNet's own page "
            "at home." % who)


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
        rules_changed()


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
        rules_changed()


def forget(domain):
    """Remove an address from both your blocked list and your allowed list."""
    with db_lock:
        S.blocked.discard(domain)
        S.allowed.discard(domain)
        db.execute("DELETE FROM blocked WHERE domain=?", (domain,))
        db.execute("DELETE FROM allowed WHERE domain=?", (domain,))
        db.commit()
        rules_changed()


def update_community_list():
    """Download the community advert list, check it, save it and start using it.

    Runs in its own thread (started from the dashboard). Progress and errors are reported through
    S.list_state and S.list_error. A download with fewer than 1,000 usable lines is treated as
    broken and thrown away, so a bad download can never replace a good list."""
    S.list_state, S.list_error = "downloading", ""
    try:
        req = urllib.request.Request(COMMUNITY_URL, headers={"User-Agent": "QuietNet"})
        # The same secure-connection settings as the relay link: they add the system's certificate
        # list when Python has none of its own (python.org's Python on a Mac), and still check
        # every certificate.
        with urllib.request.urlopen(req, timeout=45, context=cloud_agent.tls_context()) as r:
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
        count_junk()
        rules_changed()            # block decisions may differ even if the list is the same size
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
    this to know which addresses to drop when a name is blocked. Addresses older than
    RESOLVED_HOURS are forgotten, and at most 64 are kept per name (some names rotate through
    hundreds). Capped at 4,000 names; when full, the 1,000 least recently seen are forgotten.

    This runs before every allowed answer is sent, so it takes only resolved_lock, never db_lock:
    a slow dashboard query or a history trim must not hold up anyone's lookups."""
    ips = answer_ips(resp)
    if not ips:
        return
    now = time.time()
    with resolved_lock:
        m = S.resolved.setdefault(domain, {})
        for ip in ips:
            m[ip] = now
        for ip in [ip for ip, ts in m.items() if now - ts > RESOLVED_HOURS * 3600]:
            del m[ip]
        if len(m) > 64:
            for ip in sorted(m, key=m.get)[:len(m) - 64]:
                del m[ip]
        if len(S.resolved) > 4000:                     # keep memory bounded: drop the stalest names
            for d in sorted(S.resolved, key=lambda d: max(S.resolved[d].values(), default=0))[:1000]:
                S.resolved.pop(d, None)


# Why a name is blocked -> whether the enforcer also cuts its addresses. The advert list is left
# out: advert and tracker names often share addresses with ordinary sites (the same front doors
# serve Google search and Google's adverts), so cutting by address would break those sites too.
ENFORCE_WHY = ("you", "service", "schedule")


def learn_enforced_mac(ip, mac):
    """The enforcer has seen an enforced device's hardware address for the first time: remember it,
    so that if the address is later handed to a different device, that device is left alone."""
    with db_lock:
        if ip in S.enforced and not S.enforced_mac.get(ip):
            S.enforced_mac[ip] = mac
            db.execute("UPDATE enforced SET mac=? WHERE ip=?", (mac, ip))
            db.commit()


def label_of(domain):
    """The friendly name to show for a blocked name on the device page: the service it belongs to
    (YouTube for www.youtube.com), or the name itself when it belongs to none."""
    for s in suffixes(domain):
        svc = S.dom2svc.get(s)
        if svc:
            return S.svc_names.get(svc, domain)
    return domain


def live_cut_on(client):
    """Is "cut live connections" on for the device at this address now? Its own switch, unless its
    rules are paused (the address belongs to a different device now) - or, for a device whose
    rules are kept under its old address (S.follow), the switch kept there."""
    home = S.follow.get(client)
    if home is not None:
        return home in S.enforced
    return client in S.enforced and client not in S.paused_ips


def live_cut_devices():
    """{ip: hardware address to steer, or ''} for every device "cut live connections" is on for
    now (see live_cut_on). A paused address belongs to a different device, which must not be
    steered. A device whose rules are kept under its old address is steered at the address it
    has now, by its own hardware address, and not at the old one. Reads S only; the caller holds
    db_lock."""
    away = set(S.follow) | set(S.follow.values())
    out = {ip: S.enforced_mac.get(ip, "") for ip in S.enforced if ip not in S.paused_ips and ip not in away}
    for ip, home in S.follow.items():
        if home in S.enforced:
            out[ip] = S.dev_mac.get(home, "")
    return out


# Blocked names whose addresses carry only video and other large downloads for one service:
# YouTube's video servers, Netflix's and Twitch's. Their addresses are always cut for a device
# with "cut live connections", even when a name it is allowed was given the same address. Google's
# caches inside the internet provider's network serve YouTube video and Chrome, Play Store and
# Android updates (gvt1.com) from the same addresses; sparing those would let a video that is
# already playing carry on. The price is that an update downloading at that moment stops too.
ALWAYS_CUT_BY_ADDRESS = frozenset(("googlevideo.com", "nflxvideo.net", "ttvnw.net"))


def always_cut(domain):
    """Is this name one of ALWAYS_CUT_BY_ADDRESS, or beneath one?"""
    return any(s in ALWAYS_CUT_BY_ADDRESS for s in suffixes(domain))


def enforcement_plan():
    """What the enforcer should drop, per enforced device: reuses the normal rules.
    {victim_ip: {"off": all-internet?, "ips": {addresses to drop}, "mac": hardware address or ''}}

    'off' covers the kill switch, the device's internet switch and an 'all internet' schedule.
    Otherwise the addresses of names blocked by you, by a service block or by a schedule are cut.
    Pausing advert blocking pauses it here too.

    Shared addresses: big services answer many names from the same front doors (youtube.com and
    Google search, Classroom and Gmail all come from Google's; Cloudflare and Fastly carry many
    sites each). Dropping such an address would cut sites the device is allowed. So an address a
    blocked name was given is not dropped for a device if a name that device is allowed was given
    the same address in the last RESOLVED_HOURS. Those names are still blocked by DNS; only the
    address-level cut is left out. The exception is a video server's address
    (ALWAYS_CUT_BY_ADDRESS), which is always cut, or a video already playing would carry on. How many addresses were spared, and for which blocked things, is
    kept per device in S.shared_left for the device page. Devices cut off entirely are unaffected.

    This runs every two seconds, and the answer for a given name and device only changes when a
    rule does. So each name's answer is remembered (in S.plan_cache) and worked out again only
    for names not seen before, or when a rule, the pause, the schedules in force or the set of
    enforced devices has changed - and in any case at least once a minute."""
    with db_lock:                                      # copies: other threads change these while we work
        victims = live_cut_devices()
    if not victims:
        S.shared_left = {}
        return {}
    with resolved_lock:
        names = list(S.resolved)
    now = time.time()
    paused = now < S.paused_until
    key = (S.rules_version, paused, tuple(sorted(x["id"] for x in active_schedules())),
           tuple(sorted(victims)), S.local_ip)
    cache = S.plan_cache
    if cache.get("key") != key or now - cache.get("made", 0) > 60:
        cache = S.plan_cache = {"key": key, "made": now, "off": {}, "cut": {}}
    for victim in victims:
        if victim not in cache["off"]:
            # A made-up name only comes back blocked for one of the 'everything' reasons.
            blocked, why, _ = decision("quietnet.invalid", victim, paused)
            cache["off"][victim] = blocked and why in ("kill", "off", "schedule")
    # name -> (devices it is cut for, devices it is allowed for)
    cut = {}
    for domain in names:
        entry = cache["cut"].get(domain)
        if entry is None:
            cut_for, allowed_for = set(), set()
            for v in victims:
                if cache["off"][v]:
                    continue
                blocked, why, _ = decision(domain, v, paused)
                if why in ENFORCE_WHY:
                    cut_for.add(v)
                elif not blocked:
                    allowed_for.add(v)
            entry = (frozenset(cut_for), frozenset(allowed_for))
        cut[domain] = entry
    cache["cut"] = cut                                 # names that have been forgotten drop out here
    plan = {v: {"off": cache["off"][v], "ips": set(), "mac": mac} for v, mac in victims.items()}
    recent = now - RESOLVED_HOURS * 3600
    wanted = {}                                        # device -> {address to drop: the blocked names it came from}
    with resolved_lock:
        for domain, (cut_for, _) in cut.items():
            ipmap = S.resolved.get(domain) if cut_for else None
            if not ipmap:
                continue
            ips = [ip for ip, ts in ipmap.items() if ts > recent and ":" not in ip]
            for v in cut_for:
                mine = wanted.setdefault(v, {})
                for ip in ips:
                    mine.setdefault(ip, set()).add(domain)
        # Which of those addresses an allowed name was also given: one pass over the remembered
        # names, each checked against the (small) set of addresses about to be dropped.
        to_drop = set()
        for mine in wanted.values():
            to_drop.update(mine)
        allowed_at = {}                                # address -> devices a name given it is allowed for
        if to_drop:
            for domain, ipmap in S.resolved.items():
                entry = cut.get(domain)
                if not entry or not entry[1]:
                    continue
                for ip in to_drop.intersection(ipmap):
                    if ipmap[ip] > recent:
                        allowed_at.setdefault(ip, set()).update(entry[1])
    shared = {}
    for v, mine in wanted.items():
        spared, why = 0, set()
        for ip, blocked_names in mine.items():
            if v in allowed_at.get(ip, ()) and not any(always_cut(d) for d in blocked_names):
                spared += 1
                why.update(blocked_names)
            else:
                plan[v]["ips"].add(ip)
        if spared:
            labels = sorted({label_of(d) for d in why})
            shared[v] = {"count": spared, "names": labels[:5]}
    S.shared_left = shared                             # one entry per enforced device at most
    return plan


def ttl_positions(resp):
    """Where each record's lifetime ("how long it may be remembered", four bytes) sits in a DNS
    answer, leaving out the settings record (type 41), which has no real lifetime. Returns a list
    of byte offsets, or None if the packet can't be read exactly from start to end. Used to shorten
    lifetimes (cap_ttls) and to age remembered answers (cached_answer), both of which rewrite the
    packet and so must not guess."""
    try:
        buf = resp
        counts = [int.from_bytes(buf[i:i + 2], "big") for i in (4, 6, 8, 10)]

        def skip_name(pos):
            """Step past one encoded name starting at `pos`; return the position just after it.
            Unlike the copy in answer_ips, this one refuses reserved label types."""
            while True:
                n = buf[pos]
                if n == 0:
                    return pos + 1
                if n & 0xC0 == 0xC0:          # a compression pointer ends the name
                    return pos + 2
                if n & 0xC0:                  # reserved label type: this isn't a name we understand
                    raise ValueError("reserved label byte")
                pos += 1 + n

        pos, out = 12, []
        for _ in range(counts[0]):
            pos = skip_name(pos) + 4
        for _ in range(sum(counts[1:])):
            pos = skip_name(pos)
            if pos + 10 > len(buf):
                raise ValueError("record header runs off the end")
            if int.from_bytes(buf[pos:pos + 2], "big") != 41:
                out.append(pos + 4)
            pos += 10 + int.from_bytes(buf[pos + 8:pos + 10], "big")
        # Only trust the reading if every record lined up and we landed exactly at the end.
        return out if pos == len(buf) else None
    except (IndexError, ValueError):
        return None


def cap_ttls(resp, limit=MAX_TTL):
    """Shorten how long a device may remember an answer.

    Without this a device can keep using an address for hours after it has been
    blocked, which would make bedtime schedules and the kill switch very slow to bite."""
    where = ttl_positions(resp)
    if where is None:                 # misread packet: hand back the untouched original
        return resp
    buf = bytearray(resp)
    for at in where:
        if int.from_bytes(buf[at:at + 4], "big") > limit:
            buf[at:at + 4] = limit.to_bytes(4, "big")
    return bytes(buf)


def question_settings(data, qend):
    """What a question says about the answer it can take, from its settings record (type 41, also
    called OPT) if it carries one. Returns (has the record, the largest UDP answer it accepts,
    whether it asks for signature records). A question with no readable settings record can take
    512 bytes over UDP and asks for no signatures. `qend` is where the question ends."""
    try:
        counts = [int.from_bytes(data[i:i + 2], "big") for i in (6, 8, 10)]
        pos = qend
        for _ in range(sum(counts)):
            while data[pos] != 0:                 # step past the record's name
                if data[pos] & 0xC0 == 0xC0:
                    pos += 1
                    break
                pos += 1 + data[pos]
            pos += 1
            if pos + 10 > len(data):
                break
            if int.from_bytes(data[pos:pos + 2], "big") == 41:
                size = int.from_bytes(data[pos + 2:pos + 4], "big")
                wants_signatures = bool(data[pos + 6] & 0x80)   # the 'DO' flag
                return True, max(512, size), wants_signatures
            pos += 10 + int.from_bytes(data[pos + 8:pos + 10], "big")
    except IndexError:
        pass
    return False, 512, False


def cache_key(data, q):
    """What a remembered answer is filed under: the name asked about (lower case), the record type,
    the class, and what the question asked of the answer - whether it carried a settings record,
    whether that asked for signature records, and whether it asked the server not to check
    signatures (the 'CD' flag). The internet's answer depends on all three, so an answer given to
    one kind of question is never handed to another: in particular, an unchecked answer fetched for
    a device that turned checking off is never given to a device that relies on it. `q` is
    parse_question(data)."""
    name, qtype, qend = q
    has_settings, _, wants_signatures = question_settings(data, qend)
    no_checking = bool(data[3] & 0x10)
    return (name, qtype, int.from_bytes(data[qend - 2:qend], "big"), has_settings, wants_signatures,
            no_checking)


def remember_answer(key, resp, now=None):
    """Keep an answer from the internet in memory for as long as it may be remembered: the shortest
    lifetime of any record in it (already cut to MAX_TTL by cap_ttls). Only good answers are kept -
    'found' or 'no such name' - never failures, cut-short answers or answers with no lifetime to go
    by. Blocked answers never come here: they are made by QuietNet, not fetched. Nor do answers
    over MAX_CACHED_SIZE bytes (a TCP answer can be 64 KB), so the memory used stays small. When
    full, the oldest answer is dropped."""
    if len(resp) < 12 or len(resp) > MAX_CACHED_SIZE:
        return
    if resp[2] & 0x02 or (resp[3] & 15) not in (0, 3):   # 0x02: cut short, ask over TCP
        return
    where = ttl_positions(resp)
    if not where:
        return
    life = min(min(int.from_bytes(resp[at:at + 4], "big") for at in where), MAX_TTL)
    if life <= 0:
        return
    now = time.monotonic() if now is None else now
    with answer_cache_lock:
        answer_cache.pop(key, None)
        answer_cache[key] = (now + life, now, bytes(resp))
        while len(answer_cache) > MAX_CACHED_ANSWERS:
            answer_cache.popitem(last=False)


def cached_answer(data, key, qend, now=None, over_tcp=False):
    """A remembered answer to this question, made ready for the device that asked, or None.

    The id and the question are copied from the device's own packet (some devices change the
    letter case of names, and check it comes back the same), and every record's lifetime is reduced
    by the time it has already spent in memory. Over UDP, an answer bigger than the device said it
    can take (512 bytes, or the size in its settings record) is not given; the answer is None, and
    the question goes to the internet as usual, which tells the device to ask over TCP."""
    now = time.monotonic() if now is None else now
    with answer_cache_lock:
        entry = answer_cache.get(key)
        if entry and entry[0] <= now:
            del answer_cache[key]
            entry = None
    if not entry:
        return None
    expires, stored, resp = entry
    if not over_tcp and len(resp) > question_settings(data, qend)[1]:
        return None
    if resp[12:qend].lower() != data[12:qend].lower():
        return None
    where = ttl_positions(resp)
    if where is None:
        return None
    gone = int(now - stored)
    buf = bytearray(data[:2] + resp[2:12] + data[12:qend] + resp[qend:])
    for at in where:
        buf[at:at + 4] = max(0, int.from_bytes(buf[at:at + 4], "big") - gone).to_bytes(4, "big")
    return bytes(buf)


def forward_udp(data, servers=None):
    """Ask the real DNS servers over UDP, first one then the spare. Returns the reply, or
    None if neither answered within 2.5 seconds. `servers` replaces the usual list (it is
    used to send home-network names to the router)."""
    for up in servers or UPSTREAMS:
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
                    if same_question(data, resp):
                        return resp
        except OSError:
            continue
    return None


def same_question(query, resp):
    """Is this reply an answer to this query: the same two-byte id and, when the query can be
    read, the same question? Checking the question as well means a forged reply must also guess
    exactly what was asked. Letter case is ignored, since some servers change it."""
    if resp[:2] != query[:2]:
        return False
    q = parse_question(query)
    if not q:
        return True
    end = q[2]
    return len(resp) >= end and resp[12:end].lower() == query[12:end].lower()


def forward_tcp(data, servers=None):
    """The same as forward_udp but over TCP, where each message is preceded by its length
    as two bytes. Used for lookups that arrived over TCP."""
    for up in servers or UPSTREAMS:
        try:
            with socket.create_connection(up, timeout=4) as s:
                s.sendall(len(data).to_bytes(2, "big") + data)
                head = recv_exact(s, 2)
                return recv_exact(s, int.from_bytes(head, "big"))
        except (OSError, ValueError):
            continue
    return None


def recv_exact(s, n, deadline=None):
    """Read exactly n bytes from a connection, or raise ValueError if it closes first - or, when a
    deadline (a time.monotonic() value) is given, if the bytes haven't all arrived by then. The
    deadline stops a client keeping a thread busy by sending one byte every few seconds."""
    buf = b""
    while len(buf) < n:
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise ValueError("too slow")
            s.settimeout(left)
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ValueError("connection closed")
        buf += chunk
    return buf


def unreadable_reply(data):
    """The reply to a packet whose question can't be read: 'format error' with the same id, if
    at least the 12-byte header is there and it is a question rather than a reply. Otherwise
    None, meaning send nothing. Such packets are never passed on to the internet."""
    if len(data) < 12 or data[2] & 0x80:
        return None
    return data[:2] + bytes([0x80 | (data[2] & 0x79), 0x80 | 1]) + bytes(8)


def is_private_reverse(name):
    """Is this a reverse lookup (address to name) of a home-network or private address -
    10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x, or IPv6 fc00::/7 and fe80::/10? Only the
    home router knows those names, so they must not go to the public servers."""
    if name.endswith(".in-addr.arpa"):
        octets = name[:-len(".in-addr.arpa")].split(".")[::-1]
        if octets[0] in ("10", "127"):
            return True
        if len(octets) < 2:
            return False
        if octets[:2] in (["192", "168"], ["169", "254"]):
            return True
        return octets[0] == "172" and octets[1].isdigit() and 16 <= int(octets[1]) <= 31
    if name.endswith(".ip6.arpa"):
        nibbles = "".join(name[:-len(".ip6.arpa")].split(".")[::-1])
        return nibbles[:2] in ("fc", "fd") or (nibbles[:2] == "fe" and nibbles[2:3] in ("8", "9", "a", "b"))
    return False


def is_home_name(name, qtype=None):
    """Is this a name only the home network can answer: .local, .lan, .home, .internal,
    .home.arpa, a single word with no dot (such as 'nas', which some routers answer for home
    devices), or a reverse lookup of a private address?

    A single word asked about with one of SIGNATURE_TYPES is not: that is a device checking DNS
    signatures asking about a top-level name such as 'com', which only the internet can answer.
    Answering it 'no such name' would make that device reject every name under it."""
    single_word = name != "" and "." not in name and qtype not in SIGNATURE_TYPES
    return name.endswith(HOME_ENDINGS) or single_word or is_private_reverse(name)


def home_router():
    """The home router's address, to send home-network names to, or None if it isn't known.
    Read from the system's routing table (Linux only) and looked up again every ROUTER_RECHECK
    seconds, so a lookup costs nothing. Never this computer itself, which would loop."""
    now = time.monotonic()
    if S.router_checked is None or now - S.router_checked > ROUTER_RECHECK:
        S.router_checked = now
        try:
            S.router = enforcer.interface_and_gateway()[1] or ""
        except Exception:
            S.router = ""
    if not S.router or is_this_computer(S.router):
        return None
    return S.router


def ask_router(data, client, qend, forwarder):
    """Answer a home-network name by asking the home router. If the router isn't known, or the
    question came from the router itself (asking it back would go round in circles), the answer
    is 'no such name'. If the router doesn't answer, 'server failure'.

    A router set up to pass lookups back to QuietNet by another route would still go round in
    circles, each asking the other. So if the same question (name and type) arrives while QuietNet
    is already waiting on the router for it, the answer is 'server failure' rather than asking
    again. (Two devices asking the very same home name at the very same moment also get this; they
    simply ask again.)"""
    router = home_router()
    if not router or client == router:
        return reply(data, qend, 3)
    q = parse_question(data)
    key = (q[0], q[1])
    with router_waiting_lock:
        if router_waiting.get(key):
            return reply(data, qend, 2)
        router_waiting[key] = 1
    try:
        resp = forwarder(data, servers=[(router, 53)])
    finally:
        with router_waiting_lock:
            router_waiting.pop(key, None)
    return cap_ttls(resp) if resp else reply(data, qend, 2)


def device_address(host):
    """The address a device is known by, from the address its lookup came from. A lookup that
    arrives on the IPv6 listener from an IPv4 device shows up as '::ffff:192.168.1.23'; that is
    the same device as '192.168.1.23', so it is filed under that. A zone suffix ('%eth0', which
    says which network card a home-only IPv6 address was seen on) is dropped. '::1' (this computer)
    and everything else is left as it is."""
    if not host:
        return host
    host = host.split("%", 1)[0]
    if host[:7].lower() == "::ffff:" and "." in host:
        try:
            return str(ipaddress.IPv4Address(host[7:]))
        except ValueError:
            return host
    return host


def no_ipv6_for_everyone(name, qtype, client):
    """Does the optional "Give no device IPv6 addresses" switch (S.no_ipv6_all, off unless the
    owner turns it on) apply to this lookup? Never to a name only the home network can answer
    (is_home_name: printers, the router and other home devices may be reachable over IPv6 alone),
    and never to QuietNet's own machine. Reads S only."""
    return S.no_ipv6_all and not is_home_name(name, qtype) and not is_this_computer(client)


def ask_for_ipv6_look(client):
    """A lookup came from an IPv6 address no device is matched to: ask ipv6_watcher to look at the
    IPv6 neighbours again now, not at the next minute. Returns True if a look is on its way. Only
    sets a flag, so it costs a lookup nothing.

    If a look has been asked for already, nothing more is needed. Otherwise this address sets one
    off, which it may do V6_ASKS_PER_ADDRESS times in IPV6_RECHECK seconds: enough for a second
    look when the first came a moment too early, without letting a device that can never be
    matched (one QuietNet has not seen over IPv4) keep the watcher busy for ever. The watcher
    itself never looks more often than every V6_QUICK_GAP seconds. Does nothing while the watcher
    isn't running."""
    if not S.v6_watching:
        return False
    if v6_wanted.is_set():
        return True
    now = time.monotonic()
    with v6_askers_lock:
        entry = v6_askers.get(client)
        if entry is None or now - entry[1] >= IPV6_RECHECK:
            if len(v6_askers) >= V6_MAX_ASKERS:
                v6_askers.clear()
            entry = v6_askers[client] = [0, now]
        if entry[0] >= V6_ASKS_PER_ADDRESS:
            return False
        entry[0] += 1
    v6_wanted.set()
    return True


def matched_ipv6_device(client):
    """The IPv4 address of the device asking from this IPv6 address (S.v6_devices), or None if it
    can't be matched. Called for a lookup, before decision(), never inside it.

    A phone makes itself a new IPv6 address about daily, and ipv6_watcher looks only every minute.
    So an unknown address asks for a look straight away (ask_for_ipv6_look) and, when a look is
    under way or can start at once, this lookup waits for it, for V6_ANSWER_WAIT seconds at most,
    and then looks the address up again. It does not wait when the watcher finished a look less
    than V6_QUICK_GAP seconds ago (the next one is not due yet) or when V6_MAX_WAITING lookups are
    waiting already, so a flood from made-up addresses can't tie up the threads that answer
    everyone else. The wait runs on one of the answering threads; the thread that receives lookups
    never waits."""
    seen_round = S.v6_round
    mapped = S.v6_devices.get(client)
    if mapped:
        return mapped
    asked = ask_for_ipv6_look(client)
    if not S.v6_looking:
        looked = S.v6_looked_at
        if not asked or (looked is not None and time.monotonic() - looked < V6_QUICK_GAP):
            return None
    if not v6_waiting.acquire(blocking=False):
        return None
    try:
        with v6_looked:
            v6_looked.wait_for(lambda: S.v6_round != seen_round, V6_ANSWER_WAIT)
    finally:
        v6_waiting.release()
    return S.v6_devices.get(client)


def answer_query(data, client, forwarder, over_tcp=False):
    """The whole life of one lookup: read it, decide, record it, answer it.

    `forwarder` is forward_udp or forward_tcp (or a stand-in, in tests); `over_tcp` says the
    question came over TCP, where an answer may be any size. Returns the reply bytes, or None when
    nothing should be sent back.
    The steps are described in docs/ARCHITECTURE.md under 'What happens to one lookup'."""
    q = parse_question(data)
    if not q:
        return unreadable_reply(data)
    name, qtype, qend = q
    loggable = bool(VALID_NAME.fullmatch(name)) and not name.endswith(IGNORED_ENDINGS)
    client = device_address(client)
    source = client                 # the address it really came from, for the history (note_lookup)
    if client in ("127.0.0.1", "::1") or client in S.v6_own:
        client = S.local_ip
    elif client and ":" in client:
        # A device asking from its own IPv6 address. Rules are set on IPv4 addresses, so file it
        # under its IPv4 address if it can be matched (a new address is looked for at once: see
        # matched_ipv6_device). If not, and any device is treated differently from the whole
        # house (device_rules_exist), refuse, rather than answer it as if it were not one. A refused
        # device tries its next DNS server. That may be QuietNet's IPv4 address, where its rules
        # are known, or the router's own IPv6 DNS server, which is a way round QuietNet, not an
        # outage (docs/KNOWN_ISSUES.md, issue 5).
        mapped = matched_ipv6_device(client)
        if mapped:
            client = mapped
        elif device_rules_exist():
            return reply(data, qend, 5)
    if name in NO_SUCH_NAME_SIGNALS or name in BLOCKED_SIGNALS:
        # The 'use the network's DNS' signals (see NO_SUCH_NAME_SIGNALS): the same answer for every
        # device, paused or not, whatever the rules say. They are written to the history as blocked,
        # because they were, so the owner can see which devices tried to bypass QuietNet.
        note_lookup(client, name, 1, source)
        if name in NO_SUCH_NAME_SIGNALS:
            return reply(data, qend, 3)
        return blocked_reply(data, qtype, qend)
    if is_other_dns_service(name) and other_dns_blocked_for(client):
        # Another DNS service (see OTHER_DNS_SERVICES), for a device the owner controls (or every
        # device, if the owner chose that): blocked, paused or not, whatever else the rules say,
        # and noted so the device's page can say it tried.
        note_lookup(client, name, 1, source)
        if client in S.other_dns or len(S.other_dns) < MAX_OTHER_DNS_DEVICES:
            S.other_dns[client] = time.time()
        return blocked_reply(data, qtype, qend)
    if not loggable:
        # Names that skip the checks: odd characters, home-network endings, reverse lookups.
        # If this device's internet is off they get the blocked answer, so they can't be used
        # to tunnel out. Otherwise home-network names go to the router, the rest to the internet.
        if internet_cut(client):
            return blocked_reply(data, qtype, qend)
        if is_home_name(name, qtype):
            return ask_router(data, client, qend, forwarder)
        resp = forwarder(data)
        return cap_ttls(resp) if resp else reply(data, qend, 2)
    blocked = decision(name, client, time.time() < S.paused_until)[0]
    note_lookup(client, name, 1 if blocked else 0, source)
    if blocked:
        return blocked_reply(data, qtype, qend)
    if qtype in NO_IPV6_TYPES and (live_cut_on(client) or no_ipv6_for_everyone(name, qtype, client)):
        # "Cut live connections" steers and cuts IPv4 only. So a device it is on gets no IPv6
        # addresses ('no error, no records', like blocked_reply for other questions), and its apps
        # connect over IPv4, through the Pi, where they can be cut. Made fresh each time and never
        # remembered, so the answer cache can't hand this empty answer to other devices, or their
        # real IPv6 answers to this one. The optional whole-house switch does the same for every
        # device (see no_ipv6_for_everyone).
        return reply(data, qend, 0)
    # Only now, with the device's own rules already checked, may a remembered answer stand in for
    # the trip to the internet.
    key = cache_key(data, q)
    resp = cached_answer(data, key, qend, over_tcp=over_tcp)
    if resp:
        record_resolved(name, resp)
        return resp
    resp = forwarder(data)
    if not resp:
        return reply(data, qend, 2)
    record_resolved(name, resp)
    resp = cap_ttls(resp)
    remember_answer(key, resp)
    return resp


# Linux's "tell me which of my addresses this packet was sent to" option (IP_PKTINFO). Python only
# names it from 3.13 on Linux; its number there has always been 8. Other systems go without it.
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8) if sys.platform.startswith("linux") else None


def ask_for_reply_address(sock):
    """On Linux, ask an IPv4 UDP socket to report, with each lookup, which of this computer's
    addresses it was sent to. True if that worked.

    Why: the socket listens on every address at once, so without this the system picks the
    address an answer is sent from. When the enforcer redirects a steered device's lookup meant for
    8.8.8.8 to this computer (see enforcer.nft_ruleset), the answer must leave from exactly the
    address the lookup was redirected to; only then can the firewall put 8.8.8.8 back as the
    sender. An answer from any other address of this computer would be thrown away by the device."""
    if IP_PKTINFO is None or sock.family != socket.AF_INET or not hasattr(sock, "recvmsg"):
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
        return True
    except OSError:
        return False


def receive_lookup(sock, with_address):
    """Wait for one lookup. Returns (packet, sender, the address it was sent to or None). The last
    is only known when ask_for_reply_address worked (with_address)."""
    if not with_address:
        data, addr = sock.recvfrom(4096)
        return data, addr, None
    data, ancillary, _flags, addr = sock.recvmsg(4096, socket.CMSG_SPACE(12))
    return data, addr, reply_address(ancillary)


def reply_address(ancillary):
    """The address a lookup was sent to, from the extra details Linux gives with it (a 12-byte
    record: the network card's number, then two addresses, the second being the one the packet
    was addressed to). None if it isn't there or isn't a plain address of one device."""
    for level, kind, value in ancillary:
        if level == socket.IPPROTO_IP and kind == IP_PKTINFO and len(value) >= 12:
            addr = ipaddress.IPv4Address(value[8:12])
            if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
                return None
            return str(addr)
    return None


def send_answer(sock, resp, addr, source):
    """Send an answer back to the device that asked, from `source` (the address the lookup was sent
    to) when that is known, so the answer leaves from the address the device or the firewall
    expects. If the system won't send from it, fall back to letting the system choose."""
    if source:
        try:
            info = struct.pack("=i4s4s", 0, socket.inet_aton(source), bytes(4))
            sock.sendmsg([resp], [(socket.IPPROTO_IP, IP_PKTINFO, info)], 0, addr)
            return
        except OSError:
            pass
    sock.sendto(resp, addr)


class Shares:
    """How many lookups (or TCP connections) each device has in hand right now, so that no one
    device can take them all. Counted per device, not per address: see share_key. One of these is
    shared by the IPv4 and the IPv6 listener (UDP_SHARES, TCP_SHARES), so a device asking over both,
    or from several IPv6 addresses, still gets one share. An IPv6 address that can't be matched to
    one device, or that sits behind a range extender, keeps a share of its own. Safe to use from
    several threads."""

    def __init__(self):
        """Nothing in hand for anyone."""
        self.lock = threading.Lock()
        self.count = {}                 # share_key -> how many it has in hand now

    def take(self, who, limit):
        """Count one more for this device, or return False if it already has `limit` in hand."""
        with self.lock:
            mine = self.count.get(who, 0)
            if mine >= limit:
                return False
            self.count[who] = mine + 1
            return True

    def give_back(self, who):
        """Count one fewer for this device, once a lookup or connection is finished with."""
        with self.lock:
            left = self.count.get(who, 1) - 1
            if left > 0:
                self.count[who] = left
            else:
                self.count.pop(who, None)


UDP_SHARES = Shares()       # lookups over UDP, across the IPv4 and IPv6 listeners
TCP_SHARES = Shares()       # connections over TCP, across the IPv4 and IPv6 listeners


def share_key(host):
    """Whose share a lookup from this address counts against (see Shares): the device's, not the
    address's. An IPv4 device reaching the IPv6 listener counts as its IPv4 address
    (device_address); this computer counts as one, whichever of its addresses it asks from; and an
    IPv6 address matched to a device (S.v6_devices) counts as that device's IPv4 address, so a
    phone with four IPv6 addresses has one share, not five. An IPv6 address that can't be matched
    counts by itself. So does one behind a range extender (S.v6_shared): an extender shows several
    devices under one hardware address, so they all match one IPv4 address, and counting them as
    one would let a single busy device use up the share of every device behind that extender. A
    few set and dictionary lookups, no database."""
    who = device_address(host)
    if who in ("127.0.0.1", "::1") or who in S.v6_own:
        return S.local_ip
    if who and ":" in who:
        return who if who in S.v6_shared else S.v6_devices.get(who, who)
    return who


class Workers:
    """A team of background threads that run the jobs handed to them, first come first served:
    at most `most` jobs at a time, and the rest wait their turn.

    It does what Python's ThreadPoolExecutor did here until 25 November, with one difference
    that matters when the program stops. Python waits, as a program ends, for every thread of
    a ThreadPoolExecutor to finish the job it holds and every job still waiting, and that
    cannot be switched off. With lookups in hand and the internet down, each one waiting five
    seconds for an answer that is not coming, QuietNet went on running for up to 20 seconds
    after it had printed "QuietNet stopped.", which is as long as Docker waits before it kills
    a program. These are daemon threads, which Python does not wait for. A job cut off as the
    program ends is a lookup whose device will simply ask again."""

    def __init__(self, most):
        """No thread is started until there is a job for it."""
        self._jobs = queue.Queue()
        self._most = most
        self._threads = 0
        self._spare = 0             # threads with nothing to do, less the jobs waiting for one
        self._lock = threading.Lock()

    def submit(self, job, *args):
        """Hand over one job: job(*args) is run by a thread that is free, by a new one if none
        is free and there are fewer than `most`, or else when one comes free.

        Raises RuntimeError, with the job not taken, if a thread is needed and Python will not
        start one: it refuses once the program is ending, and when the computer has no room
        for another."""
        with self._lock:
            if self._spare < 1 and self._threads < self._most:
                threading.Thread(target=self._work, daemon=True).start()
                self._threads += 1
                self._spare += 1
            self._spare -= 1
            self._jobs.put((job, args))

    def finish(self):
        """No more jobs will be handed over: let each thread end once those already handed
        over are done. For a team made for one piece of work, such as a network scan."""
        with self._lock:
            for _ in range(self._threads):
                self._jobs.put(None)

    def _work(self):
        """One thread of the team: run jobs as they come, until finish() says there are no more.
        A job that fails is reported in a line and does not take the thread with it."""
        while True:
            todo = self._jobs.get()
            if todo is None:
                return
            job, args = todo
            try:
                job(*args)
            except Exception as e:
                print("Background job problem:", e, flush=True)
            with self._lock:
                self._spare += 1


def udp_server(sock, shares=None):
    """Receive lookups on the UDP socket for ever, handing each to a team of 64 worker
    threads so that one slow upstream answer does not hold up the rest. At most
    MAX_DNS_WAITING are in hand at once, and at most MAX_DNS_PER_DEVICE from any one device;
    beyond that, new lookups are dropped rather than queued without limit (a flood from one
    device, or the internet being down). The per-device share means one busy or broken device
    can't use up every slot and stop everyone else's lookups. Devices simply ask again.
    `shares` counts each device's lookups in hand; start_dns gives the IPv4 and IPv6 listeners
    the same one (UDP_SHARES), so a device's share is one across both and across all its
    addresses (see share_key). Left out, this listener counts by itself.
    On the IPv6 socket, lookups from outside the home network are dropped unanswered.
    On Linux, each answer leaves from the address its lookup was sent to (see ask_for_reply_address).
    The workers are daemon threads, so lookups still in hand never hold up the program's end
    (see Workers)."""
    pool = Workers(64)
    with_address = ask_for_reply_address(sock)
    slots = threading.BoundedSemaphore(MAX_DNS_WAITING)
    on_ipv6 = sock.family == socket.AF_INET6
    shares = shares or Shares()

    def give_back(who):
        """Give back what one lookup held: one of the device's share (`who` is the share it was
        counted against), and one of the house's slots."""
        shares.give_back(who)
        slots.release()

    def work(who, data, addr, source):
        """Answer one lookup and send the reply back to the device that asked, from `source`.
        `who` is the share it was counted against, handed back when done."""
        try:
            resp = answer_query(data, addr[0], forward_udp)
            if resp:
                send_answer(sock, resp, addr, source)
        except Exception as e:
            print("Lookup problem:", e)
        finally:
            give_back(who)

    while True:
        try:
            data, addr, source = receive_lookup(sock, with_address)
        except (OSError, ValueError):
            continue
        if on_ipv6 and not v6_source_allowed(addr[0]):
            continue                        # from outside the home: no answer at all (see v6_source_allowed)
        who = share_key(addr[0])
        if not shares.take(who, MAX_DNS_PER_DEVICE):
            continue
        if not slots.acquire(blocking=False):
            shares.give_back(who)
            continue
        try:
            pool.submit(functools.partial(work, who), data, addr, source)
        except RuntimeError:
            # Python would not start a thread for it: the program is ending, or the computer has
            # no room for one more. Either way this lookup is dropped, quietly, and the device
            # asks again. Left alone, the error would end this listener with a traceback, which
            # used to be printed after "QuietNet stopped." when a lookup arrived at that moment.
            give_back(who)


class TCPHandler(socketserver.BaseRequestHandler):
    """Handles one DNS lookup that arrived over TCP (one lookup per connection)."""
    def handle(self):
        """Read the two-byte length and the question, answer it, send the reply the same way.
        The whole question must arrive within TCP_DEADLINE seconds."""
        try:
            deadline = time.monotonic() + TCP_DEADLINE
            n = int.from_bytes(recv_exact(self.request, 2, deadline), "big")
            data = recv_exact(self.request, n, deadline)
            self.request.settimeout(10)
            resp = answer_query(data, self.client_address[0], forward_tcp, over_tcp=True)
            if resp:
                self.request.sendall(len(resp).to_bytes(2, "big") + resp)
        except (OSError, ValueError):
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    """The TCP side of the DNS filter: one short-lived thread per connection, at most
    MAX_TCP_CLIENTS connections at once, and at most MAX_TCP_PER_DEVICE from any one device, so one
    device can't take every connection and shut everyone else out (more are turned away)."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kw):
        """As usual, plus the count of connections in hand, in all and for each device. `shares`
        counts each device's; start_dns swaps in the one shared by the IPv4 and IPv6 listeners
        (TCP_SHARES), so a device's share is one across both and across all its addresses."""
        self.slots = threading.BoundedSemaphore(MAX_TCP_CLIENTS)
        self.shares = Shares()
        self.holders = {}                   # an open connection's (address, port, ...) -> the share it took
        self.holders_lock = threading.Lock()
        super().__init__(*args, **kw)

    def take_slot(self, client_address):
        """Take one of this device's connections and one of the house's, or return False if
        either has none left. Which device's share was taken is remembered for give_slot_back,
        because the match between an IPv6 address and a device can change while it is open."""
        who = share_key(client_address[0])
        if not self.shares.take(who, MAX_TCP_PER_DEVICE):
            return False
        if not self.slots.acquire(blocking=False):
            self.shares.give_back(who)
            return False
        with self.holders_lock:
            self.holders[client_address] = who
        return True

    def give_slot_back(self, client_address):
        """Hand back what take_slot took, once a connection is finished with."""
        with self.holders_lock:
            who = self.holders.pop(client_address, None)
        self.shares.give_back(share_key(client_address[0]) if who is None else who)
        self.slots.release()

    def process_request(self, request, client_address):
        """Take a slot for this connection, or close it straight away if there are none left."""
        if not self.take_slot(client_address):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.give_slot_back(client_address)
            raise

    def process_request_thread(self, request, client_address):
        """Handle the connection, then give its slot back."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.give_slot_back(client_address)


class TCPServer6(TCPServer):
    """The same TCP listener on IPv6. It takes IPv6 only, leaving IPv4 to the ordinary listener on
    the same port (otherwise the two would clash on some systems)."""
    address_family = socket.AF_INET6

    def server_bind(self):
        """Ask for IPv6 only, then open the port as usual."""
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def verify_request(self, request, client_address):
        """Take connections from the home network only (see v6_source_allowed); others are closed."""
        return v6_source_allowed(client_address[0])


def start_dns(port):
    """Open the DNS port for UDP and TCP and start serving, on IPv4 and, where this computer has
    it, IPv6 (start_dns6). If the IPv4 port cannot be opened (usually because something else is
    using it) the reason is kept in S.dns_error for the dashboard to show, and the rest of
    QuietNet carries on. IPv6 is tried either way: one failing must not take the other with it,
    and the IPv6 watcher that start_dns6 starts is needed whether or not the filter is listening."""
    S.dns_port = port
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        tcp = TCPServer(("0.0.0.0", port), TCPHandler)
        tcp.shares = TCP_SHARES
    except OSError as e:
        if sock is not None:
            sock.close()
        S.dns_error = str(e)
        print("Could not start the filter on port %d: %s" % (port, e))
    else:
        threading.Thread(target=udp_server, args=(sock, UDP_SHARES), daemon=True).start()
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
    start_dns6(port)


def start_dns6(port):
    """Also listen for lookups over IPv6, on the same port, for devices the router has told to use
    an IPv6 address for DNS. Optional: if this computer has no IPv6, or the port can't be opened on
    it, the reason is printed and QuietNet carries on with IPv4 alone. Returns True if listening.

    The IPv6 watcher (ipv6_watcher) is started here whenever this computer has IPv6 at all, even
    if the port can't be opened: the dashboard's "IPv6 is off on your hub" check needs to know
    whether this computer holds a public IPv6 address, listening or not."""
    if not socket.has_ipv6 or not hasattr(socket, "IPV6_V6ONLY"):
        print("This computer has no IPv6, so the filter listens on IPv4 only.")
        return False
    threading.Thread(target=ipv6_watcher, daemon=True).start()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::", port))
        tcp = TCPServer6(("::", port), TCPHandler)
        tcp.shares = TCP_SHARES
    except OSError as e:
        if sock is not None:
            sock.close()
        print("Could not listen for lookups over IPv6 on port %d (%s). %s" % (
            port, e, "IPv4 lookups still work." if S.dns_error is None else "The filter is not listening at all."))
        return False
    threading.Thread(target=udp_server, args=(sock, UDP_SHARES), daemon=True).start()
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    S.dns_ipv6 = True
    return True


def v6_source_allowed(host):
    """May a lookup from this address be answered on the IPv6 listener?

    Over IPv4 the router's address sharing keeps the internet away from the filter. Over IPv6 this
    computer's public address can be reached directly, and only the router's own firewall (which
    some routers ship switched off) stops strangers using QuietNet. So only these are answered:
    this computer (::1), link-local (fe80::/10) and unique-local (fc00::/7) addresses, IPv4 home
    addresses written the IPv6 way, and public addresses inside the home network's own ranges
    (S.v6_prefixes, read from this computer's own addresses). Anything else gets no answer."""
    try:
        addr = ipaddress.ip_address(host.split("%", 1)[0])
    except (ValueError, AttributeError):
        return False
    if addr.version == 4:
        return True
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped.is_private
    return any(addr in net for net in HOME_ONLY_V6) or any(addr in net for net in S.v6_prefixes)


def device_rules_exist():
    """Is any device treated differently from the whole house: an internet switch, a blocked
    service or an enabled schedule for a device or a group, "Cut live connections" on for a device
    (S.enforced), or a device in a group, even a group with no rules yet? Used to decide whether an
    IPv6 lookup that can't be matched to a device must be refused (see answer_query).

    The last two matter because such a device is treated differently even with no rule to its
    name: one with "Cut live connections" gets no IPv6 addresses (answering it unmatched would hand
    them back, undoing the cut), and one in a group is kept away from other DNS services
    (other_dns_blocked_for). Reads S only, so it is cheap enough for a lookup."""
    return bool(S.enforced or S.dev_group or S.guest_group
                or any(sc != "all" for sc in S.off)
                or any(sc != "all" and ids for sc, ids in S.svc_blocks.items())
                or any(x["scope"] != "all" for x in S.schedules if x["enabled"]))


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


def refresh_local_ip():
    """Look up this computer's address again and, if it has changed, use the new one everywhere:
    the dashboard, the network scan, the 'this computer' checks and the enforcer. Returns True
    if it changed.

    A lost network (no address found) keeps the last good address rather than falling back to
    127.0.0.1: devices are still set to use it, and it will very likely come back."""
    new = find_local_ip()
    if new == S.local_ip or (new == "127.0.0.1" and S.local_ip != "127.0.0.1"):
        return False
    S.local_ip = new
    if ENF is not None:
        ENF.local_ip = new
    rules_changed()                     # 'this computer' is exempt from some rules
    print("This computer's address is now %s (type this into a device's DNS setting)." % new, flush=True)
    return True


def address_watcher():
    """Background thread: keep S.local_ip up to date, and keep each device's rules with the device
    when it changes address (refresh_devices). At start-up the network may not be ready
    yet (a Raspberry Pi can start QuietNet before Wi-Fi is connected), and the router may later
    hand this computer a different address. Checks every 10 seconds while there is no address,
    and every minute after that."""
    while True:
        time.sleep(10 if S.local_ip == "127.0.0.1" else 60)
        try:
            refresh_local_ip()
        except Exception as e:
            print("Could not check this computer's address:", e, flush=True)
        try:
            refresh_devices()
        except Exception as e:
            print("Could not check which device has which address:", e, flush=True)


# How fresh a neighbour-table entry is, from the state `ip neigh` gives it. "fresh": the device
# answered recently (or is being checked right now). "stale": the system has not heard from it for
# a while; on a home network Linux keeps such entries for good, so a device that has moved on can
# still be listed at its old address. Failed and unfinished entries are left out altogether.
FRESH_STATES = ("REACHABLE", "DELAY", "PROBE", "PERMANENT", "NOARP")
# Which freshness to believe when two entries disagree: confirmed just now, then not known, then stale.
FRESHNESS_RANK = {"fresh": 2, "": 1, "stale": 0}


def freshness_of(states):
    """How fresh a neighbour-table entry is, from the words `ip neigh` ends its line with: "fresh",
    "stale" or "" (not known), or None for an entry to leave out (failed, or never finished)."""
    if any(x in states for x in ("FAILED", "INCOMPLETE")):
        return None
    return "fresh" if any(x in states for x in FRESH_STATES) else ("stale" if "STALE" in states else "")


def keep_fresher(out, address, mac, fresh):
    """Put one neighbour-table entry into `out` ({address: (mac, freshness)}), unless the address
    is there already with an entry at least as fresh. The same address can be listed twice (once
    per network card, say); a stale entry must never replace one confirmed just now."""
    old = out.get(address)
    if old is None or FRESHNESS_RANK[fresh] > FRESHNESS_RANK[old[1]]:
        out[address] = (mac, fresh)


def neighbour_table():
    """Which devices this computer currently knows about: {ip: (mac, freshness)}, where freshness
    is "fresh", "stale" or "" (not known). See FRESH_STATES. An address listed twice keeps its
    fresher entry (keep_fresher).

    On Linux (e.g. a Raspberry Pi) it runs `ip -4 neigh show`, which says how fresh each entry is,
    and falls back to /proc/net/arp (no tools needed, but no freshness) if that can't be run. On
    macOS it reads the built-in `arp` command, which gives no freshness either."""
    out = {}
    if os.path.exists("/proc/net/arp"):
        try:
            done = subprocess.run([IP_TOOL, "-4", "neigh", "show"], capture_output=True, text=True, timeout=10)
            if done.returncode == 0:
                for line in done.stdout.splitlines():
                    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s.*\blladdr ([0-9a-fA-F:]{11,17})\b(.*)$", line.strip())
                    if not m:
                        continue
                    fresh = freshness_of(m.group(3).split())
                    if fresh is not None:
                        keep_fresher(out, m.group(1), tidy_mac(m.group(2)), fresh)
                return out
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 4 and re.fullmatch(r"[0-9a-f:]{17}", cols[3]) and cols[3] != "00:00:00:00:00:00":
                        out[cols[0]] = (cols[3], "")
        except OSError:
            pass
        return out
    try:
        text = subprocess.run([ARP, "-an"], capture_output=True, text=True, timeout=20).stdout
        for line in text.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})", line)
            if m:
                mac = tidy_mac(m.group(2))
                if mac != "ff:ff:ff:ff:ff:ff":
                    out[m.group(1)] = (mac, "")
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return out


def neighbours():
    """Which devices this computer currently knows about: {ip: mac}. See neighbour_table."""
    return {ip: mac for ip, (mac, _) in neighbour_table().items()}


def tidy_mac(text):
    """A hardware address in the usual form: lower case, two digits per part ('0:1b:...' -> '00:1b:...')."""
    return ":".join(part.zfill(2) for part in text.lower().split(":"))


# Keeping rules with the device, not the address. Rules, given and groups are kept under a device's
# IPv4 address, but a phone can be given a new address (a new private Wi-Fi address, or the router
# simply handing out a different number), and its old address can then go to another device. So
# every minute refresh_devices looks at which hardware address is at which IPv4 address and keeps
# the rules pointed at the right device. See docs/ARCHITECTURE.md, "When a device changes address".
QUIET_AFTER = 15 * 60          # seconds a device with rules must be unseen before it counts as "gone quiet"
NEW_DEVICE_DAYS = 3            # how recently a device must have first appeared to be offered as its replacement
MAX_EVENTS = 200               # notes of what QuietNet did to devices' rules, kept newest first
MAX_NOTICES = 10               # "may be the same device" notices shown at once
SHARED_AFTER = 3               # looks, each within an hour of the last, that must find one hardware address
                               # at two addresses at once before it counts as a range extender
KNOWN_MACS_DAYS = 30           # a hardware address unseen for this long is forgotten, unless rules belong to it
MAX_KNOWN_MACS = 5000          # the most hardware addresses remembered; the longest unseen are forgotten first
EXTENDER_OWNER = ("This device shares its hardware address with other devices, probably because it connects "
                  "through a Wi-Fi range extender, so QuietNet can't tell it apart from them. Its rules stay with "
                  "its address and can't follow it if that changes.")
EXTENDER_HERE = ("The device at this address now connects through a Wi-Fi range extender, so QuietNet can't tell "
                 "which device it is. The rules for %s still apply to this address.")


def clean_mac(text):
    """A hardware address in the usual form (six pairs of lower-case hex digits, '0:1b:..' padded
    to '00:1b:..'), or '' if it isn't one that belongs to a single device: not text, malformed,
    all zeros (an unfinished entry in the neighbour table), or a group address (broadcast and
    multicast, whose first byte is odd)."""
    if not isinstance(text, str):
        return ""
    parts = text.strip().lower().split(":")
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return ""
    mac = ":".join(p.zfill(2) for p in parts)
    if mac == "00:00:00:00:00:00" or int(parts[0], 16) & 1:
        return ""
    return mac


def named_devices():
    """{ip: name} for every device someone has given a name. Call holding db_lock."""
    return {ip: name for ip, name in db.execute("SELECT ip, name FROM devices") if name}


def own_rules(ip, given, count_group=True):
    """Does this address carry anything of its own: a name, a group (unless count_group is False),
    an internet switch, a blocked service, a schedule, or "cut live connections"? `given` is
    named_devices(). Reads S only."""
    scope = "device:" + ip
    return bool(ip in given or (count_group and ip in S.dev_group) or scope in S.off
                or S.svc_blocks.get(scope) or ip in S.enforced
                or any(x["scope"] == scope for x in S.schedules))


def holds_rules(ip):
    """Does this address carry real rules: an internet switch, a blocked service, a schedule or
    "cut live connections"? A name and a group alone don't count. Reads S only."""
    return own_rules(ip, {}, count_group=False)


def device_label(ip, given):
    """How to name a device in a message: the name it was given, or its address."""
    return given.get(ip) or ip


def add_event(ip, text, now=None):
    """Note something QuietNet did to a device's rules by itself, for the dashboard, keeping only
    the newest MAX_EVENTS. Call holding db_lock; the caller commits."""
    db.execute("INSERT INTO events(ts, ip, text) VALUES(?,?,?)", (time.time() if now is None else now, ip, text))
    db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)", (MAX_EVENTS,))


def set_owner(ip, mac, paused=False, guest=None):
    """Record which hardware address the rules under this address belong to, and whether they are
    paused. `guest` is (hardware address, group id) for a device never seen before that now has a
    paused address: it gets that group (the new-device group) while the pause lasts.
    Changes S and the database; call holding db_lock (the caller commits)."""
    S.dev_mac[ip] = mac
    guest = guest if paused else None
    if paused:
        S.paused_ips.add(ip)
    else:
        S.paused_ips.discard(ip)
    if guest:
        S.guest_group[ip] = guest
    else:
        S.guest_group.pop(ip, None)
    db.execute("INSERT OR REPLACE INTO device_mac(ip, mac, paused, guest_mac, guest_gid) VALUES(?,?,?,?,?)",
               (ip, mac, int(paused), guest[0] if guest else None, guest[1] if guest else None))


def drop_owner(ip):
    """Forget which device this address's rules belong to (it has none left). Call holding db_lock."""
    S.dev_mac.pop(ip, None)
    S.paused_ips.discard(ip)
    S.guest_group.pop(ip, None)
    db.execute("DELETE FROM device_mac WHERE ip=?", (ip,))


def fixed_addresses():
    """The addresses that are never treated as a household device here: this computer and the
    home router. Their rules never move and nothing moves onto them."""
    return {a for a in (S.local_ip, home_router() or S.router) if a}


def new_device_group():
    """The group a device seen for the first time is put in, or None (none chosen, or it was deleted)."""
    return S.new_device_group if S.new_device_group in S.group_names else None


def move_rules(a, b, mac):
    """Move everything kept under address `a` to address `b`: its name, its group, its own rules
    and schedules, "cut live connections" (with the hardware address to steer) and the note of
    which device it is. `mac` is the device's hardware address at `b` ('' if not known yet).
    `b` must carry no rules of its own (see holds_rules). A name or group it has gives way: `a`'s
    name and group replace them, and if `a` has none, `b` is left with none, so a departed
    visitor's group never sticks to the device that arrives. The history stays filed under the
    address each lookup came from.
    Changes S and the database together; call holding db_lock (this commits)."""
    sa, sb = "device:" + a, "device:" + b
    db.execute("DELETE FROM devices WHERE ip=?", (b,))
    db.execute("UPDATE devices SET ip=? WHERE ip=?", (b, a))
    S.dev_group.pop(b, None)
    db.execute("DELETE FROM device_group WHERE ip=?", (b,))
    if a in S.dev_group:
        S.dev_group[b] = S.dev_group.pop(a)
        db.execute("UPDATE device_group SET ip=? WHERE ip=?", (b, a))
    if sa in S.svc_blocks:
        S.svc_blocks[sb] = S.svc_blocks.pop(sa)
        db.execute("DELETE FROM service_blocks WHERE scope=?", (sb,))
        db.execute("UPDATE service_blocks SET scope=? WHERE scope=?", (sb, sa))
    if sa in S.off:
        S.off.discard(sa)
        S.off.add(sb)
        db.execute("DELETE FROM internet_off WHERE scope=?", (sb,))
        db.execute("UPDATE internet_off SET scope=? WHERE scope=?", (sb, sa))
    db.execute("UPDATE schedules SET scope=? WHERE scope=?", (sb, sa))
    if a in S.enforced:
        steer = mac or S.enforced_mac.get(a, "")
        S.enforced.discard(a)
        S.enforced_mac.pop(a, None)
        S.enforced.add(b)
        S.enforced_mac[b] = steer
        db.execute("DELETE FROM enforced WHERE ip=?", (b,))
        db.execute("UPDATE enforced SET ip=?, mac=? WHERE ip=?", (b, steer, a))
    drop_owner(a)
    if mac:
        set_owner(b, mac)
    else:
        drop_owner(b)
    S.device_warnings.pop(a, None)
    S.device_warnings.pop(b, None)
    S.follow = {k: v for k, v in S.follow.items() if k not in (a, b) and v not in (a, b)}
    S.device_notices = [n for n in S.device_notices if n["from"] not in (a, b) and n["to"] != b]
    db.commit()
    load_schedules()                     # also tells the enforcer and the answer cache that rules changed


def mac_times(macs):
    """{mac: (first seen, last seen)} for those of these hardware addresses that are remembered.
    Asks only about the ones given, a few hundred at a time, never the whole table.
    Call holding db_lock."""
    macs, out = sorted(macs), {}
    for i in range(0, len(macs), 500):
        part = macs[i:i + 500]
        out.update((mac, (first, last)) for mac, first, last in db.execute(
            "SELECT mac, first, last FROM known_macs WHERE mac IN (%s)" % ",".join("?" * len(part)), part))
    return out


def forget_old_macs(now):
    """Keep the record of hardware addresses small: forget those not seen for KNOWN_MACS_DAYS, and
    beyond MAX_KNOWN_MACS the longest unseen, except any that rules belong to. Without this, every
    private Wi-Fi address and visitor, or a device on the network making up addresses on purpose,
    would add a row for good. A forgotten address counts as new if it ever comes back.
    Call holding db_lock; the caller commits."""
    keep = "SELECT mac FROM device_mac UNION SELECT guest_mac FROM device_mac WHERE guest_mac IS NOT NULL"
    db.execute("DELETE FROM known_macs WHERE last<? AND mac NOT IN (%s)" % keep, (now - KNOWN_MACS_DAYS * 86400,))
    db.execute("DELETE FROM known_macs WHERE mac IN (SELECT mac FROM known_macs WHERE mac NOT IN (%s) "
               "ORDER BY last DESC LIMIT -1 OFFSET ?)" % keep, (MAX_KNOWN_MACS,))
    db.execute("DELETE FROM shared_macs WHERE last<?", (now - KNOWN_MACS_DAYS * 86400,))


def note_shared_macs(doubled, now):
    """Count each hardware address in `doubled`, seen at two or more addresses at the same moment
    (each confirmed reachable just now). One found like that SHARED_AFTER times, each look within
    an hour of the last, is a range extender standing in for the devices behind it, not one
    device, and stays counted as one (S.shared_macs). A phone that has just changed address can
    show at both for a moment; once is never enough. Call holding db_lock; the caller commits."""
    for mac in sorted(doubled):
        db.execute("INSERT INTO shared_macs(mac, hits, last) VALUES(?,1,?) ON CONFLICT(mac) DO UPDATE SET "
                   "hits=CASE WHEN hits>=? THEN hits+1 WHEN last<? THEN 1 ELSE hits+1 END, last=excluded.last",
                   (mac, now, SHARED_AFTER, now - 3600))
    S.shared_macs = {mac for (mac,) in db.execute("SELECT mac FROM shared_macs WHERE hits>=?", (SHARED_AFTER,))}


def note_new_devices(present, given, now):
    """Record every hardware address in `present` ({ip: mac}) as seen, and put each one never seen
    before into the new-device group, if one is chosen and its address is free: nothing of its own
    but, perhaps, that same group, given to a device that is not here now (a visitor who has gone).
    The address of an absent device with rules of its own is left to refresh_devices. The very
    first look only records what is there (nothing then is "new"). Returns the hardware addresses
    seen for the first time. Call holding db_lock; the caller commits."""
    known = mac_times(set(present.values()))
    first_look = get_setting("macs_seeded", "") != "1" and not db.execute("SELECT 1 FROM known_macs LIMIT 1").fetchone()
    gid = new_device_group()
    on_now = set(present.values())
    new = set()
    for ip, mac in sorted(present.items()):
        if mac in known:
            db.execute("UPDATE known_macs SET ip=?, last=? WHERE mac=?", (ip, now, mac))
            continue
        db.execute("INSERT OR REPLACE INTO known_macs VALUES(?,?,?,?)", (mac, ip, now, now))
        if first_look:
            continue
        new.add(mac)
        owner = S.dev_mac.get(ip)
        if (gid is None or holds_rules(ip) or ip in given or (owner and owner in on_now)
                or S.dev_group.get(ip, gid) != gid):
            continue
        S.dev_group[ip] = gid
        db.execute("INSERT OR REPLACE INTO device_group VALUES(?,?)", (ip, gid))
        set_owner(ip, mac)
        add_event(ip, "A new device appeared at %s and was put in the %s group, as you asked for new devices."
                  % (ip, S.group_names[gid]), now)
        rules_changed()
    if first_look:
        db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('macs_seeded', '1')")
    return new


def device_notices_now(present, given, now, same_number=()):
    """Possible moves for the owner to confirm: a device with rules that has gone quiet (unseen for
    QUIET_AFTER) at about the time a device with a private Wi-Fi address and nothing of its own
    appeared for the first time. It may be the same phone or tablet with a new private address.
    `same_number` (from refresh_devices) adds the cases where such a device turned up at the very
    address the rules are kept under. Range extenders' hardware addresses take no part.
    Returns a list of {"from", "name", "to", "mac", "first", "same"}. Call holding db_lock."""
    on_now = set(present.values())
    seen = mac_times(set(S.dev_mac.values()) | on_now)
    quiet = []
    for a, mac in sorted(S.dev_mac.items()):
        last = seen.get(mac, (0, 0))[1]
        if mac not in on_now and mac not in S.shared_macs and last and now - last > QUIET_AFTER:
            quiet.append((a, last))
    fresh = [(b, mac, seen[mac][0]) for b, mac in sorted(present.items())
             if mac in seen and free_for_rules(b, given) and names.is_private_mac(mac) and mac not in S.shared_macs
             and b not in S.paused_ips and b not in S.follow and now - seen[mac][0] < NEW_DEVICE_DAYS * 86400]
    out = list(same_number)
    for a, last in quiet:
        for b, mac, first in fresh:
            if first >= last - QUIET_AFTER:
                out.append({"from": a, "name": device_label(a, given), "to": b, "mac": mac, "first": first,
                            "same": False})
    return out[:MAX_NOTICES]


def free_for_rules(ip, given):
    """Does this address carry nothing of its own apart, perhaps, from a group (which a device can
    be given automatically as a new device)? Such an address can take another's rules."""
    return not own_rules(ip, given, count_group=False)


def read_table(table, fixed):
    """Tidy a neighbour table (from neighbour_table, or a stand-in {ip: mac} in the tests) into
    {ip: mac} of the devices to follow, and the set of hardware addresses found at two or more
    addresses that were each confirmed reachable just now (see note_shared_macs).

    Malformed, all-zero, broadcast and multicast hardware addresses are dropped, and so are this
    computer and the router (`fixed`), by address and by hardware address. When one hardware
    address is listed at several addresses and exactly one of them was confirmed just now, only
    that one counts: Linux keeps stale entries for a long time, so a device that has moved can
    still be listed at its old address."""
    seen_at = {}
    for ip, entry in (table or {}).items():
        mac, fresh = entry if isinstance(entry, tuple) and len(entry) == 2 else (entry, "")
        try:
            ip = str(ipaddress.IPv4Address(str(ip)))
        except ValueError:
            continue
        mac = clean_mac(mac)
        if mac:
            seen_at[ip] = (mac, fresh)
    fixed_macs = {seen_at[ip][0] for ip in fixed if ip in seen_at}
    by_mac = {}
    for ip, (mac, fresh) in seen_at.items():
        if ip not in fixed and mac not in fixed_macs:
            by_mac.setdefault(mac, []).append((ip, fresh))
    present, doubled = {}, set()
    for mac, spots in by_mac.items():
        confirmed = [ip for ip, fresh in spots if fresh == "fresh"]
        if len(confirmed) >= 2:
            doubled.add(mac)
        for ip in (confirmed if len(confirmed) == 1 else [ip for ip, _ in spots]):
            present[ip] = mac
    return present, doubled


def refresh_devices(table=None, now=None):
    """Keep each device's rules with the device, by hardware address. Run every minute by
    address_watcher, never on a lookup. `table` is {ip: mac} or {ip: (mac, freshness)} (the
    neighbour table when not given; see read_table).

    For each address A whose rules belong to a known hardware address X:
      - X is still at A: nothing to do (rules that were paused start applying again).
      - X, or the device now at A, is a range extender (S.shared_macs): rules stay with A, as they
        can't follow one device among many, and the page says so.
      - X is now at another address B with no rules of its own (a name or group at most, of a
        device not here now): everything moves to B, replacing those, and a note is kept.
      - X is at B, which has rules of its own: nothing is merged; while that lasts X's own rules
        apply to it at B (S.follow) and both devices show a warning.
      - a different device is at A (and X is not, or is at B): if it has a private Wi-Fi address
        and appeared since X was last seen, it may be X with a new address, so the rules keep
        applying and the owner is asked (a "same number" notice). Otherwise the rules are paused
        (kept for X) until X comes back, and a device never seen before gets the new-device group.
    Also records every hardware address seen, puts devices seen for the first time into the
    new-device group if one is chosen, and works out the "may be the same device" notices.
    This computer and the router never move and are never moved onto.

    Last, the same table is used to keep S.addr_device right (note_ipv4_addresses): which device
    each address belongs to, for filing the history. That is separate from the rules, which are
    still kept under addresses and moved as described above."""
    now = time.time() if now is None else now
    if table is None:
        table = neighbour_table()
    fixed = fixed_addresses()
    present, doubled = read_table(table, fixed)
    where = {}
    for ip, mac in present.items():
        where.setdefault(mac, []).append(ip)
    on_now = set(present.values())
    with db_lock:
        note_shared_macs(doubled, now)
        given = named_devices()
        new_macs = note_new_devices(present, given, now)
        forget_old_macs(now)
        for ip in list(S.dev_mac):                      # rules all removed: nothing left to follow
            if not own_rules(ip, given):
                drop_owner(ip)
        for ip, mac in present.items():                 # rules on an address whose device isn't known yet
            if ip not in S.dev_mac and own_rules(ip, given):
                set_owner(ip, clean_mac(S.enforced_mac.get(ip, "")) or mac)
        times = mac_times(set(S.dev_mac.values()) | on_now)
        gid = new_device_group()
        warnings, follow, same_number = {}, {}, []
        for a, mac in sorted(S.dev_mac.items()):
            if S.dev_mac.get(a) != mac or a in fixed:
                continue                                 # moved already in this pass, or never moves
            here = present.get(a)
            label = device_label(a, given)
            if here == mac:
                if a in S.paused_ips:
                    set_owner(a, mac)
                    add_event(a, "%s is back at %s, so its rules apply again." % (label, a), now)
                    rules_changed()
                continue
            if mac in S.shared_macs:
                warnings[a] = EXTENDER_OWNER
                if a in S.paused_ips:
                    set_owner(a, mac)
                    rules_changed()
                continue
            elsewhere = [b for b in where.get(mac, []) if b != a and b not in fixed]
            moved_away = len(elsewhere) == 1
            if moved_away:
                b = elsewhere[0]
                owner_b = S.dev_mac.get(b)
                if not holds_rules(b) and (owner_b in (None, mac) or owner_b not in on_now):
                    note = "%s moved from %s to %s; its rules moved with it." % (label, a, b)
                    if b in given or b in S.dev_group:
                        note += " The name or group that %s had before was replaced." % b
                    move_rules(a, b, mac)
                    add_event(b, note, now)
                    given = named_devices()
                    continue
                follow[b] = a
                warnings[a] = ("This device now has the address %s, which has rules of its own for another device, so "
                               "nothing was moved. Until you sort it out, the rules here apply to it there. Check both "
                               "and remove the rules you no longer want." % b)
                warnings[b] = ("The device now at this address used to be at %s, and the rules kept there apply to it "
                               "instead of these. Check both and remove the rules you no longer want." % a)
            if here is None:
                continue
            if here in S.shared_macs:                    # behind a range extender: can't tell who it is
                warnings.setdefault(a, EXTENDER_HERE % label)
                continue
            # A different device has this address now.
            guest = (here, gid) if gid is not None and here in new_macs else None
            if a in S.paused_ips:
                held = S.guest_group.get(a)
                if guest and held != guest:
                    set_owner(a, mac, paused=True, guest=guest)
                    rules_changed()
                elif held and held[0] != here:
                    set_owner(a, mac, paused=True)
                    rules_changed()
                continue
            first, last = times.get(here, (now, now))[0], times.get(mac, (0, 0))[1]
            if not moved_away and names.is_private_mac(here) and first >= last - QUIET_AFTER:
                same_number.append({"from": a, "name": label, "to": a, "mac": here, "first": first, "same": True})
                continue
            set_owner(a, mac, paused=True, guest=guest)
            add_event(a, "A different device now has the address %s, so the rules for %s are paused "
                         "until it comes back." % (a, label), now)
            rules_changed()
        for a in S.paused_ips:
            warnings.setdefault(a, "This number now belongs to a different device; the rules for %s are paused "
                                   "until it comes back." % device_label(a, given))
        if follow != S.follow:
            S.follow = follow
            rules_changed()
        S.device_warnings = warnings
        S.device_notices = device_notices_now(present, given, now, same_number)
        db.commit()
    note_ipv4_addresses(table, now)         # which device has which address, for the history


def known_mac_at(ip):
    """The hardware address last seen at this address: the live neighbour table first, then the
    record of every device seen, then the last scan. '' if none is known."""
    mac = clean_mac(neighbours().get(ip, ""))
    if mac:
        return mac
    for statement in ("SELECT mac FROM known_macs WHERE ip=? ORDER BY last DESC LIMIT 1",
                      "SELECT mac FROM seen WHERE ip=?"):
        row = sql(statement, (ip,))
        if row and clean_mac(row[0][0]):
            return clean_mac(row[0][0])
    return ""


def device_ip(text):
    """The address as text if it is an IPv4 address, else None."""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def move_rules_by_hand(a, b):
    """The owner's "Move the rules to this device": move everything kept under address `a` to
    address `b`. With `a` and `b` the same, it means "the device at this address now is the one
    these rules are for": the rules then belong to it (see same_device_by_hand).
    Returns an error message, or None when done."""
    a, b = device_ip(a), device_ip(b)
    if a is None or b is None:
        return "Those aren't device addresses."
    if a in fixed_addresses() or b in fixed_addresses():
        return "Rules can't be moved to or from this computer or the router."
    if a == b:
        return same_device_by_hand(a)
    mac = known_mac_at(b)
    with db_lock:
        given = named_devices()
        if not own_rules(a, given):
            return "There are no rules to move."
        if not free_for_rules(b, given):
            return ("That device already has rules of its own. Remove them first if you want to move "
                    "the other device's rules to it.")
        label = device_label(a, given)
        move_rules(a, b, mac)
        add_event(b, "You moved the rules for %s from %s to %s." % (label, a, b))
        db.commit()
    return None


def same_device_by_hand(a):
    """The owner says the device at address `a` now is the one its rules are for (a phone that
    made up a new private Wi-Fi address and was given the same number back): the rules belong to
    its hardware address from now on and apply to it, paused or not. Returns an error message, or
    None when done."""
    mac = known_mac_at(a)
    with db_lock:
        given = named_devices()
        if not own_rules(a, given):
            return "There are no rules to move."
        if not mac:
            return "QuietNet can't see which device has this address now. Try again in a minute."
        set_owner(a, mac)
        S.device_warnings.pop(a, None)
        S.device_notices = [n for n in S.device_notices if n["from"] != a]
        add_event(a, "You said the device now at %s is %s, so its rules apply to it." % (a, device_label(a, given)))
        db.commit()
    rules_changed()
    return None


def different_device_by_hand(a):
    """The owner says the device at address `a` now is not the one its rules are for: the rules
    are paused, kept for that device, until it comes back, and the device here gets the
    new-device group if one is chosen (it is new to the network: see refresh_devices). Returns an
    error message, or None when done."""
    a = device_ip(a)
    if a is None:
        return "That isn't a device address."
    here = known_mac_at(a)
    with db_lock:
        given = named_devices()
        owner = S.dev_mac.get(a)
        if not owner or not own_rules(a, given):
            return "There are no rules here to keep for another device."
        if here == owner:
            return "That is the device these rules belong to."
        gid = new_device_group()
        set_owner(a, owner, paused=True, guest=(here, gid) if here and gid is not None else None)
        S.device_notices = [n for n in S.device_notices if n["from"] != a]
        add_event(a, "You said the device now at %s is not %s, so its rules are paused until it comes back."
                  % (a, device_label(a, given)))
        db.commit()
    rules_changed()
    return None


def set_new_device_group(gid):
    """Choose the group a device seen for the first time is put in (None, or an unknown group, for none)."""
    with db_lock:
        S.new_device_group = gid if (isinstance(gid, int) and not isinstance(gid, bool)
                                     and gid in S.group_names) else None
        set_setting("new_device_group", "" if S.new_device_group is None else S.new_device_group)


def recent_device_events(limit=10):
    """The newest notes of what QuietNet did to devices' rules, from the last week, newest first.
    Asked on the read-only connection, so the status summary never waits for db_lock."""
    rows = read_sql("SELECT ts, ip, text FROM events WHERE ts>? ORDER BY id DESC LIMIT ?", (time.time() - 7 * 86400, limit))
    return [{"ts": ts, "ip": ip, "text": text} for ts, ip, text in rows]


def own_ipv6(announced=None):
    """This computer's own IPv6 addresses, the public ranges of the home network they belong to, and
    the one address to give devices as their DNS server. Returns (set of addresses, list of
    networks, address text or ''). Link-local and unique-local addresses are counted as this
    computer's but give no range (any such address is from the home network anyway). A range
    narrower than /64 is widened to /64, since home networks are /64 and an address handed out on its
    own often shows as /128. Read from /proc/net/if_inet6 on Linux and from `ifconfig` elsewhere.

    The address for devices must last: a "temporary" (privacy) address, or one being given up or
    still being checked, changes or vanishes within hours, so it is never chosen. A unique-local
    address (fc00::/7, set by the home router and kept when the internet provider changes the
    public range) is preferred over a public one. Link-local addresses (fe80::) are never chosen,
    as most devices cannot be told to use one for DNS.

    `announced` is the list of ranges real routers are announcing (S.router_prefixes), when the
    announcements are being listened for. A unique-local address is then only chosen if it is in
    one of them: a Thread border router (an Apple TV or HomePod mini) hands out a unique-local range
    of its own that disappears when it is unplugged. None means "not known": any will do."""
    found = []                                  # (address text, prefix length, lasts?)
    if os.path.exists("/proc/net/if_inet6"):
        try:
            with open("/proc/net/if_inet6") as f:
                for line in f:
                    cols = line.split()
                    if len(cols) >= 5 and len(cols[0]) == 32:
                        text = ":".join(cols[0][i:i + 4] for i in range(0, 32, 4))
                        # temporary 0x01, failed its check 0x08, being given up 0x20, still being checked 0x40
                        found.append((text, int(cols[2], 16), not int(cols[4], 16) & 0x69))
        except (OSError, ValueError):
            pass
    else:
        try:
            text = subprocess.run([IFCONFIG, "-a"], capture_output=True, text=True, timeout=10).stdout
            for m in re.finditer(r"inet6 ([0-9a-fA-F:]+)(?:%\S+)? prefixlen (\d+)([^\n]*)", text):
                passing = re.search(r"\b(temporary|deprecated|tentative|duplicated|detached)\b", m.group(3))
                found.append((m.group(1), int(m.group(2)), not passing))
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    own, ranges, local, public = set(), [], [], []
    for text, length, lasts in found:
        try:
            addr = ipaddress.IPv6Address(text)
        except ValueError:
            continue
        own.add(str(addr))
        if not (addr.is_multicast or addr.is_unspecified or any(addr in net for net in HOME_ONLY_V6)):
            net = ipaddress.IPv6Network("%s/%d" % (addr, min(length, 64)), strict=False)
            if net not in ranges:
                ranges.append(net)
            if lasts:
                public.append(str(addr))
        elif lasts and addr in HOME_ONLY_V6[2] and (announced is None or any(addr in n for n in announced)):
            local.append(str(addr))
    return own, ranges, (sorted(local) + sorted(public) + [""])[0]


# What `ndp -an` on a Mac prints in its "St" column, as the freshness words used here.
NDP_FRESHNESS = {"R": "fresh", "D": "fresh", "P": "fresh", "S": "stale"}


def ipv6_neighbour_table():
    """The devices this computer has recently talked to over IPv6: {IPv6 address: (hardware
    address, freshness)}, with freshness as in neighbour_table. From `ip -6 neigh` on Linux and
    `ndp -an` on a Mac. None if neither tool can be run or it reports a fault, which is not the
    same as "no neighbours": the dashboard says so, since nothing can then be matched.

    Entries the system has confirmed, is checking, or simply hasn't heard from for a while (stale)
    are all kept: a device's private IPv6 address is not handed on to another device, so a stale
    entry is still right about whose it is. Failed and unfinished entries are left out. An address
    listed twice keeps its fresher entry."""
    on_linux = os.path.exists("/proc/net/if_inet6")
    if on_linux:
        command, pattern = [IP_TOOL, "-6", "neigh", "show"], r"^([0-9a-fA-F:]+)\s.*\blladdr ([0-9a-fA-F:]{11,17})\b(.*)$"
    else:
        command = [NDP, "-an"]
        pattern = r"^([0-9a-fA-F:]+)(?:%\S+)?\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s(.*)$"
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    out = {}
    for line in done.stdout.splitlines():
        m = re.match(pattern, line.strip())
        if not m:
            continue
        rest = m.group(3).split()
        if on_linux:
            fresh = freshness_of(rest)
        else:                                   # after the hardware address: network card, expiry, state
            fresh = NDP_FRESHNESS.get(rest[2] if len(rest) > 2 else "", "")
        if fresh is None:
            continue
        try:
            keep_fresher(out, str(ipaddress.IPv6Address(m.group(1))), tidy_mac(m.group(2)), fresh)
        except ValueError:
            continue
    return out


def ipv6_neighbours():
    """The devices this computer has recently talked to over IPv6: {IPv6 address: hardware address}.
    Empty if the neighbour table can't be read. See ipv6_neighbour_table."""
    return {addr: mac for addr, (mac, _) in (ipv6_neighbour_table() or {}).items()}


def eui64_mac(address):
    """The hardware address an IPv6 address was built from, or '' if it wasn't built that way.

    Some devices make the second half of an IPv6 address from their hardware address (the "EUI-64"
    form): the first three bytes, then ff:fe, then the last three, with one bit of the first byte
    flipped. So 2001:db8::0211:22ff:fe33:4455 was built from 00:11:22:33:44:55.

    This is a hint only, and must never decide which device's rules a lookup gets. Any device can
    put someone else's hardware address into its own IPv6 address, and an address chosen at
    random can have ff:fe in the middle by chance. Which device an IPv6 address belongs to is
    decided by the neighbour table alone (refresh_ipv6_view); the hint is only shown to the owner
    (api_devices), and only when the neighbour table has seen that hardware address."""
    try:
        packed = ipaddress.IPv6Address(str(address).split("%", 1)[0]).packed
    except ValueError:
        return ""
    if packed[11:13] != b"\xff\xfe":
        return ""
    raw = bytes([packed[8] ^ 0x02]) + packed[9:11] + packed[13:16]
    return clean_mac(":".join("%02x" % b for b in raw))


def ipv4_by_hardware_address(table, scanned):
    """{hardware address: the IPv4 address its device is at}, for matching IPv6 addresses to
    devices. `table` is neighbour_table()'s answer; `scanned` is (ip, mac) rows from the last
    network scan, oldest first.

    The neighbour table is the live view, so any entry in it beats the scan. When it lists one
    hardware address at two addresses (a TV that moved from .65 to .67 keeps a stale entry at
    .65 for a long time), the one confirmed just now wins, then one of unknown freshness, then a
    stale one; never simply whichever line was printed last. Between two equally fresh, the one
    the device's rules are kept under (S.dev_mac) wins, then the lower address, so the answer is
    the same every time. Hardware addresses that can't be a device's own (all zeros, or a group
    address) are left out. A range extender's hardware address (S.shared_macs) is not: it still
    gets one address here, as it always has, and refresh_ipv6_view notes the IPv6 addresses behind
    it (S.v6_shared) so that each keeps its own share of lookups."""
    best = {}                                   # mac -> (how good, ip)
    for ip, mac in scanned:
        if clean_mac(mac):
            best[clean_mac(mac)] = ((-1, False), ip)
    for ip in sorted(table):
        mac, fresh = table[ip]
        mac = clean_mac(mac)
        if not mac:
            continue
        how_good = (FRESHNESS_RANK.get(fresh, 1), S.dev_mac.get(ip) == mac)
        if mac not in best or how_good > best[mac][0]:
            best[mac] = (how_good, ip)
    return {mac: ip for mac, (_, ip) in best.items()}


def ipv6_on_card(card, path="/proc/net/if_inet6"):
    """Does this network card have a working IPv6 address of its own (a link-local one, starting
    fe80)? True or False, or None when that can't be known: no card name, or the list of this
    computer's IPv6 addresses (`path`, Linux only) is missing or can't be read.

    This is how QuietNet knows it could have heard the router's IPv6 announcements. When IPv6 is
    switched off on a card (a system setting some guides recommend), Linux takes the card's IPv6
    addresses away and throws away every IPv6 message arriving on it before any program sees it.
    The announcement listener's socket still opens, and then hears nothing for ever, which must
    not be taken for "the router is not announcing IPv6".

    Only an address on this very card counts: Docker's own cards and the loopback keep theirs
    whatever the home network card is set to. One that failed its check (0x08) or is still being
    checked (0x40) doesn't count, as the card isn't receiving on it yet. The card's name is only
    ever compared with the file's own last column; it is never put into a command or a path."""
    if not card:
        return None
    try:
        with open(path) as f:
            for line in f:
                cols = line.split()
                if len(cols) < 6 or len(cols[0]) != 32 or cols[5] != card:
                    continue
                if (int(cols[0][:4], 16) & 0xffc0) == 0xfe80 and not int(cols[4], 16) & 0x48:
                    return True
    except (OSError, ValueError):
        return None
    return False


def can_hear_router():
    """Could this computer hear the home router's IPv6 announcements? True if the network card
    its home network is on (the one its default route uses) has working IPv6, False if it has
    not, None if that can't be known. See ipv6_on_card. Reads two small files; runs no tools."""
    return ipv6_on_card(enforcer.interface_and_gateway()[0])


def refresh_ipv6_view():
    """Look again at this computer's IPv6 addresses and ranges (for v6_source_allowed and 'this
    computer'), and match each IPv6 neighbour to an IPv4 device with the same hardware address,
    so a device's IPv6 lookups come under its IPv4 rules (see answer_query). IPv4 devices come from
    the last network scan (the 'seen' table, oldest first) and then the current neighbour table,
    which is the live view and so wins; see ipv4_by_hardware_address for how a stale entry is kept
    from beating a fresh one. If the IPv6 neighbour table can't be read, nothing is matched and
    S.v6_neighbours_ok says so for the dashboard.

    The scan table is read on the read-only connection (read_sql), so a look never waits for the
    database lock: a lookup from a new IPv6 address may be waiting on this very look, and the lock
    can be held for some seconds while an older household's data is moved (move_to_devices).

    IPv6 addresses whose hardware address is a range extender's (S.shared_macs) are noted in
    S.v6_shared, so each keeps its own share of lookups (share_key).

    Whether this computer's home network card has working IPv6 is noted too (S.v6_can_hear), with
    when a look first found that it has (S.v6_hear_since): the hour of listening behind "IPv6 is
    off on your hub" only counts while this computer could have heard the router (ipv6_dns_view).
    Losing it, or not knowing, starts that hour again."""
    with router_dns_lock:
        announced = list(S.router_prefixes) if S.ra_listening else None
    own, ranges, for_devices = own_ipv6(announced)
    can_hear = can_hear_router()
    scanned = read_sql("SELECT ip, mac FROM seen WHERE mac != '' ORDER BY ts") if read_db is not None else []
    by_mac = ipv4_by_hardware_address(neighbour_table(), scanned)
    table6 = ipv6_neighbour_table()
    matched = {addr: by_mac[mac] for addr, (mac, _) in (table6 or {}).items() if mac in by_mac}
    extenders = S.shared_macs
    shared = frozenset(addr for addr, (mac, _) in (table6 or {}).items() if mac in extenders)
    S.v6_own, S.v6_prefixes, S.v6_devices, S.v6_dns = own, ranges, matched, for_devices
    S.v6_shared = shared
    S.v6_table = table6 or {}               # kept for note_ipv6_addresses, which ipv6_look runs next
    S.v6_neighbours_ok = table6 is not None
    if can_hear is not True:
        S.v6_hear_since = None
    elif S.v6_hear_since is None:
        S.v6_hear_since = time.monotonic()
    S.v6_can_hear = can_hear
    S.v6_checked = time.monotonic()


def ipv6_look():
    """One look by ipv6_watcher: work the IPv6 view out again, then tell any lookup waiting for
    it (matched_ipv6_device) that it is done, whether or not it worked. Only after that is the
    record of which device has which IPv6 address brought up to date (note_ipv6_addresses): it
    may wait a moment for the database, and a waiting lookup must not wait with it."""
    S.v6_looking = True
    try:
        refresh_ipv6_view()
    except Exception as e:
        print("Could not check this computer's IPv6 addresses:", e, flush=True)
    finally:
        with v6_looked:
            S.v6_round += 1
            S.v6_looked_at = time.monotonic()
            S.v6_looking = False
            v6_looked.notify_all()
    try:
        note_ipv6_addresses()
    except Exception as e:
        print("Could not note which device has which IPv6 address:", e, flush=True)


def ipv6_watcher():
    """Background thread, started when this computer has IPv6: keep the IPv6 view up to date,
    looking again every IPV6_RECHECK seconds, or sooner when a lookup arrives from an IPv6 address
    no device is matched to (ask_for_ipv6_look), but never less than V6_QUICK_GAP seconds after
    the last look. Done here, never on a lookup, because it runs tools."""
    S.v6_watching = True
    try:
        while True:
            v6_wanted.clear()               # before the look: an ask that arrives during it earns another
            ipv6_look()
            if v6_wanted.wait(IPV6_RECHECK):
                time.sleep(max(0.0, V6_QUICK_GAP - (time.monotonic() - S.v6_looked_at)))
    finally:
        S.v6_watching = False


def read_router_advert(data):
    """Read one IPv6 router announcement ("router advertisement", ICMPv6 type 134). Returns
    {"lifetime": how long, in seconds, devices may send through the sender (0 = it is not a
    router for them), "servers": the DNS servers it names (its RDNSS parts, option 25) as
    (address text, seconds to keep using it), "prefixes": the address ranges it hands out (option
    3) as (network, seconds valid), "mac": the sender's hardware address as the message itself
    gives it (its source link-layer address, option 1; '' if it gives none, or one that could not
    belong to a single device)}, or None if the message is not a router announcement or is badly
    formed.

    The message comes from anyone on the home network, so every length is checked before it is
    used: the fixed 16-byte start, then each option's length byte (in 8-byte units; 0 is not
    allowed and would never move forward), which must fit inside what arrived. A DNS server part
    must be at least 24 bytes, an odd number of units, holding whole 16-byte addresses; a range
    part exactly 32 bytes. A bad option spoils the whole message, as the standard says. Each option
    takes at least 8 bytes, so the loop ends within len(data) / 8 steps. Multicast, unspecified,
    loopback and IPv4-style addresses are skipped, as no device would use them for DNS."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16 or data[0] != 134 or data[1] != 0:
        return None
    out = {"lifetime": int.from_bytes(data[6:8], "big"), "servers": [], "prefixes": [], "mac": ""}
    at = 16
    while at < len(data):
        if len(data) - at < 2:
            return None
        kind, units = data[at], data[at + 1]
        size = units * 8
        if units == 0 or at + size > len(data):
            return None
        if kind == 25:
            if units < 3 or units % 2 == 0:
                return None
            lifetime = int.from_bytes(data[at + 4:at + 8], "big")
            for start in range(at + 8, at + size, 16):
                addr = ipaddress.IPv6Address(bytes(data[start:start + 16]))
                if addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.ipv4_mapped:
                    continue
                out["servers"].append((str(addr), lifetime))
        elif kind == 1:
            # The sender's hardware address: 8 bytes on Ethernet and Wi-Fi (type, length, six bytes).
            # Another size belongs to another kind of network and is passed over; the first one counts.
            if units == 1 and not out["mac"]:
                out["mac"] = clean_mac(":".join("%02x" % b for b in data[at + 2:at + 8]))
        elif kind == 3:
            if units != 4:
                return None
            length = data[at + 2]
            if length <= 128:
                net = ipaddress.IPv6Network((bytes(data[at + 16:at + 32]), length), strict=False)
                out["prefixes"].append((net, int.from_bytes(data[at + 4:at + 8], "big")))
        at += size
    return out


def parse_router_advert(data):
    """The DNS servers one router announcement names, as a list of (address text, seconds to keep
    using it), or None if it is not a well-formed router announcement. See read_router_advert."""
    found = read_router_advert(data)
    return None if found is None else found["servers"]


def note_router_dns(servers, now, router_lifetime=1, prefixes=(), sender="", mac=""):
    """Remember the IPv6 DNS servers named in one router announcement (from read_router_advert),
    each until its stated lifetime runs out, but never more than RA_HOLD_MAX seconds without being
    named again, so a router that stops naming one (IPv6 switched off, say) is forgotten within the
    hour. A lifetime of 0 means "stop using this one now". At most RA_MAX_SERVERS are kept; past
    that the one due to be forgotten soonest makes way. Servers are noted from any announcement,
    since devices use them whoever sent it.

    Only an announcement from a real router (`router_lifetime` above 0) counts as the home
    network having IPv6 (S.ra_heard), and only its address ranges (`prefixes`) are remembered in
    S.router_prefixes, the same way. A Thread border router, such as an Apple TV or a HomePod mini,
    announces a range of its own with a lifetime of 0, and does so precisely when the home router's
    IPv6 is switched off; it must not make the network look as if it has IPv6.

    For a real router, the address the announcement came from (`sender`, its link-local address)
    and the hardware address it gave (`mac`) are kept too, in S.routers_v6, for RA_HOLD_MAX seconds
    after it was last heard and for RA_MAX_SERVERS routers at most. Nothing acts on them yet: they
    are what anyone on the home network claimed, shown in the status for the owner and kept for
    the work on steering IPv6. An announcement that gives no hardware address keeps the last one
    that sender gave."""
    with router_dns_lock:
        if router_lifetime > 0:
            S.ra_heard = now
            S.ra_heard_at = time.monotonic()
            if sender:
                S.routers_v6[sender] = {"mac": mac or S.routers_v6.get(sender, {}).get("mac", ""), "heard": now}
        for addr in [a for a, r in S.routers_v6.items() if now - r["heard"] >= RA_HOLD_MAX]:
            del S.routers_v6[addr]
        while len(S.routers_v6) > RA_MAX_SERVERS:
            del S.routers_v6[min(S.routers_v6, key=lambda a: S.routers_v6[a]["heard"])]
        if router_lifetime > 0:
            for net, valid in prefixes:
                if valid == 0:
                    S.router_prefixes.pop(net, None)
                else:
                    S.router_prefixes[net] = now + min(valid, RA_HOLD_MAX)
        for net in [n for n, until in S.router_prefixes.items() if until <= now]:
            del S.router_prefixes[net]
        while len(S.router_prefixes) > RA_MAX_SERVERS:
            del S.router_prefixes[min(S.router_prefixes, key=S.router_prefixes.get)]
        for addr, lifetime in servers:
            if lifetime == 0:
                S.router_v6_dns.pop(addr, None)
                continue
            S.router_v6_dns[addr] = now + min(lifetime, RA_HOLD_MAX)
        for addr in [a for a, until in S.router_v6_dns.items() if until <= now]:
            del S.router_v6_dns[addr]
        while len(S.router_v6_dns) > RA_MAX_SERVERS:
            del S.router_v6_dns[min(S.router_v6_dns, key=S.router_v6_dns.get)]


# Linux's "tell me each packet's hop limit" option and the note it adds (IPV6_RECVHOPLIMIT and
# IPV6_HOPLIMIT). Python names them on Linux; their numbers there have always been 51 and 52.
IPV6_RECVHOPLIMIT = getattr(socket, "IPV6_RECVHOPLIMIT", 51)
IPV6_HOPLIMIT = getattr(socket, "IPV6_HOPLIMIT", 52)


def hop_limit(ancillary):
    """The hop limit Linux noted for a received packet, from recvmsg's extra details, or None if
    it noted none."""
    for level, kind, value in ancillary or ():
        if level == socket.IPPROTO_IPV6 and kind == IPV6_HOPLIMIT and len(value) >= 4:
            return struct.unpack("=i", value[:4])[0]
    return None


def open_ra_socket():
    """Open a socket that receives the router's IPv6 announcements, or return None if that can't be
    done here. Linux only, and it needs the right to read raw network messages (NET_RAW), which the
    QuietNet container has. On a Mac, or without that right, QuietNet carries on without it. The
    socket is only ever read from; nothing is sent. Where the system allows, it is told to pass on
    router announcements only, so other IPv6 control messages are not even handed over."""
    if not os.path.exists("/proc/net/if_inet6") or not hasattr(socket, "IPPROTO_ICMPV6"):
        return None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except (OSError, ValueError):
        return None
    try:
        words = [0xFFFFFFFF] * 8                        # a set bit means "don't pass this type on"
        words[134 >> 5] &= ~(1 << (134 & 31))
        sock.setsockopt(socket.IPPROTO_ICMPV6, 1, struct.pack("=8I", *words))   # 1 = ICMP6_FILTER
    except OSError:
        pass                                            # not needed: parse_router_advert checks the type
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)    # so the listener can check it
    except OSError:
        pass
    return sock


def router_advert_listener(sock=None):
    """Background thread: listen for the router's IPv6 announcements and note which DNS servers it
    tells devices to use (see parse_router_advert and note_router_dns). A router that hands out its
    own IPv6 DNS server, as a BT Smart Hub does as it ships, lets devices send some lookups past
    QuietNet, and the dashboard warns about it. Best effort: if the socket can't be opened (see
    open_ra_socket) this returns quietly. Announcements must come from a link-local address with a
    hop limit of 255, as real ones always do (one that has passed through a router arrives with
    less, so it can't have come from the home network); when the system gives no hop limit, the
    address check alone applies. At most RA_MAX_PER_SECOND are looked at each second, so a flood of
    them costs little. Never sends anything.

    The address each announcement came from is passed on with it, so a real router's link-local
    address and hardware address are kept (note_router_dns). When listening began is kept too
    (S.ra_since), so the dashboard only says "IPv6 is off on your hub" after a full hour of
    listening; it is cleared when listening stops."""
    sock = sock or open_ra_socket()
    if sock is None:
        return
    S.ra_since = time.monotonic()
    S.ra_listening = True
    window, looked = time.monotonic(), 0
    try:
        while True:
            try:
                data, ancillary, _, addr = sock.recvmsg(RA_READ_BYTES, socket.CMSG_SPACE(4))
            except OSError as e:
                print("Stopped listening for the router's IPv6 announcements:", e, flush=True)
                return
            now = time.monotonic()
            if now - window >= 1:
                window, looked = now, 0
            if looked >= RA_MAX_PER_SECOND:
                continue
            looked += 1
            try:
                sender = ipaddress.IPv6Address(str(addr[0]).split("%")[0])
                if not sender.is_link_local:
                    continue
            except (ValueError, IndexError, TypeError):
                continue
            if hop_limit(ancillary) not in (None, 255):
                continue
            found = read_router_advert(data)
            if found is not None:
                note_router_dns(found["servers"], time.time(), found["lifetime"], found["prefixes"],
                                sender=str(sender), mac=found["mac"])
    finally:
        S.ra_listening = False
        S.ra_since = None


# How recently the IPv6 view must have been worked out for "this computer holds no public IPv6
# address" to count as something seen, not something assumed (see ipv6_dns_view).
V6_VIEW_FRESH = 3 * IPV6_RECHECK


def ipv6_dns_view(now=None, mono=None):
    """What the dashboard shows about IPv6 and DNS (the "ipv6" part of GET /api/status): the
    address to give devices for IPv6 DNS ('' if QuietNet isn't taking lookups over IPv6 or has no
    lasting address), whether the router's announcements are being listened for and when it last
    announced IPv6, the IPv6 DNS servers it names, and which of those are not this computer.
    "in_use" says the home network has IPv6: this computer has a public IPv6 range, or the router
    announced IPv6 within the last hour (devices are then marked "can bypass QuietNet over IPv6";
    api_devices marks them as well while "router_dns_not_ours" is not empty).
    A server only counts as this computer if QuietNet is taking lookups over IPv6 on that address.

    "hub_off" is the confirmation "IPv6 is off on your hub". It is true only when every one of
    these holds, so that not knowing never looks like being protected:
      - the announcement listener is running, this computer could hear the router, and both have
        been so for a full hour (RA_HOLD_MAX) without a break ("listening_for" is how long, in
        seconds; 0 when either isn't so). A listener that never started, or a restart, starts
        the hour again;
      - this computer's home network card has working IPv6 of its own ("can_hear": true, false, or
        null for not known; see ipv6_on_card). With IPv6 switched off on that card the listener
        runs but hears nothing, so the hour only counts from when a look first found it working
        (S.v6_hear_since), and starts again if it is lost;
      - no real router was heard announcing IPv6 in that hour;
      - this computer holds no public IPv6 address, and that was looked at in the last few minutes
        (V6_VIEW_FRESH), not assumed because the IPv6 watcher isn't running;
      - nothing on the home network is currently naming an IPv6 DNS server other than this
        computer ("router_dns_not_ours" is empty), whoever announced it and whatever its router
        lifetime. A router with no IPv6 internet but a private range still announces, with a
        router lifetime of 0, and can name itself as DNS server; devices use that server, so their
        lookups still skip QuietNet. Named servers are forgotten within the hour once nothing
        names them, so this cannot hold the confirmation back for good.
    The hour is measured with time.monotonic() (`mono`), not the clock: a Pi has no clock of its
    own, and the jump when it gets the right time after starting must not count as an hour.

    "routers" lists the real routers heard in the last hour (link-local address, the hardware
    address each gave, when last heard), most recent first. "neighbours_ok" is whether the IPv6
    neighbour table could be read at the last look (null before the first), and "taking_lookups"
    whether the filter is listening on IPv6 at all; the home page warns when lookups arrive over
    IPv6 but can't be matched to devices."""
    now = time.time() if now is None else now
    mono = time.monotonic() if mono is None else mono
    with router_dns_lock:
        named = sorted(a for a, until in S.router_v6_dns.items() if until > now)
        heard, heard_at = S.ra_heard, S.ra_heard_at
        routers = sorted(({"address": a, "mac": r["mac"], "heard": r["heard"]}
                          for a, r in S.routers_v6.items() if now - r["heard"] < RA_HOLD_MAX),
                         key=lambda r: (-r["heard"], r["address"]))
    ours = S.v6_own if S.dns_ipv6 else set()
    not_ours = [a for a in named if a not in ours]
    in_use = bool(S.v6_prefixes) or bool(heard and now - heard < RA_HOLD_MAX)
    since, hear_since, can_hear = S.ra_since, S.v6_hear_since, S.v6_can_hear
    if S.ra_listening and since is not None and hear_since is not None and can_hear is True:
        listening_for = max(0, int(mono - max(since, hear_since)))
    else:
        listening_for = 0
    quiet = heard_at is None or mono - heard_at >= RA_HOLD_MAX
    looked = S.v6_checked is not None and mono - S.v6_checked < V6_VIEW_FRESH
    return {"dns_address": S.v6_dns if S.dns_ipv6 else "", "listening": S.ra_listening,
            "listening_for": listening_for, "can_hear": can_hear,
            "router_heard": heard, "router_dns": named, "in_use": in_use,
            "hub_off": listening_for >= RA_HOLD_MAX and quiet and looked and not in_use and not not_ours,
            "routers": routers, "neighbours_ok": S.v6_neighbours_ok, "taking_lookups": S.dns_ipv6,
            "router_dns_not_ours": not_ours}


def hint_refresher():
    """Background thread: every two minutes (or soon after a network scan), look for a name for
    each device this computer knows about, so the dashboard can suggest one. The asking is done by
    NAMER (names.py), which never takes much more than names.ROUND_SECONDS however devices behave.
    Never run on a lookup or a dashboard request."""
    while True:
        try:
            devices = {ip: mac for ip, mac in neighbours().items() if ip != S.local_ip}
            S.hints = NAMER.round(devices)
        except Exception as e:
            print("Could not look for device names:", e, flush=True)
        NAMES_WANTED.wait(120)
        NAMES_WANTED.clear()


def reverse_name(ip):
    """The host name the network reports for an address, without its domain, or '' if none."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name.split(".")[0]
    except OSError:
        return ""


# Finds device names (names.py). Reverse lookups go through reverse_name, looked up afresh on each
# call so a stand-in put in its place is used. NAMES_WANTED asks hint_refresher to look again now.
NAMER = names.Namer(reverse=lambda ip: reverse_name(ip))
NAMES_WANTED = threading.Event()


MAX_SCAN = 1024        # the most addresses one network scan knocks on


def home_subnet(local_ip):
    """The home network this computer's address belongs to, e.g. 192.168.4.0/22.

    Read from the routing table where the system has one we can read (Linux, e.g. a Raspberry
    Pi). Elsewhere, or if it can't be read, the usual home size is assumed: the 256 addresses
    sharing the first three numbers with ours."""
    try:
        me = ipaddress.IPv4Address(local_ip)
        iface = enforcer.interface_and_gateway()[0]
        subnet = enforcer.local_subnet(iface) if iface else None
        if subnet is not None and me in subnet and subnet.prefixlen < 31:
            return subnet
        return ipaddress.IPv4Network("%s/24" % local_ip, strict=False)
    except ValueError:
        return None


def scan_targets(local_ip, subnet):
    """Which addresses a network scan knocks on: (the addresses, whether the list was cut short).

    Every usable address on the home network, but at most MAX_SCAN of them. On a bigger network
    the MAX_SCAN addresses around this computer's own are chosen, as that is where a home
    router hands out addresses."""
    me = ipaddress.IPv4Address(local_ip)
    block = subnet
    if subnet.num_addresses - 2 > MAX_SCAN:
        block = ipaddress.IPv4Network("%s/%d" % (me, 32 - (MAX_SCAN.bit_length() - 1)), strict=False)
    hosts = [ip for ip in block if ip not in (subnet.network_address, subnet.broadcast_address)]
    return [str(ip) for ip in hosts], block != subnet


def scan_plan():
    """Work out what a network scan will cover, keep it in S.scan_info for the dashboard, and
    return (the home network, the addresses to knock on). (None, []) if this computer has no
    usable address on a home network yet."""
    subnet = home_subnet(S.local_ip)
    if subnet is None or S.local_ip.startswith("127."):
        S.scan_info = {"network": "", "addresses": 0, "capped": False}
        return None, []
    targets, capped = scan_targets(S.local_ip, subnet)
    S.scan_info = {"network": str(subnet), "addresses": len(targets), "capped": capped}
    return subnet, targets


def scan_network():
    """Find every device on the home network (every address on it, up to MAX_SCAN)."""
    S.scan_state = "scanning"
    try:
        subnet, targets = scan_plan()
        if subnet is None:
            return
        # Knock on every address. Any device that is switched on has to reveal its
        # hardware address to this computer in order to receive the knock.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(2):
                for ip in targets:
                    try:
                        sock.sendto(b"\0", (ip, 9))
                    except OSError:
                        pass
                time.sleep(1.2)
        skip = (subnet.network_address, subnet.broadcast_address)
        found = {}
        for ip, mac in neighbours().items():
            try:
                addr = ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            if addr in subnet and addr not in skip:
                found[ip] = mac
        found.setdefault(S.local_ip, "")
        hosts, asked = {}, queue.Queue()

        def name_of(ip):
            """Ask the network for one device's name, and say when that is done, name or no name."""
            try:
                hosts[ip] = reverse_name(ip)
            finally:
                asked.put(ip)
        pool = Workers(32)              # daemon threads: a slow name never holds up the program's end
        for ip in found:
            pool.submit(name_of, ip)
        pool.finish()
        deadline = time.time() + 8
        # Wait for the names before taking db_lock: these are network waits of up to 8 seconds,
        # and the dashboard and the history writer would otherwise wait behind them.
        try:
            for _ in found:
                asked.get(timeout=max(0.1, deadline - time.time()))
        except queue.Empty:
            pass                        # out of time: a device not yet answered for keeps the name it had
        now = time.time()
        with db_lock:
            for ip in found:
                host = hosts.get(ip, "")
                db.execute("""INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                              mac=excluded.mac, ts=excluded.ts,
                              host=CASE WHEN excluded.host='' THEN seen.host ELSE excluded.host END""",
                           (ip, found[ip], host, now))
            db.commit()
        NAMES_WANTED.set()          # ask the devices just found for their names now, not in two minutes
    except Exception as e:
        print("Scan problem:", e, flush=True)
    finally:
        S.scan_ts = time.time()
        S.scan_state = "idle"


def api_status():
    """GET /api/status: the summary shown at the top of every dashboard page."""
    now = time.time()
    total, blocked = read_sql("SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM queries WHERE ts>?", (now - 86400,))[0]
    return {
        "ip": S.local_ip, "dns_ok": S.dns_error is None, "dns_error": S.dns_error, "dns_port": S.dns_port,
        "paused_for": max(0, int(S.paused_until - now)), "junk_on": S.junk_on,
        "other_dns_all": S.other_dns_all, "no_ipv6_all": S.no_ipv6_all,
        "kill": "all" in S.off, "clock": time.strftime("%H:%M"),
        "junk_count": S.junk_count,
        "community": {"installed": bool(S.junk_community), "count": len(S.junk_community),
                      "updated": os.path.getmtime(COMMUNITY_FILE) if os.path.exists(COMMUNITY_FILE) else None,
                      "state": S.list_state, "error": S.list_error},
        "today": {"total": total, "blocked": blocked},
        "scan": dict(S.scan_info, state=S.scan_state, ts=S.scan_ts),
        "enforcer": dict(ENF.status() if ENF else {"available": False, "reason": "", "active": False},
                         shared=dict(S.shared_left)),
        "ipv6": ipv6_dns_view(now),
        "new_device_group": S.new_device_group,
        "device_notices": list(S.device_notices),
        "device_events": recent_device_events(),
        # The device tables: "ready", or where the one-off move of an older household's data has
        # got to (see move_to_devices), with anything the owner should be told, and whether older
        # history is still being given its device.
        "devices": {"state": S.devices_state, "notice": S.devices_notice, "filling": S.history_fill},
    }


# When each device last looked something up. A plain "GROUP BY client" would walk every entry of
# the q_client_ts index (up to MAX_HISTORY_ROWS) on every dashboard refresh. This instead hops from
# one device to the next in that index, and reads each device's latest time from its end, so the
# work grows with the number of devices, not with the size of the history.
LAST_SEEN_SQL = """
    WITH RECURSIVE c(x) AS (
        SELECT MIN(client) FROM queries
        UNION ALL
        SELECT (SELECT MIN(client) FROM queries WHERE client>x) FROM c WHERE x IS NOT NULL)
    SELECT x, (SELECT MAX(ts) FROM queries WHERE client=x) FROM c WHERE x IS NOT NULL"""


# Each device's history in one question: when it last looked something up, and its counts since a
# time. It hops from one device to the next in the q_device_ts index (as LAST_SEEN_SQL does with
# addresses) and reads each device's figures from that index alone, so the work grows with the
# number of devices and the size of the last day, not with the size of the history.
DEVICE_HISTORY_SQL = """
    WITH RECURSIVE c(x) AS (
        SELECT MIN(device) FROM queries
        UNION ALL
        SELECT (SELECT MIN(device) FROM queries WHERE device>x) FROM c WHERE x IS NOT NULL)
    SELECT x, (SELECT MAX(ts) FROM queries WHERE device=x),
           (SELECT COUNT(*) FROM queries WHERE device=x AND ts>?1),
           (SELECT COALESCE(SUM(blocked), 0) FROM queries WHERE device=x AND ts>?1)
    FROM c WHERE x IS NOT NULL"""
# Lookups since a time that are still waiting to be filed against a device, counted by the address
# they were recorded under. There are few of them (tidy_history files them within minutes), except
# just after an older household's data is moved over, when the newest rows are done first.
UNFILED_COUNTS_SQL = """SELECT client, COUNT(*), COALESCE(SUM(blocked), 0) FROM queries INDEXED BY q_device_ts
                        WHERE device IS NULL AND ts>? GROUP BY client"""
# Each address's newest lookup, and the device it is filed against (empty while it is waiting).
# Hops through q_client_ts from one address to the next, as LAST_SEEN_SQL does.
NEWEST_BY_ADDRESS_SQL = """
    WITH RECURSIVE c(x) AS (
        SELECT MIN(client) FROM queries
        UNION ALL
        SELECT (SELECT MIN(client) FROM queries WHERE client>x) FROM c WHERE x IS NOT NULL)
    SELECT x, q.ts, q.device FROM c JOIN queries q
        ON q.id = (SELECT id FROM queries WHERE client=x ORDER BY ts DESC, id DESC LIMIT 1)
    WHERE x IS NOT NULL"""


def api_devices(everything=False):
    """GET /api/devices: one entry for each device, with its name, group, switches and today's
    counts, and when (if in the last 24 hours) it last tried to use another DNS service.

    A device is one hardware address (see the "devices" part of this file), so a TV that moved from
    .65 to .67 is one entry with the history of both, and an address handed from one device to
    another shows each device's own history. Each entry carries:
      "id"         the device's number (null for an address listed on its own: see below);
      "kind"       "hw", "addr", "pi" (this computer) or "hub" (the home router);
      "macs"       its hardware addresses ("mac" is the first, as before);
      "addresses"  the addresses it has now or had in the last day, each as {"address", "first",
                   "last", "now"}: when it was first and last confirmed there, and whether it is
                   there now;
      "ip"         the one address it is listed and controlled under: the IPv4 address it has now,
                   else the last it had that no other device has since been seen at, else an IPv6
                   address. Empty for a device that has left and whose address has gone to
                   another device: its history is kept under its number all the same. Such a
                   device is only listed when `everything` is true (GET /api/devices?all=1),
                   because a page written before the device tables, as an older relay may still
                   serve, knows every card by its address and could not show or open it.
    Names, groups and rules are still kept under addresses, so those fields are read from "ip". An
    address that carries a name or rules of its own, but is not the address its device is listed
    under, keeps an entry of its own ("id" null, "kind" "addr"), or its rules could not be seen or
    removed. So does an address no device is known for. No two entries share an "ip": when a
    device is listed under an address, what that address carries shows on that device's entry
    only, whichever device an old scan found there.

    Listed are the devices with any history, those found by a scan, those with rules that follow
    them (S.dev_mac) or a notice, and every address that carries a name, a group or rules,
    whoever has it now and whether or not it has any history: a rule put on the card of a device
    that was away has no recorded owner, and must not drop out of sight when the device comes
    back at another address. (An address whose name was cleared, and that carries nothing else,
    is not listed for that alone.) Lookups still waiting to be filed against a device count
    towards the device that has their address now. On an older database not moved to the device
    tables yet, the list is by address, as it was (api_devices_by_address).

    "v6_bypass" and "same_as" are as described in api_devices_by_address; "same_as" is only ever
    set on an address listed on its own."""
    if not S.devices_ready:
        return api_devices_by_address()
    now = time.time()
    since = now - 86400
    # Only names that say something: clearing a name leaves a row with an empty one, and that must
    # not count as the address carrying a name of its own (own_rules).
    given = {ip: name for ip, name in sql("SELECT ip, name FROM devices") if name}
    scanned = sql("SELECT ip, mac, host, ts FROM seen")
    hints = S.hints
    v6 = ipv6_dns_view()
    v6_on = v6["in_use"] or bool(v6["router_dns_not_ours"])
    # Copies, taken without a lock: the looks that keep these replace or add to them as we read.
    kinds, current, uses, hw = dict(S.device_kind), S.addr_device, dict(S.addr_use), dict(S.hw_device)
    shared, notices = S.shared_macs, list(S.device_notices)
    macs_of, held, scan_owner, scanned_at = {}, {}, {}, {}
    for mac, number in sorted(hw.items()):
        macs_of.setdefault(number, []).append(mac)
    for addr, use in uses.items():
        held.setdefault(use[0], []).append((addr, use[1], use[2]))
    only_at = dict(S.addr_only)
    key_of = {number: addr for addr, number in only_at.items()}
    for ip, mac, _, ts in scanned:
        mac = clean_mac(mac)
        if mac and mac not in shared and hw.get(mac) in kinds:
            scan_owner[ip] = hw[mac]
            scanned_at.setdefault(hw[mac], []).append((ts or 0, ip))

    def holder(addr):
        """The device an address belongs to: the one confirmed there now, else the last one seen
        there, else the one the last scan found there, else the device known only by that
        address. None if no device is known for it."""
        number = current.get(addr)
        if number is None:
            number = uses[addr][0] if addr in uses else scan_owner.get(addr, only_at.get(addr))
        return number if number in kinds else None

    homes = {}

    def home(number):
        """The one address a device is listed and controlled under ("ip"), or '' if it has none
        of its own now. See the docstring above for the order."""
        if number not in homes:
            mine = [use for use in held.get(number, []) if holder(use[0]) == number]
            v4 = [(last, addr) for addr, _, last in mine if ":" not in addr]
            pools = ([x for x in v4 if current.get(x[1]) == number], v4,
                     [x for x in scanned_at.get(number, []) if ":" not in x[1] and holder(x[1]) == number],
                     [(last, addr) for addr, _, last in mine])
            only = key_of.get(number)
            if kinds[number] == "pi":
                homes[number] = S.local_ip
            elif any(pools):
                homes[number] = max(next(pool for pool in pools if pool))[1]
            else:
                homes[number] = only if only and holder(only) == number else ""
        return homes[number]

    out = {}

    def card(ip, number=None):
        """The entry for a device (by its number), or for the address `ip` listed on its own,
        made with empty figures the first time it is asked for."""
        key = "address " + ip if number is None else number
        if key not in out:
            kind = kinds.get(number, "addr")
            mine = macs_of.get(number, [])
            tip = hints.get(ip, {})
            this_computer = kind == "pi" or (number is None and ip == S.local_ip)
            out[key] = {
                "ip": ip, "id": number, "kind": kind, "name": given.get(ip) or "", "hint": tip.get("name", ""),
                "hint_source": tip.get("source", ""), "hint_detail": tip.get("detail", ""),
                "mac": mine[0] if mine else "", "macs": list(mine), "addresses": [], "same_as": "",
                "this_computer": this_computer, "last": 0, "n": 0, "nb": 0, "on_network": 0,
                "v6_bypass": v6_on and not this_computer,
                "group": S.dev_group.get(ip), "off": internet_off_for(ip),
                "enforced": ip in S.enforced, "other_dns": other_dns_since(ip, since),
                "paused": ip in S.paused_ips, "warning": S.device_warnings.get(ip, "")}
        return out[key]

    def card_at(addr, number=None):
        """The entry that something known about an address belongs to: its device's (`number`
        when a hardware address already says which device, else whichever device has the address).
        But an address with a name or rules of its own that is not the one its device is listed
        under keeps an entry of its own, and so does an address no device is known for.

        When the last scan saw one device at an address but another device is listed under that
        address now, what the address carries already shows on that other device's entry, and the
        scan counts for the device it saw, wherever that is listed now. A scan row stays until the
        next scan, and must never make a second entry for an address a device is listed under."""
        here = holder(addr)
        if number is None:
            number = here
        if number is None:
            return card(addr)
        if home(number) != addr and (own_rules(addr, given) or addr in S.dev_mac or addr in S.device_warnings):
            if here is None or home(here) != addr:
                return card(addr)               # no device is listed under this address: an entry of its own
        return card(home(number), number)

    # Three small questions about the history, each answered from an index.
    for number, last, n, nb in read_sql(DEVICE_HISTORY_SQL, (since,)):
        if number in kinds:
            card(home(number), number).update(last=last or 0, n=n, nb=nb)
    for client, n, nb in read_sql(UNFILED_COUNTS_SQL, (since,)):
        if client:
            d = card_at(client)
            d.update(n=d["n"] + n, nb=d["nb"] + nb)
    for client, ts, filed in read_sql(NEWEST_BY_ADDRESS_SQL):
        if client and filed is None:
            d = card_at(client)
            d["last"] = max(d["last"], ts or 0)
    for ip, mac, host, ts in scanned:
        tidy = clean_mac(mac)
        number = hw.get(tidy) if tidy and tidy not in shared else None
        d = card_at(ip, number if number in kinds else None)
        if d["id"] is not None and tidy and tidy not in d["macs"]:
            continue                            # the scan saw a different device here than has the address now
        d["on_network"] = max(d["on_network"], ts or 0)
        d["mac"] = d["mac"] or mac or ""
        if host and not d["hint"] and names.tidy_name(host):
            d.update(hint=names.tidy_name(host), hint_source=names.LABELS["dns"])
    # Every address whose rules follow a device by hardware address, and every address a "may be
    # the same device" notice points at, is listed even before it has used QuietNet or been scanned.
    for ip, mac in list(S.dev_mac.items()) + [(n["to"], n["mac"]) for n in notices]:
        d = card_at(ip)
        if d["id"] is None:
            d["mac"] = d["mac"] or mac
    # Every address that carries a name, a group or rules is listed too, whoever has it now. A rule
    # put on the card of a device that was away at the time has no recorded owner (S.dev_mac is
    # only filled for an address whose device is there), and once the device is listed under
    # another address the rule would otherwise drop out of sight, still in force and waiting for
    # the next device given that address, with no card to see it on or switch it off from.
    scopes = (list(S.off) + [scope for scope, services in list(S.svc_blocks.items()) if services]
              + [x["scope"] for x in list(S.schedules)])
    carrying = set(given) | set(S.dev_group) | set(S.enforced) | set(S.device_warnings)
    carrying.update(scope[7:] for scope in scopes if scope.startswith("device:"))
    for ip in sorted(carrying):
        card_at(ip)
    at = {}
    for d in out.values():
        number = d["id"]
        if number is None:
            d["macs"] = [clean_mac(d["mac"])] if clean_mac(d["mac"]) else []
            d["addresses"] = [{"address": d["ip"], "first": None, "last": None, "now": False}]
        elif d["kind"] == "pi":
            d["addresses"] = [{"address": a, "first": None, "last": None, "now": True}
                              for a in [S.local_ip] + sorted(S.v6_own)[:MAX_LISTED_ADDRESSES - 1]]
        else:
            mine = [(":" in addr, -last, addr, first) for addr, first, last in held.get(number, [])
                    if holder(addr) == number
                    and (current.get(addr) == number or last >= now - ADDRESS_RECENT or addr == d["ip"])]
            d["addresses"] = [{"address": addr, "first": first, "last": -last, "now": current.get(addr) == number}
                              for _, last, addr, first in sorted(mine)[:MAX_LISTED_ADDRESSES]]
            if d["ip"] and all(a["address"] != d["ip"] for a in d["addresses"]):
                d["addresses"].insert(0, {"address": d["ip"], "first": None, "last": None, "now": False})
            for a in d["addresses"]:
                d["other_dns"] = max(d["other_dns"], other_dns_since(a["address"], since))
                tip = hints.get(a["address"])
                if tip and tip.get("name") and not d["hint"]:
                    d.update(hint=tip["name"], hint_source=tip.get("source", ""), hint_detail=tip.get("detail", ""))
        if d["ip"] and ":" not in d["ip"]:
            at.update((mac, d["ip"]) for mac in d["macs"])
    for d in out.values():
        if not d["hint"] and not d["hint_detail"] and names.is_private_mac(d["mac"]):
            d["hint_detail"] = names.PRIVATE_NOTE
        if d["id"] is None and ":" in d["ip"]:
            d["same_as"] = at.get(eui64_mac(d["ip"]), "")
    # Devices using QuietNet first (most recent at the top), then the rest in address order.
    listed = [d for d in out.values() if d["ip"] or everything]
    return sorted(listed, key=lambda d: (-d["last"], [int(x) if x.isdigit() else 0 for x in d["ip"].split(".")]))


def api_devices_by_address():
    """The device list as it was before the device tables, one entry per address: every address
    that has used QuietNet, been found by a scan or has rules that follow it (S.dev_mac),
    with its name, group, switches and today's counts, and when (if in the last 24 hours) it last
    tried to use another DNS service. Used by api_devices while an older database has not been
    moved to the device tables (S.devices_ready is False); each entry then has "id" null and
    "kind" "addr", so the answer has the same shape either way.

    "v6_bypass" is the honest label "can bypass QuietNet over IPv6": true for every device but this
    computer while the home network has IPv6 (ipv6_dns_view's "in_use"), or while something on the
    home network names an IPv6 DNS server that is not this computer ("router_dns_not_ours"), since
    a device that uses that server sends its lookups past QuietNet whether or not the home has
    IPv6 internet. That includes a device with "Cut live connections" on, because steering covers
    IPv4 only: its lookups to the router's own IPv6 DNS server, and anything it reaches over IPv6,
    never pass through QuietNet.

    "same_as" is a hint for a card filed under an IPv6 address that could not be matched to a
    device: the IPv4 address of the device whose hardware address that IPv6 address was built from
    (eui64_mac), when a scan or the neighbour table has seen that hardware address. It is only
    shown; no rule is ever applied from it."""
    since = time.time() - 86400
    given = dict(sql("SELECT ip, name FROM devices"))
    hints = S.hints
    v6 = ipv6_dns_view()
    v6_on = v6["in_use"] or bool(v6["router_dns_not_ours"])
    out = {}

    def entry(ip):
        """The dict for one device, created with empty defaults the first time it is asked for."""
        return out.setdefault(ip, {
            "ip": ip, "name": given.get(ip) or "", "hint": hints.get(ip, {}).get("name", ""),
            "hint_source": hints.get(ip, {}).get("source", ""), "hint_detail": hints.get(ip, {}).get("detail", ""),
            "mac": "", "same_as": "",
            "this_computer": ip == S.local_ip, "last": 0, "n": 0, "nb": 0, "on_network": 0,
            "v6_bypass": v6_on and ip != S.local_ip,
            "group": S.dev_group.get(ip), "off": internet_off_for(ip),
            "enforced": ip in S.enforced, "other_dns": other_dns_since(ip, since),
            "paused": ip in S.paused_ips, "warning": S.device_warnings.get(ip, "")})

    # Two small questions, each answered straight from an index, in place of one that read every
    # row of up to 30 days of history on every dashboard refresh.
    for ip, last in read_sql(LAST_SEEN_SQL):
        entry(ip)["last"] = last
    for ip, n, nb in read_sql("""SELECT client, COUNT(*), COALESCE(SUM(blocked), 0) FROM queries INDEXED BY q_ts
                            WHERE ts>? GROUP BY client""", (since,)):
        entry(ip).update(n=n, nb=nb)
    for ip, mac, host, ts in sql("SELECT ip, mac, host, ts FROM seen"):
        d = entry(ip)
        d.update(mac=mac, on_network=ts)
        if host and not d["hint"] and names.tidy_name(host):
            d.update(hint=names.tidy_name(host), hint_source=names.LABELS["dns"])
    # Every device whose rules follow it by hardware address, and every device a "may be the same
    # device" notice points at, is listed even before it has used QuietNet or been found by a scan.
    for ip, mac in list(S.dev_mac.items()) + [(n["to"], n["mac"]) for n in S.device_notices]:
        d = entry(ip)
        d["mac"] = d["mac"] or mac
    at = {clean_mac(d["mac"]): d["ip"] for d in out.values() if ":" not in d["ip"] and clean_mac(d["mac"])}
    for d in out.values():
        if not d["hint"] and not d["hint_detail"] and names.is_private_mac(d["mac"]):
            d["hint_detail"] = names.PRIVATE_NOTE
        if ":" in d["ip"]:
            d["same_as"] = at.get(eui64_mac(d["ip"]), "")
        d.update(id=None, kind="addr", macs=[clean_mac(d["mac"])] if clean_mac(d["mac"]) else [],
                 addresses=[{"address": d["ip"], "first": None, "last": None, "now": False}])
    # Devices using QuietNet first (most recent at the top), then the rest in address order.
    return sorted(out.values(), key=lambda d: (-d["last"], [int(x) if x.isdigit() else 0 for x in d["ip"].split(".")]))


# The two cheap questions behind an activity marker (see activity_marker). Each is answered by
# one step into the q_client_ts index: the device's newest entry, and its oldest inside the window.
NEWEST_FOR_DEVICE_SQL = "SELECT id, ts FROM queries WHERE client=? ORDER BY ts DESC, id DESC LIMIT 1"
OLDEST_IN_WINDOW_SQL = "SELECT MIN(ts) FROM queries WHERE client=? AND ts>?"
# The same two for a device by its number, each one step into the q_device_ts index.
NEWEST_FOR_NUMBER_SQL = "SELECT id, ts FROM queries WHERE device=? ORDER BY ts DESC LIMIT 1"
OLDEST_FOR_NUMBER_SQL = "SELECT MIN(ts) FROM queries WHERE device=? AND ts>?"
# What a device looked up since a time: the lookups filed against it (through q_device_ts), and
# those from one address that are still waiting to be filed (through q_client_ts).
DEVICE_ACTIVITY_SQL = ("SELECT domain, COUNT(*), MAX(ts), SUM(blocked) FROM queries "
                       "WHERE device=? AND ts>? GROUP BY domain")
UNFILED_ACTIVITY_SQL = ("SELECT domain, COUNT(*), MAX(ts), SUM(blocked) FROM queries INDEXED BY q_client_ts "
                        "WHERE client=? AND ts>? AND device IS NULL GROUP BY domain")


def activity_marker(ip, hours, since, device=None):
    """A short code that changes whenever one device's activity list could have changed: a new
    lookup (its newest entry), an old one leaving the window or being cleared (its oldest entry
    inside the window), or anything that changes a block decision or label (the rules version,
    the pause, the advert switch, the schedules in force, the advert lists). The page sends it back
    and is told "unchanged" without the list being built again. It reveals nothing on its own.

    With a device number the entries are the device's own, plus the newest entry under each
    address it has now (a lookup still waiting to be filed shows there first), and the code also
    changes whenever waiting lookups are filed against devices (S.history_filed), since that can
    move a lookup onto or off this device's list."""
    if device is None:
        newest = read_sql(NEWEST_FOR_DEVICE_SQL, (ip,))
        oldest = read_sql(OLDEST_IN_WINDOW_SQL, (ip, since))[0][0]
    else:
        newest = read_sql(NEWEST_FOR_NUMBER_SQL, (device,))
        for addr in device_addresses(device):
            newest += read_sql(NEWEST_FOR_DEVICE_SQL, (addr,))
        oldest = read_sql(OLDEST_FOR_NUMBER_SQL, (device, since))[0][0]
    parts = (ip, device, None if device is None else S.history_filed, float(hours), newest, oldest, S.rules_version,
             time.time() < S.paused_until, S.junk_on, tuple(sorted(x["id"] for x in active_schedules())),
             S.junk_count, len(S.junk_community))
    return hashlib.sha256(repr(parts).encode()).hexdigest()[:24]


def api_activity(ip, hours, seen=None, device=None):
    """GET /api/activity: what one device looked up in the last `hours`, grouped by owner
    (see base_of), with the label and the current block decision for every name and group.

    `device` is a device number from GET /api/devices: the list is then everything filed against
    that device, at whatever address it was made, plus what is still waiting to be filed from the
    addresses it has now. Without it the list is what was recorded under the address `ip`, as it
    always was. Either way the block decisions shown are those for the address `ip`, since rules
    are still kept under addresses (with a device number and no `ip`, the device's own address).

    Without `seen` the answer is the list itself, as it always was. With `seen` (the request's
    'since' parameter: the marker from the last answer, or empty the first time) the answer is
    {"unchanged": false, "marker": ..., "groups": the list}, or just
    {"unchanged": true, "marker": ...} when the marker still matches and the list is not built."""
    since = time.time() - hours * 3600
    if device is not None and not ip:
        ip = (device_addresses(device) + [""])[0]
    if seen is not None:
        marker = activity_marker(ip, hours, since, device)
        if seen == marker:
            return {"unchanged": True, "marker": marker}
        return {"unchanged": False, "marker": marker, "groups": activity_groups(ip, since, device)}
    return activity_groups(ip, since, device)


def device_history(device, since):
    """What one device looked up since a time, as (name, how many times, most recent, how many
    blocked) rows: everything filed against the device, and what is still waiting to be filed
    from the addresses it has now. Asked on the read-only connection."""
    found = {}
    parts = [read_sql(DEVICE_ACTIVITY_SQL, (device, since))]
    parts += [read_sql(UNFILED_ACTIVITY_SQL, (addr, since)) for addr in device_addresses(device)]
    for rows in parts:
        for domain, n, last, nb in rows:
            had = found.get(domain, (0, 0, 0))
            found[domain] = (had[0] + n, max(had[1], last), had[2] + (nb or 0))
    return [(domain,) + figures for domain, figures in found.items()]


def other_dns_since(ip, since):
    """When this device last tried to use another DNS service (see OTHER_DNS_SERVICES), if that
    was after `since` and since QuietNet started; otherwise 0. Kept in memory, so it costs the
    device list no trip to the history."""
    last = S.other_dns.get(ip, 0)
    return last if last > since else 0


def activity_groups(ip, since, device=None):
    """The activity list for one device since a time: see api_activity. A name of another DNS
    service (see OTHER_DNS_SERVICES) is shown as blocked with why 'other_dns' when this device is
    kept away from them (other_dns_blocked_for), since every lookup of it then is, and its group is
    marked "other_dns" too. Every name and group also carries "needed": who needs that whole name
    for their own system (see needed_by), or '' for most. That is so with a device number too.

    A group's "v" is 'junk' when every name in it is on the advert list. A needed group is the one
    exception: it is 'junk' only when its own whole name is on the list, and 'suspect' otherwise,
    so that a device which looked up nothing but advert sub-names (logs.roku.com, say) does not
    make the whole of roku.com read "Advert / tracker". The sub-names keep their own 'junk'."""
    if device is None:
        rows = read_sql("""SELECT domain, COUNT(*), MAX(ts), SUM(blocked) FROM queries
                      WHERE client=? AND ts>? GROUP BY domain""", (ip, since))
    else:
        rows = device_history(device, since)
    guarded = other_dns_blocked_for(ip)

    def kept_off(domain):
        """Is this name another DNS service that this device is kept away from?"""
        return guarded and is_other_dns_service(domain)

    groups = {}
    for domain, n, last, nb in rows:
        base = base_of(domain)
        g = groups.setdefault(base, {"base": base, "owner": OWNERS.get(base, ""), "n": 0, "nb": 0, "last": 0, "hosts": []})
        b, why, svc = (True, "other_dns", "") if kept_off(domain) else decision(domain, ip)
        g["hosts"].append({"d": domain, "n": n, "nb": nb, "last": last, "v": verdict(domain),
                           "b": b, "why": why, "svc": svc, "needed": needed_by(domain)})
        g["n"] += n
        g["nb"] += nb
        g["last"] = max(g["last"], last)
    for g in groups.values():
        g["hosts"].sort(key=lambda h: -h["n"])
        vs = {h["v"] for h in g["hosts"]}
        g["v"] = "junk" if vs == {"junk"} else ("suspect" if vs & {"junk", "suspect"} else "ok")
        # Who needs this whole name, if anyone (see NEEDED). The dashboard then shows "Needed by ..."
        # where it would have shown "Possibly junk", whatever the sub-names beneath it look like.
        g["needed"] = needed_by(g["base"])
        # Every sub-name seen being an advert does not make a needed name one: only the advert
        # list naming the whole name does. Still 'suspect', so the adverts filter lists the group.
        if g["needed"] and g["v"] == "junk" and not is_junk(g["base"]):
            g["v"] = "suspect"
        if kept_off(g["base"]):
            g["b"], g["why"], g["svc"] = True, "other_dns", ""
        else:
            g["b"], g["why"], g["svc"] = decision(g["base"], ip)
        g["some_blocked"] = any(h["b"] for h in g["hosts"])
        g["other_dns"] = any(h["why"] == "other_dns" for h in g["hosts"])
    return sorted(groups.values(), key=lambda g: -g["n"])


def api_rules():
    """GET /api/rules: your own blocked and allowed addresses, newest first. Each carries
    "needed": who needs that name for their own system (see needed_by), or ''. The Blocked list
    page uses it to say, beside a block, which devices it may have broken."""
    def rows(table):
        """One of the two lists. `table` is only ever the fixed text 'blocked' or 'allowed'."""
        return [{"d": d, "ts": ts, "owner": OWNERS.get(base_of(d), ""), "needed": needed_by(d)} for d, ts in
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
        rules_changed()


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
        rules_changed()


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
        S.guest_group = {ip: g for ip, g in S.guest_group.items() if g[1] != gid}
        db.execute("UPDATE device_mac SET guest_mac=NULL, guest_gid=NULL WHERE guest_gid=?", (gid,))
        db.execute("DELETE FROM service_blocks WHERE scope=?", (scope,))
        db.execute("DELETE FROM internet_off WHERE scope=?", (scope,))
        db.execute("DELETE FROM schedules WHERE scope=?", (scope,))
        if S.new_device_group == gid:
            S.new_device_group = None
            db.execute("DELETE FROM settings WHERE key='new_device_group'")
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

    def json_from_our_page(self):
        """True if a change request is JSON and, when the browser says which page sent it, that page
        is on this computer.

        The type must be exactly application/json (extra settings after a ';' are allowed). A
        looser 'contains application/json' check let a hostile page send
        'text/plain; application/json', which browsers treat as plain text and send to another
        site without asking. Any localhost port is accepted as the sender, since an SSH tunnel to a
        Pi may use a different one."""
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        o = urlparse(origin)
        return o.scheme == "http" and o.hostname in ("localhost", "127.0.0.1")

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
            # all=1 also lists devices with no address of their own now (see api_devices).
            self.send_json(api_devices(qs.get("all", [""])[0] == "1"))
        elif url.path == "/api/activity":
            try:
                hours = min(max(float(qs.get("hours", ["24"])[0]), 0.1), KEEP_DAYS * 24)
            except ValueError:
                hours = 24
            # 'since' may be sent empty (the first ask), and parse_qs drops empty values unless told not to.
            seen = parse_qs(url.query, keep_blank_values=True).get("since", [None])[0]
            # 'device' is a device number from GET /api/devices; without one (or with one QuietNet
            # doesn't know) the list is the one recorded under the address 'ip', as it always was.
            device = device_number(qs.get("device", [""])[0])
            self.send_json(api_activity(qs.get("ip", [""])[0], hours, seen, device))
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
            self.send_json(dict(ENF.status() if ENF else {"available": False, "reason": "not started", "active": False},
                                shared=dict(S.shared_left)))
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
        if not self.json_from_our_page():
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
            if ENF:
                rules_changed()
                ENF.poke()                        # a rule may have changed: let the enforcer act on it now
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
            # A name a device's own system depends on is not blocked until the person has been
            # asked: the request must say "sure": true (exactly that). The check is here, not in
            # the page, so it covers the Block button, a typed name and the relayed dashboard alike.
            who = needed_by(domain) if path == "/api/block" else ""
            if who and body.get("sure") is not True:
                return self.send_json({"error": needed_refusal(who), "needed": who, "domain": domain}, 409)
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
                if body.get("off") and scope.startswith("device:") and is_this_computer(scope[7:]):
                    return self.send_json({"error": "QuietNet can't switch off the internet for the "
                                                    "computer it runs on."}, 400)
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
            if body.get("on"):
                # Only an ordinary device on the home network: never the router, this computer,
                # or anything outside. (Without the enforcer, only the basic checks can be made.)
                problem = (ENF.can_target(ip) if ENF and ENF.available()
                           else enforcer.target_problem(ip, None, None, S.local_ip))
                if problem:
                    return self.send_json({"error": problem}, 400)
                # Remember which device this is, so if the address is later given to a different
                # device, that one isn't steered by mistake. The live table first: the last scan's
                # record may be out of date. If neither knows yet, the enforcer fills it in later.
                mac = neighbours().get(ip, "")
                if not mac:
                    row = sql("SELECT mac FROM seen WHERE ip=?", (ip,))
                    mac = row[0][0] if row and row[0][0] else ""
                with db_lock:
                    S.enforced.add(ip)
                    S.enforced_mac[ip] = mac
                    db.execute("INSERT OR REPLACE INTO enforced(ip, mac) VALUES(?,?)", (ip, mac))
                    db.commit()
            else:
                with db_lock:
                    S.enforced.discard(ip)
                    S.enforced_mac.pop(ip, None)
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
                rules_changed()
            return self.send_json({"ok": True})
        if path == "/api/move-rules":       # "Move the rules to this device"
            if not isinstance(body.get("from"), str) or not isinstance(body.get("to"), str):
                return self.send_error(400)
            error = move_rules_by_hand(body["from"], body["to"])
            return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True})
        if path == "/api/different-device":   # "No, it's a different device"
            if not isinstance(body.get("ip"), str):
                return self.send_error(400)
            error = different_device_by_hand(body["ip"])
            return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True})
        if path == "/api/new-device-group":
            set_new_device_group(body.get("group"))
            return self.send_json({"ok": True, "group": S.new_device_group})
        if path == "/api/other-dns-switch":     # keep every device away from other DNS services
            with db_lock:
                S.other_dns_all = bool(body.get("on"))
                db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('other_dns_all', ?)",
                           ("1" if S.other_dns_all else "0",))
                db.commit()
            rules_changed()
            return self.send_json({"ok": True})
        if path == "/api/no-ipv6-switch":       # give no device IPv6 addresses (optional, off by default)
            with db_lock:
                S.no_ipv6_all = bool(body.get("on"))
                db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('no_ipv6_all', ?)",
                           ("1" if S.no_ipv6_all else "0",))
                db.commit()
            rules_changed()
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
                scan_plan()                       # so the answer can say how much will be scanned
                threading.Thread(target=scan_network, daemon=True).start()
            # 'capped' is true when the home network is bigger than MAX_SCAN addresses and only
            # the MAX_SCAN around this computer's own address are knocked on.
            return self.send_json(dict(S.scan_info, ok=True))
        if path == "/api/update-list":
            if S.list_state != "downloading":
                threading.Thread(target=update_community_list, daemon=True).start()
            return self.send_json({"ok": True})
        if path == "/api/clear-history":
            ip = body.get("ip")
            device = device_number(body.get("device"))
            if "device" in body and device is None and not ip:
                # A device number QuietNet doesn't know, and no address to fall back on. Refuse:
                # carrying on would clear everyone's history, which is not what was asked for.
                return self.send_json({"error": "QuietNet doesn't know that device."}, 400)
            if ip or device is not None:
                # One device's history goes in steps, which can take a while for a busy device; long
                # enough, through the relay, to run past its 30-second wait. So answer at once.
                global last_clear
                last_clear = threading.Thread(target=clear_history, args=(ip,) if device is None else (ip, device),
                                              daemon=True)
                last_clear.start()
            else:
                clear_history()                   # everyone's is one quick statement
            return self.send_json({"ok": True})
        self.send_error(404)


def start_up(args, stop):
    """Start everything, in order: database, lists, DNS filter, enforcer, device keeper, cloud
    link. Then open the dashboard's port and return its web server, ready to serve.

    `stop` is the StopRequest, which is already listening. It is looked at before the enforcer
    and before the cloud link, the two things that need cleaning up or can take a while to start
    (the cloud link's first pairing try can take 20 seconds), and before the device keeper,
    which would be wrong to start on the way out (see the lines there): once a stop has been
    asked for, nothing more is started and None is returned in place of the web server. A
    request that arrives later than that means there is no serving (see StopRequest.serve) and
    no browser is opened. Either way run() goes on to clean_up(), which stops whatever was
    started.

    To start one more thing: start it here, look at `stop.asked` first if it is slow to start or
    would be wrong to start on the way out, and give it its line in clean_up(). Then give it a
    stand-in in WholeLife.setUp in tests/test_start_stop.py: those tests run this very function
    inside the test program, and anything without a stand-in would be started there for real.
    A test in that file fails until every name used here is accounted for."""
    global ENF, CA, BROWSER
    init_db()
    load_lists()
    S.local_ip = find_local_ip()
    threading.Thread(target=log_writer, daemon=True).start()
    if not args.no_device_names:
        NAMER.start_listeners()
        threading.Thread(target=hint_refresher, daemon=True).start()
    start_dns(args.dns_port)
    threading.Thread(target=router_advert_listener, daemon=True).start()

    if stop.asked:
        return None
    ENF = enforcer.Enforcer(S.local_ip, enforcement_plan, neighbours, data_dir=DATA, learn_mac=learn_enforced_mac,
                            dns_port=None if S.dns_error else S.dns_port)
    ENF.start()
    threading.Thread(target=address_watcher, daemon=True).start()
    if stop.asked:
        return None
    # Only now, with the filter answering and the enforcer started: bring an older household's
    # data into the device tables if that is still to do, then keep track of devices' addresses.
    # Not once a stop has been asked for: the move would be cut off part-way moments later, when
    # the program ends, and while it lasted it would hold the database lock, which the enforcer
    # needs for its last tick before it can hand the network back (see clean_up).
    threading.Thread(target=device_keeper, daemon=True).start()
    if stop.asked:
        return None
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
    if not args.no_browser and not stop.asked:
        BROWSER = open_browser_soon(url)
    return web


def open_browser_soon(url, after=0.5):
    """Open the dashboard in the person's browser `after` seconds from now: half a second, by
    when the program will be serving it. Returns the timer, started, so that clean_up() can
    call it off: a stop request in that half second must not open a browser on a dashboard
    that has gone. A daemon thread, so that it can never hold up the program's end."""
    timer = threading.Timer(after, webbrowser.open, (url,))
    timer.daemon = True
    timer.start()
    return timer


def clean_up():
    """Stop what start_up() started, and say that QuietNet has stopped.

    To have one more thing stopped, add its line here (and see start_up() for its stand-in in
    the tests). Each line must be safe whether its thing was started, only made, or never
    reached (still None), because a stop request or an error can end start-up at any point.

    The device keeper has no line here, and neither have the other background jobs start_up()
    starts with nothing but a thread: each is a daemon thread with nothing to put back, and ends
    with the program. That holds even for a move to the device tables that is under way: it is
    one transaction, which the database undoes when it is next opened, and the move is then run
    again from the start (see move_to_devices). The clean-up does not wait for it. The one way
    a move can hold the clean-up up is by its hold on the database lock: the enforcer's thread
    may be part-way through a tick that is waiting for that lock, and the enforcer's stop()
    gives it up to 15 seconds to finish and hand the network back. What it has not put back by
    then is put back at the next start (docs/KNOWN_ISSUES.md, "The move has only been run on
    made-up databases"). The enforcer is still stopped first, ahead of the cloud link, because
    the house's internet depends on it."""
    if BROWSER:
        BROWSER.cancel()                # if it has not opened yet, it never will
    if ENF:
        ENF.stop()                      # waits until the network is restored
    if CA:
        CA.stop()
    print("\nQuietNet stopped.", flush=True)


def run(args, stop=None):
    """The whole life of the program: listen for a stop request, start up, serve the dashboard
    until asked to stop, clean up.

    The listening is set up first, so that from then on no stop request can end the program
    without its clean-up: the enforcer may already be steering devices' traffic through this
    computer, and must hand them back to the router. The clean-up runs however the rest ends:
    a stop request during start-up (start_up() then gives no web server to serve), one while
    serving, or an error such as the dashboard's port being in use. Further stop requests are
    ignored while it runs.

    `stop` is a StopRequest that is listening already: the one made at the top of this file
    when it is run as the program. A request it noted before this point, while the program
    was still loading, is acted on like any other during start-up: nothing that needs
    cleaning up is started."""
    stop = stop or StopRequest()
    stop.listen()
    try:
        web = start_up(args, stop)
        if web is not None:
            stop.serve(web)
    finally:
        stop.ignore()                   # a second request must not interrupt the clean-up
        clean_up()


def main(stop=None):
    """Read the command line, then run until Ctrl-C or a stop request. See run() for the order
    of things, and for `stop`."""
    ap = argparse.ArgumentParser(description="QuietNet home advert and tracker blocker")
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--web-port", type=int, default=8377)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-device-names", action="store_true",
                    help="don't ask the home network for device names (the tests use this)")
    run(ap.parse_args(), stop)


if __name__ == "__main__":
    main(STOP_FROM_THE_TOP)
