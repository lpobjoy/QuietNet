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
import argparse
import collections
import functools
import hashlib
import ipaddress
import json
import os
import queue
import re
import shutil
import signal
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
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import enforcer
import cloud_agent
import names

# MAP OF THIS FILE (each part starts with a "# ----- name" banner):
#   settings and State   the values you might tune, and S, everything held in memory
#   database             the SQLite connection, the tables, saved settings, the history writer
#   devices              one device is one hardware address: the device tables, which device has which
#                        address now (S.addr_device) and whose rules a lookup from each address gets
#                        (S.addr_rules), the history, names, groups and rules held against the device,
#                        a device that may be another with a new hardware address, and the one-off
#                        move of an older household's data into those tables
#   rules                the lists, schedules and decision(): is this name blocked for this device, and why
#   DNS                  reading questions, building answers, asking the real servers, the UDP/TCP listeners
#   helpers              this computer's address, the neighbour table, the owner's answers about
#                        devices (same device, different device, Merge and Separate, each shown
#                        before it is done), device names (the work is in names.py), the network
#                        scan, and the api_...() functions that build each dashboard answer
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
# Who a rule is for: the whole house, a group, or one device. A device is named by its number
# ("dev:12") once the device tables are in use. "device:<address>" is how a device was named
# before them, and how an older dashboard page still names one; it then means the device listed
# under that address now (see stored_scope). On an older database not moved over yet, rules are
# still kept under "device:<address>".
SCOPE = re.compile(r"all|device:[0-9a-f.:]{3,45}|dev:\d{1,9}|group:\d+")
# One device is one hardware address (see the "devices" part of this file). These say how the
# record of which device has which address is kept, and how history and rules are held against
# the device.
# Version 1 held only the history against the device; version 2 holds names, groups and rules
# against it too. A database at version 1 is brought to 2 by the same move, after start-up.
DEVICES_VERSION = 2            # the shape of the device tables, saved with the data when it is moved over
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
# A device says which address it is taking when it joins (a DHCP request, heard by names.py). That
# word changes whose rules a lookup from the address gets straight away, before the neighbour
# table has caught up (see note_dhcp).
DHCP_HOLD = 120                # seconds such a word stands if the neighbour table confirms nobody at the address
DHCP_LOOK_DELAY = 1.0          # seconds after one before the neighbour table is looked at again
DHCP_MAX_CLAIMS = 256          # the most such words remembered at once; the oldest make way
DHCP_MAX_PER_SECOND = 20       # how many are taken in each second; any more are ignored
MAX_REPORT_LINES = 60          # the most lines kept of the report on moving rules to the devices

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
    hints = {}              # device number (and address) -> {"name", "source", "detail"}: the name suggested (names.py)
    services = []           # the catalogue from services.json
    svc_names = {}          # service id -> friendly name
    dom2svc = {}            # address -> service id
    svc_blocks = {}         # scope -> set of blocked service ids
    off = set()             # scopes whose internet is switched off
    # A "device key" below is how a device is known to the rules: its device number once the device
    # tables are in use (S.devices_ready), and its IPv4 address on an older database not moved yet.
    given = {}              # device key -> the name someone gave it
    enforced = set()        # device keys we actively enforce (cut live connections for)
    enforced_mac = {}       # device key -> the hardware address noted when enforcing was switched on, for a device
                            # known only by an address ('' = not known, or a device known by its hardware address)
    resolved = {}           # domain -> {ip: last-seen} : the addresses we've handed out
    dev_group = {}          # device key -> group id
    group_names = {}        # group id -> name
    schedules = []          # timed rules, e.g. bedtime (see load_schedules)
    sched_cache = (0.0, [])  # (when worked out, schedules in force at that moment)
    scan_state = "idle"     # idle | scanning
    scan_ts = 0.0
    scan_info = {}          # what the last scan covered: {"network", "addresses", "capped"}
    rules_version = 0       # goes up whenever a rule changes; the enforcer's plan cache watches it
    plan_cache = {}         # see enforcement_plan
    plan_table = (0.0, None)  # (when by time.monotonic(), the neighbour table) as enforcement_plan last read it
    shared_left = {}        # steered address -> {"count", "names"}: addresses left to the name block (see enforcement_plan)
    router = ""           # the home router's address, for home-network names ('' = not known)
    router_checked = None   # when (time.monotonic()) the router's address was last looked up
    v6_own = set()          # this computer's own IPv6 addresses (see refresh_ipv6_view)
    v6_prefixes = []        # the home network's public IPv6 ranges, from this computer's own addresses
    v6_devices = {}         # a device's IPv6 address -> its IPv4 address, matched by hardware address
    v6_by_mac = {}          # hardware address -> {"ll": its one link-local IPv6 address (empty if none or several), "lls": [every link-local], "addrs": [all its IPv6 addresses]}
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
    other_dns = {}          # device key -> when (time.time()) it last looked up another DNS service
    dev_mac = {}            # older database only: address with rules or a name -> the hardware address they belong to
    paused_ips = set()      # older database only: addresses whose rules are paused, as a different device is there now
    device_warnings = {}    # device key -> a plain-English warning for its page
    device_notices = []     # "is it the same device?" questions for the owner: see device_notices_now
    new_device_group = None  # group id that a device seen for the first time is put in (None = no group)
    shared_macs = set()     # hardware addresses seen at several addresses at once: range extenders, not devices
    other_dns_all = False   # block other DNS services for every device, not just those with rules?
    no_ipv6_all = False     # give no device IPv6 addresses in answers? (the optional whole-house switch)
    ipv6_steer = False      # take IPv6 away from steered devices (option c2)? Off unless the owner turns it on
    router_prefixes = {}    # IPv6 ranges announced by a real router -> when to forget each (time.time())
    # One device is one hardware address: see the "devices" part of this file.
    devices_ready = False   # are the device tables in use? False for an older database not moved over yet
    devices_state = "old"   # "ready", "moving", "waiting" (too little free space), "failed", or "old" (not tried yet)
    devices_notice = ""     # what to tell the owner about that move ('' = nothing)
    devices_moved_at = 0.0  # when (time.time()) the device tables were made: older history gets its device from the move
    copy_made_at = 0.0      # when the copy of the data kept from before the move was made (0 = with the device tables)
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
    behind_extender = {}    # device known only by its address -> the range extender's hardware address seen answering for it
    device_kind = {}        # device number -> "hw", "addr", "pi" (this computer) or "hub" (the home router)
    pi_device = None        # the number of the fixed device that is this computer
    hub_device = None       # the number of the fixed device that is the home router
    hub_mac = ""            # the home router's hardware address, as last seen at its IPv4 address
    hw_unsettled = frozenset()  # hardware addresses found at two live IPv4 addresses at the last look
    v6_table = {}           # the IPv6 neighbour table as last read by refresh_ipv6_view
    device_seen = {}        # device number -> when it was last seen, waiting to be saved (save_address_use)
    hw_seen = {}            # hardware address -> the same
    # Rules held against the device: see "whose rules a lookup gets" in the "devices" part of this file.
    addr_rules = {}         # address, IPv4 or IPv6 -> the number of the device whose rules a lookup from it gets
    rules4 = {}             # the IPv4 part of that, from the last look at the neighbour table (note_ipv4_addresses)
    rules6 = {}             # the IPv6 part, from the last look at the IPv6 neighbours (refresh_ipv6_view)
    had4 = {}               # IPv4 address -> the device the looks last gave that address's rules to (S.rules4),
                            # remembered while a hardware address not confirmed yet is listed there and until
                            # that device is listed anywhere else: who a newcomer there took over from
    dhcp_claims = {}        # IPv4 address -> (hardware address, when by time.monotonic(), the device confirmed
                            # there at the time): a device's own word, heard as it joined, that it is taking
                            # that address (note_dhcp)
    provisional = {}        # device number -> the number of a device whose rules apply to it as well, until the
                            # owner says whether the two are the same device (see start_follow)
    not_same = set()        # (device number, device number) pairs the owner said are different devices
    dev_first = {}          # device number -> when it was first seen
    dev_last = {}           # device number -> when it was last seen
    seeded = False          # has a first look been taken? Until then no device counts as "new" (new-device group)
    rule_conflicts = []     # rules the move set aside for the owner to decide on: see load_move_notes
    set_aside = frozenset()  # the devices (known only by a number) holding those rules: until the owner has
                            # chosen they apply to no lookup, and no device is given them (load_move_notes)
    move_report = []        # plain-English lines saying what the move of rules to the devices did
    old_rules = 0           # numbers that carry names or rules in the tables from before the device tables,
                            # though those are no longer read: an older QuietNet has been run on this data


S = State()
ENF = None
CA = None
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
# Guards the pieces S.addr_rules is put together from (S.rules4, S.rules6, S.dhcp_claims, the
# address-only devices) and the putting together itself. Held only for dictionary work: never
# while the database or a system tool is used, and never taken by a lookup, which only reads
# S.addr_rules. Take it after db_lock when both are needed, never before.
rule_map_lock = threading.RLock()
# Set by note_dhcp while a look at the neighbour table is on its way (look_soon), and when the
# listener last counted the words it takes in each second.
look_due = threading.Event()
dhcp_window = [0.0, 0]
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
    # then (or if that fails) everything works on the old tables: the names, groups and rules kept
    # under addresses in `devices`, `device_group`, `enforced`, `device_mac` and the "device:<address>"
    # scopes. Once moved, those are held against the device (see DEVICE_TABLES_SQL) and the old
    # tables are left empty.
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
    try:
        db.execute("ALTER TABLE enforced ADD COLUMN mac TEXT")    # added after 0.5; older databases lack it
        db.commit()
    except sqlite3.OperationalError:
        pass                                                       # already there
    for column in ("guest_mac TEXT", "guest_gid INTEGER"):     # added later; older databases lack them
        try:
            db.execute("ALTER TABLE device_mac ADD COLUMN " + column)
            db.commit()
        except sqlite3.OperationalError:
            pass                                                   # already there
    S.shared_macs = {mac for (mac,) in sql("SELECT mac FROM shared_macs WHERE hits>=?", (SHARED_AFTER,))}
    S.other_dns_all = get_setting("other_dns_all", "0") == "1"
    S.no_ipv6_all = get_setting("no_ipv6_all", "0") == "1"
    S.ipv6_steer = get_setting("ipv6_steer", "0") == "1"
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
    S.junk_on = get_setting("junk_on", "1") == "1"
    S.paused_until = float(get_setting("paused_until", "0"))
    if new_household:
        make_device_tables()
        db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('devices_version', ?)", (str(DEVICES_VERSION),))
        db.commit()
    S.devices_state, S.devices_notice = "old", ""
    S.moved_steady, S.copy_unwanted = None, False
    load_devices()                  # also loads the names, groups, rules and schedules (load_rules)
    open_read_db()                  # after the tables exist, so it never sees a half-made database
    rules_changed()


def load_rules():
    """Load every name, group, internet switch, blocked service and "cut live connections" switch
    into S, from wherever this database keeps them: against the device (the device tables, with
    "dev:<number>" scopes) once those are in use, and under addresses (the old tables, with
    "device:<address>" scopes) on an older database not moved over yet. The schedules are loaded by
    load_schedules. Called by load_devices, which has just worked out which it is (S.devices_ready).

    On an older database the note of which hardware address each address's rules belong to, and
    whether they are paused because a different device has the address now, is loaded too
    (S.dev_mac, S.paused_ips): see pause_old_rules."""
    with db_lock:
        S.group_names = dict(db.execute("SELECT id, name FROM groups"))
        S.off = {scope for (scope,) in db.execute("SELECT scope FROM internet_off")}
        blocks = {}
        for scope, service in db.execute("SELECT scope, service FROM service_blocks"):
            blocks.setdefault(scope, set()).add(service)
        S.svc_blocks = blocks
        S.dev_mac, S.paused_ips, S.provisional, S.not_same = {}, set(), {}, set()
        S.device_warnings, S.device_notices = {}, []
        S.rule_conflicts, S.move_report, S.old_rules, S.set_aside = [], [], 0, frozenset()
        if S.devices_ready:
            S.given = {number: name for number, name in db.execute("SELECT id, name FROM device WHERE name != ''")}
            S.dev_group = dict(db.execute("SELECT device, gid FROM group_member"))
            S.enforced_mac = {number: mac or "" for number, mac in db.execute("SELECT device, mac FROM live_cut")}
            for number, other, state in db.execute("SELECT device, follows, state FROM device_follow"):
                if state == "asked":
                    S.provisional[number] = other
                else:
                    S.not_same.add((number, other))
            load_move_notes()
        else:
            S.given = {ip: name for ip, name in db.execute("SELECT ip, name FROM devices") if name}
            S.dev_group = dict(db.execute("SELECT ip, gid FROM device_group"))
            S.enforced_mac = {ip: mac or "" for ip, mac in db.execute("SELECT ip, mac FROM enforced")}
            for ip, mac, paused in db.execute("SELECT ip, mac, paused FROM device_mac"):
                S.dev_mac[ip] = mac
                if paused:
                    S.paused_ips.add(ip)
        S.enforced = set(S.enforced_mac)


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
#   device        one row per device, with the name it was given. kind: "hw" (known by its
#                 hardware address), "addr" (known only by a network address: no hardware address is
#                 known for it, or it sits behind a Wi-Fi range extender that shows several devices
#                 under one hardware address), "pi" (this computer) or "hub" (the home router).
#                 Numbers are never used twice.
#   device_hw     which hardware address belongs to which device.
#   address_use   a dated record of which device used which address. When an address turns up with
#                 another device a new row is opened, and the old one is no longer added to. It is
#                 for the history and for showing the owner. It never decides whose rules apply,
#                 and it never steers.
#   moved_address for a household moved over from an older version: which device each address in
#                 its old history was given to, and whether that rests on certain evidence.
#   queries.device  the device each lookup belonged to WHEN IT WAS MADE, so a device keeps its
#                 history across every address it has had, and an address handed to another device
#                 does not hand over the history with it.
#   group_member  which group a device is in, and whether QuietNet put it there by itself (`auto`:
#                 the new-device group) or the owner chose it.
#   live_cut      the devices "cut live connections" is on for.
#   device_follow a device that also gets another device's rules until the owner says whether the
#                 two are the same ("asked"), and pairs the owner said are different ("no").
#   rule_conflict rules the move from an older version set aside, for the owner to decide: they
#                 apply to nobody until then.
#   behind_extender  which devices known only by a number sit behind a Wi-Fi range extender, and
#                 the extender's hardware address: such a number is never merged (merge_problem).
#   A device's own internet switch, blocked services and schedules are kept in the same tables as
#   a group's and the whole house's, under the scope "dev:<number>".
#
# Two maps in memory, both kept by looking at the neighbour tables (note_ipv4_addresses every
# ADDRESS_LOOK seconds, the IPv6 look after it), so that a lookup finds its device with one
# dictionary lookup and never touches the database:
#
#   S.addr_device  which device has each address now, counting only addresses confirmed at the
#                 last look. The history is filed by it.
#   S.addr_rules   whose rules a lookup from each address gets. Wider than S.addr_device, so that a
#                 phone that has been idle for a minute (its entry gone stale) still gets its own
#                 rules on its first lookup: see "whose rules a lookup gets" below.

# Which devices known only by a number sit behind a Wi-Fi range extender, and which extender (its
# hardware address) last answered for the number. Kept in the database, not worked out afresh at
# each look: a merge of such a number must be refused whether or not the extender happens to be
# listed at that moment (see merge_problem). A database whose device tables were made before this
# table gets it when it is loaded (make_extender_table): it is small and empty, so that is instant.
BEHIND_EXTENDER_SQL = "CREATE TABLE IF NOT EXISTS behind_extender(device INTEGER PRIMARY KEY, mac TEXT)"
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
    # Rules held against the device (version 2 of the device tables).
    # `auto` is 1 for a membership QuietNet gave by itself (the new-device group), 0 for one the owner chose.
    "CREATE TABLE IF NOT EXISTS group_member(device INTEGER PRIMARY KEY, gid INTEGER, auto INTEGER DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS live_cut(device INTEGER PRIMARY KEY, mac TEXT)",
    "CREATE TABLE IF NOT EXISTS device_follow(device INTEGER, follows INTEGER, state TEXT, since REAL, "
    "PRIMARY KEY(device, follows))",
    "CREATE TABLE IF NOT EXISTS rule_conflict(id INTEGER PRIMARY KEY, device INTEGER, held INTEGER, addr TEXT, "
    "text TEXT, ts REAL)",
    BEHIND_EXTENDER_SQL,
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
    mark_own_memberships()


def mark_own_memberships():
    """Give the table of group members its `auto` column if it lacks it (a database whose rules
    were moved to the devices before the column was added). Every membership already there counts
    as the owner's own choice (0), so no device is forgotten that was kept before. The table holds
    one small row per device in a group, so this is instant. Call holding db_lock; the caller
    commits."""
    if "auto" not in {row[1] for row in db.execute("PRAGMA table_info(group_member)")}:
        db.execute("ALTER TABLE group_member ADD COLUMN auto INTEGER DEFAULT 0")


def make_extender_table():
    """Make the table of numbers behind a Wi-Fi range extender if this database lacks it (its
    device tables were made before the table was added). It starts empty and the looks fill it, so
    this is instant. Call holding db_lock; the caller commits."""
    db.execute(BEHIND_EXTENDER_SQL)


def rules_on_devices():
    """Does this database hold names, groups and rules against the device (version 2 of the
    device tables)? The table of group members is made in one step with the move of the rules
    (move_to_devices), so if it is there, the rules were moved. The tables themselves are asked,
    not the saved version number: a lost setting must never make a moved database look unmoved."""
    return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='group_member'").fetchone())


def load_devices():
    """Load the device tables into S, and make sure the two fixed devices exist: this computer
    ("pi") and the home router ("hub"). Then load the names, groups, rules and schedules from
    wherever this database keeps them (load_rules, load_schedules). Called at start-up and when
    the move finishes.

    The device tables are in use (S.devices_ready) only when they are there AND hold the rules too
    (DEVICES_VERSION). On an older database, or one that so far holds only the history against the
    device, S.devices_ready is left False and everything carries on under addresses, as it did
    before, until move_to_devices has done its work."""
    with db_lock:
        S.addr_device, S.map4, S.map6, S.addr_use = {}, {}, {}, {}
        S.hw_device, S.addr_only, S.device_kind, S.behind_extender = {}, {}, {}, {}
        S.hw_unsettled, S.device_seen, S.hw_seen = frozenset(), {}, {}
        S.pi_device, S.hub_device, S.hub_mac = None, None, ""
        S.dev_first, S.dev_last, S.seeded = {}, {}, False
        with rule_map_lock:
            S.addr_rules, S.rules4, S.rules6, S.dhcp_claims, S.had4 = {}, {}, {}, {}, {}
        S.history_fill = False
        S.devices_ready = devices_made() and rules_on_devices()
        if S.devices_ready:
            mark_own_memberships()
            make_extender_table()
            load_device_rows()
            if db.in_transaction:
                db.commit()
            S.devices_moved_at = float(get_setting("devices_moved_at", "0") or 0)
            S.copy_made_at = float(get_setting("devices_copy_at", "0") or 0)
            S.history_fill = get_setting("devices_fill", "") == "pending"
            S.devices_state, S.devices_notice = "ready", ""
            # Until a first look has been taken, no device counts as new (see note_new_device).
            S.seeded = get_setting("macs_seeded", "") == "1" or any(
                number != S.hub_device for number in S.hw_device.values())
        load_rules()
        load_schedules()
        if S.devices_ready:
            rebuild_address_map()
            rebuild_rule_map()


def load_device_rows():
    """Read the device tables into S.device_kind, S.addr_only, S.hw_device, S.hub_mac, S.addr_use
    (the newest row for each address), S.behind_extender and when each device was first and last
    seen, making the two fixed devices if they are missing. Call holding db_lock; the caller
    commits."""
    now = time.time()
    kinds, only, hw, use, first_seen, last_seen = {}, {}, {}, {}, {}, {}
    for number, kind, key, first, last in db.execute("SELECT id, kind, key, first, last FROM device"):
        kinds[number] = kind
        first_seen[number], last_seen[number] = first or 0, last or 0
        if kind == "addr":
            only[key[5:]] = number
    S.device_kind, S.dev_first, S.dev_last = kinds, first_seen, last_seen
    with rule_map_lock:
        S.addr_only = only
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
    S.behind_extender = {number: mac for number, mac in db.execute("SELECT device, mac FROM behind_extender")
                         if kinds.get(number) == "addr"}


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
    S.dev_first[number] = S.dev_last[number] = now
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
            with rule_map_lock:
                S.addr_only[addr] = number
                # A lookup from this address gets this device's rules, unless a device known by its
                # hardware address is there (see rebuild_rule_map).
                S.addr_rules.setdefault(addr, number)
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


# ----- whose rules a lookup gets
#
# Rules are held against the device, so nothing moves when a device changes address: only
# S.addr_rules changes, which says whose rules a lookup from each address gets. It is put
# together (rebuild_rule_map) from, strongest first:
#
#   1. this computer's own addresses: always the fixed "pi" device;
#   2. the IPv4 neighbour table as last looked at (S.rules4, from note_ipv4_addresses): every
#      address confirmed just now, as in S.addr_device, AND an address whose entry has gone stale,
#      as long as the device it names is not confirmed anywhere else, AND an address whose entry
#      has gone altogether, which keeps the device the last look gave it until that device, or
#      anyone else at that address, shows in the table. A phone idle for a minute has a stale
#      entry, and one asleep for longer may have none; without this its first lookup after waking
#      would get only the whole house's rules, and bedtime would leak. The table is still right
#      about who last spoke from the address: a device given that address must announce itself
#      before it can ask anything, and Linux then rewrites the entry. None of this is kept across
#      a restart, and none of it comes from address_use;
#   3. a device's own word, heard as it joined (a DHCP request: note_dhcp), that it is taking an
#      address. Until a look confirms who is there, a lookup from that address gets that
#      device's rules if QuietNet knows the device, and otherwise nobody's but the whole house's:
#      the rules of the device that had the address before are paused on it. This is what stops a
#      phone given the TV's old number being treated as the TV for its first seconds. A device
#      takes one address at a time, so its word is withdrawn when it says it is taking another
#      address, or when a look confirms it at another address: a device that asked for its old
#      number back and was refused must not leave its rules on the device that has that number
#      now;
#   4. the IPv6 neighbours (S.rules6, from refresh_ipv6_view);
#   5. a device known only by that address (S.addr_only): rules kept against a number apply to
#      lookups from that number while no device known by its hardware address is there. Not the
#      rules the move set aside for the owner to choose (S.set_aside): those apply to no lookup
#      until the owner has chosen. And an IPv6 address known only by itself, carrying nothing,
#      does not count as matched when a lookup comes from it (ipv6_match).
#
# An address in none of these gets the whole house's rules only. One hardware address at two live
# addresses keeps its rules at the one it had first; the other gets none until the first goes
# (see note_ipv4_addresses). address_use never comes into it.

def rebuild_rule_map():
    """Put S.addr_rules together afresh from its parts (see the notes above). The finished
    dictionary replaces the old one in a single step, so a lookup reading it never sees it half
    made. Only dictionary work: no database, no tools. Words heard from DHCP that are older than
    DHCP_HOLD are dropped here. Rules the move set aside for the owner to choose (S.set_aside)
    are left out: they apply to no lookup until the owner has chosen."""
    with rule_map_lock:
        now = time.monotonic() if S.dhcp_claims else 0.0
        aside = S.set_aside
        rules = {addr: number for addr, number in S.addr_only.items() if number not in aside}
        rules.update(S.rules6)
        rules.update(S.rules4)
        confirmed = S.map4
        for addr, claim in list(S.dhcp_claims.items()):
            mac, when = claim[0], claim[1]
            if now - when > DHCP_HOLD:
                del S.dhcp_claims[addr]
                continue
            claimant = dhcp_device(mac)
            there = confirmed.get(addr)
            if there is not None:
                # The neighbour table confirmed someone there at the last look: it decides. (The
                # word is kept meanwhile: the device that was there may only just have left, and
                # its entry takes up to a minute to stop counting as confirmed.)
                continue
            if claimant is not None:
                rules[addr] = claimant
            elif addr in S.addr_only and S.addr_only[addr] not in aside:
                rules[addr] = S.addr_only[addr]
            else:
                rules.pop(addr, None)
        for addr in ["127.0.0.1", "::1", S.local_ip] + list(S.v6_own):
            if addr:
                rules[addr] = S.pi_device
        S.addr_rules = rules


def dhcp_device(mac):
    """The number of the device a hardware address heard in a DHCP request belongs to, if it is
    one whose rules may be applied on that word alone: a device QuietNet already knows by that
    hardware address. None for a hardware address never seen (the next look makes its device),
    the router's, a range extender's, or one that is at two live addresses at once."""
    number = S.hw_device.get(mac)
    if number is None or S.device_kind.get(number) != "hw" or mac in S.shared_macs or mac in S.hw_unsettled:
        return None
    return number


def note_dhcp(mac, address):
    """A device has just said, in a DHCP request it broadcast, that it is taking this IPv4 address
    (heard by names.py, which passes on the hardware address and the address asked for). Change
    whose rules a lookup from that address gets straight away (see rebuild_rule_map, point 3), and
    ask for a look at the neighbour table in a moment, which settles it. Returns True if the word
    was taken in.

    A device takes one address at a time, so this word replaces any earlier one from the same
    hardware address for another address. A device that rejoins asks for the number it had
    before; if the router has since given that number to another device it refuses, and the
    device then asks for the number it is offered. Without this the first word would leave the
    asker's rules on the other device's number for as long as that device was idle. A look that
    confirms the asker at another address withdraws the word too (note_ipv4_addresses).

    Anyone on the home network can send such a request with any hardware address in it, so it is
    never allowed to overrule what the neighbour table confirmed at the last look, it never makes
    a device, it never steers (the enforcer goes by the live neighbour table alone), and it lapses
    after DHCP_HOLD seconds. At most DHCP_MAX_PER_SECOND are taken in each second, and
    DHCP_MAX_CLAIMS remembered. Never for this computer's or the router's address or the router's
    hardware address. Does nothing until the device tables are in use. No database, no tools."""
    if not S.devices_ready:
        return False
    mac = clean_mac(mac)
    try:
        addr = ipaddress.IPv4Address(str(address))
    except ValueError:
        return False
    if not mac or addr.is_unspecified or addr.is_multicast or addr.is_loopback or mac == S.hub_mac:
        return False
    address = str(addr)
    if address in fixed_addresses():
        return False
    now = time.monotonic()
    with rule_map_lock:
        if now - dhcp_window[0] >= 1:
            dhcp_window[0], dhcp_window[1] = now, 0
        if dhcp_window[1] >= DHCP_MAX_PER_SECOND:
            return False
        dhcp_window[1] += 1
        for other in [a for a, claim in S.dhcp_claims.items() if claim[0] == mac and a != address]:
            del S.dhcp_claims[other]
        if address not in S.dhcp_claims and len(S.dhcp_claims) >= DHCP_MAX_CLAIMS:
            del S.dhcp_claims[min(S.dhcp_claims, key=lambda a: S.dhcp_claims[a][1])]
        S.dhcp_claims[address] = (mac, now, S.map4.get(address))
        rebuild_rule_map()
    look_soon()
    return True


def look_soon():
    """Look at the neighbour table once more in DHCP_LOOK_DELAY seconds, on a thread of its own:
    a device that has just said it is taking an address (note_dhcp) will have finished joining by
    then. One look is on its way at a time, however many devices speak."""
    if look_due.is_set():
        return
    look_due.set()

    def look():
        """The look itself, after the wait."""
        time.sleep(DHCP_LOOK_DELAY)
        look_due.clear()
        try:
            note_ipv4_addresses()
        except Exception as e:
            print("Could not look at which device has which address:", e, flush=True)

    threading.Thread(target=look, daemon=True).start()


def seen_now(number, now):
    """Note that a device was confirmed on the network just now: kept in memory for the rules
    (S.dev_last) and saved to the database with the next minute's pass (S.device_seen)."""
    S.device_seen[number] = now
    if now > S.dev_last.get(number, 0):
        S.dev_last[number] = now


def note_ipv4_addresses(table=None, now=None):
    """Work out which device has which IPv4 address now, from the neighbour table, and keep
    S.addr_device, S.addr_rules and the address record up to date. Run every ADDRESS_LOOK seconds
    by device_keeper, each minute by refresh_devices and a moment after a device says it is taking
    an address (look_soon), never on a lookup. `table` is {ip: (hardware address, freshness)} or
    {ip: hardware address} (the neighbour table when not given).

    The safeguards, so that one device is never taken for another:
      - For the history (S.addr_device), only an address confirmed just now counts (its neighbour
        entry is fresh, or its freshness can't be known on this system). Linux keeps an entry for
        a device that left for a long time, and that address may since have gone to another device.
        A lookup from an address that is not confirmed is saved without a device, and filed once a
        later look has confirmed who was there (tidy_history).
      - For the rules (S.addr_rules), a stale entry still counts, unless the device it names is
        confirmed at another address: see "whose rules a lookup gets" above.
      - An address that turns up with a different hardware address belongs to that device from
        then on: the old device's record of it stops, its history stays its own, and its rules no
        longer apply there. A new device at an old address gets none of them.
      - One hardware address at two confirmed addresses at once may be a Wi-Fi range extender
        standing in for several devices. The address the device already had stays its own; the
        other gets no device, and no rules, until the first is no longer confirmed, so a second
        device behind an extender is never taken for the first. While that lasts the hardware
        address is unsettled (S.hw_unsettled) and its IPv6 addresses are not matched either. If
        no address was its own before, neither is given to it.
      - A hardware address known to be a range extender's (S.shared_macs) gives each of its
        addresses a device of its own, known by that address.
      - A new hardware address is a new device. Nothing is merged automatically. A device seen
        for the first time goes into the new-device group if one is chosen (note_new_device),
        unless it may be a known device with a new private Wi-Fi address (note_followers): then
        that device's rules apply to it for now and the owner is asked. Whether a number changed
        hands is judged from what these looks themselves saw (S.had4), never from the record of
        who used an address, and never while the earlier device is listed anywhere in the table.
      - A device's word that it was taking an address (note_dhcp) is dropped once the table
        confirms someone new there, or confirms the device that said it at another address.
    This computer and the home router are the two fixed devices and are never mixed with others."""
    if not S.devices_ready:
        return
    now = time.time() if now is None else now
    looked = time.monotonic()
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
        unsettled, made, held = set(), set(), {}    # held: address -> device, from an entry gone stale
        for mac, spots in by_mac.items():
            live = [ip for ip, fresh in spots if fresh == "fresh"] or [ip for ip, fresh in spots if fresh == ""]
            if mac in S.shared_macs:
                for ip in live:
                    number = device_of_address(ip, now)
                    mapped[ip] = (number, True)
                    note_behind_extender(number, mac)
                continue
            number = S.hw_device.get(mac)
            if not live:
                # Every entry for this hardware address has gone stale. It is still the last
                # device heard from each of those addresses, so its rules stay on one of them: the
                # only one, or the one it was most recently confirmed at.
                # A stale entry never makes a device: a hardware address not known yet is left out.
                if number is not None:
                    held.update((ip, number) for ip in own_address(number, [ip for ip, _ in spots]))
                continue
            if len(live) > 1:
                unsettled.add(mac)
                live = own_address(number, live)
            for ip in live:
                if number is None:
                    number = device_of_hw(mac, now)
                    if number is not None:
                        made.add(number)
                mapped[ip] = (number, True)
                S.hw_seen[mac] = now
        # Every device whose hardware address is listed anywhere in the table, fresh or stale.
        listed = {S.hw_device.get(mac) for mac in by_mac}
        known, present, took_over = {}, {}, []      # present: device -> (address, hardware address) confirmed now
        for ip, (number, confirmed) in mapped.items():
            if number is None:
                continue
            known[ip] = number
            # Did this address change hands? Only the looks themselves say so (S.had4: the device
            # the last looks gave this address's rules to), never the record of who used an
            # address (address_use), which reaches back a month. And not when that device is
            # listed anywhere in the table, even on a stale entry: it has moved, and whoever has
            # its old number now is somebody else.
            before = S.had4.get(ip)
            if confirmed and before is not None and before != number and before not in listed:
                took_over.append((ip, number, before))
            use_address(ip, number, now, confirmed)
            if confirmed:
                seen_now(number, now)
                present.setdefault(number, (ip, seen_at[ip][0]))
                if S.device_kind.get(number) == "hw" and S.addr_only.get(ip) in S.behind_extender:
                    # A device known by its own hardware address is confirmed at this number: no
                    # range extender is answering for it now.
                    note_behind_extender(S.addr_only[ip], "")
        S.hw_unsettled = frozenset(unsettled)
        S.map4 = known
        # An address that has dropped out of the table altogether (Linux gives up on an entry
        # when a sleeping phone does not answer) keeps the device the last look gave it, as long
        # as that device is not listed anywhere in the table now. Nobody else has spoken from the
        # address, or the table would name them; and if the device were dropped here, its first
        # lookup after waking would get only the whole house's rules.
        rules = {addr: number for addr, number in S.rules4.items()
                 if addr not in seen_at and number not in listed and S.device_kind.get(number) == "hw"}
        rules.update(held)
        rules.update(known)
        # Who had each address last, for the next look's "did it change hands?". Kept while the
        # address is listed with a hardware address QuietNet has no device for yet (a newcomer's
        # entry reads stale until this computer first answers it), dropped once the device is
        # listed anywhere, or once a device QuietNet knows has spoken from the address since.
        had = {addr: number for addr, number in S.had4.items()
               if number not in listed and S.device_kind.get(number) == "hw"
               and (addr not in seen_at or S.hw_device.get(seen_at[addr][0]) is None)}
        had.update(rules)
        S.had4 = had
        confirmed_at = {}                       # hardware address -> the addresses it is confirmed at now
        for addr, (number, confirmed) in mapped.items():
            if confirmed and number is not None:
                confirmed_at.setdefault(seen_at[addr][0], set()).add(addr)
        with rule_map_lock:
            S.rules4 = rules
            for addr, claim in list(S.dhcp_claims.items()):
                mac, when, before = claim
                if when >= looked:
                    continue                    # heard after this look read the table
                there = known.get(addr) if addr in known and mapped[addr][1] else None
                elsewhere = confirmed_at.get(mac, set()) - {addr}
                if (there is not None and there != before) or (elsewhere and mac not in S.shared_macs):
                    # The neighbour table has confirmed someone new there since the word was
                    # heard (the device that said it, or another): the table decides from now on.
                    # Or it has confirmed the device that said it at another address: it is
                    # there, not here, and its rules must not stay on whoever has this one. (A
                    # device that really has just moved is then covered by the looks alone: its
                    # rules reach the new address once its entry at the old one lapses.)
                    del S.dhcp_claims[addr]
        rebuild_address_map()
        first_look = not S.seeded
        note_followers(present, took_over, made, now, listed)
        if not first_look:
            for number in sorted(made):
                note_new_device(number, present.get(number, ("", ""))[0], now)
        else:
            S.seeded = True
            db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('macs_seeded', '1')")
        rebuild_rule_map()
        S.device_warnings = device_warnings_now(seen_at, unsettled)
        S.device_notices = device_notices_now(present, now)
        if db.in_transaction:
            db.commit()


def note_behind_extender(number, mac):
    """Remember that the device `number`, known only by its address, sits behind the Wi-Fi range
    extender with the hardware address `mac`; with '' for `mac`, that it no longer does (a device
    known by its own hardware address was confirmed at its number). Kept in S.behind_extender and
    the database, so that it is still known when the extender is not listed (the device behind it
    is asleep or away, or QuietNet has just restarted): merge_problem goes by it. Does nothing
    when that is what is remembered already, which is every look but the first. Call holding
    db_lock; the caller commits."""
    if number is None or S.behind_extender.get(number, "") == mac:
        return
    kept = dict(S.behind_extender)
    if mac:
        kept[number] = mac
        db.execute("INSERT OR REPLACE INTO behind_extender(device, mac) VALUES(?,?)", (number, mac))
    else:
        kept.pop(number, None)
        db.execute("DELETE FROM behind_extender WHERE device=?", (number,))
    S.behind_extender = kept


def own_address(number, addresses):
    """Of these addresses, all listed for one hardware address, the ones that count as its
    device's own: the only one, or (of several) the one the device `number` was most recently
    confirmed at, going by what the looks themselves have seen (S.addr_use, in memory). An empty
    list if it was confirmed at none of them, or its device is not known yet: then none is given
    to it, because the others may be other devices behind the same Wi-Fi range extender."""
    if number is None:
        return [] if len(addresses) > 1 else list(addresses)
    if len(addresses) == 1:
        return list(addresses)
    own = [ip for ip in addresses if ip in S.addr_use and S.addr_use[ip][0] == number]
    newest = max([S.addr_use[ip][2] for ip in own], default=None)
    own = [ip for ip in own if S.addr_use[ip][2] == newest]
    return own if len(own) == 1 else []


def note_ipv6_addresses(table=None, now=None):
    """Work out which device has which IPv6 address now, from the IPv6 neighbour table as last
    read (S.v6_table; `table` in its place for the tests), and keep S.addr_device, S.addr_rules
    and the address record up to date. Run after each look at the IPv6 neighbours (ipv6_look),
    never on a lookup.

    An IPv6 address belongs to the device with the hardware address the neighbour table gives it,
    so a phone's four or more addresses, and the new one it makes about daily, all come to one
    device, and all get that device's rules. A stale entry still counts: a device's own IPv6
    address is not handed on to another.
    Never matched: an address whose hardware address is a range extender's (S.shared_macs), or is
    unsettled because it is at two live IPv4 addresses at once (S.hw_unsettled). Those lookups are
    filed under whatever address they were judged under, and get no device's rules. An address
    built from a hardware address (eui64_mac) proves nothing and is not looked at here."""
    if not S.devices_ready:
        return
    now = time.time() if now is None else now
    table = S.v6_table if table is None else table
    with db_lock:
        if not S.devices_ready:
            return
        known, made = {}, set()
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
                new = mac not in S.hw_device
                number = device_of_hw(mac, now)
                if new and number is not None:
                    made.add(number)
                if fresh != "stale":
                    S.hw_seen[mac] = now
            if number is None:
                continue
            known[addr] = number
            use_address(addr, number, now, fresh != "stale")
            if fresh != "stale":
                seen_now(number, now)
        S.map6 = known
        with rule_map_lock:
            S.rules6 = dict(known)
        rebuild_address_map()
        if S.seeded:
            for number in sorted(made):
                note_new_device(number, "", now)
        rebuild_rule_map()
        if db.in_transaction:
            db.commit()


def ipv6_rules(table):
    """Whose rules a lookup from each IPv6 address gets, from the IPv6 neighbour table just read:
    {address: device number}. The same matching as note_ipv6_addresses, but from memory alone
    (S.hw_device), so that the look a lookup may be waiting on (ipv6_look) can publish it without
    waiting for the database. A hardware address never seen before has no device yet and is left
    out; note_ipv6_addresses makes its device a moment later."""
    known = {}
    for addr, entry in (table or {}).items():
        mac = clean_mac(entry[0] if isinstance(entry, tuple) else entry)
        if not mac or addr in S.v6_own:
            continue
        if mac == S.hub_mac:
            number = S.hub_device
        elif mac in S.shared_macs or mac in S.hw_unsettled:
            continue
        else:
            number = S.hw_device.get(mac)
        if number is not None:
            known[addr] = number
    return known


# ----- a device that may be another one with a new hardware address
#
# Nothing is ever merged automatically. But two things would let rules slip if nothing were done:
#
#   - A phone told to "forget this network" comes back with a new private Wi-Fi address, so as a
#     new device, usually at the number it had before. If it simply had no rules, forgetting the
#     network would be a way out of bedtime.
#   - Rules can be held against a number alone (a device known only by its address: set before
#     QuietNet knew which device has it, left there by the move from an older version because the
#     old tables could not say whose they were, or for a device behind a Wi-Fi range extender).
#     When a device known by its hardware address then turns up at that number, the rules would
#     silently stop applying.
#
# In both cases the newcomer is given the other device's rules AS WELL AS its own, for now
# (S.provisional), and the owner is asked "is it the same device?". "Yes" joins the two
# (merge_devices). "No" ends it (end_follow). If the first device is seen on the network again
# while the newcomer is too, they cannot be one device, and it ends by itself.

def devices_with_rules():
    """The numbers of the devices that carry anything of their own: a name, a group, an internet
    switch, a blocked service, a schedule or "cut live connections". Reads S only."""
    out = set(k for k in S.given if isinstance(k, int)) | set(k for k in S.dev_group if isinstance(k, int))
    out.update(k for k in S.enforced if isinstance(k, int))
    scopes = list(S.off) + [scope for scope, ids in list(S.svc_blocks.items()) if ids]
    scopes += [x["scope"] for x in list(S.schedules)]
    for scope in scopes:
        if scope.startswith("dev:") and scope[4:].isdigit():
            out.add(int(scope[4:]))
    return out


def worth_following(number):
    """Does this device carry something a newcomer at its address should be held to until the
    owner has answered: a name, a rule of its own, or a group other than the one every new device
    is put in anyway? (A departed visitor that was only in the new-device group needs no question:
    the next visitor gets that group as a new device.) Reads S only."""
    return (number in S.given or holds_rules(number)
            or (number in S.dev_group and S.dev_group[number] != new_device_group()))


def start_follow(number, other, addr, text, now):
    """Give the device `number` the rules of the device `other` as well as its own, until the owner
    says whether they are the same device, and note it for the owner. Call holding db_lock; the
    caller commits."""
    S.provisional[number] = other
    db.execute("INSERT OR REPLACE INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
               (number, other, "asked", now))
    add_event(addr, text, now)
    rules_changed()


def end_follow(number, now=None, why=""):
    """Stop giving the device `number` another device's rules: they are different devices. That is
    remembered, so the question is not asked again for the same two. The newcomer goes into the
    new-device group if one is chosen and it first appeared in the last NEW_DEVICE_DAYS days, as
    any other new device would have. `why` is the note kept for the owner. Returns the other
    device's number, or None if there was nothing to end. Call holding db_lock; the caller commits."""
    other = S.provisional.pop(number, None)
    if other is None:
        return None
    now = time.time() if now is None else now
    S.not_same.add((number, other))
    db.execute("INSERT OR REPLACE INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
               (number, other, "no", now))
    addr = (device_addresses(number) + [""])[0]
    if why:
        add_event(addr, why, now)
    if now - S.dev_first.get(number, 0) < NEW_DEVICE_DAYS * 86400:
        note_new_device(number, addr, now)
    rules_changed()
    return other


def note_followers(present, took_over, made, now, listed=()):
    """Start and end the "may be the same device" follows after one look (see the notes above).
    `present` is {device: (address, hardware address)} for the devices confirmed just now,
    `took_over` a list of (address, device there now, device the looks last gave that address's
    rules to) for addresses that changed hands at this look, `made` the devices first seen at
    this look, and `listed` the devices whose hardware address is anywhere in the neighbour table
    now, on a fresh entry or a stale one. Call holding db_lock; the caller commits.

    A follow starts when:
      - a device with a private Wi-Fi address and nothing of its own takes over the address of a
        device that has a name or rules, is known by its hardware address, is listed nowhere in
        the neighbour table now, and was last seen before (or within QUIET_AFTER of) the
        newcomer's first appearance. "Takes over" means the looks themselves had that address as
        that device's until now (S.had4): never the record of who used an address (address_use),
        which would hold every newcomer at a number the device left weeks ago to its rules;
      - or the address of such a device starts being answered for by a Wi-Fi range extender, so
        that QuietNet can no longer tell which device is there: its rules keep applying to that
        number (the device known only by that address follows it);
      - or a device known by its hardware address is confirmed at an address that a device known
        only by that address holds a name or rules against.
    A newcomer that takes the number of a device which is itself being held to another's rules
    follows that other device instead: a phone that forgets the network twice before the owner
    has answered is still held to its rules, and nothing ever follows a follower.
    Never for this computer or the router, never for two devices the owner has already said are
    different, and never onto rules the move set aside for the owner to choose (S.set_aside):
    that question is the owner's, and they apply to nobody until it is answered."""
    carrying = {number for number in devices_with_rules() if worth_following(number)}
    aside = S.set_aside
    for number, other in list(S.provisional.items()):
        if (number not in S.device_kind or other not in S.device_kind or other not in carrying
                or other in aside):
            S.provisional.pop(number, None)
            db.execute("DELETE FROM device_follow WHERE device=? AND follows=?", (number, other))
            rules_changed()
        elif S.device_kind.get(other) == "hw" and other in present and number in present:
            end_follow(number, now, "%s is on the network again, so the device now at %s is a different one and its "
                                    "rules no longer apply to that device." % (device_label(other), present[number][0]))
    for addr, number, other in took_over:
        # The device that had the number may itself have been held to another device's rules:
        # the rules belong to that one, so that is the one to follow.
        other = S.provisional.get(other, other)
        if (number in S.provisional or other in S.provisional or other == number or (number, other) in S.not_same
                or S.device_kind.get(other) != "hw" or other not in carrying or other in present or other in listed
                or number not in present or own_rules(number, count_group=False)):
            continue
        if S.device_kind.get(number) == "addr" and present[number][1] in S.shared_macs:
            start_follow(number, other, addr,
                         "The device at %s now connects through a Wi-Fi range extender, so QuietNet can't tell "
                         "which device it is. The rules for %s still apply to that number." % (addr, device_label(other)),
                         now)
            continue
        if (S.device_kind.get(number) != "hw" or not names.is_private_mac(present[number][1])
                or S.dev_first.get(number, now) < S.dev_last.get(other, 0) - QUIET_AFTER):
            continue
        made.discard(number)                # it may be a known device: not put in the new-device group for now
        start_follow(number, other, addr,
                     "A device with a new private Wi-Fi address now has the number %s, which %s had. It may be the "
                     "same device, so the rules for %s apply to it until you say." % (addr, device_label(other),
                                                                                     device_label(other)), now)
    for number, (addr, _) in sorted(present.items()):
        other = S.addr_only.get(addr)
        if (other is None or other == number or S.device_kind.get(number) != "hw" or other not in carrying
                or other in aside or number in S.provisional or (number, other) in S.not_same):
            continue
        made.discard(number)
        start_follow(number, other, addr,
                     "Rules are kept under the number %s, and a device QuietNet can tell apart now has it. The rules "
                     "apply to that device until you say whether they are for it." % addr, now)


def note_new_device(number, addr, now):
    """A device has been seen for the first time: put it in the new-device group, if one is chosen
    and it has no group. Only a device known by its hardware address: a device known only by an
    address may be a household device that has merely started showing behind a Wi-Fi range
    extender, and must not be restricted by accident. Call holding db_lock; the caller commits."""
    gid = new_device_group()
    if gid is None or S.device_kind.get(number) != "hw" or number in S.dev_group or number in S.provisional:
        return
    S.dev_group[number] = gid
    db.execute("INSERT OR REPLACE INTO group_member(device, gid, auto) VALUES(?,?,1)", (number, gid))
    add_event(addr, "A new device appeared%s and was put in the %s group, as you asked for new devices."
              % (" at " + addr if addr else "", S.group_names[gid]), now)
    rules_changed()


def device_notices_now(present, now):
    """The "is it the same device?" questions for the owner, as a list of {"from", "to", "name",
    "mac", "first", "same", "from_device", "to_device"}. `present` is {device: (address, hardware
    address)} for the devices confirmed at this look. Reads S only.

    "same" true: the newcomer ("to_device", at the address "to") already gets the other device's
    rules for now (S.provisional), and "from" is the same address. With it, "held" true says the
    rules were kept under a number alone (the other device is known only by its address), and
    "extender" true that the newcomer is a number behind a Wi-Fi range extender, which can't be
    joined to another device: the only answer then is "no, it's a different device". "same" false is only a
    suggestion, with nothing applied: a device with a name or rules has gone quiet (unseen for
    QUIET_AFTER) at about the time a device with a private Wi-Fi address and nothing of its own
    appeared for the first time, at another address ("from" is the quiet device's last address,
    '' if it has none now). Range extenders' hardware addresses, this computer and the router take
    no part. "name" is the name of the device the rules belong to."""
    out = []
    mac_of = {}
    for mac, number in list(S.hw_device.items()):
        mac_of.setdefault(number, mac)
    for number, other in sorted(S.provisional.items()):
        addr = present.get(number, ("", ""))[0] or (device_addresses(number) + [""])[0]
        out.append({"from": addr, "to": addr, "name": device_label(other), "mac": mac_of.get(number, ""),
                    "first": S.dev_first.get(number, now), "same": True, "from_device": other, "to_device": number,
                    "held": S.device_kind.get(other) == "addr", "extender": S.device_kind.get(number) == "addr"})
    followed = set(S.provisional.values())
    quiet = [d for d in sorted(devices_with_rules())
             if worth_following(d) and S.device_kind.get(d) == "hw" and d not in present and d not in followed and d not in S.provisional
             and S.dev_last.get(d) and now - S.dev_last[d] > QUIET_AFTER and mac_of.get(d) not in S.shared_macs]
    fresh = [(number, addr, mac) for number, (addr, mac) in sorted(present.items())
             if S.device_kind.get(number) == "hw" and names.is_private_mac(mac) and number not in S.provisional
             and not own_rules(number, count_group=False)
             and now - S.dev_first.get(number, 0) < NEW_DEVICE_DAYS * 86400]
    for other in quiet:
        for number, addr, mac in fresh:
            if S.dev_first.get(number, 0) >= S.dev_last[other] - QUIET_AFTER and (number, other) not in S.not_same:
                out.append({"from": (device_addresses(other) + [""])[0], "to": addr, "name": device_label(other),
                            "mac": mac, "first": S.dev_first.get(number, now), "same": False,
                            "from_device": other, "to_device": number, "held": False, "extender": False})
    return out[:MAX_NOTICES]


def device_warnings_now(seen_at, unsettled):
    """{device number: a plain-English warning for its page}, worked out after each look.
    `seen_at` is the look's {address: (hardware address, freshness)}, `unsettled` the hardware
    addresses found at two live addresses at once. Reads S only."""
    out = {}
    for ip, (mac, _) in seen_at.items():
        if mac in S.shared_macs and ip in S.addr_only:
            out[S.addr_only[ip]] = EXTENDER_OWNER
    for mac in unsettled:
        if mac in S.hw_device:
            out[S.hw_device[mac]] = UNSETTLED_WARNING
    for number in S.set_aside:
        out[number] = SET_ASIDE_WARNING
    for number, other in S.provisional.items():
        if S.device_kind.get(other) == "addr":
            out[number] = ("Rules were kept under this device's number before QuietNet could tell which device has "
                           "it. Until you say whether they are for this device, they apply to it.")
            continue
        label = device_label(other)
        if S.device_kind.get(number) == "addr":
            out[number] = ("The device at this number now connects through a Wi-Fi range extender, so QuietNet "
                           "can't tell which device it is. The rules for %s still apply to this number." % label)
            continue
        out[number] = ("This device turned up with a new private Wi-Fi address at the number %s had, so it may be "
                       "the same device. Until you say, the rules for %s apply to it as well as its own."
                       % (label, label))
        out.setdefault(other, "A device with a new private Wi-Fi address may be this one. Until you say whether it "
                              "is, these rules apply to that device too.")
    return out


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


# Devices that carry something the owner set or is being asked about are never forgotten: a group
# the owner put them in, "cut live connections", a rule or schedule of their own, or either side of
# a "same device?" question. (A name is spared separately, in forget_old_devices.) The new-device
# group QuietNet itself gave a device (group_member.auto) is no reason to keep it: every new
# hardware address gets that group, so a device making hardware addresses up would otherwise fill
# the device table for good, and no real newcomer could then be given a device.
KEPT_DEVICES_SQL = """
    SELECT device FROM group_member WHERE auto=0 UNION SELECT device FROM live_cut
    UNION SELECT device FROM device_follow WHERE state='asked'
    UNION SELECT follows FROM device_follow WHERE state='asked'
    UNION SELECT CAST(SUBSTR(scope, 5) AS INTEGER) FROM internet_off WHERE scope LIKE 'dev:%'
    UNION SELECT CAST(SUBSTR(scope, 5) AS INTEGER) FROM service_blocks WHERE scope LIKE 'dev:%'
    UNION SELECT CAST(SUBSTR(scope, 5) AS INTEGER) FROM schedules WHERE scope LIKE 'dev:%'"""


def forget_old_devices(now=None):
    """Keep the device tables small, each hour: forget address records and devices not seen for
    KEEP_DAYS (as long as history is kept, so a forgotten device has no history left), and beyond
    MAX_ADDRESS_USE and MAX_DEVICES the longest unseen. The two fixed devices are never forgotten,
    and neither is a device with a name, a group the owner put it in, rules of its own or an open
    "same device?" question (KEPT_DEVICES_SQL): a child's tablet left in a drawer for two months
    must still be under its bedtime when it comes out. A device whose only mark is the new-device
    group QuietNet itself gave it is forgotten like any other, its membership with it. A forgotten
    device that comes back is a new device with a new number, and gets that group again."""
    if not S.devices_ready:
        return
    now = time.time() if now is None else now
    cutoff = now - KEEP_DAYS * 86400
    save_address_use()
    with db_lock:
        db.execute("DELETE FROM address_use WHERE last<?", (cutoff,))
        db.execute("DELETE FROM address_use WHERE rowid IN "
                   "(SELECT rowid FROM address_use ORDER BY last DESC LIMIT -1 OFFSET ?)", (MAX_ADDRESS_USE,))
        db.execute("DELETE FROM device WHERE kind IN ('hw', 'addr') AND name='' AND last<? AND id NOT IN (%s)"
                   % KEPT_DEVICES_SQL, (cutoff,))
        db.execute("DELETE FROM device WHERE id IN (SELECT id FROM device WHERE kind IN ('hw', 'addr') AND name='' "
                   "AND id NOT IN (%s) ORDER BY last DESC LIMIT -1 OFFSET ?)" % KEPT_DEVICES_SQL, (MAX_DEVICES,))
        for table in ("device_hw", "address_use", "moved_address", "group_member", "behind_extender"):
            db.execute("DELETE FROM %s WHERE device NOT IN (SELECT id FROM device)" % table)
        db.execute("DELETE FROM device_follow WHERE device NOT IN (SELECT id FROM device) "
                   "OR follows NOT IN (SELECT id FROM device)")
        db.execute("DELETE FROM rule_conflict WHERE device NOT IN (SELECT id FROM device) "
                   "OR held NOT IN (SELECT id FROM device)")
        load_device_rows()
        db.commit()
        S.not_same = {pair for pair in S.not_same if pair[0] in S.device_kind and pair[1] in S.device_kind}
        if any(number not in S.device_kind for number in S.dev_group):
            # A forgotten device leaves no group membership behind (only the new-device group
            # QuietNet itself gave it can be forgotten with it: see KEPT_DEVICES_SQL).
            S.dev_group = {number: gid for number, gid in S.dev_group.items() if number in S.device_kind}
            rules_changed()
        load_move_notes()
        S.map4 = {addr: number for addr, number in S.map4.items() if number in S.device_kind}
        S.map6 = {addr: number for addr, number in S.map6.items() if number in S.device_kind}
        S.had4 = {addr: number for addr, number in S.had4.items() if number in S.device_kind}
        with rule_map_lock:
            S.rules4 = {addr: number for addr, number in S.rules4.items() if number in S.device_kind}
            S.rules6 = {addr: number for addr, number in S.rules6.items() if number in S.device_kind}
        rebuild_address_map()
        rebuild_rule_map()


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

    Its age is counted from the time of the move it was made for when that move finished (the
    later one, if the rules were moved after the history), otherwise (a copy left by a move that
    failed) from when the file was written. A part-written copy left by an
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
            moved = name == path and S.devices_ready and (S.copy_made_at or S.devices_moved_at)
            made = (S.copy_made_at or S.devices_moved_at) if moved else os.path.getmtime(name)
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
    groups are not touched here: move_rules_to_devices moves them next, in the same transaction.

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
      7. The time of the move is saved with the settings (the version of the tables is saved by
         move_rules_to_devices, when the rules have been moved too).
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
    for key, value in (("devices_moved_at", repr(now)), ("devices_fill", "pending")):
        db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, str(value)))
    add_event("", "QuietNet now keeps each device's history with the device itself, whatever address it has. "
                  "A copy of your data from just before this change, with the history up to then, is kept beside "
                  "it as %s for %d days and then deleted. Forgetting everyone's history deletes it too."
                  % (BEFORE_DEVICES, KEEP_DAYS), now)
    return {"devices": sum(1 for key in numbers if key.startswith("hw:")), "addresses": len(addresses),
            "uncertain": uncertain}


# What the old tables keep under addresses: names, groups, "cut live connections", and the rules
# and schedules whose scope is "device:<address>". Once the rules are held against the device these
# are left empty, so anything found in them later was put there by an older QuietNet run on this
# data (see old_rules_waiting).
OLD_RULES_SQL = """
    SELECT ip FROM devices WHERE name != '' UNION SELECT ip FROM device_group UNION SELECT ip FROM enforced
    UNION SELECT SUBSTR(scope, 8) FROM internet_off WHERE scope LIKE 'device:%'
    UNION SELECT SUBSTR(scope, 8) FROM service_blocks WHERE scope LIKE 'device:%'
    UNION SELECT SUBSTR(scope, 8) FROM schedules WHERE scope LIKE 'device:%'"""


def rules_in_words(things, groups, schedules):
    """What one address carried, in plain words for the owner: "called "Den TV"; in the Kids group;
    internet switched off; 2 blocked services (YouTube, TikTok); the "Bedtime" schedule; cut live
    connections". `things` is one entry of move_rules_to_devices' list; `groups` is {id: name} and
    `schedules` {id: name}."""
    parts = []
    if things["name"]:
        parts.append('called "%s"' % things["name"])
    if things["gid"] is not None:
        parts.append("in the %s group" % groups.get(things["gid"], "a"))
    if things["off"]:
        parts.append("internet switched off")
    if things["services"]:
        labels = sorted(S.svc_names.get(s, s) for s in things["services"])
        parts.append("%d blocked service%s (%s)" % (len(labels), "" if len(labels) == 1 else "s", ", ".join(labels[:6])))
    for sid in things["schedules"]:
        parts.append('the "%s" schedule' % schedules.get(sid, "unnamed"))
    if things["cut"] is not None:
        parts.append("cut live connections")
    return "; ".join(parts)


def move_rules_to_devices(now):
    """The second part of the move, in the same transaction as the first (build_devices): take
    every name, group and rule the old tables keep under an IPv4 address and hold it against a
    device. Changes the database only, never S, so that if anything fails the whole transaction is
    rolled back and QuietNet carries on exactly as it was. Returns {"moved", "held", "conflicts",
    "names_lost", "lines"}: how many addresses' rules went to a device known by its hardware
    address, how many stayed with their number, how many were left for the owner to decide, how
    many names gave way, and the report in plain words.

    Nothing is dropped and nothing is newly applied without the owner being told:

      - CERTAIN evidence only moves rules onto a device: the old record of which hardware address
        the rules under an address belong to (device_mac; failing that, the hardware address noted
        when "cut live connections" was switched on). Paused or not: a pause meant "these are that
        device's, and it is not here".
      - With no such record, a group or rules stay with the NUMBER: they go to a device known only
        by that address, and keep applying to lookups from it, as rules kept under an address
        always did. When a device QuietNet can tell apart is seen there, it is given them for now
        and the owner is asked whether they are its own (note_followers).
      - A name with no rules goes to the device its address was given to in the first part, even
        on a best guess: a name restricts nobody.
      - The rules behind a range extender's hardware address stay with the number, as before.
      - Two addresses whose rules are certainly ONE device's. The old tables could hold both, and
        the older QuietNet then applied to the device the set kept under the number it was NOT
        at, never the set under the number it had. So the set that was applying is the one kept
        with the device: the one from a number other than the one it was last recorded at (with
        more than two, the last of those in text order, as the old pass left it). Every other
        set that asks for something that one doesn't, the set under its present number among
        them, is SET ASIDE for the owner to choose (rule_conflict): it is kept against a device
        known only by that number, applies to no lookup and is given to no device until the
        owner has chosen to give it to the device, remove it, or leave it with the number
        (S.set_aside). So the device has exactly the rules it had the day before. A set that
        asks for nothing the kept one doesn't is folded in. Only when the old record can't say
        where the device was last (it was at none of the numbers, or the times are equal) is the
        choice a guess: then the first in order is kept and the owner is told it is a guess.
      - Two names landing on one device: the name kept with the rules that stay with it wins
        (failing that, the one from the address it was most recently at); the other is recorded
        in the notes and the report. A set that is set aside keeps its own name with it.
      - A device never seen before that was in the new-device group at a paused address keeps
        that group.
    Afterwards the old tables are emptied (their rows now live against devices; the copy kept
    before the move has them as they were), the version is saved, and the report is kept for the
    home page."""
    router = home_router() or S.router
    this_computer = {"127.0.0.1", "::1", S.local_ip}
    shared = {mac for (mac,) in db.execute("SELECT mac FROM shared_macs WHERE hits>=?", (SHARED_AFTER,))}
    groups = dict(db.execute("SELECT id, name FROM groups"))
    schedules = dict(db.execute("SELECT id, name FROM schedules"))
    kinds = dict(db.execute("SELECT id, kind FROM device"))

    def device(kind, key):
        """The number of the device with this key, made if it is not there."""
        row = db.execute("SELECT id FROM device WHERE key=?", (key,)).fetchone()
        if row:
            return row[0]
        number = db.execute("INSERT INTO device(kind, key, name, first, last) VALUES(?,?,?,?,?)",
                            (kind, key, "", now, now)).lastrowid
        kinds[number] = kind
        return number

    def by_hardware(mac):
        """The number of the device with this hardware address, made if it is not there."""
        row = db.execute("SELECT device FROM device_hw WHERE mac=?", (mac,)).fetchone()
        if row and row[0] in kinds:
            return row[0]
        number = device("hw", "hw:" + mac)
        db.execute("INSERT OR REPLACE INTO device_hw(mac, device, first, last) VALUES(?,?,?,?)", (mac, number, now, now))
        return number

    pi, hub = device("pi", "pi"), device("hub", "hub")
    hub_macs = {mac for (mac,) in db.execute("SELECT mac FROM device_hw WHERE device=?", (hub,))}
    carried = {}                                # address -> what it carries

    def at(addr):
        """The entry for what one address carries, made empty the first time."""
        return carried.setdefault(addr, {"addr": addr, "name": "", "gid": None, "off": False, "services": set(),
                                         "schedules": [], "cut": None})

    for ip, name in db.execute("SELECT ip, name FROM devices"):
        if ip and name:
            at(ip)["name"] = name
    for ip, gid in db.execute("SELECT ip, gid FROM device_group"):
        if ip and gid in groups:
            at(ip)["gid"] = gid
    for (scope,) in db.execute("SELECT scope FROM internet_off WHERE scope LIKE 'device:%'"):
        at(scope[7:])["off"] = True
    for scope, service in db.execute("SELECT scope, service FROM service_blocks WHERE scope LIKE 'device:%'"):
        at(scope[7:])["services"].add(service)
    for sid, scope in db.execute("SELECT id, scope FROM schedules WHERE scope LIKE 'device:%' ORDER BY id"):
        at(scope[7:])["schedules"].append(sid)
    owner, guests = {}, []
    for ip, mac in db.execute("SELECT ip, mac FROM enforced"):
        if ip:
            at(ip)["cut"] = clean_mac(mac)
            if clean_mac(mac):
                owner[ip] = clean_mac(mac)
    for ip, mac, paused, guest_mac, guest_gid in db.execute("SELECT ip, mac, paused, guest_mac, guest_gid FROM device_mac"):
        if clean_mac(mac):
            owner[ip] = clean_mac(mac)
        if paused and clean_mac(guest_mac) and guest_gid in groups:
            guests.append((clean_mac(guest_mac), guest_gid))
    guess = dict(db.execute("SELECT addr, device FROM moved_address"))

    def has_rules(things):
        """Does this address carry more than a name?"""
        return bool(things["gid"] is not None or things["off"] or things["services"] or things["schedules"]
                    or things["cut"] is not None)

    def recent(addr, number):
        """When the device was last recorded at this address (0 if never)."""
        return db.execute("SELECT MAX(last) FROM address_use WHERE addr=? AND device=?", (addr, number)).fetchone()[0] or 0

    def give(number, things, with_name=True):
        """Hold what one address carried against a device."""
        scope = "dev:%d" % number
        if with_name and things["name"]:
            db.execute("UPDATE device SET name=? WHERE id=?", (things["name"], number))
        if things["gid"] is not None:
            db.execute("INSERT OR REPLACE INTO group_member(device, gid) VALUES(?,?)", (number, things["gid"]))
        if things["off"]:
            db.execute("INSERT OR IGNORE INTO internet_off VALUES(?)", (scope,))
        for service in sorted(things["services"]):
            db.execute("INSERT OR IGNORE INTO service_blocks VALUES(?,?)", (scope, service))
        for sid in things["schedules"]:
            db.execute("UPDATE schedules SET scope=? WHERE id=?", (scope, sid))
        if things["cut"] is not None:
            db.execute("INSERT OR REPLACE INTO live_cut(device, mac) VALUES(?,?)",
                       (number, things["cut"] if kinds.get(number) == "addr" else ""))

    targets, lines = {}, []                     # device -> [(things, certain?)]
    counts = {"moved": 0, "held": 0, "conflicts": 0, "names_lost": 0}
    for addr in sorted(carried):
        things, mac = carried[addr], owner.get(addr, "")
        if addr in this_computer:
            number, certain = pi, True
        elif router and addr == router:
            number, certain = hub, True
        elif mac and mac in hub_macs:
            number, certain = hub, True
        elif mac and mac in shared:
            number, certain = device("addr", "addr:" + addr), True
        elif mac:
            number, certain = by_hardware(mac), True
        elif has_rules(things):
            number, certain = device("addr", "addr:" + addr), False
        else:
            number = guess.get(addr)
            number, certain = (number if number in kinds else device("addr", "addr:" + addr)), False
        targets.setdefault(number, []).append((things, certain))
    for number in sorted(targets):
        sets = sorted(targets[number], key=lambda s: (-s[1], -recent(s[0]["addr"], number), s[0]["addr"]))
        ruled = [s for s in sets if has_rules(s[0])]
        parked = []                             # addresses whose rules were set aside for the owner
        was_at = None                           # the number the device was last recorded at, when that can be told
        if kinds[number] == "hw" and len(ruled) > 1:
            # (Every set with rules that reaches a device known by its hardware address came on
            # certain evidence, and they are in order of when the device was last at each.)
            if recent(ruled[0][0]["addr"], number) > recent(ruled[1][0]["addr"], number):
                # The older QuietNet gave a device the rules kept under a number it was NOT at
                # (with several, the last in text order). That set was the one applying, so it
                # is the one that stays with the device.
                was_at = ruled[0][0]["addr"]
                applying = max(ruled[1:], key=lambda s: s[0]["addr"])
                ruled = [applying] + [s for s in ruled if s is not applying]
        if ruled:
            first = ruled[0][0]
            give(number, first, with_name=False)
            words = rules_in_words(dict(first, name=""), groups, schedules)
            if kinds[number] == "hw":
                counts["moved"] += 1
                lines.append("The rules kept under %s (%s) are now kept with the device itself, whatever number it has."
                             % (first["addr"], words))
            elif kinds[number] in ("pi", "hub"):
                lines.append("The rules kept under %s (%s) are kept with %s." % (
                    first["addr"], words, "this computer" if kinds[number] == "pi" else "the router"))
            elif ruled[0][1]:
                counts["held"] += 1
                lines.append("The rules kept under %s (%s) stay with that number, as before: the device there connects "
                             "through a Wi-Fi range extender, so QuietNet knows it only by its number."
                             % (first["addr"], words))
            else:
                counts["held"] += 1
                lines.append("QuietNet could not tell for certain which device the rules kept under %s are for (%s), "
                             "so they stay with that number and apply to whichever device has it. When QuietNet sees "
                             "a device there it will ask you whether they are that device's." % (first["addr"], words))
            for things, certain in ruled[1:]:
                same = (things["gid"] in (None, first["gid"]) and (first["off"] or not things["off"])
                        and things["services"] <= first["services"] and not things["schedules"]
                        and (things["cut"] is None or first["cut"] is not None))
                if kinds[number] != "hw" or same:
                    # This computer's or the router's two addresses, or nothing the first set lacks.
                    give(number, things, with_name=False)
                    continue
                parked.append(things["addr"])
                held = device("addr", "addr:" + things["addr"])
                give(held, things)
                words = rules_in_words(things, groups, schedules)
                if was_at:
                    text = ("The same device had rules under two numbers. It was last at %s, so the rules kept "
                            "under %s were the ones applying to it, and they still are. Those kept under %s were "
                            "not applying to it. They are set aside and apply to no device until you choose: %s."
                            % (was_at, first["addr"], things["addr"], words))
                else:
                    text = ("The same device had rules under two numbers, and QuietNet can't tell which were "
                            "applying to it. Those kept under %s are in use. Those kept under %s are set aside "
                            "and apply to no device until you choose: %s." % (first["addr"], things["addr"], words))
                db.execute("INSERT INTO rule_conflict(device, held, addr, text, ts) VALUES(?,?,?,?,?)",
                           (number, held, things["addr"], text, now))
                counts["conflicts"] += 1
                lines.append(text + " Choose on the home page what to do with them.")
        if was_at:
            sets = [ruled[0]] + [s for s in sets if s is not ruled[0]]   # the name kept with the rules that stay
        named = [things for things, _ in sets if things["name"] and things["addr"] not in parked]
        if named:
            db.execute("UPDATE device SET name=? WHERE id=?", (named[0]["name"], number))
            for things in named[1:]:
                if things["name"] != named[0]["name"]:
                    counts["names_lost"] += 1
                    text = ('The name "%s", kept under %s, was not kept: that device is now called "%s", the name '
                            'kept under %s.' % (things["name"], things["addr"], named[0]["name"], named[0]["addr"]))
                    lines.append(text)
                    add_event(things["addr"], text, now)
    for mac, gid in guests:
        if mac not in shared and mac not in hub_macs:
            db.execute("INSERT OR IGNORE INTO group_member(device, gid, auto) VALUES(?,?,1)", (by_hardware(mac), gid))
    for table in ("internet_off", "service_blocks"):
        db.execute("DELETE FROM %s WHERE scope LIKE 'device:%%'" % table)
    for table in ("devices", "device_group", "enforced", "device_mac"):
        db.execute("DELETE FROM %s" % table)
    if carried:
        add_event("", "QuietNet now keeps each device's name, group and rules with the device itself, whatever number "
                      "it has, so nothing has to be moved when a number changes. The rules of %d device%s went with "
                      "their device, %d stayed with a number, and %d need%s your decision on the home page."
                  % (counts["moved"], "" if counts["moved"] == 1 else "s", counts["held"], counts["conflicts"],
                     "s" if counts["conflicts"] == 1 else ""), now)
    try:
        old = json.loads(get_setting("rules_move_report", "[]") or "[]")
    except ValueError:
        old = []
    old = old if isinstance(old, list) else []
    for key, value in (("devices_version", DEVICES_VERSION), ("rules_moved_at", repr(now)),
                       ("rules_move_report", json.dumps((old + lines)[-MAX_REPORT_LINES:]))):
        db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, str(value)))
    return dict(counts, lines=lines)


def load_move_notes():
    """Load what the move of rules to the devices left for the owner: the rules it set aside for
    the owner to decide on (S.rule_conflicts, each {"id", "device", "held", "addr", "text"}; the
    devices holding them are S.set_aside, and until the owner has chosen they apply to no lookup:
    rebuild_rule_map, note_followers), its report in plain words (S.move_report), and how many
    numbers carry names or rules in the old tables again (S.old_rules; see old_rules_waiting).
    Call holding db_lock."""
    S.rule_conflicts = [{"id": cid, "device": number, "held": held, "addr": addr, "text": text}
                        for cid, number, held, addr, text in db.execute(
                            "SELECT id, device, held, addr, text FROM rule_conflict ORDER BY id")]
    aside = frozenset(c["held"] for c in S.rule_conflicts)
    if aside != S.set_aside:
        with rule_map_lock:
            S.set_aside = aside
        rebuild_rule_map()
        rules_changed()
    try:
        report = json.loads(get_setting("rules_move_report", "[]") or "[]")
    except ValueError:
        report = []
    S.move_report = [str(line) for line in report][-MAX_REPORT_LINES:] if isinstance(report, list) else []
    S.old_rules = old_rules_waiting()


def old_rules_waiting():
    """How many numbers carry a name, a group or rules in the tables from before the device
    tables. Those tables are emptied when the rules are moved to the devices and never written
    again, so anything in them now was put there by an older QuietNet that was run on this data
    afterwards. This version does not read them: the owner is told, and offered to have them
    brought in (move_old_rules). Call holding db_lock."""
    return len(db.execute(OLD_RULES_SQL).fetchall())


def move_old_rules():
    """The owner's "Bring them in": hold against devices the names, groups and rules that an older
    QuietNet left in the old tables (old_rules_waiting), by the same careful steps as the first
    move (move_rules_to_devices), in one transaction. Any error rolls it back and changes nothing.
    Returns an error message, or None when done."""
    if not S.devices_ready:
        return not_ready_message()
    with db_lock:
        save_address_use()                  # what the looks have seen, before the tables are read back
        if db.in_transaction:
            db.commit()
        db.execute("BEGIN IMMEDIATE")
        try:
            move_rules_to_devices(time.time())
            db.commit()
        except Exception as e:
            db.rollback()
            print("Could not bring in the rules an older QuietNet left:", e, flush=True)
            return "QuietNet could not bring them in (%s). Nothing was changed." % (str(e) or type(e).__name__)
        load_device_rows()
        load_rules()
        load_schedules()
        rebuild_rule_map()
    return None


def settle_conflict(cid, choice):
    """The owner's choice for one set of rules the move set aside (S.rule_conflicts): "give" joins
    them to the device they were certainly for (merge_devices: every rule either had is kept, and
    where both are in a group the device takes the group the set-aside rules named, with a note
    of the one it left), "remove" removes them, and "keep" leaves them with the number, where
    from then on they apply to whichever device has it, as rules held against a number do.
    "Keep" also remembers that they are not that device's (S.not_same), so that closing the
    question does not at once give them to that very device and ask about it again. Either way
    the question is closed. Returns an error message, or None when done."""
    entry = next((c for c in S.rule_conflicts if c["id"] == cid), None)
    if entry is None or choice not in ("give", "remove", "keep"):
        return "QuietNet doesn't know that choice."
    number, held = entry["device"], entry["held"]
    if choice == "give" and number in S.device_kind and held in S.device_kind:
        merge_devices(number, held, "You gave the rules kept under %s to %s." % (entry["addr"], device_label(number)),
                      prefer=held)
    with db_lock:
        if choice == "remove" and held in S.device_kind:
            clear_device_rules(held)
            add_event(entry["addr"], "You removed the rules kept under %s." % entry["addr"])
        if choice == "keep" and number in S.device_kind and held in S.device_kind:
            S.not_same.add((number, held))
            db.execute("INSERT OR REPLACE INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
                       (number, held, "no", time.time()))
            add_event(entry["addr"], "You left the rules kept under %s with that number. They apply to whichever "
                                     "device has it, but not to %s." % (entry["addr"], device_label(number)))
        db.execute("DELETE FROM rule_conflict WHERE id=?", (cid,))
        db.commit()
        load_move_notes()
        load_schedules()
    return None


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
        the devices (build_devices), and the names, groups and rules, which go from their
        addresses to the devices (move_rules_to_devices). Any error rolls all of it back, so the
        database is exactly as it was, QuietNet carries on with the old tables, and the owner is
        told ("failed"). It is tried again at the next start. Nothing in memory is changed until
        the transaction has been saved.
      - A database that already has the device tables for its history but still keeps its rules
        under addresses (version 1) gets only the second half, by the same steps.
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
            S.devices_notice = ("QuietNet needs about %d MB of free space to bring your household's data up to "
                                "date, and there is only %d MB. Nothing has been changed. Until it is done, each "
                                "device's rules stay with its number and do not follow it to a new one. Free some "
                                "space on this computer and QuietNet will try again within the hour." % (wanted, free))
            return S.devices_state
        S.devices_state, S.devices_notice = "moving", ""
        started = time.monotonic()
        copy_database(os.path.join(DATA, BEFORE_DEVICES))
        with db_lock:
            if db.in_transaction:
                db.commit()
            db.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                first_half = not devices_made()
                make_device_tables()
                report = build_devices(now) if first_half else {"devices": 0, "addresses": 0, "uncertain": 0}
                rules = move_rules_to_devices(now)
                db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('devices_copy_at', ?)", (repr(now),))
                db.commit()
            except BaseException:
                db.rollback()
                raise
            if first_half:
                S.moved_steady = time.monotonic()   # the fill waits FILL_SETTLE from here before it may finish
            load_devices()
        print("Moved the household's data to the device tables in %.1f seconds: %d devices, %d addresses "
              "(%d matched on a best guess); the rules of %d went with their device, %d stayed with a number, "
              "%d are for the owner to decide."
              % (time.monotonic() - started, report["devices"], report["addresses"], report["uncertain"],
                 rules["moved"], rules["held"], rules["conflicts"]), flush=True)
    except Exception as e:
        S.devices_ready = False
        S.devices_state = "failed"
        S.devices_notice = ("QuietNet could not bring your household's data up to date (%s). Nothing has been "
                            "changed. Until it is done, each device's rules stay with its number and do not follow "
                            "it to a new one. It will try again the next time it starts."
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
    S.addr_device and S.addr_rules right (note_ipv4_addresses); each minute it files waiting
    lookups against their device (tidy_history); each hour it forgets devices long gone
    (forget_old_devices) and the copy of the data from before the move once that is old enough
    (forget_old_copy; this one also while the move is still to do or has failed). The first look
    comes straight away, before the first pause: whose rules each address gets is not kept across
    a restart, so until a look has been taken every device gets the whole house's rules only.

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
        time.sleep(ADDRESS_LOOK)


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


def rule_key(who):
    """The device key for `who`, which may already be one, or an address. With the device tables
    in use an address stands for the device whose rules a lookup from it gets (S.addr_rules), and
    for itself if no device is known for it; a device number is returned as it is. On an older
    database the address is the key. One dictionary lookup at most."""
    if isinstance(who, str) and S.devices_ready:
        return S.addr_rules.get(who, who)
    return who


def scopes_for(who):
    """Every set of rules that applies to a device: the whole house, itself, and its group.
    `who` is a device key: a device number once the device tables are in use, an IPv4 address on
    an older database not moved over yet, or None (or an address no device is known for) for a
    lookup that gets the whole house's rules only. An address is also taken for the device whose
    rules a lookup from it gets (rule_key). Reads S only: no database, nothing slow.

    A device that may be another one with a new hardware address (S.provisional) gets that
    device's own rules and group as well as its own, until the owner says whether they are the
    same. On an older database, an address whose rules are paused because a different device has
    it now (S.paused_ips) gets the whole house's rules only."""
    out = ["all"]
    who = rule_key(who)
    if who is None or who == "":
        return out
    if isinstance(who, int):
        out.append("dev:%d" % who)
        if who in S.dev_group:
            out.append("group:%d" % S.dev_group[who])
        other = S.provisional.get(who)
        if other is not None:
            out.append("dev:%d" % other)
            if other in S.dev_group and S.dev_group[other] != S.dev_group.get(who):
                out.append("group:%d" % S.dev_group[other])
        return out
    if S.devices_ready or who in S.paused_ips:
        return out                          # an address no device is known for, or (older database) a paused one
    out.append("device:" + who)
    if who in S.dev_group:
        out.append("group:%d" % S.dev_group[who])
    return out


def other_dns_blocked_for(who):
    """Is this device kept away from other DNS services (OTHER_DNS_SERVICES)? Yes when the owner
    chose that for every device (S.other_dns_all), and otherwise only for devices the owner
    controls: "cut live connections" is on, it is in a group, or it has an internet switch, a
    blocked service or a schedule of its own. Devices with none of these are left alone, because
    a device set to use one of these services strictly (Android's Private DNS set to a name, an
    encrypted DNS profile on an iPhone or a Mac) does not fall back: it would lose all names.
    `who` is a device key. Reads S only, so it is cheap enough for a lookup."""
    if S.other_dns_all or live_cut_on(who):
        return True
    scopes = scopes_for(who)[1:]
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


def is_this_computer(who):
    """Is this QuietNet's own machine? Its lookups (the relay link, the clock, list downloads) are
    not a household device's, so the kill switch and 'internet off' never apply. `who` is a device
    key (the fixed "pi" device's number) or one of this computer's addresses."""
    return who in ("127.0.0.1", "::1") or (who is not None and (who == S.local_ip or who == S.pi_device))


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
    the kill switch, schedules, blocked services and switched-off devices stay in force.

    `client` is a device key (see scopes_for), which answer_query has already found with one
    dictionary lookup in S.addr_rules. Nothing here touches the database or waits for anything."""
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
    """The enforcer has seen the hardware address at an enforced address for the first time:
    remember it, so that if the address is later handed to a different device, that device is left
    alone. Only an older database needs this (rules kept under addresses): with the device tables
    in use the plan always names the hardware address to steer (live_cut_devices)."""
    with db_lock:
        if not S.devices_ready and ip in S.enforced and not S.enforced_mac.get(ip):
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


def live_cut_on(who):
    """Is "cut live connections" on for this device now? Its own switch, or that of a device it
    may be (S.provisional: see scopes_for). On an older database, the switch kept under its
    address, unless the rules there are paused because a different device has the address now.
    `who` is a device key (or an address: see rule_key). Reads S only."""
    who = rule_key(who)
    if isinstance(who, int):
        return who in S.enforced or S.provisional.get(who) in S.enforced
    return not S.devices_ready and who in S.enforced and who not in S.paused_ips


def live_cut_devices(table=None):
    """{address: (hardware address to steer, device key)} for every device "cut live connections"
    is on for and that can be steered right now. `table` is the IPv4 neighbour table as just read
    ({ip: (hardware address, freshness)}); read here when not given.

    With rules held against the device, the address to steer comes ONLY from the live neighbour
    table, never from a record of where the device used to be (address_use) and never from a
    device's own word (a DHCP request):
      - the table read for this tick must list the address, and with the device's own hardware
        address. The entry may be fresh or stale. A steered device's entry is stale for most of
        the time: Linux counts an entry as confirmed only for about half a minute after this
        computer itself last sent that device something (a DNS answer, a name question), and
        steering sends the device nothing of the kind. Dropping a device whenever its entry read
        stale would hand it back to the router between lookups, and a bedtime starting then would
        cut nothing. The steering message is addressed to that hardware address alone, so a
        different device at the address can't be steered by it; and when another device speaks
        from the address, Linux rewrites the entry and the address leaves the plan;
      - the address must be one the look at the neighbour table gave to that device (S.rules4:
        confirmed there, or its entry gone stale with the device confirmed nowhere else). That
        map is never filled from address_use or DHCP, and is empty after a restart until a look;
      - a stale entry is passed over when the same hardware address has an entry that is not
        stale at another address in this table: the device is there now, and the stale one is the
        address it left;
      - a device known only by its address (behind a Wi-Fi range extender) is steered only on its
        own switch, only while its entry is not stale (one hardware address answers for several
        devices there, so a stale entry says nothing about which), and only while the entry
        holds the hardware address noted when the cut was switched on, which is noted now if it
        was not known then;
      - every address reaches the firewall through ipaddress.IPv4Address.
    No matching entry in the table, no steering. This computer and the router are never steered.

    On an older database not moved to the device tables yet: the address the switch is kept
    under, with the hardware address noted when it was switched on ('' if not known), unless its
    rules are paused. Reads S; the caller holds db_lock."""
    if not S.devices_ready:
        return {ip: (S.enforced_mac.get(ip, ""), ip) for ip in S.enforced if ip not in S.paused_ips}
    if not S.enforced:
        return {}
    table = neighbour_table() if table is None else table
    entries, fresh_at = {}, {}              # fresh_at: hardware address -> addresses where its entry is not stale
    for ip, entry in (table or {}).items():
        mac, fresh = entry if isinstance(entry, tuple) and len(entry) == 2 else (entry, "")
        mac = clean_mac(mac)
        if not mac:
            continue
        try:
            ip = str(ipaddress.IPv4Address(str(ip)))
        except ValueError:
            continue
        entries[ip] = (mac, fresh)
        if fresh != "stale":
            fresh_at.setdefault(mac, set()).add(ip)
    held, out = S.rules4, {}
    for ip, (mac, fresh) in entries.items():
        number = held.get(ip)
        kind = S.device_kind.get(number)
        if not live_cut_on(number):
            continue
        if kind == "hw":
            if S.hw_device.get(mac) != number or (fresh == "stale" and fresh_at.get(mac)):
                continue
        elif kind == "addr":
            # Known only by its number: steered only on its own switch (never because a device it
            # stands in for has the cut on: QuietNet can't tell which device is there), only on an
            # entry that is not stale, and only while the hardware address noted for it still
            # answers there.
            noted = S.enforced_mac.get(number, "")
            if fresh == "stale" or number not in S.enforced or (noted and noted != mac):
                continue
            if not noted:
                S.enforced_mac[number] = mac
                db.execute("UPDATE live_cut SET mac=? WHERE device=?", (mac, number))
                db.commit()
        else:
            continue
        out[ip] = (mac, number)
    return out


def plan_neighbours():
    """{ip: hardware address} for the enforcer: the neighbour table enforcement_plan read a moment
    ago for the same tick, if it read one, so the table is not read twice every two seconds;
    otherwise read now (see neighbours)."""
    read_at, table = S.plan_table
    if table is not None and time.monotonic() - read_at < 1.5:
        return {ip: mac for ip, (mac, _) in table.items()}
    return neighbours()


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

    Which addresses to steer, and the hardware address expected at each, come from the live
    neighbour table (live_cut_devices): a device is steered wherever that table lists its own
    hardware address at the address its rules are held at, on a fresh entry or a stale one, and
    nowhere else. The enforcer checks the hardware address again before it sends anything.

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
    table = None
    if S.devices_ready and S.enforced:
        table = neighbour_table()                      # read outside the lock: it runs a system tool
        S.plan_table = (time.monotonic(), table)
    with db_lock:                                      # copies: other threads change these while we work
        steer = live_cut_devices(table)
    if not steer:
        S.shared_left = {}
        return {}
    victims = {ip: mac for ip, (mac, _) in steer.items()}
    who = {ip: key for ip, (_, key) in steer.items()}  # the device each address belongs to, for its rules
    with resolved_lock:
        names = list(S.resolved)
    now = time.time()
    paused = now < S.paused_until
    key = (S.rules_version, paused, tuple(sorted(x["id"] for x in active_schedules())),
           tuple(sorted((ip, str(who[ip])) for ip in victims)), S.local_ip)
    cache = S.plan_cache
    if cache.get("key") != key or now - cache.get("made", 0) > 60:
        cache = S.plan_cache = {"key": key, "made": now, "off": {}, "cut": {}}
    for victim in victims:
        if victim not in cache["off"]:
            # A made-up name only comes back blocked for one of the 'everything' reasons.
            blocked, why, _ = decision("quietnet.invalid", who[victim], paused)
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
                blocked, why, _ = decision(domain, who[v], paused)
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


# How old (seconds) the neighbour table enforcement_plan last read may be for plan6 to go by it.
# The enforcer asks for both every two seconds, plan6 first, so the table plan6 finds is the one the
# tick before read; a tick that ran late still finds it.
PLAN_TABLE_KEPT = 5


def steered_now():
    """{IPv4 address: (hardware address, device key)} for the devices "Cut live connections" is on for
    and that can be steered right now, for plan6: live_cut_devices' answer, so with the device tables
    in use only a device the live neighbour table lists, at the address its rules are held at and with
    its own hardware address. Goes by the neighbour table enforcement_plan read for the tick before
    (S.plan_table) while that is no more than PLAN_TABLE_KEPT seconds old, so `ip neigh` is not run
    twice every two seconds; otherwise the table is read here, before the lock is taken, because
    reading it runs a system tool."""
    table = None
    if S.devices_ready and S.enforced:
        read_at, table = S.plan_table
        if table is None or time.monotonic() - read_at > PLAN_TABLE_KEPT:
            table = neighbour_table()
    with db_lock:
        return live_cut_devices(table)


def plan6():
    """What IPv6 steering should do now, for the enforcer's IPv6Steerer (option c2). Reads memory
    only (no database beyond a quick locked copy; the neighbour table only when the IPv4 plan has not
    just read it: see steered_now), so it is cheap enough to run every two seconds on the enforcer's
    tick. While the setting is off no device is named and nothing is read.

    Returns {"enabled", "hub", "our_v6", "port", "servers", "shared", "devices"}:
      - "enabled" is the household's setting (off unless turned on);
      - "hub" is the real router heard announcing IPv6 most recently, by its link-local and hardware
        addresses ({} until one is heard, which keeps the steerer from doing anything);
      - "devices" are the devices "Cut live connections" is on for and that the live neighbour table
        lists now (steered_now: no matching entry there, no steering, over IPv6 as over IPv4), keyed by
        the IPv4 address each is at, each with its hardware address and its own link-local IPv6
        address ("ll", or "" when this computer has not learned one yet). A merged device with two
        hardware addresses is named once for each, at the address each is at. A device known only by
        its number, or behind a range extender, is passed through with "ll": "" (and its hardware
        address is listed in "shared") so the steerer can report it and never steer it. A device
        whose hardware address is at two live addresses at once (S.hw_unsettled: its IPv6 addresses
        are matched to no device either), or has more than one link-local address in the neighbour
        table, is passed with "ll": "" and "unclear": True (it may be behind an extender not yet
        recognised), so it too is left alone;
      - "our_v6" is a lasting IPv6 address of this computer to answer redirected lookups from (the one
        also offered to devices as a DNS server; '' when there is none, so no redirect is added);
      - "port" is the port QuietNet answers on while it is listening over IPv6 (None otherwise, so no
        redirect is added); "servers" the router's IPv6 DNS addresses to catch; "shared" the range
        extenders' hardware addresses, never steered."""
    hub = {}
    now = time.time()
    with router_dns_lock:
        heard = [(a, r) for a, r in S.routers_v6.items() if r.get("mac")]
        if heard:
            addr, rec = max(heard, key=lambda ar: ar[1].get("heard", 0))
            hub = {"v6": addr, "mac": rec["mac"]}
        named = [a for a, until in S.router_v6_dns.items() if until > now]
    ours = S.v6_own if S.dns_ipv6 else set()
    servers = ([hub["v6"]] if hub.get("v6") else []) + [a for a in named if a not in ours]
    by_mac = S.v6_by_mac
    devices = {}
    extenders = set(S.shared_macs)
    for ip, (mac, number) in (steered_now() if S.ipv6_steer else {}).items():
        if not mac:
            continue
        if mac in S.shared_macs or (S.devices_ready and S.device_kind.get(number) != "hw"):
            # Behind a range extender, or known only by its number: reported, never steered.
            devices[ip] = {"mac": mac, "ll": ""}
            extenders.add(mac)
            continue
        info = by_mac.get(mac) or {}
        lls = info.get("lls") or ([info["ll"]] if info.get("ll") else [])
        if len(lls) > 1 or (S.devices_ready and mac in S.hw_unsettled):
            # Several link-local addresses, or at two live addresses at once: left alone.
            devices[ip] = {"mac": mac, "ll": "", "unclear": True}
        else:
            devices[ip] = {"mac": mac, "ll": lls[0] if lls else ""}
    return {"enabled": S.ipv6_steer, "hub": hub, "our_v6": S.v6_dns if S.dns_ipv6 else "",
            "port": S.dns_port if S.dns_ipv6 else None, "servers": servers,
            "shared": sorted(extenders), "devices": devices}


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


def ipv6_match(client):
    """What this IPv6 address is matched to, or None: the number of the device whose rules it gets
    (S.addr_rules) once the device tables are in use, and on an older database the IPv4 address of
    the device with the same hardware address (S.v6_devices).

    A device known only by this very address that carries no group and no rules of its own is not
    a match. It is only where the history of an address nobody could be matched to was filed, and
    the device asking may be one with rules (its neighbour entry has gone, or it is behind a Wi-Fi
    range extender). So such an address is looked for again and refused like any unmatched one,
    not answered under the whole house's rules. Reads S only: a few dictionary lookups."""
    if not S.devices_ready:
        return S.v6_devices.get(client)
    number = S.addr_rules.get(client)
    if number is not None and S.addr_only.get(client) == number and not own_rules(number, count_name=False):
        return None
    return number


def matched_ipv6_device(client):
    """The device asking from this IPv6 address (see ipv6_match), or None if it can't be matched.
    Called for a lookup, before decision(), never inside it.

    A phone makes itself a new IPv6 address about daily, and ipv6_watcher looks only every minute.
    So an unknown address asks for a look straight away (ask_for_ipv6_look) and, when a look is
    under way or can start at once, this lookup waits for it, for V6_ANSWER_WAIT seconds at most,
    and then looks the address up again. It does not wait when the watcher finished a look less
    than V6_QUICK_GAP seconds ago (the next one is not due yet) or when V6_MAX_WAITING lookups are
    waiting already, so a flood from made-up addresses can't tie up the threads that answer
    everyone else. The wait runs on one of the answering threads; the thread that receives lookups
    never waits."""
    seen_round = S.v6_round
    mapped = ipv6_match(client)
    if mapped is not None:
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
    return ipv6_match(client)


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
    # `who` is the device key the lookup is judged under (see scopes_for); `client` is the address
    # it is recorded under in the history.
    if client in ("127.0.0.1", "::1") or client in S.v6_own:
        client = S.local_ip
        who = S.pi_device if S.devices_ready else client
    elif S.devices_ready:
        # Rules are held against the device: one dictionary lookup says whose rules this address
        # gets (S.addr_rules), over IPv4 and IPv6 alike. An IPv4 address no device is known for
        # gets the whole house's rules. An IPv6 address that can't be matched (one known only by
        # itself, with nothing held against it, counts as unmatched: ipv6_match) is looked for at
        # once (matched_ipv6_device); if it still can't be, and any device is treated differently
        # from the whole house (device_rules_exist), the lookup is refused, rather than answered
        # as if it came from no device in particular. A refused device tries its next DNS server.
        # That may be QuietNet's IPv4 address, or the router's own IPv6 DNS server, which is a way
        # round QuietNet, not an outage (docs/KNOWN_ISSUES.md, issue 5).
        if client and ":" in client:
            who = ipv6_match(client)
            if who is None:
                who = matched_ipv6_device(client)
                if who is None and device_rules_exist():
                    return reply(data, qend, 5)
            client = S.v6_devices.get(client, client)   # the history still files it under its IPv4 address
        else:
            who = S.addr_rules.get(client)
        if who is None:
            who = source
    elif client and ":" in client:
        # An older database, with rules still kept under IPv4 addresses: a device asking from its
        # own IPv6 address is judged under its IPv4 address if it can be matched, and refused if
        # not while any device is treated differently, as above.
        mapped = matched_ipv6_device(client)
        if mapped:
            client = mapped
        elif device_rules_exist():
            return reply(data, qend, 5)
        who = client
    else:
        who = client
    if name in NO_SUCH_NAME_SIGNALS or name in BLOCKED_SIGNALS:
        # The 'use the network's DNS' signals (see NO_SUCH_NAME_SIGNALS): the same answer for every
        # device, paused or not, whatever the rules say. They are written to the history as blocked,
        # because they were, so the owner can see which devices tried to bypass QuietNet.
        note_lookup(client, name, 1, source)
        if name in NO_SUCH_NAME_SIGNALS:
            return reply(data, qend, 3)
        return blocked_reply(data, qtype, qend)
    if is_other_dns_service(name) and other_dns_blocked_for(who):
        # Another DNS service (see OTHER_DNS_SERVICES), for a device the owner controls (or every
        # device, if the owner chose that): blocked, paused or not, whatever else the rules say,
        # and noted so the device's page can say it tried.
        note_lookup(client, name, 1, source)
        if who in S.other_dns or len(S.other_dns) < MAX_OTHER_DNS_DEVICES:
            S.other_dns[who] = time.time()
        return blocked_reply(data, qtype, qend)
    if not loggable:
        # Names that skip the checks: odd characters, home-network endings, reverse lookups.
        # If this device's internet is off they get the blocked answer, so they can't be used
        # to tunnel out. Otherwise home-network names go to the router, the rest to the internet.
        if internet_cut(who):
            return blocked_reply(data, qtype, qend)
        if is_home_name(name, qtype):
            return ask_router(data, client, qend, forwarder)
        resp = forwarder(data)
        return cap_ttls(resp) if resp else reply(data, qend, 2)
    blocked = decision(name, who, time.time() < S.paused_until)[0]
    note_lookup(client, name, 1 if blocked else 0, source)
    if blocked:
        return blocked_reply(data, qtype, qend)
    if qtype in NO_IPV6_TYPES and (live_cut_on(who) or no_ipv6_for_everyone(name, qtype, who)):
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
# The same for IPv6 (IPV6_RECVPKTINFO asks for it; IPV6_PKTINFO carries it). Their numbers on Linux
# have always been 49 and 50. Needed so an IPv6 lookup the enforcer redirected from the router's
# address is answered from the address it was redirected to (option c2).
IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49) if sys.platform.startswith("linux") else None
IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50) if sys.platform.startswith("linux") else None


def ask_for_reply_address(sock):
    """On Linux, ask a UDP socket to report, with each lookup, which of this computer's addresses it
    was sent to. True if that worked.

    Why: the socket listens on every address at once, so without this the system picks the address an
    answer is sent from. When the enforcer redirects a steered device's lookup meant for 8.8.8.8 (or,
    over IPv6, the router) to this computer (see enforcer.nft_ruleset), the answer must leave from
    exactly the address the lookup was redirected to; only then can the firewall put the original
    server back as the sender. An answer from any other address of this computer would be thrown away
    by the device. Both the IPv4 and the IPv6 listener ask for it, each in its own way."""
    if not hasattr(sock, "recvmsg"):
        return False
    try:
        if sock.family == socket.AF_INET and IP_PKTINFO is not None:
            sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
            return True
        if sock.family == socket.AF_INET6 and IPV6_RECVPKTINFO is not None:
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
            return True
    except OSError:
        return False
    return False


def receive_lookup(sock, with_address):
    """Wait for one lookup. Returns (packet, sender, where it was sent). The last is None unless
    ask_for_reply_address worked (with_address): over IPv4 it is then the address text, over IPv6 a
    ('v6', address text, network card number) tuple, both ready to pass to send_answer."""
    if not with_address:
        data, addr = sock.recvfrom(4096)
        return data, addr, None
    space = socket.CMSG_SPACE(20 if sock.family == socket.AF_INET6 else 12)
    data, ancillary, _flags, addr = sock.recvmsg(4096, space)
    source = reply_address6(ancillary) if sock.family == socket.AF_INET6 else reply_address(ancillary)
    return data, addr, source


def reply_address(ancillary):
    """The address an IPv4 lookup was sent to, from the extra details Linux gives with it (a 12-byte
    record: the network card's number, then two addresses, the second being the one the packet
    was addressed to). None if it isn't there or isn't a plain address of one device."""
    for level, kind, value in ancillary:
        if level == socket.IPPROTO_IP and kind == IP_PKTINFO and len(value) >= 12:
            addr = ipaddress.IPv4Address(value[8:12])
            if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
                return None
            return str(addr)
    return None


def reply_address6(ancillary):
    """Where an IPv6 lookup was sent, from the extra details Linux gives with it (a 20-byte record:
    the address it was addressed to, then the network card's number). Returns a ('v6', address text,
    card number) tuple, or None if it isn't there or isn't a plain address of one device. The card
    number is kept because replying from an IPv6 address - a link-local one especially - needs it."""
    for level, kind, value in ancillary:
        if level == socket.IPPROTO_IPV6 and kind == IPV6_PKTINFO and len(value) >= 20:
            addr = ipaddress.IPv6Address(value[:16])
            if addr.is_multicast or addr.is_unspecified:
                return None
            return ("v6", str(addr), struct.unpack("=I", value[16:20])[0])
    return None


def send_answer(sock, resp, addr, source):
    """Send an answer back to the device that asked, from `source` (where the lookup was sent) when
    that is known, so the answer leaves from the address the device or the firewall expects. `source`
    is an IPv4 address text, an IPv6 ('v6', address text, card number) tuple, or None (let the system
    choose). If the system won't send from the address, fall back to letting it choose."""
    if isinstance(source, tuple) and len(source) == 3 and source[0] == "v6":
        try:
            info = ipaddress.IPv6Address(source[1]).packed + struct.pack("=I", source[2])
            sock.sendmsg([resp], [(socket.IPPROTO_IPV6, IPV6_PKTINFO, info)], 0, addr)
            return
        except OSError:
            pass
    elif source:
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


def udp_server(sock, shares=None):
    """Receive lookups on the UDP socket for ever, handing each to a pool of 64 worker
    threads so that one slow upstream answer does not hold up the rest. At most
    MAX_DNS_WAITING are in hand at once, and at most MAX_DNS_PER_DEVICE from any one device;
    beyond that, new lookups are dropped rather than queued without limit (a flood from one
    device, or the internet being down). The per-device share means one busy or broken device
    can't use up every slot and stop everyone else's lookups. Devices simply ask again.
    `shares` counts each device's lookups in hand; start_dns gives the IPv4 and IPv6 listeners
    the same one (UDP_SHARES), so a device's share is one across both and across all its
    addresses (see share_key). Left out, this listener counts by itself.
    On the IPv6 socket, lookups from outside the home network are dropped unanswered.
    On Linux, each answer leaves from the address its lookup was sent to (see ask_for_reply_address)."""
    pool = ThreadPoolExecutor(max_workers=64)
    with_address = ask_for_reply_address(sock)
    slots = threading.BoundedSemaphore(MAX_DNS_WAITING)
    on_ipv6 = sock.family == socket.AF_INET6
    shares = shares or Shares()

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
            shares.give_back(who)
            slots.release()

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
        pool.submit(functools.partial(work, who), data, addr, source)


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
    return bool(S.enforced or S.dev_group
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
    """Background thread: keep S.local_ip up to date, and take the minute's look at the neighbour
    table (refresh_devices: spotting Wi-Fi range extenders, and on an older database keeping the
    pause on an address a different device has). At start-up the network may not be ready
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


# Rules are held against the device (see the "devices" part of this file), so nothing has to be
# moved when a device changes address. What is left here: reading the neighbour table for the
# minute's pass (refresh_devices), spotting Wi-Fi range extenders, the owner's answers to "is it
# the same device?", and the small safeguard that stands in for all of that on an older database
# whose data has not been moved to the device tables yet (pause_old_rules).
QUIET_AFTER = 15 * 60          # seconds a device with rules must be unseen before it counts as "gone quiet"
NEW_DEVICE_DAYS = 3            # how recently a device must have first appeared to be offered as its replacement
MAX_EVENTS = 200               # notes of what QuietNet did to devices' rules, kept newest first
MAX_NOTICES = 10               # "may be the same device" notices shown at once
SHARED_AFTER = 3               # looks, each within an hour of the last, that must find one hardware address
                               # at two addresses at once before it counts as a range extender
KNOWN_MACS_DAYS = 30           # a hardware address not seen sharing for this long stops counting as a range extender
EXTENDER_OWNER = ("This device connects through a Wi-Fi range extender that shows several devices under one "
                  "hardware address, so QuietNet knows it only by its number. Its rules stay with that number and "
                  "can't follow it if the number changes.")
UNSETTLED_WARNING = ("This device's hardware address is at more than one number at once. Its rules apply only at "
                     "the number it had first, until the other goes or QuietNet has seen enough to know it is a "
                     "Wi-Fi range extender.")
SET_ASIDE_WARNING = ("These rules were kept under this number for a device that also had rules under another number. "
                     "They were not applying to it, so they are set aside and apply to no device until you choose "
                     "what to do with them on the home page.")
STILL_MOVING = ("QuietNet has not finished bringing your data up to date, so it can't do that yet. Try again in "
                "a few minutes.")
MOVE_WAITING = ("QuietNet needs more free space on this computer before it can bring your data up to date, so it "
                "can't do that yet. Free some space and it will try again within the hour.")
MOVE_FAILED = ("QuietNet could not bring your data up to date, so it can't do that yet. It will try again the next "
               "time QuietNet is restarted.")


def not_ready_message():
    """Why something that needs the device tables can't be done yet, in words that fit the state
    of the move (S.devices_state): waiting for free space, failed until the next restart, or
    simply not finished (STILL_MOVING)."""
    return {"waiting": MOVE_WAITING, "failed": MOVE_FAILED}.get(S.devices_state, STILL_MOVING)


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


def scope_of(who):
    """The scope a device's own rules are kept under: "dev:<number>" for a device number, and
    "device:<address>" for an address (an older database not moved to the device tables yet)."""
    return "dev:%d" % who if isinstance(who, int) else "device:%s" % who


def scope_device(scope):
    """The device key in a scope that names one device ("dev:12" gives 12, "device:192.168.1.5"
    gives that address), or None for the whole house, a group, or anything else."""
    if scope.startswith("dev:") and scope[4:].isdigit():
        return int(scope[4:])
    if scope.startswith("device:"):
        return scope[7:]
    return None


def own_rules(who, count_name=True, count_group=True):
    """Does this device carry anything of its own: a name (unless count_name is False), a group
    (unless count_group is False), an internet switch, a blocked service, a schedule, or "cut live
    connections"? `who` is a device key. Reads S only."""
    scope = scope_of(who)
    return bool((count_name and who in S.given) or (count_group and who in S.dev_group) or scope in S.off
                or S.svc_blocks.get(scope) or who in S.enforced
                or any(x["scope"] == scope for x in S.schedules))


def holds_rules(who):
    """Does this device carry real rules: an internet switch, a blocked service, a schedule or
    "cut live connections"? A name and a group alone don't count. Reads S only."""
    return own_rules(who, count_name=False, count_group=False)


def device_label(who):
    """How to name a device in a message: the name it was given, else the address it has or last
    had, else "a device with no name". `who` is a device key."""
    if who in S.given:
        return S.given[who]
    if isinstance(who, int):
        return (device_addresses(who) + ["a device with no name"])[0]
    return who


def steady_label(who):
    """A name for a device that does not move from one look to the next: the name it was given,
    else "device <number>". Never shown to anyone: a preview's marker is worked out with it
    (preview_marker), because the address an unnamed device is shown by (device_label) changes as
    its neighbour entries go fresh and stale, and that alone must not make a preview out of date."""
    if who in S.given:
        return S.given[who]
    return "device %d" % who if isinstance(who, int) else who


def add_event(ip, text, now=None):
    """Note something QuietNet did to a device's rules by itself, for the dashboard, keeping only
    the newest MAX_EVENTS. `ip` is the address it happened at ('' if none). Call holding db_lock;
    the caller commits."""
    db.execute("INSERT INTO events(ts, ip, text) VALUES(?,?,?)", (time.time() if now is None else now, ip, text))
    db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)", (MAX_EVENTS,))


def fixed_addresses():
    """The addresses that are never treated as a household device here: this computer and the
    home router."""
    return {a for a in (S.local_ip, home_router() or S.router) if a}


def new_device_group():
    """The group a device seen for the first time is put in, or None (none chosen, or it was deleted)."""
    return S.new_device_group if S.new_device_group in S.group_names else None


def note_shared_macs(doubled, now):
    """Count each hardware address in `doubled`, seen at two or more addresses at the same moment
    (each confirmed reachable just now). One found like that SHARED_AFTER times, each look within
    an hour of the last, is a range extender standing in for the devices behind it, not one
    device, and stays counted as one (S.shared_macs). A phone that has just changed address can
    show at both for a moment; once is never enough. One not seen sharing for KNOWN_MACS_DAYS is
    forgotten. Call holding db_lock; the caller commits."""
    for mac in sorted(doubled):
        db.execute("INSERT INTO shared_macs(mac, hits, last) VALUES(?,1,?) ON CONFLICT(mac) DO UPDATE SET "
                   "hits=CASE WHEN hits>=? THEN hits+1 WHEN last<? THEN 1 ELSE hits+1 END, last=excluded.last",
                   (mac, now, SHARED_AFTER, now - 3600))
    db.execute("DELETE FROM shared_macs WHERE last<?", (now - KNOWN_MACS_DAYS * 86400,))
    S.shared_macs = {mac for (mac,) in db.execute("SELECT mac FROM shared_macs WHERE hits>=?", (SHARED_AFTER,))}


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
    """The minute's look at the neighbour table, run by address_watcher, never on a lookup.
    `table` is {ip: mac} or {ip: (mac, freshness)} (the neighbour table when not given; see
    read_table).

      - Counts hardware addresses seen at two confirmed addresses at once, to spot Wi-Fi range
        extenders (note_shared_macs). This is done here, once a minute, and not on the look every
        few seconds, so that a phone caught at two addresses for a moment is not taken for one.
      - With the device tables in use, takes the same look the device keeper takes every few
        seconds (note_ipv4_addresses), which keeps S.addr_device and S.addr_rules right. Rules
        are held against the device, so nothing is moved.
      - On an older database not moved over yet, keeps the one safeguard that matters there
        (pause_old_rules)."""
    now = time.time() if now is None else now
    if table is None:
        table = neighbour_table()
    fixed = fixed_addresses()
    present, doubled = read_table(table, fixed)
    with db_lock:
        note_shared_macs(doubled, now)
        if not S.devices_ready:
            pause_old_rules(present, fixed, now)
        db.commit()
    note_ipv4_addresses(table, now)


# ----- an older database, not moved to the device tables yet
#
# Until move_to_devices has done its work (it waits for free space, and a failed move is not tried
# again until the next start), names, groups and rules are still kept under IPv4 addresses, as
# they were before the device tables. They are no longer moved from address to address: that
# machinery went when rules came to be held against the device. One safeguard is kept, because
# without it a visitor's phone given the number a child's tablet had would be cut off by the
# tablet's rules: the rules under an address are paused while a different device has it.

def set_owner(ip, mac, paused=False):
    """Older database only: record which hardware address the rules under this address belong to,
    and whether they are paused. Changes S and the database; call holding db_lock (the caller
    commits)."""
    S.dev_mac[ip] = mac
    if paused:
        S.paused_ips.add(ip)
    else:
        S.paused_ips.discard(ip)
    db.execute("INSERT OR REPLACE INTO device_mac(ip, mac, paused, guest_mac, guest_gid) VALUES(?,?,?,NULL,NULL)",
               (ip, mac, int(paused)))


def drop_owner(ip):
    """Older database only: forget which device this address's rules belong to (it has none
    left). Call holding db_lock."""
    S.dev_mac.pop(ip, None)
    S.paused_ips.discard(ip)
    db.execute("DELETE FROM device_mac WHERE ip=?", (ip,))


def pause_old_rules(present, fixed, now):
    """Older database only (S.devices_ready is False): pause the rules kept under an address
    while a different device has it, and let them apply again when the device they belong to is
    back. `present` is {ip: hardware address} from read_table, `fixed` this computer's and the
    router's addresses, which are never paused. Call holding db_lock; the caller commits.

    An address with a name or rules whose device is not known yet learns it from the device seen
    there. Nothing is paused when either hardware address is a Wi-Fi range extender's: QuietNet
    can't tell the devices behind one apart. Rules are not moved to a device's new address here;
    the owner is told so while the move to the device tables is waiting (S.devices_notice)."""
    for ip in list(S.dev_mac):
        if not own_rules(ip):
            drop_owner(ip)
    for ip, mac in present.items():
        if ip not in S.dev_mac and own_rules(ip):
            set_owner(ip, clean_mac(S.enforced_mac.get(ip, "")) or mac)
    warnings = {}
    for ip, mac in sorted(S.dev_mac.items()):
        if ip in fixed:
            continue
        here = present.get(ip)
        other = here is not None and here != mac and mac not in S.shared_macs and here not in S.shared_macs
        if other and ip not in S.paused_ips:
            set_owner(ip, mac, paused=True)
            add_event(ip, "A different device now has the address %s, so the rules for %s are paused "
                          "until it comes back." % (ip, device_label(ip)), now)
            rules_changed()
        elif ip in S.paused_ips and here is not None and not other:
            set_owner(ip, mac)
            add_event(ip, "%s is back at %s, so its rules apply again." % (device_label(ip), ip), now)
            rules_changed()
        if ip in S.paused_ips:
            warnings[ip] = ("This number now belongs to a different device; the rules for %s are paused "
                            "until it comes back." % device_label(ip))
    S.device_warnings = warnings


def same_device_at_address(ip):
    """Older database only: the owner's "It's the same device" on a card whose rules are paused
    because a different hardware address has its number now (pause_old_rules). The rules kept
    under that address are recorded as belonging to the hardware address there now, so they apply
    again. This is the one answer the owner can still give before the move to the device tables
    has been done; without it a phone back at its old number with a new private Wi-Fi address
    would have its rules paused with no way to lift the pause. Returns an error message, or None
    when done."""
    if ip in fixed_addresses():
        return "Rules can't be moved to or from this computer or the router."
    mac = clean_mac(neighbours().get(ip, ""))       # read before taking the lock: it runs a system tool
    with db_lock:
        if S.devices_ready:
            return "QuietNet has just finished bringing your data up to date. Open this page again and answer there."
        if ip not in S.paused_ips or not own_rules(ip):
            return "There are no paused rules under that number."
        if not mac:
            return "QuietNet can't see which device has this number now. Try again in a minute."
        set_owner(ip, mac)
        S.device_warnings.pop(ip, None)
        add_event(ip, "You said the device now at %s is %s, so its rules apply to it." % (ip, device_label(ip)))
        db.commit()
    rules_changed()
    return None


# ----- the owner's answers to "is it the same device?"

def device_ip(text):
    """The address as text if it is an IPv4 address, else None."""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def address_holder(addr):
    """The number of the device listed under this address in GET /api/devices: the device
    confirmed there now, else the last one seen there, else the one the last scan found there,
    else the device known only by that address. This computer's and the router's own addresses
    are always those two fixed devices. None if no device is known for it. This is the same order
    api_devices uses, so that a request that names a device by its card's address
    reaches the device that card shows."""
    if is_this_computer(addr) or addr in S.v6_own:
        return S.pi_device
    if addr and addr == (home_router() or S.router):
        return S.hub_device                 # the router's own address is always the router
    number = S.addr_device.get(addr)
    if number is None:
        use = S.addr_use.get(addr)
        if use:
            number = use[0]
        else:
            # Asked on the read-only connection, so a dashboard question never waits for db_lock.
            row = read_sql("SELECT mac FROM seen WHERE ip=?", (addr,)) if read_db is not None else []
            mac = clean_mac(row[0][0]) if row else ""
            number = S.hw_device.get(mac) if mac and mac not in S.shared_macs else None
            if number is None:
                number = S.addr_only.get(addr)
    return number if number in S.device_kind else None


def device_for_address(text, make=False):
    """The number of the device a request means when it names one by address: the device listed
    under that address now (address_holder). With `make`, an address no device is known for yet
    gets one, so a name or a rule can be held against it: the device with the hardware address
    the neighbour table lists there now (the live table first: a scan's record may be out of
    date), else the one the last scan found there, and failing both, or behind a Wi-Fi range
    extender, a device known only by that address. The address is then recorded as that device's,
    so its card shows what was just set. None if the text is not an IPv4 or IPv6 address, or no
    device is known (or can be made). Not for the lookup path: it may run a tool and it reads and
    writes the database."""
    try:
        addr = str(ipaddress.ip_address(str(text).split("%", 1)[0]))
    except ValueError:
        return None
    number = address_holder(addr)
    if number is None and make:
        row = sql("SELECT mac FROM seen WHERE ip=?", (addr,))
        mac = clean_mac(neighbours().get(addr, "")) or (clean_mac(row[0][0]) if row else "")
        with db_lock:
            now = time.time()
            if mac and mac not in S.shared_macs and mac != S.hub_mac:
                number = device_of_hw(mac, now)
                if number is not None:
                    use_address(addr, number, now, confirmed=False)
            if number is None:
                number = device_of_address(addr, now)
            if db.in_transaction:
                db.commit()
    return number


def device_in_request(body, make=False):
    """The device key a dashboard request is about. With the device tables in use: the device
    number in "device" if QuietNet knows it, else the device listed under the address in "ip"
    (device_for_address). On an older database not moved over yet: the address in "ip", as it
    always was. None if the request names no device QuietNet can use."""
    if not S.devices_ready:
        ip = body.get("ip")
        return ip[:64] if isinstance(ip, str) and ip else None
    number = device_number(body.get("device"))
    if number is None and isinstance(body.get("ip"), str):
        number = device_for_address(body["ip"], make)
    return number


def stored_scope(scope, make=False):
    """The scope to keep a rule under, from the scope a request gave (already matched against
    SCOPE). The whole house and groups are as given. With the device tables in use a device is
    always kept by its number: "dev:<number>" must be a device QuietNet knows, and
    "device:<address>", which an older dashboard page still sends, means the device listed under
    that address now (with `make`, an address no device is known for gets a device known only by
    that address). On an older database not moved over yet, "device:<address>" is kept as given.
    None if the request names a device QuietNet can't use."""
    if scope == "all" or scope.startswith("group:"):
        return scope
    if not S.devices_ready:
        return scope if scope.startswith("device:") else None
    if scope.startswith("dev:"):
        number = device_number(scope[4:])
    else:
        number = device_for_address(scope[7:], make)
    return None if number is None else "dev:%d" % number


def shown_scope(scope):
    """A kept scope as the dashboard is given it. A device's scope is given as "device:<address>"
    when the device has an address now (the first GET /api/devices would list with it), since
    that is the only form a page written before the device tables understands; a device with no
    address now is given as "dev:<number>". Everything else is as kept."""
    number = scope_device(scope)
    if isinstance(number, int):
        addresses = device_addresses(number)
        if addresses:
            return "device:" + addresses[0]
    return scope


def set_device_name(who, name):
    """Give a device a name ('' clears it). `who` is a device key. Changes S and the database."""
    with db_lock:
        if isinstance(who, int):
            db.execute("UPDATE device SET name=? WHERE id=?", (name, who))
        else:
            db.execute("INSERT INTO devices(ip,name) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name",
                       (who, name))
        db.commit()
        if name:
            S.given[who] = name
        else:
            S.given.pop(who, None)


def set_device_group(who, gid):
    """Put a device in a group, or take it out of its group (`gid` None or an unknown group).
    `who` is a device key. Changes S and the database."""
    with db_lock:
        table, column = ("group_member", "device") if isinstance(who, int) else ("device_group", "ip")
        if gid in S.group_names:
            S.dev_group[who] = gid
            db.execute("INSERT OR REPLACE INTO %s(%s, gid) VALUES(?,?)" % (table, column), (who, gid))
        else:
            S.dev_group.pop(who, None)
            db.execute("DELETE FROM %s WHERE %s=?" % (table, column), (who,))
        db.commit()
        rules_changed()


def set_live_cut(who, on, mac=""):
    """Switch "cut live connections" on or off for a device. `who` is a device key. `mac` is the
    hardware address seen at its address when it was switched on, kept for a device known only by
    an address (and on an older database), so that a different device given that address later is
    not steered by mistake; a device known by its hardware address needs none. Changes S and the
    database."""
    with db_lock:
        table, column = ("live_cut", "device") if isinstance(who, int) else ("enforced", "ip")
        if on:
            if isinstance(who, int) and S.device_kind.get(who) == "hw":
                mac = ""
            S.enforced.add(who)
            S.enforced_mac[who] = mac
            db.execute("INSERT OR REPLACE INTO %s(%s, mac) VALUES(?,?)" % (table, column), (who, mac))
        else:
            S.enforced.discard(who)
            S.enforced_mac.pop(who, None)
            db.execute("DELETE FROM %s WHERE %s=?" % (table, column), (who,))
        db.commit()
        rules_changed()


def clear_device_rules(number):
    """Remove everything a device carries but its name: its group, its internet switch, its
    blocked services, its schedules and "cut live connections". Changes S and the database; call
    holding db_lock (the caller commits and reloads the schedules)."""
    scope = "dev:%d" % number
    S.dev_group.pop(number, None)
    S.off.discard(scope)
    S.svc_blocks.pop(scope, None)
    S.enforced.discard(number)
    S.enforced_mac.pop(number, None)
    db.execute("DELETE FROM group_member WHERE device=?", (number,))
    db.execute("DELETE FROM live_cut WHERE device=?", (number,))
    for table in ("internet_off", "service_blocks", "schedules"):
        db.execute("DELETE FROM %s WHERE scope=?" % table, (scope,))


def merge_devices(keep, gone, note="", prefer=None, prefer_name=None):
    """The owner says two entries are one device: join `gone` into `keep`. Everything `gone` has
    goes to `keep`: its hardware addresses, its addresses and the record of them, and its history.
    `keep` ends with every internet switch, blocked service, schedule and "cut live connections"
    that either had. A device has one name and is in one group, so where both had one, one gives
    way, and the owner is told which in the recent changes, every time: the name kept is that of
    `prefer_name` (one of the two; `keep` when not given), else the other's; the group kept is
    that of `prefer` (one of the two; `keep` when not given), else the other's. A group that
    gives way takes its blocks and schedules off the device, which is why it is never dropped
    without a word. `gone` is then no more, and its number is never used again. `note` is kept
    for the owner. Never for this computer or the router.

    Changes S and the database in one step, holding db_lock; the history is then given its new
    device in small steps, letting go of the lock between them, as clear_history does."""
    with db_lock:
        save_address_use()                  # first, and by itself: it saves (commits) what the looks have seen
        ks, gs = "dev:%d" % keep, "dev:%d" % gone
        named, other = (gone, keep) if prefer_name == gone else (keep, gone)
        name = S.given.get(named) or S.given.get(other) or ""
        name_lost = S.given.get(other) if S.given.get(named) and S.given.get(other) not in (None, name) else None
        first = min([t for t in (S.dev_first.get(keep), S.dev_first.get(gone)) if t] or [0])
        last = max(S.dev_last.get(keep, 0), S.dev_last.get(gone, 0))
        db.execute("UPDATE device SET name=?, first=?, last=? WHERE id=?", (name, first, last, keep))
        S.dev_first[keep], S.dev_last[keep] = first, last
        S.given.pop(gone, None)
        if name:
            S.given[keep] = name
        first, second = S.dev_group.get(keep), S.dev_group.get(gone)
        if prefer == gone:
            first, second = second, first
        gid = first if first is not None else second
        group_lost = second if first is not None and second is not None and second != first else None
        S.dev_group.pop(gone, None)
        db.execute("DELETE FROM group_member WHERE device=?", (gone,))
        if gid is not None:
            S.dev_group[keep] = gid
            db.execute("INSERT OR REPLACE INTO group_member(device, gid) VALUES(?,?)", (keep, gid))
        if gs in S.off:
            S.off.discard(gs)
            S.off.add(ks)
            db.execute("DELETE FROM internet_off WHERE scope=?", (gs,))
            db.execute("INSERT OR IGNORE INTO internet_off VALUES(?)", (ks,))
        for service in S.svc_blocks.pop(gs, ()):
            S.svc_blocks.setdefault(ks, set()).add(service)
            db.execute("INSERT OR IGNORE INTO service_blocks VALUES(?,?)", (ks, service))
        db.execute("DELETE FROM service_blocks WHERE scope=?", (gs,))
        db.execute("UPDATE schedules SET scope=? WHERE scope=?", (ks, gs))
        if gone in S.enforced:
            mac = S.enforced_mac.pop(gone, "")
            S.enforced.discard(gone)
            db.execute("DELETE FROM live_cut WHERE device=?", (gone,))
            if keep not in S.enforced:
                mac = "" if S.device_kind.get(keep) == "hw" else mac
                S.enforced.add(keep)
                S.enforced_mac[keep] = mac
                db.execute("INSERT OR REPLACE INTO live_cut(device, mac) VALUES(?,?)", (keep, mac))
        db.execute("UPDATE device_hw SET device=? WHERE device=?", (keep, gone))
        for mac, number in list(S.hw_device.items()):
            if number == gone:
                S.hw_device[mac] = keep
        db.execute("UPDATE address_use SET device=? WHERE device=?", (keep, gone))
        db.execute("UPDATE moved_address SET device=? WHERE device=?", (keep, gone))
        for use in list(S.addr_use.values()):
            if use[0] == gone:
                use[0] = keep
        # A third device that is being held to the rules of the one that goes ("may be the same
        # device", not answered yet) is held to the kept device's from now on: the question is
        # still open, and the rules must not slip off it meanwhile. And what the owner said about
        # the one that goes ("not the same device as ...") is true of the kept device too.
        moved_on = time.time()
        for n, d in list(S.provisional.items()):
            if d == gone and n not in (keep, gone):
                S.provisional[n] = keep
                db.execute("INSERT OR REPLACE INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
                           (n, keep, "asked", moved_on))
        for a, b in list(S.not_same):
            pair = (keep if a == gone else a, keep if b == gone else b)
            if gone in (a, b) and pair[0] != pair[1] and S.provisional.get(pair[0]) != pair[1]:
                S.not_same.add(pair)
                db.execute("INSERT OR REPLACE INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
                           (pair[0], pair[1], "no", moved_on))
        db.execute("DELETE FROM device_follow WHERE device=? OR follows=?", (gone, gone))
        db.execute("DELETE FROM device_follow WHERE device=? AND follows=?", (keep, gone))
        S.provisional = {n: d for n, d in S.provisional.items() if gone not in (n, d)}
        S.not_same = {pair for pair in S.not_same if gone not in pair}
        # A question about rules set aside for the device that goes is now about the kept device;
        # one about rules the device that goes was holding is answered by this very joining.
        db.execute("UPDATE rule_conflict SET device=? WHERE device=?", (keep, gone))
        db.execute("DELETE FROM rule_conflict WHERE held=? OR held=device", (gone,))
        db.execute("DELETE FROM device WHERE id=?", (gone,))
        db.execute("DELETE FROM behind_extender WHERE device=?", (gone,))
        S.behind_extender = {n: mac for n, mac in S.behind_extender.items() if n != gone}
        S.device_kind.pop(gone, None)
        S.dev_first.pop(gone, None)
        S.dev_last.pop(gone, None)
        S.device_warnings = {k: v for k, v in S.device_warnings.items() if k not in (keep, gone)}
        S.device_notices = [n for n in S.device_notices if gone not in (n.get("from_device"), n.get("to_device"))
                            and keep not in (n.get("from_device"), n.get("to_device"))]
        S.map4 = {addr: (keep if n == gone else n) for addr, n in S.map4.items()}
        S.map6 = {addr: (keep if n == gone else n) for addr, n in S.map6.items()}
        with rule_map_lock:
            S.addr_only = {addr: n for addr, n in S.addr_only.items() if n != gone}
            S.rules4 = {addr: (keep if n == gone else n) for addr, n in S.rules4.items()}
            S.had4 = {addr: (keep if n == gone else n) for addr, n in S.had4.items()}
            S.rules6 = {addr: (keep if n == gone else n) for addr, n in S.rules6.items()}
        rebuild_address_map()
        rebuild_rule_map()
        here = (device_addresses(keep) + [""])[0]
        if note:
            add_event(here, note)
        if group_lost is not None:
            kept_group, lost_group = S.group_names.get(gid, "other"), S.group_names.get(group_lost, "other")
            add_event(here, "The two were in different groups. %s is now in the %s group and no longer in the %s "
                            "group, so what is blocked or scheduled for the %s group no longer applies to it. Change "
                            "its group on its page if that is wrong."
                      % (device_label(keep), kept_group, lost_group, lost_group))
        if name_lost:
            add_event(here, 'The two had different names. The device is called "%s"; the name "%s" was not kept.'
                      % (name, name_lost))
        db.commit()
        load_move_notes()
        load_schedules()                    # also tells the enforcer and the answer cache that rules changed
    while True:
        with db_lock:
            n = db.execute("UPDATE queries SET device=? WHERE id IN (SELECT id FROM queries WHERE device=? LIMIT ?)",
                           (keep, gone, PRUNE_BATCH)).rowcount
            db.commit()
            S.history_filed += 1
        if n < PRUNE_BATCH:
            break
        time.sleep(0.05)                    # give the history writer and the dashboard a turn at the lock


def same_device_by_hand(to_device, from_device=None):
    """The owner's "Yes, it's the same device" (and "Move the rules to this device"): the device
    `to_device` is the device `from_device`, which the rules belong to. Without `from_device` it
    is the device whose rules `to_device` is being given for now (S.provisional). The two are
    joined into one (merge_devices). Returns an error message, or None when done.

    The device known by a hardware address is the one kept: a phone's new private Wi-Fi address
    joins the phone it always was, and rules that were kept under a number alone go to the device
    that has it. Refused for this computer and the router, and, unless QuietNet was already
    giving it those rules, for a device that has rules of its own: joining then needs the owner
    to see what would apply afterwards, which the device page's "Merge with" shows first
    (merge_preview, merge_by_hand; the dashboard now asks its "same device?" questions that way
    too, and this call is kept for pages written before it). Refused too
    for rules the move set aside for the owner to choose: that choice is made on the home page
    (settle_conflict)."""
    if not S.devices_ready:
        return not_ready_message()
    asked = S.provisional.get(to_device)
    if from_device is None:
        from_device = asked
    if to_device not in S.device_kind or from_device not in S.device_kind or to_device == from_device:
        return "There are no rules to move."
    kinds = (S.device_kind[to_device], S.device_kind[from_device])
    if "pi" in kinds or "hub" in kinds:
        return "Rules can't be moved to or from this computer or the router."
    if kinds == ("addr", "hw"):
        return ("QuietNet knows that device only by its number (it is behind a Wi-Fi range extender), so it can't "
                "be joined to another device. The rules keep applying to that number.")
    if not own_rules(from_device):
        return "There are no rules to move."
    if from_device in S.set_aside or to_device in S.set_aside:
        return "Those rules are waiting for your decision under \"Rules that need your decision\" on the home page."
    if asked != from_device and holds_rules(to_device):
        return ("That device already has rules of its own. Use \"Merge with\" on its page instead: it shows "
                "what would apply to each of them before anything is changed.")
    keep, gone = (from_device, to_device) if kinds[1] == "hw" else (to_device, from_device)
    if kinds[1] == "hw" and to_device in S.dev_group and S.dev_group[to_device] == new_device_group():
        # The newcomer was only in the new-device group because QuietNet took it for a new device.
        # It is not one, so that group gives way: a visitors' group must not stick to the family's
        # tablet because it came back with a new hardware address.
        set_device_group(to_device, None)
    newcomer = S.given.get(to_device) or "the device at %s" % (device_addresses(to_device) + ["a new number"])[0]
    # Where both are in a group, the one kept is that of the device the rules belong to: it is
    # those rules the owner is accepting. merge_devices notes the group that gave way.
    merge_devices(keep, gone, "You said %s is the same device as %s, so they are now one device with one set of "
                              "rules." % (newcomer, device_label(from_device)), prefer=from_device)
    return None


def different_device_by_hand(number):
    """The owner's "No, it's a different device": stop giving the device `number` the rules of
    the device it might have been (end_follow). Those rules stay with the device they belong to.
    Returns an error message, or None when done."""
    if not S.devices_ready:
        return not_ready_message()
    with db_lock:
        other = S.provisional.get(number)
        if other is None:
            return "There are no rules here to keep for another device."
        label, here = device_label(other), (device_addresses(number) + ["this number"])[0]
        end_follow(number, None, "You said the device now at %s is not %s, so the rules for %s no longer apply to it."
                   % (here, label, label))
        S.device_warnings = {k: v for k, v in S.device_warnings.items() if k not in (number, other)}
        S.device_notices = [n for n in S.device_notices if n.get("to_device") != number]
        db.commit()
    return None


# ----- Merge and Separate, each shown to the owner before it is done
#
# Nothing is ever merged automatically, and nothing here happens on the first ask either. A request
# to merge two devices, or to separate a hardware address from a device, is answered with a
# preview: what would apply to each hardware address afterwards, in plain words. Only a second
# request that sends the preview's marker back ("seen") is carried out, and only while the preview
# would still read the same: if a rule, a name, a group or a hardware address has changed since,
# nothing is done and the owner is shown the new preview. So what is applied is what was shown.
# The one thing left out of that comparison is the address an unnamed device is shown by: it moves
# from one look to the next (whichever of a merged laptop's two addresses was confirmed last), and
# changes nothing that would be done. The marker is worked out with steady_label in its place.

PREVIEW_CHANGED = ("Something changed since this was shown, so nothing was done. Look at what would apply "
                   "now and confirm again.")
MAX_HARDWARE_ADDRESSES = 16    # hardware addresses one device may hold; no more can be merged into it


def schedule_words(x):
    """One schedule in plain words for a preview: 'the "Bedtime" schedule (all internet off, 21:00
    to 07:00)', with 'not in use' added for one that is switched off. `x` is an entry of S.schedules."""
    what = "all internet off" if x["off"] else "blocks " + ", ".join(
        sorted(S.svc_names.get(s, s) for s in x["services"])[:6])
    return 'The "%s" schedule (%s, %s to %s%s)' % (x["name"], what, x["start"], x["end"],
                                                  "" if x["enabled"] else ", not in use")


def rule_items(own, groups, cut):
    """What a device's rules come to, as an ordered {key: plain words}: the groups it is in, the
    internet switches, the blocked services, the schedules and "cut live connections". `own` is the
    device scopes whose rules count as the device's own ("dev:12"; several when two devices are
    about to become one), `groups` the ids of the groups whose rules reach it, `cut` whether "cut
    live connections" is on. What is set for the whole house is left out: it applies to every
    device whatever is merged or separated. The keys are the same for the same rule however it
    reaches the device, so two of these can be compared to say what is new and what stops. Reads
    S only."""
    items = {}
    groups = [gid for gid in dict.fromkeys(groups) if gid in S.group_names]
    for gid in groups:
        items[("group", gid)] = "In the %s group" % S.group_names[gid]
    scopes = [(scope, "", "own") for scope in own]
    scopes += [("group:%d" % gid, " for the %s group" % S.group_names[gid], gid) for gid in groups]
    for scope, tail, key in scopes:
        if scope in S.off:
            items[("off", key)] = "Internet switched off" + tail
    for scope, tail, key in scopes:
        for service in sorted(S.svc_blocks.get(scope, ()), key=lambda s: S.svc_names.get(s, s).lower()):
            items[("service", service, key)] = "%s blocked%s" % (S.svc_names.get(service, service), tail)
    for scope, tail, key in scopes:
        for x in list(S.schedules):
            if x["scope"] == scope:
                items[("schedule", x["id"])] = schedule_words(x) + tail
    if cut:
        items[("cut",)] = "Cut live connections"
    return items


def rules_now(number):
    """The rules that reach a device now, as rule_items gives them: its own, its group's, and
    those of a device it may be while the owner has not answered (S.provisional). Reads S only."""
    own, groups = ["dev:%d" % number], [S.dev_group.get(number)]
    other = S.provisional.get(number)
    if other is not None:
        own.append("dev:%d" % other)
        groups.append(S.dev_group.get(other))
    return rule_items(own, groups, number in S.enforced or other in S.enforced)


def hardware_of(number):
    """The hardware addresses that belong to a device, in order. Reads S only."""
    return sorted(mac for mac, n in list(S.hw_device.items()) if n == number)


def own_membership(number):
    """Is this device in its group because QuietNet put it there by itself (the group chosen for
    new devices), and not because the owner chose it? Asks the database, so not for a lookup."""
    row = sql("SELECT auto FROM group_member WHERE device=?", (number,))
    return bool(row and row[0][0])


def preview_marker(preview):
    """A short code for one preview, which changes whenever a rule, a name, a group or a hardware
    address in the preview would read differently. The page sends it back to have the change
    carried out (see the notes above). It is given the preview as built with steady_label, so the
    address an unnamed device happens to be shown by does not come into it."""
    return hashlib.sha256(json.dumps(preview, sort_keys=True).encode()).hexdigest()[:24]


def merge_problem(device, other):
    """Why these two devices can't be merged, in words for the owner, or None if they can.
    Never this computer or the router, never rules waiting for the owner's decision, never two
    devices both known only by a number, and never a number behind a Wi-Fi range extender (one
    hardware address answers for several devices there, so QuietNet could not keep the merged
    device together).

    Whether a number is behind a range extender is remembered (S.behind_extender, kept by the
    looks and saved), not read from what the last look happened to list: the device behind the
    extender may be asleep or away, or QuietNet may just have restarted, and the merge must be
    refused all the same. It lifts by itself when the extender has not been seen sharing for
    KNOWN_MACS_DAYS and is forgotten (S.shared_macs), or when a device known by its own hardware
    address is confirmed at that number."""
    if not S.devices_ready:
        return not_ready_message()
    if device not in S.device_kind or other not in S.device_kind or device == other:
        return "Choose two different devices to merge."
    kinds = (S.device_kind[device], S.device_kind[other])
    if "pi" in kinds or "hub" in kinds:
        return "This computer and the router can't be merged with another device."
    if device in S.set_aside or other in S.set_aside:
        return "Those rules are waiting for your decision under \"Rules that need your decision\" on the home page."
    if kinds == ("addr", "addr"):
        return ("QuietNet knows both of those only by their numbers, with no hardware address for either, so it "
                "can't keep them together as one device.")
    for number in (device, other):
        if S.device_kind[number] == "addr" and (S.behind_extender.get(number) in S.shared_macs
                                                or S.provisional.get(number) is not None):
            return ("QuietNet knows that device only by its number (it is behind a Wi-Fi range extender), so it can't "
                    "be joined to another device. The rules keep applying to that number.")
    if len(hardware_of(device)) + len(hardware_of(other)) > MAX_HARDWARE_ADDRESSES:
        return "That would give one device more hardware addresses than QuietNet keeps for a device."
    return None


def merge_plan(device, other):
    """How two devices would be merged: (the one kept, the one that goes, the group the merged
    device ends in or None, the groups that give way, the devices whose own-accord membership
    must be dropped first). `device` is the one the owner is merging INTO, whose name and group
    win where both have one; `other` is the one being merged into it.

    The device known by a hardware address is the one kept, whichever way round they were given:
    a device known only by a number has no hardware address to be recognised by. A group that
    QuietNet itself put a device in as a new device gives way to the other device's group, or to
    none: the device is not new, so the new-device group must not stick to it (or a visitors'
    group would follow the family's tablet home). That is so whichever of the two it is; when
    both were put in theirs that way, only `other`'s gives way. Otherwise the group kept is
    `device`'s, else `other`'s."""
    keep, gone = (other, device) if (S.device_kind[device], S.device_kind[other]) == ("addr", "hw") else (device, other)
    mine, theirs = S.dev_group.get(device), S.dev_group.get(other)
    kept = {device: mine, other: theirs}
    drop = []
    if theirs is not None and own_membership(other):
        drop.append(other)
    elif mine is not None and own_membership(device):
        drop.append(device)
    for number in drop:
        kept[number] = None
    gid = kept[device] if kept[device] is not None else kept[other]
    lost = [g for g in dict.fromkeys((mine, theirs)) if g is not None and g != gid]
    return keep, gone, gid, lost, drop


def merge_preview(device, other):
    """What merging `other` into `device` would do, for the owner to read before anything is
    done: (None, the preview) or (an error message, None). Changes nothing.

    The preview is {"device", "with", "keep" (the number the merged device will have), "label",
    "other_label", "name" (what it will be called), "group" and "group_name" (the group it will
    be in, null and '' for none), "notes" (plain-English lines, the last of which says whether
    Separate can undo the merge: it can only when both devices are known by a hardware address),
    "hardware" (one entry for each hardware address of either device: {"mac", "label" (the device
    it belongs to now), "applies" (every rule that will apply to it afterwards, each {"text",
    "new"}: "new" true if it does not apply to that hardware address today), "stops" (the rules
    that apply to it today and will not afterwards)}), "marker"}. Rules set for the whole house
    are left out: they apply either way."""
    problem = merge_problem(device, other)
    if problem:
        return problem, None
    keep, gone, gid, lost, _ = merge_plan(device, other)
    names_now = (S.given.get(device), S.given.get(other))
    name = names_now[0] or names_now[1] or ""
    follow = S.provisional.get(keep)
    own, groups, cut = ["dev:%d" % keep, "dev:%d" % gone], [gid], keep in S.enforced or gone in S.enforced
    if follow is not None and follow != gone:
        own.append("dev:%d" % follow)
        groups.append(S.dev_group.get(follow))
        cut = cut or follow in S.enforced
    after = rule_items(own, groups, cut)
    before = {number: rules_now(number) for number in (device, other)}
    by_number = [number for number in (device, other) if S.device_kind[number] == "addr"]

    def build(label):
        """The preview with each device named by `label`: device_label for the one the owner
        reads, steady_label for the one the marker is worked out from."""
        hardware = []
        for number in (device, other):
            for mac in hardware_of(number):
                hardware.append({"mac": mac, "label": label(number),
                                 "applies": [{"text": text, "new": key not in before[number]}
                                             for key, text in after.items()],
                                 "stops": [text for key, text in before[number].items() if key not in after]})
        notes = []
        if name:
            notes.append('The merged device will be called "%s".' % name
                         + (' The name "%s" is not kept.' % names_now[1]
                            if all(names_now) and names_now[1] != name else ""))
        for g in lost:
            notes.append("It will no longer be in the %s group, so what is blocked or scheduled for that group "
                         "stops applying to it." % S.group_names.get(g, "other"))
        for held, to in sorted(S.provisional.items()):
            if to in (device, other) and held not in (device, other):
                notes.append("%s may be the same device as %s, and you have not answered that yet. Until you do, "
                             "the merged device's rules apply to it too." % (label(held), label(to)))
        for number in by_number:
            notes.append("QuietNet knows %s only by its number. Its rules and history go to the merged device; "
                         "anything that still looks things up from that number afterwards will show as a separate "
                         "entry again." % label(number))
        notes.append("The history of both becomes one history. Every internet switch, blocked service and schedule "
                     "either has is kept.")
        if by_number:
            # Separate takes a hardware address out of a device, and a number has none: it can
            # never give the number its name and rules back, however many hardware addresses the
            # kept device holds. So the owner is told plainly, before confirming.
            notes.append("This can't be undone with Separate: QuietNet knows %s only by its number, so there is no "
                         "hardware address to take out again. Its rules become the merged device's own for good. To "
                         "go back, you would take them off again on the merged device's page, one at a time."
                         % label(by_number[0]))
        else:
            notes.append("You can undo this with Separate on the device's page. The history then stays with this "
                         "device.")
        return {"device": device, "with": other, "keep": keep, "label": label(device),
                "other_label": label(other), "name": name, "group": gid,
                "group_name": S.group_names.get(gid, "") if gid is not None else "", "notes": notes,
                "hardware": hardware}

    preview = build(device_label)
    preview["marker"] = preview_marker(build(steady_label))
    return None, preview


def merge_by_hand(device, other, seen):
    """The owner's "Merge", after reading the preview: `other` is the same device as `device`, so
    the two become one (merge_devices). `seen` is the marker of the preview the owner was shown;
    if the preview would read differently now, nothing is done. Returns (an error message, None),
    or (None, the number the merged device has)."""
    with db_lock:
        problem, preview = merge_preview(device, other)
        if problem:
            return problem, None
        if not isinstance(seen, str) or seen != preview["marker"]:
            return PREVIEW_CHANGED, None
        keep, gone, _, _, drop = merge_plan(device, other)
    for number in drop:
        set_device_group(number, None)
    merge_devices(keep, gone, "You merged %s into %s, so they are now one device with one set of rules."
                  % (preview["other_label"], preview["label"]), prefer=device, prefer_name=device)
    return None, keep


def separate_problem(number, mac):
    """Why this hardware address can't be separated from this device, in words for the owner, or
    None if it can: the device must be one known by its hardware addresses, hold this one, and
    hold at least one other (a device is never left with none)."""
    if not S.devices_ready:
        return not_ready_message()
    if number not in S.device_kind:
        return UNKNOWN_DEVICE
    held = hardware_of(number)
    if S.device_kind[number] != "hw" or len(held) < 2:
        return "This device has only one hardware address, so there is nothing to separate."
    if mac not in held:
        return "That hardware address does not belong to this device."
    if len(S.device_kind) >= 2 * MAX_DEVICES:
        return "QuietNet is remembering as many devices as it can, so it can't make another one just now."
    return None


def separate_preview(number, mac):
    """What separating the hardware address `mac` from the device `number` would do, for the owner
    to read before anything is done: (None, the preview) or (an error message, None). Changes
    nothing.

    The preview is {"device", "mac", "label", "stays" (the hardware addresses that stay with the
    device), "rules" (what the device carries now, in plain words: its group, its own internet
    switch, blocked services, schedules and "cut live connections"; with "rules": "copy" the
    separated device is given the same, with "none" it gets none of them), "follows" and "held",
    "notes", "marker"}.

    "follows" is the number of the device this one is being held to the rules of while the owner
    has not answered "same device?" (S.provisional), or null; "held" is what reaches it that way,
    in plain words, beyond what is in "rules". Those go on applying to both hardware addresses
    whatever the owner chooses here (separate_by_hand carries the open question to the new
    device), so they are shown, and a note says so: Separate must never be a way out from under
    rules that are being held to a device. Both are part of the marker, so a question that is
    answered, or starts, between the preview and the confirm makes the preview out of date."""
    problem = separate_problem(number, mac)
    if problem:
        return problem, None
    own = rule_items(["dev:%d" % number], [S.dev_group.get(number)], number in S.enforced)
    followed = S.provisional.get(number)
    held = [] if followed is None else [text for key, text in rules_now(number).items() if key not in own]
    several = len(hardware_of(number)) != 2

    def build(label):
        """The preview with each device named by `label`: device_label for the one the owner
        reads, steady_label for the one the marker is worked out from."""
        me = label(number)
        notes = ["The hardware address %s becomes a device of its own again, with no name." % mac,
                 "Its history so far stays with %s. From now on what it looks up is kept under the new device." % me,
                 "%s keeps its name, its group, its rules and its other hardware address%s."
                 % (me, "es" if several else ""),
                 "QuietNet will not ask whether the two are the same device again. You can merge them again from "
                 "either one's page."]
        if followed is not None:
            whose = label(followed)
            notes.append("%s may be the same device as %s, and you have not answered that yet. Until you do, the "
                         "rules for %s go on applying to both: to %s and to the separated hardware address, "
                         "whichever you choose here. QuietNet will ask about each of them."
                         % (me, whose, whose, me))
        return {"device": number, "mac": mac, "label": me, "stays": [m for m in hardware_of(number) if m != mac],
                "rules": list(own.values()), "held": held, "follows": followed, "notes": notes}

    preview = build(device_label)
    preview["marker"] = preview_marker(build(steady_label))
    return None, preview


def separate_by_hand(number, mac, rules, seen, table=None):
    """The owner's "Separate", after reading the preview: the hardware address `mac` is not the
    device `number` after all, and becomes a device of its own. `rules` is the owner's answer to
    "do the rules go with it?": "copy" gives the new device the same group, internet switch,
    blocked services, schedules and "cut live connections" (each a copy of its own from then on),
    "none" gives it nothing but what is set for the whole house. There is no default: the owner
    must say. `seen` is the marker of the preview the owner was shown; if the preview would read
    differently now, nothing is done. Returns (an error message, None), or (None, the new
    device's number).

    The history stays with the device it was merged into, and so does the record of addresses:
    the new device starts a record of its own at the next look. The two are remembered as
    different devices (S.not_same), so the new one is never held to the other's rules as "maybe
    the same device".

    If the device is itself being held to a third device's rules, the question not answered yet
    (S.provisional), the new device is held to them too, and the question is asked about each.
    Both hardware addresses were under those rules before, so nothing is newly blocked, and
    neither gets out from under them by being separated, whichever of the two the owner picks and
    whatever the answer about the device's own rules. The preview says so (separate_preview).

    `table` is the IPv4 neighbour table as just read, for a look straight
    afterwards, so that lookups from the separated device stop getting the other's rules at once
    and not at the next look; without it the next look (seconds away) does that."""
    if rules not in ("copy", "none"):
        return "Please choose whether the rules go with it.", None
    with db_lock:
        problem, preview = separate_preview(number, mac)
        if problem:
            return problem, None
        if not isinstance(seen, str) or seen != preview["marker"]:
            return PREVIEW_CHANGED, None
        save_address_use()                  # first, and by itself: it saves (commits) what the looks have seen
        now = time.time()
        # A device's key names the hardware address it was first known by. If that is the one
        # leaving, the device is re-keyed to one that stays, so the key is free for the new device.
        if db.execute("SELECT 1 FROM device WHERE id=? AND key=?", (number, "hw:" + mac)).fetchone():
            db.execute("UPDATE device SET key=? WHERE id=?", ("hw:" + preview["stays"][0], number))
        if db.execute("SELECT 1 FROM device WHERE key=?", ("hw:" + mac,)).fetchone():
            db.rollback()
            return "QuietNet could not separate that hardware address. Nothing was changed.", None
        seen_row = db.execute("SELECT first, last FROM device_hw WHERE mac=?", (mac,)).fetchone() or (now, now)
        first, last = seen_row[0] or now, seen_row[1] or now
        new = db.execute("INSERT INTO device(kind, key, name, first, last) VALUES('hw',?,?,?,?)",
                         ("hw:" + mac, "", first, last)).lastrowid
        S.device_kind[new] = "hw"
        S.dev_first[new], S.dev_last[new] = first, last
        db.execute("UPDATE device_hw SET device=? WHERE mac=?", (new, mac))
        S.hw_device[mac] = new
        for pair in ((new, number), (number, new)):
            S.not_same.add(pair)
            db.execute("INSERT OR REPLACE INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
                       (pair[0], pair[1], "no", now))
        followed = S.provisional.get(number)
        if followed is not None:
            # An open "same device?" question goes with it: see the docstring.
            S.provisional[new] = followed
            db.execute("INSERT OR REPLACE INTO device_follow(device, follows, state, since) VALUES(?,?,?,?)",
                       (new, followed, "asked", now))
        if rules == "copy":
            copy_device_rules(number, new)
        add_event((device_addresses(number) + [""])[0],
                  "You separated the hardware address %s from %s. It is a device of its own again, %s. Its history "
                  "so far stays with %s.%s"
                  % (mac, preview["label"], "with the same rules" if rules == "copy" else "with no rules of its own",
                     preview["label"],
                     "" if followed is None else " It may still be the same device as %s, so the rules for %s apply "
                     "to it until you say." % (device_label(followed), device_label(followed))), now)
        db.commit()
        load_schedules()                    # also tells the enforcer and the answer cache that rules changed
    if table is not None:
        note_ipv4_addresses(table)
        note_ipv6_addresses()
    return None, new


def copy_device_rules(number, new):
    """Give the device `new` a copy of everything the device `number` carries but its name: its
    group (as the owner's own choice), its internet switch, its blocked services, its schedules
    and "cut live connections". Changes S and the database; call holding db_lock (the caller
    commits and reloads the schedules)."""
    old_scope, scope = "dev:%d" % number, "dev:%d" % new
    if number in S.dev_group:
        S.dev_group[new] = S.dev_group[number]
        db.execute("INSERT OR REPLACE INTO group_member(device, gid, auto) VALUES(?,?,0)", (new, S.dev_group[number]))
    if old_scope in S.off:
        S.off.add(scope)
        db.execute("INSERT OR IGNORE INTO internet_off VALUES(?)", (scope,))
    for service in sorted(S.svc_blocks.get(old_scope, ())):
        S.svc_blocks.setdefault(scope, set()).add(service)
        db.execute("INSERT OR IGNORE INTO service_blocks VALUES(?,?)", (scope, service))
    db.execute("INSERT INTO schedules(name, scope, days, t_from, t_to, off, services, enabled) "
               "SELECT name, ?, days, t_from, t_to, off, services, enabled FROM schedules WHERE scope=? ORDER BY id",
               (scope, old_scope))
    if number in S.enforced:
        S.enforced.add(new)
        S.enforced_mac[new] = ""
        db.execute("INSERT OR REPLACE INTO live_cut(device, mac) VALUES(?,?)", (new, ""))


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
    computer'), and match each IPv6 neighbour to an IPv4 device with the same hardware address
    (S.v6_devices): that is the address a device's IPv6 lookups are recorded under in the history,
    what its share of the listeners is counted by, and, on an older database not yet moved to the
    device tables, the address whose rules they get (see answer_query). With the device tables in
    use, whose rules each IPv6 address gets is published here too, straight from the IPv6
    neighbours' hardware addresses (ipv6_rules, into S.addr_rules). IPv4 devices come from
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
    # Each hardware address's IPv6 addresses, and its link-local one, so IPv6 steering can address a
    # device by its own link-local without running a tool on the lookup path (plan6). Range extenders
    # are left out: their addresses are never steered.
    by_mac = {}
    for addr, (mac, _) in (table6 or {}).items():
        if mac in extenders:
            continue
        info = by_mac.setdefault(mac, {"ll": "", "lls": [], "addrs": []})
        info["addrs"].append(addr)
        try:
            if ipaddress.IPv6Address(addr).is_link_local:
                info["lls"].append(addr)
        except ValueError:
            pass
    # A hardware address with more than one link-local address is treated as shared straight away:
    # "ll" is left empty so plan6 never picks one of them. A single device with an old stale entry
    # still listed is left alone until the old entry goes - the safe direction (design 4.4).
    for info in by_mac.values():
        info["ll"] = info["lls"][0] if len(info["lls"]) == 1 else ""
    S.v6_own, S.v6_prefixes, S.v6_devices, S.v6_dns = own, ranges, matched, for_devices
    S.v6_by_mac = by_mac
    S.v6_shared = shared
    S.v6_table = table6 or {}               # kept for note_ipv6_addresses, which ipv6_look runs next
    if S.devices_ready:
        # Whose rules a lookup from each IPv6 address gets, from memory alone, so that a lookup
        # waiting on this look finds its device the moment it is woken (see ipv6_rules).
        with rule_map_lock:
            S.rules6 = ipv6_rules(S.v6_table)
        rebuild_rule_map()
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
    last_poke = 0.0
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
                # A real router announcing resets a steered device's idea of where the router is, so
                # wake the enforcer to send the claim again at once (option c2). Only while the setting
                # is on, and at most once a second, so with it off nothing is changed and a flood of
                # announcements can't drive the enforcer's loop.
                if found["lifetime"] > 0 and S.ipv6_steer and ENF is not None and now - last_poke >= 1:
                    last_poke = now
                    ENF.poke()
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
            S.hints = hints_by_device(NAMER.round(devices), devices)
        except Exception as e:
            print("Could not look for device names:", e, flush=True)
        NAMES_WANTED.wait(120)
        NAMES_WANTED.clear()


def hints_by_device(found, devices):
    """The names NAMER found ({ip: hint}), also filed under the device each address belongs to
    ({device number: hint} in the same dictionary), going by the hardware address the name was
    found for (`devices` is the {ip: hardware address} that was asked about). A device keeps its
    suggested name whatever address it has next. On an older database there are no device numbers
    and the answer is as given."""
    hints = dict(found)
    if S.devices_ready:
        for ip, hint in found.items():
            number = S.hw_device.get(clean_mac(devices.get(ip, "")))
            if number is not None and S.device_kind.get(number) == "hw":
                hints[number] = hint
    return hints


def reverse_name(ip):
    """The host name the network reports for an address, without its domain, or '' if none."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name.split(".")[0]
    except OSError:
        return ""


# Finds device names (names.py). Reverse lookups go through reverse_name, looked up afresh on each
# call so a stand-in put in its place is used. NAMES_WANTED asks hint_refresher to look again now.
# Its DHCP listener also passes on which address each device says it is taking (see note_dhcp).
NAMER = names.Namer(reverse=lambda ip: reverse_name(ip), on_address=lambda mac, address: note_dhcp(mac, address))
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
        pool = ThreadPoolExecutor(max_workers=32)
        jobs = {ip: pool.submit(reverse_name, ip) for ip in found}
        deadline = time.time() + 8
        # Wait for the names before taking db_lock: these are network waits of up to 8 seconds,
        # and the dashboard and the history writer would otherwise wait behind them.
        hosts = {}
        for ip, job in jobs.items():
            try:
                hosts[ip] = job.result(timeout=max(0.1, deadline - time.time()))
            except Exception:
                hosts[ip] = ""
        now = time.time()
        with db_lock:
            for ip in jobs:
                host = hosts[ip]
                db.execute("""INSERT INTO seen(ip,mac,host,ts) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                              mac=excluded.mac, ts=excluded.ts,
                              host=CASE WHEN excluded.host='' THEN seen.host ELSE excluded.host END""",
                           (ip, found[ip], host, now))
            db.commit()
        pool.shutdown(wait=False)
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
        "other_dns_all": S.other_dns_all, "no_ipv6_all": S.no_ipv6_all, "ipv6_steer": S.ipv6_steer,
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
        # history is still being given its device. "report" is what the move of rules to the
        # devices did, in plain words; "conflicts" the rules it set aside for the owner
        # to decide on (see settle_conflict); "old_rules" how many numbers carry names or rules an
        # older QuietNet left in tables this version no longer reads (see move_old_rules).
        "devices": {"state": S.devices_state, "notice": S.devices_notice, "filling": S.history_fill,
                    "report": list(S.move_report), "conflicts": [dict(c) for c in S.rule_conflicts],
                    "old_rules": S.old_rules},
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
    another shows each device's own history. Names, groups and rules are held against the device,
    so they are read by its number, whatever address it has. Each entry carries:
      "id"         the device's number (null for an address listed on its own: see below);
      "kind"       "hw", "addr", "pi" (this computer) or "hub" (the home router);
      "macs"       its hardware addresses ("mac" is the first, as before);
      "addresses"  the addresses it has now or had in the last day, each as {"address", "first",
                   "last", "now"}: when it was first and last confirmed there, and whether it is
                   there now;
      "ip"         the one address it is listed under: the IPv4 address it has now, else the last
                   it had that no other device has since been seen at, else an IPv6 address. Of
                   two, the one confirmed most recently, and of two confirmed at the same moment
                   the lower, as device_addresses orders them, so that a schedule's scope
                   (shown_scope) and device_label name the address the card is listed under. Empty
                   for a device that has left and whose address has gone to another device: its
                   history, name and rules are kept under its number all the same. Such a device is
                   only listed when `everything` is true (GET /api/devices?all=1), because a page
                   written before the device tables, as an older relay may still serve, knows
                   every card by its address and could not show or open it;
      "paused"     always false here (rules are no longer kept under addresses, so there is
                   nothing to pause); kept for pages that read it;
      "warning"    a plain-English note for its page: it may be another device with a new hardware
                   address, it is behind a Wi-Fi range extender, or its hardware address is at two
                   numbers at once.
    A request that names a device by the address in "ip" reaches the device listed under it here
    (address_holder). An address no device is known for (lookups from it are waiting to be filed,
    or a scan found it with no hardware address) has an entry of its own, with "id" null and
    "kind" "addr"; naming it or giving it a rule makes it a device known by that address. No two
    entries share an "ip".

    Listed are the devices with any history, those found by a scan, those with a name, a group or
    rules, those a "same device?" question is about, and those the owner has merged, separated or
    said are different devices. Lookups still waiting to be filed against
    a device count towards the device that has their address now. On an older database not moved
    to the device tables yet, the list is by address, as it was (api_devices_by_address).

    "v6_bypass" and "same_as" are as described in api_devices_by_address; "same_as" is only ever
    set on an address listed on its own."""
    if not S.devices_ready:
        return api_devices_by_address()
    now = time.time()
    since = now - 86400
    given = dict(S.given)
    scanned = sql("SELECT ip, mac, host, ts FROM seen")
    hints = S.hints
    v6 = ipv6_dns_view()
    v6_on = v6["in_use"] or bool(v6["router_dns_not_ours"])
    # Copies, taken without a lock: the looks that keep these replace or add to them as we read.
    kinds, current, uses, hw = dict(S.device_kind), S.addr_device, dict(S.addr_use), dict(S.hw_device)
    shared, notices, warnings = S.shared_macs, list(S.device_notices), dict(S.device_warnings)
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
        address. None if no device is known for it. (address_holder gives the same answer.)"""
        number = current.get(addr)
        if number is None:
            number = uses[addr][0] if addr in uses else scan_owner.get(addr, only_at.get(addr))
        return number if number in kinds else None

    homes = {}

    def home(number):
        """The one address a device is listed under ("ip"), or '' if it has none of its own now.
        See the docstring above for the order."""
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
                # The most recently confirmed; of two confirmed at the same moment (both cards
                # of a merged laptop, at every look), the lower address, as device_addresses
                # has it, so that the card and a schedule's scope name the same address.
                homes[number] = min(next(pool for pool in pools if pool), key=lambda x: (-x[0], x[1]))[1]
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
            who = ip if number is None else number          # what its rules are read by
            tip = hints.get(number) or hints.get(ip, {})
            this_computer = kind == "pi" or (number is None and ip == S.local_ip)
            out[key] = {
                "ip": ip, "id": number, "kind": kind, "name": given.get(number) or "", "hint": tip.get("name", ""),
                "hint_source": tip.get("source", ""), "hint_detail": tip.get("detail", ""),
                "mac": mine[0] if mine else "", "macs": list(mine), "addresses": [], "same_as": "",
                "this_computer": this_computer, "last": 0, "n": 0, "nb": 0, "on_network": 0,
                "v6_bypass": v6_on and not this_computer,
                "group": S.dev_group.get(number), "off": internet_off_for(who),
                "enforced": live_cut_on(who), "other_dns": other_dns_since(who, since),
                "paused": False, "warning": warnings.get(number, "")}
        return out[key]

    def card_at(addr, number=None):
        """The entry that something known about an address belongs to: its device's (`number`
        when a hardware address already says which device, else whichever device has the
        address), or an entry of its own for an address no device is known for."""
        if number is None:
            number = holder(addr)
        if number is None:
            return card(addr)
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
    # Every device with a name, a group or rules is listed, whether or not it has ever used
    # QuietNet or been found by a scan, and so is every device a "same device?" question is about:
    # a rule must never be in force, or waiting for its device, with no entry to see it on.
    carrying = devices_with_rules() | set(S.provisional) | set(S.provisional.values()) | set(warnings)
    carrying.update(n.get("to_device") for n in notices)
    # And so is every device the owner has merged (it holds more than one hardware address) or
    # said is a different device from another (a separated hardware address among them): what the
    # owner has just done must show, even before the device next looks anything up.
    carrying.update(number for number, mine in macs_of.items() if len(mine) > 1)
    carrying.update(number for pair in list(S.not_same) for number in pair)
    for number in sorted(n for n in carrying if n in kinds):
        card(home(number), number)
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
    given = dict(S.given)
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
    # Every address whose rules belong to a known hardware address is listed even before it has
    # used QuietNet or been found by a scan.
    for ip, mac in list(S.dev_mac.items()):
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
    always was. The block decisions shown are the device's own (rules are held against the
    device): the device given by number, else the device listed under the address `ip`
    (address_holder), else, for an address no device is known for, the whole house's. On an older
    database not moved to the device tables yet they are those kept under the address.

    Without `seen` the answer is the list itself, as it always was. With `seen` (the request's
    'since' parameter: the marker from the last answer, or empty the first time) the answer is
    {"unchanged": false, "marker": ..., "groups": the list}, or just
    {"unchanged": true, "marker": ...} when the marker still matches and the list is not built."""
    since = time.time() - hours * 3600
    who = device
    if who is None:
        who = (address_holder(ip) if S.devices_ready and ip else None) or ip
    if device is not None and not ip:
        ip = (device_addresses(device) + [""])[0]
    if seen is not None:
        marker = activity_marker(ip, hours, since, device)
        if seen == marker:
            return {"unchanged": True, "marker": marker}
        return {"unchanged": False, "marker": marker, "groups": activity_groups(ip, since, device, who)}
    return activity_groups(ip, since, device, who)


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


def other_dns_since(who, since):
    """When this device last tried to use another DNS service (see OTHER_DNS_SERVICES), if that
    was after `since` and since QuietNet started; otherwise 0. `who` is a device key, or the
    address of a lookup no device was known for. Kept in memory, so it costs the device list no
    trip to the history."""
    last = max(S.other_dns.get(who, 0), S.other_dns.get(rule_key(who), 0))
    return last if last > since else 0


def activity_groups(ip, since, device=None, who=None):
    """The activity list for one device since a time: see api_activity. `who` is the device key
    its block decisions are worked out for (the address `ip` when not given). A name of another
    DNS service (see OTHER_DNS_SERVICES) is shown as blocked with why 'other_dns' when this device
    is kept away from them (other_dns_blocked_for), since every lookup of it then is, and its
    group is marked "other_dns" too. Every name and group also carries "needed": who needs that
    whole name for their own system (see needed_by), or '' for most. That is so with a device
    number too.

    A group's "v" is 'junk' when every name in it is on the advert list. A needed group is the one
    exception: it is 'junk' only when its own whole name is on the list, and 'suspect' otherwise,
    so that a device which looked up nothing but advert sub-names (logs.roku.com, say) does not
    make the whole of roku.com read "Advert / tracker". The sub-names keep their own 'junk'."""
    who = ip if who is None else who
    if device is None:
        rows = read_sql("""SELECT domain, COUNT(*), MAX(ts), SUM(blocked) FROM queries
                      WHERE client=? AND ts>? GROUP BY domain""", (ip, since))
    else:
        rows = device_history(device, since)
    guarded = other_dns_blocked_for(who)

    def kept_off(domain):
        """Is this name another DNS service that this device is kept away from?"""
        return guarded and is_other_dns_service(domain)

    groups = {}
    for domain, n, last, nb in rows:
        base = base_of(domain)
        g = groups.setdefault(base, {"base": base, "owner": OWNERS.get(base, ""), "n": 0, "nb": 0, "last": 0, "hosts": []})
        b, why, svc = (True, "other_dns", "") if kept_off(domain) else decision(domain, who)
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
            g["b"], g["why"], g["svc"] = decision(g["base"], who)
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
    """GET /api/groups: every group with its members and switches, in name order. "devices" is the
    members' device numbers; "members" the address each is listed under now ('' for a member with
    no address of its own now), so its length is the number of members. On an older database not
    moved to the device tables yet the members are addresses and "devices" is empty."""
    out = []
    for gid, name in sorted(S.group_names.items(), key=lambda x: x[1].lower()):
        scope = "group:%d" % gid
        keys = [who for who, g in list(S.dev_group.items()) if g == gid]
        numbers = sorted(who for who in keys if isinstance(who, int))
        members = sorted([(device_addresses(n) + [""])[0] for n in numbers] + [who for who in keys if isinstance(who, str)])
        out.append({"id": gid, "name": name, "off": scope in S.off, "members": members, "devices": numbers,
                    "services": len(S.svc_blocks.get(scope, ()))})
    return out


def api_controls(scope):
    """What is switched off / blocked for one device, one group, or the whole house, and why.
    `scope` is a kept scope (see stored_scope). A device also shows what reaches it from the whole
    house, from its group and, while it may be another device with a new hardware address
    (S.provisional), from that device and its group."""
    inherited = []
    if scope != "all":
        inherited.append("all")
    who = scope_device(scope)
    if who is not None:
        inherited.extend(sc for sc in scopes_for(who)[1:] if sc != scope)
    own = S.svc_blocks.get(scope, ())
    timed = [x for x in active_schedules() if x["scope"] == scope or x["scope"] in inherited]
    services = {}
    for v in S.services:
        via = next((sc for sc in inherited if v["id"] in S.svc_blocks.get(sc, ())), None)
        why = via_words(via) if via else ""
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
        off_from = via_words(off_via)
    elif sch:
        off_from = 'by the "%s" schedule' % sch["name"]
    return {"off": scope in S.off and scope != "all", "off_from": off_from, "services": services}


def via_words(scope):
    """Where a rule that reaches a device comes from, in plain words: "for the whole house", "for
    the Kids group", or, for the rules of a device this one may be, "for <its name>, which this
    device may be"."""
    who = scope_device(scope)
    if who is None:
        return "for the " + scope_label(scope)
    return "for %s, which this device may be" % device_label(who)


def api_schedules():
    """GET /api/schedules: every schedule, each marked with whether it is in force now. A
    schedule for one device carries the device's number in "device" (null otherwise), and its
    "scope" is given as the dashboard understands it (see shown_scope)."""
    out = []
    for x in S.schedules:
        who = scope_device(x["scope"])
        out.append(dict(x, scope=shown_scope(x["scope"]), device=who if isinstance(who, int) else None,
                        active=x["enabled"] and schedule_in_force(x)))
    return out


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
    scope = stored_scope(scope, make=True)      # a device is kept by its number (see stored_scope)
    if scope is None:
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
    """Block or unblock one service for one scope, in memory and in the database. A device may be
    named by its number or, as before the device tables, by its address (see stored_scope);
    returns False, changing nothing, if it names a device QuietNet can't use."""
    scope = stored_scope(scope, make=True)
    if scope is None:
        return False
    with db_lock:
        if on:
            S.svc_blocks.setdefault(scope, set()).add(service)
            db.execute("INSERT OR IGNORE INTO service_blocks VALUES(?,?)", (scope, service))
        else:
            S.svc_blocks.get(scope, set()).discard(service)
            db.execute("DELETE FROM service_blocks WHERE scope=? AND service=?", (scope, service))
        db.commit()
        rules_changed()
    return True


def set_internet_off(scope, off):
    """Switch all internet off or on for one scope. The scope 'all' is the kill switch. A device
    may be named by its number or, as before the device tables, by its address (see
    stored_scope); returns False, changing nothing, if it names a device QuietNet can't use."""
    scope = stored_scope(scope, make=True)
    if scope is None:
        return False
    with db_lock:
        if off:
            S.off.add(scope)
            db.execute("INSERT OR IGNORE INTO internet_off VALUES(?)", (scope,))
        else:
            S.off.discard(scope)
            db.execute("DELETE FROM internet_off WHERE scope=?", (scope,))
        db.commit()
        rules_changed()
    return True


def delete_group(gid):
    """Delete a group and everything that hangs off it: its members' membership, its
    service blocks, its internet switch and its schedules."""
    scope = "group:%d" % gid
    with db_lock:
        S.group_names.pop(gid, None)
        S.dev_group = {who: g for who, g in S.dev_group.items() if g != gid}
        S.svc_blocks.pop(scope, None)
        S.off.discard(scope)
        db.execute("DELETE FROM groups WHERE id=?", (gid,))
        db.execute("DELETE FROM device_group WHERE gid=?", (gid,))
        if S.devices_ready:
            db.execute("DELETE FROM group_member WHERE gid=?", (gid,))
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
            # A device may be named by its number or by the address it is listed under (see
            # stored_scope). One QuietNet doesn't know has nothing of its own: only what reaches
            # every device is shown.
            self.send_json(api_controls(stored_scope(scope) or scope))
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
            # The device is named by its number ("device") or by the address it is listed under
            # ("ip"): see device_in_request. The name is held against the device.
            who, name = device_in_request(body, make=True), str(body.get("name", "")).strip()[:40]
            if who is None:
                return self.send_json({"error": UNKNOWN_DEVICE}, 400)
            set_device_name(who, name)
            return self.send_json({"ok": True})
        if path in ("/api/service-block", "/api/internet"):
            scope = str(body.get("scope", ""))
            if not SCOPE.fullmatch(scope):
                return self.send_error(400)
            if path == "/api/internet" and scope == "all":
                return self.send_error(400)
            if path == "/api/service-block" and body.get("service") not in S.svc_names:
                return self.send_error(400)
            scope = stored_scope(scope, make=True)      # a device is kept by its number
            if scope is None:
                return self.send_json({"error": UNKNOWN_DEVICE}, 400)
            if path == "/api/internet":
                if body.get("off") and is_this_computer(scope_device(scope)):
                    return self.send_json({"error": "QuietNet can't switch off the internet for the "
                                                    "computer it runs on."}, 400)
                set_internet_off(scope, bool(body.get("off")))
            else:
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
            # "Cut live connections" is held against the device: named by its number ("device"),
            # or by the address it is listed under ("ip"). An address given must be a real IPv4
            # address and nothing else. (The address that ends up in a firewall rule is not this
            # one but the one the live neighbour table shows the device at, checked again there:
            # see live_cut_devices.)
            who, ip, on = device_number(body.get("device")), None, bool(body.get("on"))
            if who is None:
                try:
                    if not isinstance(body.get("ip"), str):
                        raise ValueError
                    ip = str(ipaddress.IPv4Address(body["ip"]))
                except ValueError:
                    return self.send_error(400)
            elif on:
                ip = next((a for a in device_addresses(who) if ":" not in a), None)
            if on and ip:
                # Only an ordinary device on the home network: never the router, this computer,
                # or anything outside. (Without the enforcer, only the basic checks can be made.)
                problem = (ENF.can_target(ip) if ENF and ENF.available()
                           else enforcer.target_problem(ip, None, None, S.local_ip))
                if problem:
                    return self.send_json({"error": problem}, 400)
            if who is None:
                who = device_in_request({"ip": ip}, make=on)
            if who is None:
                # Nothing is known at that address, so there is nothing to switch off.
                return self.send_json({"ok": True}) if not on else self.send_json({"error": UNKNOWN_DEVICE}, 400)
            if not on:
                set_live_cut(who, False)
                return self.send_json({"ok": True})
            if isinstance(who, int) and S.device_kind.get(who) in ("pi", "hub"):
                return self.send_json({"error": "QuietNet can't steer the router or itself."}, 400)
            # For a device known only by its address (and on an older database), remember which
            # hardware address is there, so if the address is later given to a different device,
            # that one isn't steered by mistake. The live table first: the last scan's record may
            # be out of date. If neither knows yet, it is filled in when the device is first seen.
            mac = neighbours().get(ip, "") if ip else ""
            if ip and not mac:
                row = sql("SELECT mac FROM seen WHERE ip=?", (ip,))
                mac = row[0][0] if row and row[0][0] else ""
            set_live_cut(who, True, mac)
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
            gid = body.get("group")
            known = gid in S.group_names        # a value that can't be a group id at all (a list, say) is refused
            who = device_in_request(body, make=known)
            if who is None:
                # Taking an address nothing is known about out of its group changes nothing.
                return self.send_json({"ok": True}) if not known else self.send_json({"error": UNKNOWN_DEVICE}, 400)
            set_device_group(who, gid if known else None)
            return self.send_json({"ok": True})
        if path == "/api/move-rules":       # "Yes, it's the same device" and "Move the rules to this device"
            # The two devices are named by number ("from_device", "to_device") or, as an older
            # page does, by address ("from", "to": the same address twice means "the device here
            # now is the one whose rules it is being given").
            to_device = device_number(body.get("to_device"))
            from_device = device_number(body.get("from_device"))
            if to_device is None or (from_device is None and "from_device" in body):
                if not isinstance(body.get("from"), str) or not isinstance(body.get("to"), str):
                    return self.send_error(400)
                if device_ip(body["from"]) is None or device_ip(body["to"]) is None:
                    return self.send_json({"error": "Those aren't device addresses."}, 400)
                if not S.devices_ready:
                    # An older database not moved yet: the one answer still possible is "the
                    # device here now is the one these paused rules belong to".
                    same = device_ip(body["from"]) == device_ip(body["to"])
                    error = same_device_at_address(device_ip(body["to"])) if same else not_ready_message()
                    return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True})
                to_device = device_for_address(body["to"])
                from_device = None if body["from"] == body["to"] else next(
                    (n["from_device"] for n in list(S.device_notices)
                     if n["to_device"] == to_device and n["from"] == device_ip(body["from"])),
                    device_for_address(body["from"]))
                if body["from"] != body["to"] and from_device is None:
                    return self.send_json({"error": "There are no rules to move."}, 400)
            error = same_device_by_hand(to_device, from_device)
            return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True})
        if path == "/api/different-device":   # "No, it's a different device"
            number = device_number(body.get("device"))
            if number is None:
                if not isinstance(body.get("ip"), str) or device_ip(body["ip"]) is None:
                    return self.send_error(400)
                number = device_for_address(body["ip"]) if S.devices_ready else None
            error = different_device_by_hand(number)
            return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True})
        if path == "/api/merge":              # "Merge with...": what would apply first, then (with "seen") the merge
            # "device" is the device merged into, "with" the one merged into it, both by number.
            # Without "seen" nothing is changed: the answer is the preview. With "seen" (the
            # preview's marker) the merge is done, if the preview would still read the same.
            device, other = device_number(body.get("device")), device_number(body.get("with"))
            if device is None or other is None:
                return self.send_json({"error": UNKNOWN_DEVICE if S.devices_ready else not_ready_message()}, 400)
            if "seen" not in body:
                error, preview = merge_preview(device, other)
                return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True, "preview": preview})
            error, kept = merge_by_hand(device, other, body["seen"])
            if error:
                return self.send_json({"error": error}, 409 if error == PREVIEW_CHANGED else 400)
            return self.send_json({"ok": True, "device": kept})
        if path == "/api/separate":           # "Separate": what would happen first, then (with "seen") the separation
            # "device" is the device's number, "mac" the hardware address to take out of it.
            # Without "seen" nothing is changed: the answer is the preview. With "seen" and the
            # owner's answer to "do the rules go with it?" ("rules": "copy" or "none") it is done.
            device, mac = device_number(body.get("device")), clean_mac(body.get("mac"))
            if device is None:
                return self.send_json({"error": UNKNOWN_DEVICE if S.devices_ready else not_ready_message()}, 400)
            if not mac:
                return self.send_json({"error": "That is not a hardware address."}, 400)
            if "seen" not in body:
                error, preview = separate_preview(device, mac)
                return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True, "preview": preview})
            if body.get("rules") not in ("copy", "none"):
                return self.send_json({"error": "Please choose whether the rules go with it."}, 400)
            # The neighbour table is read before the lock is taken (it runs a system tool), for a
            # look straight after the separation: see separate_by_hand.
            error, new = separate_by_hand(device, mac, body["rules"], body["seen"], neighbour_table())
            if error:
                return self.send_json({"error": error}, 409 if error == PREVIEW_CHANGED else 400)
            return self.send_json({"ok": True, "device": new})
        if path == "/api/rule-conflict":      # the owner's choice for rules the move set aside
            cid = body.get("id")
            if not isinstance(cid, int) or isinstance(cid, bool) or not isinstance(body.get("choice"), str):
                return self.send_error(400)
            error = settle_conflict(cid, body["choice"])
            return self.send_json({"error": error}, 400) if error else self.send_json({"ok": True})
        if path == "/api/move-old-rules":     # bring in what an older QuietNet left in the old tables
            error = move_old_rules()
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
        if path == "/api/ipv6-steer-switch":     # take IPv6 away from steered devices (off by default)
            # Turning it off is also "Stop IPv6 steering now": the next enforcer tick hands every
            # steered device back to the router (IPv6Steerer.release_all), and poke() runs it at once.
            with db_lock:
                S.ipv6_steer = bool(body.get("on"))
                db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('ipv6_steer', ?)",
                           ("1" if S.ipv6_steer else "0",))
                db.commit()
            if ENF is not None:
                ENF.poke()                        # hand the devices back (or start) at once, not in 2 seconds
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


# What a change is answered with when it names a device QuietNet can't find.
UNKNOWN_DEVICE = "QuietNet doesn't know that device."


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
    ap.add_argument("--no-device-names", action="store_true",
                    help="don't ask the home network for device names (the tests use this)")
    args = ap.parse_args()

    init_db()
    load_lists()
    S.local_ip = find_local_ip()
    threading.Thread(target=log_writer, daemon=True).start()
    if not args.no_device_names:
        NAMER.start_listeners()
        threading.Thread(target=hint_refresher, daemon=True).start()
    start_dns(args.dns_port)
    threading.Thread(target=router_advert_listener, daemon=True).start()

    global ENF
    ENF = enforcer.Enforcer(S.local_ip, enforcement_plan, plan_neighbours, data_dir=DATA,
                            learn_mac=learn_enforced_mac, dns_port=None if S.dns_error else S.dns_port,
                            plan6=plan6)
    ENF.start()
    threading.Thread(target=address_watcher, daemon=True).start()
    # Only now, with the filter answering and the enforcer started: bring an older household's
    # data into the device tables if that is still to do, then keep track of devices' addresses.
    threading.Thread(target=device_keeper, daemon=True).start()
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
