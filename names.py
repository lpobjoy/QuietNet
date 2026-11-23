"""Finding names for the devices on the home network, so the dashboard can say "Lewis's iPhone"
rather than "Unnamed device 192.168.1.54".

Devices tell the network about themselves in several ways. This module listens for, or asks for,
each of them, and suggests the best name found:

  - DHCP: when a device joins the network it usually broadcasts its own name (and often what
    software it runs) while asking the router for an address. Heard by listening on port 67 (a
    Raspberry Pi only: it needs admin rights). Nothing is ever sent on that port.
  - Bonjour (mDNS): Apple devices, many printers, TVs, smart speakers and Linux computers answer
    "what is the name of this address?" on port 5353, and announce themselves there too.
  - Windows network (NetBIOS): Windows computers, many network drives and Samba answer a
    "what are your names?" question on port 137.
  - UPnP (SSDP): TVs, Sonos speakers, games consoles and routers answer a "who is there?" call on
    port 1900 with the address of a short description of themselves, which holds a friendly name.
  - The router: a reverse lookup ("which name has this address?") through the home router.

Every byte learnt from the network is untrusted: each packet reader is bounded and gives up
quietly on anything malformed, names are only ever treated as text, and the whole round of
asking has a fixed time budget, so a slow or hostile device cannot hold it up.

No outside packages: Python's standard library only. Used by server.py (Namer, run every two
minutes from its hint_refresher thread). Explained in docs/ARCHITECTURE.md, "Device names".
"""
import collections
import http.client
import ipaddress
import re
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

ROUND_SECONDS = 5.0          # the most one round of asking may take, all sources together
MDNS_WAIT = 2.0              # how long to wait for Bonjour answers within a round
NETBIOS_WAIT = 2.0           # the same for Windows network answers
SSDP_WAIT = 1.5              # the same for UPnP answers (before fetching their descriptions)
FETCH_SECONDS = 2.0          # the most one UPnP description download may take
MAX_DESCRIPTION = 64 * 1024  # the largest UPnP description read; real ones are a few kilobytes
MAX_PACKET = 9000            # the most read from one network packet
MAX_ANSWERS = 512            # the most packets read in one listening window
MAX_RECORDS = 64             # the most records read from one Bonjour packet
MAX_DEVICES = 256            # the most devices asked about in one round
MAX_FETCHES = 16             # the most UPnP descriptions downloaded in one round
MAX_LEARNT = 1024            # the most entries kept in any table of things heard
MAX_NAME = 40                # the longest suggested name (the same limit as a name typed in)
KEEP_SECONDS = 6 * 3600      # how long a name heard once is still suggested without being heard again
DESCRIPTION_KEEP = 3600      # how long a downloaded UPnP description is reused before asking again

MDNS = ("224.0.0.251", 5353)
SSDP = ("239.255.255.250", 1900)
NETBIOS_PORT = 137
DHCP_PORT = 67

# Which source wins when two disagree, best first, and the label each is shown with.
PRIORITY = ("dhcp", "mdns", "netbios", "ssdp", "dns")
LABELS = {"dhcp": "DHCP", "mdns": "Bonjour", "netbios": "Windows network", "ssdp": "UPnP", "dns": "router"}
# Where a model or maker is looked for, best first.
DETAIL_ORDER = ("mdns", "ssdp", "dhcp")
PRIVATE_NOTE = "Private Wi-Fi address, so probably a phone, tablet or laptop"
# Endings that only mean "on the home network" and are dropped from a suggested name.
HOME_SUFFIXES = (".local", ".lan", ".home", ".internal", ".home.arpa", ".localdomain")
# Names that say nothing about which device this is.
MEANINGLESS = ("local", "localhost", "localdomain", "home", "lan", "internal", "unknown", "android")

M_SEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\nST: ssdp:all\r\n\r\n")
# The NetBIOS name "*" (asking for every name a computer has), in NetBIOS's own spelling.
NBSTAT_NAME = b"\x20" + b"CK" + b"AA" * 15 + b"\x00"


# ------------------------------------------------------------------ tidying

def printable(text, limit):
    """`text` with every run of spaces, tabs or line breaks made one space, and anything that is not
    an ordinary printable character (control characters, invisible marks) removed; at most `limit`
    characters. Used on everything heard from the network before it is kept."""
    text = " ".join(str(text)[:limit * 4].split())
    return "".join(ch for ch in text if ch.isprintable())[:limit].strip()


def is_address(text):
    """Is this text just an IP address? Such a 'name' tells nobody anything."""
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def tidy_name(text, home_domain=""):
    """Turn a name heard from the network into one for people, or '' if nothing useful is left.

    The rules, applied in order:
      1. Control characters and invisible marks are removed and spaces tidied (printable()).
      2. A name with no spaces is a network-style name, such as 'Lewiss-iPhone.local'. From these
         the home endings (.local, .lan, .home, .internal, .home.arpa, .localdomain) and the home
         network's own domain are dropped; then, if dots remain, only the part before the first
         dot is kept. Dashes become spaces only when every part between them is at least three
         characters long and starts with a letter ('Lewiss-iPhone' -> 'Lewiss iPhone', but
         'DESKTOP-4F2K1JQ' and 'RX-V685' stay as they are).
      3. Names with spaces (friendly names such as 'Living Room TV') are kept as they are.
      4. At most MAX_NAME characters. A bare IP address, or a word such as 'localhost' that every
         device could say, counts as no name."""
    text = printable(text, 256).strip(" .")
    if text and " " not in text and not is_address(text):
        low = text.lower()
        endings = (("." + home_domain.lower().strip(".")),) if home_domain.strip(".") else ()
        for end in endings + HOME_SUFFIXES:
            if low.endswith(end) and len(low) > len(end):
                text = text[:-len(end)]
                break
        text = text.split(".")[0]
        parts = text.split("-")
        if len(parts) > 1 and all(len(p) >= 3 and p[0].isalpha() for p in parts):
            text = " ".join(parts)
    text = text[:MAX_NAME].rstrip(" .-")
    if not text or is_address(text) or text.lower() in MEANINGLESS:
        return ""
    return text


def is_private_mac(mac):
    """Does this hardware address have its 'locally administered' bit set? Phones, tablets and
    laptops make up such an address for each Wi-Fi network ('private Wi-Fi address'), so a device
    using one is very likely one of those. Group (multicast) addresses don't count."""
    try:
        first = int(str(mac).split(":")[0], 16)
    except ValueError:
        return False
    return bool(first & 0x02) and not first & 0x01


def home_domain(path="/etc/resolv.conf"):
    """The home network's own domain (for example 'home' on a BT Smart Hub), from the system's
    resolver settings, or '' if there is none or it can't be read. Dropped from suggested names."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f.read(16384).splitlines():
                words = line.split()
                if len(words) >= 2 and words[0] in ("search", "domain"):
                    if re.fullmatch(r"[A-Za-z0-9.-]{1,63}", words[1]):
                        return words[1].lower().strip(".")
    except OSError:
        pass
    return ""


def usable_address(ip):
    """Is this an IPv4 address of an ordinary device on a home network (private, not multicast,
    not a loopback address)? Only such devices are asked about."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return addr.is_private and not (addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local)


# ------------------------------------------------------------------ DNS-style packets (Bonjour, NetBIOS)

def read_name(buf, pos):
    """Read one encoded name from a DNS-style packet starting at `pos`. Returns (list of labels as
    bytes, the position just after the name). Raises ValueError on anything malformed.

    Names may be shortened with 'pointers' to an earlier copy. A hostile packet can make those
    point at themselves, or run off the end; this mirrors the safeguards of server.py's DNS
    readers and adds the ones a reader that follows pointers needs: each pointer must go further
    back than the last one did (so they can't loop), there are at most 16 of them, and the whole
    name is at most 255 bytes."""
    labels, after, total, jumps = [], None, 0, 0
    limit = pos                      # a pointer must point before here
    while True:
        if pos >= len(buf):
            raise ValueError("name runs off the end")
        n = buf[pos]
        if n == 0:
            return labels, (after if after is not None else pos + 1)
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError("pointer cut short")
            target = ((n & 0x3F) << 8) | buf[pos + 1]
            if target >= min(limit, pos):
                raise ValueError("pointer does not point backwards")
            jumps += 1
            if jumps > 16:
                raise ValueError("too many pointers")
            if after is None:
                after = pos + 2
            pos = limit = target
            continue
        if n & 0xC0:
            raise ValueError("reserved label type")
        if pos + 1 + n > len(buf):
            raise ValueError("label runs off the end")
        labels.append(bytes(buf[pos + 1:pos + 1 + n]))
        total += n + 1
        if total > 255:
            raise ValueError("name too long")
        pos += 1 + n


def encode_name(name):
    """A dotted name in DNS's own form: each part prefixed with its length, ending in a zero byte."""
    out = b""
    for part in name.strip(".").split("."):
        raw = part.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def label_text(label):
    """One label of a name as text. Bonjour names are UTF-8; anything else is shown, not trusted."""
    return label.decode("utf-8", "replace")


def reverse_pointer(ip):
    """The name used to ask 'which name has this address?': 192.168.1.54 -> 54.1.168.192.in-addr.arpa."""
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def address_of_reverse(labels):
    """The IPv4 address a reverse name ('54.1.168.192.in-addr.arpa', as labels) stands for, or ''."""
    words = [label_text(l).lower() for l in labels]
    if len(words) != 6 or words[4:] != ["in-addr", "arpa"]:
        return ""
    ip = ".".join(reversed(words[:4]))
    try:
        return str(ipaddress.IPv4Address(ip))
    except ValueError:
        return ""


def mdns_query(names, qtype=12):
    """A Bonjour question asking about each of `names` (pointer records by default), with the
    'answer me directly' bit set on each, so answers come back to the asking port."""
    head = struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0)
    return head + b"".join(encode_name(n) + struct.pack(">HH", qtype, 0x8001) for n in names)


def read_records(data):
    """Every record in a DNS-style answer packet, as a list of (type, owner name labels, value).
    The value is the target name's labels for a pointer (12), the address text for an address (1),
    a list of text strings for a text record (16), and None otherwise. Stops quietly at the first
    thing it can't read and returns what came before; reads at most MAX_RECORDS records."""
    out = []
    if len(data) < 12:
        return out
    counts = struct.unpack(">HHHH", data[4:12])
    pos = 12
    try:
        for _ in range(min(counts[0], MAX_RECORDS)):
            pos = read_name(data, pos)[1] + 4
        for _ in range(min(sum(counts[1:]), MAX_RECORDS)):
            owner, pos = read_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            start, pos = pos + 10, pos + 10 + rdlen
            if pos > len(data):
                break
            value = None
            if rtype == 12:
                value = read_name(data, start)[0]
            elif rtype == 1 and rdlen == 4:
                value = socket.inet_ntoa(data[start:pos])
            elif rtype == 16:
                value, at = [], start
                while at < pos and len(value) < 32:
                    n = data[at]
                    value.append(data[at + 1:min(at + 1 + n, pos)].decode("utf-8", "replace"))
                    at += 1 + n
            out.append((rtype, owner, value))
    except (ValueError, IndexError, struct.error):
        pass
    return out


def is_answer(data):
    """Is this DNS-style packet an answer (rather than a question)? Bonjour listeners hear both."""
    return len(data) >= 12 and bool(data[2] & 0x80)


def learn_from_mdns(data, source, wanted):
    """What one Bonjour answer from `source` says about the devices in `wanted`:
    {ip: {"name": ..., "model": ...}}. Three kinds of record are used:
      - an answer to 'which name has this address?' (a pointer from a reverse name), for that address;
      - a device announcing its own address ('Lewiss-iPhone.local is 192.168.1.54'), only when the
        address is the one the packet came from: a device may name itself, not others;
      - the device-information record ('Lewis's MacBook Pro._device-info._tcp.local', with
        'model=MacBookPro18,3'), for the address the packet came from. Its first part is the name
        the owner gave the device, which reads better than the network name, so it is preferred."""
    found = {}
    if not is_answer(data):
        return found
    for rtype, owner, value in read_records(data):
        if rtype == 12 and value:
            ip = address_of_reverse(owner)
            if ip in wanted:
                found.setdefault(ip, {}).setdefault("name", ".".join(label_text(l) for l in value))
        elif rtype == 1 and value == source and source in wanted and owner:
            found.setdefault(source, {}).setdefault("name", ".".join(label_text(l) for l in owner))
        elif rtype == 16 and source in wanted and len(owner) >= 4 and \
                [label_text(l).lower() for l in owner[-3:]] == ["_device-info", "_tcp", "local"]:
            entry = found.setdefault(source, {})
            entry["friendly"] = label_text(owner[0])
            for item in value or []:
                key, _, val = item.partition("=")
                if key.lower() == "model" and val:
                    entry["model"] = val
    return found


def nbstat_query(ident):
    """A Windows network (NetBIOS) question asking a computer for all its names."""
    return struct.pack(">HHHHHH", ident & 0xFFFF, 0, 1, 0, 0, 0) + NBSTAT_NAME + struct.pack(">HH", 0x21, 1)


def parse_nbstat(data):
    """The computer's own name from a Windows network (NetBIOS) answer, or '' if there is none or
    the packet can't be read. A computer lists several names; its own is the first one that is
    unique to it (not a group) with the 'workstation' ending (0x00)."""
    try:
        counts = struct.unpack(">HHHH", data[4:12])
        if not data[2] & 0x80 or counts[1] < 1:
            return ""
        pos = 12
        for _ in range(min(counts[0], 4)):
            pos = read_name(data, pos)[1] + 4
        pos = read_name(data, pos)[1]
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype != 0x21 or rdlen < 1 or pos >= len(data):
            return ""
        count = min(data[pos], (rdlen - 1) // 18, (len(data) - pos - 1) // 18)
        pos += 1
        for i in range(count):
            entry = data[pos + 18 * i:pos + 18 * i + 18]
            flags = int.from_bytes(entry[16:18], "big")
            if entry[15] == 0 and not flags & 0x8000:
                name = printable(entry[:15].decode("latin-1"), 15)
                if name:
                    return name
    except (ValueError, IndexError, struct.error):
        pass
    return ""


# ------------------------------------------------------------------ DHCP

def vendor_words(vendor):
    """A plain description of the software a device named when it joined the network, or ''.
    Only a few very common, unambiguous labels are translated; anything else is shown as given."""
    vendor = printable(vendor, 60)
    low = vendor.lower()
    if low.startswith("msft"):
        return "Runs Windows"
    if low.startswith("android-dhcp"):
        return "Runs Android"
    return "Software: " + vendor if vendor else ""


def parse_dhcp(data):
    """What a device said about itself in a DHCP request it broadcast when joining the network:
    {"mac", "name", "vendor"}, or None if this isn't a readable request from a device (offers and
    answers from a DHCP server are ignored), or it names nothing.

    Only 'discover', 'request' and 'inform' messages are used. The options are read with a fixed
    limit on how many, and every length is checked against the packet."""
    if len(data) < 240 or data[0] != 1 or data[1] != 1 or data[2] != 6 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    mac = ":".join("%02x" % b for b in data[28:34])
    options, pos = {}, 240
    for _ in range(512):
        if pos >= len(data):
            break
        code = data[pos]
        if code == 0:
            pos += 1
            continue
        if code == 255 or pos + 1 >= len(data):
            break
        n = data[pos + 1]
        value = data[pos + 2:pos + 2 + n]
        if len(value) < n:
            break
        options.setdefault(code, bytes(value))
        pos += 2 + n
    if options.get(53, b"")[:1] not in (b"\x01", b"\x03", b"\x08"):
        return None
    name = printable(options.get(12, b"").decode("utf-8", "replace"), 64)
    vendor = printable(options.get(60, b"").decode("utf-8", "replace"), 64)
    if not name and not vendor:
        return None
    return {"mac": mac, "name": name, "vendor": vendor}


# ------------------------------------------------------------------ UPnP (SSDP)

def parse_ssdp(data):
    """The description address (LOCATION) from an answer to a UPnP 'who is there?' call, or ''."""
    text = data[:MAX_PACKET].decode("latin-1")
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines[0].upper().startswith("HTTP/1.1 200"):
        return ""
    for line in lines[1:64]:
        key, _, value = line.partition(":")
        if key.strip().lower() == "location":
            return value.strip()[:512]
    return ""


def location_allowed(url, ip):
    """May a UPnP description be fetched from `url` for the device at `ip`? Only plain http, only
    from exactly that device's own private address (never another computer, which would let a
    device on the network make QuietNet fetch from anywhere), and no user name in the address."""
    try:
        parts = urlsplit(url)
        parts.port                                     # raises ValueError if the port is not a number
    except ValueError:
        return False
    if parts.scheme != "http" or "@" in parts.netloc or not usable_address(ip):
        return False
    return parts.hostname == ip


def parse_description(body):
    """The friendly name, maker and model from a UPnP device description:
    {"name", "manufacturer", "model"}, or None if it is refused or can't be read.

    Refused outright: anything declaring its own document type or entities (the way to make an XML
    reader expand a small document into a huge one), and anything with zero bytes in it (which
    would be a multi-byte text encoding that the first check could not see into)."""
    if b"\x00" in body or re.search(rb"<!\s*(doctype|entity)", body, re.I):
        return None
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        return None
    device = next((el for el in root.iter() if str(el.tag).split("}")[-1] == "device"), None)
    if device is None:
        return None
    out = {}
    for field, key in (("friendlyName", "name"), ("manufacturer", "manufacturer"), ("modelName", "model")):
        child = next((el for el in device if str(el.tag).split("}")[-1] == field), None)
        out[key] = printable(child.text or "", 80) if child is not None else ""
    return out


def fetch_description(url, ip, timeout=FETCH_SECONDS, connect=http.client.HTTPConnection):
    """Download and read a UPnP description (see parse_description), or None. Only from the
    device's own address (location_allowed); redirects are not followed (anything but '200 OK' is
    refused); at most MAX_DESCRIPTION bytes; and the whole download must finish within `timeout`
    seconds, however slowly the device drips its answer."""
    if not location_allowed(url, ip):
        return None
    parts = urlsplit(url)
    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in path):
        return None
    end = time.monotonic() + timeout
    conn = connect(ip, parts.port or 80, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "QuietNet", "Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        length = resp.getheader("Content-Length", "")
        if length.isdigit() and int(length) > MAX_DESCRIPTION:
            return None
        body = b""
        read = getattr(resp, "read1", resp.read)
        while True:
            if time.monotonic() > end:
                return None
            chunk = read(8192)
            if not chunk:
                break
            body += chunk
            if len(body) > MAX_DESCRIPTION:
                return None
    except (OSError, http.client.HTTPException, ValueError):
        return None
    finally:
        conn.close()
    return parse_description(body)


# ------------------------------------------------------------------ putting it together

def detail_for(key, entry):
    """The model or maker one source reported, in words for people, or ''."""
    if key == "mdns" and entry.get("model"):
        return "Model: " + printable(entry["model"], 60)
    if key == "ssdp":
        maker, model = printable(entry.get("manufacturer", ""), 60), printable(entry.get("model", ""), 60)
        if model and maker and maker.lower() not in model.lower():
            return "Model: %s (%s)" % (model, maker)
        if model:
            return "Model: " + model
        if maker:
            return "Made by " + maker
    if key == "dhcp":
        return vendor_words(entry.get("vendor", ""))
    return ""


def choose(by, domain=""):
    """The suggestion for one device from what each source said ({source key: entry}):
    {"name", "source", "detail"}. The name comes from the first source in PRIORITY with a usable
    name; the detail (model or maker) from the first in DETAIL_ORDER that has one."""
    name = source = detail = ""
    for key in PRIORITY:
        entry = by.get(key) or {}
        candidate = tidy_name(entry.get("friendly") or entry.get("name", ""), domain)
        if candidate:
            name, source = candidate, LABELS[key]
            break
    for key in DETAIL_ORDER:
        detail = detail_for(key, by.get(key) or {})
        if detail:
            break
    return {"name": name, "source": source, "detail": detail[:80]}


def run_all(work, items, deadline, workers=16):
    """Run work(item) for each item on up to `workers` background threads, and return
    {item: result} for those finished by `deadline` (time.monotonic()). Threads still busy then
    are left to finish on their own; they are daemon threads, so they never hold up shutting down.
    A result of None, or an error, gives no entry."""
    todo, done, lock = list(items), {}, threading.Lock()

    def worker():
        """Take items until none are left or the time is up."""
        while time.monotonic() < deadline:
            with lock:
                if not todo:
                    return
                item = todo.pop(0)
            try:
                result = work(item)
            except Exception:
                result = None
            if result is not None:
                with lock:
                    done[item] = result

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(workers, len(todo)))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return dict(done)


def remember(table, key, value):
    """Keep `value` under `key` in an ordered table of things heard, newest last, dropping the
    oldest beyond MAX_LEARNT, so a flood of made-up devices can't use up memory."""
    table.pop(key, None)
    table[key] = value
    while len(table) > MAX_LEARNT:
        table.popitem(last=False)


class Namer:
    """Finds and remembers names for the devices on the home network. There is one, server.NAMER.

    round() asks every source at once, each on its own thread, and waits at most ROUND_SECONDS;
    a source still busy then is left behind and not started again until it has finished. What
    each source said is kept per device (with its hardware address, so a reused address doesn't
    inherit the last device's name) for KEEP_SECONDS, because phones in particular answer only
    when awake. The two listeners (start_listeners) add what devices announce in between.

    The network is reached only through make_socket and connect, which the tests replace."""

    def __init__(self, reverse=None, make_socket=socket.socket, connect=http.client.HTTPConnection,
                 domain_file="/etc/resolv.conf"):
        """`reverse` is the reverse-lookup function (ip -> name or ''), supplied by server.py."""
        self.reverse = reverse
        self.make_socket = make_socket
        self.connect = connect
        self.domain_file = domain_file
        self.lock = threading.Lock()
        self.heard_dhcp = collections.OrderedDict()      # hardware address -> what it said when joining
        self.heard_mdns = collections.OrderedDict()      # ip -> what it announced over Bonjour
        self.descriptions = collections.OrderedDict()    # UPnP description address -> (when, what it said)
        self.cache = collections.OrderedDict()           # ip -> {"mac", "by": {source key: (when, entry)}}
        self.busy = {}                                   # source key -> its thread from the last round
        self.listening = {}                              # listener name -> True if it is running
        self.sources = [("dhcp", self.ask_dhcp), ("mdns", self.ask_mdns), ("netbios", self.ask_netbios),
                        ("ssdp", self.ask_ssdp), ("dns", self.ask_router)]

    # ----- one round

    def round(self, devices, budget=ROUND_SECONDS):
        """Ask every source about `devices` ({ip: hardware address}) and return the suggestion for
        every device with anything known: {ip: {"name", "source", "detail"}}. Never takes much more
        than `budget` seconds, whatever the devices do."""
        devices = dict(sorted((ip, mac) for ip, mac in devices.items() if usable_address(ip))[:MAX_DEVICES])
        deadline = time.monotonic() + budget
        running = []
        for key, ask in self.sources:
            old = self.busy.get(key)
            if old is not None and old.is_alive():
                continue                                 # still stuck from an earlier round
            box = {}
            t = threading.Thread(target=self._run_source, args=(ask, devices, deadline, box), daemon=True)
            self.busy[key] = t
            t.start()
            running.append((key, t, box))
        results = {}
        for key, t, box in running:
            t.join(max(0.0, deadline - time.monotonic()) + 0.2)
            if not t.is_alive():
                results[key] = box.get("found") or {}
        self._keep(devices, results)
        return self.suggestions()

    @staticmethod
    def _run_source(ask, devices, deadline, box):
        """Run one source, putting what it found in box['found']. A failing source finds nothing."""
        try:
            box["found"] = ask(devices, deadline)
        except Exception:
            box["found"] = {}

    def _keep(self, devices, results):
        """Store what each source found this round against each device, and forget entries older
        than KEEP_SECONDS and devices whose hardware address has changed."""
        now = time.monotonic()
        with self.lock:
            for ip, mac in devices.items():
                slot = self.cache.get(ip)
                if slot is None or (mac and slot["mac"] and slot["mac"] != mac):
                    slot = {"mac": mac, "by": {}}
                slot["mac"] = mac or slot["mac"]
                for key, found in results.items():
                    entry = found.get(ip)
                    if entry:
                        slot["by"][key] = (now, entry)
                slot["by"] = {k: v for k, v in slot["by"].items() if now - v[0] < KEEP_SECONDS}
                remember(self.cache, ip, slot)
            for ip in [ip for ip, slot in self.cache.items() if not slot["by"] and ip not in devices]:
                del self.cache[ip]

    def suggestions(self):
        """The current suggestion for every remembered device that has a name or a detail."""
        domain = home_domain(self.domain_file)
        now = time.monotonic()
        out = {}
        with self.lock:
            for ip, slot in self.cache.items():
                by = {k: entry for k, (when, entry) in slot["by"].items() if now - when < KEEP_SECONDS}
                hint = choose(by, domain)
                if hint["name"] or hint["detail"]:
                    out[ip] = hint
        return out

    # ----- the sources: each takes ({ip: mac}, deadline) and returns {ip: entry}

    def ask_dhcp(self, devices, deadline):
        """What each device said when it last joined the network, matched by hardware address.
        Nothing is sent: this only reads what the DHCP listener heard."""
        with self.lock:
            return {ip: dict(self.heard_dhcp[mac]) for ip, mac in devices.items() if mac in self.heard_dhcp}

    def _collect(self, sock, deadline, window, handle):
        """Read packets from `sock` for `window` seconds (never past `deadline`), at most
        MAX_ANSWERS of them, passing each to handle(data, source address). One packet that can't
        be handled is skipped; it never ends the round."""
        end = min(deadline, time.monotonic() + window)
        for _ in range(MAX_ANSWERS):
            left = end - time.monotonic()
            if left <= 0:
                return
            try:
                sock.settimeout(left)
                data, addr = sock.recvfrom(MAX_PACKET)
            except OSError:                              # includes the time running out
                return
            try:
                handle(bytes(data[:MAX_PACKET]), addr[0])
            except Exception:
                pass

    @staticmethod
    def _send(sock, data, where):
        """Send one packet, ignoring a failure (a device that has just left, a network that is down)."""
        try:
            sock.sendto(data, where)
        except OSError:
            pass

    def ask_mdns(self, devices, deadline):
        """Ask over Bonjour which name each device has: once to the Bonjour group address (a few
        devices per packet) and once directly to each device (Apple devices answer that), from a
        passing port so nothing else on this computer is disturbed. Adds what the listener heard."""
        found = {}
        ips = sorted(devices)

        def heard(data, source):
            """Add one answer's names to `found`, first answer winning."""
            for ip, entry in learn_from_mdns(data, source, devices).items():
                merged = found.setdefault(ip, {})
                for k, v in entry.items():
                    merged.setdefault(k, v)

        if ips:
            try:
                with self.make_socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    try:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                    except OSError:
                        pass
                    sock.bind(("", 0))
                    for i in range(0, len(ips), 20):
                        self._send(sock, mdns_query([reverse_pointer(ip) for ip in ips[i:i + 20]]), MDNS)
                    for ip in ips:
                        self._send(sock, mdns_query([reverse_pointer(ip)]), (ip, MDNS[1]))
                    self._collect(sock, deadline, MDNS_WAIT, heard)
            except OSError:
                pass
        with self.lock:
            for ip in devices:
                for k, v in self.heard_mdns.get(ip, {}).items():
                    found.setdefault(ip, {}).setdefault(k, v)
        return found

    def ask_netbios(self, devices, deadline):
        """Ask each device, on the Windows network port, for its names."""
        found = {}
        if not devices:
            return found

        def heard(data, source):
            """Keep the name a device gave for itself."""
            name = parse_nbstat(data)
            if name and source in devices:
                found.setdefault(source, {"name": name})

        try:
            with self.make_socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("", 0))
                for n, ip in enumerate(sorted(devices)):
                    self._send(sock, nbstat_query(0x5100 + n), (ip, NETBIOS_PORT))
                self._collect(sock, deadline, NETBIOS_WAIT, heard)
        except OSError:
            pass
        return found

    def ask_ssdp(self, devices, deadline):
        """Make one UPnP 'who is there?' call, then download the description of each device that
        answered (only from its own address; see location_allowed). A description is reused for
        DESCRIPTION_KEEP seconds, and at most MAX_FETCHES are downloaded per round."""
        where = {}

        def heard(data, source):
            """Note a device's description address, if it may be fetched."""
            url = parse_ssdp(data)
            if source in devices and url and location_allowed(url, source):
                urls = where.setdefault(source, [])
                if url not in urls and len(urls) < 4:
                    urls.append(url)

        try:
            with self.make_socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                except OSError:
                    pass
                sock.bind(("", 0))
                self._send(sock, M_SEARCH, SSDP)
                self._collect(sock, deadline, SSDP_WAIT, heard)
        except OSError:
            pass
        now = time.monotonic()
        found, to_fetch = {}, []
        with self.lock:
            for ip, urls in sorted(where.items()):
                kept = [self.descriptions[u][1] for u in urls
                        if u in self.descriptions and now - self.descriptions[u][0] < DESCRIPTION_KEEP]
                if kept and kept[0]:
                    found[ip] = kept[0]
                elif not kept:
                    to_fetch.append(ip)

        def fetch(ip):
            """Download the first readable description this device offered (None if none)."""
            for url in where[ip]:
                desc = fetch_description(url, ip, min(FETCH_SECONDS, max(0.1, deadline - time.monotonic())),
                                         self.connect)
                with self.lock:
                    remember(self.descriptions, url, (time.monotonic(), desc or {}))
                if desc:
                    return desc
            return None

        found.update(run_all(fetch, to_fetch[:MAX_FETCHES], deadline, workers=8))
        return found

    def ask_router(self, devices, deadline):
        """Ask the home router for each device's name (a reverse lookup), sixteen at a time."""
        if self.reverse is None:
            return {}

        def look(ip):
            """One reverse lookup, as an entry, or None if the router knows no name."""
            name = self.reverse(ip)
            return {"name": name} if name else None

        return run_all(look, sorted(devices), deadline)

    # ----- the listeners

    def start_listeners(self):
        """Start listening for Bonjour announcements and DHCP requests, each on its own thread.
        Either may be impossible (the port is in use, or needs admin rights, as on a Mac); then
        QuietNet says so once, in the log, and carries on without it."""
        self._listen("bonjour", "Bonjour announcements (port 5353)", self.open_mdns_listener, self.hear_mdns)
        self._listen("dhcp", "devices joining the network (DHCP, port 67)", self.open_dhcp_listener, self.hear_dhcp)

    def _listen(self, key, what, opener, handler):
        """Open one listener and start its thread. Returns True if it is listening."""
        try:
            sock = opener()
        except OSError as e:
            self.listening[key] = False
            print("Device names: not listening for %s (%s). Names will still be found by asking devices directly."
                  % (what, e.strerror or e), flush=True)
            return False
        self.listening[key] = True
        threading.Thread(target=self._listen_loop, args=(sock, handler), daemon=True).start()
        return True

    @staticmethod
    def _listen_loop(sock, handler):
        """Pass every packet heard to `handler`, for as long as the program runs. A packet that
        can't be handled is skipped; a failing socket is retried after a pause, never in a tight loop."""
        while True:
            try:
                data, addr = sock.recvfrom(MAX_PACKET)
            except OSError:
                time.sleep(1)
                continue
            try:
                handler(bytes(data[:MAX_PACKET]), addr[0])
            except Exception:
                pass

    def open_mdns_listener(self):
        """A socket that hears Bonjour messages sent to the group address. It is bound to the group
        address itself, not to every address, so the system's own Bonjour service (avahi on a Pi,
        mDNSResponder on a Mac) keeps receiving every message sent straight to it."""
        sock = self.make_socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            sock.bind(MDNS)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            struct.pack("4s4s", socket.inet_aton(MDNS[0]), socket.inet_aton("0.0.0.0")))
        except OSError:
            sock.close()
            raise
        return sock

    def open_dhcp_listener(self):
        """A socket that hears DHCP requests devices broadcast when joining the network. Bound to the
        broadcast address only, so a DHCP server on this computer still gets every request sent
        straight to it. Nothing is ever sent from it."""
        sock = self.make_socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("255.255.255.255", DHCP_PORT))
        except OSError:
            sock.close()
            raise
        return sock

    def hear_mdns(self, data, source):
        """Keep what one Bonjour announcement says about the device that sent it."""
        if not usable_address(source):
            return
        learnt = learn_from_mdns(data, source, {source}).get(source)
        if learnt:
            with self.lock:
                entry = dict(self.heard_mdns.get(source, {}))
                entry.update(learnt)
                remember(self.heard_mdns, source, entry)

    def hear_dhcp(self, data, source):
        """Keep what one DHCP request says, by the hardware address of the device that sent it."""
        said = parse_dhcp(data)
        if said:
            with self.lock:
                remember(self.heard_dhcp, said["mac"], {"name": said["name"], "vendor": said["vendor"]})
