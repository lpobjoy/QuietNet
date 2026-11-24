"""QuietNet announcer - a trial: tell devices they may use this computer for IPv6 DNS.

OFF unless the owner switches it on, and only a trial. A home router with IPv6 sends every
device a regular announcement ("router advertisement") that can name a DNS server, and a BT
Smart Hub names itself. That cannot be changed on the hub, so devices send some of their
lookups past QuietNet. This module makes the Pi send announcements of its own that name this
computer as an IPv6 DNS server as well. It cannot replace the hub's announcement: each device
then knows two servers and chooses between them. So it never makes a device safe from
bypassing QuietNet, and the dashboard says so.

How it works, in plain terms:
  - Every few minutes the Pi sends one small message to every device on the home network. It
    says only: "the computer sending this can be used for IPv6 DNS for the next ten minutes".
  - The address it names is this computer's own home-only address on its home network card
    (its "link-local" address, starting fe80), which is also the address the message comes
    from. That address is always there, never changes when the internet provider changes the
    home's IPv6 range, and QuietNet always answers lookups sent to it.

Safety rules this module keeps (docs/ARCHITECTURE.md lists them with the reasons):
  - It sends nothing at all, and opens no socket, unless the owner has switched the trial on.
  - The message never offers this computer as a router: its router lifetime is 0, it hands out
    no address range, no route, and none of the "ask a DHCPv6 server" flags, and it leaves the
    devices' other network settings alone. It carries nothing but the DNS part. One thing in it
    is not "nothing to say": the two DHCPv6 flags have no such value, so leaving them clear
    reads "DHCPv6 is not used here", which is the opposite of what a router that sets them
    says. The trial therefore holds back while the home router hands out addresses by DHCPv6
    (see server.announce_hold_reason, and known issue 102 for what is left open).
  - It can only ever name the computer that sends it (build_dns_announcement refuses anything
    else), and nothing but a checked hardware address and a checked address goes into it.
  - It is sent only while QuietNet really is answering lookups over IPv6 on the usual DNS port:
    before every message, and every CHECK_EVERY seconds between them, QuietNet asks itself a
    test question at the very address it is about to name. If there is no answer, devices are
    told at once to stop using it.
  - It holds back, with a plain reason for the dashboard, whenever the rest of QuietNet says
    announcing could harm a household device (the `hold_reason` it is given: see
    server.announce_hold_reason), and when the home network card has more than one home-only
    address: answering from the very address that was asked has not been tried on a real Pi
    with two of them (see card_facts).
  - Devices are told to stop (the same message with a lifetime of 0, sent GOODBYES times) when
    the trial is switched off and when QuietNet is stopped cleanly. A goodbye that could not
    be sent is tried again at every look until one goes or the lifetime has run out, and the
    log never says devices were told when they were not. If the Pi loses power instead, devices
    drop it by themselves when the lifetime runs out (DNS_LIFETIME seconds).

This needs a Linux machine and the right to send raw network messages (NET_RAW, which the
QuietNet container has). On anything else it reports itself unavailable and does nothing. It
uses only the Python standard library.
"""
import ipaddress
import os
import re
import socket
import struct
import threading
import time

import enforcer

AF_PACKET = getattr(socket, "AF_PACKET", None)   # Linux only; None elsewhere so this module still imports
ETH_IPV6 = 0x86DD                   # the number that marks a network frame as carrying IPv6
ALL_DEVICES = "ff02::1"             # the IPv6 address every device on the home network listens to
ALL_DEVICES_MAC = "33:33:00:00:00:01"   # the hardware address that goes with it
# How long, in seconds, a device may go on using this computer for IPv6 DNS after the last
# announcement it heard. Short, so devices drop it soon after the Pi stops without warning; but
# Android ignores a DNS server offered for less than about two minutes, and one lost message must
# not make devices drop it, so it is three times the gap between announcements (as RFC 8106 advises).
DNS_LIFETIME = 600
ANNOUNCE_EVERY = 200                # seconds between announcements once under way
FIRST_ANNOUNCEMENTS = 3             # the first few go out closer together, so devices learn it quickly...
FIRST_GAP = 16                      # ...this many seconds apart
CHECK_EVERY = 20                    # seconds between checks that QuietNet still answers over IPv6
GOODBYES = 3                        # "stop using me" messages sent each time (Wi-Fi can lose one)...
GOODBYE_GAP = 0.3                   # ...this many seconds apart
MAX_WITHDRAWN = 4                   # earlier addresses of this computer one message may also call off
PROBE_TRIES = 2                     # test questions asked before deciding QuietNet is not answering
PROBE_WAIT = 1.5                    # seconds to wait for the answer to each
DNS_PORT = 53                       # an announcement can name an address but not a port: it must be this one
# A network card's name as Linux allows it: at most 15 characters, no slash, no spaces. Checked
# before the name is used in a file path or handed to the system.
CARD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}")
LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")


# ---------------------------------------------------------------- building the message

def own_hardware_address(mac):
    """The six raw bytes of a hardware address that one network card can send from. Raises
    ValueError for anything that is not six pairs of hex digits, for all zeros, and for a group
    address (one that stands for many devices, which has the lowest bit of its first byte set):
    a frame must never claim to come from one of those."""
    if not isinstance(mac, str) or not re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac):
        raise ValueError("not a hardware address: %r" % (mac,))
    raw = enforcer.mac_to_bytes(mac)
    if raw == bytes(6) or raw[0] & 1:
        raise ValueError("not one card's own hardware address: %r" % (mac,))
    return raw


def home_only_address(address):
    """An IPv6 address that only works inside the home (link-local, starting fe80), as an
    ipaddress object. Raises ValueError for anything else, including an address with a network
    card's name on the end ('fe80::1%wlan0')."""
    if "%" in str(address):
        raise ValueError("an address with a network card's name on the end: %r" % (address,))
    addr = ipaddress.IPv6Address(address)       # raises ValueError for text that is not an IPv6 address
    if addr not in LINK_LOCAL:
        raise ValueError("not a home-only (link-local) IPv6 address: %r" % (address,))
    return addr


def checksum(source, destination, message):
    """The check number every ICMPv6 message carries (RFC 4443, section 2.3). `source` and
    `destination` are the two 16-byte addresses and `message` the ICMPv6 message with its own
    check field set to zero. It is worked out over a made-up header (the two addresses, the
    message's length and the number 58 for ICMPv6) followed by the message, added up 16 bits at a
    time with the carries folded back in, then inverted. A device throws away a message whose
    check number is wrong."""
    data = source + destination + struct.pack(">I3xB", len(message), 58) + message
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def dns_part(address, lifetime):
    """The 24-byte part of an announcement that names one IPv6 DNS server (the "RDNSS option",
    RFC 8106): type 25, length 3 (in units of 8 bytes), two unused bytes, how many seconds
    devices may use the server (0 means "stop using it now"), then its address."""
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or not 0 <= lifetime <= 0xFFFFFFFF:
        raise ValueError("not a lifetime in seconds: %r" % (lifetime,))
    return struct.pack(">BBHI", 25, 3, 0, lifetime) + ipaddress.IPv6Address(address).packed


def build_dns_announcement(our_mac, our_address, lifetime, withdrawn=()):
    """One whole network frame, ready to send: an announcement to every device on the home
    network that the computer sending it can be used for IPv6 DNS for `lifetime` seconds (0
    tells devices to stop using it).

    `our_mac` is the hardware address of this computer's home network card and `our_address`
    its home-only (link-local) IPv6 address on that card. The message comes from that address
    and names that same address as the DNS server, so it can only ever name its own sender.
    `withdrawn` lists earlier addresses of this computer that devices may still hold; each is
    added with a lifetime of 0, and nothing else can be added. Raises ValueError rather than
    build a frame from anything unchecked.

    Layer by layer (the tests check every byte):
      - Ethernet: to 33:33:00:00:00:01 (every device), from our_mac, type 0x86DD (IPv6).
      - IPv6: from our_address to ff02::1 (every device on this network), next header 58
        (ICMPv6), hop limit 255. Devices ignore an announcement with any other hop limit, which
        is how they know it has not come through a router from somewhere else.
      - ICMPv6 "router advertisement" (type 134, code 0), 16 bytes, every field after the
        checksum zero: no hop limit to adopt; no "get addresses from a DHCPv6 server" flag (M)
        and no "get other settings from one" flag (O); ordinary router preference (the standard
        requires that when the lifetime is 0); ROUTER LIFETIME 0, which means "do not send your
        traffic through me"; and no timers to adopt. For the hop limit and the timers zero means
        "nothing to say". The M and O flags have no such value: clear, they read "DHCPv6 is not
        used here", which differs from a router that sets them, and a device may go by whichever
        announcer it heard last. They stay clear all the same (the design forbids them, and this
        computer is no DHCPv6 server); the trial holds back instead while the home router sets
        M (server.announce_hold_reason).
      - The DNS part(s): see dns_part. No address range (so no device makes itself an address
        from this), no route, no hardware address part: nothing else at all."""
    source_mac = own_hardware_address(our_mac)
    source = home_only_address(our_address)
    others = []
    for old in withdrawn:
        addr = home_only_address(old)
        if addr != source and addr not in others:
            others.append(addr)
    if len(others) > MAX_WITHDRAWN:
        raise ValueError("too many earlier addresses to call off in one message")
    parts = dns_part(source, lifetime) + b"".join(dns_part(addr, 0) for addr in others)
    destination = ipaddress.IPv6Address(ALL_DEVICES).packed
    head = struct.pack(">BBHBBHII", 134, 0, 0, 0, 0, 0, 0, 0)
    check = checksum(source.packed, destination, head + parts)
    message = head[:2] + struct.pack(">H", check) + head[4:] + parts
    ip = struct.pack(">IHBB", 6 << 28, len(message), 58, 255) + source.packed + destination
    ethernet = enforcer.mac_to_bytes(ALL_DEVICES_MAC) + source_mac + struct.pack(">H", ETH_IPV6)
    return ethernet + ip + message


# ---------------------------------------------------------------- facts about this computer

def link_locals_of(card, path="/proc/net/if_inet6"):
    """Every working home-only (link-local, fe80) IPv6 address of one of this computer's network
    cards, as text, lowest first; an empty list if it has none or the list of addresses (`path`,
    Linux only) can't be read.

    An address that failed its "is anyone else using this?" check (0x08), is being given up
    (0x20) or is still being checked (0x40) does not count: the card is not sending from it. The
    card's name is only compared with the file's own last column."""
    found = set()
    try:
        with open(path) as f:
            for line in f:
                cols = line.split()
                if len(cols) < 6 or len(cols[0]) != 32 or cols[5] != card:
                    continue
                addr = ipaddress.IPv6Address(bytes.fromhex(cols[0]))
                if addr in LINK_LOCAL and not int(cols[4], 16) & 0x68:
                    found.add(addr)
    except (OSError, ValueError):
        return []
    return [str(addr) for addr in sorted(found)]


def link_local_of(card, path="/proc/net/if_inet6"):
    """The working home-only (link-local, fe80) IPv6 address of one of this computer's network
    cards, as text, or '' if it has none or the list can't be read. If the card has several, the
    lowest is given, so the answer is the same every time. See link_locals_of."""
    found = link_locals_of(card, path)
    return found[0] if found else ""


def hardware_address_of(card, folder="/sys/class/net"):
    """The hardware address of one of this computer's network cards, as Linux reports it in
    `folder`, or '' if it can't be read. The card's name is checked first (CARD_NAME), since it
    becomes part of a file path."""
    if not isinstance(card, str) or not CARD_NAME.fullmatch(card) or ".." in card:
        return ""
    try:
        with open(os.path.join(folder, card, "address")) as f:
            return f.read().strip().lower()
    except OSError:
        return ""


def card_facts(card=None, inet6_path="/proc/net/if_inet6", folder="/sys/class/net"):
    """What is needed to announce from this computer: (network card, its hardware address, its
    home-only IPv6 address, ''), or (None, None, None, why not) with a plain-English reason for
    the dashboard. The card is the one this computer's home network is on (the one its default
    route uses), unless `card` names one (the tests do). Reads small files; runs no tools.

    A card with more than one working home-only address gives all three facts (the lowest
    address) AND a reason not to announce. On Linux both of QuietNet's UDP listeners answer
    each lookup from the address it was sent to (server.ask_for_reply_address and send_answer),
    and an answer over TCP always does. Only if the system refuses to send from that address
    does the answer leave from whichever of the card's addresses the system picks, and a device
    throws away an answer from an address it did not ask, and waits. That has never been tried
    on a real Pi with two home-only addresses, and the announcer's own test question, asked
    from this computer, could not notice it going wrong. So the trial holds back until manual
    step 79 has been run; taking the hold out is the owner's decision. The facts are still
    given so that devices already told can be sent a goodbye."""
    if card is None:
        card = enforcer.interface_and_gateway()[0]
    if not isinstance(card, str) or not CARD_NAME.fullmatch(card) or ".." in card:
        return None, None, None, ("QuietNet could not find the network card this computer's home network is on. "
                                  "It looks again every %d seconds." % CHECK_EVERY)
    mac = hardware_address_of(card, folder)
    try:
        own_hardware_address(mac)
    except ValueError:
        return None, None, None, "This computer's home network card has no hardware address QuietNet can send from."
    addresses = link_locals_of(card, inet6_path)
    if not addresses:
        return None, None, None, ("This computer's home network card has no IPv6 address of its own, so there is nothing "
                                  "to announce. IPv6 may be switched off on this computer.")
    if len(addresses) > 1:
        return card, mac, addresses[0], (
            "This computer's home network card has more than one home-only IPv6 address (%s), so QuietNet cannot be "
            "sure its answers would leave from the one it announced. It is not announcing itself. Remove the extra "
            "address, or leave the trial off." % " and ".join(addresses[:4]))
    return card, mac, addresses[0], ""


def why_unavailable():
    """A plain-English reason the trial cannot run on this computer at all, or '' if it can.
    Shown on the dashboard."""
    if AF_PACKET is None or not os.path.exists("/proc/net/if_inet6"):
        return "This trial only works where QuietNet runs on a Raspberry Pi or another Linux computer with IPv6."
    return ""


def open_sender(card):
    """Open the socket announcements are sent through. Needs admin rights or NET_RAW. Its
    protocol number is 0, which tells Linux to hand it nothing: it is only ever sent on, never
    read, so nothing can pile up in it. Each frame names the card when it is sent (see
    Announcer._send)."""
    if AF_PACKET is None:
        raise OSError("this computer cannot send raw network frames")
    return socket.socket(AF_PACKET, socket.SOCK_RAW, 0)


def dns_answers(address, card="", port=DNS_PORT, wait=PROBE_WAIT, tries=PROBE_TRIES):
    """Is a DNS server answering at this address right now? True only if it sends back a reply
    to a test question within `wait` seconds, in at most `tries` goes.

    This is how the announcer knows QuietNet's IPv6 DNS is really answering, not merely started:
    it asks the very address it is about to announce. The test question is a bare 12-byte DNS
    header with a random number and no name in it. QuietNet answers that at once with "format
    error" (server.unreadable_reply), without writing anything to the history and without
    asking the internet, and that answer, carrying the same number and marked as a reply, is
    all that is looked for. `card` is the network card a home-only (fe80) address is on, which
    the system needs to know to reach it. An IPv4 address works too (the tests use 127.0.0.1)."""
    try:
        if "%" in str(address):
            return False                # the card is given separately, never on the end of the address
        addr = ipaddress.ip_address(address)
        if addr.version == 6:
            scope = socket.if_nametoindex(card) if addr in LINK_LOCAL else 0
            family, where = socket.AF_INET6, (str(addr), port, 0, scope)
        else:
            family, where = socket.AF_INET, (str(addr), port)
        sock = socket.socket(family, socket.SOCK_DGRAM)
    except (OSError, ValueError, TypeError):
        return False
    try:
        sock.settimeout(wait)
        sock.connect(where)             # so only an answer from that very address and port is taken
        for _ in range(tries):
            question = os.urandom(2) + bytes(10)
            try:
                sock.send(question)
                answer = sock.recv(512)
            except OSError:             # nothing came back in time, or nothing is listening there
                continue
            if len(answer) >= 12 and answer[:2] == question[:2] and answer[2] & 0x80:
                return True
        return False
    except (OSError, ValueError):
        return False
    finally:
        sock.close()


# ---------------------------------------------------------------- the announcer

class Announcer:
    """Sends the announcements while the trial is switched on, and tells devices to stop when it
    is switched off, when QuietNet stops answering over IPv6, and when QuietNet is stopped.

    Give it dns_listening(), which says whether QuietNet's own IPv6 DNS listener is open on the
    usual port, and hold_reason(address), which gives a plain-English reason not to announce
    that address just now ('' when there is none). Call start() once; it does nothing on the
    network until `on` is true. switch() turns the trial on or off, status() is what the
    dashboard shows, and stop() says goodbye at shut-down. One background thread does all the
    sending, one step() at a time."""

    def __init__(self, dns_listening, on=False, log=print, facts=card_facts, answers=dns_answers,
                 open_sender=open_sender, clock=time.monotonic, pause=time.sleep, unavailable=None,
                 hold_reason=None):
        """Remember the choices; touch nothing on the network. `on` is the owner's saved choice
        (off unless they switched it on). `hold_reason(address)` is asked before every
        announcement and at every look between them: any text it returns is shown on the
        dashboard and nothing is announced (None: there is never such a reason). The rest are
        stand-ins for the tests: `facts` gives the card, hardware address and address to announce
        (card_facts), `answers` asks the test question (dns_answers), `open_sender` opens the
        sending socket, `clock` and `pause` are the steady timer and the wait between goodbyes,
        and `unavailable` is the reason the trial can't run here ('' if it can; None works it
        out)."""
        self.dns_listening = dns_listening
        self.hold_reason = hold_reason
        self.on = bool(on)
        self.log = log
        self.unavailable = why_unavailable() if unavailable is None else unavailable
        self.state = "off"            # off | starting | announcing | held | stopping | unavailable
        self.reason = ""              # why it is held or unavailable, in plain English
        self.address = ""             # the address being announced right now ('' = none)
        self.last_sent = None         # when (time.time()) the last announcement went out
        self._facts = facts
        self._answers = answers
        self._open_sender = open_sender
        self._clock = clock
        self._pause = pause
        # Addresses devices were told to use and have not yet been told to drop -> when (self._clock())
        # each was last announced. One is forgotten only when a goodbye naming it really left, or when
        # DNS_LIFETIME seconds have passed since it was announced (devices have dropped it by themselves).
        self._told = {}
        self._last = None             # (card, hardware address, address) of the last announcement that went out
        self._cleared = False         # has the once-only goodbye been dealt with since this run last could not announce?
        self._unsent_logged = False   # has the log said that the goodbye at switching off could not be sent?
        self._sent_at = None          # when (self._clock()) the last announcement went out
        self._sent = 0                # announcements sent since it last began announcing
        self._sock = None
        self._lock = threading.RLock()    # one step at a time
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None

    # -- what the rest of QuietNet calls ------------------------------------

    def start(self):
        """Start the background thread. Call once. While the trial is off the thread only
        waits; it sends nothing and opens nothing."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def switch(self, on):
        """Turn the trial on or off (the owner's choice; the caller saves it). Returns at once:
        the background thread starts announcing, or sends the goodbyes, within a moment."""
        self.on = bool(on)
        if self.on and self.state in ("off", "stopping"):
            self.state = "starting"
        elif not self.on and self.state in ("announcing", "starting"):
            self.state = "stopping"
        self._wake.set()

    def status(self):
        """What the dashboard shows (the "dns_announce" part of GET /api/status): {"on": the
        owner's choice, "available": can the trial run on this computer at all, "state": "off",
        "starting", "announcing", "held" (on, but not announcing; "reason" says why),
        "stopping" (off, and telling devices to stop; "reason" is not empty while that message
        could not be sent yet) or "unavailable", "reason": plain English or '', "address": the address being
        announced or '', "sent": when (time.time()) the last announcement went out or None,
        "lifetime": seconds devices keep it after the last one, "every": seconds between
        announcements}. Never waits for the sending thread."""
        announcing = self.state == "announcing"
        return {"on": self.on, "available": not self.unavailable, "state": self.state, "reason": self.reason,
                "address": self.address if announcing else "", "sent": self.last_sent if announcing else None,
                "lifetime": DNS_LIFETIME, "every": ANNOUNCE_EVERY}

    def ask_to_stop(self):
        """Begin stopping without waiting: the background thread sends the goodbyes and ends.
        Called first at shut-down, so the goodbyes go out while the rest of QuietNet tidies up."""
        self._stop.set()
        self._wake.set()

    def stop(self, wait=5):
        """Stop, and wait (up to `wait` seconds) until devices have been told to stop using this
        computer for IPv6 DNS. Without the wait the program could exit before the goodbyes left.
        Five seconds covers a check that was under way (two test questions of 1.5 seconds) and the
        goodbyes after it; when ask_to_stop() was called earlier, most of that has already passed."""
        self.ask_to_stop()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(wait)

    # -- the work -----------------------------------------------------------

    def _run(self):
        """The background thread: one step, then wait until the next is due or someone calls
        switch() or stop(). A step that fails is reported and tried again; when asked to stop,
        one last step says goodbye."""
        while not self._stop.is_set():
            try:
                wait = self.step()
            except Exception as e:
                self.log("IPv6 DNS announcement trial: problem (%s); trying again." % e)
                wait = CHECK_EVERY
            if self._stop.is_set():
                break
            self._wake.wait(wait)
            self._wake.clear()
        try:
            self.step()
        except Exception as e:
            self.log("IPv6 DNS announcement trial: could not say goodbye (%s)." % e)

    def step(self):
        """Do whatever is due now, and return how many seconds until the next look (None: nothing
        to do until switch() or stop() is called).

        Off, or stopping: if devices were told to use this computer, tell them to stop; close the
        socket (see _finish). On: find the card and its addresses, check QuietNet is taking and
        answering lookups over IPv6 at the address to be named and that nothing says announcing
        could do harm (hold_reason), and if anything is missing hold back, telling devices to
        stop if they were told before (or once, in case an earlier run that ended without warning
        left them using it). Otherwise send an announcement if one is due: the first few
        FIRST_GAP seconds apart, then every ANNOUNCE_EVERY seconds."""
        with self._lock:
            self._forget_what_has_run_out()
            if not self.on or self._stop.is_set():
                return self._finish()
            self._unsent_logged = False
            if self.unavailable:
                self.state, self.reason, self.address = "unavailable", self.unavailable, ""
                return None
            card, mac, address, problem = self._facts()
            if not problem and not self._listening():
                problem = ("QuietNet is not taking lookups over IPv6 on the usual DNS port (%d) on this computer, "
                           "so it is not announcing itself." % DNS_PORT)
            if not problem:
                problem = self._held_back(address)
            if not problem and not self._answering(address, card):
                problem = ("QuietNet did not answer a test lookup over IPv6, so it is not announcing itself. "
                           "It checks again every %d seconds." % CHECK_EVERY)
            if problem:
                return self._hold(problem, card, mac, address)
            if set(self._told) - {address}:
                # Devices still hold an earlier address of this computer: call it off. The goodbye
                # names the present address as well, so once it has gone (or if the present address
                # was never announced) the present one is announced straight away, and the first
                # few announcements go close together again. A goodbye that could not be sent is
                # tried again at the next look without disturbing the announcements.
                self._say_goodbye(card, mac, address)
                if address not in self._told:
                    self._sent_at, self._sent = None, 0
            now = self._clock()
            if self._sent_at is None or now - self._sent_at >= self._gap():
                try:
                    frame = build_dns_announcement(mac, address, DNS_LIFETIME)
                except ValueError as e:
                    return self._hold("QuietNet could not make the announcement (%s)." % e, card, mac, address)
                error = self._send(card, frame)
                if error:
                    return self._hold("This computer would not send the announcement (%s). In Docker, QuietNet needs "
                                      "the NET_RAW right, which docker-compose.yml gives it." % error, None, None, None)
                if self.state != "announcing":
                    self.log("IPv6 DNS announcement trial: announcing %s on %s, about every %d seconds."
                             % (address, card, ANNOUNCE_EVERY))
                self._told[address] = now
                self._last = (card, mac, address)
                self._cleared = False
                self._sent_at, self._sent, self.last_sent = now, self._sent + 1, time.time()
                self.state, self.reason, self.address = "announcing", "", address
            return max(1.0, min(CHECK_EVERY, self._sent_at + self._gap() - now))

    def _forget_what_has_run_out(self):
        """Forget every address last announced DNS_LIFETIME seconds ago or more: devices have
        dropped it by themselves, so no goodbye is owed for it. This is what stops a goodbye that
        can never be sent from being tried for ever."""
        now = self._clock()
        for address in [a for a, at in self._told.items() if now - at >= DNS_LIFETIME]:
            del self._told[address]

    def _finish(self):
        """The trial is switched off, or QuietNet is stopping: tell devices to stop using this
        computer if they were told to use it, close the socket, and return when to look again
        (None: not until switch() is called).

        The log says devices were told only when a goodbye really left. If none could be sent
        (the card refused, or is gone) after the trial was switched off, the state stays
        "stopping" and the goodbye is tried again every CHECK_EVERY seconds, until one goes or
        the DNS_LIFETIME seconds devices keep the address for have passed. At shut-down there is
        one go only, since the program is about to end, and the log says plainly if it failed."""
        owed = bool(self._told)
        while self._told and self._say_goodbye():
            pass
        minutes = DNS_LIFETIME // 60
        if self._told and not self._stop.is_set():
            self._close()
            if not self._unsent_logged:
                self.log("IPv6 DNS announcement trial: switched off, but this computer could not send the message "
                         "telling devices to stop using it for IPv6 DNS. It tries again every %d seconds; devices "
                         "stop by themselves within %d minutes." % (CHECK_EVERY, minutes))
                self._unsent_logged = True
            self._sent_at, self._sent = None, 0
            self.state, self.address = "stopping", ""
            self.reason = ("This computer could not send the message yet. It tries again every %d seconds, and "
                           "devices stop by themselves within %d minutes." % (CHECK_EVERY, minutes))
            return CHECK_EVERY
        if owed and not self._told:
            self.log("IPv6 DNS announcement trial: stopped. Devices were told to stop using this "
                     "computer for IPv6 DNS.")
        elif owed:
            self.log("IPv6 DNS announcement trial: stopped, but this computer could not send the message telling "
                     "devices to stop using it for IPv6 DNS. They stop by themselves within %d minutes." % minutes)
        elif self._unsent_logged:
            self.log("IPv6 DNS announcement trial: stopped. The message telling devices to stop never got out; "
                     "the %d minutes they keep this computer for have now passed." % minutes)
        self._close()
        self._told, self._last, self._unsent_logged = {}, None, False
        self._sent_at, self._sent, self._cleared = None, 0, False
        self.state, self.reason, self.address = "off", "", ""
        return None

    def _gap(self):
        """Seconds between the announcement just sent and the next one."""
        return FIRST_GAP if self._sent < FIRST_ANNOUNCEMENTS else ANNOUNCE_EVERY

    def _listening(self):
        """Is QuietNet's own IPv6 DNS listener open on the usual port? False if asking fails."""
        try:
            return bool(self.dns_listening())
        except Exception:
            return False

    def _held_back(self, address):
        """A plain-English reason, from the rest of QuietNet, not to announce this address just
        now, or '' if there is none (see server.announce_hold_reason). If asking fails, that is
        itself a reason: the trial must never announce on a guess."""
        if self.hold_reason is None:
            return ""
        try:
            return str(self.hold_reason(address) or "")
        except Exception:
            return ("QuietNet could not tell whether it is safe to announce itself, so it is not announcing. "
                    "It checks again every %d seconds." % CHECK_EVERY)

    def _answering(self, address, card):
        """Does QuietNet answer a test question at the address about to be announced? False if
        asking fails."""
        try:
            return bool(self._answers(address, card))
        except Exception:
            return False

    def _hold(self, problem, card, mac, address):
        """Hold back: something needed for announcing is missing (`problem`, plain English for
        the dashboard). If devices were told to use this computer, or the once-only goodbye has
        not been dealt with since this run began holding back, tell them to stop now. That second
        case covers a QuietNet that ended without warning while announcing and came back unable
        to answer. A goodbye that could not be sent is tried again at every look (this is called
        every CHECK_EVERY seconds while held) until one goes or the addresses have run out. The
        pacing is set back, so announcing starts again at once, with its first few announcements
        close together, when the problem goes. Returns how long until the next look."""
        if self._told or not self._cleared:
            self._say_goodbye(card, mac, address)
        if self.state != "held" or self.reason != problem:
            self.log("IPv6 DNS announcement trial: not announcing. " + problem)
        self._sent_at, self._sent = None, 0
        self.state, self.reason, self.address = "held", problem, ""
        return CHECK_EVERY

    def _say_goodbye(self, card=None, mac=None, address=None):
        """Tell every device to stop using this computer for IPv6 DNS: the announcement again
        with a lifetime of 0, naming the address it is sent from and up to MAX_WITHDRAWN earlier
        ones devices may still hold, sent GOODBYES times because Wi-Fi can lose a message sent to
        everyone. Returns True if at least one goodbye was sent.

        Where it is sent from: the card, hardware address and address given, or else the card's
        present ones; and if those can't be found or make no frame, the ones the last
        announcement went out with. The frame is sent whole through a packet socket, so it can
        still leave after the card has lost its IPv6 address.

        An address is forgotten only when a goodbye naming it really left. If none could be sent,
        the addresses devices were told stay remembered, and the callers try again at the next
        look (see _hold and _finish). The once-only goodbye of a run that never announced
        (nothing remembered) is not tried again after a send that failed, so a computer that may
        not send raw frames does not try for ever."""
        if card is None or mac is None or address is None:
            try:
                card, mac, address, _ = self._facts()
            except Exception:
                card = mac = address = None
        sources = [] if card is None or mac is None or address is None else [(card, mac, address)]
        if self._told and self._last is not None and self._last not in sources:
            sources.append(self._last)
        frame, named = None, []
        for card, mac, address in sources:
            named = [address] + sorted(set(self._told) - {address})[:MAX_WITHDRAWN]
            try:
                frame = build_dns_announcement(mac, address, 0, named[1:])
                break
            except ValueError:
                continue
        if frame is None:
            return False                # nothing to send from; whatever devices were told stays remembered
        sent = False
        for n in range(GOODBYES):
            if n:
                self._pause(GOODBYE_GAP)
            if self._send(card, frame):
                break                   # refused: the rest would be too; the next look tries again
            sent = True
        if sent:
            for told in named:
                self._told.pop(told, None)
        if sent or not self._told:
            self._cleared = True
        return sent

    def _send(self, card, frame):
        """Send one frame out of the home network card, opening the socket first if need be.
        Returns '' if it went, or the system's reason if not (the socket is then closed, to be
        opened afresh next time)."""
        try:
            if self._sock is None:
                self._sock = self._open_sender(card)
            self._sock.sendto(frame, (card, ETH_IPV6))
            return ""
        except (OSError, ValueError, TypeError) as e:
            self._close()
            return str(e) or e.__class__.__name__

    def _close(self):
        """Close the sending socket, if it is open."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
