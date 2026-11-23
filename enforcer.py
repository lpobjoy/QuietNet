"""QuietNet enforcer - cut connections that are already live.

A DNS block only stops a device *finding* an address. Once a device has opened a
connection (a Disney+ stream already playing, say), it keeps talking to that
address directly and the DNS block does nothing. The enforcer closes that gap.

How it works, in plain terms:
  - Every device on a home network asks "who is the router?" and remembers the
    answer. The enforcer answers that question for a chosen device with "the
    router is me" (this is called ARP). From then on, that device's traffic to
    the internet flows *through* this computer.
  - This computer forwards everything as normal, EXCEPT packets heading for an
    address that is blocked for that device - those it quietly drops. Because the
    device sees QuietNet as the DNS resolver, QuietNet already knows which
    addresses belong to Disney+, Fortnite and so on.
  - The result: blocked services and bedtimes cut live connections within
    seconds, not just new ones. Everything else the device does is untouched.

Safety rules this module keeps:
  - It only steers devices you explicitly choose, on this machine's own network,
    and never the router or this machine.
  - It won't steer anything unless forwarding really is on and no other firewall
    would silently drop the forwarded traffic (either would cut the device off).
  - A device that leaves the plan is handed straight back to the real router.
  - What it changed (kernel settings, steered devices) is written to disk, so if
    QuietNet is killed or crashes, the next start puts the network back first.

This needs a Linux machine (a Raspberry Pi is the intended home) and the right
to use the network directly (run as root, or the container's NET_RAW/NET_ADMIN).
On anything else it reports itself unavailable and does nothing. It uses only the
Python standard library plus the system's own firewall command (nft or iptables).
"""
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time

AF_PACKET = getattr(socket, "AF_PACKET", None)   # Linux only; None elsewhere so this module still imports
ETH_ARP = 0x0806
IS_LINUX = os.path.exists("/proc/net/route")
TABLE = "quietnet"


# ---------------------------------------------------------------- pure helpers

def mac_to_bytes(mac):
    """'aa:bb:cc:dd:ee:ff' -> the six raw bytes. Raises ValueError for anything else."""
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError("not a hardware address: %r" % mac)
    return bytes(int(p, 16) for p in parts)


def build_arp_reply(sender_ip, sender_mac, target_ip, target_mac, eth_src=None):
    """One ARP 'reply' frame saying: sender_ip is at sender_mac. Addressed to target.

    To make a device route through us, sender_ip is the router's address and
    sender_mac is OURS. To heal it afterwards, sender_mac is the router's real
    hardware address. eth_src is who the frame physically comes from. When healing it
    must be us: network switches get confused by frames claiming to come from another
    machine, and Wi-Fi drops them. It defaults to sender_mac."""
    eth = mac_to_bytes(target_mac) + mac_to_bytes(eth_src or sender_mac) + struct.pack(">H", ETH_ARP)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2)        # ethernet, IPv4, reply
    arp += mac_to_bytes(sender_mac) + socket.inet_aton(sender_ip)
    arp += mac_to_bytes(target_mac) + socket.inet_aton(target_ip)
    return eth + arp


def parse_arp_request(frame):
    """If this frame is an ARP 'who has this address?' question, return
    (asker's address, asker's hardware address, address asked about). Otherwise None."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x06" or frame[20:22] != b"\x00\x01":
        return None
    return socket.inet_ntoa(frame[28:32]), frame[22:28].hex(":"), socket.inet_ntoa(frame[38:42])


def _checked_ipv4(text):
    """The address as checked text, or ValueError if it isn't a plain IPv4 address. Every address
    that goes into a firewall rule passes through here first, so nothing a person or a device typed
    can ever be read by the firewall as part of a rule."""
    return str(ipaddress.IPv4Address(text))


def _redirect_target(our_ip, dns_port):
    """(this machine's address, the DNS port) for the DNS redirect, or None when there should be
    no redirect: no port given, or this machine only knows itself as 127.0.0.1 (its network is
    down), which a device's lookup can't be sent to. A port outside 1-65535 is a ValueError."""
    if dns_port is None:
        return None
    if isinstance(dns_port, bool) or not isinstance(dns_port, int) or not 0 < dns_port < 65536:
        raise ValueError("not a port number: %r" % (dns_port,))
    addr = ipaddress.IPv4Address(our_ip)
    if addr.is_loopback or addr.is_unspecified:
        return None
    return str(addr), dns_port


DOT_PORT = 853      # private DNS (DNS over TLS) and DNS over QUIC both use this port


def nft_ruleset(plan, our_ip, dns_port=None):
    """The complete nftables program for the current plan.

    plan: {victim_ip: {"off": bool, "ips": [blocked ip, ...]}}
    'off' means cut everything for that device (except reaching QuietNet itself);
    otherwise only the listed addresses are dropped.

    For every steered device, two more things are done whatever its plan says (known issue 8):
      - Ordinary DNS lookups (port 53) sent to any other server (8.8.8.8, the router) are sent to
        QuietNet instead, at our_ip and dns_port, so this household's rules still apply. Only
        traffic arriving from a steered device is touched: this machine's own lookups never pass
        the "prerouting" step, and the router and this machine are never steered.
      - Private DNS (DNS over TLS, port 853 over TCP) and DNS over QUIC (port 853 over UDP) are
        dropped, so the device falls back to ordinary DNS, which then comes to QuietNet.
    With dns_port None the redirect is left out (the port 853 drops stay).

    Every address is checked first; a bad one raises ValueError rather than reach the firewall."""
    our_ip = _checked_ipv4(our_ip)
    victims = sorted(plan, key=lambda ip: ipaddress.IPv4Address(ip))
    for victim in victims:
        _checked_ipv4(victim)
    target = _redirect_target(our_ip, dns_port)
    # Loading a table that already exists ADDS to it; it does not replace it. Without the first
    # two lines, a rule dropped from the plan would stay in the kernel - a device whose internet
    # was switched back on would stay cut off until QuietNet restarted. "Declare, delete, define"
    # is the standard way to replace a table: the first line makes sure there is something to
    # delete (so the delete cannot fail), and nft applies the whole text as one step, so there is
    # no moment with half the rules loaded.
    lines = ["table inet %s" % TABLE, "delete table inet %s" % TABLE,
             "table inet %s {" % TABLE, "  chain forward {", "    type filter hook forward priority -150; policy accept;"]
    who = "{ %s }" % ", ".join(victims)
    if victims:
        lines.append("    ip saddr %s tcp dport %d drop" % (who, DOT_PORT))
        lines.append("    ip saddr %s udp dport %d drop" % (who, DOT_PORT))
    for victim in victims:
        rule = plan[victim]
        if rule.get("off"):
            lines.append("    ip saddr %s ip daddr != %s drop" % (victim, our_ip))
        elif rule.get("ips"):
            addrs = ", ".join(sorted(rule["ips"]))
            lines.append("    ip saddr %s ip daddr { %s } drop" % (victim, addrs))
    lines.append("  }")
    if victims and target:
        # Priority -100 is the usual place for this step ("dstnat"), written as a number so that
        # older versions of nft read it too. conntrack puts the original server's address back on
        # the answers, so the device sees a reply from the server it asked.
        lines += ["  chain dns_redirect {", "    type nat hook prerouting priority -100; policy accept;"]
        for proto in ("udp", "tcp"):
            lines.append("    ip saddr %s ip daddr != %s %s dport 53 dnat ip to %s:%d"
                         % (who, target[0], proto, target[0], target[1]))
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def iptables_rules(plan, our_ip):
    """The same plan expressed as iptables commands, for systems without nft. Port 853 (private
    DNS) is dropped here too, but ordinary DNS sent to another server is NOT redirected to
    QuietNet: that would need rules in a second iptables table, kept and cleared alongside this one,
    and the Pi's own image always has nft. Status() says so when this tool is in use."""
    cmds = [["-F", "QUIETNET"]]
    for victim, rule in sorted(plan.items()):
        _checked_ipv4(victim)
        for proto in ("tcp", "udp"):
            cmds.append(["-A", "QUIETNET", "-s", victim, "-p", proto, "--dport", str(DOT_PORT), "-j", "DROP"])
        if rule.get("off"):
            cmds.append(["-A", "QUIETNET", "-s", victim, "!", "-d", our_ip, "-j", "DROP"])
        else:
            for ip in sorted(rule.get("ips", [])):
                cmds.append(["-A", "QUIETNET", "-s", victim, "-d", ip, "-j", "DROP"])
    return cmds


_COUNTER = r"(counter(\s+packets\s+\d+\s+bytes\s+\d+)?\s+)?"
FINAL_REJECT = re.compile(r"^\s*" + _COUNTER + r"(drop|reject)\b")
_PLAIN_JUMP = re.compile(r"^\s*" + _COUNTER + r"(jump|goto)\s+(\S+)\s*$")
_PLAIN_RETURN = re.compile(r"^\s*" + _COUNTER + r"return\s*$")


def _nft_tables(ruleset_text):
    """Read `nft list ruleset` into {(family, table): {chain: {"forward": bool, "drop": bool,
    "rules": [rule text, ...]}}}. "forward" means the chain is hooked on forwarded traffic, and
    "drop" that its policy drops whatever reaches the end. Sets and other blocks are skipped."""
    tables, depth, table, chain = {}, 0, None, None
    for line in ruleset_text.splitlines():
        s = line.strip()
        if depth == 0:
            m = re.match(r"table\s+(\S+)\s+(\S+)\s*\{", s)
            if m:
                table = (m.group(1), m.group(2))
                tables.setdefault(table, {})
        elif depth == 1 and table:
            m = re.match(r"chain\s+(\S+)\s*\{", s)
            if m:
                chain = tables[table].setdefault(m.group(1), {"forward": False, "drop": False, "rules": []})
        elif depth == 2 and chain is not None:
            if re.search(r"\bhook\s+forward\b", s):
                chain["forward"] = True
                chain["drop"] = bool(re.search(r"\bpolicy\s+drop\b", s))
            elif s and s != "}":
                chain["rules"].append(s)
        depth = max(0, depth + s.count("{") - s.count("}"))
        if depth <= 1:
            chain = None
        if depth == 0:
            table = None
    return tables


def _chain_verdict(chains, name, iface, seen, base=True):
    """What happens to traffic coming in on `iface` and going back out of it when it runs through
    one chain: "accept", "drop", "end" (the base chain's policy decides), or None (it carries on
    after the rule that jumped here). Only rules that apply to all traffic are followed, plus the
    accept our advice adds, so a rule that only matches some traffic never clears a firewall.

    base: is this the forward chain itself, or a chain reached from it only by goto? A goto
    target that runs out of rules ends the forward chain there, but one reached (at any depth)
    through a jump goes back and carries on after that jump, as nftables does."""
    if name in seen or name not in chains:
        return None
    seen = seen | {name}
    ours = re.compile(r'^iifname "?%s"?\s+oifname "?%s"?\s.*\baccept\s*$' % (re.escape(iface), re.escape(iface)))
    for rule in chains[name]["rules"]:
        if ours.match(rule):
            return "accept"
        if FINAL_REJECT.match(rule):
            return "drop"
        if _PLAIN_RETURN.match(rule):
            return None
        m = _PLAIN_JUMP.match(rule)
        if m:
            goto = m.group(3) == "goto"
            verdict = _chain_verdict(chains, m.group(4), iface, seen, base and goto)
            if goto:
                return verdict or ("end" if base else None)
            if verdict:
                return verdict
    return None


def forward_blockers(ruleset_text, iface):
    """Every *other* firewall chain, as listed by `nft list ruleset`, that would drop the traffic
    we forward. Returns [(family, table, chain, made_by_docker), ...]; [] means all clear.

    In nftables each table's forward chain is run in turn and every one must let a packet through:
    an accept in one table does not override a drop or reject in another. So each chain is judged
    on its own. Docker sets its forward policy to drop; firewalld ends its forward chain with a
    reject. Either is fine if the same chain (or a chain it always jumps to) first accepts traffic
    coming in on our network connection and going back out of it - the rule our advice adds."""
    found = []
    for (family, table), chains in sorted(_nft_tables(ruleset_text).items()):
        if table == TABLE or family not in ("ip", "inet"):
            continue                  # only ip and inet tables see the IPv4 traffic we forward
        for name, chain in sorted(chains.items()):
            if not chain["forward"]:
                continue
            verdict = _chain_verdict(chains, name, iface, frozenset())
            if verdict == "drop" or (verdict != "accept" and chain["drop"]):
                found.append((family, table, name, family == "ip" and "DOCKER-USER" in chains))
    return found


def foreign_forward_drop(ruleset_text, iface):
    """Would some *other* firewall, as listed by `nft list ruleset`, drop the traffic we forward?
    Returns the first offending table's name, or '' (see forward_blockers for the details)."""
    found = forward_blockers(ruleset_text, iface)
    return found[0][1] if found else ""


def nft_advice(family, table, chain, docker, iface):
    """The command that lets our forwarded traffic through one blocking nftables chain. Docker's
    rules go in its DOCKER-USER chain, which Docker keeps for exactly this; a chain made with
    iptables (ip filter FORWARD) is changed with iptables; anything else is changed with nft."""
    if docker:
        return "sudo iptables -I DOCKER-USER -i %s -o %s -j ACCEPT" % (iface, iface)
    if (family, table, chain) == ("ip", "filter", "FORWARD"):
        return "sudo iptables -I FORWARD -i %s -o %s -j ACCEPT" % (iface, iface)
    return "sudo nft insert rule %s %s %s iifname %s oifname %s accept" % (family, table, chain, iface, iface)


def iptables_forward_drop(listing, iface):
    """The same question for the older tool, given the output of `iptables -S`.
    True if forwarded traffic would be dropped."""
    if re.search(r"-i %s -o %s .*-j ACCEPT" % (re.escape(iface), re.escape(iface)), listing):
        return False
    return bool(re.search(r"^-P FORWARD DROP", listing, re.M)) or \
        bool(re.search(r"^-A FORWARD -j (REJECT|DROP)\b", listing, re.M))


def iptables_advice(tool, listing, iface):
    """The command that lets our forwarded traffic through, for rules listed by `<tool> -S`:
    into Docker's DOCKER-USER chain if Docker made one, otherwise at the top of FORWARD."""
    chain = "DOCKER-USER" if re.search(r"^-N DOCKER-USER\b", listing, re.M) else "FORWARD"
    return "sudo %s -I %s -i %s -o %s -j ACCEPT" % (tool, chain, iface, iface)


def lasting_note(fixes):
    """A sentence to put before the commands that let passed-on traffic through: a rule added by
    hand lasts only until the Pi restarts. For Docker's chain, QuietNet's installer can add a small
    service that puts the rule back after every restart, so say that running it again does so."""
    if any(" DOCKER-USER " in fix for fix in fixes):
        return ("A command run by hand lasts until the Pi restarts; running QuietNet's install command "
                "again (with --yes) makes the Docker part permanent. ")
    return "A command run by hand lasts until the Pi restarts. "


def target_problem(ip, subnet, gateway_ip, local_ip):
    """Why this address can't be steered, in plain English, or '' if it can.
    subnet may be None when this machine's network isn't known (then only the basics are checked)."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return "That isn't a valid device address."
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
        return "That isn't a device on your home network."
    if ip in (gateway_ip, local_ip):
        return "QuietNet can't steer the router or itself."
    if subnet is not None:
        if addr not in subnet:
            return "That device isn't on the same network as QuietNet."
        if addr in (subnet.network_address, subnet.broadcast_address):
            return "That isn't a device on your home network."
    return ""


# ---------------------------------------------------------------- system facts

def _routes():
    """The rows of the Linux routing table, as lists of columns ([] if it can't be read)."""
    try:
        with open("/proc/net/route") as f:
            return [line.split() for line in f.readlines()[1:]]
    except OSError:
        return []


def _hex_ip(text):
    """An address as written in /proc/net/route (little-endian hex) -> dotted form."""
    return socket.inet_ntoa(struct.pack("<I", int(text, 16)))


def interface_and_gateway():
    """Return (interface, gateway_ip) from the Linux routing table, or (None, None)."""
    try:
        for c in _routes():
            if len(c) >= 3 and c[1] == "00000000":          # the default route
                return c[0], _hex_ip(c[2])
    except ValueError:
        pass
    return None, None


def local_subnet(iface):
    """The home network this interface is directly connected to (e.g. 192.168.1.0/24), or None."""
    try:
        for c in _routes():
            if len(c) >= 8 and c[0] == iface and c[2] == "00000000" and c[7] != "00000000":
                return ipaddress.IPv4Network("%s/%s" % (_hex_ip(c[1]), _hex_ip(c[7])), strict=False)
    except ValueError:
        pass
    return None


def mac_of_interface(iface):
    """The hardware address of one of this machine's network interfaces, or None."""
    try:
        with open("/sys/class/net/%s/address" % iface) as f:
            return f.read().strip()
    except OSError:
        return None


def _proc_path(key):
    """'net.ipv4.conf.eth0.send_redirects' -> '/proc/sys/net/ipv4/conf/eth0/send_redirects'.
    The interface part is kept whole, since interface names can themselves contain dots."""
    prefix = "net.ipv4.conf."
    if key.startswith(prefix):
        iface, leaf = key[len(prefix):].rsplit(".", 1)
        return os.path.join("/proc/sys/net/ipv4/conf", iface, leaf)
    return os.path.join("/proc/sys", *key.split("."))


def sysctl_get(key):
    """Read one kernel setting as text, or '' if it cannot be read. Read straight from
    /proc/sys, so it works in a slim container that has no 'sysctl' tool."""
    try:
        with open(_proc_path(key)) as f:
            return f.read().strip()
    except OSError:
        return ""


def sysctl_set(key, value):
    """Change one kernel setting. True if it worked. A container usually may not change
    these; callers read the setting back to find out (see Enforcer._routing_ready)."""
    try:
        with open(_proc_path(key), "w") as f:
            f.write(str(value))
        return True
    except OSError:
        return False


def ipt(tool, args):
    """Run one iptables command, waiting up to 5 seconds if another program holds the
    firewall lock (Docker and ufw often do). True if it worked."""
    try:
        return subprocess.run([tool, "-w", "5"] + args, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ---------------------------------------------------------------- the enforcer

class Enforcer:
    """Applies a live plan to the network. Give it a plan() callback that returns
    {victim_ip: {"off": bool, "ips": set(), "mac": optional hardware address}} and a neighbours()
    callback that returns {ip: mac}. Call start() once; it does nothing until plan() is non-empty."""

    def __init__(self, local_ip, plan, neighbours, log=print, data_dir=None, learn_mac=None, dns_port=None):
        """Work out this machine's network (interface, router, own hardware address) and which
        firewall tool is installed. Touches nothing on the network; start() does that.

        data_dir: where to keep notes of what was changed, so a crash can be undone at the next
        start (None keeps no notes). learn_mac(ip, mac): told the hardware address of a chosen
        device the first time it is seen, if the plan didn't already say. dns_port: the port QuietNet
        answers lookups on; a steered device's lookups sent to another server are redirected there
        (None: no redirect)."""
        self.local_ip = local_ip
        self.dns_port = dns_port
        self.plan = plan
        self.neighbours = neighbours
        self.log = log
        self.learn_mac = learn_mac
        self.state_path = os.path.join(data_dir, "enforcer_state.json") if data_dir else None
        self.iface, self.gateway_ip = interface_and_gateway()
        self.subnet = local_subnet(self.iface) if self.iface else None
        self.our_mac = mac_of_interface(self.iface) if self.iface else None
        self.backend = "nft" if shutil.which("nft") else ("iptables" if shutil.which("iptables") else None)
        self.reason = self._why_unavailable()
        self.problem = ""             # why steering is paused right now, shown on the device page
        self._sock = None
        self._saved_sysctls = {}      # setting -> original value, only for settings we changed
        self._spoofed = {}            # device address -> the hardware address we steered
        self._applied = ""            # last firewall text we pushed, to avoid needless reloads
        self._ipt_loaded = False      # iptables only: our chain may hold drop rules that must be cleared
        self._fw_checked, self._fw_blocker = 0.0, ""
        self._fw_fix = None     # what another firewall blocks and the commands that fix it (see firewall_fix)
        self.device_problems = {}     # device address -> a problem with that device alone
        self._pending = {}            # device address -> (hardware address, times answers are due)
        self._pending_lock = threading.Lock()
        self._sender = None
        self._active = False
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.RLock()
        self._thread = None

    # -- availability -------------------------------------------------------

    def _why_unavailable(self):
        """A plain-English reason the enforcer cannot run here, or '' if it can.
        Shown on the dashboard, so keep the wording friendly."""
        if not IS_LINUX or AF_PACKET is None:
            return "The enforcer runs on Linux (your Raspberry Pi). On this computer it's off; blocks still apply to new connections."
        if os.geteuid() != 0:
            return "Run QuietNet with admin rights (or the container's NET_RAW/NET_ADMIN) to cut live connections."
        if not self.iface or not self.gateway_ip or not self.our_mac:
            return "Couldn't work out this machine's network, so live-connection enforcing is off."
        if not self.backend:
            return "No firewall tool (nft or iptables) found, so live-connection enforcing is off."
        return ""

    def available(self):
        """Can the enforcer run on this machine at all?"""
        return not self.reason

    def can_target(self, ip):
        """'' if this device may be steered, otherwise a plain-English reason why not."""
        return target_problem(ip, self.subnet, self.gateway_ip, self.local_ip)

    def status(self):
        """What the dashboard needs to know: available, why not, any problem stopping all steering,
        problems with particular devices, active, tool and router, and whether a steered device's
        lookups sent to another DNS server are redirected to QuietNet ("dns_redirect"; only the
        nft tool does this, see iptables_rules)."""
        return {"available": self.available(), "reason": self.reason, "problem": self.problem,
                "problems": dict(self.device_problems), "active": self._active,
                "backend": self.backend, "gateway": self.gateway_ip,
                "dns_redirect": self.backend == "nft" and self.dns_port is not None,
                "firewall": self.firewall_fix()}

    def firewall_fix(self):
        """When another firewall on this machine is what stops all steering right now: which firewall
        rules are in the way ("blocked_by"), the commands that let passed-on traffic through
        ("commands"), and whether the installer can make the fix last after a restart ("installer":
        true when one of the commands is for Docker's DOCKER-USER chain, which the installer's
        quietnet-forward service keeps). None when no firewall is in the way, so the dashboard can
        show this on its home page as well as on a device's page."""
        fix = self._fw_fix
        if not fix or not self.problem or self.problem != self._fw_blocker:
            return None
        return {"blocked_by": list(fix["blocked_by"]), "commands": list(fix["commands"]),
                "installer": fix["installer"]}

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        """Start the background thread, if the enforcer can run here. Call once.

        If it can't run, it still tidies up anything a crashed earlier run left behind, and if
        the reason is only that the network isn't up yet (common at boot), it keeps looking."""
        if not self.available():
            self.log("Enforcer off: " + self.reason)
            if IS_LINUX:
                self._recover_without_steering()
                if self.iface is None or self.gateway_ip is None:
                    threading.Thread(target=self._wait_for_network, daemon=True).start()
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _wait_for_network(self):
        """Look for the network every 15 seconds, and start the enforcer once it's found."""
        while not self._stop.wait(15):
            self.iface, self.gateway_ip = interface_and_gateway()
            self.subnet = local_subnet(self.iface) if self.iface else None
            self.our_mac = mac_of_interface(self.iface) if self.iface else None
            self.reason = self._why_unavailable()
            if self.available():
                self.log("Network found; enforcer starting.")
                self._thread = threading.Thread(target=self._run, daemon=True)
                self._thread.start()
                return

    def _open_socket(self):
        """Open the raw socket used to send and hear ARP frames. Needs admin rights or NET_RAW."""
        s = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_ARP))
        s.bind((self.iface, ETH_ARP))
        return s

    def _run(self):
        """The background thread: undo any leftovers, tick every 2 seconds until asked to stop,
        then clean up. A tick that fails is reported and the next one tries again."""
        try:
            self._sock = self._open_socket()
            self._recover()
            threading.Thread(target=self._answer_questions, daemon=True).start()
            self.log("Enforcer ready on %s (gateway %s) via %s." % (self.iface, self.gateway_ip, self.backend))
            while True:
                self._wake.wait(2)                # every 2 seconds, or at once when poked
                self._wake.clear()
                if self._stop.is_set():
                    break
                try:
                    self._tick()
                except Exception as e:
                    self.log("Enforcer tick problem: %s" % e)
        except Exception as e:
            self.log("Enforcer stopped unexpectedly: %s" % e)
        finally:
            self._teardown()

    # -- notes on disk, so a crash can be undone -------------------------------

    def _save_state(self):
        """Write down which devices are steered and which settings we changed (or remove the
        notes when there is nothing to undo)."""
        if not self.state_path:
            return
        try:
            if self._saved_sysctls or self._spoofed:
                with open(self.state_path, "w") as f:
                    json.dump({"sysctls": self._saved_sysctls, "spoofed": self._spoofed}, f)
            elif os.path.exists(self.state_path):
                os.remove(self.state_path)
        except OSError as e:
            self.log("Could not save the enforcer's notes: %s" % e)

    def _read_state(self):
        """The notes left by an earlier run, or None if there are none."""
        if not self.state_path:
            return None
        try:
            with open(self.state_path) as f:
                old = json.load(f)
            return old if isinstance(old, dict) else None
        except (OSError, ValueError):
            return None

    def _recover(self):
        """At start-up: if the last run didn't get to clean up, clean up now.

        The leftovers are adopted as our own: the devices count as steered and the settings as
        changed by us. Each tick then hands back every device that isn't in the plan (retrying
        until it works) and puts the settings back once nobody is steered."""
        self._remove_firewall()
        old = self._read_state()
        if old is None:
            return
        self._spoofed = {ip: mac for ip, mac in (old.get("spoofed") or {}).items() if isinstance(mac, str)}
        self._saved_sysctls = {k: v for k, v in (old.get("sysctls") or {}).items() if isinstance(v, str) and v}
        if self._spoofed:
            self.log("Handing %d device(s) back to the router after an unclean stop." % len(self._spoofed))
            if self._heal(dict(self._spoofed), rounds=5):
                self._spoofed = {}
        if not self._spoofed:
            self._restore_routing()

    def _recover_without_steering(self):
        """The enforcer can't run, but an earlier run may have left things behind: undo what we can.
        Without the network we can't hand devices back, so if any were steered we leave forwarding
        on (they keep their internet until they re-learn the router) and keep the notes."""
        old = self._read_state()
        if old is None:
            return
        self._remove_firewall()
        if not old.get("spoofed"):
            for key, value in (old.get("sysctls") or {}).items():
                if isinstance(value, str) and value:
                    sysctl_set(key, value)
            try:
                os.remove(self.state_path)
            except OSError:
                pass

    # -- routing ------------------------------------------------------------

    def _routing_ready(self):
        """Make this machine forward packets and stop it sending 'redirect' hints (remembering the
        old settings), then check it really took. Returns '' when it's safe to steer, otherwise a
        plain-English reason it isn't - steering without forwarding would cut the device off."""
        changed = False
        for key, value in (("net.ipv4.ip_forward", "1"),
                           ("net.ipv4.conf.all.send_redirects", "0"),
                           ("net.ipv4.conf.%s.send_redirects" % self.iface, "0")):
            current = sysctl_get(key)
            if current not in ("", value):
                self._saved_sysctls.setdefault(key, current)
                sysctl_set(key, value)
                changed = True
        if changed:
            self._save_state()
        if sysctl_get("net.ipv4.ip_forward") != "1":
            return ("This machine won't pass traffic on, so steering a device would cut it off. On the Pi, run: "
                    "echo net.ipv4.ip_forward=1 | sudo tee /etc/sysctl.d/90-quietnet.conf && sudo sysctl --system")
        return self._forward_blocker()

    def _forward_blocker(self):
        """Why another firewall stops us passing traffic on, in plain English with the command that
        fixes it, or ''. Asked of every firewall tool present, because rules can live where one
        tool can't see them (rules made with iptables-legacy are invisible to nft). Every blocker
        found is named, with its own command, so one fix doesn't just uncover the next.

        It fails closed: if a tool that is present can't be asked, that counts as a blocker, since
        steering into a firewall we couldn't see may cut the device off. A clean answer is
        remembered for 30 seconds; a failure is asked again next tick."""
        now = time.time()
        if now - self._fw_checked < 30:
            return self._fw_blocker
        tools = [t for t in ("nft", "iptables", "iptables-legacy") if t == self.backend or shutil.which(t)]
        names, fixes = [], []
        for tool in tools:
            args = ["nft", "list", "ruleset"] if tool == "nft" else [tool, "-w", "5", "-S"]
            try:
                p = subprocess.run(args, capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                p = None
            if p is not None and p.returncode != 0 and tool == "iptables-legacy" and \
                    re.search(r"does not exist|insmod", p.stderr or ""):
                continue                     # the old firewall isn't loaded at all, so it holds no rules
            if p is None or p.returncode != 0:
                self._fw_fix = None
                return ("QuietNet couldn't read this machine's firewall rules with %s, so it won't steer a device "
                        "in case they would cut it off. Check that 'sudo %s' works on the Pi."
                        % (tool, " ".join(a for a in args if a not in ("-w", "5"))))
            if tool == "nft":
                for family, table, chain, docker in forward_blockers(p.stdout or "", self.iface):
                    names.append(("Docker's table '%s'" if docker else "table '%s'") % table)
                    fixes.append(nft_advice(family, table, chain, docker, self.iface))
            elif iptables_forward_drop(p.stdout or "", self.iface):
                names.append("%s's forwarding rules" % tool)
                fixes.append(iptables_advice(tool, p.stdout or "", self.iface))
        message, self._fw_fix = "", None
        if names:
            unique = []
            for fix in fixes:                # nft and iptables can both see the same rules
                if fix not in unique:
                    unique.append(fix)
            message = ("Another firewall on this machine (%s) blocks passed-on traffic, so steering a device "
                       "would cut it off. %sTo allow it, run on the Pi: %s"
                       % (", ".join(names), lasting_note(unique), " && ".join(unique)))
            self._fw_fix = {"blocked_by": names, "commands": unique,
                            "installer": any(" DOCKER-USER " in fix for fix in unique)}
        self._fw_checked, self._fw_blocker = now, message
        return message

    def _restore_routing(self):
        """Put back the kernel settings we changed, and clear the notes."""
        for key, value in self._saved_sysctls.items():
            if value != "":
                sysctl_set(key, value)
        self._saved_sysctls = {}
        self._save_state()

    # -- each tick ----------------------------------------------------------

    def _tick(self):
        """One pass: hand back devices that left the plan, check it's safe to steer, load the
        firewall rules, steer the chosen devices. This computer, the router and anything off the
        home network are never included. Routing is switched on when the first device is chosen
        and restored when the last is handed back."""
        plan = {ip: r for ip, r in (self.plan() or {}).items() if not self.can_target(ip)}
        with self._lock:
            hosts = self.neighbours()
            gone = {ip: mac for ip, mac in self._spoofed.items() if ip not in plan or hosts.get(ip, mac) != mac}
            if gone and self._heal(gone, rounds=3):
                for ip in gone:
                    self._spoofed.pop(ip, None)
                self._save_state()
            # (If the hand-back couldn't be sent, they stay listed and we try again next tick,
            # keeping forwarding on meanwhile so they still have internet.)

            if not plan:
                self._apply_firewall({})
                if self._saved_sysctls and not self._spoofed:
                    self._restore_routing()
                self.problem, self.device_problems, self._active = "", {}, False
                return

            self.problem = self._routing_ready()
            if self.problem:
                self.device_problems = {}
                if self._spoofed and self._heal(dict(self._spoofed), rounds=3):
                    self._spoofed = {}
                    self._save_state()
                self._apply_firewall({})
                self._active = False
                return
            self._apply_firewall(plan)
            self.device_problems = self._spoof(plan, hosts)
            self._active = bool(self._spoofed)

    def _spoof(self, plan, hosts):
        """Send each chosen device an ARP message saying the router's address is at our hardware
        address, so it sends its outgoing traffic to us. Repeated every tick: devices forget.
        Returns {device address: problem} for devices it had to leave alone."""
        problems = {}
        for victim, rule in plan.items():
            mac = hosts.get(victim)
            if not mac:
                continue                      # haven't seen this device's hardware address yet
            if rule.get("mac") and rule["mac"] != mac:
                problems[victim] = ("A different device is now using %s, so it isn't being steered. Switch 'Cut "
                                    "live connections' off and on again on the device you mean." % victim)
                continue
            if not rule.get("mac") and self.learn_mac:
                self.learn_mac(victim, mac)   # remember which device this is from now on
            try:
                self._sock.send(build_arp_reply(self.gateway_ip, self.our_mac, victim, mac))
            except OSError as e:
                self.log("Could not steer %s: %s" % (victim, e))
                continue
            if self._spoofed.get(victim) != mac:
                self._spoofed[victim] = mac
                self._save_state()
        return problems

    def _answer_questions(self):
        """Listen for a steered device asking "who is the router?" and answer at once - and again
        after the real router has had its say. A device believes the most recent answer, but Linux
        ignores a second answer for about a second after the first, so the later answers are what
        stop it slipping back to the real router for a moment after every question. The same is
        done when the router is heard asking about a steered device, because the device learns the
        router's real address from that question too."""
        sock = self._sock
        try:
            sock.settimeout(1)
        except (OSError, AttributeError):
            return
        while not self._stop.is_set():
            try:
                frame = sock.recv(128)
            except socket.timeout:
                continue
            except OSError:
                return                        # socket closed: we're stopping
            q = parse_arp_request(frame)
            if not q:
                continue
            asker_ip, asker_mac, wanted = q
            if wanted == self.gateway_ip:
                # A steered device asking who the router is.
                with self._lock:
                    steered = self._spoofed.get(asker_ip) == asker_mac
                if steered:
                    self._schedule_answers(asker_ip, asker_mac)
            elif asker_ip == self.gateway_ip:
                # The router asking about a steered device. A device that hears this learns the
                # router's real hardware address from it, so steer it again once Linux will listen.
                with self._lock:
                    mac = self._spoofed.get(wanted)
                if mac:
                    self._schedule_answers(wanted, mac)

    ANSWER_AT = (0, 0.05, 0.3, 1.02, 1.1, 1.6)     # seconds after a question; see _answer_questions

    def _schedule_answers(self, ip, mac):
        """Plan the answers to one device's question. A device that asks again before its answers
        have all gone out just has its plan restarted - so a flood of (possibly forged) questions
        never costs more than one entry per steered device, and one sending thread in all."""
        now = time.monotonic()
        with self._pending_lock:
            self._pending[ip] = (mac, [now + d for d in self.ANSWER_AT])
            if self._sender is None or not self._sender.is_alive():
                self._sender = threading.Thread(target=self._send_answers, daemon=True)
                self._sender.start()

    def _send_answers(self):
        """The one sending thread: every 50 ms, send whatever planned answers are due. Ends when
        nothing is left to send (it is started again when a question arrives)."""
        while not self._stop.is_set():
            now, due = time.monotonic(), []
            with self._pending_lock:
                for ip, (mac, times) in list(self._pending.items()):
                    if times and times[0] <= now:
                        due.append((ip, mac))
                        times.pop(0)
                    if not times:
                        del self._pending[ip]
                if not due and not self._pending:
                    self._sender = None
                    return
            for ip, mac in due:
                self._resteer(ip, mac, build_arp_reply(self.gateway_ip, self.our_mac, ip, mac))
            time.sleep(0.05)

    def _resteer(self, ip, mac, reply):
        """Send one prepared 'the router is me' answer, unless the device was handed back meanwhile."""
        with self._lock:
            if self._spoofed.get(ip) != mac or self._sock is None:
                return
            try:
                self._sock.send(reply)
            except OSError:
                pass

    def _heal(self, victims, rounds):
        """Tell each device the router's real hardware address again, a few times in case one
        message is lost. Returns False if it couldn't, because the router's hardware address isn't
        known yet; callers keep the devices listed and try again later."""
        gw_mac = self.neighbours().get(self.gateway_ip)
        if not (self._sock and gw_mac and self.our_mac):
            self.log("Couldn't hand %d device(s) back to the router yet (its hardware address isn't known); "
                     "will keep trying." % len(victims))
            return False
        for i in range(rounds):
            for victim, mac in victims.items():
                try:
                    self._sock.send(build_arp_reply(self.gateway_ip, gw_mac, victim, mac, eth_src=self.our_mac))
                except (OSError, ValueError):
                    pass
            if i < rounds - 1:
                time.sleep(0.3)
        return True

    def _apply_firewall(self, plan):
        """Load the drop rules for the plan, but only if they differ from what is already
        loaded. With nft the whole table is replaced in one step (see nft_ruleset), so there is never
        a half-applied state and no rule outlives the plan that asked for it. With iptables, the
        chain and the jump to it are checked every time (something else may have flushed them), and
        the rules count as loaded only if every command worked. While nothing is enforced and no
        rules are left to clear, iptables isn't run at all: each call takes the firewall lock that
        Docker and ufw also need, and the empty plan is asked for every two seconds."""
        if self.backend == "nft":
            text = nft_ruleset(plan, self.local_ip, self.dns_port)
            if text != self._applied:
                p = subprocess.run(["nft", "-f", "-"], input=text, text=True, capture_output=True)
                if p.returncode:
                    self.log("nft load failed: %s" % p.stderr.strip())
                else:
                    self._applied = text
        elif self.backend == "iptables":
            if not plan and not self._ipt_loaded:
                return
            if plan:
                self._ipt_loaded = True
            # If the chain had to be made, or the jump put back, or the chain no longer holds the
            # rules we loaded, something else has flushed the firewall: load the rules again.
            created = ipt("iptables", ["-N", "QUIETNET"])
            had_jump = ipt("iptables", ["-C", "FORWARD", "-j", "QUIETNET"])
            jump_ok = had_jump or ipt("iptables", ["-I", "FORWARD", "-j", "QUIETNET"])
            cmds = iptables_rules(plan, self.local_ip)
            key = repr(cmds)
            if created or not had_jump or self._chain_rule_count() not in (None, len(cmds) - 1):
                self._applied = ""
            if key != self._applied or not jump_ok:
                ok = jump_ok and all([ipt("iptables", args) for args in cmds])
                self._applied = key if ok else ""
                if not ok:
                    self.log("iptables update failed; will try again.")
            if not plan and self._applied == key:
                self._ipt_loaded = False          # emptied: nothing more to clear until a plan returns

    def _chain_rule_count(self):
        """How many rules QuietNet's iptables chain holds right now, or None if that can't be told."""
        try:
            p = subprocess.run(["iptables", "-w", "5", "-S", "QUIETNET"], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return None
        if p.returncode != 0 or not (p.stdout or "").strip():
            return None
        return sum(1 for line in p.stdout.splitlines() if line.startswith("-A QUIETNET"))

    def _remove_firewall(self):
        """Remove our firewall table (nft) or chain (iptables). Harmless if it isn't there. With nft
        this one command removes every chain in the table: the drops and the DNS redirect alike."""
        if self.backend == "nft":
            subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True)
        elif self.backend == "iptables":
            ipt("iptables", ["-D", "FORWARD", "-j", "QUIETNET"])
            ipt("iptables", ["-F", "QUIETNET"])
            ipt("iptables", ["-X", "QUIETNET"])
            # If the chain is still there (another program held the lock, say), it may still hold
            # drop rules, so the next tick with nothing enforced must still empty it.
            # Only a definite "no such chain" (exit code 1) counts as gone: a busy lock or a
            # time-out says nothing, so the chain is treated as still loaded.
            try:
                p = subprocess.run(["iptables", "-w", "5", "-n", "-L", "QUIETNET"], capture_output=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                p = None
            self._ipt_loaded = not (p is not None and p.returncode == 1)
        self._applied = ""

    # -- stop and restore ---------------------------------------------------

    def stop(self, wait=15):
        """Ask the enforcer to stop, and wait (up to `wait` seconds) until it has handed every
        device back to the router and removed its firewall rules. Without the wait, the program
        could exit first and leave those behind."""
        self._stop.set()
        self._wake.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(wait)

    def poke(self):
        """Run the next tick now rather than waiting up to 2 seconds. Called when a rule changes,
        so the kill switch, a bedtime switched on by hand or a new block bites straight away."""
        self._wake.set()

    def _teardown(self):
        """Undo everything: tell every device the router's real hardware address (five times, in
        case a message is lost), remove the firewall rules, restore the kernel settings, close the
        socket. If devices couldn't be handed back, forwarding is left on and the notes kept, so
        they keep their internet and the next start finishes the job."""
        with self._lock:
            hosts = self.neighbours()
            victims = {ip: mac for ip, mac in hosts.items() if ip not in (self.local_ip, self.gateway_ip)}
            victims.update(self._spoofed)
            healed = not victims or self._heal(victims, rounds=5)
            self._remove_firewall()
            if healed or not self._spoofed:
                self._spoofed = {}
                self._restore_routing()
            else:
                self._save_state()
            if self._sock:
                self._sock.close()
                self._sock = None
            self._active = False
        self.log("Enforcer stopped; network restored." if healed or not self._spoofed
                 else "Enforcer stopped; devices will be handed back at the next start.")
