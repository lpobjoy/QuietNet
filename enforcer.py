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

This needs a Linux machine (a Raspberry Pi is the intended home) and the right
to use the network directly (run as root, or the container's NET_RAW/NET_ADMIN).
On anything else it reports itself unavailable and does nothing. It only ever
targets devices you explicitly choose, and it restores everything cleanly when
it stops. It uses only the Python standard library plus the system's own
firewall command (nft or iptables), nothing downloaded.
"""
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


# ---------------------------------------------------------------- pure helpers

def mac_to_bytes(mac):
    """'aa:bb:cc:dd:ee:ff' -> the six raw bytes. Raises ValueError for anything else."""
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError("not a hardware address: %r" % mac)
    return bytes(int(p, 16) for p in parts)


def build_arp_reply(sender_ip, sender_mac, target_ip, target_mac):
    """One ARP 'reply' frame saying: sender_ip is at sender_mac. Addressed to target.

    To make a device route through us, we send it a reply where sender_ip is the
    router's address and sender_mac is OURS. To heal it afterwards, we send the
    same but with the router's real hardware address."""
    eth = mac_to_bytes(target_mac) + mac_to_bytes(sender_mac) + struct.pack(">H", ETH_ARP)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2)        # ethernet, IPv4, reply
    arp += mac_to_bytes(sender_mac) + socket.inet_aton(sender_ip)
    arp += mac_to_bytes(target_mac) + socket.inet_aton(target_ip)
    return eth + arp


def nft_ruleset(plan, our_ip):
    """The complete nftables program for the current plan.

    plan: {victim_ip: {"off": bool, "ips": [blocked ip, ...]}}
    'off' means cut everything for that device (except reaching QuietNet itself);
    otherwise only the listed addresses are dropped."""
    # Loading a table that already exists ADDS to it; it does not replace it. Without the first
    # two lines, a rule dropped from the plan would stay in the kernel - a device whose internet
    # was switched back on would stay cut off until QuietNet restarted. "Declare, delete, define"
    # is the standard way to replace a table: the first line makes sure there is something to
    # delete (so the delete cannot fail), and nft applies the whole text as one step, so there is
    # no moment with half the rules loaded.
    lines = ["table inet quietnet", "delete table inet quietnet",
             "table inet quietnet {", "  chain forward {", "    type filter hook forward priority -150; policy accept;"]
    for victim, rule in sorted(plan.items()):
        if rule.get("off"):
            lines.append("    ip saddr %s ip daddr != %s drop" % (victim, our_ip))
        elif rule.get("ips"):
            addrs = ", ".join(sorted(rule["ips"]))
            lines.append("    ip saddr %s ip daddr { %s } drop" % (victim, addrs))
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def iptables_rules(plan, our_ip):
    """The same plan expressed as iptables commands, for systems without nft."""
    cmds = [["-F", "QUIETNET"]]
    for victim, rule in sorted(plan.items()):
        if rule.get("off"):
            cmds.append(["-A", "QUIETNET", "-s", victim, "!", "-d", our_ip, "-j", "DROP"])
        else:
            for ip in sorted(rule.get("ips", [])):
                cmds.append(["-A", "QUIETNET", "-s", victim, "-d", ip, "-j", "DROP"])
    return cmds


# ---------------------------------------------------------------- system facts

def interface_and_gateway():
    """Return (interface, gateway_ip) from the Linux routing table, or (None, None)."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                c = line.split()
                if len(c) >= 3 and c[1] == "00000000":          # the default route
                    gw = socket.inet_ntoa(struct.pack("<I", int(c[2], 16)))
                    return c[0], gw
    except OSError:
        pass
    return None, None


def mac_of_interface(iface):
    """The hardware address of one of this machine's network interfaces, or None."""
    try:
        with open("/sys/class/net/%s/address" % iface) as f:
            return f.read().strip()
    except OSError:
        return None


def sysctl_get(key):
    """Read one kernel setting as text, or '' if it cannot be read."""
    try:
        return subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def sysctl_set(key, value):
    """Change one kernel setting. Failures are ignored; _why_unavailable has already
    checked for the admin rights this needs."""
    try:
        subprocess.run(["sysctl", "-w", "%s=%s" % (key, value)], capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


# ---------------------------------------------------------------- the enforcer

class Enforcer:
    """Applies a live plan to the network. Give it a plan() callback that returns
    {victim_ip: {"off": bool, "ips": set()}} and a neighbours() callback that
    returns {ip: mac}. Call start() once; it does nothing until plan() is non-empty."""

    def __init__(self, local_ip, plan, neighbours, log=print):
        """Work out this machine's network (interface, router, own hardware address) and which
        firewall tool is installed. Touches nothing on the network; start() does that."""
        self.local_ip = local_ip
        self.plan = plan
        self.neighbours = neighbours
        self.log = log
        self.iface, self.gateway_ip = interface_and_gateway()
        self.our_mac = mac_of_interface(self.iface) if self.iface else None
        self.backend = "nft" if shutil.which("nft") else ("iptables" if shutil.which("iptables") else None)
        self.reason = self._why_unavailable()
        self._sock = None
        self._saved_sysctls = {}
        self._applied = ""            # last firewall text we pushed, to avoid needless reloads
        self._active = False
        self._stop = threading.Event()
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

    def status(self):
        """What the dashboard needs to know: available, why not, active, tool and router."""
        return {"available": self.available(), "reason": self.reason, "active": self._active,
                "backend": self.backend, "gateway": self.gateway_ip}

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        """Start the background thread, if the enforcer can run here. Call once."""
        if not self.available():
            self.log("Enforcer off: " + self.reason)
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _open_socket(self):
        """Open the raw socket used to send ARP frames. Needs admin rights or NET_RAW."""
        s = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_ARP))
        s.bind((self.iface, ETH_ARP))
        return s

    def _turn_on_routing(self):
        """Remember the current kernel settings, then make this machine forward packets
        and stop it sending 'redirect' hints. Undone by _restore_routing."""
        for key in ("net.ipv4.ip_forward",
                    "net.ipv4.conf.all.send_redirects",
                    "net.ipv4.conf.%s.send_redirects" % self.iface):
            self._saved_sysctls[key] = sysctl_get(key)
        sysctl_set("net.ipv4.ip_forward", "1")                      # relay the traffic we don't drop
        sysctl_set("net.ipv4.conf.all.send_redirects", "0")        # don't teach devices to bypass us
        sysctl_set("net.ipv4.conf.%s.send_redirects" % self.iface, "0")

    def _restore_routing(self):
        """Put back the kernel settings saved by _turn_on_routing."""
        for key, value in self._saved_sysctls.items():
            if value != "":
                sysctl_set(key, value)
        self._saved_sysctls = {}

    def _run(self):
        """The background thread: prepare, tick every 2 seconds until asked to stop, then clean up.
        A tick that fails is reported and the next one tries again."""
        self._sock = self._open_socket()
        if self.backend == "iptables":
            subprocess.run(["iptables", "-N", "QUIETNET"], capture_output=True)
            subprocess.run(["iptables", "-C", "FORWARD", "-j", "QUIETNET"], capture_output=True).returncode \
                or subprocess.run(["iptables", "-I", "FORWARD", "-j", "QUIETNET"], capture_output=True)
        self.log("Enforcer ready on %s (gateway %s) via %s." % (self.iface, self.gateway_ip, self.backend))
        while not self._stop.wait(2):
            try:
                self._tick()
            except Exception as e:
                self.log("Enforcer tick problem: %s" % e)
        self._teardown()

    def _tick(self):
        """One pass: fetch the current plan, load the firewall rules, steer the chosen devices.
        This computer is never included. Routing is switched on when the first device is chosen and
        restored when the last is released."""
        plan = {ip: r for ip, r in (self.plan() or {}).items() if ip != self.local_ip}
        with self._lock:
            if plan and not self._saved_sysctls:
                self._turn_on_routing()
            self._apply_firewall(plan)
            self._spoof(plan)
            self._active = bool(plan)
            if not plan and self._saved_sysctls:
                self._restore_routing()

    def _spoof(self, plan):
        """Send each chosen device an ARP message saying the router's address is at our hardware
        address, so it sends its outgoing traffic to us. Repeated every tick: devices forget."""
        hosts = self.neighbours()
        for victim in plan:
            mac = hosts.get(victim)
            if not mac:
                continue                      # haven't seen this device's hardware address yet
            try:                              # tell the victim: the router is at our address
                self._sock.send(build_arp_reply(self.gateway_ip, self.our_mac, victim, mac))
            except OSError as e:
                self.log("Could not steer %s: %s" % (victim, e))

    def _apply_firewall(self, plan):
        """Load the drop rules for the plan, but only if they differ from what is already
        loaded. With nft the whole table is replaced in one step (see nft_ruleset), so there is never
        a half-applied state and no rule outlives the plan that asked for it."""
        if self.backend == "nft":
            text = nft_ruleset(plan, self.local_ip)
            if text != self._applied:
                p = subprocess.run(["nft", "-f", "-"], input=text, text=True, capture_output=True)
                if p.returncode:
                    self.log("nft load failed: %s" % p.stderr.strip())
                else:
                    self._applied = text
        elif self.backend == "iptables":
            cmds = iptables_rules(plan, self.local_ip)
            key = repr(cmds)
            if key != self._applied:
                for args in cmds:
                    subprocess.run(["iptables"] + args, capture_output=True)
                self._applied = key

    # -- stop and restore ---------------------------------------------------

    def stop(self, wait=15):
        """Ask the enforcer to stop, and wait (up to `wait` seconds) until it has handed every
        device back to the router and removed its firewall rules. Without the wait, the program
        could exit first and leave those behind."""
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(wait)

    def _teardown(self):
        """Undo everything: tell every device the router's real hardware address (five times, in
        case a message is lost), remove the firewall rules, restore the kernel settings, close the socket."""
        with self._lock:
            # Heal every device we steered: tell it the router's real address again, a few times.
            hosts = self.neighbours()
            gw_mac = hosts.get(self.gateway_ip)
            if self._sock and gw_mac:
                for _ in range(5):
                    for victim, mac in hosts.items():
                        if victim != self.local_ip and victim != self.gateway_ip:
                            try:
                                self._sock.send(build_arp_reply(self.gateway_ip, gw_mac, victim, mac))
                            except OSError:
                                pass
                    time.sleep(0.3)
            if self.backend == "nft":
                subprocess.run(["nft", "delete", "table", "inet", "quietnet"], capture_output=True)
            elif self.backend == "iptables":
                subprocess.run(["iptables", "-D", "FORWARD", "-j", "QUIETNET"], capture_output=True)
                subprocess.run(["iptables", "-F", "QUIETNET"], capture_output=True)
                subprocess.run(["iptables", "-X", "QUIETNET"], capture_output=True)
            self._restore_routing()
            if self._sock:
                self._sock.close()
                self._sock = None
            self._active = False
        self.log("Enforcer stopped; network restored.")
