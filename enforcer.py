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
ETH_IPV6 = 0x86DD
IPPROTO_ICMPV6 = 58
ND_SOLICIT = 135           # neighbour solicitation: "who has this IPv6 address?"
ND_ADVERT = 136            # neighbour advertisement: "this IPv6 address is at this hardware address"
ND_HOP_LIMIT = 255         # neighbour-discovery messages must carry this; a lower one has passed a router
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


def _checked_mac(mac):
    """The hardware address as checked, lower-case text (aa:bb:cc:dd:ee:ff), or ValueError if it
    isn't one. Every hardware address that goes into a firewall rule passes through here first, so
    nothing a person or a device named can ever be read by the firewall as part of a rule."""
    return ":".join("%02x" % b for b in mac_to_bytes(mac))


# ---------------------------------------------- IPv6 neighbour discovery (taking IPv6 away: option c2)
#
# IPv6 has no ARP; devices find each other with "neighbour discovery", a kind of ICMPv6 message. To
# take IPv6 away from a steered device, the Pi claims the home router's link-local address belongs to
# the Pi, but only ever to that one device. The device then sends its IPv6 (its DNS included) to the
# Pi, which answers DNS with no IPv6 addresses (the device has "Cut live connections" on) and passes
# none of the rest on, so the device uses IPv4, where QuietNet already filters. These builders make
# the whole frames byte for byte so they can be checked against a real capture; nothing here opens a
# socket or touches the network.

def v6_bytes(address):
    """The sixteen raw bytes of an IPv6 address. Raises ValueError for anything that isn't one."""
    return ipaddress.IPv6Address(address).packed


def _checked_ipv6(text):
    """The address as checked text, or ValueError if it isn't a plain IPv6 address. Every IPv6
    address that goes into a firewall rule passes through here first. An address with a network
    card named after a '%' (fe80::1%wlan0) is refused: Python accepts any text at all after the
    '%' and hands it back unchanged, so it could be read by the firewall as part of a rule."""
    addr = ipaddress.IPv6Address(text)
    if getattr(addr, "scope_id", None):
        raise ValueError("not a plain IPv6 address: %r" % (text,))
    return str(addr)


def icmpv6_checksum(source, destination, body):
    """The ICMPv6 checksum for a message from `source` to `destination` (both IPv6 address text)
    carrying `body` (the ICMPv6 message, its checksum field left as zero).

    Unlike the checksum for IPv4's ICMP, this one folds the two addresses, the message length and the
    protocol number into the sum (a "pseudo-header"), so a message with the wrong source or
    destination is thrown away by the device. The sum itself is the usual one's-complement of the
    16-bit words."""
    pseudo = (v6_bytes(source) + v6_bytes(destination) + struct.pack(">I", len(body))
              + b"\x00\x00\x00" + bytes([IPPROTO_ICMPV6]))
    data = pseudo + body
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def neighbour_advertisement(claimed_ip, claimed_mac, target_ip, target_mac, eth_src=None,
                            router=True, solicited=True, override=True):
    """One IPv6 "neighbour advertisement" frame saying: `claimed_ip` is at `claimed_mac`, addressed
    to one device (`target_ip`, its link-local address, at `target_mac`, its hardware address).

    To take IPv6 away from a device, claimed_ip is the router's link-local address and claimed_mac is
    OURS, so the device sends its IPv6 to us. To hand it back, claimed_mac is the router's real
    hardware address. `eth_src` is the hardware address the frame physically comes from; it is always
    ours (a switch or Wi-Fi drops a frame that claims to come from another machine), and defaults to
    claimed_mac for callers that pass our own.

    The three flags are set on purpose: `router` says the claimed address is a router (we are standing
    in for it, so a device keeps sending it everything, DNS included), `solicited` answers a device's
    own reachability check, and `override` tells the device to believe this in place of what it had.
    The message carries the hop limit of 255 that a real one always has and a checksum that covers the
    addresses, so a device accepts it only on its own link."""
    eth_src = eth_src or claimed_mac
    flags = (0x80 if router else 0) | (0x40 if solicited else 0) | (0x20 if override else 0)
    body = bytes([ND_ADVERT, 0, 0, 0, flags, 0, 0, 0]) + v6_bytes(claimed_ip)
    body += bytes([2, 1]) + mac_to_bytes(claimed_mac)        # option 2: the target's link-layer address
    checksum = icmpv6_checksum(claimed_ip, target_ip, body)
    body = body[:2] + struct.pack(">H", checksum) + body[4:]
    ip6 = bytes([0x60, 0, 0, 0]) + struct.pack(">H", len(body)) + bytes([IPPROTO_ICMPV6, ND_HOP_LIMIT])
    ip6 += v6_bytes(claimed_ip) + v6_bytes(target_ip)
    eth = mac_to_bytes(target_mac) + mac_to_bytes(eth_src) + struct.pack(">H", ETH_IPV6)
    return eth + ip6 + body


def parse_neighbour_solicitation(frame):
    """If this Ethernet frame is an IPv6 "neighbour solicitation" ("who has this address?") carrying
    the hop limit of 255 that a real one always has, return (the asker's IPv6 address, the asker's
    hardware address, the IPv6 address it is asking about). Otherwise None.

    The asker's hardware address comes from the message's own source link-layer option where it gives
    one, and from the frame itself where it does not. A solicitation whose source is the unspecified
    address (::) is a device checking its own new address is free; it is never answered, so None is
    returned for it, lest the Pi tell a device its own address is taken."""
    if len(frame) < 78 or frame[12:14] != b"\x86\xdd":
        return None
    if frame[20] != IPPROTO_ICMPV6 or frame[21] != ND_HOP_LIMIT or frame[54] != ND_SOLICIT:
        return None
    source = ipaddress.IPv6Address(frame[22:38])
    if source.is_unspecified:
        return None
    target = ipaddress.IPv6Address(frame[62:78])
    asker_mac = frame[6:12].hex(":")
    at = 78
    while at + 8 <= len(frame):
        kind, units = frame[at], frame[at + 1]
        if units == 0:
            break
        if kind == 1:                                        # option 1: the sender's own hardware address
            asker_mac = frame[at + 2:at + 8].hex(":")
            break
        at += units * 8
    return str(source), asker_mac, str(target)


def solicited_node_multicast(address):
    """The "solicited-node" multicast address a device uses to ask who owns `address`: ff02::1:ffXX:XXXX
    built from that address's own last three bytes. Joining this group on the home network card is how
    the Pi hears those questions about the router's address."""
    low = ipaddress.IPv6Address(address).packed[13:16]
    return str(ipaddress.IPv6Address(b"\xff\x02" + bytes(9) + b"\x01\xff" + low))


def multicast_mac(multicast_ip):
    """The Ethernet hardware address an IPv6 multicast address maps to: 33:33 then its last four
    bytes. Used only to recognise frames, never as a destination for a claim."""
    low = ipaddress.IPv6Address(multicast_ip).packed[12:16]
    return "33:33:" + ":".join("%02x" % b for b in low)


def na_claim_problem(target_ip, target_mac, forbidden_macs):
    """Why a neighbour-advertisement claim must not be sent to this destination, in short, or '' if
    it is safe. The claim is only ever sent to one steered device's own link-local address and
    hardware address, so this refuses anything else: a destination address that is not a single
    device's link-local address (never the all-nodes group ff02::1, nor any other multicast or the
    unspecified address), or a destination hardware address that is missing, a group address, all
    zeros, or one of `forbidden_macs` (the router's, this computer's, a fixed or a shared one)."""
    try:
        addr = ipaddress.IPv6Address(str(target_ip).split("%", 1)[0])
    except (ValueError, AttributeError):
        return "not a valid IPv6 address"
    if not addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return "not a device's own link-local address"
    try:
        raw = mac_to_bytes(target_mac)
    except (ValueError, AttributeError):
        return "not a valid hardware address"
    if raw == bytes(6) or raw[0] & 1:                        # all zeros, or a group/multicast address
        return "not one device's own hardware address"
    if str(target_mac).lower() in {str(m).lower() for m in forbidden_macs if m}:
        return "the router, this computer, a fixed or a shared hardware address"
    return ""


def _plain_ipv6(text):
    """One IPv6 address in its usual short spelling, so the same address written two ways compares
    equal ('FE80:0::23' and 'fe80::23'). Text that is not an IPv6 address is handed back unchanged
    (na_claim_problem then refuses it); nothing at all gives ''."""
    text = str(text or "")
    try:
        return str(ipaddress.IPv6Address(text))
    except ValueError:
        return text


def _ip6_dns_rules(ipv6):
    """The ip6 lines for the firewall's "redirect DNS" chain, given the `ipv6` dict passed to
    nft_ruleset, or [] when there is nothing to redirect. The dict holds `target` (this computer's
    IPv6 address a lookup is sent to instead of the router), `port` (the port QuietNet answers on),
    `servers` (the router's IPv6 DNS addresses to catch) and `macs` (the hardware addresses of the
    steered devices; only traffic from these is touched). Every address, port and hardware address is
    checked, so a bad one raises ValueError rather than reach the firewall. The match is by hardware
    address because a device has many IPv6 addresses and gets new ones often.

    Only lookups addressed to the router's IPv6 DNS addresses are caught, as the design says. A lookup
    a steered device sends to any other IPv6 DNS server (one built into the device, or typed in by
    hand) is not matched: it is dropped with the rest of the device's IPv6 and gets no answer, while
    its IPv4 lookups are still answered. Known issue 101 records this."""
    target = _checked_ipv6(ipv6["target"])
    port = ipv6.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError("not a port number: %r" % (port,))
    servers = sorted(_checked_ipv6(s) for s in ipv6.get("servers", ()))
    macs = sorted(_checked_mac(m) for m in ipv6.get("macs", ()))
    if not (servers and macs):
        return []
    who = "{ %s }" % ", ".join(macs)
    where = "{ %s }" % ", ".join(servers)
    lines = ["  chain dns_redirect6 {",
             "    type nat hook prerouting priority -100; policy accept;"]
    for proto in ("udp", "tcp"):
        lines.append("    ether saddr %s ip6 daddr %s %s dport 53 dnat ip6 to [%s]:%d"
                     % (who, where, proto, target, port))
    lines.append("  }")
    return lines


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


def nft_ruleset(plan, our_ip, dns_port=None, ipv6=None):
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

    `ipv6`, when given (see _ip6_dns_rules), adds a second "redirect DNS" chain that sends a steered
    device's IPv6 lookups for the router's IPv6 address to QuietNet instead. It is independent of the
    IPv4 victims above: the IPv6 steering is done by neighbour discovery, not ARP, and matches devices
    by hardware address. Left None (the default) the output is exactly as it was before IPv6 steering,
    so nothing changes for a household that does not use it.

    Every address, port and hardware address is checked first; a bad one raises ValueError rather than
    reach the firewall."""
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
    if ipv6:
        lines += _ip6_dns_rules(ipv6)
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


# ---------------------------------------------------------------- taking IPv6 away

class IPv6Steerer:
    """Takes IPv6 away from chosen devices (design option c2), so their traffic uses IPv4, where
    QuietNet already filters and can cut it off. It claims the home router's link-local address
    belongs to this computer, but only ever to a steered device's own hardware and link-local
    addresses - never the all-nodes group, never the router, this computer, a fixed or a shared
    address. A steered device then sends its IPv6 (its DNS included) here; QuietNet answers DNS with
    no IPv6 addresses (the device has "Cut live connections" on) and passes none of the rest on.

    This needs no IPv6 forwarding and changes no lasting setting on this computer, so if QuietNet
    stops the devices fix themselves. The claim is re-sent every tick and whenever the device checks
    the router is reachable (handle_solicitation) or the router announces itself again, since any of
    those would otherwise let the device drift back. Which devices are steered is saved by hardware
    address, so a restart hands them back.

    One hardware address with more than one link-local address is never claimed. Each device has one
    such address, so two mean that several devices may share the hardware address (a Wi-Fi range
    extender QuietNet has not recognised, or a laptop passing a virtual machine through its Wi-Fi),
    and a claim to the wrong one would take IPv6 from a device the owner never chose. Every link-local
    address heard from a hardware address is kept for an hour (note_frame, HEARD_KEPT), and counted
    together with the one the plan gives and the one last claimed (steer).

    The Enforcer owns one of these and drives it; the sending is done through the Enforcer's own raw
    socket (`send`), and this class keeps no socket of its own except the one it listens on. Off
    unless the household turns it on: `set_target` is given `enabled` from a setting."""

    HEARD_KEPT = 3600            # seconds a link-local address heard from a hardware address is remembered
    HEARD_PER_DEVICE = 4         # how many are remembered for one hardware address (two already mean "leave alone")
    HEARD_DEVICES = 512          # how many hardware addresses anything is remembered for

    def __init__(self, iface, our_mac, send, log=print, save=None, fixed_macs=(), clock=time.monotonic):
        """Hold what is needed to build and send claims. `send(frame)` puts one whole Ethernet frame
        on the wire; `save()` is called when the saved set of steered devices changes; `fixed_macs`
        are hardware addresses a claim is never sent to (this computer's and the router's are added
        as they become known); `clock()` gives a steady time in seconds, by which heard addresses are
        aged (the tests hand in their own, so none of them waits)."""
        self.clock = clock
        self.iface = iface
        self.our_mac = our_mac
        self.send = send
        self.log = log
        self.save = save or (lambda: None)
        self.fixed_macs = set(fixed_macs)
        self.enabled = False
        self.hub = {}                 # {"v6": the router's link-local address, "mac": its hardware address}
        self.our_v6 = ""              # this computer's IPv6 address a redirected lookup is sent to
        self.port = None              # the port QuietNet answers lookups on (None: no DNS redirect)
        self.servers = []             # the router's IPv6 DNS addresses to catch
        self.shared = set()           # range-extender hardware addresses (never steered)
        self.redirect_ok = True       # set by the Enforcer: can the IPv6 DNS redirect be loaded (nft, no failed load)?
        self.devices = {}             # device IPv4 address -> {"mac": .., "ll": link-local address, "unclear": bool}
        self._steered = {}            # hardware address -> the link-local we last claimed the router at
        self._heard = {}              # hardware address -> {link-local address heard from it, or claimed: when (clock())}
        self._heard_lock = threading.Lock()   # the listener thread adds to _heard while the tick reads it
        self._last_hub = {}           # the router's link-local and hardware addresses our claims were made against
        self._problems = {}           # device IPv4 address -> why it is not being steered
        self._stop = None             # set while listen() runs, so delayed reachability answers can bow out

    def set_target(self, config):
        """Take in what to steer towards, worked out by the server (plan6). Stores it; sends nothing."""
        self.enabled = bool(config.get("enabled"))
        self.hub = config.get("hub") or {}
        self.our_v6 = config.get("our_v6") or ""
        self.port = config.get("port")
        self.servers = list(config.get("servers") or ())
        self.shared = {str(m).lower() for m in (config.get("shared") or ()) if m}
        self.devices = config.get("devices") or {}

    def _forbidden(self):
        """The hardware addresses a claim must never be sent to: this computer's, the router's, any
        fixed one and every range extender's."""
        bad = set(self.fixed_macs)
        if self.our_mac:
            bad.add(self.our_mac)
        if self.hub.get("mac"):
            bad.add(self.hub["mac"])
        return {str(m).lower() for m in bad if m} | self.shared

    def ready(self):
        """Is everything in hand to send a claim safely AND answer the device's lookups: turned on,
        this computer's hardware and IPv6 addresses known, the router's link-local and hardware
        addresses known, a port to answer on, a router DNS address to catch, and the firewall able to
        load the redirect? A claim is withheld unless its lookups can be answered, so a steered
        device's lookups to the router's IPv6 DNS address are never left silent (design (c2): "DNS is
        answered"). A lookup it sends to any other IPv6 DNS server is not caught (see _ip6_dns_rules)."""
        return bool(self.enabled and self.our_mac and self.hub.get("v6") and self.hub.get("mac")
                    and self.our_v6 and self.port and self.servers and self.redirect_ok)

    def why_not_ready(self):
        """A plain-English reason nothing is being steered, or '' when it is on and ready. Shown on
        the dashboard so the owner can see why QuietNet is leaving devices' IPv6 alone."""
        if not self.enabled:
            return ""
        if not self.our_mac:
            return "QuietNet does not know this computer's hardware address yet, so it is leaving every device's IPv6 alone."
        if not (self.hub.get("v6") and self.hub.get("mac")):
            return "QuietNet has not heard the hub announce IPv6 yet, so it is leaving every device's IPv6 alone."
        if not self.our_v6:
            return "This computer has no lasting IPv6 address of its own to answer lookups from, so QuietNet is leaving every device's IPv6 alone."
        if not self.port:
            return "QuietNet is not listening for lookups over IPv6, so it is leaving every device's IPv6 alone."
        if not self.servers:
            return "QuietNet has not learned the hub's IPv6 DNS address to catch, so it is leaving every device's IPv6 alone."
        if not self.redirect_ok:
            return "The nft firewall tool is needed to answer these devices' IPv6 lookups (or its rules could not be loaded), so QuietNet is leaving every device's IPv6 alone."
        return ""

    def steer(self):
        """Send each chosen device a claim that the router's address is at this computer, and hand
        back any device that has left the plan. Returns {device IPv4 address: why not} for devices it
        had to leave alone. Safe to call every tick; devices forget, so it is meant to repeat.

        A device is claimed at one link-local address only when that is the only one known for its
        hardware address: the one the plan gives (from this computer's neighbour table), every one
        heard from it in the last hour (heard_addresses) and the one last claimed, taken together.
        With more than one it is left alone and said so, and if it was already claimed the address
        claimed is sent the correction, since the other address may be another device behind the same
        hardware address. So a claim never moves from one address to another: the old one is corrected
        first, and the new one is claimed only once the old one is no longer known."""
        self._problems = {}
        if not self.ready():
            self.release_all()
            return self._problems
        hub_ll, forbidden = self.hub["v6"], self._forbidden()
        new_hub = {"v6": self.hub["v6"], "mac": self.hub["mac"]}
        hub_changed = self._last_hub != new_hub
        self._last_hub = new_hub
        wanted = {}                       # hardware address -> the link-local we claim the router at
        chosen = set()                    # every chosen hardware address, address known or not
        for ip, dev in self.devices.items():
            mac = str(dev.get("mac", ""))
            if not mac:
                continue
            if dev.get("unclear"):
                self._problems[ip] = ("More than one device seems to share this device's hardware address "
                                      "(it may be behind a range extender), so QuietNet leaves its IPv6 alone.")
                continue
            if mac.lower() in self.shared:
                self._problems[ip] = "This device is behind a range extender, so QuietNet leaves its IPv6 alone."
                continue
            heard = self.heard_addresses(mac)
            planned = _plain_ipv6(dev.get("ll", ""))
            claimed = _plain_ipv6(self._steered.get(mac, ""))
            if len(set(heard) | {a for a in (planned, claimed) if a}) > 1:
                # Not in `chosen`, so a claim already made is corrected and forgotten below.
                self._problems[ip] = ("More than one device seems to share this device's hardware address "
                                      "(it may be behind a range extender), so QuietNet leaves its IPv6 alone.")
                continue
            chosen.add(mac)
            # The plan's address first; one heard on the wire only when the plan gave none; then the one
            # last claimed, so a chosen device whose neighbour-table entry drops out stays steered at its
            # last known address. All of them are the same address here, or there would be two.
            ll = planned or (heard[0] if heard else "") or claimed
            if not ll:
                self._problems[ip] = ("QuietNet has not yet learned this device's IPv6 link-local address, "
                                      "so its IPv6 is not taken away yet.")
                continue
            reason = na_claim_problem(ll, mac, forbidden)
            if reason:
                self._problems[ip] = "QuietNet is not taking this device's IPv6 away (%s)." % reason
                continue
            try:
                self.send(neighbour_advertisement(hub_ll, self.our_mac, ll, mac, eth_src=self.our_mac))
            except (OSError, ValueError) as e:
                self.log("Could not take IPv6 from %s: %s" % (ip, e))
                continue
            wanted[mac] = ll
            self._remember(mac, ll)       # a claimed address counts as known for an hour after its last claim
        changed = False
        for mac in list(self._steered):
            if mac not in chosen:         # no longer chosen (or now shared/unclear): hand it back
                self._correct(mac, self._steered[mac])
                del self._steered[mac]
                changed = True
        for mac, ll in wanted.items():
            if self._steered.get(mac) != ll:
                self._steered[mac] = ll
                changed = True
        if changed or (hub_changed and self._steered):
            self.save()
        return self._problems

    def _correct(self, mac, ll):
        """Tell one device the router's real hardware address again (override set), so it goes back to
        the router. Uses the router's live address when known, otherwise the one saved with the steered
        devices (so a restart can hand them back before the router is heard again). Returns False if
        neither is known, or this computer's hardware address isn't."""
        hub = self.hub if (self.hub.get("v6") and self.hub.get("mac")) else self._last_hub
        if not (hub.get("v6") and hub.get("mac") and self.our_mac):
            return False
        try:
            self.send(neighbour_advertisement(hub["v6"], hub["mac"], ll, mac,
                                              eth_src=self.our_mac, solicited=False, override=True))
            return True
        except (OSError, ValueError):
            return False

    def release_all(self, rounds=1):
        """Hand every steered device back to the router (a few times, in case a frame is lost) and
        forget them. Used when the setting goes off and when QuietNet stops; the correction is built
        from the router's live or saved addresses. The devices are forgotten even where neither is
        known (then they fix themselves once the Pi stops answering their checks)."""
        if not self._steered:
            return
        for _ in range(max(1, rounds)):
            for mac, ll in self._steered.items():
                self._correct(mac, ll)
        self._steered = {}
        self._last_hub = {}
        self.save()

    def _remember(self, mac, ll):
        """Note that this link-local address belongs to this hardware address as of now: heard from
        it on the wire, or just claimed. At most HEARD_PER_DEVICE are kept for one hardware address
        (the one noted longest ago makes way) and HEARD_DEVICES hardware addresses in all (the one
        that has gone longest without a note makes way)."""
        mac = str(mac).lower()
        with self._heard_lock:
            known = self._heard.pop(mac, {})          # put back last, so the dictionary stays in order of latest note
            known[ll] = self.clock()
            while len(known) > self.HEARD_PER_DEVICE:
                del known[min(known, key=known.get)]
            self._heard[mac] = known
            while len(self._heard) > self.HEARD_DEVICES:
                del self._heard[next(iter(self._heard))]

    def heard_addresses(self, mac, now=None):
        """The link-local addresses known for this hardware address from the last HEARD_KEPT seconds:
        those heard from it on the wire (note_frame) and any claimed (steer), most recently noted
        first. Older ones are forgotten here. More than one means several devices may share the
        hardware address, and steer() then leaves it alone."""
        mac = str(mac).lower()
        now = self.clock() if now is None else now
        with self._heard_lock:
            known = self._heard.get(mac)
            if not known:
                return []
            for ll in [a for a, when in known.items() if now - when >= self.HEARD_KEPT]:
                del known[ll]
            if not known:
                del self._heard[mac]
                return []
            return sorted(known, key=known.get, reverse=True)

    def note_frame(self, frame):
        """Learn a device's link-local IPv6 address from a frame heard on the wire, so a device that
        has never spoken IPv6 to the Pi can still be steered. The Ethernet source hardware address is
        matched with the IPv6 source address, and kept only when the source is a link-local address and
        the hardware address is one single device's (not a group, not all zeros) and not a forbidden
        one. Every such address is kept, with the time, for HEARD_KEPT seconds after it was last heard
        (heard_addresses): a second one from the same hardware address is the sign of several devices
        behind it, and steer() then leaves that hardware address alone. A forged pair can therefore
        only get a device left alone, or a claim sent to that frame's own hardware address, which a
        device ignores if the claimed address is not its own."""
        if len(frame) < 54 or frame[12:14] != b"\x86\xdd":
            return
        src_mac = frame[6:12].hex(":")
        try:
            src = ipaddress.IPv6Address(frame[22:38])
        except ValueError:
            return
        if not src.is_link_local or src.is_multicast:
            return
        raw = frame[6:12]
        if raw == bytes(6) or raw[0] & 1:
            return
        if src_mac.lower() in self._forbidden():
            return
        self._remember(src_mac, str(src))

    def handle_solicitation(self, frame):
        """Answer one device's check that the router is still reachable, for a device we are steering.
        A device asks "who has the router's address?" every 15 to 45 seconds; Linux will not answer for
        an address it does not own, so without this the device would go back to the real router. The
        reply is sent only to the device that asked, and only when it is one we steer and the question
        is about the router's address."""
        parsed = parse_neighbour_solicitation(frame)
        if not parsed or not self.ready():
            return
        asker_ip, asker_mac, wanted = parsed
        if wanted != self.hub.get("v6"):
            return
        ll = self._steered.get(asker_mac)
        if ll is None:                    # not a device we steer
            return
        # Answer to the device's own recorded link-local address, not the question's source: a device
        # resolving the router because of ordinary internet traffic asks from its public address, and a
        # reply there would be thrown away. Validating the recorded address keeps the never-sent-to-the-
        # wrong-address rule.
        if na_claim_problem(ll, asker_mac, self._forbidden()):
            return
        self._answer_check(asker_mac, ll)

    ANSWER_DELAYS = (0.05, 0.3, 1.0)      # seconds; extra answers so a re-send beats the real router's reply

    def _answer_check(self, mac, ll):
        """Send the reachability answer to one steered device at its recorded link-local address, now
        and (while the listener is running) a few more times, so the Pi's answer beats the router's."""
        self._send_advert(mac, ll)
        if self._stop is not None:
            for delay in self.ANSWER_DELAYS:
                t = threading.Timer(delay, self._repeat_check, (mac, ll))
                t.daemon = True
                t.start()

    def _repeat_check(self, mac, ll):
        """One of the delayed reachability answers, sent only if the Pi is still steering that device."""
        if self._stop is not None and not self._stop.is_set() and self._steered.get(mac) == ll:
            self._send_advert(mac, ll)

    def _send_advert(self, mac, ll):
        """Send one "the router's address is at this computer" advertisement to one device."""
        try:
            self.send(neighbour_advertisement(self.hub["v6"], self.our_mac, ll, mac, eth_src=self.our_mac))
        except (OSError, ValueError):
            pass

    def redirect_info(self):
        """What the firewall needs to send steered devices' IPv6 DNS lookups to QuietNet (for
        nft_ruleset's `ipv6`), or None when there is nothing to redirect: turned off, nobody steered,
        no lasting IPv6 address of our own to answer from, no port, or no router DNS address to catch."""
        if not (self.enabled and self._steered and self.our_v6 and self.port and self.servers):
            return None
        return {"target": self.our_v6, "port": self.port,
                "servers": list(self.servers), "macs": list(self._steered)}

    def state_dict(self):
        """Which devices are steered, by hardware address, for enforcer_state.json."""
        return dict(self._steered)

    def state_hub(self):
        """The router's link-local and hardware addresses our claims were made against, saved with the
        steered devices so a restart can send the correction before the router is heard again, or {}."""
        return dict(self._last_hub) if self._steered else {}

    def adopt(self, saved, hub=None):
        """Take on the steered devices an earlier run saved, so a restart can hand them back, together
        with the router's addresses those claims were made against. The saved router is accepted only
        when it is a valid link-local address and a single device's hardware address (nothing from the
        notes file reaches a frame unchecked); otherwise it is left empty, which gives the old
        behaviour (the devices are forgotten once a tick cannot correct them)."""
        if isinstance(saved, dict):
            self._steered = {m: l for m, l in saved.items() if isinstance(m, str) and isinstance(l, str)}
        if isinstance(hub, dict):
            v6, mac = hub.get("v6"), hub.get("mac")
            try:
                ok = (isinstance(v6, str) and ipaddress.IPv6Address(v6).is_link_local
                      and isinstance(mac, str) and mac_to_bytes(mac) != bytes(6)
                      and not (mac_to_bytes(mac)[0] & 1) and mac.lower() != str(self.our_mac).lower())
            except (ValueError, AttributeError):
                ok = False
            if ok:
                self._last_hub = {"v6": v6, "mac": mac}

    def active(self):
        """Is at least one device having its IPv6 taken away right now?"""
        return bool(self._steered)

    def status(self):
        """What the dashboard needs: whether it is turned on, how many devices are steered, whether
        the router's IPv6 address is known yet, why nothing is steered (while on), and per-device
        problems."""
        return {"enabled": self.enabled, "steered": len(self._steered),
                "hub_known": bool(self.hub.get("v6") and self.hub.get("mac")),
                "problem": self.why_not_ready(),
                "problems": dict(self._problems)}

    # -- hearing the devices' questions (not reached by the tests; needs a real network) ----

    def open_listener(self):
        """Open the sockets that hear devices' reachability checks: a packet socket that hands over the
        whole frames, and an IPv6 socket used only to join the multicast group those checks arrive on,
        so the network card passes them up. Linux only; returns (packet socket, join socket), either of
        which may be None when it can't be opened."""
        if AF_PACKET is None or not self.iface:
            return None, None
        try:
            pkt = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_IPV6))
            pkt.bind((self.iface, ETH_IPV6))
        except OSError:
            return None, None
        try:
            join = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        except OSError:
            join = None
        return pkt, join

    def _join(self, join_sock, group):
        """Join one multicast group on the home network card, so its frames are heard."""
        try:
            mreq = v6_bytes(group) + struct.pack("@I", socket.if_nametoindex(self.iface))
            join_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            return True
        except (OSError, ValueError):
            return False

    # Besides the hub's solicited-node group, listen on the groups phones send from their own
    # link-local address (mDNS and group-membership reports), so link-local addresses can be learned
    # even from a device that has never spoken IPv6 to the Pi. These joins vanish when the socket
    # closes, so there is still no lasting host setting.
    EXTRA_GROUPS = ("ff02::fb", "ff02::16")

    def listen(self, stop):
        """Background loop until `stop` is set. While the setting is off and nobody is steered it holds
        no sockets open and does nothing; once it is on (or devices are still being handed back) it
        opens the packet socket, joins the groups the questions arrive on, learns link-local addresses
        from the frames it hears and answers steered devices' reachability checks. Re-joins when the
        router's address changes. Best effort: if the sockets can't be opened it waits and tries again,
        and QuietNet carries on without it."""
        self._stop = stop
        pkt = join = None
        joined = None
        try:
            while not stop.is_set():
                want = self.enabled or self._steered
                if not want:
                    pkt, join, joined = self._close_listener(pkt, join)
                    stop.wait(1)
                    continue
                if pkt is None:
                    pkt, join = self.open_listener()
                    joined = None
                    if pkt is None:
                        stop.wait(1)
                        continue
                    try:
                        pkt.settimeout(1)
                    except (OSError, AttributeError):
                        pkt, join, joined = self._close_listener(pkt, join)
                        stop.wait(1)
                        continue
                groups = ([solicited_node_multicast(self.hub["v6"])] if self.hub.get("v6") else []) \
                    + list(self.EXTRA_GROUPS)
                if join is not None and groups != joined:
                    for group in groups:
                        self._join(join, group)
                    joined = groups
                try:
                    frame = pkt.recv(256)
                except socket.timeout:
                    continue
                except OSError:
                    pkt, join, joined = self._close_listener(pkt, join)
                    continue
                try:
                    self.note_frame(frame)
                    self.handle_solicitation(frame)
                except Exception as e:
                    self.log("IPv6 reachability answer problem: %s" % e)
        finally:
            self._close_listener(pkt, join)

    def _close_listener(self, pkt, join):
        """Close both listening sockets (leaving any multicast group) and report (None, None, None)."""
        for s in (pkt, join):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass
        return None, None, None


# ---------------------------------------------------------------- the enforcer

class Enforcer:
    """Applies a live plan to the network. Give it a plan() callback that returns
    {victim_ip: {"off": bool, "ips": set(), "mac": optional hardware address}} and a neighbours()
    callback that returns {ip: mac}. Call start() once; it does nothing until plan() is non-empty."""

    def __init__(self, local_ip, plan, neighbours, log=print, data_dir=None, learn_mac=None, dns_port=None,
                 plan6=None):
        """Work out this machine's network (interface, router, own hardware address) and which
        firewall tool is installed. Touches nothing on the network; start() does that.

        data_dir: where to keep notes of what was changed, so a crash can be undone at the next
        start (None keeps no notes). learn_mac(ip, mac): told the hardware address of a chosen
        device the first time it is seen, if the plan didn't already say. dns_port: the port QuietNet
        answers lookups on; a steered device's lookups sent to another server are redirected there
        (None: no redirect). plan6(): returns what IPv6 steering should do (see IPv6Steerer and the
        server's plan6); None leaves IPv6 steering out entirely."""
        self.local_ip = local_ip
        self.dns_port = dns_port
        self.plan = plan
        self.plan6 = plan6
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
        # IPv6 steering (option c2), off unless the household turns it on. It sends through this
        # enforcer's own raw socket and saves its state in the same notes file.
        self._v6 = IPv6Steerer(self.iface, self.our_mac, self._send_frame, log=log,
                               save=self._save_state) if plan6 else None
        self._v6_problems = {}
        self._v6_problem = ""          # a whole-feature IPv6 problem to show (forwarding on, nft missing)
        self._v6_load_failed = False   # the nft load with the ip6 chain was rejected, so stop claiming
        self._hosts = {}               # the neighbour table the last IPv4 tick read, reused by IPv6 steering

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
                "firewall": self.firewall_fix(), "ipv6_steering": self.ipv6_status()}

    def ipv6_status(self):
        """What the dashboard shows about taking IPv6 away (option c2): whether it is offered at all
        here (the nft tool is needed), turned on, how many devices are steered, whether the router's
        IPv6 address is known yet, why nothing is steered, and any per-device problems. When the nft
        tool is missing (or the enforcer has no IPv6 steering) nothing can be answered, so it reports
        only {"offered": False}. See IPv6Steerer.status."""
        if self._v6 is None or self.backend != "nft":
            return {"offered": False}
        info = self._v6.status()
        info["offered"] = True
        info["problem"] = self._v6_problem or info.get("problem", "")
        info["problems"] = dict(info.get("problems") or {}, **self._v6_problems)
        return info

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

    def _send_frame(self, frame):
        """Put one whole Ethernet frame on the wire through the raw socket (used by IPv6 steering).
        The socket's bound protocol only filters what is received, so an IPv6 frame sends fine on it."""
        if self._sock is not None:
            self._sock.send(frame)

    def _run(self):
        """The background thread: undo any leftovers, tick every 2 seconds until asked to stop,
        then clean up. A tick that fails is reported and the next one tries again."""
        try:
            self._sock = self._open_socket()
            if self._v6:
                self._v6.iface, self._v6.our_mac = self.iface, self.our_mac
            self._recover()
            threading.Thread(target=self._answer_questions, daemon=True).start()
            if self._v6:
                threading.Thread(target=self._v6.listen, args=(self._stop,), daemon=True).start()
            self.log("Enforcer ready on %s (gateway %s) via %s." % (self.iface, self.gateway_ip, self.backend))
            while True:
                self._wake.wait(2)                # every 2 seconds, or at once when poked
                self._wake.clear()
                if self._stop.is_set():
                    break
                if self._v6:
                    try:
                        self._tick_v6()           # before _tick, so its DNS redirect loads this tick
                    except Exception as e:
                        self.log("IPv6 steering problem: %s" % e)
                try:
                    self._tick()
                except Exception as e:
                    self.log("Enforcer tick problem: %s" % e)
        except Exception as e:
            self.log("Enforcer stopped unexpectedly: %s" % e)
        finally:
            self._teardown()

    def _tick_v6(self):
        """One pass of IPv6 steering. Kept apart from _tick so a fault in one does not stop the other;
        the firewall's DNS redirect reads the result on the same tick (_apply_firewall). IPv6 follows
        IPv4 steering: only devices the enforcer is actually holding (self._spoofed) are claimed, so a
        device whose IPv4 steering is paused or not yet started is left alone and handed back. Nothing
        is claimed without the nft tool to answer the lookups, or while this computer is set to pass
        IPv6 on (then taking a device's IPv6 away would stop nothing)."""
        self._v6.iface, self._v6.our_mac = self.iface, self.our_mac
        self._v6.fixed_macs = {m for m in (self.our_mac, self.gateway_mac()) if m}
        config = dict(self.plan6() or {})
        if not config.get("enabled"):
            self._v6_load_failed = False          # switched off: a later load may try the ip6 chain again
        self._v6_problem = ""
        # Only claim devices IPv4 steering actually holds, matched by hardware address.
        with self._lock:
            held = {ip: str(mac).lower() for ip, mac in self._spoofed.items()}
        wanted = bool(config.get("enabled"))
        all_devices = config.get("devices") or {}
        devices = {ip: d for ip, d in all_devices.items()
                   if held.get(ip) == str(d.get("mac", "")).lower()}
        held_back = {ip: "QuietNet is not steering this device right now, so its IPv6 is left alone."
                     for ip in all_devices if ip not in devices}
        config["devices"] = devices
        if self.backend != "nft":
            config["enabled"] = False
            if wanted:
                self._v6_problem = ("Taking IPv6 away from steered devices needs the nft firewall tool, which is "
                                    "not installed here, so QuietNet is leaving every device's IPv6 alone.")
        elif sysctl_get("net.ipv6.conf.all.forwarding") == "1":
            config["enabled"] = False
            if wanted:
                self._v6_problem = ("This computer is set to pass IPv6 traffic on, so taking IPv6 away from a device "
                                    "would not stop anything. QuietNet is leaving devices' IPv6 alone. To use this, "
                                    "switch IPv6 forwarding off on the Pi.")
        self._v6.redirect_ok = (self.backend == "nft" and not self._v6_load_failed)
        self._v6.set_target(config)
        problems = self._v6.steer()
        if wanted and config.get("enabled"):
            problems = dict(held_back, **problems)
        self._v6_problems = problems

    def gateway_mac(self):
        """The router's hardware address, from the neighbour table the last IPv4 tick already read, or
        '' if not known yet. A claim is never sent to it (the router must not be told its own address is
        elsewhere). Reusing that table keeps the IPv6 tick from running its own `ip neigh`."""
        mac = self._hosts.get(self.gateway_ip, "")
        return mac or self.neighbours().get(self.gateway_ip, "")

    # -- notes on disk, so a crash can be undone -------------------------------

    def _save_state(self):
        """Write down which devices are steered and which settings we changed (or remove the
        notes when there is nothing to undo)."""
        if not self.state_path:
            return
        try:
            v6 = self._v6.state_dict() if self._v6 else {}
            if self._saved_sysctls or self._spoofed or v6:
                data = {"sysctls": self._saved_sysctls, "spoofed": self._spoofed}
                if v6:
                    data["v6_spoofed"] = v6
                    data["v6_hub"] = self._v6.state_hub()
                with open(self.state_path, "w") as f:
                    json.dump(data, f)
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
        if self._v6:
            # Adopt the IPv6-steered devices and the router's addresses saved with them, so the first
            # tick hands every saved device back with a correction built from the saved router address;
            # devices still chosen are claimed again once the router is next heard announcing.
            self._v6.adopt(old.get("v6_spoofed"), old.get("v6_hub"))
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
            self._hosts = hosts                   # reused by the IPv6 tick, so it runs no `ip neigh` of its own
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
            ipv6 = self._v6.redirect_info() if self._v6 else None
            text = nft_ruleset(plan, self.local_ip, self.dns_port, ipv6=ipv6)
            if text != self._applied:
                p = subprocess.run(["nft", "-f", "-"], input=text, text=True, capture_output=True)
                if p.returncode and ipv6 is not None:
                    # The load with the ip6 DNS redirect was rejected. Fall back to the rules without it,
                    # so the IPv4 rules still land, and stop IPv6 claiming (the next IPv6 tick hands the
                    # devices back, since redirect_ok is then false). Without this the whole table would
                    # fail every tick and IPv4 rule changes would stop landing too.
                    self.log("nft load failed with the IPv6 DNS redirect; loading without it: %s" % p.stderr.strip())
                    self._v6_load_failed = True
                    text = nft_ruleset(plan, self.local_ip, self.dns_port, ipv6=None)
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
            if self._v6:
                # Hand IPv6-steered devices back first (the correction with the router's real hardware
                # address), within the stop wait. Those not corrected fix themselves once we stop
                # answering their checks. A fault here must not stop the IPv4 clean-up below.
                try:
                    self._v6.set_target(self.plan6() or {})
                    self._v6.release_all(rounds=3)
                except Exception as e:
                    self.log("IPv6 steering clean-up problem: %s" % e)
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
