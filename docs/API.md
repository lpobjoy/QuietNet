# API reference

QuietNet has two web interfaces: the dashboard API on the Pi, and the relay. The dashboard page (`static/index.html`) is the only intended caller of both. This reference is for anyone changing the code or writing tests.

See also: [How QuietNet works](ARCHITECTURE.md)

## Dashboard API (`server.py`)

Listens on `127.0.0.1:8377`.

**Rules for every request**

- The `Host` header must be `localhost` or `127.0.0.1` (a port is allowed). Anything else gets `403`.
- `POST` requests must have `Content-Type: application/json` (otherwise `415`) and a JSON body (unreadable JSON gets `400`).
- A change must be sent as exactly `application/json` (a `; charset=…` is fine), or it gets `415`. If the browser sends an `Origin`, it must be `http://localhost` or `http://127.0.0.1` on any port, or it gets `415`.
- A body larger than 64 KB gets `413`. A body that is JSON but not an object gets `400`.
- Every answer carries `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- Successful changes return `{"ok": true}` unless noted. Refusals with a message return `400` and `{"error": "…"}`. Refusals of badly formed input return a bare `400`.

A **scope** is `all`, `group:<id>` or, for one device, `dev:<number>` (the device's `id` in `/api/devices`). Names, groups and rules are held against the device, whatever address it has.

**Naming a device.** Every call about one device takes its number: as `dev:<number>` in a scope, or as `device` in a body. The older way still works, because an older dashboard page (which an older relay may still serve) sends it: `device:<ip>` in a scope, or `ip` in a body, means **the device listed under that address in `/api/devices` now**. A change sent that way for an address no device is known for yet goes to the device with the hardware address the neighbour table lists there (else the one the last scan found there), and failing both makes a device known only by that address (kind `addr`), with the rule held against that number. When both are sent, the number wins. A number QuietNet doesn't know is refused with `400` and `{"error": "QuietNet doesn't know that device."}`. (On an older database that has not been moved to the device tables yet, `devices.state` not `"ready"`, there are no device numbers: rules are kept under `device:<ip>` as they were, and a `dev:` scope is refused.)

### Reading

| Request | Returns |
| --- | --- |
| `GET /` | The dashboard page |
| `GET /api/status` | See below |
| `GET /api/devices` | List of devices, one entry per device, most recently active first. With `?all=1` it also lists devices that have no address of their own now (`"ip": ""`: see below) |
| `GET /api/activity?ip=<ip>&device=<number>&hours=<n>&since=<marker>` | What one device contacted, grouped by company. `device` is the device's number (`id` in `/api/devices`): the list is then the device's own history at every address it has had. Without it, or with a number QuietNet doesn't know, the list is what was recorded under the address `ip`, as before. `hours` defaults to 24, limited to 0.1–720. `since` is optional: see below |
| `GET /api/rules` | `{"blocked": [...], "allowed": [...]}`, each item `{"d", "ts", "owner"}` |
| `GET /api/services` | The service catalogue: `[{"id", "name", "cat"}]` |
| `GET /api/groups` | `[{"id", "name", "off", "members", "devices", "services"}]`. `devices` is the members' device numbers; `members` is the address each is listed under now (`""` for a member with no address of its own now), so its length is the number of members |
| `GET /api/schedules` | All schedules, each with `"active"` (in force right now). A schedule for one device also carries `"device"` (its number; `null` otherwise), and its `"scope"` is given as `device:<ip>` while the device has an address (the form an older page understands), else as `dev:<number>` |
| `GET /api/controls?scope=<scope>` | Switches for one scope, and what it inherits. `400` if the scope is badly formed. A device QuietNet doesn't know has nothing of its own: only what reaches every device is shown |
| `GET /api/cloud` | Remote access state: `{"configured", "paired", "relay", "name", "state", "detail"}` |
| `GET /api/enforcer` | `{"available", "reason", "problem", "problems", "active", "backend", "gateway", "dns_redirect", "firewall", "shared"}`. `firewall` is `null`, or, when another firewall on the Pi is what stops all steering, `{"blocked_by": [text, ...], "commands": [command, ...], "installer": true/false}`: the firewall rules in the way, the commands that let passed-on traffic through (each lasts until the Pi restarts), and whether running the install command again makes the fix permanent (only for Docker's firewall). The home page shows it; escape every part. `dns_redirect` is `true` when a steered device's ordinary DNS sent to another server is redirected to QuietNet (the `nft` tool only; with `iptables` it is `false`). `problem` says why all steering is paused right now (forwarding off, or another firewall in the way or impossible to check), or `""`. `problems` is `{device address: text}` for devices left alone, e.g. because a different device now has the address. `shared` is `{device address: {"count", "names"}}` for enforced devices with addresses left to the DNS block because a site the device is allowed shares them: `count` addresses, and up to five blocked services or names (`names`). Escape both before display |

`/api/status`:

```json
{
  "ip": "192.168.1.60", "dns_ok": true, "dns_error": null, "dns_port": 53,
  "paused_for": 0, "junk_on": true, "other_dns_all": false, "no_ipv6_all": false, "kill": false, "clock": "08:49",
  "junk_count": 74210,
  "community": {"installed": true, "count": 74100, "updated": 1795000000.0, "state": "idle", "error": ""},
  "today": {"total": 18234, "blocked": 2101},
  "scan": {"state": "idle", "ts": 1795000000.0, "network": "192.168.1.0/24", "addresses": 254, "capped": false},
  "enforcer": {"available": false, "reason": "…", "active": false, "shared": {}},
  "ipv6": {"dns_address": "fd12:3456::60", "listening": true, "listening_for": 5400, "can_hear": true,
           "router_heard": 1795000000.0,
           "router_dns": ["fe80::1"], "router_dns_not_ours": ["fe80::1"], "in_use": true, "hub_off": false,
           "routers": [{"address": "fe80::1", "mac": "aa:bb:cc:dd:ee:ff", "heard": 1795000000.0}],
           "neighbours_ok": true, "taking_lookups": true},
  "new_device_group": 2,
  "device_notices": [{"from": "192.168.1.54", "name": "Wilf's iPad", "to": "192.168.1.71",
                      "mac": "da:11:22:33:44:03", "first": 1795000000.0, "same": false,
                      "from_device": 7, "to_device": 12, "held": false, "extender": false}],
  "device_events": [{"ts": 1795000000.0, "ip": "192.168.1.71",
                     "text": "A new device appeared at 192.168.1.71 and was put in the Kids group, as you asked for new devices."}],
  "devices": {"state": "ready", "notice": "", "filling": false, "report": [], "conflicts": [], "old_rules": 0}
}
```

`devices` is about the device tables (one device is one hardware address; see ARCHITECTURE.md, "One device, many addresses"). `state` is `"ready"` when they are in use. On a household moved over from an older QuietNet it shows where that one-off move has got to: `"old"` (not tried yet; it runs shortly after start-up), `"moving"`, `"waiting"` (too little free space; tried again within the hour) or `"failed"` (tried again at the next start). In the last two nothing was changed, QuietNet runs on the old tables, rules stay under addresses and do not follow a device to a new one, `/api/devices` lists by address, and `notice` is a plain-English sentence for the home page saying so (`""` otherwise; escape it before display). `filling` is `true` while older history is still being given its device, in the background, after a move. `report` is what the move of names, groups and rules to the devices did, as plain-English lines (the last 60; empty on a household that never had an older database). `conflicts` lists rules the move left with a number for the owner to decide, each `{"id", "device", "held", "addr", "text"}`: the same device had rules under two numbers, those from where it was last seen are in use, and the others (`text` says what they are) stay with the number `addr`, held by the device `held`, until `POST /api/rule-conflict` settles it. `old_rules` is how many numbers carry a name, a group or rules in tables this version no longer reads, because an older QuietNet was run on this data afterwards; `POST /api/move-old-rules` brings them in. Escape `report` and `text` before display. An older QuietNet sends no `devices`, or none of the last three.

`new_device_group` is the group a device seen for the first time is put in, or `null` for none (the default). `device_notices` are QuietNet's questions about a device that may be another one with a new hardware address (a phone told to forget the network comes back with a new private Wi-Fi address, so as a new device). Each has `to_device` and `to` (the newcomer and the address it is at), `from_device` and `name` (the device the rules belong to, and its name), `mac` and `first` (the newcomer's hardware address and when it was first seen). With `same` true the newcomer is **already being given the other device's rules as well as its own**, and `from` is the same address as `to`: it turned up, with a private Wi-Fi address and nothing of its own, at the number that device had; or (`held` true) the rules were kept under that number alone and a device QuietNet can tell apart now has it; or (`extender` true) a Wi-Fi range extender now answers for that number, so the device there can't be told apart or joined to another. The dashboard asks whether it is the same device, offering `POST /api/move-rules` ("yes"; not offered when `extender` is true) and `POST /api/different-device` ("no"). With `same` false it is only a suggestion and nothing is applied: a device with rules has gone quiet just as a new device with a private Wi-Fi address appeared at another address (`from` is the quiet device's last address, `""` if it has none now). `other_dns_all` is whether every device is kept away from other DNS services, not just those the owner controls (see `POST /api/other-dns-switch`). `no_ipv6_all` is whether the optional "Give no device IPv6 addresses" switch is on (see `POST /api/no-ipv6-switch`; `false` unless the owner turned it on). `device_events` is up to ten notes from the last week of what QuietNet did to devices' rules by itself (held a newcomer to another device's rules, put a new device in the group, what the move of an older household's rules did), newest first. Names, addresses and notes come from the household's network: escape them before display. See ARCHITECTURE.md, "Rules held against the device".

`ipv6` is about devices using IPv6 for DNS. `dns_address` is the IPv6 address to give devices as a DNS server, shown on "Set up a device": a unique-local one if this computer has one, else a public one, never a temporary or link-local one; `""` if QuietNet isn't taking lookups over IPv6 or has no lasting address. `listening` says whether QuietNet hears the router's IPv6 announcements (Linux only, and only with the right to read raw network messages; always `false` on a Mac). `router_heard` is when the router last announced IPv6 on the home network (`null` if never heard). `router_dns` lists the IPv6 DNS servers those announcements tell devices to use, each kept until its stated lifetime runs out or for an hour at most; `router_dns_not_ours` is those that are not this computer taking lookups over IPv6. When that is not empty, the dashboard warns that some lookups skip QuietNet. Servers handed out only by DHCPv6 are not seen. `in_use` is `true` when the home network has IPv6: this computer has a public IPv6 range, or the router announced IPv6 in the last hour. Devices are then marked "can bypass QuietNet over IPv6" (`v6_bypass` in `/api/devices`), and the "Cut live connections" card says it covers IPv4 only. Devices are marked as well while `router_dns_not_ours` is not empty, whatever `in_use` says: a router with no IPv6 internet can still name its own IPv6 DNS server (in an announcement with a router lifetime of 0), and devices use it.

`hub_off` is the confirmation "IPv6 is off on your hub", shown on "Set up a device". It is `true` only when all of these hold: QuietNet has been listening for the router's announcements, and able to hear them, for a full hour without a break (`listening_for`, in seconds, is how long; 0 while it isn't listening or can't hear); no real router announced IPv6 in that hour; this computer holds no public IPv6 range; its own IPv6 addresses were looked at in the last three minutes; and `router_dns_not_ours` is empty, since a server named by any announcement, even one with a router lifetime of 0, is one devices use. A listener that never started or has stopped, a restart, and a Mac all give `false`: not knowing never reads as "off".

`can_hear` says whether this computer could have heard the router at all: `true` when the network card its home network is on (the one its default route uses) has a working link-local IPv6 address of its own, `false` when it has none, `null` when that isn't known (before the first look, no default route, or not Linux). With IPv6 switched off on that card (for example `net.ipv6.conf.wlan0.disable_ipv6=1`), the listener still runs but Linux hands it nothing, so the hour only counts from the moment a look first found the address there, and starts again if it goes. While `can_hear` is `false` the dashboard says QuietNet can't tell whether IPv6 is on, and why. An older QuietNet sends no `can_hear`. The hour is measured by a steady timer, not the clock, so a Pi learning the right time after starting can't shorten it.

`routers` lists the real routers heard announcing IPv6 in the last hour, most recent first: the link-local `address` each announcement came from, the hardware address (`mac`) it gave about itself (`""` if it gave none) and when it was last `heard`. They are what a sender on the home network claimed; nothing acts on them yet. `neighbours_ok` is whether this computer's list of IPv6 neighbours could be read at the last look (`null` before the first look): `false` means IPv6 lookups can't be matched to devices, and the home page says so when `taking_lookups` (the filter is listening on IPv6) is `true`. The addresses come from the home network: escape them before display.

`enforcer` is `{"available", "reason", "active", "shared"}` when the enforcer never started (as on a Mac, shown above); otherwise it carries every field of `GET /api/enforcer`, `firewall` and `shared` included.

`junk_count` is worked out when an advert list is loaded or downloaded, not on each call. In `scan`, `network`, `addresses` and `capped` describe what the last scan covered (or will cover): the home network, how many addresses were knocked on, and whether the network was too big to scan in full (more than 1,024 addresses, in which case the 1,024 around this computer are scanned). They are left out until a scan has been asked for since QuietNet started, and are `""`, `0` and `false` if this computer had no network address at the time.

`/api/devices` item:

```json
{"id": 7, "kind": "hw", "ip": "192.168.1.23", "macs": ["11:22:33:44:55:66"], "mac": "11:22:33:44:55:66",
 "addresses": [{"address": "192.168.1.23", "first": 1794000000.0, "last": 1795000000.0, "now": true},
               {"address": "2a00:23c8:1:2:1111::1", "first": 1794990000.0, "last": 1795000000.0, "now": true}],
 "name": "", "hint": "Sams iPad", "hint_source": "Bonjour", "hint_detail": "Model: iPad13,1",
 "this_computer": false, "last": 1795000000.0, "n": 412, "nb": 37, "on_network": 1795000000.0,
 "group": 1, "off": false, "enforced": false, "other_dns": 0, "paused": false, "warning": "",
 "v6_bypass": true, "same_as": ""}
```

**One entry per device.** A device is one hardware address, whatever network address it has, so a TV that moved from `.65` to `.67` is one entry with the history of both, and when an address passes from one device to another each keeps its own history.

- `id` is the device's number. It never changes while the device is remembered and is never given to another device. Pass it as `device` (or `dev:<id>` in a scope) to every call about the device. It is `null` for an address listed on its own (below).
- `kind` is `"hw"` (known by its hardware address), `"addr"` (known only by a network address: no hardware address is known for it, or it is behind a Wi-Fi range extender that shows several devices under one hardware address), `"pi"` (this computer) or `"hub"` (the home router).
- `macs` is the device's hardware addresses; `mac` is the first, as before.
- `addresses` is the addresses it has now or was confirmed at in the last day, IPv4 first, 32 at most. `first` and `last` are when it was first and last confirmed there (`null` where that isn't recorded) and `now` is whether it is there at this moment. A phone usually shows one IPv4 address and several IPv6 ones.
- `ip` is the one address the entry is shown under: the IPv4 address the device has now; else the last one it had that no other device has been seen at since; else an IPv6 address. **It is `""` for a device that has left and whose address has since gone to another device.** Such a device keeps its history, name and rules under its `id` (they apply again the moment it is back), and is listed only with `?all=1`: a page from before the device tables (which an older relay may still serve) knows each card by its address and could not show or open it. The dashboard page does not show such devices yet.

**Names, groups and rules are held against the device**, so `name`, `group`, `off`, `enforced` and `warning` are the device's own, whatever address it has, and go with it when its address changes. `off` and `enforced` say what applies to it now, including what reaches it from a device it may be (`device_notices`, `same` true). An address no device is known for (lookups from it are still waiting to be filed, or a scan found it with no hardware address) has an entry of its own, with `id` `null` and `kind` `"addr"`; naming it or giving it a rule makes it a device (known by the hardware address seen there, else by that address). Every device with a name, a group, an internet switch, a blocked service, a schedule or "Cut live connections" is always listed, whether or not it has any history (a device whose name was cleared, and that carries nothing else, is not listed for that alone). No two entries share an `ip`.

Listed are the devices with any history, those found by a scan, those with a name or rules, and those a `device_notices` entry is about. Lookups made in the last few minutes that are not filed against a device yet count towards the device that has their address now.

While `devices.state` in `/api/status` is not `"ready"` (an older household not moved over yet), the list is by address as it was: every entry has `id` `null`, `kind` `"addr"` and its one address in `addresses`.

`v6_bypass` is the label "can bypass QuietNet over IPv6": `true` for every device except this computer while the home network has IPv6 (`ipv6.in_use` in `/api/status`) or while something on the home network names an IPv6 DNS server that is not this computer (`ipv6.router_dns_not_ours` is not empty), and `false` otherwise. It is `true` for a device with "Cut live connections" on as well, because steering covers IPv4 only. The dashboard shows it for devices that use QuietNet.

`same_as` is a hint, only for an entry filed under an IPv6 address that QuietNet could not match to a device: the IPv4 address of the device whose hardware address that IPv6 address appears to be built from, when a scan or the neighbour table has seen that hardware address; otherwise `""`. Any device can make itself such an address, so it is only ever shown ("Probably the same device as ..."); no rule is applied from it.

`paused` is always `false` once the device tables are in use: rules are not kept under addresses, so there is nothing to pause (a different device given the address simply has its own rules). It is kept for pages that read it, and is still `true`, on an older database not moved over yet, for an address whose rules are paused because a different device has it. `warning` is a plain-English sentence for the device's page ("" if none): the device may be another one with a new hardware address and is being given its rules for now, it is behind a Wi-Fi range extender and known only by its number, or its hardware address is at two numbers at once so its rules apply only at the first. Escape it before display.

`name` is the name someone gave the device ("" if none). `hint` is the name QuietNet suggests from what the network reported ("" if none); `hint_source` says where it came from: `"DHCP"`, `"Bonjour"`, `"Windows network"`, `"UPnP"` or `"router"` ("" with no hint). `hint_detail` is a model or maker the device reported about itself (for example `"Model: Sonos One (Sonos, Inc.)"` or `"Runs Windows"`), or, for a device with neither a hint nor such a detail whose hardware address is a made-up private one, `"Private Wi-Fi address, so probably a phone, tablet or laptop"`; otherwise "". All three are plain text chosen by devices on the network: escape them before display. The dashboard saves a hint as the name with the ordinary `POST /api/device-name` call. See ARCHITECTURE.md, "Device names".

`other_dns` is when (seconds since 1970) the device last looked up another DNS service such as `dns.google` in the last 24 hours, or 0. It is kept in memory, so it starts at 0 again when QuietNet restarts; the device's activity list still shows older tries.

`n` and `nb` are lookups and blocked lookups in the last 24 hours. `last` is 0 for a device that has been seen on the network but has never used QuietNet.

`/api/activity` item:

```json
{"base": "bbc.co.uk", "owner": "BBC", "n": 3, "nb": 0, "last": 1795000000.0,
 "v": "ok", "b": false, "why": null, "svc": "", "some_blocked": false, "other_dns": false,
 "hosts": [{"d": "www.bbc.co.uk", "n": 2, "nb": 0, "last": 1795000000.0, "v": "ok", "b": false, "why": null, "svc": ""}]}
```

**The `since` marker.** Without `since`, the answer is the plain list of items above, as it always was. With `since` (send it empty, `since=`, the first time), the answer is an object:

```json
{"unchanged": false, "marker": "3f9a0c1b2d4e5f6a7b8c9d0e", "groups": [ ...the same list... ]}
```

Sending that `marker` back as `since` with the same `ip`, `device` and `hours` gets `{"unchanged": true, "marker": "<the same>"}`, without the list, when nothing has changed: no new lookup for the device, nothing leaving the time window or cleared, and no change to the rules, the pause, the advert switch, the schedules in force or the advert lists. A wrong or out-of-date marker simply gets the full answer with the current marker. The marker is 24 hex characters and should be treated as opaque: store it and send it back, never read anything into it. It only means something for the same `ip`, `device` and `hours`.

**By device.** With `device=<number>` the list is everything filed against that device, at whatever address each lookup was made, plus the last few minutes' lookups from the addresses it has now that are still waiting to be filed. The block decisions shown (`b`, `why`, `svc`) are the device's own: the device given by number, else the device listed under the address `ip`, else (an address no device is known for) the whole house's.

For QuietNet's own computer, `kill`, `off` and `schedule` never appear: it is exempt from them (see [How QuietNet works](ARCHITECTURE.md#the-order-rules-are-checked-in)).

`v` is the label: `ok`, `suspect` (possibly junk, shown for a person to judge, never blocked on its own) or `junk` (on the advert list). `b` is whether it is blocked for this device now, `why` is the reason code (`kill`, `off`, `schedule`, `you`, `allowed`, `service`, `list`, or `other_dns` for another DNS service, which is blocked whatever the rules say for a device the owner controls: one with "cut live connections", a group, or rules of its own, or every device when `other_dns_all` is on), and `svc` names the service or schedule responsible. A group's `other_dns` is `true` when any of its names is another DNS service.

`/api/controls`:

```json
{"off": false, "off_from": "for the Kids group",
 "services": {"youtube": {"on": true, "from": ""}, "tiktok": {"on": false, "from": "for the whole house"}}}
```

`on` is this scope's own switch. `from` explains a block inherited from a wider scope or a schedule. For a device that is being given another device's rules for now (`device_notices`, `same` true), what reaches it from that device reads "for Wilf's iPad, which this device may be".

### Changing

| Request | Body | Notes |
| --- | --- | --- |
| `POST /api/block` | `{"domain"}` | The text is tidied first (scheme, path, port and `www.` removed). Returns `{"ok", "domain"}` |
| `POST /api/unblock` | `{"domain"}` | Adds an allow if the advert list would still block it |
| `POST /api/forget` | `{"domain"}` | Removes both the block and the allow |
| `POST /api/service-block` | `{"scope", "service", "on"}` | `400` for an unknown service or a badly formed scope; `400` with `{"error"}` for a device QuietNet doesn't know |
| `POST /api/internet` | `{"scope", "off"}` | Not for `all` (that is the kill switch): `400`. `400` with `{"error"}` for this computer, or a device QuietNet doesn't know |
| `POST /api/kill` | `{"on"}` | The kill switch |
| `POST /api/pause` | `{"minutes"}` | Pauses advert blocking and your own blocks. 0 resumes. Limited to 24 hours |
| `POST /api/junk-switch` | `{"on"}` | Advert blocking on or off |
| `POST /api/other-dns-switch` | `{"on"}` | "Stop every device using another DNS service". Off (the default), other DNS services such as `dns.google` are blocked only for devices the owner controls; on, for every device. Saved, and shown as `other_dns_all` in `/api/status` |
| `POST /api/no-ipv6-switch` | `{"on"}` | "Give no device IPv6 addresses". Off (the default), only devices with "Cut live connections" get "no records" for IPv6 address lookups (and HTTPS and SVCB lookups); on, every device does, except for names only the home network can answer and QuietNet's own machine. Saved, and shown as `no_ipv6_all` in `/api/status`. Takes effect on the next lookup, both ways |
| `POST /api/schedule` | see below | Creates, or changes when `id` matches an existing schedule |
| `POST /api/schedule-enable` | `{"id", "on"}` | |
| `POST /api/schedule-delete` | `{"id"}` | |
| `POST /api/group` | `{"name", "id"?}` | Creates, or renames when `id` exists. Returns `{"ok", "id"}` |
| `POST /api/group-delete` | `{"id"}` | Also deletes the group's rules and schedules |
| `POST /api/device-group` | `{"device" or "ip", "group"}` | An unknown or missing group removes the device from its group |
| `POST /api/device-name` | `{"device" or "ip", "name"}` | Name cut to 40 characters. `400` with `{"error"}` if it names no device QuietNet can use |
| `POST /api/enforce` | `{"device" or "ip", "on"}` | "Cut live connections" for one device. An `ip` must be a real IPv4 address, as text (`400` otherwise). Switching on also refuses, with `400` and `{"error"}`, this computer, the router and addresses that are never devices; when the enforcer is running it also refuses addresses outside the home network. The switch is held against the device and goes with it. Which address is steered comes only from the live neighbour table: the device is steered where it is confirmed now, with its own hardware address, and nowhere else. For a device known only by its address (behind a Wi-Fi range extender) the hardware address seen there is recorded, so a different one later answering at that number is not steered |
| `POST /api/move-rules` | `{"from_device", "to_device"}` or `{"from", "to"}` | "Yes, it's the same device": joins the two into one device. `to_device` is the newcomer and `from_device` the device the rules belong to (both from a `device_notices` entry). The device kept ends with its own name and group (else the other's) and every internet switch, blocked service, schedule and "cut live connections" that either had; the other's hardware addresses, addresses and history go to it; nothing is dropped (only the new-device group QuietNet itself gave the newcomer gives way). An older page sends two IPv4 addresses as text instead: the same address twice means "the device here now is the one whose rules it is being given". Refused with `400` and `{"error"}` when either is this computer or the router, there is nothing to move, the newcomer is a number behind a range extender, or (unless QuietNet was already giving it those rules) the newcomer has rules of its own |
| `POST /api/rule-conflict` | `{"id", "choice"}` | The owner's choice for one entry of `devices.conflicts` in `/api/status`: `"give"` joins the rules left with the number to the device they were certainly for (nothing either had is dropped), `"remove"` removes them, `"keep"` leaves them with the number, where they apply to whichever device has it. Either way the entry is closed. `400` for anything else |
| `POST /api/move-old-rules` | `{}` | "Bring them in": holds against devices the names, groups and rules an older QuietNet left in the old tables (`devices.old_rules` in `/api/status`), by the same steps as the first move, in one transaction. `400` with `{"error"}` if it can't, with nothing changed |
| `POST /api/different-device` | `{"device"}` or `{"ip"}` | "No, it's a different device": the newcomer stops being given the other device's rules, which stay with the device they belong to; the answer is remembered so the question is not asked again; and a newcomer first seen in the last three days goes into the new-device group if one is chosen. Refused with `400` and `{"error"}` when nothing is being asked about that device |
| `POST /api/new-device-group` | `{"group"}` | The group a device seen for the first time is put in. `null`, or anything that isn't an existing group's id, means none. Returns `{"ok", "group"}` with the group now set (`null` for none). Deleting the group sets it back to none |
| `POST /api/cloud` | `{"relay", "code"}` or `{"action": "forget"}` | Pair with a relay, or unpair. A relay address starting `http://` is refused, with nothing sent, unless the host is `localhost`, `127.0.0.1` or `::1`: `400` with `{"error": "That relay address starts with http://, which would send this Pi's key unprotected. Use an address starting with https:// instead."}` |
| `POST /api/scan` | `{}` | Starts a network scan in the background. Returns what it will cover: `{"ok": true, "network": "192.168.4.0/22", "addresses": 1022, "capped": false}` |
| `POST /api/update-list` | `{}` | Starts the community list download in the background |
| `POST /api/clear-history` | `{"ip"?, "device"?}` | One device's history, or everyone's. With `device` (a device's number, `id` in `/api/devices`) everything filed against that device goes, at every address it has had, with any lookups still waiting to be filed from the addresses it has now; another device's history at the same address is left alone. With `ip` alone, what was recorded under that address goes, as before. With neither, everyone's. A `device` QuietNet doesn't know falls back to `ip`; with no `ip` either the answer is `400` and nothing is cleared. Everyone's is cleared before the answer, and with it the copy of the database kept from before the move to the device tables (`quietnet.db.before-devices`), which holds the history from that time; clearing one device's history leaves that copy alone until it is 30 days old. One device's is cleared in the background, 5,000 rows at a time, and the answer comes at once, so its page may briefly show part of it while the clear runs |

Schedule body:

```json
{"id": 3, "name": "Bedtime", "scope": "group:1", "days": [6, 0, 1, 2, 3],
 "start": "21:00", "end": "07:00", "off": true, "services": []}
```

`scope` may name a device as `dev:<number>` or, as an older page does, `device:<ip>`; it is kept against the device either way. `days` are whole numbers 0–6 with 0 as Monday. Times are `HH:MM`, 24-hour. Either `off` is true (all internet) or `services` lists at least one service id. Error messages: "Please choose who the schedule is for.", "Please choose at least one day.", "Please fill in both times.", "The start and end times can't be the same.", "Please choose what to block."

## Relay (`cloud/relay.py`)

Listens on `$PORT` (default 8080). HTTPS is expected to be provided by the host.

Every answer carries the same four protective headers as the dashboard API, plus `Cache-Control: no-store`. Bodies over 64 KB are not read: a form counts as empty, and a relayed call gets `413`. The one exception is `POST /agent/respond` from a paired Pi answering a call that is waiting for it (named in an `X-QuietNet-Call` header), which may be up to 16 MB (see that call below). A body must arrive within 30 seconds; one that trickles in more slowly is dropped without an answer.

When the relay already has 300 connections open, any further request gets `503` with the plain text "The relay is busy. Please try again in a moment." and the connection is closed. A successful sign-in also sets a `qn_known` cookie (one year), which gives that browser its own limit on wrong guesses for that account (20 in 15 minutes) instead of the shared ones. It is signed over the password record, so a new password voids it, and `/logout` removes it.

Guesses are limited. When a limit is reached the answer is `429` with "Too many attempts. Please wait a few minutes and try again."

| What | Limit |
| --- | --- |
| Wrong passwords for one email | 5 in 15 minutes |
| Wrong passwords across all emails | 60 in 5 minutes |
| Sign-ins to one email, right or wrong | 30 in 15 minutes |
| Sign-ins from one network address, right or wrong | 60 in 15 minutes |
| Wrong passwords and sign-ins from a browser that signed in to that account before (instead of the four above) | 20 wrong and 30 in all, each in 15 minutes |
| Wrong pairing codes from one network address | 20 in 10 minutes |
| Wrong pairing codes, overall | 200 in 10 minutes |
| Successful pairings for one account | 20 a day (the answer then says "This account has paired too many QuietNets today. Please try again tomorrow.") |
| New accounts, overall | 10 an hour |

A network address is the last entry of `X-Forwarded-For` (added by the host's proxy), or the connection's own address if there is none. IPv6 addresses are counted by their first half.

### Website (browser, session cookie)

| Request | Does |
| --- | --- |
| `GET /healthz` | `{"ok": true}` |
| `GET /login`, `GET /signup` | The forms. The sign-in form links to sign-up only while sign-up is allowed |
| `POST /signup` | Form fields `email`, `password` (8 characters or more). Creates the account if the email is new, then answers `200` with the sign-in form and the note "Thank you. Now sign in with that email and password. If the email already had an account, use that account's password." The answer is the same, and takes as long, if the email already has an account, which is left untouched. It does not sign you in. Every try counts towards the limit of 10 an hour. `403` when sign-up is switched off (`QUIETNET_SIGNUP`, which defaults to `first`: only while no account exists) |
| `POST /login` | Form fields `email`, `password`. `503` "The relay is busy" if four passwords are already being checked and none finishes within 5 seconds |
| `GET /logout` | A "Sign out?" page with a button. Changes nothing. Redirects to `/login` if not signed in |
| `POST /logout` | Form field `token`, the sign-out token in the page's sign-out button (made from the session cookie and the relay's secret). With the right token, signs the account out everywhere (every session cookie made for it so far, in any browser, stops working), clears both cookies and redirects to `/login`. Without it, changes nothing and redirects to `/` (or to `/login` if not signed in) |
| `GET /` | Your QuietNets, with pairing codes for those not yet paired. A code older than 15 minutes is replaced when this page is opened. Each waiting QuietNet also shows the one-line install command with this relay's address and the code (the address from `QUIETNET_RELAY_URL`, `RAILWAY_PUBLIC_DOMAIN` or the `Host` header, used only if it is a plain address; otherwise a placeholder to replace). A **Licence** card gives one sentence for the licence's state (see "Licences" below), in the licence's last 7 days a warning ("Your QuietNet licence ends on 4 January 2027. Filtering at home carries on; remote access and updates stop unless it's renewed."; not for plans that renew by themselves), and "Pis: N of M" (paired Pis of the licence's seats; just "Pis: N" for an account with no licence), followed by "(1 waiting to be paired)" when Pis waiting with a code still in date hold seats too. With the licence gate on: a paired Pi whose account may not use remote access shows "Remote access paused" instead of Online or Offline (it still opens `/pi/<id>/`, which is then the paused page); when a new Pi isn't allowed the Add a QuietNet form is replaced by "Adding a Pi needs a current licence.", or, when every seat is taken, "Your licence covers 2 Pis and both are in use. Remove one to add another." (paired Pis fill the seats) or "Your licence covers 2 Pis: 1 is paired and 1 is waiting to be paired. Remove one to add another." (waiting Pis make up the rest); and when pairing isn't allowed (no current licence, or paired Pis fill the seats) a waiting QuietNet shows "Adding a Pi needs a current licence." or "Your licence covers 1 Pi and it is in use. Remove one to pair this one." in place of its code and install command, and its code is not renewed. This page refuses nothing and logs nothing itself; the gates behind it do |
| `POST /pis/new` | Form field `name`. Creates a QuietNet and a pairing code. `403` with a page saying so when the account already has 10 QuietNets, paired or waiting. With the licence gate on, also `403` with "Adding a Pi needs a current licence." when the licence doesn't allow pairing, or the same seats sentence as the home page when paired Pis plus Pis waiting with a code still in date already fill the seats. With the gate off these are let through and logged |
| `POST /pis/<id>/delete` | Removes one of your QuietNets. Its Pi is locked out at once |
| `POST /theme` | Form field `theme`: `calm`, `household` or `control` (anything else saves `calm`). Sets the `qn_theme` cookie (below) and redirects (`303`) to `/`, always. Redirects to `/login`, setting nothing, if not signed in. Offered by the Appearance card on `/` |
| `GET /pi/<id>/` | The dashboard page, set to call this Pi, with a bar across the top naming the Pi, saying whether it is online, and offering a way back and a sign-out button. With the licence gate on and remote access not allowed: the **paused page** instead (below) |
| `GET` or `POST /pi/<id>/api/…` | Passed to the Pi. Needs the header `X-QuietNet: 1`. With the licence gate on and remote access not allowed: `402` with `{"error"}` (below), and nothing is passed to the Pi |
| `POST /pi/<id>/rescue` | Form field `what`: `internet-on` or `pause-hour`. Sends one fixed call to the Pi, in every licence state and whether the gate is on or off (below). Redirects to `/login` if not signed in; `404` if the Pi isn't yours; `400` with a page for any other `what`, and nothing is sent; `429` with a page, nothing sent and nothing logged, after 20 rescues by the account in the last hour |

**Forms from another website.** `POST /login`, `/signup`, `/logout`, `/pis/new`, `/theme`, `/pis/<id>/delete` and `/pi/<id>/rescue` are refused with `403` when the request's `Sec-Fetch-Site` header is `cross-site` or `same-site`, with the message "That form was sent from another website, so it was refused. Open this relay's own page and try again." (on the sign-in form for `/login` and `/signup`, on a short "Refused" page for the others). Requests without the header are handled as usual. This does not apply to `/agent/…`, or to `/pi/…` other than the rescue form.

The session cookie is `qn_session`, valid for 14 days, `HttpOnly` and `SameSite=Lax`, and `Secure` when the request arrived over HTTPS. Its value is `user.number.expiry.signature`; a cookie from before session numbers (three parts) counts as signed out.

**The look (theme) cookie.** `qn_theme=calm|household|control; SameSite=Lax; Path=/; Max-Age=31536000`, plus `Secure` over HTTPS. It is not `HttpOnly`, because the dashboard's own script reads it to pick its look; it holds nothing secret. It is a display preference only: wherever it is read it is checked against the three names, and anything else means `calm`. Every relay page (signed in or out, and error pages) is drawn in that look (`<html data-theme="...">`); with no cookie, `calm`. The dashboard under `/pi/<id>/` is on the same website, so the same cookie sets its look. The relay's pages carry no scripts.

Relayed calls can fail in these ways:

| Status | Meaning |
| --- | --- |
| `402` | Remote access is paused for this account's licence (gate on only). `{"error": "..."}`, for example "Remote access is paused because the licence ended on 4 January 2027. Your Pi is still blocking at home." This is checked after "is it your Pi", so another account's Pi is still `404` |
| `403` | The `X-QuietNet: 1` header is missing |
| `404` | Not signed in, not your Pi, or not an `/api/` path |
| `503` | The Pi is not paired, or has not been heard from for 40 seconds; or its answer was too large for the relay to pass on right now (`{"error": "Your QuietNet's answer was too large for the relay to pass on right now. Please try again in a moment."}`) |
| `504` | The Pi did not answer within 30 seconds |
| `413` | The request body is over 64 KB |
| `502` | The Pi answered with a status outside 200–599 |

Any other status and body are the Pi's own.

### Pi side (`cloud_agent.py`)

| Request | Body or header | Returns |
| --- | --- | --- |
| `POST /agent/pair` | `{"code", "install"?}` | `{"ok", "id", "token"}` (the only time the token is sent; the relay keeps only its hash), or `400` with `{"error"}` if the code is wrong, used or expired. A code works once and for 15 minutes. `429` after too many wrong codes (from this network address or overall), or when the account has paired too many QuietNets today; the code is not used up. `install` is the Pi's install id, exactly 32 lower-case hex characters; anything else is ignored (older Pis send none). It is stored on the Pi's entry. `403` cases, none of which use up the code: (1) another paired Pi of the same account has the same install id and is online: `{"error": "Another Pi with the same identity is online. This usually means the SD card was copied. On this Pi, run the installer with --new-identity, then pair again."}` (if that other entry is offline, it is this Pi paired again, and the old entry is removed and its token stops working); (2) with the licence gate on, the licence doesn't allow pairing: `{"error": "Remote access needs a QuietNet licence. Your Pi is still filtering at home. Visit q3n.net to renew.", "licence": "<state>"}`; (3) with the gate on, paired Pis (not counting one being replaced) already fill the seats: `{"error": "Your licence covers 2 Pis and both are in use. Remove one at q3n.net, then pair again.", "licence": "<state>"}`. The seat count and the pairing happen together, so codes sent at the same moment can't pair more Pis than the seats, and a code sent twice at once pairs once (the other gets the `400`). Never `401` for a licence reason |
| `GET /agent/poll` | Header `X-QuietNet-Token`; optional `X-QuietNet-Agent: 2` | Waits up to 25 seconds. `{"licence": {...}}` (no `id`) if nothing to do, or `{"id", "method", "path", "body"?, "licence": {...}}`, plus `"latest"` in both when set (below). A Pi has one poll waiting at a time: a new one ends the older one, which returns with no `id`. `401` if the token is not recognised. `503` with `{"error"}` when 150 Pis are already waiting. Always `200` for a licence reason, and the wait and poll slots are the same whatever the licence. `X-QuietNet-Agent: 2` (from 0.6) is recorded on the Pi's entry; anything else counts as 1 and picks the older rescue call |
| `POST /agent/respond` | Headers `X-QuietNet-Token` and `X-QuietNet-Call` (the call id); `{"id", "status", "body"}`, up to 16 MB | `{"ok": true}`, or `413` if too big. An answer to a call that was sent to a different Pi is ignored, as is a second answer to the same call. An answer over 64 KB needs room: one at a time per account (across all its Pis) and 48 MB across every account. If none comes within 10 seconds, the answer is `503` and the waiting browser gets `503` at once |

`body` in both directions is the JSON text as a string, passed through unchanged.

**The `licence` object in poll answers** (version 1):

```json
{"licence": {"v": 1, "state": "past_due", "remote": true, "updates": true,
             "until": 1798934400, "grace_until": 1800144000,
             "seats": 2, "used": 1, "now": 1798000000},
 "latest": "0.6"}
```

| Key | Meaning |
| --- | --- |
| `v` | Format version, `1` |
| `state` | `none`, `trial`, `active`, `cancelling`, `past_due`, `expired` or `revoked`: the real state, gate on or off |
| `remote`, `updates` | What the relay will actually allow. **With the gate off both are `true` whatever the state**, because nothing is refused then; with it on they follow the state |
| `until` | End of the paid period (Unix seconds), `0` for no end |
| `grace_until` | Only for `past_due`: when it becomes `expired` |
| `seats` | Pis the licence covers. Left out for `none`: an account with no licence has none |
| `used` | Paired Pis |
| `now` | The relay's clock, so a Pi with a wrong clock can still count days |

`latest` is added only when `QUIETNET_LATEST` holds a version number such as `0.6` or `0.6.1`. Pis before 0.6 ignore both keys: they hand on only an answer with an `id`, and use only its `id`, `method`, `path` and `body`.

### Licences (relay)

Each account has at most one licence. The relay works out its state from what is stored (the time-based steps are applied as it is read):

| State | Remote access | Updates | Add or pair Pis |
| --- | --- | --- | --- |
| `none` (no licence) | No | No | No |
| `trial` | Yes | Yes | Yes, within seats |
| `active` | Yes | Yes | Yes, within seats |
| `cancelling` (active, set to end at the period end) | Yes, until the end date | Yes | Yes |
| `past_due` (until `grace_until`, or 14 days after the end date if that is not set; with neither set, no end) | Yes | Yes | No |
| `expired` (also: `active` or `trial` 3 days past the end date; `cancelling` from the end date; `past_due` once its grace ends) | No | No | No |
| `revoked` | No | No | No |

**The gate.** `QUIETNET_LICENCE_GATE=on` enforces the table. Off (the default, and any other value), every request is let through and what would have been refused is logged instead: one log line and one `licence_log` row, at most once an hour for each account and kind of refusal (remote access, adding a Pi, adding beyond the seats, pairing, pairing beyond the seats). Refusals with the gate on are logged the same way. `licence_log` keeps the newest 1000 of these lines (and rescues) per account; the owner's own lines (grants and changes from the command line, and the legacy grant) are always kept.

**The paused page** (`GET /pi/<id>/`, gate on, remote access not allowed) says why ("Your QuietNet licence ended on 4 January 2027. Your Pi is still filtering and blocking at home as normal." for an expired licence; other words for `revoked` and `none`), then two buttons, each a form posting to `/pi/<id>/rescue`: **Turn the internet back on for every device** (`what=internet-on`) and **Pause blocking for an hour** (`what=pause-hour`), and how to reach the dashboard at home or stop using QuietNet.

**Rescue calls.** The relay builds the call itself from fixed text; nothing from the browser goes into its path or body:

| Button | Pi from 0.6 (`X-QuietNet-Agent: 2`) | Older Pi |
| --- | --- | --- |
| `internet-on` | `POST /api/rescue {"what": "internet-on"}` | `POST /api/kill {"on": false}` (kill switch only) |
| `pause-hour` | `POST /api/pause {"minutes": 60}` | the same |

It goes through the bridge like any relayed call. The result page says "Done. Every device's internet switch is back on. It can take a minute or two for devices to notice." (older Pi: "Done. The household kill switch is off. ..."), or "Done. Blocking is paused for an hour."; `503` with "Your Pi isn't connected to q3n.net right now, so this couldn't be sent. Is it switched on?" when the Pi is not paired or not heard from for 40 seconds; `504` when it doesn't answer in 30 seconds; `502` when it answers with an error. Every rescue is written to `licence_log`. An account may press 20 times an hour; after that the answer is `429` ("That's a lot of rescue presses in the last hour, so this one wasn't sent. Please wait a few minutes and try again."), nothing is sent and nothing is logged.

**Owner's command line** (run inside the relay's container, for example with `railway ssh`). It gives up root first, as the server does, then opens `relay.db`:

```
python relay.py licence show <email>
python relay.py licence list
python relay.py licence grant <email> --plan owner|gift|legacy [--days N] [--seats N]
python relay.py licence revoke <email> --reason "..."
python relay.py licence restore <email>
python relay.py licence seats <email> N
```

`--days` left out or `0` means no end date; `--seats` 1 to 10, left out keeps the licence's seats (2 for a new one). `grant` sets `active` and clears any reason; `revoke` sets `revoked` with the reason and keeps the plan and dates; `restore` sets `active` again, keeping the end date. The account is found by its current email. Each change writes a `licence_log` row. `list` prints every account, one line each (email, account number, licence id, state now, plan, end date, and "Pis: N of M", or "no licence" and "Pis: N"), then the number of accounts, or "No accounts on this relay yet."; it changes nothing. Exit status 0 when done, 1 for an unknown email or a licence that isn't there, 2 for a wrong command (a missing or blank `--reason` included); the reason is printed in plain words.
