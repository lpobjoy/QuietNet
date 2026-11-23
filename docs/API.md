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

A **scope** is `all`, `group:<id>` or `device:<ip>`.

### Reading

| Request | Returns |
| --- | --- |
| `GET /` | The dashboard page |
| `GET /api/status` | See below |
| `GET /api/devices` | List of devices, most recently active first |
| `GET /api/activity?ip=<ip>&hours=<n>&since=<marker>` | What one device contacted, grouped by company. `hours` defaults to 24, limited to 0.1–720. `since` is optional: see below |
| `GET /api/rules` | `{"blocked": [...], "allowed": [...]}`, each item `{"d", "ts", "owner"}` |
| `GET /api/services` | The service catalogue: `[{"id", "name", "cat"}]` |
| `GET /api/groups` | `[{"id", "name", "off", "members", "services"}]` |
| `GET /api/schedules` | All schedules, each with `"active"` (in force right now) |
| `GET /api/controls?scope=<scope>` | Switches for one scope, and what it inherits. `400` if the scope is badly formed |
| `GET /api/cloud` | Remote access state: `{"configured", "paired", "relay", "name", "state", "detail"}` |
| `GET /api/enforcer` | `{"available", "reason", "problem", "problems", "active", "backend", "gateway", "dns_redirect", "firewall", "shared"}`. `firewall` is `null`, or, when another firewall on the Pi is what stops all steering, `{"blocked_by": [text, ...], "commands": [command, ...], "installer": true/false}`: the firewall rules in the way, the commands that let passed-on traffic through (each lasts until the Pi restarts), and whether running the install command again makes the fix permanent (only for Docker's firewall). The home page shows it; escape every part. `dns_redirect` is `true` when a steered device's ordinary DNS sent to another server is redirected to QuietNet (the `nft` tool only; with `iptables` it is `false`). `problem` says why all steering is paused right now (forwarding off, or another firewall in the way or impossible to check), or `""`. `problems` is `{device address: text}` for devices left alone, e.g. because a different device now has the address. `shared` is `{device address: {"count", "names"}}` for enforced devices with addresses left to the DNS block because a site the device is allowed shares them: `count` addresses, and up to five blocked services or names (`names`). Escape both before display |

`/api/status`:

```json
{
  "ip": "192.168.1.60", "dns_ok": true, "dns_error": null, "dns_port": 53,
  "paused_for": 0, "junk_on": true, "other_dns_all": false, "kill": false, "clock": "08:49",
  "junk_count": 74210,
  "community": {"installed": true, "count": 74100, "updated": 1795000000.0, "state": "idle", "error": ""},
  "today": {"total": 18234, "blocked": 2101},
  "scan": {"state": "idle", "ts": 1795000000.0, "network": "192.168.1.0/24", "addresses": 254, "capped": false},
  "enforcer": {"available": false, "reason": "…", "active": false, "shared": {}},
  "ipv6": {"dns_address": "fd12:3456::60", "listening": true, "router_heard": 1795000000.0,
           "router_dns": ["fe80::1"], "router_dns_not_ours": ["fe80::1"], "in_use": true},
  "new_device_group": 2,
  "device_notices": [{"from": "192.168.1.54", "name": "Wilf's iPad", "to": "192.168.1.71",
                      "mac": "da:11:22:33:44:03", "first": 1795000000.0, "same": false}],
  "device_events": [{"ts": 1795000000.0, "ip": "192.168.1.71",
                     "text": "Wilf's iPad moved from 192.168.1.54 to 192.168.1.71; its rules moved with it."}]
}
```

`new_device_group` is the group a device seen for the first time is put in, or `null` for none (the default). `device_notices` lists devices with rules that have gone quiet just as a new device with a private Wi-Fi address appeared (`from` and `name`: the quiet one; `to`, `mac`, `first`: the new one and when it was first seen); the dashboard offers `POST /api/move-rules` for each. An entry with `same` true is a device with a private Wi-Fi address that appeared, since the rules' device was last seen, at the very address the rules are kept under (`from` and `to` are then that address): the rules still apply to it, and the dashboard asks whether it is the same device, offering `POST /api/move-rules` with that address twice ("yes") and `POST /api/different-device` ("no"). `other_dns_all` is whether every device is kept away from other DNS services, not just those the owner controls (see `POST /api/other-dns-switch`). `device_events` is up to ten notes from the last week of what QuietNet did to devices' rules by itself (moved them, paused them, put a new device in the group), newest first. Names, addresses and notes come from the household's network: escape them before display. See ARCHITECTURE.md, "When a device changes address".

`ipv6` is about devices using IPv6 for DNS. `dns_address` is the IPv6 address to give devices as a DNS server, shown on "Set up a device": a unique-local one if this computer has one, else a public one, never a temporary or link-local one; `""` if QuietNet isn't taking lookups over IPv6 or has no lasting address. `listening` says whether QuietNet hears the router's IPv6 announcements (Linux only, and only with the right to read raw network messages; always `false` on a Mac). `router_heard` is when the router last announced IPv6 on the home network (`null` if never heard). `router_dns` lists the IPv6 DNS servers those announcements tell devices to use, each kept until its stated lifetime runs out or for an hour at most; `router_dns_not_ours` is those that are not this computer taking lookups over IPv6. When that is not empty, the dashboard warns that some lookups skip QuietNet. Servers handed out only by DHCPv6 are not seen. `in_use` is `true` when the home network has IPv6: this computer has a public IPv6 range, or the router announced IPv6 in the last hour. The "Cut live connections" card then says that IPv6 connections can't be cut directly. The addresses come from the home network: escape them before display.

`enforcer` is `{"available", "reason", "active", "shared"}` when the enforcer never started (as on a Mac, shown above); otherwise it carries every field of `GET /api/enforcer`, `firewall` and `shared` included.

`junk_count` is worked out when an advert list is loaded or downloaded, not on each call. In `scan`, `network`, `addresses` and `capped` describe what the last scan covered (or will cover): the home network, how many addresses were knocked on, and whether the network was too big to scan in full (more than 1,024 addresses, in which case the 1,024 around this computer are scanned). They are left out until a scan has been asked for since QuietNet started, and are `""`, `0` and `false` if this computer had no network address at the time.

`/api/devices` item:

```json
{"ip": "192.168.1.23", "name": "", "hint": "Sams iPad", "hint_source": "Bonjour", "hint_detail": "Model: iPad13,1",
 "mac": "11:22:33:44:55:66",
 "this_computer": false, "last": 1795000000.0, "n": 412, "nb": 37, "on_network": 1795000000.0,
 "group": 1, "off": false, "enforced": false, "other_dns": 0, "paused": false, "warning": ""}
```

`paused` is `true` when a different device now has this address, so the rules kept under it (its own and its group's) are paused until the device they belong to comes back; only the whole house's rules apply, plus the new-device group if the device there now was never seen before. `warning` is a plain-English sentence for the device's page when its rules are paused or could not be moved, or the device is behind a Wi-Fi range extender ("" if none); escape it before display. A device whose rules follow it by hardware address, or that a `device_notices` entry points at, is listed even before it has used QuietNet or been found by a scan.

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

Sending that `marker` back as `since` with the same `ip` and `hours` gets `{"unchanged": true, "marker": "<the same>"}`, without the list, when nothing has changed: no new lookup for the device, nothing leaving the time window or cleared, and no change to the rules, the pause, the advert switch, the schedules in force or the advert lists. A wrong or out-of-date marker simply gets the full answer with the current marker. The marker is 24 hex characters and should be treated as opaque: store it and send it back, never read anything into it. It only means something for the same `ip` and `hours`.

For QuietNet's own computer, `kill`, `off` and `schedule` never appear: it is exempt from them (see [How QuietNet works](ARCHITECTURE.md#the-order-rules-are-checked-in)).

`v` is the label: `ok`, `suspect` (possibly junk, shown for a person to judge, never blocked on its own) or `junk` (on the advert list). `b` is whether it is blocked for this device now, `why` is the reason code (`kill`, `off`, `schedule`, `you`, `allowed`, `service`, `list`, or `other_dns` for another DNS service, which is blocked whatever the rules say for a device the owner controls: one with "cut live connections", a group, or rules of its own, or every device when `other_dns_all` is on), and `svc` names the service or schedule responsible. A group's `other_dns` is `true` when any of its names is another DNS service.

`/api/controls`:

```json
{"off": false, "off_from": "for the Kids group",
 "services": {"youtube": {"on": true, "from": ""}, "tiktok": {"on": false, "from": "for the whole house"}}}
```

`on` is this scope's own switch. `from` explains a block inherited from a wider scope or a schedule.

### Changing

| Request | Body | Notes |
| --- | --- | --- |
| `POST /api/block` | `{"domain"}` | The text is tidied first (scheme, path, port and `www.` removed). Returns `{"ok", "domain"}` |
| `POST /api/unblock` | `{"domain"}` | Adds an allow if the advert list would still block it |
| `POST /api/forget` | `{"domain"}` | Removes both the block and the allow |
| `POST /api/service-block` | `{"scope", "service", "on"}` | `400` for an unknown service or scope |
| `POST /api/internet` | `{"scope", "off"}` | Not for `all` (that is the kill switch): `400` |
| `POST /api/kill` | `{"on"}` | The kill switch |
| `POST /api/pause` | `{"minutes"}` | Pauses advert blocking and your own blocks. 0 resumes. Limited to 24 hours |
| `POST /api/junk-switch` | `{"on"}` | Advert blocking on or off |
| `POST /api/other-dns-switch` | `{"on"}` | "Stop every device using another DNS service". Off (the default), other DNS services such as `dns.google` are blocked only for devices the owner controls; on, for every device. Saved, and shown as `other_dns_all` in `/api/status` |
| `POST /api/schedule` | see below | Creates, or changes when `id` matches an existing schedule |
| `POST /api/schedule-enable` | `{"id", "on"}` | |
| `POST /api/schedule-delete` | `{"id"}` | |
| `POST /api/group` | `{"name", "id"?}` | Creates, or renames when `id` exists. Returns `{"ok", "id"}` |
| `POST /api/group-delete` | `{"id"}` | Also deletes the group's rules and schedules |
| `POST /api/device-group` | `{"ip", "group"}` | An unknown or missing group removes the device from its group |
| `POST /api/device-name` | `{"ip", "name"}` | Name cut to 40 characters |
| `POST /api/enforce` | `{"ip", "on"}` | "Cut live connections" for one device. Must be a real IPv4 address, as text (`400` otherwise). Switching on also refuses, with `400` and `{"error"}`, this computer and addresses that are never devices; when the enforcer is running it also refuses the router and addresses outside the home network. The device's hardware address is recorded so a different device later given the same address is left alone |
| `POST /api/move-rules` | `{"from", "to"}` | "Move the rules to this device": moves the name, group, own service blocks, internet switch, schedules and "cut live connections" from one address to another. Both must be IPv4 addresses as text (`400` otherwise). Refused with `400` and `{"error"}` when either is this computer or the router, `from` has nothing to move, or `to` has rules of its own (a group alone is allowed, and replaced by `from`'s group, or removed if `from` has none). The history stays under the old address. With `from` and `to` the same address it means "the device at this address now is the one these rules are for": the rules belong to its hardware address from then on, and a pause ends. Refused with `400` and `{"error"}` if the address has no rules or the device there can't be seen |
| `POST /api/different-device` | `{"ip"}` | "No, it's a different device": the rules kept under this IPv4 address are paused, kept for the device they belong to, until it comes back, and the device there now gets the new-device group if one is chosen. Refused with `400` and `{"error"}` when the address has no rules, or the device there is the one they belong to |
| `POST /api/new-device-group` | `{"group"}` | The group a device seen for the first time is put in. `null`, or anything that isn't an existing group's id, means none. Returns `{"ok", "group"}` with the group now set (`null` for none). Deleting the group sets it back to none |
| `POST /api/cloud` | `{"relay", "code"}` or `{"action": "forget"}` | Pair with a relay, or unpair. A relay address starting `http://` is refused, with nothing sent, unless the host is `localhost`, `127.0.0.1` or `::1`: `400` with `{"error": "That relay address starts with http://, which would send this Pi's key unprotected. Use an address starting with https:// instead."}` |
| `POST /api/scan` | `{}` | Starts a network scan in the background. Returns what it will cover: `{"ok": true, "network": "192.168.4.0/22", "addresses": 1022, "capped": false}` |
| `POST /api/update-list` | `{}` | Starts the community list download in the background |
| `POST /api/clear-history` | `{"ip"?}` | One device's history, or everyone's. Everyone's is cleared before the answer. One device's is cleared in the background, 5,000 rows at a time, and the answer comes at once, so its page may briefly show part of it while the clear runs |

Schedule body:

```json
{"id": 3, "name": "Bedtime", "scope": "group:1", "days": [6, 0, 1, 2, 3],
 "start": "21:00", "end": "07:00", "off": true, "services": []}
```

`days` are whole numbers 0–6 with 0 as Monday. Times are `HH:MM`, 24-hour. Either `off` is true (all internet) or `services` lists at least one service id. Error messages: "Please choose who the schedule is for.", "Please choose at least one day.", "Please fill in both times.", "The start and end times can't be the same.", "Please choose what to block."

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
| `GET /` | Your QuietNets, with pairing codes for those not yet paired. A code older than 15 minutes is replaced when this page is opened. Each waiting QuietNet also shows the one-line install command with this relay's address and the code (the address from `QUIETNET_RELAY_URL`, `RAILWAY_PUBLIC_DOMAIN` or the `Host` header, used only if it is a plain address; otherwise a placeholder to replace) |
| `POST /pis/new` | Form field `name`. Creates a QuietNet and a pairing code. `403` with a page saying so when the account already has 10 QuietNets, paired or waiting |
| `POST /pis/<id>/delete` | Removes one of your QuietNets. Its Pi is locked out at once |
| `POST /theme` | Form field `theme`: `calm`, `household` or `control` (anything else saves `calm`). Sets the `qn_theme` cookie (below) and redirects (`303`) to `/`, always. Redirects to `/login`, setting nothing, if not signed in. Offered by the Appearance card on `/` |
| `GET /pi/<id>/` | The dashboard page, set to call this Pi, with a bar across the top naming the Pi, saying whether it is online, and offering a way back and a sign-out button |
| `GET` or `POST /pi/<id>/api/…` | Passed to the Pi. Needs the header `X-QuietNet: 1` |

**Forms from another website.** `POST /login`, `/signup`, `/logout`, `/pis/new`, `/theme` and `/pis/<id>/delete` are refused with `403` when the request's `Sec-Fetch-Site` header is `cross-site` or `same-site`, with the message "That form was sent from another website, so it was refused. Open this relay's own page and try again." (on the sign-in form for `/login` and `/signup`, on a short "Refused" page for the others). Requests without the header are handled as usual. This does not apply to `/pi/…` or `/agent/…`.

The session cookie is `qn_session`, valid for 14 days, `HttpOnly` and `SameSite=Lax`, and `Secure` when the request arrived over HTTPS. Its value is `user.number.expiry.signature`; a cookie from before session numbers (three parts) counts as signed out.

**The look (theme) cookie.** `qn_theme=calm|household|control; SameSite=Lax; Path=/; Max-Age=31536000`, plus `Secure` over HTTPS. It is not `HttpOnly`, because the dashboard's own script reads it to pick its look; it holds nothing secret. It is a display preference only: wherever it is read it is checked against the three names, and anything else means `calm`. Every relay page (signed in or out, and error pages) is drawn in that look (`<html data-theme="...">`); with no cookie, `calm`. The dashboard under `/pi/<id>/` is on the same website, so the same cookie sets its look. The relay's pages carry no scripts.

Relayed calls can fail in these ways:

| Status | Meaning |
| --- | --- |
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
| `POST /agent/pair` | `{"code"}` | `{"ok", "id", "token"}` (the only time the token is sent; the relay keeps only its hash), or `400` with `{"error"}` if the code is wrong, used or expired. A code works once and for 15 minutes. `429` after too many wrong codes (from this network address or overall), or when the account has paired too many QuietNets today; the code is not used up |
| `GET /agent/poll` | Header `X-QuietNet-Token` | Waits up to 25 seconds. `{}` if nothing to do, or `{"id", "method", "path", "body"?}`. A Pi has one poll waiting at a time: a new one ends the older one, which returns `{}`. `401` if the token is not recognised. `503` with `{"error"}` when 150 Pis are already waiting |
| `POST /agent/respond` | Headers `X-QuietNet-Token` and `X-QuietNet-Call` (the call id); `{"id", "status", "body"}`, up to 16 MB | `{"ok": true}`, or `413` if too big. An answer to a call that was sent to a different Pi is ignored, as is a second answer to the same call. An answer over 64 KB needs room: one at a time per account (across all its Pis) and 48 MB across every account. If none comes within 10 seconds, the answer is `503` and the waiting browser gets `503` at once |

`body` in both directions is the JSON text as a string, passed through unchanged.
