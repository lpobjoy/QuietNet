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
| `GET /api/activity?ip=<ip>&hours=<n>` | What one device contacted, grouped by company. `hours` defaults to 24, limited to 0.1–720 |
| `GET /api/rules` | `{"blocked": [...], "allowed": [...]}`, each item `{"d", "ts", "owner"}` |
| `GET /api/services` | The service catalogue: `[{"id", "name", "cat"}]` |
| `GET /api/groups` | `[{"id", "name", "off", "members", "services"}]` |
| `GET /api/schedules` | All schedules, each with `"active"` (in force right now) |
| `GET /api/controls?scope=<scope>` | Switches for one scope, and what it inherits. `400` if the scope is badly formed |
| `GET /api/cloud` | Remote access state: `{"configured", "paired", "relay", "name", "state", "detail"}` |
| `GET /api/enforcer` | `{"available", "reason", "problem", "problems", "active", "backend", "gateway"}`. `problem` says why all steering is paused right now (forwarding off, or another firewall in the way or impossible to check), or `""`. `problems` is `{device address: text}` for devices left alone, e.g. because a different device now has the address |

`/api/status`:

```json
{
  "ip": "192.168.1.60", "dns_ok": true, "dns_error": null, "dns_port": 53,
  "paused_for": 0, "junk_on": true, "kill": false, "clock": "08:49",
  "junk_count": 74210,
  "community": {"installed": true, "count": 74100, "updated": 1795000000.0, "state": "idle", "error": ""},
  "today": {"total": 18234, "blocked": 2101},
  "scan": {"state": "idle", "ts": 1795000000.0, "network": "192.168.1.0/24", "addresses": 254, "capped": false},
  "enforcer": {"available": false, "reason": "…", "active": false}
}
```

`junk_count` is worked out when an advert list is loaded or downloaded, not on each call. In `scan`, `network`, `addresses` and `capped` describe what the last scan covered (or will cover): the home network, how many addresses were knocked on, and whether the network was too big to scan in full (more than 1,024 addresses, in which case the 1,024 around this computer are scanned). They are left out until a scan has been asked for since QuietNet started, and are `""`, `0` and `false` if this computer had no network address at the time.

`/api/devices` item:

```json
{"ip": "192.168.1.23", "name": "Tablet", "hint": "ipad", "mac": "11:22:33:44:55:66",
 "this_computer": false, "last": 1795000000.0, "n": 412, "nb": 37, "on_network": 1795000000.0,
 "group": 1, "off": false, "enforced": false}
```

`n` and `nb` are lookups and blocked lookups in the last 24 hours. `last` is 0 for a device that has been seen on the network but has never used QuietNet.

`/api/activity` item:

```json
{"base": "bbc.co.uk", "owner": "BBC", "n": 3, "nb": 0, "last": 1795000000.0,
 "v": "ok", "b": false, "why": null, "svc": "", "some_blocked": false,
 "hosts": [{"d": "www.bbc.co.uk", "n": 2, "nb": 0, "last": 1795000000.0, "v": "ok", "b": false, "why": null, "svc": ""}]}
```

For QuietNet's own computer, `kill`, `off` and `schedule` never appear: it is exempt from them (see [How QuietNet works](ARCHITECTURE.md#the-order-rules-are-checked-in)).

`v` is the label: `ok`, `suspect` (possibly junk, shown for a person to judge, never blocked on its own) or `junk` (on the advert list). `b` is whether it is blocked for this device now, `why` is the reason code (`kill`, `off`, `schedule`, `you`, `allowed`, `service`, `list`), and `svc` names the service or schedule responsible.

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
| `POST /api/schedule` | see below | Creates, or changes when `id` matches an existing schedule |
| `POST /api/schedule-enable` | `{"id", "on"}` | |
| `POST /api/schedule-delete` | `{"id"}` | |
| `POST /api/group` | `{"name", "id"?}` | Creates, or renames when `id` exists. Returns `{"ok", "id"}` |
| `POST /api/group-delete` | `{"id"}` | Also deletes the group's rules and schedules |
| `POST /api/device-group` | `{"ip", "group"}` | An unknown or missing group removes the device from its group |
| `POST /api/device-name` | `{"ip", "name"}` | Name cut to 40 characters |
| `POST /api/enforce` | `{"ip", "on"}` | "Cut live connections" for one device. Must be a real IPv4 address, as text (`400` otherwise). Switching on also refuses, with `400` and `{"error"}`, this computer and addresses that are never devices; when the enforcer is running it also refuses the router and addresses outside the home network. The device's hardware address is recorded so a different device later given the same address is left alone |
| `POST /api/cloud` | `{"relay", "code"}` or `{"action": "forget"}` | Pair with a relay, or unpair |
| `POST /api/scan` | `{}` | Starts a network scan in the background. Returns what it will cover: `{"ok": true, "network": "192.168.4.0/22", "addresses": 1022, "capped": false}` |
| `POST /api/update-list` | `{}` | Starts the community list download in the background |
| `POST /api/clear-history` | `{"ip"?}` | One device's history, or everyone's |

Schedule body:

```json
{"id": 3, "name": "Bedtime", "scope": "group:1", "days": [6, 0, 1, 2, 3],
 "start": "21:00", "end": "07:00", "off": true, "services": []}
```

`days` are whole numbers 0–6 with 0 as Monday. Times are `HH:MM`, 24-hour. Either `off` is true (all internet) or `services` lists at least one service id. Error messages: "Please choose who the schedule is for.", "Please choose at least one day.", "Please fill in both times.", "The start and end times can't be the same.", "Please choose what to block."

## Relay (`cloud/relay.py`)

Listens on `$PORT` (default 8080). HTTPS is expected to be provided by the host.

Every answer carries the same four protective headers as the dashboard API, plus `Cache-Control: no-store`. Bodies over 64 KB are not read: a form counts as empty, and a relayed call gets `413`. The one exception is `POST /agent/respond` from a paired Pi answering a call that is waiting for it (named in an `X-QuietNet-Call` header), which may be up to 16 MB (see that call below). A body must arrive within 30 seconds; one that trickles in more slowly is dropped without an answer.

When the relay already has 300 connections open, any further request gets `503` with the plain text "The relay is busy. Please try again in a moment." and the connection is closed. A successful sign-in or sign-up also sets a `qn_known` cookie (one year), which gives that browser its own limit on wrong guesses for that account (20 in 15 minutes) instead of the shared ones. It is signed over the password record, so a new password voids it, and `/logout` removes it.

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
| `GET /login`, `GET /signup` | The forms |
| `POST /signup` | Form fields `email`, `password` (8 characters or more). Signs in and redirects to `/`. `403` when sign-up is switched off (`QUIETNET_SIGNUP`) |
| `POST /login` | Form fields `email`, `password`. `503` "The relay is busy" if four passwords are already being checked and none finishes within 5 seconds |
| `GET /logout` | A "Sign out?" page with a button. Changes nothing. Redirects to `/login` if not signed in |
| `POST /logout` | Form field `token`, the sign-out token in the page's sign-out button (made from the session cookie and the relay's secret). With the right token, clears both cookies and redirects to `/login`. Without it, changes nothing and redirects to `/` (or to `/login` if not signed in) |
| `GET /` | Your QuietNets, with pairing codes for those not yet paired. A code older than 15 minutes is replaced when this page is opened |
| `POST /pis/new` | Form field `name`. Creates a QuietNet and a pairing code. `403` with a page saying so when the account already has 10 QuietNets, paired or waiting |
| `POST /pis/<id>/delete` | Removes one of your QuietNets. Its Pi is locked out at once |
| `GET /pi/<id>/` | The dashboard page, set to call this Pi |
| `GET` or `POST /pi/<id>/api/…` | Passed to the Pi. Needs the header `X-QuietNet: 1` |

The session cookie is `qn_session`, valid for 14 days, `HttpOnly` and `SameSite=Lax`, and `Secure` when the request arrived over HTTPS.

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
| `POST /agent/pair` | `{"code"}` | `{"ok", "id", "token"}`, or `400` with `{"error"}` if the code is wrong, used or expired. A code works once and for 15 minutes. `429` after too many wrong codes (from this network address or overall), or when the account has paired too many QuietNets today; the code is not used up |
| `GET /agent/poll` | Header `X-QuietNet-Token` | Waits up to 25 seconds. `{}` if nothing to do, or `{"id", "method", "path", "body"?}`. A Pi has one poll waiting at a time: a new one ends the older one, which returns `{}`. `401` if the token is not recognised. `503` with `{"error"}` when 150 Pis are already waiting |
| `POST /agent/respond` | Headers `X-QuietNet-Token` and `X-QuietNet-Call` (the call id); `{"id", "status", "body"}`, up to 16 MB | `{"ok": true}`, or `413` if too big. An answer to a call that was sent to a different Pi is ignored, as is a second answer to the same call. An answer over 64 KB needs room: one at a time per account (across all its Pis) and 48 MB across every account. If none comes within 10 seconds, the answer is `503` and the waiting browser gets `503` at once |

`body` in both directions is the JSON text as a string, passed through unchanged.
