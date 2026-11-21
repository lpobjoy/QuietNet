# API reference

QuietNet has two web interfaces: the dashboard API on the Pi, and the relay. The dashboard page (`static/index.html`) is the only intended caller of both. This reference is for anyone changing the code or writing tests.

See also: [How QuietNet works](ARCHITECTURE.md)

## Dashboard API (`server.py`)

Listens on `127.0.0.1:8377`.

**Rules for every request**

- The `Host` header must be `localhost` or `127.0.0.1` (a port is allowed). Anything else gets `403`.
- `POST` requests must have `Content-Type: application/json` (otherwise `415`) and a JSON body (unreadable JSON gets `400`).
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
| `GET /api/enforcer` | `{"available", "reason", "active", "backend", "gateway"}` |

`/api/status`:

```json
{
  "ip": "192.168.1.60", "dns_ok": true, "dns_error": null, "dns_port": 53,
  "paused_for": 0, "junk_on": true, "kill": false, "clock": "08:49",
  "junk_count": 74210,
  "community": {"installed": true, "count": 74100, "updated": 1795000000.0, "state": "idle", "error": ""},
  "today": {"total": 18234, "blocked": 2101},
  "scan": {"state": "idle", "ts": 1795000000.0},
  "enforcer": {"available": false, "reason": "…", "active": false}
}
```

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
| `POST /api/enforce` | `{"ip", "on"}` | "Cut live connections" for one device. Must be a real IPv4 address, as text |
| `POST /api/cloud` | `{"relay", "code"}` or `{"action": "forget"}` | Pair with a relay, or unpair |
| `POST /api/scan` | `{}` | Starts a network scan in the background |
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

Every answer carries the same four protective headers as the dashboard API, plus `Cache-Control: no-store`. Bodies over 64 KB are not read: a form counts as empty, and a relayed call gets `413`.

Wrong guesses are limited. When a limit is reached the answer is `429` with "Too many attempts. Please wait a few minutes and try again."

| What | Limit |
| --- | --- |
| Wrong passwords for one email | 5 in 15 minutes |
| Wrong passwords across all emails | 60 in 5 minutes |
| Wrong pairing codes, overall | 20 in 10 minutes |
| New accounts, overall | 10 an hour |

### Website (browser, session cookie)

| Request | Does |
| --- | --- |
| `GET /healthz` | `{"ok": true}` |
| `GET /login`, `GET /signup` | The forms |
| `POST /signup` | Form fields `email`, `password` (8 characters or more). Signs in and redirects to `/`. `403` when sign-up is switched off (`QUIETNET_SIGNUP`) |
| `POST /login` | Form fields `email`, `password` |
| `GET` or `POST /logout` | Clears the cookie |
| `GET /` | Your QuietNets, with pairing codes for those not yet paired. A code older than 15 minutes is replaced when this page is opened |
| `POST /pis/new` | Form field `name`. Creates a QuietNet and a pairing code |
| `POST /pis/<id>/delete` | Removes one of your QuietNets. Its Pi is locked out at once |
| `GET /pi/<id>/` | The dashboard page, set to call this Pi |
| `GET` or `POST /pi/<id>/api/…` | Passed to the Pi. Needs the header `X-QuietNet: 1` |

The session cookie is `qn_session`, valid for 14 days, `HttpOnly` and `SameSite=Lax`, and `Secure` when the request arrived over HTTPS.

Relayed calls can fail in these ways:

| Status | Meaning |
| --- | --- |
| `403` | The `X-QuietNet: 1` header is missing |
| `404` | Not signed in, not your Pi, or not an `/api/` path |
| `503` | The Pi is not paired, or has not been heard from for 40 seconds |
| `504` | The Pi did not answer within 30 seconds |
| `413` | The request body is over 64 KB |
| `502` | The Pi answered with a status outside 200–599 |

Any other status and body are the Pi's own.

### Pi side (`cloud_agent.py`)

| Request | Body or header | Returns |
| --- | --- | --- |
| `POST /agent/pair` | `{"code"}` | `{"ok", "id", "token"}`, or `400` with `{"error"}`. A code works once and for 15 minutes. `429` after too many wrong codes |
| `GET /agent/poll` | Header `X-QuietNet-Token` | Waits up to 25 seconds. `{}` if nothing to do, or `{"id", "method", "path", "body"?}`. `401` if the token is not recognised |
| `POST /agent/respond` | Header `X-QuietNet-Token`; `{"id", "status", "body"}` | `{"ok": true}` |

`body` in both directions is the JSON text as a string, passed through unchanged.
