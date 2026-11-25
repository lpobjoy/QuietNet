# Guide for agents (and people) working on QuietNet

Read this first. It is short, and it says what must stay true.

## What this is

A home network filter. Devices point their DNS at it; it records what they look up, blocks adverts, trackers and chosen services, and can cut live connections on a Raspberry Pi. An optional relay on a public host lets the owner reach it from outside.

- How it works, in full: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Every HTTP call: [docs/API.md](docs/API.md)
- Faults and gaps not yet fixed: [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md)
- Testing: [docs/TESTING.md](docs/TESTING.md)

## Where things are

| File | What it holds |
| --- | --- |
| `server.py` | DNS filter, rules engine, dashboard web server, start-up. A map of its sections is near the top |
| `enforcer.py` | Cuts live connections: ARP steering and firewall rules. Linux only |
| `cloud_agent.py` | The Pi's outbound link to the relay |
| `cloud/relay.py` | The relay: accounts, pairing, licences (and the owner's `licence` command line), the browser-to-Pi bridge. Deployed on its own; must not import the other programs |
| `static/index.html` | The dashboard. One file, served by both the Pi and the relay. Its script opens with notes for editors |
| `services.json`, `junk_domains.txt` | Data: blockable services and the built-in advert list |
| `install.sh` | The one-line installer for a Pi. Plain POSIX `sh` (dash, busybox ash, bash); everything in functions, only the last line runs; every value checked before use. Notes for editors at the top |
| `tests/` | One file per part. `test_quietnet.py` holds the shared helpers |
| `tests/test_installer.py` | Runs `install.sh` against stand-in commands; never real Docker, the network or the real `/etc` |

## Before you finish any change

```bash
python3 -m unittest discover tests
```

It takes about a minute and needs nothing installed. It must end in `OK`. Run it as an ordinary user if you can: as an admin user on Linux, the shutdown tests that start the real program are skipped.

## Rules

1. **Standard library only.** No third-party packages in the programs or the tests. A test enforces this.
2. **Every function and class has a docstring** that says what it does and, where it is not obvious, why. A test enforces this. Write for a reader who has not seen the rest of the file.
3. **Plain English, everywhere**: comments, error messages, the dashboard, the docs. Say "the router's hardware address", not "the gateway MAC". No jargon where an ordinary word will do. Messages shown to people should say what happened and what to do.
4. **Every behaviour change comes with a test**, named as a plain statement of the behaviour (`test_a_code_works_only_once`). One behaviour per test.
5. **Keep the docs true.** If you change a call, update `docs/API.md`. If you change how something works, update `docs/ARCHITECTURE.md`. If you fix or find a fault, update `docs/KNOWN_ISSUES.md`. Add a line to `CHANGELOG.md` under "Unreleased".
6. **Tests never touch the real network or the real data folder.** Use the stand-ins already in the test files. Never run the real `nft`, `iptables` or `sysctl` from a test.

## Security rules: do not loosen these without the owner's say-so

Each of these is the only thing standing between a hostile web page, or a stranger on the internet, and someone's home network. Each has tests.

- **The dashboard listens on `127.0.0.1` only and refuses any `Host` but localhost** (`Web.local_only`). Do not bind it to the home network or accept other host names.
- **Dashboard changes must arrive as JSON** (`Web.do_POST`). Do not accept form-encoded or plain-text bodies; that is the defence against forged cross-site requests.
- **Every relay handler that acts for a person starts with `user()` or `my_pi()`.** `my_pi()` is what keeps one account away from another's Pi.
- **Relayed API calls must carry the `X-QuietNet: 1` header** (`Relay.pi_request`).
- **Every value put into HTML is escaped**: `esc()` or `num()` in the dashboard, `html.escape()` in the relay. This includes ids and counts.
- **Nothing reaches a firewall rule unvalidated.** The enforced address goes through `ipaddress.IPv4Address`; addresses to drop come only from parsed DNS answers.
- **The enforcer's firewall text must delete the old table before defining the new one** (`nft_ruleset`). Loading a table that exists adds to it, and stale drop rules cut devices off.
- **Both web servers send the frame, nosniff and referrer headers on every answer** (`end_headers`).
- **Wrong guesses at the relay are counted and capped** (`Throttle`), and pairing codes expire.
- **Request bodies are capped** (`MAX_BODY`) on both servers.

## Things that are easy to get wrong

- **Rules live in two places.** `S` (memory) and the database. Change both, holding `db_lock`. See `block()` for the pattern.
- **`decision()` runs for every lookup.** Keep it free of database calls and anything slow.
- **The order of checks in `decision()` is behaviour people rely on.** It is tabulated in `docs/ARCHITECTURE.md`; change the two together.
- **The dashboard page is edited by the relay with a plain text replace** on the opening `head` and `body` tags. Keep exactly one of each, lower case, no attributes.
- **The three looks (themes) must each stay complete.** The dashboard's style sheet and the relay's `RELAY_CSS` set every colour and size name for each look under `[data-theme="..."]`, with Calm as the root default (the font stacks `--font-body` and `--font-mono` are shared from the root on purpose). A new colour or size name goes into all three looks (and Calm's and Household's dark sets), the markup stays free of fixed colours and inline styles, and nothing is loaded from other websites: no font files, `@import` or outside addresses. Theme names are checked against `calm`, `household` and `control` wherever the `qn_theme` cookie is read.
- **History queries must use an index.** `queries` can hold a month of a household's lookups. A test checks the query plans.
- **`cloud/relay.py` is deployed without the other programs.** It cannot import them.
- **Licence code stays on the relay and never answers 401.** It must never reach the Pi's blocking (`decision()`, the enforcer, the internet switches). A licence refusal is `402` or `403`, never `401`, which today's Pis take to mean "unpaired" and delete their token. Every licence decision reads `licence_state()`. Every refusal goes through `licence_gate()` (`pi_request`, `POST /pis/new`, `agent_pair`); the home page only reads `gate_on()` and `licence_state()` to decide what to show. The two rescue calls must keep working in every licence state.
- **Whatever `start_up()` starts, `clean_up()` stops and the tests stand in for.** One line in each (`server.py`); every thread a daemon thread, because Python waits at exit for any other (lookups in hand once kept the program running for 20 seconds after "QuietNet stopped."); and a stand-in in `WholeLife.setUp` (`tests/test_start_stop.py`), or those tests start the real thing inside the test program. A request to stop is only ever noted, never raised as an exception. See "Starting and stopping" in `docs/ARCHITECTURE.md`.
- **Python 3.9 must still work** for the programs: the macOS launcher prefers the Python that Apple supplies. Avoid newer syntax such as `match` or `X | Y` type hints at run time.
- **A test must not depend on the time of day or on a sleep being long enough.** For a schedule that is in force now, use `in_force_now()` from `tests/test_quietnet.py`, never a fixed window such as 00:00 to 23:59. See "Writing more" in `docs/TESTING.md`.

## Working method

- Work on a branch and open a pull request; do not push to `main`.
- Keep a change to one concern where you can.
- The enforcer and the containers cannot be fully tested here. If you change either, say so in the pull request and list what needs checking on a real Pi (`docs/TESTING.md` has the manual steps).
