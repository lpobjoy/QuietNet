# Changelog

## Unreleased

Second review (security, dependencies, efficiency):
- **Fixed: enforcer rules piled up.** Reloading the firewall table added to the old rules, so a device switched off and back on stayed cut off until QuietNet restarted. Each load now replaces the table.
- **Fixed: the dashboard could be shown inside another website** and its buttons clicked by trickery. Both web servers now forbid that.
- **Fixed: forged DNS answers** from a sender other than the server asked are now ignored.
- **Relay hardening:** wrong passwords and pairing codes are counted and capped; pairing codes last 15 minutes; unknown emails take as long to refuse as wrong passwords; sign-up can be closed with `QUIETNET_SIGNUP=first` or `closed`; request bodies are capped at 64 KB.
- **Dashboard:** ids and counts are escaped like every other value; input of the wrong type gets a clean refusal; only a real IPv4 address can be enforced.
- **Privacy on shared machines:** the data folders and the saved relay token are readable by their owner only.
- **Faster dashboard:** today's totals and the device list are answered from an index, where before they read the whole history. Less disk forcing, which suits an SD card.
- **For whoever works on this next:** every function and class now has a docstring (a test keeps it so); `server.py` and `relay.py` open with a map; the dashboard script opens with notes for editors; `AGENTS.md` sets out the rules.
- **Automatic checks:** the tests run on every pull request, and GitHub will propose an update when a newer Python base image is published.

First review:
- **Fixed: the Pi container did not start.** The `Dockerfile` left out `cloud_agent.py`, which 0.5 began to need.
- **Fixed: no way in on a Pi with no screen.** The dashboard only opens on the Pi itself, but the README pointed to the Pi's network address. `docker-compose.yml` now accepts `QUIETNET_CLOUD` and `QUIETNET_PAIR` so the Pi can be paired with a relay at start-up, and the README describes this and the SSH tunnel alternative.
- **Fixed: the enforcer left its changes behind on shutdown.** Stopping QuietNet (Ctrl-C or `docker stop`) now waits while the enforcer hands devices back to the router, removes its firewall table and restores the kernel settings.
- **Documentation** in `docs/`: how QuietNet works, an API reference, a testing guide, and a list of known issues from a review of 0.5.
- **Tests** for the parts that had none: the DNS packet handling, the dashboard API, the enforcer's behaviour, the relay, the Pi's link to the relay, and the packaging. 312 tests in all, up from 37.
- Corrected the relay's description of password storage: it uses PBKDF2, not scrypt.

## 0.5 — 2026-11-20
- **Reach your QuietNet from anywhere.** A new relay service (`cloud/`, host it on Railway) lets you sign in to a website and control your home Pi remotely — with no router changes, because the Pi connects *out* to the relay and holds the line open.
- Accounts (email + PBKDF2-hashed password), signed session cookies, and pairing: create a code on the relay, enter it on the Pi's **Remote access** page.
- Only you can reach your Pi: per-account isolation, a CSRF guard on relayed calls, and HTTPS (provided by Railway). The relay never stores your history or rules — those stay on the Pi.
- One dashboard works both locally and through the relay.
- Full remote flow tested locally end-to-end; relay runs as its own container.

## 0.4 — 2026-11-20
- **Live-connection enforcer (per device).** Normally a block only stops new connections; the enforcer also cuts things already running (e.g. a Disney+ stream mid-play). On a Raspberry Pi it steers a chosen device's traffic through QuietNet and drops only what's blocked for that device, forwarding everything else. Bedtime and the kill switch become instant for that device. Strictly opt-in per device, with clean start/stop that restores the network.
- Reuses the existing rules: QuietNet records the addresses it hands out, so it knows which belong to Disney+, Fortnite, etc.
- Linux/Raspberry Pi only (uses raw ARP + the kernel firewall `nft`); the container now includes `nftables`. On macOS the enforcer reports itself off and blocks still apply to new connections.
- More tests (ARP frame layout, firewall rule generation, the block plan).

## 0.3 — 2026-11-20
- **Schedules:** block apps, services or all internet automatically at set times — bedtime, homework, school nights — per device, per group or house-wide. Overnight windows (e.g. 21:00–07:00) supported.
- **Kill switch:** one button stops all internet for every device using QuietNet, until you turn it back on.
- Blocks, schedules and the kill switch now bite on connections within ~2 minutes (answer lifetimes are shortened).
- **Runs in a container** (`Dockerfile` + `docker-compose.yml`) for easy, portable setup on a Raspberry Pi or any Linux box.
- Device scan now works on Linux by reading the kernel's neighbour table directly (no extra tools, works in a plain container).
- Added an automated test suite (`tests/`), standard library only.
- Fixes from a code review: malformed schedule data can no longer corrupt saved schedules; unblocking during a bedtime schedule no longer leaves a stray permanent allow; pausing still respects explicit allows; malformed DNS replies are passed through untouched.

## 0.2 — 2026-11-20
- Block whole apps and services (Fortnite, Disney+, YouTube, TikTok and more) with one tap.
- Rules per device, per group, or for the whole house.
- Groups (e.g. "Kids", "TVs") to control several devices at once.
- Internet on/off switch for a device or a group.
- "Find devices on my network": scans the home network for every device, with hostname and hardware address.
- Pausing now only pauses advert blocking; service blocks and switched-off devices stay blocked.
- Launcher prefers the Python that Apple supplies, which macOS allows to see other devices on the network.

## 0.1 — 2026-11-19
- First version: DNS filter that records which addresses each device contacts.
- Dashboard with per-device activity, advert/tracker labels and one-click block/unblock.
- Built-in junk list plus optional download of a large community list.
- Step-by-step guide for pointing devices at QuietNet.
