# Changelog

## Unreleased

Fourth review (every part looked at again; 32 points fixed, known issues 46 to 77):
- **Fixed: the kill switch, internet-off and whole-house bedtimes also cut off QuietNet's own computer**, so a Pi lost its link to the relay and couldn't be switched back on from outside. Its own lookups are now exempt from these (ordinary blocks still apply). The dashboard no longer shows it as switched off, and refuses to switch it off.
- **Fixed: names that skip the checks could get out while a device's internet was off.** Home-network names, reverse lookups and names with odd characters now get the blocked answer then, and a packet QuietNet can't read is never passed on.
- **Fixed: home-network names went to 1.1.1.1 and 8.8.8.8.** `printer.lan`, `nas.home` and reverse lookups of home addresses now go to the home router, or get "no such name" if it isn't known.
- **Fixed: any website could sign you out of the relay.** Signing out is now a button that posts a form with a token; opening `/logout` only asks.
- **Fixed: the relay could be swamped.** Connections, waiting Pis, password checks, large answers (one per account, 48 MB in all), slow headers and slow uploads are all capped; every sign-in counts towards a limit, not just wrong ones; an account may hold 10 QuietNets and pair 20 a day.
- **Fixed: one stranger could stop everyone pairing** with wrong codes. They are now counted per network address, and a Pi started with `QUIETNET_PAIR` keeps trying its code while the relay is busy or down.
- **Fixed: the Pi's link to the relay could stop for good** after an unexpected answer, until the container was restarted. It now always tries again.
- **Fixed: with Docker and firewalld together, a steered device could lose its internet.** Each firewall table is checked on its own, and the advice names a command that suits each firewall in the way.
- **Fixed: schedules ran on UTC in the Pi container.** It now uses the Pi's time zone (see `TZ` in `docker-compose.yml`). If you had shifted schedule times to make up for UTC, put them back to real local times after rebuilding.
- **Fixed: one device could take every place for lookups.** Each may hold at most 16 at once.
- **Fixed: a misspelt `QUIETNET_SIGNUP` left sign-up open.** Unknown values now close it, with a warning.
- **Faster:** DNS answers never wait for the database; the history trim and device list use indexes properly; the enforcer's plan only works out what has changed; the status summary no longer rebuilds the advert lists; the relay finds Pis through indexes; with only `iptables`, nothing runs while no device is enforced.
- **Dashboard:** works again on Safari 12 to 14.0 (it stuck on "Starting…", and dialogs were off-screen); the four-second refresh no longer overlaps, pauses in a background tab, and fetches an open device's activity every 30 seconds.
- **Network scan:** covers the real size of the home network, up to 1,024 addresses; it no longer holds up the database while waiting for names; the Pi's own address is picked up when the network comes up or changes.
- **Mac:** pairing works with Python from python.org (it borrows the system's certificates), and the message names "Install Certificates.command" if needed. The launcher no longer runs Apple's Python stand-in a second time, and says how to get Python.
- Still open from this review: issues 78 to 83 (home names and the router, real-Pi checks, TCP per-device share, the list download on python.org Python, dashboard reads holding the database lock, the activity list sent in full).

Third review (the enforcer, the relay and the DNS filter), with an independent check of the fixes and a live test of the enforcer between two containers:
- **Fixed: the enforcer could cut a device off by mistake.** It now won't steer a device when the Pi isn't passing traffic on, or when another firewall (often Docker's) would drop it, and the device page says what to run on the Pi. It never steers the router, the Pi itself or another network, and leaves an address alone if a different device now has it.
- **Fixed: devices weren't always handed back.** A device switched off is handed back at once. After a crash or `docker kill`, the next start undoes what was left behind, using notes the enforcer keeps as it works. "Hand back" messages now come from the Pi's own hardware address (Wi-Fi was dropping them).
- **Fixed: a steered device slipped back to the router for a moment every half-minute.** The enforcer now answers its "who is the router?" questions itself. Measured: once settled, nothing got through in 60 to 146 seconds. Changes saved on the dashboard reach the enforcer at once rather than at its next two-second check. Still open: up to about three seconds of traffic can get through just after the kill switch is turned on (known issue 45).
- **Fixed: a plain-text request could pass the dashboard's JSON check** (`text/plain; application/json`). The type must now be exact, and changes sent from another website are refused. Works through an SSH tunnel on any port.
- **Fixed: strangers could lock the owner out of the relay** by guessing wrongly on purpose. A browser that has signed in before is let through (with the right password).
- **Fixed: longer remote history views failed** after 30 seconds: the relay's 64 KB limit applied to the Pi's answers. A paired Pi may now send up to 16 MB.
- **Faster remote dashboard:** the Pi handles up to eight relayed calls at once. A Pi can only answer calls sent to it.
- **DNS:** floods of lookups and slow TCP clients can no longer pile up; answers must repeat the question; history is capped by size as well as age.
- **Enforcer:** the advert list is no longer cut by address (it shares addresses with ordinary sites); pausing applies to the enforcer too; `iptables` waits for its lock and retries; kernel settings are read through `/proc/sys`, so they work in the slim container.
- **Containers:** `docker logs` shows output straight away; the compose file explains the one-time forwarding setting; the Pi image includes the `iptables` commands, used only to read the Pi's other firewall rules.
- An independent review of these changes found eleven more points, all fixed: the firewall check now fails closed; a flood of forged ARP questions can't start unlimited threads; `iptables` rules are reloaded after an outside flush; the "signed in before" marker has its own cap, is voided by a password change and removed at sign-out; only a call that is really waiting can bring a 16 MB answer; history is trimmed in small steps; one device's problem is shown only on that device's page; the enforcer tests no longer read the real network.

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
