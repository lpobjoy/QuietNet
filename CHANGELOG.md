# Changelog

## Unreleased

Docker's firewall and "Cut live connections" (23 November):
- **New: the installer can make Docker's firewall let passed-on traffic through for good.** Docker drops traffic the Pi passes on, so "Cut live connections" asked people to run `sudo iptables -I DOCKER-USER -i wlan0 -o wlan0 -j ACCEPT`, and that was lost at every restart. After asking (or with `--yes`), the installer now adds a small systemd service, `quietnet-forward`, that puts this one rule back every time Docker starts, for the network connection the Pi reaches its router on. It lets through only traffic that comes in on that connection and goes straight back out on it. It is skipped, with a note, without systemd or iptables, and a service of the same name made by hand is left alone. `--uninstall` says how to remove it. **To get it on a Pi already installed, run the install line again.**
- The device page's firewall advice now says a command run by hand lasts until the Pi restarts and, for Docker's firewall, that running the install line again makes it permanent.

Device names (23 November):
- **New: QuietNet suggests a name for most devices** instead of "Unnamed device". It asks the devices themselves, in the ways they already answer: Bonjour (Apple devices, printers, TVs, speakers, Linux), the Windows network (Windows PCs, network drives), UPnP (TVs, Sonos, consoles, routers), the names devices give when they join the network (DHCP, on a Pi only) and, as before, the router. The new `names.py` does this; **rebuild the Pi container** to include it.
- The Devices page shows a suggestion marked as one, with where it came from and a **Use this name** button. A model or maker the device reported, or "Private Wi-Fi address, so probably a phone, tablet or laptop", shows under an unnamed device.
- `/api/devices` items have two new fields, `hint_source` and `hint_detail`; `hint` is now tidied for people (`Lewiss-iPhone.local` becomes `Lewiss iPhone`).
- **The Pi now sends small name questions on the home network every two minutes and listens on UDP ports 5353 and 67** (known issue 89). `--no-device-names` turns this off.
- Everything heard is treated as untrusted: every packet reader is bounded, UPnP descriptions are fetched only from the device's own address with size and time limits, and a round of asking never takes much more than 5 seconds.
- **Fixed before release (review):** on the Pi the DHCP listener no longer takes UDP port 67, so a DHCP server started on the Pi after QuietNet (dnsmasq, a hotspot) still starts; it reads packets through a system filter instead. A Bonjour announcement is no longer passed to the next device given the same address, and ages out 6 hours after it was heard. A Bonjour answer naming another device's address is ignored. Machine-made names (a Chromecast's identity number, `Sonos-` plus a hardware address) are no longer suggested, so the device's friendly name wins. A UPnP device sending its answer a byte at a time can no longer keep a download, and a thread, going past its 2 seconds, and a description is not fetched again while one is under way. DHCP names put in the overflow fields (option 52) are read. On the device list, the suggestion is plain text; **Use this name** is on the device page, where keyboards can reach it.

One-line install for a Pi (23 November):
- The relay's pages no longer show an emoji beside the QuietNet name, and a test keeps emoji out of the relay and the dashboard.
- **New: `install.sh`, a one-line installer** for Raspberry Pi OS and other Debian or Ubuntu style Linux: `curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh`. It offers to install Docker (with Docker's own script), downloads QuietNet into `/opt/quietnet`, offers to free port 53 from systemd-resolved, switches on traffic forwarding for "Cut live connections", builds and starts the container (Compose project `quietnet`), and says what to set in the router. `--relay` and `--code` pair it with your relay in the same step. Running it again updates in place, keeping history and rules in the `quietnet_quietnet-data` volume; `--uninstall` removes it and keeps them. Starting by hand with `docker compose up -d` still works.
- **New: the relay's page shows the exact install line** for each QuietNet waiting to be paired, with the relay's address and the code filled in, above the manual steps for a Pi already running QuietNet. An account with no QuietNets is told how to start. The relay's address comes from `QUIETNET_RELAY_URL`, then Railway's `RAILWAY_PUBLIC_DOMAIN`, then the page's own address, and is used only if it is a plain address; `QUIETNET_INSTALL_URL` changes where the line fetches the installer from.
- **Fixed in the installer before release:** when it uses `sudo`, it checks once at the start that sudo works and, if not, says so plainly (and suggests `ssh -t`) instead of blaming a later step; folder checks run as root, so a folder the person cannot read is never taken for empty, and a working copy with its own `data/` folder or `.git` is never replaced; a `quietnet` container with no Compose project label (started with `docker run`) is no longer replaced on install or removed on uninstall; the message about another container says it "already exists", not that it is running; when Docker's script fails, or the Compose plugin is missing, it points to Docker's own install guides rather than Debian's packages, which lack the plugin. The closing message now gives the SSH tunnel line for opening the dashboard from another computer.
- **Fixed: the relay's install line never uses a `QUIETNET_RELAY_URL` the installer would refuse.** `http://` is used only for exactly `localhost` or `127.0.0.1`; any other `http://` address is ignored, and the line falls back to `RAILWAY_PUBLIC_DOMAIN` or the page's own address (`usable_relay_url`).
- Open points, mostly about running it on a real Pi and installing from GitHub's `main` branch without a signature check, are known issues 85 to 88.

Known issues closed (23 November; nine closed, five narrowed, see `docs/KNOWN_ISSUES.md`):
- **Changed: the relay now allows only the first account by default** (`QUIETNET_SIGNUP` defaults to `first`, was `open`). A relay that already has accounts keeps them and they can still sign in, but nobody new can sign up unless you set `QUIETNET_SIGNUP=open`. The start-up log says which setting is in force (issue 6).
- **Changed: signing out of the relay now signs you out everywhere**, in every browser and any copied cookie. The session cookie has a new form, so **everyone signed in to the relay before the upgrade will need to sign in again** once (issue 7).
- **Fixed: Firefox's secure DNS and iCloud Private Relay could take lookups past QuietNet.** QuietNet now gives the answers that tell them to use the network's DNS; these lookups show as blocked in history (issue 8).
- **Fixed: devices given an IPv6 DNS address skipped QuietNet.** The filter now also listens on IPv6, and carries on with IPv4 alone if it can't. The device page now says that "Cut live connections" works on IPv4 only (issue 5; IPv6 steering is still open).
- **Fixed: a relay address starting with `http://` was accepted**, which would send the Pi's key unprotected. It is refused unless the relay is on the same computer (`localhost`, `127.0.0.1`, `::1`). A Pi already paired over `http://` to another computer stops connecting and asks to be paired again with `https://` (issue 20).
- **Relay hardening:** Pi tokens are stored only as a hash (existing ones are converted at start-up; no re-pairing needed); forms sent from another website are refused, which stops login forgery in current browsers; sign-up no longer says whether an email already has an account, and no longer signs you in, so sign in after creating your account; limits on guessing survive a restart; the relay gives up root at start-up and runs as `nobody` (or `QUIETNET_RUN_AS=uid:gid`) after taking over its data folder (issues 7, 19, 21).
- **Faster: answers are remembered** for their (shortened) lifetime, so repeat lookups don't go to the internet each time. Rules are still checked for every lookup first, and any rule change clears the memory (issue 22).
- **Faster dashboard:** history questions use a read-only database connection of their own, so they never hold up rule changes or the history writer; clearing a busy device's history goes in steps; an open device's activity list is only sent again when it has changed (issues 82, 83).
- **Home names:** single-word names such as `nas` go to the home router, never the internet; a router that sends lookups back to QuietNet can't make the two ask each other for ever (issue 78).
- **Fair shares:** one device may hold at most 8 of the 64 TCP lookup connections (issue 80).
- **Mac:** the community list download works with Python from python.org without "Install Certificates.command" (issue 81).
- **Smaller:** the Devices page says when a scan covered only part of a large network; rows are spaced properly on Safari before 14.1; the README and `server.py` now say blocked names get the address `0.0.0.0` (issue 12).
- New point found while checking: remembered answers don't take each device's extended DNS settings into account (issue 84, minor). Fixed the same day (below).

Faults in those fixes, found by an independent check and fixed the same day:
- **Fixed: a device asking from its own IPv6 address escaped its device and group rules.** Its IPv6 address is now matched to its IPv4 address by hardware address; if it can't be matched while device or group rules exist, it is refused and asks over IPv4 instead. The Pi image now includes `iproute2` for this, so **rebuild the Pi container** (issue 5).
- **Fixed: over IPv6 the filter answered anyone on the internet** whose router firewall let them through. It now answers home addresses only (issue 5).
- **Fixed: remembered answers** could use a lot of memory (answers over 4 KB are no longer kept), could be too big for the device asking over UDP, and could hand an unchecked answer fetched for one device to the others (issues 22, 84).
- **Fixed: devices that check DNS signatures failed every `.com` lookup** when the router was unknown, because `com` was treated as a home name (issue 78).
- **Fixed:** a new community list of the same size now refreshes open activity pages; clearing one device's history answers at once and carries on in the background (issues 82, 83).
- **Relay:** handing over the data folder never follows links and touches only the relay's own files; a refused change of user stops the relay with a plain message; a forged session cookie with a huge number no longer crashes the request; two sign-ups at once on a new relay can't both get in (issues 6, 7, 21).

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
- Left open by this review: issues 78 to 83 (home names and the router, real-Pi checks, TCP per-device share, the list download on python.org Python, dashboard reads holding the database lock, the activity list sent in full). All but the real-Pi checks were fixed on 23 November (above).

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
