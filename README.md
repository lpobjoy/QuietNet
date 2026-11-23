# QuietNet

See what every device in your home is talking to, block the adverts and trackers, and switch off apps, services or the whole internet for a device or a group of devices — from one simple dashboard.

> **Proprietary software.** The code is public so it can be read, but it is not free to use. Anyone who wants to use QuietNet needs a paid licence — see [Licence](#licence).

## What it does

- **Shows what each device contacts** — grouped by company, with plain labels such as "Advert / tracker" and "Possibly junk".
- **Blocks adverts and trackers automatically**, using a built-in list plus an optional community list of over 70,000 addresses.
- **One-click Block / Unblock** on anything a device talks to.
- **Blocks whole apps and services** — Fortnite, Roblox, YouTube, Netflix, Disney+, TikTok, Snapchat, Discord and more.
- **Rules for one device, a group, or the whole house** — make a "Kids" or "TVs" group and control them together.
- **Internet on/off switch** for any device or group.
- **Schedules** — block apps, services or all internet automatically at set times (bedtime, homework, school nights), per device, group or whole house.
- **Kill switch** — one button stops all internet everywhere until you turn it back on.
- **Cut live connections** (Raspberry Pi) — optionally stop a device even mid-stream, not just new connections. See below.
- **Finds the devices on your network**, with their hardware addresses and a suggested name for each, found by asking the devices themselves (Bonjour, the Windows network, UPnP, DHCP and the router). One click uses the suggestion.
- **Pause advert blocking for 10 minutes** when a website or app misbehaves.

## Start it

**On a Mac (for trying it out):** double-click **Start QuietNet.command**. A window opens (leave it open) and the dashboard appears at <http://localhost:8377>. The first time, macOS may ask whether Python can accept incoming connections, or find devices on your local network — choose **Allow** for both.

If the launcher says it can't find a working Python, install it from [python.org](https://www.python.org/downloads/macos/) or run `xcode-select --install`. With Python from python.org, pairing with a relay borrows the Mac's own security certificates; if it still says the relay's certificate couldn't be checked, open that Python's folder in Applications and double-click **Install Certificates.command**, then restart QuietNet.

**On a Raspberry Pi (for leaving it running): one line.** On Raspberry Pi OS, or another Debian or Ubuntu style Linux, run:

```bash
curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh
```

It checks for Docker and, if it is missing, asks before installing it with Docker's own script from get.docker.com. It then downloads QuietNet into `/opt/quietnet`, frees DNS port 53 if the computer's own name service (systemd-resolved, common on Ubuntu) holds it (it asks first), switches on traffic forwarding for **Cut live connections** and (after asking) adds a small service, `quietnet-forward`, that lets that traffic through Docker's firewall after every restart, and builds and starts the container. At the end it prints the Pi's address on your home network: set that as the DNS server in your router, and have the router always give the Pi that same address. Administrator steps go through `sudo`, which may ask for your password; when running it over SSH, use `ssh -t` so it can. Because the dashboard opens only on the Pi itself, the closing message also gives the SSH tunnel line for opening it from another computer.

- **Pair with your relay in the same step.** On your relay, choose **Add a QuietNet**. The page shows the exact line to run, with the relay's address and a pairing code filled in, for example:

  ```bash
  curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh -s -- --relay https://your-relay.up.railway.app --code A1B2-C3D4
  ```

  The code works once and for 15 minutes. `--relay` and `--code` must be given together. A Pi that is already paired keeps its pairing and ignores a new code.
- **Update** by running the same line again. The program files are replaced; your history and rules are kept, because they live in Docker's `quietnet_quietnet-data` volume, not in `/opt/quietnet`.
- **Uninstall** with `curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh -s -- --uninstall`. It stops QuietNet and removes `/opt/quietnet`, keeps your history and rules, and says how to delete them (`sudo docker volume rm quietnet_quietnet-data`) and how to undo the forwarding, `quietnet-forward` and systemd-resolved changes.
- **Other options:** `--yes` answers yes to every question (for installs with no one at the keyboard; without it and without a terminal, the installer stops rather than install Docker or change systemd-resolved), `--ref NAME` installs a branch or tag other than `main`, and `--help` lists everything. `QUIETNET_DIR` chooses another folder.

The installer always installs from GitHub's `main` branch (or the `--ref` you give), and nothing checks a signature on what it downloads; see known issue 86. You can read [install.sh](install.sh) before running it.

**By hand, on a Raspberry Pi or any Linux box:** with Docker installed, in this folder, run:

```bash
docker compose up -d
```

QuietNet then runs all the time and restarts with the machine. It installs nothing from the internet — the container is just Python and QuietNet's own code. Host networking is used so QuietNet can see the home network and answer DNS on port 53. If you run it this way from a folder called `QuietNet` and later use the installer, the installer takes over the same container and data. Started from a folder with any other name, the installer stops rather than fight over the container, and says how to stop the old one (its history and rules stay in that folder's own volume).

Schedules follow the Pi's own time zone, summer time included: the compose file shares it with the container. To choose a zone by name instead, start with `TZ=Europe/London docker compose up -d` (never set `TZ` to nothing, which means UTC). On Docker Desktop for Mac or Windows the shared zone is usually UTC, so set `TZ` by name there. If you upgraded from a version before this and had shifted your schedule times to make up for UTC, rebuild with `docker compose up -d --build` and put them back to the real times.

The dashboard only opens on the computer QuietNet runs on, at <http://localhost:8377>. On a Pi with no screen, reach it one of two ways:

- **Through your relay** (see [Reach it from anywhere](#reach-it-from-anywhere-optional)). The easiest way is the line the relay shows, which installs and pairs in one go (above). If you started QuietNet by hand, create a pairing code on the relay, then start the Pi with the relay's address and the code:

  ```bash
  QUIETNET_CLOUD=https://your-relay.up.railway.app QUIETNET_PAIR=A1B2-C3D4 docker compose up -d
  ```

  The code is used once. After that the Pi remembers the pairing and a plain `docker compose up -d` is enough.
- **Through an SSH tunnel** from another computer on your network: `ssh -L 8377:localhost:8377 pi@<the-pi's-address>`, then open <http://localhost:8377> on that computer.

> Running it on an always-on box like a Raspberry Pi is the intended setup: it works for every device in the house without touching your router, and it doesn't depend on your Mac being awake.

## Use it

1. On the **Devices** page press **Find devices on my network** and give your devices friendly names.
2. Open **Set up a device** and follow the steps to point a phone, TV or tablet at QuietNet (or the whole house, via your router).
3. Use the device for a few minutes, then open it on the **Devices** page:
   - press **Block** on anything you don't want it talking to;
   - press **Choose services** to block apps such as Fortnite or Disney+;
   - flip the **Internet** switch to cut it off completely.
4. Use **Groups** to apply the same switches to several devices at once, and **Blocked list** for whole-house rules.

## How it works

Every device has a setting called DNS — the "phone book" it uses to find addresses on the internet. When a device is pointed at QuietNet, it asks QuietNet first. QuietNet writes the request down, then either passes it on (to 1.1.1.1, with 8.8.8.8 as a spare) or, if it's blocked, answers with the address `0.0.0.0` (`::` for IPv6), which devices treat as "can't be reached". Names that only exist on your home network, such as `printer.lan` or a plain `nas`, are asked of your router instead and never leave the house. Repeat lookups within a couple of minutes are answered from memory, but your rules are always checked first, so a block bites on the very next lookup. QuietNet answers on both IPv4 and IPv6, where the computer has it.

Rules are checked in this order: internet switched off → addresses you blocked or allowed yourself → blocked services → the advert list. The kill switch, internet switches and bedtimes never cut off the QuietNet computer itself, so it keeps its link to your relay and can always be switched back on from outside.

## Cutting live connections (the enforcer)

A normal block only stops a device *finding* an address. If a Disney+ stream is already playing, the device already has the connection open, so the block doesn't interrupt it until it next reconnects. The **enforcer** closes that gap.

When you turn on **Cut live connections** for a device (on that device's page), QuietNet — running on the Raspberry Pi — tells that device "I am the router", so the device's traffic flows through the Pi. The Pi forwards everything as normal **except** packets heading for an address that's blocked for that device, which it drops. So a blocked Disney+ stream dies within seconds, bedtime and the kill switch become instant for that device, and everything else it does is untouched.

- **Raspberry Pi / Linux only.** It uses the Pi's network directly, so it needs the container's `NET_RAW` and `NET_ADMIN` privileges (already set in `docker-compose.yml`) or to run as root. On a Mac it simply reports itself off, and ordinary DNS blocking still applies.
- **One-time Pi setting.** The Pi must be allowed to pass traffic on, which a container can't switch on by itself. The one-line installer does this for you. If you started QuietNet by hand, run this once on the Pi:

  ```bash
  echo net.ipv4.ip_forward=1 | sudo tee /etc/sysctl.d/90-quietnet.conf && sudo sysctl --system
  ```

  If it's missing — or another firewall on the Pi (often Docker's own, or firewalld) would drop the traffic — QuietNet **won't steer** the device rather than cut it off, and the device's page says exactly what to run for each firewall in the way. A command run by hand lasts until the Pi restarts. For Docker's firewall, running the install line again (with `--yes`, or answering yes) makes it permanent: it adds the `quietnet-forward` service, which lets through only traffic that comes in on the Pi's network connection and goes straight back out on it, and puts that rule back every time Docker starts. With firewalld or ufw, that command lasts until the firewall reloads, so also add the rule to that firewall's own settings.
- **Opt-in per device.** It only ever touches devices you switch it on for — never the router, the Pi itself, or anything outside your home network — and hands each device straight back to the router when you switch it off. If a different device later gets the same network number, it's left alone.
- **Safe if stopped suddenly.** `docker stop`, a restart or a crash all end with devices handed back to the router: QuietNet notes what it changed, and puts it back first thing at its next start if it didn't get the chance.
- **Works best when the device uses QuietNet for DNS** (the normal setup), because that's how QuietNet learns which addresses belong to Disney+, Fortnite and so on.
- **It cuts by address, for things you chose:** blocked services, schedules, the internet switch, the kill switch and addresses you blocked yourself. The advert list isn't enforced this way, because advert addresses are often shared with ordinary sites. If a blocked service shares an address with a site the device is allowed (YouTube and Google search, Classroom and Gmail do; so do many sites on Cloudflare or Fastly), that address is not cut, so the allowed site keeps working; the blocked service is still blocked by name, so it can't open new connections there. The device page says when this happens. Switching the enforcer off for the device removes all of this instantly.
- **IPv4 only.** A device that also uses IPv6 can keep connections made that way; DNS blocking still applies to it. The device's page says so.
- Everyone on the network should know it's in use — it steers a device's traffic through the Pi.

## Reach it from anywhere (optional)

By default the dashboard only opens on your home network. If you want to check or change things while you're out, QuietNet comes with a small **relay** you host yourself (for example on [Railway](https://railway.app)).

Because the Pi can't usually be reached from the internet directly, it works the other way around: the Pi makes an outgoing connection to your relay and holds it open, and your browser's requests travel down that line. **No router changes are needed.**

1. Deploy the relay — see [`cloud/README.md`](cloud/README.md). You get a web address like `your-relay.up.railway.app`.
2. Open it, create your account, then sign in with it, and choose **Add a QuietNet** to get a pairing code. By default only the first account can be created (`QUIETNET_SIGNUP=first`), so create yours straight away; set `QUIETNET_SIGNUP=open` on the relay if other people need accounts of their own.
3. **New Pi:** run the one line the relay's page shows on the Pi. It installs QuietNet and pairs it (see [Start it](#start-it)). **Pi already running QuietNet:** on the Pi's own dashboard, open **Set up a device → Remote access**, enter the relay address (it must start with `https://`, or have no scheme at all) and the code. (On a Pi with no screen, pass them when starting the container instead — see [Start it](#start-it).)

After that, sign in to the relay from anywhere to control your Pi. Only your account can reach it, and the relay never stores your history or rules — it just passes your requests through to the Pi while you're looking. **Sign out** signs you out on every browser and device at once.

## Good to know

- This computer has to be on and awake for the devices pointed at it to work.
- A device only shows activity, and can only be blocked, once it has been pointed at QuietNet.
- QuietNet sees which addresses are contacted (e.g. `ads.example.com`), never the content of pages or messages.
- It can't remove adverts that come from the same address as the real content (e.g. YouTube adverts).
- Blocking isn't instant: a device may carry on for a few minutes until it next looks an address up. A few apps use their own built-in phone book and can get around it. QuietNet tells Firefox to switch off its own secure DNS and Apple devices to switch off iCloud Private Relay on your network; It also blocks the well-known encrypted DNS services (Google, Cloudflare, Quad9, NextDNS and others) so Android's "Private DNS" and browsers' "secure DNS" fall back to QuietNet, and flags a device that tries them. With "Cut live connections" on, a device's lookups sent to another DNS server such as 8.8.8.8 are answered by QuietNet too. Android's "Private DNS" setting should still be left off (or on Automatic) on devices you want covered.
- Devices are recognised by their network number (IP address), and QuietNet follows each one by its hardware address: when a device with rules gets a new number, its name and rules move with it within a minute, and if its old number goes to another device, the rules are paused rather than applied to the wrong one. A phone or tablet that makes up a new **private Wi-Fi address** looks like a brand-new device, so choose **New devices go into group** on the Groups page (for example your children's group) to keep new ones covered; the home page also offers to move the rules when a device with rules goes quiet just as a new one appears. Reserving each device's number in your router still helps.
- History is stored only on this computer, in the `data` folder, for 30 days. Tell the people in your home that it's running.
- The dashboard can only be opened on the computer QuietNet runs on.
- **Appearance.** The dashboard and the relay's pages come in three looks: **Calm** (the default, with the sections down the side), **Household** (warmer, with devices and groups as large cards) and **Control room** (dark and compact, with the day's figures across the top). Calm and Household follow your device's light or dark setting; Control room is always dark. Choose one under **Appearance**, at the end of **Set up a device** or from the Appearance button at the top of the dashboard, and on the relay's home page. The choice is remembered by that browser only (in a cookie), and changes nothing on your network. The pages use the fonts already on your device; nothing is downloaded.

## Built from scratch

QuietNet uses no third-party packages or libraries. Everything — the DNS filter, the network scan, the web server and the dashboard — is written in this repository and needs only Python 3 (already on a Mac).

| File | What it is |
| --- | --- |
| `server.py` | The main program: DNS filter, rules, network scan and dashboard server |
| `names.py` | Finds names for the devices on your network by asking them (Bonjour, Windows network, UPnP, DHCP and the router) |
| `enforcer.py` | The live-connection enforcer (ARP + kernel firewall, Linux/Pi) |
| `cloud_agent.py` | The Pi's outbound link to the relay (for remote access) |
| `cloud/` | The relay you host (e.g. on Railway) to reach your Pi from anywhere |
| `static/index.html` | The dashboard (works locally and through the relay) |
| `services.json` | The apps and services that can be blocked, and the addresses each one uses |
| `junk_domains.txt` | The built-in advert and tracker list |
| `Start QuietNet.command` | Double-click launcher for macOS |
| `install.sh` | The one-line installer for a Raspberry Pi or other Debian or Ubuntu style Linux: installs, updates, pairs and uninstalls |
| `Dockerfile`, `docker-compose.yml` | Run it in a container on a Pi or any Linux box |
| `tests/` | Automated checks for every part: rules, DNS, dashboard API, enforcer, relay, remote link and installer (standard library only) |
| `docs/` | How it works, the API, how to test it, and known issues |
| `AGENTS.md` | Rules for anyone, person or AI agent, changing the code |
| `data/` | Created when it runs: history, your rules, downloaded list (never uploaded) |

Options for advanced use: `python3 server.py --dns-port 53 --web-port 8377 --no-browser`.

See [CHANGELOG.md](CHANGELOG.md) for what changed in each version.

## Documentation

- [How QuietNet works](docs/ARCHITECTURE.md) — the parts, what happens to a lookup, the order rules are checked in, the enforcer, remote access, the security model, and what is stored.
- [API reference](docs/API.md) — every call the dashboard and the relay accept.
- [Testing](docs/TESTING.md) — how to run the tests and what they cover.
- [Known issues](docs/KNOWN_ISSUES.md) — faults and gaps found in review, with suggested fixes.
- [Hosting the relay](cloud/README.md)
- [Guide for agents](AGENTS.md) — what must stay true when changing the code.

Run the tests with `python3 -m unittest discover tests`.

## Licence

Copyright © 2026 lpobjoy. All rights reserved.

QuietNet is proprietary. You may read the code here, but you may not run, copy, modify or share it without a paid licence. To buy one, get in touch through <https://github.com/lpobjoy>. Full terms are in [LICENSE](LICENSE).
