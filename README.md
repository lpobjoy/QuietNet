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
- **Finds the devices on your network**, with their names and hardware addresses, so you can name and group them.
- **Pause advert blocking for 10 minutes** when a website or app misbehaves.

## Start it

**On a Mac (for trying it out):** double-click **Start QuietNet.command**. A window opens (leave it open) and the dashboard appears at <http://localhost:8377>. The first time, macOS may ask whether Python can accept incoming connections, or find devices on your local network — choose **Allow** for both.

**On a Raspberry Pi or any Linux box (for leaving it running):** with Docker installed, run:

```bash
docker compose up -d
```

QuietNet then runs all the time and restarts with the machine. It installs nothing from the internet — the container is just Python and QuietNet's own code. The dashboard is at `http://<the-pi's-address>:8377`. Host networking is used so QuietNet can see the home network and answer DNS on port 53.

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

Every device has a setting called DNS — the "phone book" it uses to find addresses on the internet. When a device is pointed at QuietNet, it asks QuietNet first. QuietNet writes the request down, then either passes it on (to 1.1.1.1, with 8.8.8.8 as a spare) or, if it's blocked, answers "that doesn't exist".

Rules are checked in this order: internet switched off → addresses you blocked or allowed yourself → blocked services → the advert list.

## Cutting live connections (the enforcer)

A normal block only stops a device *finding* an address. If a Disney+ stream is already playing, the device already has the connection open, so the block doesn't interrupt it until it next reconnects. The **enforcer** closes that gap.

When you turn on **Cut live connections** for a device (on that device's page), QuietNet — running on the Raspberry Pi — tells that device "I am the router", so the device's traffic flows through the Pi. The Pi forwards everything as normal **except** packets heading for an address that's blocked for that device, which it drops. So a blocked Disney+ stream dies within seconds, bedtime and the kill switch become instant for that device, and everything else it does is untouched.

- **Raspberry Pi / Linux only.** It uses the Pi's network directly, so it needs the container's `NET_RAW` and `NET_ADMIN` privileges (already set in `docker-compose.yml`) or to run as root. On a Mac it simply reports itself off, and ordinary DNS blocking still applies.
- **Opt-in per device.** It only ever touches devices you switch it on for, and it restores the network cleanly when switched off or stopped.
- **Works best when the device uses QuietNet for DNS** (the normal setup), because that's how QuietNet learns which addresses belong to Disney+, Fortnite and so on.
- **It blocks by address.** If a blocked service shares an address with something else (big content networks sometimes do), that other thing can be affected too. Switching the enforcer off for the device removes all of this instantly.
- Everyone on the network should know it's in use — it steers a device's traffic through the Pi.

## Good to know

- This computer has to be on and awake for the devices pointed at it to work.
- A device only shows activity, and can only be blocked, once it has been pointed at QuietNet.
- QuietNet sees which addresses are contacted (e.g. `ads.example.com`), never the content of pages or messages.
- It can't remove adverts that come from the same address as the real content (e.g. YouTube adverts).
- Blocking isn't instant: a device may carry on for a few minutes until it next looks an address up. A few apps use their own built-in phone book and can get around it.
- Devices are recognised by their network number (IP address). Reserve each device's number in your router so its name and rules stay with it.
- History is stored only on this computer, in the `data` folder, for 30 days. Tell the people in your home that it's running.
- The dashboard can only be opened on the computer QuietNet runs on.

## Built from scratch

QuietNet uses no third-party packages or libraries. Everything — the DNS filter, the network scan, the web server and the dashboard — is written in this repository and needs only Python 3 (already on a Mac).

| File | What it is |
| --- | --- |
| `server.py` | The main program: DNS filter, rules, network scan and dashboard server |
| `enforcer.py` | The live-connection enforcer (ARP + kernel firewall, Linux/Pi) |
| `static/index.html` | The dashboard |
| `services.json` | The apps and services that can be blocked, and the addresses each one uses |
| `junk_domains.txt` | The built-in advert and tracker list |
| `Start QuietNet.command` | Double-click launcher for macOS |
| `Dockerfile`, `docker-compose.yml` | Run it in a container on a Pi or any Linux box |
| `tests/` | Automated checks for the rules engine (standard library only) |
| `data/` | Created when it runs: history, your rules, downloaded list (never uploaded) |

Options for advanced use: `python3 server.py --dns-port 53 --web-port 8377 --no-browser`.

See [CHANGELOG.md](CHANGELOG.md) for what changed in each version.

## Licence

Copyright © 2026 lpobjoy. All rights reserved.

QuietNet is proprietary. You may read the code here, but you may not run, copy, modify or share it without a paid licence. To buy one, get in touch through <https://github.com/lpobjoy>. Full terms are in [LICENSE](LICENSE).
