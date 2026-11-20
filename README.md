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
- **Finds the devices on your network**, with their names and hardware addresses, so you can name and group them.
- **Pause advert blocking for 10 minutes** when a website or app misbehaves.

## Start it

Double-click **Start QuietNet.command**. A window opens (leave it open) and the dashboard appears in your browser at <http://localhost:8377>.

The first time, macOS may ask whether Python can accept incoming connections, or whether Terminal can find devices on your local network — choose **Allow** for both.

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
| `server.py` | The whole program: DNS filter, rules, network scan and dashboard server |
| `static/index.html` | The dashboard |
| `services.json` | The apps and services that can be blocked, and the addresses each one uses |
| `junk_domains.txt` | The built-in advert and tracker list |
| `Start QuietNet.command` | Double-click launcher for macOS |
| `data/` | Created when it runs: history, your rules, downloaded list (never uploaded) |

Options for advanced use: `python3 server.py --dns-port 53 --web-port 8377 --no-browser`.

See [CHANGELOG.md](CHANGELOG.md) for what changed in each version.

## Licence

Copyright © 2026 lpobjoy. All rights reserved.

QuietNet is proprietary. You may read the code here, but you may not run, copy, modify or share it without a paid licence. To buy one, get in touch through <https://github.com/lpobjoy>. Full terms are in [LICENSE](LICENSE).
