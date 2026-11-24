# Known issues

Two reviews have been made: of version 0.5 on 21 November 2026, and a second, deeper pass the same day covering security, the software QuietNet depends on, and efficiency. A third, on 22 November, looked at the enforcer, the relay and the DNS filter, followed by an independent check of its fixes and a live test of the enforcer between two containers. A fourth, also on 22 November, looked again at every part (the DNS filter, the database, the relay, the Pi's link to it, the enforcer's firewall check, the dashboard page and the packaging) and fixed 32 points. On 23 November the open issues themselves were worked through: nine were closed (6, 8, 19, 20, 22, 80, 81, 82 and 83), five were narrowed (5, 7, 12, 21 and 78, each now stating only what is left), and one new point was found while checking the fixes (84). An independent check of those fixes the same day found eleven more faults in them, all fixed (see "Faults in the 23 November fixes" under Fixed), and closed 84. Later on 23 November a one-line installer was added; its open points are 85 to 88. Device names followed (89), then three selectable looks for the dashboard and the relay (90). Last, a review of how robust the blocker is found six faults to fix before relying on it; all six were fixed the same day (see "Found in the robustness review" under Fixed), in part for 4 and 5, and what they leave open is listed under 4, 5, 12, 79 and the new 93. On 24 November a fault found in a real household was fixed (95, under Fixed): the dashboard had called an address a Samsung TV depends on "Possibly junk". This file lists what is still open, then what has been fixed.

The numbers are referred to from tests and other documents. Keep them stable.

## Open: needs testing on a real Pi

### 4. With Docker installed, an enforced device may lose all internet

Docker sets the host's rule for forwarded traffic to "drop unless allowed". An accept in the enforcer's own table does not override a drop in another, so a steered device would be cut off completely.

**Now handled (22 November):** before steering, the enforcer asks every firewall tool present whether another firewall would drop passed-on traffic. If one would, it does not steer, and the device page says what to run on the Pi. Once that accept is in place the check clears and steering starts.

Since the fourth review, each firewall table is judged on its own: an accept in Docker's table no longer hides a reject in firewalld's, because in the kernel each table decides separately. Every table in the way is named, each with a command that suits it: `sudo iptables -I DOCKER-USER -i eth0 -o eth0 -j ACCEPT` for Docker's, `sudo iptables -I FORWARD …` for a rule made with `iptables` without Docker (ufw, for example), and `sudo nft insert rule <family> <table> <chain> iifname eth0 oifname eth0 accept` for anything else, such as firewalld. These commands last until the firewall is reloaded: firewalld drops them on a reload and ufw on a restart, so on those hosts the owner needs to make the rule permanent in that firewall's own settings. This was confirmed in a two-container test with a Docker-style "drop" rule loaded: refused with the advice shown; the advice followed; steering started within 30 seconds and the device kept its internet. The enforcer does not add the accept itself, since that changes the owner's firewall.

**Docker's rule now lasts (23 November):** a command run by hand is lost when the Pi restarts, which the owner found on a real Pi (64-bit Raspberry Pi OS on Wi-Fi, `wlan0`): after a restart the device page asked for `sudo iptables -I DOCKER-USER -i wlan0 -o wlan0 -j ACCEPT` again. The installer now offers to add a small systemd service, `quietnet-forward`, that puts this one rule back every time Docker starts, for the connection the Pi reaches its router on (see [Architecture](ARCHITECTURE.md), the installer's step 10). The device page's advice says the command lasts until a restart and that re-running the installer makes the Docker part permanent. firewalld and ufw still need the rule added in their own settings.

**Shown on the home page (23 November):** the advice used to appear only on an enforced device's own page, so an owner who never opened it saw nothing wrong. When another firewall stops all steering, the home page now says "Cut live connections" is not working for any device, names the firewall, gives the command, says it lasts until the next restart and, for Docker's firewall, that re-running the install command sets it up permanently (`firewall` in `GET /api/enforcer`).

**Still to check on a real Pi with Docker:** that the check spots Docker's real rules there, and that the advice clears it. With Docker and firewalld together: that steering stays refused until both commands have been run, then starts; and that the `nft insert` command works against a real firewalld table. For `quietnet-forward`: that on a real Pi it is started after Docker, that the check clears straight after the install and again after a restart, and that `sudo systemctl restart docker` brings the rule back. If the Pi later moves to another connection (from Wi-Fi to a cable), the service still names the old one until the installer is run again. For the home-page notice: after a restart without `quietnet-forward` (or with the `DOCKER-USER` rule removed), the home page should show the notice with `sudo iptables -I DOCKER-USER -i wlan0 -o wlan0 -j ACCEPT` and the re-run-the-installer line, and it should clear within about 30 seconds of running the command.

### 15. The firewall reload fix needs confirming on a Pi

Issue 15 (below, under Fixed) was confirmed against the real `nft` tool. On 22 November it was also confirmed with real steering between two containers: a steered device was cut off by the kill switch, and recovered within a few seconds of it being switched off, without restarting QuietNet. What remains is the same check with real devices on a real Pi.

### 45. The kill switch can let a little traffic through at first

In the two-container test, a steered device that was already settled sometimes got about one to three seconds of traffic through just after the kill switch was turned on. After that, nothing got through in 60 to 100 seconds of trying. The DNS block applies at once, so this only affects connections that were already open.

**Still to check on a real Pi:** how long the gap is with real devices (phones and TVs answer ARP differently from Linux). It is not being tuned further for now.

### 78. Home-network names sent to the router

Since the fourth review, names such as `printer.lan` or `nas.home`, and reverse lookups of home addresses, go to the home router instead of 1.1.1.1 (fixed issue 48). On 23 November the two gaps left in the code were closed:

- Single-word names (a plain `nas`, with no ending) now go to the home router too, or get "no such name" if the router isn't known. They never go to the public servers. The exception is a question about a single word with one of the record types used to check DNS signatures (NS, SOA, DS, RRSIG, NSEC, DNSKEY, NSEC3): that is a device checking signatures asking about a top-level name such as `com`, and it goes to the internet as before. Answering it "no such name" would make that device reject every `.com` name.
- If the same question (name and type) arrives while QuietNet is still waiting on the router for it, the answer is "server failure" rather than a second ask, so a router set up to send its lookups back to QuietNet can't make the two ask each other for ever. Two devices asking for the very same home name at the very same moment also get "server failure"; they simply ask again.

**Still to check on a real Pi:** that home names, single-word names included, resolve through a real router, and that the router's device names (one of the sources in issue 89) work when the Pi uses itself for DNS.

### 79. Other changes that need a real Pi or host

These could only be checked with stand-ins here:

- **Time zone in the container.** After `docker compose up -d --build`, `docker exec quietnet date` should show the Pi's local time, and the dashboard clock should match the Pi.
- **This computer's address changing.** When the Pi's address changes, the enforcer is told the new one. Check that its own-address rules follow within a minute.
- **No IPv6 for live-cut devices (added 23 November).** With the BT Hub's IPv6 on and "Cut live connections" on for an iPad or phone, check that `dig AAAA www.youtube.com @<the Pi>` from that device (or the device's own behaviour) gets no addresses while another device gets them, that a new YouTube or Netflix stream on it goes over IPv4 (`sudo conntrack -L -f ipv6` on the Pi, or the hub's device page, shows nothing new from it), that bedtime then stops it within seconds, and how long a stream started over IPv6 before switching it on carries on. Check the device's page shows the IPv6 note, and does not with IPv6 off on the hub (after an hour).
- **A Pi with `iptables` but no `nft`.** With nothing enforced, no `iptables` commands should run each tick.
- **The relay behind Railway.** Limits per network address read the last entry of the `X-Forwarded-For` header. Check that Railway's proxy adds it there (rather than replacing the header) and that there is only one proxy in front. If every caller looks the same, the per-address limit behaves like the old shared one.
- **DNS over IPv6 (added 23 November).** On a home network with IPv6, check that the log does not say IPv6 listening failed, that the router actually gives devices the Pi's IPv6 address for DNS, and that such devices' lookups appear on the dashboard under their IPv4 address (matched through `ip -6 neigh`, which the rebuilt image now includes). Check that a lookup from a public IPv6 address outside the home range gets no answer, and that with a device switched off, its IPv6 lookups are blocked or refused.
- **The router's own IPv6 DNS server (added 23 November).** With the BT Hub's IPv6 on, check that `/api/status` shows `ipv6.listening: true` and the hub's IPv6 DNS server in `router_dns` within about ten minutes, and that the warning appears on the home page. Check that `dns_address` is an address the Pi keeps (not a temporary one), that a Windows laptop given it as its IPv6 DNS server shows only the Pi's addresses under DNS servers in `ipconfig /all`, and whether an Android phone still uses the hub's IPv6 DNS server with the Pi's typed in. Switch IPv6 off on the hub and check the warning goes within the hour.
- **The relay giving up root on Railway (added 23 November).** After a redeploy the log should say "Running as user 65534, group 65534, not root." Sign-up and sign-in should still save to `/data`, and an existing root-owned `relay.db` (with its `-wal` and `-shm` files) should be handed over and keep working. If Railway refuses the change of owner, the log shows the "still running as root" warning instead.
- **Shared addresses (added 23 November).** With YouTube blocked and "Cut live connections" on for a device, compare `sudo nft list table inet quietnet` with `dig www.google.com` and `dig classroom.google.com`: their addresses should not be in the drop list, Classroom should load, a YouTube video already playing should stop (its `googlevideo.com` addresses are still dropped), and the device page should say some of YouTube's addresses are shared.
- **Other DNS servers (added 23 November).** With "Cut live connections" on for a phone or laptop, set its DNS by hand to 8.8.8.8 and run `nslookup disneyplus.com 8.8.8.8` with Disney+ blocked: it should get `0.0.0.0`, the lookup should appear on the device page, and the device should accept the answer (which shows the reply comes back looking as if from 8.8.8.8, and leaves the Pi from the right address on `wlan0`). Try the same with the BT Hub's own address as the DNS server. `sudo nft list table inet quietnet` should show the `dns_redirect` chain naming only steered devices, and after `docker stop quietnet` there should be no `quietnet` table. Check that Docker's own `nat` rules on the Pi are unaffected and steered devices keep their internet. Set Android's Private DNS to `dns.google`: expect "can't connect" or a fall-back, and the "tried to use another DNS service" note; with Private DNS on Automatic on a steered phone, check it still works. Set Chrome or Edge's secure DNS to Google or Cloudflare: it should fall back in automatic mode, or fail in strict mode.
- **Rules following a device (added 23 November).** On the Pi, give a phone a name and a blocked service, then turn its private Wi-Fi address off and on (or forget and rejoin the network). Within about a minute its name and rules should be at its new address and a note should be on the home page. Check that `/proc/net/arp` inside the container lists the household's devices with their hardware addresses (it only lists devices that have talked to the Pi recently), that the Pi and the BT Hub never appear in a note, and that a device with "cut live connections" on is steered at its new address. Choose "New devices go into group" and join a new device: it should be put in the group.
- **Row spacing on old Safari (added 23 November).** The dashboard spaces rows with margins where flex `gap` is ignored. This has not been seen on a real Safari before 14.1.

### 89. Device names: what still can't be named, and what the Pi now sends

Since 23 November QuietNet asks devices for their own names over DHCP, Bonjour, the Windows network, UPnP and the router (ARCHITECTURE.md, "Device names"). Written and tested with stand-ins only; not yet run on a real Pi or home network.

**What this means for the network.** The Pi now listens on UDP 5353 (the Bonjour group address only) and reads a copy of the DHCP requests arriving for UDP 67 (through a packet filter, without taking the port and never answering), and every two minutes sends a Bonjour question to the group and to each device, a NetBIOS question to each device, one UPnP call to the UPnP group, and short HTTP requests to devices' own UPnP description addresses. These are small and ordinary, but they are new: a household with network monitoring will see them.

**What still can't be named, and why:**
- Phones and tablets with a private Wi-Fi address that send no name when joining, don't answer Bonjour while asleep, and aren't known to the router. Many Android phones fall here. They get the "private Wi-Fi address" note instead.
- DHCP names are heard only when a device joins or rejoins the network while QuietNet is running: switching on, a computer restarting, a phone reconnecting to Wi-Fi. A device that stays connected only renews its lease, and renewals go straight to the router, so they are not heard. A Windows PC or smart TV on a cable that is never restarted may never give a DHCP name. Heard only on the Pi (Linux), through a packet filter that needs the container's NET_RAW permission; on a Mac only if run with admin rights and port 67 is free.
- On a Mac, the DHCP listener binds the broadcast address on port 67. A DHCP server started on the same Mac afterwards may find the port taken. On the Pi this does not happen: there the listener never takes the port, so dnsmasq or a hotspot can start before or after QuietNet.
- Bonjour answers are believed only from the device they are about. A Mac that is asleep, whose Bonjour Sleep Proxy (often an Apple TV or AirPort) answers for it, is named only once it wakes. This is deliberate: any device could otherwise answer for another and give it a misleading name.
- A Bonjour announcement heard from an address before QuietNet has seen which device holds it is tied to the device holding it at the next round, up to two minutes later. If the address passes to another device inside those two minutes, the announcement could be shown for the wrong device until it ages out (6 hours) or that device is named.
- Smart plugs, cameras and other small devices that speak none of these. No hardware-maker table is used, by choice.
- Devices on another network segment or behind a mesh node that doesn't pass multicast on.
- On a Mac, the Bonjour listener may share port 5353 with the system or be refused; asking devices directly still works.

**Still to check on a real Pi:** that the log shows no "Device names: not listening" line on a plain Raspberry Pi OS with avahi running (or, if it does, that avahi keeps working: `avahi-browse -a` still lists devices); that iPhones, Macs, a Windows PC, a smart TV and the router each get a suggestion; that the round never takes much more than 5 seconds (`docker logs` stays quiet; the dashboard stays quick); that nothing is ever sent from port 67 (`sudo tcpdump -ni eth0 udp port 67 or udp port 68` shows only the router and devices); that a DHCP server started on the Pi after QuietNet still starts.

### 85. The one-line installer has not been run on a real Pi

`install.sh` (added 23 November) has only been run against stand-in commands, under dash and bash on a Mac and in a Debian container, and by hand under busybox ash in an Alpine container with no network. It has never installed real Docker, built the real image, or changed a real system's settings. **Still to check** (the steps are in [Testing](TESTING.md#checking-the-installer-on-a-real-pi)):

- Docker's own install script on Raspberry Pi OS, 64-bit and 32-bit. Docker has been winding down 32-bit Arm support, so on 32-bit Pi OS it may fail; the installer then points to Docker's own install guides for Debian and Ubuntu, which have not been followed on a Pi either. Also on the newest Pi OS and Debian release (Trixie).
- Switching off systemd-resolved's listener on Ubuntu, and that the Pi's own lookups still work after `/etc/resolv.conf` is re-pointed.
- The column layout of `ss -lntup` on each system, which the port 53 check reads.
- `sudo` asking for a password at the start of a piped install (and again if a long build outlasts sudo's 15-minute memory), sudo refusing a user not allowed to use it, and `ssh` without `-t`, the Pi's address in the closing message, and pairing appearing on the relay within a minute.
- The `quietnet-forward` service (issue 4): that `ip -4 route show default` names the right connection on Wi-Fi and on a cable, and that the service starts and survives a restart.
- That `--uninstall` and a re-run behave as the tests expect with real Docker Compose (project name, volume name, `down --rmi local`).

### 86. The installer runs whatever is on GitHub's main branch, unsigned

The one line fetches `install.sh` from GitHub's `main` branch, and the installer downloads QuietNet from `main` (or `--ref`). Both go over HTTPS, but nothing checks a signature or a known checksum. So anyone who can push to `main` on GitHub, or who takes over the GitHub account, controls what every newly installed or updated Pi runs, as root and with network rights. The relay's install line shows `main` too, unless the relay owner sets `QUIETNET_INSTALL_URL`.

**Possible fixes:** protect `main` (required reviews, no direct pushes) and turn on two-factor sign-in for the account; publish tagged releases and have the relay's line and the installer use a tag rather than `main`; or sign releases and check the signature (hard with the standard library and plain `sh` alone). Until then, a cautious owner can read `install.sh` before running it, or pin `--ref` to a tag they have checked.

### 87. The installer depends on get.docker.com

When Docker is missing (and the person agrees), the installer downloads `https://get.docker.com` and runs it as root. That is Docker's own published script, but QuietNet does not control it: if it changes, breaks, drops a system (as with 32-bit Arm), or is tampered with, the install fails or runs something unexpected. Nothing checks it either. People who would rather not can install Docker themselves first (from their system's packages or Docker's instructions), and the installer then skips this step.

### 88. Pairing again with the installer, and the code kept by Docker

- `--relay` and `--code` on a re-run pair only a Pi that isn't paired yet. `cloud_agent.py` ignores `QUIETNET_CLOUD` and `QUIETNET_PAIR` once it holds a key, so the installer can't move a paired Pi to a new relay or account; that still needs **Unlink** on the Pi's Remote access card first. The installer's closing message says so.
- The pairing code is never written to a file, but Docker keeps it in the container's settings (`docker inspect quietnet` shows `QUIETNET_PAIR`) until the next run without `--code`. It has already been used or has expired by then, so it is of no use to anyone, but it is visible.
- Uninstalling says how to remove the systemd-resolved settings file, but does not point `/etc/resolv.conf` back at `stub-resolv.conf`. Lookups keep working either way.

### 94. Licences on the relay: what the first phase leaves out

The relay now keeps a licence per account and can enforce it (`QUIETNET_LICENCE_GATE`, off by default). Gaps left on purpose, or found while building it:

- **No way to pay or renew yet.** The paused page has no Renew button and the Licence card no billing buttons; licences come only from the owner's command line until payments are added. The wording still says "Renew at q3n.net", as the design asks.
- **"Blocking is paused for an hour", not "until 14:35".** The relay doesn't know the Pi's time zone, so the result page after the second rescue button gives no clock time.
- **Downloads don't take seats yet.** Seats in use are only the account's paired Pis. Installs that downloaded but never paired, and the 60-day expiry of seats, come with downloads.
- **The gate's "once an hour" is kept in memory.** After a restart the same would-be refusal can be logged again straight away. `licence_log` keeps the newest 1000 lines per account that the account itself caused (gate notes, at most one an hour for each kind of refusal, and rescues, at most 20 an hour); the owner's own lines are always kept, so the oldest gate notes and rescues of a busy account are dropped.
- **Waiting Pis beyond the free seats still get codes.** While the licence allows pairing and paired Pis leave a seat free, the home page gives every waiting Pi a fresh code, even when there are more waiting Pis than free seats (they can be left from before the gate was on). Pairing them stops at the seats: the first to pair take the free seats and the rest are refused with the seats sentence.
- **The legacy licences end 90 days after the first start.** Grant the owner's own account `--plan owner` (no end) before switching the gate on, or its Pis will pause when the legacy licence ends.
- **The Pi's side isn't built yet.** Pis before 0.6 ignore the licence in poll answers and send no install id or agent header, so they get the older rescue call (kill switch off only) and every copy of them pairs as a separate Pi.

## Open: design decisions for the owner

### 5. IPv6: the enforcer, and devices known by two addresses

On 23 November the DNS half was fixed: the filter now also listens on IPv6 (`::`, same port, UDP and TCP), so a device given an IPv6 DNS server by the router is filtered too. If the computer has no IPv6, or the port can't be opened, it says so and carries on with IPv4. An IPv4 device reaching it over IPv6 (`::ffff:192.168.1.23`) is filed under its IPv4 address. What remains:

- **The enforcer steers and drops IPv4 only (eased 23 November).** On a BT Smart Hub, which hands out IPv6 as it ships, most streams and app connections went over IPv6, so bedtime or the kill switch left them running though the README promised an instant cut. A device with "Cut live connections" on now gets "no records" for IPv6 address lookups (AAAA) and for HTTPS and SVCB lookups (which can carry IPv6 hints), so its apps connect over IPv4 through the Pi; other devices are unaffected. What remains: a connection it already had over IPv6 is not cut and may carry on until the app reconnects; an app that has an IPv6 address from before, or hard-coded, can still use it; and an app using its own DNS can still get IPv6 addresses. The device page says so when the network has IPv6. Steering IPv6 itself would need neighbour advertisements in place of ARP.
- **A device asking from a real IPv6 address is matched to its IPv4 address by hardware address**, using the IPv6 neighbour table and the IPv4 devices from the last scan and the neighbour table, looked at again every minute. Matched, it is filed under its IPv4 address and all its rules apply. If it can't be matched (a new temporary address in its first minute, or a device QuietNet has never seen over IPv4) and any rule names a particular device or group, the answer is "refused", and the device asks QuietNet's IPv4 address instead. A device given only an IPv6 DNS server, and never seen by QuietNet over IPv4, would get no answers at all while such rules exist. With no device or group rules, an unmatched device is answered and shows up apart from its IPv4 address. Before this was fixed (later on 23 November), the IPv6 listener was a way round device rules: a child's phone asking from its IPv6 address got real answers during its group's bedtime.
- **The router's own IPv6 DNS server (fixed in part, 23 November).** A router that hands out IPv6 (a BT Smart Hub does as it ships) also tells devices to use its own IPv6 DNS server. Windows and Android set up by hand for IPv4 only kept using it as well, so blocks and bedtime applied only some of the time while the device still showed lookups. "Set up a device" now gives the Pi's IPv6 address for each kind of device, or, if the Pi has none, says to switch IPv6 off on the router (BT Smart Hub: Advanced settings, IPv6). QuietNet listens for the router's announcements and the dashboard warns when they name a DNS server that is not the Pi. What remains: Android may keep the router's IPv6 DNS server even with the Pi's typed in, so there the sure fix is switching IPv6 off on the router; servers handed out by DHCPv6 alone are not seen; the IPv6 address given changes if the internet provider changes the home network's public range and the Pi has no unique-local address.
- On the Pi, matching needs the `ip` tool (`iproute2`, now in the image). Without it nothing is matched, so with device rules in place every IPv6 lookup from a real IPv6 address is refused.

### 93. Ways a device can still get round QuietNet

The robustness review's fixes (see Fixed) close the easy ways round, but not all of them. Each needs either a change on the device, a router that can block them, or a much bigger change to QuietNet:

- **Devices without "Cut live connections" can still use another DNS server by its address.** A phone or TV set by hand to 8.8.8.8 (or the router's address) sends its lookups straight there. The redirect works only for devices steered through the Pi. The BT Smart Hub cannot block outgoing DNS itself. Turning on "Cut live connections" for the device closes it.
- **Secure DNS set up by address alone, or with a service not on the list.** A browser told to use `https://1.1.1.1/dns-query` uses the ordinary web port and never looks a name up, so neither the name block nor the port 853 drop stops it. Services not in `OTHER_DNS_SERVICES` are not blocked; add them there.
- **A VPN, or an app with its own built-in DNS,** gets round all of it, steered or not. QuietNet sees only that the device went quiet.
- **IPv6.** The redirect and the port 853 drop cover IPv4 only, like the rest of the enforcer. A steered device gets no IPv6 addresses from QuietNet, but a connection it opened over IPv6 before "Cut live connections" was switched on (or before bedtime began) is not cut and may carry on until the app reconnects; an app that remembers an IPv6 address, or uses its own DNS, can still reach it over IPv6. An Android phone may keep using the router's IPv6 DNS server even with the Pi's typed in (issue 5). Switching IPv6 off on the router closes all of these.
- **With `iptables` in place of `nft`,** ordinary DNS to another server is not redirected (port 853 is still dropped). The Pi image always has `nft`.
- **Lookups already on their way to 8.8.8.8** when steering starts are not redirected until they time out, as is normal for this kind of redirect.
- **A device with no rules of its own can use another DNS service** (Private DNS, secure DNS) unless the home-page switch "Stop every device using another DNS service" is on. Off by default, because a device set to use one strictly loses all names when it is blocked.
- **The "tried to use another DNS service" flag is kept in memory**, so it is lost when QuietNet restarts; the device's history still shows the lookups.
- **A device that changes both its private Wi-Fi address and its number at once** looks brand new, so its rules are not moved automatically: only the new-device group or the home-page notice catches it. Its old history stays filed under its old address.
- **A visitor given the number a child's phone had, with a private Wi-Fi address of its own,** gets the child's rules until the owner answers "Is it the same device?". This errs towards keeping the rules; answering "No" pauses them.
- **Behind a Wi-Fi range extender that shows every device with its own hardware address,** rules can't follow a device: they stay with its address, as before the 23 November changes. Until the extender has been seen at two addresses at once on three looks, it is treated as one device.

### 18. The local dashboard has no password

Anyone who can open `http://localhost:8377` on the QuietNet computer controls it: another account on the same machine, or anyone with an SSH login. This is by design for a single-owner home machine. It matters if the Pi is shared.

## Open: smaller security points

### 7. Relay

Four of the six points were fixed on 23 November (see below). Still open:

- The overall cap on wrong pairing codes was raised from 20 to 200 in 10 minutes, now that each network address has its own cap of 20. Codes are 32 bits, so someone guessing without stop has about a 1 in 400 chance a year of hitting a given live code, against about 1 in 4,000 before. Judged acceptable; the owner may want to confirm.
- The relay's room for large answers (48 MB) counts each answer's stated size. While one is being read, memory briefly reaches two to three times that size.
- The guard against login forgery relies on the browser's `Sec-Fetch-Site` header. Browsers that don't send it (for example Safari before 16.4) are still exposed. Closing that fully would need a one-time form token tied to a cookie set before sign-in. Low risk: the visitor would see the attacker's QuietNets, not their own.

### 21. The Pi container runs as the root user

Since 23 November the relay gives up root at start-up (see below). The Pi container still runs as root: it needs network rights (raw sockets, the firewall, kernel settings) that are simplest to hold as root.

## Open: minor

### 12. Minor

- The enforcer drops addresses handed out in the last six hours. A service that moves to new addresses is covered as soon as the device looks them up through QuietNet.
- An address a blocked service shares with an allowed site is spared only once QuietNet has handed that address out for the allowed site in the last six hours. Until then it is dropped, so the first connection to a rarely used allowed site on the same front door can stall for up to two seconds (the next plan) before it is spared. And while an address is spared, a connection to the blocked service that was already open on it is not cut; new ones still fail at the name.
- The look (theme) cookie `qn_theme` on the Pi's own dashboard (`localhost:8377`) is shared with every other page served from `localhost`, whatever the port, because browsers do not keep cookies apart by port. Harmless: it is only a display choice, checked against the three names wherever it is read.
- Like the relay's other forms, the Appearance form (`POST /theme`) relies on `Sec-Fetch-Site` against other websites; a browser that does not send it could be made to change its own look. Harmless: it changes only how the pages look, in that browser.

### 90. The three looks: what differs from the mockups, and what is untried

Added on 23 November (Calm, Household and Control room, on the dashboard and the relay). Not faults, but gaps to know about:

- **System fonts, not the mockups' fonts.** The mockups use Inter, Space Grotesk and JetBrains Mono, loaded from Google Fonts. QuietNet loads nothing from other websites and ships no font files, so the pages use fonts already on the device: the system's own sans-serif (San Francisco, Segoe UI or Roboto) for text, a rounded system face for Household's headings where there is one (Apple devices; elsewhere the plain sans-serif), and the system's monospace face for addresses. The pages therefore look close to the mockups but not identical, and differ a little from one platform to another.
- **The choice belongs to the browser, not the account.** It is a cookie (`qn_theme`), so each browser and device remembers its own, and signing in elsewhere does not bring it along. The Pi's own dashboard (`localhost:8377`) and the relay are different websites, so a look chosen on one is not carried to the other; the relay and the dashboard opened through it do share one.
- **The relay's sign-in pages cannot change the look.** Choosing one needs a signed-in person (`POST /theme`); signed out, the pages use whatever the cookie already says, else Calm.
- **Control room has no light version.** It is always dark, whatever the device is set to.
- **With scripts switched off the dashboard shows Calm** for every choice, because its look is picked by a small script. The dashboard needs scripts to work at all, so this matters little. The relay's pages are drawn in the chosen look on the server and need no script.
- **The kill switch has no "arm, then switch" step** as in the Control room group mockup: it keeps the confirmation dialog every look has, so it behaves the same in all three.
- **Not yet tried in a real browser on every platform.** The tests check the page's text (the early script, each look's colours, no outside requests, no inline styles), not how it is drawn. Older Safari (12 to 14.0), Firefox on Android and Windows high-contrast mode in particular are untried; see [Testing](TESTING.md) for the manual checks.

## Software QuietNet depends on

QuietNet uses **no third-party Python packages**, so there is no package list to scan. A test (`test_packaging.StandardLibraryOnly`) keeps it that way. What it does depend on:

| Dependency | Where | State on 21 November 2026 |
| --- | --- | --- |
| Python 3.13 | Both containers (`python:3.13-slim`) | In its security-fixes-only period, supported until October 2028. Latest is 3.13.18 (25 October 2026). The image tag follows the newest 3.13 release each time the container is rebuilt |
| Debian packages, including `nftables` | Pi container | Installed fresh at build time |
| Python 3.9 from Apple | macOS, via `Start QuietNet.command` | Python 3.9 is past the end of its upstream support. Apple maintains its own copy on its own timetable |
| StevenBlack hosts list | Downloaded on request | Data only. Each line is checked before use and nothing in it is executed |
| Docker's install script (`get.docker.com`) | Run by `install.sh` as root, only when Docker is missing and the person agrees | Not checked; see issue 87 |
| QuietNet's own code on GitHub (`main`) | Fetched by the one-line install and by every update through it | Not signed; see issue 86 |

The Python security fixes published during 2026 were checked against the modules QuietNet uses (`http.server`, `urllib`, `sqlite3`, `socket`, `ssl` as a client, `hashlib`, `hmac`, `json`, `subprocess`, `webbrowser`). Those found:

- Fixes to `tarfile`, `zipfile`, `tempfile`, the XML parser and `mimetypes`: QuietNet does not use these.
- A use-after-free in server-side TLS with certain callbacks: QuietNet never serves TLS itself. The host does that for the relay.
- A memory denial-of-service in `http.client` (fixed in 3.13.11): the Pi's link to the relay uses this module, so the fix matters. Any image built since December 2025 has it.
- Option injection in `webbrowser.open()` through a crafted address: QuietNet opens only its own fixed `localhost` address.
- Removal of trust in a compromised certificate authority (3.13.18): applies to the Pi's HTTPS connections to the relay and to the list download. Rebuild to pick it up.

**To do:** rebuild both containers so they carry 3.13.18. `.github/dependabot.yml` now asks GitHub to open a pull request whenever a newer base image appears. On a Mac, running QuietNet with a current Python from python.org is safer than Apple's 3.9, though the scan feature works best with Apple's (see the launcher's comment).

This check used the published release notes. It is not a scan of the built image, which needs a tool such as `docker scout` or `trivy` run against the image itself.

## Fixed

### Found in a real household (24 November)

A Samsung TV stopped opening apps such as Disney+. The owner had blocked `samsungcloudsolution.net` from the TV's page, where the dashboard had labelled it "Possibly junk" and put a highlighted Block button beside it. Nothing afterwards said that the block was the cause.

| # | Problem | What was done |
| --- | --- | --- |
| 95 | **The dashboard called an address a TV depends on "Possibly junk" and offered to block it.** One sub-name of `samsungcloudsolution.net` has "log" in it, which the word list behind "Possibly junk" matches, and a group takes that label when any name in it has it. The owner label knew `samsungcloudsolution.com` as "Samsung TV" but not the `.net` twin, so the row did not even say whose it was | A short table of names a device's own system needs (`NEEDED` in `server.py`, about 30 whole names for Samsung and LG TVs, Apple, Android and Google devices, Amazon Fire TV and Echo, Roku, Windows, PlayStation, Xbox and Nintendo Switch). Such a row shows "Needed by Samsung TVs" and never "Possibly junk", and its Block button is no longer the highlighted one. `samsungcloudsolution.net` is labelled "Samsung TV" |
| 95 | **Nothing asked before such a block was made**, from the Block button or from a name typed on the Blocked list page | `POST /api/block` refuses a needed name with `409` and who needs it, unless the request says `"sure": true`. The dashboard asks, saying who needs the address and what may happen, and blocks only on a yes. The check is the server's, so it covers every way of blocking, through the relay too. Blocking one sub-name beneath a needed name does not ask |
| 95 | **Nothing pointed back at the block once the TV played up** | On the Blocked list page and on a "Blocked by you" row of a device page, a needed name carries a note: who needs it, and to unblock it if apps have stopped opening, or the device can't sign in or update |

What this leaves open:

- **The table is a short, hand-kept list**, not a full one. A device not on it (a Sony or Philips TV, a smart speaker other than Echo, a printer) can still have a needed address labelled "Possibly junk". The general "this doesn't look like an advert or tracker" question is still asked for names with no label, but not for "Possibly junk" ones. Names considered and left out for want of certainty: `samsungotn.net` and `samsungqbe.com` (Samsung TV updates and online check), `lge.com` and `lgtvcommon.com` (LG), `amazon.co.uk` and `amazonalexa.com` (Echo), `nintendowifi.net`, `xbox.com`.
- **Only the whole name asks.** Blocking a sub-name that a device needs (`time.samsungcloudsolution.com`, say) does not ask, by design: sub-names are how a single tracker is blocked.
- **Blocking a whole service does not ask.** The PlayStation, Xbox and Nintendo switches under "Block apps and services" cover names in the table, and are a deliberate choice with their own switch.
- **A needed name on the downloaded advert list** would still be blocked automatically (`why` is `list`); the row then shows "Advert / tracker" and "Needed by ..." together, but no note. None is on the built-in list (a test checks).
- **Not tried in a browser or on the TV itself.** The page's new parts are checked as text and were run once with stand-ins; see `docs/TESTING.md` for the manual check.

### Found in the second check of the relay licence build (24 November)

A second check of the first phase of licences, after the fixes below, found five more faults, each confirmed by a second reviewer. All were fixed the same day.

| Problem | What was done |
| --- | --- |
| **The go-live steps gave no way to find every account.** `licence show` needs an email the owner already knows, so an account made while sign-up was open could keep its 90-day legacy licence with nobody told | New `python relay.py licence list`: every account, its licence (id, state, plan, end date) and its Pis, then the total; it changes nothing. The go-live steps and the manual checks use it |
| **An account with no licence was told it had 2 seats**: "This account has no QuietNet licence yet" then "Pis: 0 of 2" on the Licence card, the same in `licence show`, and `"seats": 2` in poll answers | Without a licence the card and `show` say just "Pis: N", and the poll answer leaves `seats` out. The seat checks themselves are unchanged |
| **The "Licence gate: on/off" start-up line could be missing from Railway's log**, which the docs say to check: start-up lines were printed without being flushed, so through a pipe they sat in Python's buffer until the next log line, or were lost if the relay stopped first | Every start-up line goes through `say()`, which flushes it, and the relay's image sets `PYTHONUNBUFFERED=1` |
| **The manual licence checks couldn't be followed as written**: granting seats equal to the number of Pis made adding the test Pi log a would-be refusal the step said not to expect, and the gate-on step needed an unlicensed test account with a paired Pi that couldn't be made once the gate was on (or at all, with sign-up at its default) | Step 3 asks for more seats than Pis; step 5 says to set up the test account and its Pi before turning the gate on, or to use `licence revoke` and `licence restore` on an account that already has one |
| **`docs/API.md` said `past_due` lasts "14 days from the failed payment"**, which the relay doesn't record | It now says what the code does: until `grace_until`, or 14 days after the end date if that is not set, and with neither, no end |

### Found in the check of the relay licence build (24 November)

Independent reviewers checked the first phase of licences on the relay, and a second reviewer confirmed each fault. All were fixed the same day.

| Problem | What was done |
| --- | --- |
| **Rescue presses had no limit**, and each wrote a licence log row, so one account pressing in a loop (answered at once when its Pi is offline) could fill the relay's disk | Each account may press 20 times an hour (`RESCUE_LIMIT_PER_ACCOUNT`); beyond that the answer is `429`, with nothing sent and nothing logged. `licence_log` also keeps only the newest 1000 lines per account that the account caused, always keeping the owner's own |
| **Pairing several codes at the same moment could go past the seats**, since the seat count and marking the Pi paired were separate steps; one code sent twice at once could also pair twice | `agent_pair` counts the seats, looks again at any entry being replaced, and marks the Pi paired while holding `db_lock`, and only updates an entry still unpaired with its code in date |
| **The home page contradicted itself** when a waiting Pi held a seat: "Pis: 1 of 2" on the Licence card, but "both are in use" in place of the add form | The refusal names waiting Pis ("1 is paired and 1 is waiting to be paired"), on the home page and from `POST /pis/new`, and the card adds "(1 waiting to be paired)" |
| **Pairing codes were still shown when pairing would be refused** (gate on, no current licence or every seat paired), with a working-looking install line | A waiting Pi shows why in place of its code, and its code is not renewed |
| **No warning before a licence ended** (design 4.4 asks for one at 7 days) | The Licence card warns in the last 7 days, except for plans that renew by themselves |
| **A blank `--reason` gave exit status 1**, which is documented for an unknown email | It is now a wrong command (2), like a missing one |
| Tests and docs: the agent-header test could pass with "3" stored as 3; the "nothing reached the Pi" checks could never fail; the relay tests took on a developer's `QUIETNET_LICENCE_GATE` and `QUIETNET_LATEST`; the docs said the home page goes through `licence_gate()`, left `/pi/<id>/rescue` and `/theme` out of the cross-site list, and gave the wrong default for `--seats` on a re-grant | Each fixed |

### Found in the robustness review (23 November)

A review of whether the blocker can be relied on found six faults to fix first. All were fixed the same day; what each leaves open is in the issue named.

| # | Problem | What was done |
| --- | --- | --- |
| 5 | **Windows and Android also used the BT Hub's own IPv6 DNS server.** "Set up a device" changed IPv4 DNS only, and the hub, with IPv6 on as it ships, names its own IPv6 DNS server, so a child's laptop or phone got blocks and bedtime only some of the time while still showing lookups | "Set up a device" gives the Pi's lasting IPv6 address for each kind of device (unique-local if it has one, else public; never temporary or link-local), or says to switch IPv6 off on the router (BT Smart Hub: Advanced settings, IPv6). A listener reads the router's IPv6 announcements (never sends), and the home page and "Set up a device" warn when they name a DNS server that is not the Pi (`ipv6` in `GET /api/status`). Still open: issue 5 |
| 8 | **A device could use any other DNS server**: 8.8.8.8, Android's Private DNS, port 853, or a browser's secure DNS, getting round every name block with one setting, even while steered through the Pi | The well-known encrypted DNS services (`OTHER_DNS_SERVICES`: Google, Cloudflare, Quad9, OpenDNS, NextDNS, CleanBrowsing, AdGuard, Mullvad, DNS.SB, Control D, and every name beneath them) get the blocked answer for every device (narrowed the same day to devices the owner controls, unless the owner chooses every device: see below), paused or not, so Private DNS or secure DNS set to one of them falls back to ordinary DNS; the device list and page say "tried to use another DNS service". For steered devices, the enforcer's `nft` table redirects ordinary DNS sent to any other server (8.8.8.8, the router) to QuietNet and drops port 853; on Linux, answers leave from the address each lookup was sent to, which the redirect needs. With `iptables` only, port 853 is dropped but there is no redirect. Still open: issue 93 |
| 91 | **Blocking YouTube with "Cut live connections" on also cut Google search, Classroom, Docs and Gmail**, because they share Google's front-door addresses; sites on Cloudflare, Fastly or Akamai could do the same | An address is not dropped for a device if a name that device is allowed was given the same address in the last six hours; the blocked name is still blocked by DNS. The device page says how many addresses were left to the name block (`shared` in `GET /api/enforcer` and `/api/status`) |
| 92 | **Rules belonged to the IP address**. A phone that switched its private Wi-Fi address, or was given a new number, lost its name, group, bedtime and service blocks, and a parent's laptop later given the old number took on the child's bedtime | Each address's rules are tied to the hardware address seen there. When that device appears at a new address with nothing of its own, everything moves with it and a note is kept; if the new address has rules of its own, both devices show a warning. When a different device takes the address, its own and its group's rules are paused until the device comes back. A "New devices go into group" setting on the Groups page puts devices never seen before into a chosen group, and the home page offers to move the rules when a device with rules goes quiet just as a new private-address device appears. Still open: issue 93 |
| 4 | **"Cut live connections" stopped after every restart, and nothing said so on the home page.** The Docker rule the owner was told to add lasted only until the Pi restarted, and the advice appeared only on an enforced device's own page | The installer's `quietnet-forward` service puts Docker's rule back every time Docker starts. When another firewall stops all steering, the home page says "Cut live connections" is not working for any device, names the firewall, gives the command, says it lasts until the next restart and, for Docker's firewall only, that re-running the install command sets it up permanently (`firewall` in `GET /api/enforcer`). Still open: issue 4 |
| 5 | **On BT's default IPv6, "Cut live connections" left most streams running**, because the enforcer steers and cuts IPv4 only, and the README called the cut instant | A device with it on gets "no records" for IPv6 address lookups (AAAA) and for HTTPS and SVCB lookups, which can carry IPv6 hints, so its apps connect over IPv4 through the Pi; other devices, and the same device while its rules are paused, are unaffected, and the answer is never remembered for others. The device's card says, when the network has IPv6 (`in_use`), that IPv6 connections can't be cut directly. The README says what happens. Still open: issue 5 |

### Faults in the robustness review's fixes (23 November)

A second check of the fixes above found these. All were fixed the same day; the ones marked "check on the Pi" need confirming with real devices.

| # | Problem | What was done |
| --- | --- | --- |
| 92 | **Two devices that swapped addresses swapped rules.** After a router restart, Dad's laptop at the child's old number got the child's YouTube block and bedtime, and the child's phone got none, with only two crossed warnings | When a device turns up at an address with rules of its own for another device, nothing is merged, but while that lasts its own rules apply to it there (`S.follow`, `scopes_for`), "cut live connections" follows it by its hardware address, and its old address is paused if a different device has it. Each device keeps its own rules; both pages still warn |
| 92 | **A device moving to an address left with only a name, or a visitor's automatic group**, of a device no longer on the network got no rules at all: nothing moved and the new address was paused. Every number that had ever held a visitor became such a trap | An address with no rules of its own beyond a name or group, whose device is not on the network now, counts as free: the arriving device's rules move there, its name and group replacing those, and the note says so. A moved device with no group no longer inherits the visitors' group (`move_rules`). A new visitor at a departed visitor's address is simply given the group |
| 92 | **A device that changed its private Wi-Fi address but got the same number back lost all its rules**, with no notice and no way to put them back (the hand move refused "two different devices") | A device with a private Wi-Fi address that appeared since the rules' device was last seen keeps the rules at that number, and the owner is asked "Is it the same device?" (`same` notices): yes makes the rules belong to it (`POST /api/move-rules` with the same address twice), no pauses them (`POST /api/different-device`). A paused address's page also offers "It's the same device" |
| 92 | **A device never seen before at a paused address got only the whole house's rules, for good**, missing the new-device group | It gets the new-device group while the pause lasts (`S.guest_group`, kept in `device_mac`), and the group goes when it leaves |
| 92 | **A stale entry in the neighbour table held a moved device's rules back.** Linux keeps old entries on a small network for a long time, so a phone that moved could still be listed at its old address, and its rules stayed there | The neighbour table is read with `ip -4 neigh`, which says how fresh each entry is; when one hardware address is listed at several addresses and only one was confirmed just now, that one counts. Check on the Pi: `ip neigh` after a device changes address |
| 92 | **A Wi-Fi range extender that shows every device behind it with its own hardware address made rules jump between devices**: the child's bedtime could move to a parent's laptop behind the same extender, and a phone that went upstairs had its rules paused | A hardware address seen at two addresses, each confirmed reachable, on three looks within an hour of each other is taken for a range extender (`shared_macs`). Rules that belong to one stay with their address and never move or pause, and rules at an address an extender now answers for keep applying; both pages say why. Check on the Pi whether the household's extender does this |
| 92 | **The record of hardware addresses had no limit**, and was read whole every minute, so a device making up addresses could grow it by about 250 rows a minute | Addresses unseen for 30 days are forgotten, at most 5,000 are kept (the longest unseen go first), never one that rules belong to, and only the addresses on the network now are looked up |
| 8 | **Blocking other DNS services for every device cut off phones set to use one strictly.** Android's Private DNS set to a name, an encrypted DNS profile on an iPhone or a Mac, and Firefox's strictest setting do not fall back, so a parent's phone lost every name at home | Other DNS services are now blocked only for devices the owner controls: those with "cut live connections", a group, or an internet switch, blocked service or schedule of their own. A home-page switch, "Stop every device using another DNS service" (`POST /api/other-dns-switch`), extends it to every device, and says what it can cut off |
| 91 | **The shared-address guard spared YouTube's video servers.** Google's caches inside the internet provider's network serve YouTube video and Chrome, Play Store and Android downloads (`gvt1.com`) from the same addresses, so a video already playing carried on. Inferred from how those caches work; check on the Pi | Addresses of names that carry only video for one service (`ALWAYS_CUT_BY_ADDRESS`: `googlevideo.com`, `nflxvideo.net`, `ttvnw.net`) are always cut. A download from the same cache stops too while the block is on. Check on the Pi: compare `dig` for a `googlevideo.com` name and the `gvt1.com` name from the same cache against `nft list table inet quietnet` |
| 5 | **Any IPv6 announcement counted as the router's.** An Apple TV or HomePod mini acting as a Thread border router announces a range of its own when the router's IPv6 is switched off, so the device page wrongly said IPv6 connections can't be cut, and "Set up a device" could give an address that vanished when the HomePod was unplugged | Announcements must arrive with a hop limit of 255. Only one with a router lifetime above 0 counts as the network having IPv6, and a unique-local address is only given to devices if a real router announces its range. DNS servers are still noted from any announcement, since devices use them whoever names them |

### Faults in the 23 November fixes

An independent check of the 23 November fixes found these. All were fixed the same day.

| # | Problem | What was done |
| --- | --- | --- |
| 5 | **The new IPv6 listener was a way round device rules.** Rules are kept by IPv4 address, so a device asking from its own IPv6 address escaped its internet switch, its group, its blocked services and its group's schedules | IPv6 neighbours are matched to IPv4 devices by hardware address every minute (`refresh_ipv6_view`), and matched lookups are filed under the IPv4 address. An unmatched one is refused while any device or group rule exists, so the device falls back to IPv4. This computer's own IPv6 addresses now count as this computer |
| 5 | **The IPv6 listener answered anyone.** A public IPv6 address can be reached from the internet unless the router's firewall stops it, which would make QuietNet an open resolver | Only `::1`, link-local, unique-local and public addresses inside the home network's own ranges are answered over IPv6, on UDP and TCP; anything else gets no answer (`v6_source_allowed`) |
| 22 | **The answer memory counted answers, not bytes.** TCP answers can be 64 KB, so one device could pin hundreds of megabytes; and a big remembered answer could be given over UDP to a device that had asked for less | Answers over 4,096 bytes are not remembered. Over UDP, a remembered answer is only given if it fits the size the device asked for (512 bytes, or its settings record's size) |
| 84 | **Remembered answers ignored what the question asked of them.** An unchecked answer fetched for a device that turned signature checking off (the "CD" flag) could be given to every other device | Remembered answers are filed by whether the question had a settings record, whether it asked for signatures, and the CD flag as well (`cache_key`) |
| 78 | **Single-word names included top-level names such as `com`**, so a device checking DNS signatures got "no such name" for `com` and rejected every `.com` answer | Single words asked with a signature-checking record type go to the internet |
| 83 | **A new community list of the same size didn't change the activity marker**, and didn't refresh the enforcer's plan or the answer memory | Installing a downloaded list counts as a rule change (`rules_changed`) |
| 82 | **Clearing a busy device's history could outlast the relay's 30-second wait** now that it goes in steps | One device's clear runs in the background and the call answers at once |
| 21 | **Handing over the relay's data folder followed links**, so a compromised relay could leave a link to a system file for the next start, as root, to hand over; and a refused change of user crashed with a raw error | Only `relay.db` and its companion files are handed over, only when each is a plain file, and links are never followed. A refused change of user, or a user number too big for the system, stops the relay with a plain message |
| 7 | **A session cookie with an enormous user number crashed the request** (the number was too big for the database) | Such a cookie counts as signed out |
| 6 | **Two sign-ups at once on a new relay could both get in** despite "first account only" | In `first` mode the account is added only if there are still none, in the same database statement |

### Open issues closed (23 November)

| # | Problem | What was done |
| --- | --- | --- |
| 6 | **Sign-up on the relay was open unless you closed it**, so anyone who found the address could make an account | `QUIETNET_SIGNUP` now defaults to `first`: only the first account can be created. `open` and `closed` can still be chosen, and a misspelt value still closes sign-up. The start-up log says which setting is in force. A relay that already has accounts keeps them, but nobody new can sign up unless the owner sets `QUIETNET_SIGNUP=open` |
| 7 (four of six points) | **Relay sessions, tokens and forms:** signing out left a copied cookie valid for 14 days; Pi tokens were stored as plain text; another site could sign a visitor in to the attacker's account; the sign-up form said when an email already had an account | Signing out (and any change to the password record) ends every session for that account, in every browser: the cookie is now `user.number.expiry.signature`, and signing out bumps the number. Pi tokens are stored as a SHA-256 hash; tokens in an existing database are hashed at start-up and paired Pis keep working. Forms sent from another website (`Sec-Fetch-Site` of `cross-site` or `same-site`) are refused. Sign-up gives the same answer whether or not the email has an account, and no longer signs you in. The other two points stay open under issue 7 |
| 8 | **Devices that bring their own phone book** (Firefox's secure DNS, iCloud Private Relay) sent lookups past QuietNet | `use-application-dns.net` gets "no such name", so Firefox uses the network's DNS; `mask.icloud.com` and `mask-h2.icloud.com` are blocked, so Apple devices switch Private Relay off for the network. This applies to every device, paused or not, whatever the rules say, and these lookups show as blocked in history so the owner can see who tried. Android's Private DNS setting had no such signal. **Widened the same day** to other DNS services and other DNS servers: see "Found in the robustness review" above, and issue 93 for what is still open |
| 19 | **The relay's limits on guessing were kept in memory** and reset when it restarted | They are also kept in `relay.db` (a `throttle` table) and read back at start-up, dropping anything older than a day. At most 1,000 times are kept per name |
| 20 | **A relay address beginning `http://` was accepted**, which would send the Pi's token unprotected | Refused, before anything is sent, unless the host is `localhost`, `127.0.0.1` or `::1`. A Pi already paired with such an address by an older version never contacts it, and its Remote access card says to pair again with `https://` |
| 22 | **Every allowed lookup went to the internet** | Answers are kept in memory for their (shortened) lifetime, up to 5,000 of them, and cleared on any rule change. The rules are always checked for the asking device first, so a block bites on the very next lookup. Failures, empty replies, cut-short answers and home-router answers are not kept |
| 80 | **TCP lookups had no per-device share** | One device may hold at most 8 of the 64 TCP connections; more are closed at once |
| 81 | **The community list download could fail on a Mac** with Python from python.org | It uses the same secure-connection settings as the relay link, which borrow the system's certificate list when Python has none. Certificates are still always checked |
| 82 | **Dashboard reads held the database lock** | History questions (today's totals, the device list's history, the activity list) use a second, read-only connection with its own lock. Clearing one device's history goes 5,000 rows at a time, letting go of the lock between steps. Reads of the small tables (rules, devices, the scan's findings) still use the main lock; they are quick |
| 83 | **A device's activity list was sent in full every 30 seconds** | Each answer carries a marker; the page sends it back with the next request, and gets "unchanged" without the list when nothing has changed. Calls without the marker get the plain list as before |
| 12 (three of four points) | The README and `server.py` said blocked lookups were answered "that doesn't exist"; flex rows sat too close on Safari before 14.1; the dashboard didn't say when a scan was cut short | Both now say blocked names get the address `0.0.0.0` (or `::`). Where flex `gap` is ignored the page spaces rows with margins. The Devices page says when only the addresses nearest this computer were checked |

### In the fourth review (22 November)

| # | What was wrong | Fix |
| --- | --- | --- |
| 46 | **The kill switch, a switched-off "this device" or a whole-house bedtime also cut off QuietNet's own computer**, so the Pi lost its link to the relay (and could not be switched back on from outside), its clock and its list downloads | QuietNet's own computer is never cut off by these. Ordinary blocks (your own, the advert list, blocked services) still apply to it |
| 47 | **Names that skip the checks** (odd characters, home-network endings, reverse lookups) **were passed to the internet even while a device's internet was off**, so they could be used to get data out. A packet QuietNet couldn't read was passed on untouched | While a device's internet is off these get the blocked answer. An unreadable packet gets a "format error" answer, or none if it is too short or is itself an answer, and is never passed on |
| 48 | **Home-network names and reverse lookups of home addresses went to 1.1.1.1 and 8.8.8.8**, which can't answer them, and told those servers about the home network | They go to the home router (read from the Pi's routing table, looked up again every five minutes). If the router isn't known, or the router itself asked, the answer is "no such name". `.home.arpa` is now treated as a home ending too |
| 49 | **One device could take all 256 places for lookups**, stopping everyone else's | At most 16 per device (UDP) |
| 50 | **DNS answers could wait for the database** while the dashboard asked a question, the history was trimmed or cleared | The addresses remembered for the enforcer have their own lock; answering a lookup never waits for the database |
| 51 | **The network scan held the database lock for up to eight seconds** while it waited for device names | It waits for the names first and holds the lock only to save them |
| 52 | **Every history trim read the whole table** | Two steps, one finding old rows through the time index, the other surplus rows by row number |
| 53 | **The device list read through the whole history** to find each device's last lookup, on every refresh | It jumps from device to device in the index, so the work grows with the number of devices, not the size of the history |
| 54 | **The enforcer's plan worked out every remembered name for every device every two seconds** | Each name's answer is remembered and worked out again only for new names, after a rule change, or once a minute. Addresses are always read fresh |
| 55 | **The status summary joined both advert lists on every call** (every four seconds, 100,000+ names) | The count is worked out when a list changes |
| 56 | **This computer's address was only found at start-up**, so a Pi that started before its network was ready kept `127.0.0.1` | Looked up again every 10 seconds until found, then every minute; the enforcer is told. A lost network keeps the last good address |
| 57 | **The network scan assumed a network of 254 addresses**, missing devices on bigger home networks | It reads the real size from the routing table and scans all of it, up to 1,024 addresses (those around this computer, if the network is bigger). The answer says what was covered |
| 58 | **Any website could sign you out of the relay** by sending your browser to `/logout` | Opening `/logout` only shows a "Sign out?" button. Signing out needs a form carrying a token tied to your session |
| 59 | **One stranger sending wrong pairing codes stopped everyone pairing** (a single shared limit of 20), and a Pi on a `QUIETNET_PAIR` code gave up after one failure | Wrong codes are counted per network address (20 in 10 minutes), with a higher overall limit (200). The Pi tries its code again after any refusal except "wrong or expired", waiting 5 seconds at first and up to a minute |
| 60 | **Only two large answers could be read at once across the whole relay**, so one Pi could hold both places and everyone else's longer pages timed out | One at a time per account (so one person can't take all the room by pairing several Pis), and at most 48 MB across every account. An answer that can't get room within 10 seconds is refused and the browser told at once (`503`) |
| 61 | **A large answer could tie up the relay's memory**: a slow upload held its room for as long as it liked, and several copies of each answer were kept | A body must arrive within 30 seconds, reading stops if the browser has given up, and only one copy is kept |
| 62 | **Sign-ins with the right password were never limited**, so a flood of sign-ins could keep the relay's processor busy checking passwords | Every attempt counts: 30 per account and 60 per network address in 15 minutes (a browser that has signed in before has its own cap of 30). At most four passwords are checked at once; beyond that the answer is "The relay is busy" |
| 63 | **The relay had no limit on connections or threads** | At most 300 connections (more are told the relay is busy), 150 of them waiting Pis, one waiting poll per Pi, 10 seconds for a request's headers and 30 seconds for its body to arrive |
| 64 | **An account could create and pair QuietNets without limit**, filling the relay's disk | At most 10 per account, and 20 successful pairings a day |
| 65 | **Finding a Pi by its token or pairing code read the whole table**, and removed Pis stayed in the relay's memory | Indexes added (an existing database gains them at start-up); removed Pis are forgotten |
| 66 | **A relay cookie with non-English letters dropped the connection** | It counts as signed out |
| 67 | **A misspelt `QUIETNET_SIGNUP` left sign-up open** | Any value other than `open`, `first` or `closed` closes it, with a warning at start-up |
| 68 | **The Pi's link to the relay could stop for good after an unexpected error**, such as a cut-off answer during a relay restart, until the container was restarted | Every error is caught; the link tries again after 1 second, then longer, up to 30, and the Remote access card says what happened |
| 69 | **On a Mac with Python from python.org, pairing failed certificate checks**, and the message said the relay couldn't be reached | If Python has no certificate list, it borrows the system's own. If none is found, the message names "Install Certificates.command". Checks are never switched off. (The list download had the same fault until 23 November: issue 81) |
| 70 | **An accept in one firewall table hid a reject in another**, so with Docker and firewalld a device could be steered and lose its internet | Every table's forwarding chain is judged on its own |
| 71 | **The firewall advice was always Docker's command**, which does nothing for firewalld, or for ufw without Docker | The advice suits the firewall in the way, and every one in the way is listed with its own command |
| 72 | **With only `iptables`, three commands ran every two seconds** even with no device enforced | Nothing runs until a device is enforced; leftover rules are still emptied, including when the firewall lock was busy at start-up |
| 73 | **The dashboard's four-second refresh could overlap itself**, and fetched a device's whole activity list every time, even in a background tab | It waits for the previous refresh (for up to 30 seconds, so one request that never finishes can't stop it for good), pauses while the tab is hidden or a dialog is open, and fetches the activity list every 30 seconds |
| 74 | **The dashboard stuck on "Starting…" on Safari before 13.1** (iOS 12), because its script used a newer operator | The script uses only what those versions understand |
| 75 | **Dialogs appeared off-screen on Safari before 14.1**, so the page looked stuck after pressing the kill switch | The page spells out the positions those versions need |
| 76 | **Schedules ran on UTC inside the Pi container**, an hour or more out for most homes | The container shares the Pi's time zone and includes the time zone tables; `TZ` can name one instead |
| 77 | **On a Mac without Apple's developer tools, the launcher ran Apple's Python stand-in a second time**, ending on an error from Apple's tools | It recognises the stand-in, never runs it, and says how to get Python (python.org or `xcode-select --install`) |

### In the third review (22 November)

| # | What was wrong | Fix |
| --- | --- | --- |
| 25 | **A plain-text request could pass the dashboard's JSON check.** The check looked for the words `application/json` anywhere in the type, so a hostile page could send `text/plain; application/json`, which browsers send to another site without asking | The type must be exactly `application/json`; and a change whose browser-reported sender is not on this computer is refused |
| 19 | **A stranger could keep the owner locked out of the relay** by guessing wrongly on purpose; the overall limit could even lock everyone out | A browser that has signed in before carries a signed marker and gets its own limit instead of the shared ones (it still needs the right password). The marker is voided by a password change and removed at sign-out |
| 26 | **A Pi's large answers were refused by the relay.** The 64 KB limit applied to them too, so a busy device's longer history hung for 30 seconds and then failed | A paired Pi may answer a waiting call with up to 16 MB, two at a time (so self-paired "Pis" can't flood the relay's memory); anything bigger is replaced on the Pi by a short message |
| 23 | **The remote dashboard was slow**: the Pi handled relayed calls one at a time | Up to eight at once |
| 27 | **A Pi could answer a call meant for another Pi**, if it knew the call's id | Each call remembers which Pi it was sent to |
| 24 | **A flood of lookups queued without limit**; a TCP client could hold a thread for ever by sending a byte every few seconds; history had no size limit | At most 256 lookups in hand; at most 64 TCP connections, 8 seconds each; history capped at two million rows; stalled relay connections dropped after 30 seconds |
| 28 | **A forged DNS answer only had to guess the id** (once it came from the right address) | It must also repeat the question asked |
| 29 | **A crash or `docker kill` left devices steered at the Pi** and the kernel settings changed, with nothing to undo them | What is changed is written down as it happens, and undone at the next start (even if the enforcer can't run then) |
| 30 | **A device switched off from enforcing wasn't handed back** until it forgot the Pi by itself; with the last device, forwarding was switched off under it, cutting it off meanwhile | Handed back at once; forwarding stays on until every device has been handed back |
| 31 | **Steering went ahead even when forwarding couldn't be switched on**, as in a container, cutting the device off | Forwarding is read back; if it's off, nothing is steered and the device page says what to run on the Pi |
| 32 | **"Hand back" messages claimed to come from the router's hardware address**, which Wi-Fi drops and network switches mis-learn | They come from the Pi's own |
| 33 | **The router, the Pi itself or another network's addresses could be enforced** | Refused by the dashboard and skipped by the enforcer |
| 34 | **If an address passed to a different device, that device was steered** | Enforcing remembers the device's hardware address and leaves any other alone, saying so on the device page |
| 35 | **A steered device slipped back to the router for up to two seconds every half-minute** (each time it re-asked, the router's answer won) | The enforcer answers those questions itself, at once and again after Linux's one-second lock; measured: nothing got through in 146 seconds |
| 36 | **`iptables` failures went unnoticed**: commands didn't wait for the firewall lock, a failed rule was treated as loaded, and a removed jump was never put back | Waits for the lock; reloads until every command works; re-checks the jump every tick |
| 37 | **Advert-list addresses were cut by address**, which also cuts ordinary sites sharing them; pausing didn't pause the enforcer | The advert list stays a DNS-only block; pausing applies to the enforcer too |
| 38 | **The kernel settings couldn't be read or changed in the slim container**, which has no `sysctl` tool | Read and written through `/proc/sys` directly |
| 39 | **`docker logs` showed nothing** until much later, because output was held back | Output is sent at once |
| 40 | **The check for other firewalls trusted what it couldn't see**: a listing that failed counted as "all clear", and the container had no tool to read `iptables-legacy` rules | It fails closed, and the image includes the `iptables` commands for reading |
| 41 | **A flood of forged "who is the router?" questions could start unlimited threads** | One sending thread; repeat questions restart a device's plan instead of adding to it |
| 42 | **After something flushed `iptables`, QuietNet put its jump back but not its rules** | The chain's contents are checked too, and reloaded when needed |
| 43 | **The first history trim after upgrading could hold up DNS answers for many seconds** | Trimmed 5,000 rows at a time, letting go of the lock between steps |
| 44 | **The enforcer tests read the real machine's network**, so on a Pi or Linux runner about 20 of them failed | The tests use a fixed stand-in network |

### In the second review

| # | What was wrong | Fix |
| --- | --- | --- |
| 13 | **Another website could show the dashboard inside itself**, invisibly, and trick someone into clicking the kill switch or unblocking an address. The local dashboard has no login, so this worked against it directly | Both web servers now send headers on every answer that forbid being shown inside another page |
| 14 | **Forged DNS answers were accepted from any sender** that guessed the port and a two-byte id | The filter now accepts an answer only from the server it asked |
| 15 | **Enforcer rules piled up and never went away.** Loading the firewall table again added to the old rules. A device whose internet was switched off and then on again stayed cut off until QuietNet restarted | The rules text now deletes the old table before defining the new one, as a single step |
| 16 | **Ids and counts were put into the dashboard page unescaped.** Through the relay these come from a Pi the relay does not control, so a hostile "Pi" could have run script in the owner's signed-in page | Every value is now escaped |
| 17 | **The Pi's relay token and the history database were readable by other accounts** on the same machine | `cloud.json` is owner-only; both data folders are owner-only |
| 6 | **No limit on password or pairing-code guesses; codes never expired; unknown emails answered faster than wrong passwords** | Wrong guesses are counted and capped; codes last 15 minutes and a fresh one is issued when the page is opened; unknown emails take as long as wrong passwords; sign-up can be closed |
| 7 | **Request bodies were read whole, whatever their size**; a Pi could make the relay send any status code | Bodies over 64 KB are refused on both servers; only ordinary status codes are passed on |
| 9 | **Input of the wrong type dropped the connection** with no answer | Clean `400` refusals throughout the dashboard API |
| 10 | **An impossible address such as 999.999.999.999 could be enforced**, which stopped every firewall rule loading | The address must now be a real IPv4 address |
| 11 | **History queries read the whole table** on every dashboard refresh | A second index, and the devices query split in two so each part is answered from an index. The database is also told not to force the disk after every write, which suits an SD card |
| 12 | The community list stored `0.0.0.0` as a blocked name; the enforcer read a set while it could be changing | Both corrected |

### In the first review

| # | What was wrong | Fix |
| --- | --- | --- |
| 1 | The Pi container stopped at start-up: the `Dockerfile` left out `cloud_agent.py` | The file is copied |
| 2 | No way in on a Pi with no screen: the dashboard answers on `localhost` only, but the README pointed to the Pi's network address | `docker-compose.yml` passes the pairing settings through; the README describes the relay and an SSH tunnel |
| 3 | The enforcer left its firewall table and kernel settings behind on shutdown | Stopping waits for the clean-up; `docker stop` is handled like Ctrl-C |
| | The relay's documentation said passwords used scrypt | It uses PBKDF2; the wording is corrected |

Every fix has a test. `docs/TESTING.md` says which file covers which part.
