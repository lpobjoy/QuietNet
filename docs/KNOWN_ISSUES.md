# Known issues

Two reviews have been made: of version 0.5 on 21 November 2026, and a second, deeper pass the same day covering security, the software QuietNet depends on, and efficiency. A third, on 22 November, looked at the enforcer, the relay and the DNS filter, followed by an independent check of its fixes and a live test of the enforcer between two containers. A fourth, also on 22 November, looked again at every part (the DNS filter, the database, the relay, the Pi's link to it, the enforcer's firewall check, the dashboard page and the packaging) and fixed 32 points. On 23 November the open issues themselves were worked through: nine were closed (6, 8, 19, 20, 22, 80, 81, 82 and 83), five were narrowed (5, 7, 12, 21 and 78, each now stating only what is left), and one new point was found while checking the fixes (84). An independent check of those fixes the same day found eleven more faults in them, all fixed (see "Faults in the 23 November fixes" under Fixed), and closed 84. Later on 23 November a one-line installer was added; its open points are 85 to 88. This file lists what is still open, then what has been fixed.

The numbers are referred to from tests and other documents. Keep them stable.

## Open: needs testing on a real Pi

### 4. With Docker installed, an enforced device may lose all internet

Docker sets the host's rule for forwarded traffic to "drop unless allowed". An accept in the enforcer's own table does not override a drop in another, so a steered device would be cut off completely.

**Now handled (22 November):** before steering, the enforcer asks every firewall tool present whether another firewall would drop passed-on traffic. If one would, it does not steer, and the device page says what to run on the Pi. Once that accept is in place the check clears and steering starts.

Since the fourth review, each firewall table is judged on its own: an accept in Docker's table no longer hides a reject in firewalld's, because in the kernel each table decides separately. Every table in the way is named, each with a command that suits it: `sudo iptables -I DOCKER-USER -i eth0 -o eth0 -j ACCEPT` for Docker's, `sudo iptables -I FORWARD …` for a rule made with `iptables` without Docker (ufw, for example), and `sudo nft insert rule <family> <table> <chain> iifname eth0 oifname eth0 accept` for anything else, such as firewalld. These commands last until the firewall is reloaded: firewalld drops them on a reload and ufw on a restart, so on those hosts the owner needs to make the rule permanent in that firewall's own settings. This was confirmed in a two-container test with a Docker-style "drop" rule loaded: refused with the advice shown; the advice followed; steering started within 30 seconds and the device kept its internet. QuietNet does not add the accept itself, since that changes the owner's firewall.

**Still to check on a real Pi with Docker:** that the check spots Docker's real rules there, and that the advice clears it. With Docker and firewalld together: that steering stays refused until both commands have been run, then starts; and that the `nft insert` command works against a real firewalld table.

### 15. The firewall reload fix needs confirming on a Pi

Issue 15 (below, under Fixed) was confirmed against the real `nft` tool. On 22 November it was also confirmed with real steering between two containers: a steered device was cut off by the kill switch, and recovered within a few seconds of it being switched off, without restarting QuietNet. What remains is the same check with real devices on a real Pi.

### 45. The kill switch can let a little traffic through at first

In the two-container test, a steered device that was already settled sometimes got about one to three seconds of traffic through just after the kill switch was turned on. After that, nothing got through in 60 to 100 seconds of trying. The DNS block applies at once, so this only affects connections that were already open.

**Still to check on a real Pi:** how long the gap is with real devices (phones and TVs answer ARP differently from Linux). It is not being tuned further for now.

### 78. Home-network names sent to the router

Since the fourth review, names such as `printer.lan` or `nas.home`, and reverse lookups of home addresses, go to the home router instead of 1.1.1.1 (fixed issue 48). On 23 November the two gaps left in the code were closed:

- Single-word names (a plain `nas`, with no ending) now go to the home router too, or get "no such name" if the router isn't known. They never go to the public servers. The exception is a question about a single word with one of the record types used to check DNS signatures (NS, SOA, DS, RRSIG, NSEC, DNSKEY, NSEC3): that is a device checking signatures asking about a top-level name such as `com`, and it goes to the internet as before. Answering it "no such name" would make that device reject every `.com` name.
- If the same question (name and type) arrives while QuietNet is still waiting on the router for it, the answer is "server failure" rather than a second ask, so a router set up to send its lookups back to QuietNet can't make the two ask each other for ever. Two devices asking for the very same home name at the very same moment also get "server failure"; they simply ask again.

**Still to check on a real Pi:** that home names, single-word names included, resolve through a real router, and that the device name hints work when the Pi uses itself for DNS.

### 79. Other changes that need a real Pi or host

These could only be checked with stand-ins here:

- **Time zone in the container.** After `docker compose up -d --build`, `docker exec quietnet date` should show the Pi's local time, and the dashboard clock should match the Pi.
- **This computer's address changing.** When the Pi's address changes, the enforcer is told the new one. Check that its own-address rules follow within a minute.
- **A Pi with `iptables` but no `nft`.** With nothing enforced, no `iptables` commands should run each tick.
- **The relay behind Railway.** Limits per network address read the last entry of the `X-Forwarded-For` header. Check that Railway's proxy adds it there (rather than replacing the header) and that there is only one proxy in front. If every caller looks the same, the per-address limit behaves like the old shared one.
- **DNS over IPv6 (added 23 November).** On a home network with IPv6, check that the log does not say IPv6 listening failed, that the router actually gives devices the Pi's IPv6 address for DNS, and that such devices' lookups appear on the dashboard under their IPv4 address (matched through `ip -6 neigh`, which the rebuilt image now includes). Check that a lookup from a public IPv6 address outside the home range gets no answer, and that with a device switched off, its IPv6 lookups are blocked or refused.
- **The relay giving up root on Railway (added 23 November).** After a redeploy the log should say "Running as user 65534, group 65534, not root." Sign-up and sign-in should still save to `/data`, and an existing root-owned `relay.db` (with its `-wal` and `-shm` files) should be handed over and keep working. If Railway refuses the change of owner, the log shows the "still running as root" warning instead.
- **Row spacing on old Safari (added 23 November).** The dashboard spaces rows with margins where flex `gap` is ignored. This has not been seen on a real Safari before 14.1.

### 85. The one-line installer has not been run on a real Pi

`install.sh` (added 23 November) has only been run against stand-in commands, under dash and bash on a Mac and in a Debian container, and by hand under busybox ash in an Alpine container with no network. It has never installed real Docker, built the real image, or changed a real system's settings. **Still to check** (the steps are in [Testing](TESTING.md#checking-the-installer-on-a-real-pi)):

- Docker's own install script on Raspberry Pi OS, 64-bit and 32-bit. Docker has been winding down 32-bit Arm support, so on 32-bit Pi OS it may fail; the installer then points to Docker's own install guides for Debian and Ubuntu, which have not been followed on a Pi either. Also on the newest Pi OS and Debian release (Trixie).
- Switching off systemd-resolved's listener on Ubuntu, and that the Pi's own lookups still work after `/etc/resolv.conf` is re-pointed.
- The column layout of `ss -lntup` on each system, which the port 53 check reads.
- `sudo` asking for a password at the start of a piped install (and again if a long build outlasts sudo's 15-minute memory), sudo refusing a user not allowed to use it, and `ssh` without `-t`, the Pi's address in the closing message, and pairing appearing on the relay within a minute.
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

## Open: design decisions for the owner

### 5. IPv6: the enforcer, and devices known by two addresses

On 23 November the DNS half was fixed: the filter now also listens on IPv6 (`::`, same port, UDP and TCP), so a device given an IPv6 DNS server by the router is filtered too. If the computer has no IPv6, or the port can't be opened, it says so and carries on with IPv4. An IPv4 device reaching it over IPv6 (`::ffff:192.168.1.23`) is filed under its IPv4 address. The device page now says that "Cut live connections" works on IPv4 only. What remains:

- **The enforcer steers and drops IPv4 only.** An enforced device keeps any connection it made over IPv6. Steering IPv6 would need neighbour advertisements in place of ARP.
- **A device asking from a real IPv6 address is matched to its IPv4 address by hardware address**, using the IPv6 neighbour table and the IPv4 devices from the last scan and the neighbour table, looked at again every minute. Matched, it is filed under its IPv4 address and all its rules apply. If it can't be matched (a new temporary address in its first minute, or a device QuietNet has never seen over IPv4) and any rule names a particular device or group, the answer is "refused", and the device asks QuietNet's IPv4 address instead. A device given only an IPv6 DNS server, and never seen by QuietNet over IPv4, would get no answers at all while such rules exist. With no device or group rules, an unmatched device is answered and shows up apart from its IPv4 address. Before this was fixed (later on 23 November), the IPv6 listener was a way round device rules: a child's phone asking from its IPv6 address got real answers during its group's bedtime.
- On the Pi, matching needs the `ip` tool (`iproute2`, now in the image). Without it nothing is matched, so with device rules in place every IPv6 lookup from a real IPv6 address is refused.

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
| 8 | **Devices that bring their own phone book** (Firefox's secure DNS, iCloud Private Relay) sent lookups past QuietNet | `use-application-dns.net` gets "no such name", so Firefox uses the network's DNS; `mask.icloud.com` and `mask-h2.icloud.com` are blocked, so Apple devices switch Private Relay off for the network. This applies to every device, paused or not, whatever the rules say, and these lookups show as blocked in history so the owner can see who tried. Android's Private DNS setting has no such signal and is not covered |
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
