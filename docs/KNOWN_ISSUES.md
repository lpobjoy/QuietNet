# Known issues

Two reviews have been made: of version 0.5 on 21 November 2026, and a second, deeper pass the same day covering security, the software QuietNet depends on, and efficiency. A third, on 22 November, looked at the enforcer, the relay and the DNS filter, followed by an independent check of its fixes and a live test of the enforcer between two containers. A fourth, also on 22 November, looked again at every part (the DNS filter, the database, the relay, the Pi's link to it, the enforcer's firewall check, the dashboard page and the packaging) and fixed 32 points. This file lists what is still open, then what has been fixed.

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

Since the fourth review, names such as `printer.lan` or `nas.home`, and reverse lookups of home addresses, go to the home router instead of 1.1.1.1 (fixed issue 48). Two gaps remain:

- QuietNet will not send a name back to the router if the router itself asked. But a router set up to send its own lookups to QuietNet through another route could still make the two ask each other in turn.
- Single-word names (a plain `nas`, with no ending) still go to the public servers. Some routers answer those for home devices.

**Still to check on a real Pi:** that home names resolve through a real router, and that the device name hints work when the Pi uses itself for DNS.

### 79. Other fourth-review changes that need a real Pi or host

These could only be checked with stand-ins here:

- **Time zone in the container.** After `docker compose up -d --build`, `docker exec quietnet date` should show the Pi's local time, and the dashboard clock should match the Pi.
- **This computer's address changing.** When the Pi's address changes, the enforcer is told the new one. Check that its own-address rules follow within a minute.
- **A Pi with `iptables` but no `nft`.** With nothing enforced, no `iptables` commands should run each tick.
- **The relay behind Railway.** Limits per network address read the last entry of the `X-Forwarded-For` header. Check that Railway's proxy adds it there (rather than replacing the header) and that there is only one proxy in front. If every caller looks the same, the per-address limit behaves like the old shared one.

## Open: design decisions for the owner

### 5. IPv4 only

The DNS filter listens on IPv4 addresses only, and the enforcer steers and drops IPv4 only. On a home network with IPv6:

- a device given an IPv6 DNS server by the router will use that and skip QuietNet;
- an enforced device keeps any connection it made over IPv6.

**Fix:** listen for DNS on IPv6 as well. For the enforcer, either steer IPv6 too (neighbour advertisements in place of ARP) or state the limit on the device page.

### 6. Sign-up on the relay is open unless you close it

Anyone who finds the relay's address can create an account. Accounts cannot see each other's Pis, so this exposes nothing, but it is an open door on a public server. A setting now exists to close it: `QUIETNET_SIGNUP=first` allows only the first account, and `closed` allows none. The default is still `open`, so that existing set-ups behave as before. Since the fourth review, a misspelt value (anything other than `open`, `first` or `closed`) closes sign-up and is warned about at start-up, rather than leaving it open.

**Recommended:** set `QUIETNET_SIGNUP=first` on Railway. Consider making it the default.

### 8. Devices that bring their own phone book

iCloud Private Relay, Android's Private DNS setting, and browsers with "secure DNS" switched on send lookups past QuietNet.

**Fix:** two widely used signals close most of it. Block `mask.icloud.com` and `mask-h2.icloud.com`, which makes Apple devices switch Private Relay off for that network. Answer "no such name" for `use-application-dns.net`, which makes Firefox use the network's DNS.

### 18. The local dashboard has no password

Anyone who can open `http://localhost:8377` on the QuietNet computer controls it: another account on the same machine, or anyone with an SSH login. This is by design for a single-owner home machine. It matters if the Pi is shared.

### 19. Limits on guessing are kept in memory

The relay's limits reset when it restarts. (The lock-out half of this issue is fixed: see below.)

## Open: smaller security points

### 7. Relay

- Signing out clears the cookie in the browser, but a copied cookie stays valid for its full 14 days. The only way to end every session is to delete the `secret` row in `relay.db`.
- Pi tokens are stored as plain text in `relay.db`. Storing a hash would mean a leaked database could not be used to pose as a Pi. The data folder is now private to its owner, which narrows this.
- The sign-in form carries no one-time token, so another site could sign a visitor in to the attacker's own account ("login forgery"). The visitor would see the attacker's QuietNets, not their own. Low risk.
- The sign-up form says when an email already has an account. Low risk for a single-owner relay.
- The overall cap on wrong pairing codes was raised from 20 to 200 in 10 minutes, now that each network address has its own cap of 20. Codes are 32 bits, so someone guessing without stop has about a 1 in 400 chance a year of hitting a given live code, against about 1 in 4,000 before. Judged acceptable; the owner may want to confirm.
- The relay's room for large answers (48 MB) counts each answer's stated size. While one is being read, memory briefly reaches two to three times that size.

### 80. TCP lookups have no per-device share

Since the fourth review, one device can hold at most 16 of the 256 places for lookups over UDP (fixed issue 49). Lookups over TCP still share 64 connections across the house with no per-device share, so one device could fill them. TCP is used only for large answers, so ordinary lookups are not affected.

### 81. The community list download can fail on a Mac with Python from python.org

That Python has no certificate list of its own until "Install Certificates.command" is run. The Pi's link to the relay now borrows the system's list in that case (fixed issue 69), but the community advert list download in `server.py` does not, so it fails with a certificate error.

**Fix:** use `cloud_agent.tls_context()` for the download too.

### 20. A relay address beginning `http://` is accepted

The Pi will pair with a relay over plain HTTP if given such an address. Over the internet that would send the Pi's token unprotected. An address typed without a scheme gets `https://`, so this needs a deliberate `http://`. It is left in for running a relay on the same machine during development.

**Fix:** refuse `http://` unless the host is `localhost` or `127.0.0.1`.

### 21. Both containers run as the root user

The Pi container needs network rights that are simplest to hold as root. The relay does not need them, but Railway mounts its storage volume owned by root, so an unprivileged relay could not write its database without extra set-up.

## Open: efficiency

### 22. Every allowed lookup goes to the internet

QuietNet keeps no memory of answers. Because it also cuts every answer's lifetime to 120 seconds, devices ask again often, and each ask is a round trip to 1.1.1.1. On a busy home network that adds delay and traffic.

**Fix:** keep answers in memory for their (shortened) lifetime, keyed by name and record type, and clear the memory whenever a rule changes.

### 82. Dashboard reads still hold the database lock

Since the fourth review, DNS answers never wait for the database (fixed issue 50). But clearing the history, and the dashboard's own history questions, still hold the database lock while they run, so they can hold up other dashboard calls and the history writer for a moment.

**Fix:** a second, read-only database connection for the dashboard's questions.

### 83. A device's activity list is sent in full every 30 seconds

Since the fourth review, the dashboard fetches an open device's activity list every 30 seconds rather than every 4 (fixed issue 73). The server has no way to say "nothing has changed", so each fetch still sends the whole list, which for a busy device over a week is large, especially through the relay.

**Fix:** let the page send back a marker of the last change it saw, and answer "unchanged" when nothing is new; or cap the names listed per company.

### 12. Minor

- The README and the comment at the top of `server.py` say blocked lookups are answered "that doesn't exist". They are answered with the address `0.0.0.0`, which devices treat the same way.
- The enforcer drops addresses handed out in the last six hours. A service that moves to new addresses is covered as soon as the device looks them up through QuietNet.
- On Safari before 14.1, rows of buttons and labels sit closer together than intended (the page uses flex `gap`, which those versions ignore). Nothing breaks or disappears.
- When a network is too big to scan in full, the scan covers the 1,024 addresses around this computer and the API says so (`capped`), but the dashboard page does not yet tell the person.

## Software QuietNet depends on

QuietNet uses **no third-party Python packages**, so there is no package list to scan. A test (`test_packaging.StandardLibraryOnly`) keeps it that way. What it does depend on:

| Dependency | Where | State on 21 November 2026 |
| --- | --- | --- |
| Python 3.13 | Both containers (`python:3.13-slim`) | In its security-fixes-only period, supported until October 2028. Latest is 3.13.18 (25 October 2026). The image tag follows the newest 3.13 release each time the container is rebuilt |
| Debian packages, including `nftables` | Pi container | Installed fresh at build time |
| Python 3.9 from Apple | macOS, via `Start QuietNet.command` | Python 3.9 is past the end of its upstream support. Apple maintains its own copy on its own timetable |
| StevenBlack hosts list | Downloaded on request | Data only. Each line is checked before use and nothing in it is executed |

The Python security fixes published during 2026 were checked against the modules QuietNet uses (`http.server`, `urllib`, `sqlite3`, `socket`, `ssl` as a client, `hashlib`, `hmac`, `json`, `subprocess`, `webbrowser`). Those found:

- Fixes to `tarfile`, `zipfile`, `tempfile`, the XML parser and `mimetypes`: QuietNet does not use these.
- A use-after-free in server-side TLS with certain callbacks: QuietNet never serves TLS itself. The host does that for the relay.
- A memory denial-of-service in `http.client` (fixed in 3.13.11): the Pi's link to the relay uses this module, so the fix matters. Any image built since December 2025 has it.
- Option injection in `webbrowser.open()` through a crafted address: QuietNet opens only its own fixed `localhost` address.
- Removal of trust in a compromised certificate authority (3.13.18): applies to the Pi's HTTPS connections to the relay and to the list download. Rebuild to pick it up.

**To do:** rebuild both containers so they carry 3.13.18. `.github/dependabot.yml` now asks GitHub to open a pull request whenever a newer base image appears. On a Mac, running QuietNet with a current Python from python.org is safer than Apple's 3.9, though the scan feature works best with Apple's (see the launcher's comment).

This check used the published release notes. It is not a scan of the built image, which needs a tool such as `docker scout` or `trivy` run against the image itself.

## Fixed

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
| 69 | **On a Mac with Python from python.org, pairing failed certificate checks**, and the message said the relay couldn't be reached | If Python has no certificate list, it borrows the system's own. If none is found, the message names "Install Certificates.command". Checks are never switched off. (The list download still has this fault: issue 81) |
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
