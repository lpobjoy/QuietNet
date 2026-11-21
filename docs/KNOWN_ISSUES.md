# Known issues

Two reviews have been made: of version 0.5 on 21 November 2026, and a second, deeper pass the same day covering security, the software QuietNet depends on, and efficiency. This file lists what is still open, then what has been fixed.

The numbers are referred to from tests and other documents. Keep them stable.

## Open: needs testing on a real Pi

### 4. With Docker installed, an enforced device may lose all internet

Docker sets the host's rule for forwarded traffic to "drop unless allowed". The enforcer's own table accepts forwarded traffic, but an accept in one table does not override a drop in another. A steered device's traffic would then be dropped by Docker's rule, cutting the device off completely where only the blocked addresses were meant to go.

This could not be tested in review. To check: enforce a device, block nothing for it, and see whether it can still browse.

**Fix if confirmed:** add an explicit accept for the home network's forwarded traffic in Docker's `DOCKER-USER` chain while the enforcer is active, and remove it on teardown.

### 15. The firewall reload fix needs confirming on a Pi

Issue 15 (below, under Fixed) was confirmed and fixed against the real `nft` tool in a test machine, but not with real devices. To check: enforce a device, switch its internet off, confirm it is cut off, switch it back on, and confirm it recovers within a few seconds without restarting QuietNet.

## Open: design decisions for the owner

### 5. IPv4 only

The DNS filter listens on IPv4 addresses only, and the enforcer steers and drops IPv4 only. On a home network with IPv6:

- a device given an IPv6 DNS server by the router will use that and skip QuietNet;
- an enforced device keeps any connection it made over IPv6.

**Fix:** listen for DNS on IPv6 as well. For the enforcer, either steer IPv6 too (neighbour advertisements in place of ARP) or state the limit on the device page.

### 6. Sign-up on the relay is open unless you close it

Anyone who finds the relay's address can create an account. Accounts cannot see each other's Pis, so this exposes nothing, but it is an open door on a public server. A setting now exists to close it: `QUIETNET_SIGNUP=first` allows only the first account, and `closed` allows none. The default is still `open`, so that existing set-ups behave as before.

**Recommended:** set `QUIETNET_SIGNUP=first` on Railway. Consider making it the default.

### 8. Devices that bring their own phone book

iCloud Private Relay, Android's Private DNS setting, and browsers with "secure DNS" switched on send lookups past QuietNet.

**Fix:** two widely used signals close most of it. Block `mask.icloud.com` and `mask-h2.icloud.com`, which makes Apple devices switch Private Relay off for that network. Answer "no such name" for `use-application-dns.net`, which makes Firefox use the network's DNS.

### 18. The local dashboard has no password

Anyone who can open `http://localhost:8377` on the QuietNet computer controls it: another account on the same machine, or anyone with an SSH login. This is by design for a single-owner home machine. It matters if the Pi is shared.

### 19. Limits on guessing are simple by design

The relay's limits are kept in memory, so they reset when it restarts. The per-account limit (five wrong passwords in fifteen minutes) means a stranger who knows your email can keep you locked out by guessing wrongly on purpose. For a self-hosted relay with one owner this is a fair trade; a public service would want something finer.

## Open: smaller security points

### 7. Relay

- Signing out clears the cookie in the browser, but a copied cookie stays valid for its full 14 days. The only way to end every session is to delete the `secret` row in `relay.db`.
- Pi tokens are stored as plain text in `relay.db`. Storing a hash would mean a leaked database could not be used to pose as a Pi. The data folder is now private to its owner, which narrows this.
- The sign-in form carries no one-time token, so another site could sign a visitor in to the attacker's own account ("login forgery"). The visitor would see the attacker's QuietNets, not their own. Low risk.
- The sign-up form says when an email already has an account. Low risk for a single-owner relay.

### 20. A relay address beginning `http://` is accepted

The Pi will pair with a relay over plain HTTP if given such an address. Over the internet that would send the Pi's token unprotected. An address typed without a scheme gets `https://`, so this needs a deliberate `http://`. It is left in for running a relay on the same machine during development.

**Fix:** refuse `http://` unless the host is `localhost` or `127.0.0.1`.

### 21. Both containers run as the root user

The Pi container needs network rights that are simplest to hold as root. The relay does not need them, but Railway mounts its storage volume owned by root, so an unprivileged relay could not write its database without extra set-up.

## Open: efficiency

### 22. Every allowed lookup goes to the internet

QuietNet keeps no memory of answers. Because it also cuts every answer's lifetime to 120 seconds, devices ask again often, and each ask is a round trip to 1.1.1.1. On a busy home network that adds delay and traffic.

**Fix:** keep answers in memory for their (shortened) lifetime, keyed by name and record type, and clear the memory whenever a rule changes.

### 23. The remote dashboard is slower than it needs to be

Each refresh of the dashboard makes three to six API calls. Through the relay each one is a separate round trip, and the Pi handles them one at a time: it asks the relay for work, does one call, answers, and asks again. On a slow link the page lags.

**Fix:** let the Pi take several waiting calls per poll and answer them together, or add one combined "everything this tab needs" call.

### 24. A flood of lookups queues without limit

The UDP listener hands every lookup to a pool of 64 workers. If lookups arrive faster than they can be answered (a misbehaving device, or the upstream servers being unreachable), the waiting list grows without bound.

**Fix:** drop new lookups when more than a few hundred are waiting. Devices retry on their own.

### 12. Minor

- The README and the comment at the top of `server.py` say blocked lookups are answered "that doesn't exist". They are answered with the address `0.0.0.0`, which devices treat the same way.
- The enforcer drops addresses handed out in the last six hours. A service that moves to new addresses is covered as soon as the device looks them up through QuietNet.

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
