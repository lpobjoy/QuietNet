# Known issues

Found in a review of version 0.5 on 21 November 2026. Each entry says what is wrong, what it affects, and a suggested fix. The numbers are referred to from the tests and the other documents, so keep them stable; strike an entry through when it is fixed.

Entries marked **Tested** have a check in `tests/` that is currently an expected failure. It will start passing when the issue is fixed, and the test run will then say so.

## Needs testing on a real Pi

### 4. With Docker installed, an enforced device may lose all internet

Docker sets the host's rule for forwarded traffic to "drop unless allowed". The enforcer's own table accepts forwarded traffic, but an accept in one table does not override a drop in another. A steered device's traffic would then be dropped by Docker's rule, cutting the device off completely where only the blocked addresses were meant to go.

This could not be tested in the review. To check: enforce a device, block nothing for it, and see whether it can still browse.

**Fix if confirmed:** add an explicit accept for the home network's forwarded traffic in Docker's `DOCKER-USER` chain while the enforcer is active, and remove it on teardown.

### 5. IPv4 only

The DNS filter listens on IPv4 addresses only, and the enforcer steers and drops IPv4 only. On a home network with IPv6:

- a device given an IPv6 DNS server by the router will use that and skip QuietNet;
- an enforced device keeps any connection it made over IPv6.

**Fix:** listen for DNS on IPv6 as well. For the enforcer, either steer IPv6 too (neighbour advertisements in place of ARP) or state the limit on the device page.

## Relay security

### 6. Open sign-up, no limit on guesses, pairing codes that never expire

- Anyone who finds the relay's address can create an account. Accounts are separate from each other, so this exposes nothing, but it is an open door on a public server.
- There is no limit on login attempts or on pairing attempts.
- A pairing code is eight characters from 0–9 and A–F (about four billion possibilities) and stays valid until used. A stranger who guessed one would pair their own machine as your Pi and could show you false information. They would not gain control of your real Pi.

**Fix:** allow sign-up only while there are no accounts, or behind an invite code set as an environment variable. Limit attempts per address on `/login` and `/agent/pair`. Expire pairing codes after fifteen minutes.

### 7. Smaller relay points

- Signing out clears the cookie in the browser, but a copied cookie stays valid for its full 14 days. There is no way to end all sessions short of deleting the signing secret.
- Pi tokens are stored as plain text in `relay.db`. Storing a hash would mean a leaked database could not be used to pose as a Pi.
- Request bodies are read whole with no size limit.

## Filtering gaps

### 8. Devices that bring their own phone book

iCloud Private Relay, Android's Private DNS setting, and browsers with "secure DNS" switched on send lookups past QuietNet. The README mentions this briefly.

**Fix:** two widely used signals close most of it. Block `mask.icloud.com` and `mask-h2.icloud.com`, which makes Apple devices switch Private Relay off for that network. Answer "no such name" for `use-application-dns.net`, which makes Firefox use the network's DNS.

## Robustness

### 9. Input of the wrong type drops the connection — Tested

Several dashboard API calls assume the type of a value and fail if it is something else. The server thread raises an error and the connection closes with no reply. Nothing is changed, so no harm follows, but the answer should be a clean `400`.

- `/api/block`, `/api/unblock`, `/api/forget` with a `domain` that is a number
- `/api/pause` with `minutes` that is not a number

**Fix:** check the type before use in `clean_domain()` and the pause handler.
**Test:** `test_dashboard_api.BlockingAddresses.test_a_domain_that_is_not_text_is_refused_politely`

### 10. An impossible address can stall the enforcer

`/api/enforce` accepts any four groups of one to three digits, so `999.999.999.999` is accepted. The firewall tool rejects a rule containing it, and because the whole table is loaded at once, no rule changes take effect until that entry is removed.

**Fix:** validate with `ipaddress.IPv4Address` in place of the pattern.

### 11. History queries read the whole table

The status summary counts today's lookups by time, but the only index on the history table starts with the device address, so the database reads every row. The devices list groups the entire table on every refresh. With 30 days of a household's lookups this will become slow, most noticeably through the relay.

**Fix:** add an index on `queries(ts)`, and limit the devices query to recent history.

### 12. Minor

- The community list download accepts the line `0.0.0.0 0.0.0.0` from the source file and stores `0.0.0.0` as a blocked name. Harmless.
- `enforcement_plan()` reads the set of enforced devices while a dashboard request may be changing it. The enforcer catches the resulting error and tries again two seconds later.
- The README and the comment at the top of `server.py` say blocked lookups are answered "that doesn't exist". They are answered with the address `0.0.0.0`, which devices treat the same way.

## Fixed

### ~~1. The Pi container stops at start-up~~

`server.py` imports `cloud_agent`, but the `Dockerfile` did not copy `cloud_agent.py`, so `docker compose up` failed with `ModuleNotFoundError`. The file is now copied.
**Test:** `test_packaging.Containers.test_the_pi_container_includes_every_program_file_the_server_imports`

### ~~2. The dashboard cannot be opened on a Pi with no screen~~

The dashboard answers on `localhost` only, but the README said to open it at the Pi's network address, and `docker-compose.yml` gave no way to pair a Pi with a relay without the dashboard. The dashboard stays closed to the home network, which is the safer choice: opening it would let anyone in the house change the rules unless a password were added. In its place, `docker-compose.yml` now passes `QUIETNET_CLOUD` and `QUIETNET_PAIR` through, and the README describes the two ways in: the relay, or an SSH tunnel.
**Tests:** `test_packaging.Containers.test_compose_lets_a_pi_with_no_screen_be_paired`, `test_packaging.Readme.test_the_readme_does_not_send_people_to_an_address_that_is_refused`

### ~~3. The enforcer does not clean up when QuietNet stops~~

On Ctrl-C the program exited before the enforcer's clean-up ran, and `docker stop` was not handled at all, so the firewall table and kernel settings were left behind. `Enforcer.stop()` now waits for the clean-up to finish, the program treats `docker stop` the same as Ctrl-C, and the container is given 20 seconds to stop.
**Tests:** `test_enforcer.Teardown.test_stop_waits_until_the_network_has_been_restored`, `test_shutdown`

### Other

- The relay's documentation said passwords were hashed with scrypt. The code uses PBKDF2-SHA256. The wording in `cloud/README.md` and the comment at the top of `cloud/relay.py` now match the code.
