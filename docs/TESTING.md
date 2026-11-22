# Testing

## Running the tests

From the repository folder:

```bash
python3 -m unittest discover tests
```

Nothing needs installing. The run takes about sixteen seconds and ends with a line such as:

```
Ran 312 tests in 16.5s

OK
```

To run one file, or one test:

```bash
python3 -m unittest tests/test_relay.py
python3 -m unittest tests.test_relay.Relaying.test_another_account_cannot_reach_your_pi
```

`pytest tests` also works if you have it.

## What the tests are safe to do

- They use throwaway data folders. Your real history and rules are never read or changed.
- They contact nothing outside the computer. Where the code would reach the internet, a stand-in on the same computer answers. One exception: `test_shutdown.py` starts the real program for a moment, and at start-up it asks the local network for the names of nearby devices.
- `test_shutdown.py` is skipped (the run reports `skipped=2`) on a Linux machine with admin rights and a firewall tool, because there the real enforcer could start. Run the tests as an ordinary user to include it.
- They need no admin rights. The enforcer's raw socket, firewall command and kernel settings are replaced with stand-ins that record what they were asked to do.
- Web servers are started on spare ports chosen by the operating system, so they do not clash with a running QuietNet.

## What each file covers

| File | Tests | Covers |
| --- | --- | --- |
| `test_quietnet.py` | 47 | The rules engine: adverts, your own blocks and allows, services, groups, pause, the kill switch, schedules (including overnight and week-wrap), answer lifetimes, and the enforcer's plan and rule text |
| `test_dns.py` | 49 | Reading questions and refusing malformed ones; blocked answers for each record type; pulling addresses out of answers; what is recorded and what is not; the address helpers; the community list download; that forged answers are ignored; and the real filter running over UDP and TCP against a stand-in upstream |
| `test_dashboard_api.py` | 68 | Every dashboard API call over real HTTP: the `Host` and JSON guards, blocking, switches, groups, schedules, devices, activity, history, enforcement and remote access settings; the protective headers, size limits and wrong-type input; that history questions use an index; and that changes survive a restart |
| `test_enforcer.py` | 67 | What the enforcer sends and to whom; that it never touches this computer or devices not chosen; firewall reloads only on change, and each reload replaces the old rules; kernel settings switched, read back and restored; refusing to steer when forwarding is off or another firewall would drop traffic; handing devices back the moment they leave the plan; never steering the router, itself or other networks; the hardware-address guard; notes on disk and recovery after a crash; `iptables` waiting for its lock, retrying, and reloading after an outside flush; spotting Docker's and firewalld's rules, and not steering when they can't be read; answering "who is the router?" with one thread however many questions arrive; tidying up when it can't start, and starting once the network appears; teardown, and that stopping waits for it; when it reports itself unavailable; reading the routing table |
| `test_relay.py` | 89 | Password records; session cookies and tampering; the bridge between browser and Pi; sign-up, login and sign-out; pairing codes; that one account cannot reach another's Pi; the forged-request guard; offline and timeout answers; that one Pi can't answer for another; large answers from a paired Pi; that a browser which signed in before can't be locked out by strangers, has its own cap, loses its marker on a password change or sign-out; that only a waiting call can bring a large answer; that a stalled connection is dropped; the remote dashboard page; limits on wrong guesses; pairing code expiry; closing sign-up; upgrading a 0.5 database |
| `test_cloud_agent.py` | 25 | Pairing and saving the token, readable by its owner only; set-up from environment variables; running a relayed request against the local dashboard; the polling loop; that a slow call doesn't hold up the next; that an answer too big to relay becomes a short message; what happens when the relay unpairs the Pi, fails or cannot be reached |
| `test_packaging.py` | 36 | Standard library only; the containers include what the programs import; the compose file passes the pairing settings; `services.json` and `junk_domains.txt` are well formed with no overlaps; the dashboard calls only API addresses the server has; the README lists every file; every function and class has a docstring |
| `test_shutdown.py` | 2 | Starts the whole program and stops it with Ctrl-C and with the signal `docker stop` sends; checks it exits cleanly |

## Expected failures

There are none at present. When a fault is found that cannot be fixed straight away, write the test for the correct behaviour, mark it `@unittest.expectedFailure`, and point it at an entry in [Known issues](KNOWN_ISSUES.md). The run stays green, and reports "unexpected success" once the fault is fixed, which is the cue to remove the mark.

## Automatic runs

`.github/workflows/tests.yml` runs the suite on every push to `main` and every pull request, on Linux with Python 3.13 (what the containers use) and on macOS with the Python that Apple supplies (what the Mac launcher prefers).

## Writing more

The existing files share a few helpers, all in `test_quietnet.py`:

- `Base`: a test class whose `setUp` empties the rule tables and reloads the rules, so each test starts clean.
- `query(name, qtype)`: builds a DNS question packet.
- `fake_answer(data)`: the reply a real upstream would give, with a one-day lifetime.
- `is_blocked(name, client)`: asks the filter and reports whether the answer was the block address.
- `at(day, "HH:MM")`: a moment on a given weekday, for schedule tests.

Conventions: one behaviour per test; the test name states the behaviour in plain words; a comment explains any check whose reason is not obvious from the name.

## Not covered

These need a real network or a real host, and are not tested automatically:

- The enforcer on a real Pi with real devices. On 22 November it was tested between two containers on one Docker network, standing in for the Pi and a device: steering; non-blocked traffic still flowing; the kill switch cutting the device within about a second and lifting cleanly; nothing getting through over 146 seconds while cut off; hand-back when switched off; refusing to steer while forwarding was off, and while a Docker-style "drop" rule was loaded (then steering once the advised accept was added); recovery after `docker kill`; and a clean `docker stop`. What remains is a real Pi, real devices and Docker's real rules (issues 4 and 15).

  To repeat that test: build the image, create a Docker network, start a plain `python:3.13-slim` container on it as the "device", and start QuietNet on the same network with `--cap-add NET_ADMIN --cap-add NET_RAW --sysctl net.ipv4.ip_forward=1`. Have QuietNet send the device any packet so it learns the device's hardware address, enforce the device through the API (inside the QuietNet container, POST JSON to `http://127.0.0.1:8377/api/enforce` with `Host: localhost`), and watch the device's `/proc/net/arp` entry for the router change to QuietNet's hardware address. Test cutting with a UDP DNS question from the device to `1.1.1.1`.
- The network scan (`scan_network`) and host-name lookups, which depend on the devices present.
- The dashboard page in a browser. Its API calls are checked against the server, but its behaviour is not.
- Building and starting the containers.
- The relay under load, or with many Pis.

A short manual check after changing the enforcer or the containers:

1. `docker compose up -d` on the Pi; confirm `docker logs quietnet` shows "QuietNet is running".
2. Point one device at the Pi for DNS and confirm it appears on the Devices page.
3. Block a service for that device and confirm a new connection fails.
4. Turn on "Cut live connections", start a stream, block its service, and confirm the stream stops within a few seconds while other sites still load. Unblock it and confirm the service works again without restarting QuietNet.
5. `docker stop quietnet`, then confirm the device still has internet and `nft list tables` on the Pi shows no `quietnet` table.
