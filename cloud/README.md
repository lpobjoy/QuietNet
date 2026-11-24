# QuietNet relay

Lets you reach your home QuietNet (on a Raspberry Pi) from anywhere, without
changing your router. You host this small service; the Pi connects out to it.

It uses only the Python standard library.

## Deploy on Railway

1. Push this repository to GitHub (already done if you're reading it there).
2. In Railway: **New Project → Deploy from GitHub repo**, pick this repo.
3. Set these in the service on Railway (see "The service's settings" below for why they are not in
   the repository):
   - Variable `RAILWAY_DOCKERFILE_PATH` = `cloud/Dockerfile`. Railway then builds the relay's
     container from that file, with the repository's top folder as the build context, which the
     file needs.
   - **Builder** Dockerfile (the service's Settings, under Build). Railway picks it by itself once
     it finds the file, but a service first built some other way can keep Railpack, so set it.
   - **Healthcheck path** `/healthz` (the service's Settings, under Deploy). A new deploy only takes
     over once the relay answers there.
   - **Restart policy** On Failure, which is Railway's default.
   - Leave the start command empty: the Dockerfile's last line starts the relay.

   Railway provides the public HTTPS address and the `PORT`.
4. Add a **Volume** mounted at `/data` so accounts survive redeploys.
5. Sign-up needs no setting: by default (`QUIETNET_SIGNUP=first`) only the first account can be created, which should be yours, so create it straight after deploying. The values are `first` (the default), `open` (anyone who finds the address can make an account; they still cannot see your Pi) and `closed`. Any other value, such as a misspelling, switches sign-up off and the relay's log warns about it. The log says at start-up which setting is in force.

   **Upgrading a relay set up before this default changed:** existing accounts are kept and can still sign in, but new sign-ups stop once any account exists. If you relied on the old default to let others sign up, add `QUIETNET_SIGNUP=open`. Everyone will need to sign in again once after the upgrade, because the session cookie changed.
6. Open the Railway URL, create your account, sign in with it, and choose **Add a QuietNet** to get a
   pairing code. For a new Pi, the page shows one line to run on it, which installs QuietNet and
   pairs it in one go. For a Pi already running QuietNet, enter the code (and the Railway URL) on
   the Pi's own QuietNet page under **Remote access**. The code works once and for 15 minutes;
   reload the page for a new one. One account can hold up to 10 QuietNets and pair up to 20 a day.

## The service's settings

The repository has no `railway.json`. Railway stops reading those files on 1 December 2026. Its
replacement, a `.railway/railway.ts` file, needs Railway's npm package installed in the
repository. Its Python and Go versions need a pip package or a Go module, and QuietNet uses no
outside packages. That file is also never read when the relay is deployed: the Railway command line
copies it into the service's settings when someone runs `railway config apply`. So the settings
live in the service on Railway itself, and this page is where they are written down:

| Setting | Value | Where on Railway |
| --- | --- | --- |
| How to build | With Docker, from `cloud/Dockerfile` | Variable `RAILWAY_DOCKERFILE_PATH=cloud/Dockerfile`, and Settings, Build: builder Dockerfile |
| Build context | The repository's top folder | Railway's default. `railway up` uploads from where it is run |
| Start command | None. The Dockerfile's `CMD ["python3", "relay.py"]` starts the relay | Settings, Deploy: leave the start command empty |
| Health check | `/healthz`, which answers `{"ok": true}` | Settings, Deploy: healthcheck path |
| Restart policy | On Failure | Settings, Deploy (Railway's default) |
| Storage | A volume mounted at `/data` | The service's Volumes |

If you change one of these on Railway, change this table too.

**Moving a relay that was set up with `railway.json`.** Do these in order, before the copy of the
repository you deploy from loses `railway.json`. While the file is there it overrides the service's
settings, so setting the same values now changes nothing:

1. Set `RAILWAY_DOCKERFILE_PATH=cloud/Dockerfile` on the service. From the folder linked to the
   project, `railway variable set RAILWAY_DOCKERFILE_PATH=cloud/Dockerfile --skip-deploys` does it
   without starting a deploy. On the website, the variable waits until you press Deploy.
2. In the service's Settings, under Build: set the builder to Dockerfile. Under Deploy: set the
   healthcheck path to `/healthz`, check the restart policy is On Failure and the start command is
   empty. Railway holds changes made on its website until you press the Deploy button on the banner
   it shows. That redeploys what is running now, `railway.json` and all, which is safe. Until then
   `railway config pull --json` doesn't list the new values, and the build log shows no health check.
3. Optional: `railway config migrate status`, from the linked folder, lists any service that still
   has a config file path set. If this one does, clear it in the service's Settings (the config file
   path field); after 1 December Railway ignores it anyway. `railway config migrate cutover` also
   clears it and changes nothing else, but it is meant for moving to `.railway/railway.ts`, so
   there is no need for it here.
4. Deploy from a copy of the repository without `railway.json`, then check the deploy as below.

If a deploy builds the wrong thing, put `railway.json` back (it still works until 1 December) and
redeploy while you look into it.

**Checking a deploy.** After every deploy that follows a change to these settings:

1. **It built from `cloud/Dockerfile`.** Run `railway logs --build` from the linked folder, or open
   the build log on Railway. It should show the Dockerfile's steps: `FROM python:3.13-slim`, then
   `COPY cloud/relay.py ./relay.py` and `COPY static ./static`. If the log talks about Railpack or
   Nixpacks, or installing packages, Railway did not find the variable: check
   `RAILWAY_DOCKERFILE_PATH` and redeploy. The "Config as Code is deprecated" warning should be gone.
2. **The health check ran on `/healthz`.** The deploy log should show the health check starting on
   path `/healthz` and succeeding before the deploy goes live. If it shows no health check at all,
   the healthcheck path is not set.
3. **The relay answers.** `curl -s https://<your relay>/healthz` prints `{"ok": true}`.
4. **It started as before.** `railway logs --deployment` shows the start-up lines, among them
   "Running as user 65534, group 65534, not root." and the licence gate line. Sign in and open a Pi.

## Licences

Each account has a licence, which decides whether it can reach its Pis through the relay and add or pair Pis. Blocking at home never depends on it: a Pi whose licence has lapsed stays paired, keeps filtering, and its paused page keeps two buttons to turn the internet back on for every device or pause blocking for an hour.

- `QUIETNET_LICENCE_GATE`: `on` enforces licences. Anything else, including leaving it unset (the default), lets everything through and only logs what would have been refused (lines starting "Licence gate:", at most once an hour per account and kind of refusal). The start-up log says which (the relay writes each start-up line out at once, so it shows in Railway's log straight away).
- `QUIETNET_LATEST`: the newest QuietNet version, such as `0.6`, told to paired Pis so they can say an update is out. Leave it unset until there is one. A value that isn't a plain version number is ignored, with a warning in the log.

**The command line.** Licences are managed from inside the relay's own container, never from a web page. Reach it with `railway ssh` (not `railway run`, which runs the command on your own computer), then:

```
python relay.py licence show <email>
python relay.py licence list
python relay.py licence grant <email> --plan owner|gift|legacy [--days N] [--seats N]
python relay.py licence revoke <email> --reason "..."
python relay.py licence restore <email>
python relay.py licence seats <email> N
```

`--days` left out, or 0, means no end date. `--seats` is how many Pis it covers, 1 to 10; left out, it keeps the licence's current seats (2 for a new licence). `revoke` keeps the plan and dates and records the reason; `restore` makes it active again with the same end date. The account is found by its current email. Every change is written to the licence's log, which `show` prints. `list` prints every account on the relay, one line each, with its licence (id, state, plan and end date) and its Pis, and changes nothing. A wrong command (including a missing or blank `--reason`) exits with status 2; an unknown email, or changing a licence the account doesn't have, exits with 1. Like the relay itself, the command gives up root before opening the database, so the database stays writable by the running relay.

**Going live, in order:**

1. Deploy with `QUIETNET_LICENCE_GATE` unset. On its first start the relay gives every account that already exists a `legacy` licence, active for 90 days, covering at least 2 Pis (or as many as the account has). This happens once; restarts don't repeat or extend it. Accounts made later have no licence until you grant one.
2. Check `QUIETNET_SIGNUP`, and run `python relay.py licence list` to see every account and its licence.
3. Give your own account a licence with no end: `python relay.py licence grant <your email> --plan owner --seats N`. Give any other existing account an end date you choose (`--plan legacy --days N`), and tell its owner.
4. Watch the log for a few days (Railway's log, and `licence show`). With your account granted there should be no "Licence gate" lines for it.
5. Set `QUIETNET_LICENCE_GATE=on` and redeploy. If anything pauses an account by mistake, unset it again: that is the quick way back.

`docs/TESTING.md` has the manual checks for each step.

## The install line on the home page

The line looks like
`curl -fsSL https://raw.githubusercontent.com/lpobjoy/QuietNet/main/install.sh | sh -s -- --relay https://your-relay.up.railway.app --code A1B2-C3D4`.
Two settings shape it, and on Railway neither is usually needed:

- `QUIETNET_RELAY_URL`: this relay's public web address, such as `https://relay.example.com`
  (`http://` only for `localhost` or `127.0.0.1`, see below). If it is unset or not usable, the relay uses `https://` plus Railway's `RAILWAY_PUBLIC_DOMAIN`, and failing that
  `https://` plus the address the browser asked for. Set it if you use your own domain, or if the
  line shows the wrong address. Each of these is used only if it is a plain address (letters,
  digits, dots, dashes and an optional port), since the line is pasted into a shell; if none is,
  the line shows `https://your-relay-address` with a note to replace it.
- `QUIETNET_INSTALL_URL`: where the line fetches `install.sh` from. The default is the copy on
  GitHub's `main` branch. Point it at a copy you have checked, or a tagged release, if you would
  rather not have new Pis run whatever is on `main` (see known issue 86 in `docs/KNOWN_ISSUES.md`).

The relay never fetches the installer itself; only the Pi does.

## Limits

The relay protects itself from being swamped: at most 300 connections at once, 10 seconds for a
request's headers to arrive, one large answer per account (48 MB across all of them), and limits on sign-ins and pairing codes, counted per network address as well
as overall. The per-address limits read the address Railway's proxy adds to the end of `X-Forwarded-For`.
When the relay is full, a page gets a short "The relay is busy" message; try again in a moment.

To sign out, use the **Sign out** button. It signs your account out on every browser and device at once. Opening `/logout` directly only asks whether you want to.

The limits on guessing are saved in the relay's database, so a restart or redeploy does not reset them.

## Running as an ordinary user

The container starts as root, because Railway's volume is owned by root. Before it opens its database or answers anything, the relay hands `/data` to the `nobody` user and stops being root; the log says "Running as user 65534, group 65534, not root." To use another user, set `QUIETNET_RUN_AS=uid:gid` (`0:0` keeps root). If the volume doesn't allow a change of owner, the relay carries on as root and the log warns about it. If the host refuses the change of user itself, the relay stops with a message saying so rather than carry on half-changed. Only `/data` itself and `relay.db` (with its `-wal`, `-shm` and `-journal` files) are handed over, and links are never followed.

## Other hosts

Any host that can build a Dockerfile works. Build from the repository's top folder with
`docker build -f cloud/Dockerfile .`, keep `/data` on lasting storage, and point the host's health
check, if it has one, at `/healthz`.

## Run locally (for development)

```bash
PORT=8080 python3 cloud/relay.py
```

Then pair a local Pi agent against `http://localhost:8080`. The install line on the home page will
guess `https://localhost:8080`, which is wrong for a local relay, so start it with
`QUIETNET_RELAY_URL=http://localhost:8080` as well. Plain `http://` is accepted only for a relay on
the same computer: the install line and `install.sh` take it for `localhost` and `127.0.0.1` (written
in small letters), and the Pi's own dashboard also for `::1`. A `QUIETNET_RELAY_URL` starting
`http://` with any other host is ignored, and the line falls back to the addresses above. A relay on
any other computer must use `https://`.

## What it stores

Your account (email + a PBKDF2-hashed password), the list of your Pis (with a hash of each Pi's key, never the key itself, and the random install id a Pi sends when it pairs), your account's licence and its log, and recent wrong guesses. It never
stores browsing history or rules — those stay on the Pi and only pass through while
you're looking at them.
