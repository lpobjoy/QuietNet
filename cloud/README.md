# QuietNet relay

Lets you reach your home QuietNet (on a Raspberry Pi) from anywhere, without
changing your router. You host this small service; the Pi connects out to it.

It uses only the Python standard library.

## Deploy on Railway

1. Push this repository to GitHub (already done if you're reading it there).
2. In Railway: **New Project → Deploy from GitHub repo**, pick this repo.
3. Railway reads `railway.json` and builds `cloud/Dockerfile`. No settings needed —
   it provides the public HTTPS address and the `PORT`.
4. Add a **Volume** mounted at `/data` so accounts survive redeploys.
5. Sign-up needs no setting: by default (`QUIETNET_SIGNUP=first`) only the first account can be created, which should be yours, so create it straight after deploying. The values are `first` (the default), `open` (anyone who finds the address can make an account; they still cannot see your Pi) and `closed`. Any other value, such as a misspelling, switches sign-up off and the relay's log warns about it. The log says at start-up which setting is in force.

   **Upgrading a relay set up before this default changed:** existing accounts are kept and can still sign in, but new sign-ups stop once any account exists. If you relied on the old default to let others sign up, add `QUIETNET_SIGNUP=open`. Everyone will need to sign in again once after the upgrade, because the session cookie changed.
6. Open the Railway URL, create your account, sign in with it, and choose **Add a QuietNet** to get a
   pairing code. For a new Pi, the page shows one line to run on it, which installs QuietNet and
   pairs it in one go. For a Pi already running QuietNet, enter the code (and the Railway URL) on
   the Pi's own QuietNet page under **Remote access**. The code works once and for 15 minutes;
   reload the page for a new one. One account can hold up to 10 QuietNets and pair up to 20 a day.

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

Your account (email + a PBKDF2-hashed password), the list of your Pis (with a hash of each Pi's key, never the key itself) and recent wrong guesses. It never
stores browsing history or rules — those stay on the Pi and only pass through while
you're looking at them.
