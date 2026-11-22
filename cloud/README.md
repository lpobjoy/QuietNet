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
5. Add the variable `QUIETNET_SIGNUP=first`. Only the first account can then be created, which should be yours. Without it, anyone who finds the address can make an account (they still cannot see your Pi). The values are `open` (the default), `first` and `closed`. Any other value, such as a misspelling, switches sign-up off and the relay's log warns about it at start-up.
6. Open the Railway URL, create your account, and choose **Add a QuietNet** to get a
   pairing code. Enter that code (and the Railway URL) on the Pi's own QuietNet page
   under **Remote access**. The code works once and for 15 minutes; reload the page for a new one.
   One account can hold up to 10 QuietNets and pair up to 20 a day.

## Limits

The relay protects itself from being swamped: at most 300 connections at once, 10 seconds for a
request's headers to arrive, one large answer per account (48 MB across all of them), and limits on sign-ins and pairing codes, counted per network address as well
as overall. The per-address limits read the address Railway's proxy adds to the end of `X-Forwarded-For`.
When the relay is full, a page gets a short "The relay is busy" message; try again in a moment.

To sign out, use the **Sign out** button. Opening `/logout` directly only asks whether you want to.

## Run locally (for development)

```bash
PORT=8080 python3 cloud/relay.py
```

Then pair a local Pi agent against `http://localhost:8080`.

## What it stores

Your account (email + a PBKDF2-hashed password) and the list of your Pis. It never
stores browsing history or rules — those stay on the Pi and only pass through while
you're looking at them.
