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
5. Open the Railway URL, create your account, and choose **Add a QuietNet** to get a
   pairing code. Enter that code (and the Railway URL) on the Pi's own QuietNet page
   under **Remote access**.

## Run locally (for development)

```bash
PORT=8080 python3 cloud/relay.py
```

Then pair a local Pi agent against `http://localhost:8080`.

## What it stores

Your account (email + a scrypt-hashed password) and the list of your Pis. It never
stores browsing history or rules — those stay on the Pi and only pass through while
you're looking at them.
