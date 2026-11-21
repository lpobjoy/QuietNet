"""QuietNet cloud agent - the Pi's outbound link to the relay.

This lets you reach the Pi's dashboard from anywhere without changing your router.
The Pi makes an outbound connection to the relay (which you host, e.g. on Railway),
holds it open, and waits for your browser's requests to come down it. Each request
is run against the Pi's own local dashboard and the answer is sent back up the line.

Pairing: once, you create a pairing code on the relay website and enter it (with the
relay's address) on the Pi's local dashboard, or set the QUIETNET_CLOUD and
QUIETNET_PAIR environment variables. After that the Pi reconnects on its own.

Standard library only.
"""
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request


class CloudAgent:
    """The Pi's side of remote access. One instance, created by server.main().

    State lives in `cfg` (relay address, token, Pi id), saved in data/cloud.json. `state` and
    `detail` are for the dashboard: off, connecting, online or error, and a sentence of explanation."""
    def __init__(self, local_port, data_dir, log=print):
        """`local_port` is where this Pi's own dashboard listens; `data_dir` is where
        cloud.json is kept. Starts nothing; see start()."""
        self.local_port = local_port
        self.path = os.path.join(data_dir, "cloud.json")
        self.log = log
        self.cfg = self._load()
        self.state = "off"          # off | connecting | online | error
        self.detail = ""
        self._stop = threading.Event()
        # Headless setup: environment variables win if the Pi isn't paired yet.
        env_relay = os.environ.get("QUIETNET_CLOUD", "").strip()
        if env_relay and not self.cfg.get("token"):
            self.cfg["relay"] = env_relay.rstrip("/")

    # -- config ---------------------------------------------------------

    def _load(self):
        """Read cloud.json. A missing or damaged file means 'not paired'."""
        try:
            with open(self.path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self):
        """Write cloud.json, readable only by the account QuietNet runs as."""
        try:
            # The file holds the token that lets the relay control this QuietNet, so only the
            # account running QuietNet may read it (0o600 = owner read/write, nobody else).
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.cfg, f)
            os.chmod(self.path, 0o600)                 # also tighten a file created by an older version
        except OSError as e:
            self.log("Could not save cloud settings: %s" % e)

    def status(self):
        """What the dashboard's Remote access card shows. Never includes the token."""
        return {"configured": bool(self.cfg.get("relay")), "paired": bool(self.cfg.get("token")),
                "relay": self.cfg.get("relay", ""), "name": self.cfg.get("name", ""),
                "state": self.state, "detail": self.detail}

    def forget(self):
        """Unpair: wipe the saved relay address and token. The loop notices and goes idle."""
        self.cfg = {}
        self._save()
        self.state, self.detail = "off", ""

    # -- pairing --------------------------------------------------------

    def pair(self, relay, code):
        """Exchange a pairing code for a token and save it. Returns None on success, or a
        sentence explaining what went wrong (shown to the person as is)."""
        relay = (relay or self.cfg.get("relay", "")).strip().rstrip("/")
        if not relay.startswith(("http://", "https://")):
            relay = "https://" + relay
        try:
            resp = self._http("POST", relay + "/agent/pair", {"code": str(code).strip().upper()}, timeout=20)
        except urllib.error.HTTPError as e:
            try:
                return (json.loads(e.read()).get("error") or "Pairing failed.")
            except Exception:
                return "Pairing failed (the relay rejected the code)."
        except (urllib.error.URLError, socket.timeout, OSError):
            return "Couldn't reach the relay at that address."
        if not resp.get("token"):
            return "Pairing failed."
        self.cfg = {"relay": relay, "token": resp["token"], "id": resp.get("id", "")}
        self._save()
        self.state = "connecting"
        return None

    # -- run loop -------------------------------------------------------

    def start(self):
        # Allow one-shot pairing from an environment variable on first boot.
        """Pair from the QUIETNET_PAIR environment variable if set and not yet paired, then
        start the background loop."""
        code = os.environ.get("QUIETNET_PAIR", "").strip()
        if code and self.cfg.get("relay") and not self.cfg.get("token"):
            err = self.pair(self.cfg["relay"], code)
            self.log("Cloud pairing: " + (err or "success"))
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        """Ask the background loop to end."""
        self._stop.set()

    def _run(self):
        """The background loop. While paired: wait on the relay for a request (the relay holds
        the call open for up to 25 seconds), run it, send the answer, repeat.

        On 401 the relay no longer knows this Pi, so the token is discarded. On other failures the
        pairing is kept and the loop waits before retrying: 5 seconds after a relay error, and 1, 2,
        4 ... up to 30 seconds while the relay cannot be reached."""
        backoff = 1
        while not self._stop.is_set():
            if not (self.cfg.get("relay") and self.cfg.get("token")):
                self.state = "off"
                self._stop.wait(2)
                continue
            try:
                self.state = "connecting" if self.state != "online" else self.state
                call = self._http("GET", self.cfg["relay"] + "/agent/poll", None, timeout=35, token=True)
                self.state, self.detail, backoff = "online", "", 1
                if call and call.get("id"):
                    self._handle(call)
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    self.state, self.detail = "error", "This Pi was unpaired on the relay. Pair it again."
                    self.cfg.pop("token", None)
                    self._save()
                else:
                    self.state, self.detail = "error", "Relay error %d" % e.code
                self._stop.wait(5)
            except (urllib.error.URLError, socket.timeout, OSError) as e:
                self.state, self.detail = "error", "Can't reach the relay (%s)" % e
                self._stop.wait(min(backoff, 30))
                backoff = min(backoff * 2, 30)

    def _handle(self, call):
        """Run one relayed request against our own local dashboard and send the answer back."""
        status, body = self._local(call.get("method", "GET"), call.get("path", "/"), call.get("body"))
        try:
            self._http("POST", self.cfg["relay"] + "/agent/respond",
                       {"id": call["id"], "status": status, "body": body}, timeout=20, token=True)
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError):
            pass        # the browser's request will simply time out; no harm done

    def _local(self, method, path, body):
        """Send one request to this Pi's own dashboard and return (status, body text).

        Only ever calls 127.0.0.1 on the dashboard's port: the path comes from the relay, but the
        host and port do not. It names itself 'localhost' because the dashboard refuses anything else."""
        url = "http://127.0.0.1:%d%s" % (self.local_port, path if path.startswith("/") else "/" + path)
        data = body.encode() if (body and method == "POST") else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", "X-QuietNet": "1",
                                              "Host": "localhost"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "ignore")
        except (urllib.error.URLError, socket.timeout, OSError):
            return 502, '{"error":"The Pi could not answer."}'

    def _http(self, method, url, obj, timeout, token=False):
        """One JSON request to the relay; returns the decoded answer ({} if empty). Raises
        urllib's errors for the caller to handle. token=True adds this Pi's token header."""
        data = json.dumps(obj).encode() if obj is not None else None
        headers = {"Content-Type": "application/json"}
        if token and self.cfg.get("token"):
            headers["X-QuietNet-Token"] = self.cfg["token"]
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
