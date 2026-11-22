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
import http.client
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request

MAX_AT_ONCE = 8                     # relayed requests handled at the same time
MAX_ANSWER = 12 * 1024 * 1024       # largest answer sent up; the relay takes 16 MB, and JSON escaping adds some
PAIR_RETRY_MAX = 60                 # longest wait, in seconds, between tries of a QUIETNET_PAIR code

# Lists of trusted certificate authorities that operating systems keep, tried in this order when
# Python has none of its own (python.org's Mac builds start with none). Adding trusted authorities
# never weakens the check: certificates are always verified.
SYSTEM_CA_FILES = (
    "/etc/ssl/cert.pem",                                 # macOS, Alpine, the BSDs
    "/etc/ssl/certs/ca-certificates.crt",                # Debian, Ubuntu, Raspberry Pi OS
    "/etc/pki/tls/certs/ca-bundle.crt",                  # Fedora, Red Hat
    "/etc/ssl/ca-bundle.pem",                            # openSUSE
)

CERT_HELP = ("The relay's security certificate couldn't be checked. If you installed Python from "
             "python.org on a Mac, open its folder in Applications, double-click "
             "'Install Certificates.command', then restart QuietNet. Otherwise check the relay address.")

_tls = None
_tls_lock = threading.Lock()


def tls_context():
    """The settings used for secure (https) calls to the relay, made once and reused.

    Starts from Python's defaults, which always check the certificate and the host name. If Python
    has no trusted certificate authorities loaded (the case for python.org's Mac builds until
    'Install Certificates.command' is run), the operating system's own list is added from the
    first of SYSTEM_CA_FILES that exists. If there is none, calls fail with a certificate error,
    which is reported with CERT_HELP. Verification is never turned off."""
    global _tls
    with _tls_lock:
        if _tls is None:
            ctx = ssl.create_default_context()
            if not ctx.cert_store_stats().get("x509_ca"):
                for path in SYSTEM_CA_FILES:
                    if os.path.isfile(path):
                        try:
                            ctx.load_verify_locations(cafile=path)
                            break
                        except (OSError, ssl.SSLError):
                            continue
            _tls = ctx
        return _tls


def is_cert_error(e):
    """True when `e` is a failed certificate check, whether raised directly or wrapped by urllib."""
    reason = getattr(e, "reason", None) if isinstance(e, urllib.error.URLError) else e
    return isinstance(reason, ssl.SSLCertVerificationError)


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
        self._slots = threading.BoundedSemaphore(MAX_AT_ONCE)
        self._pending_code = ""     # a QUIETNET_PAIR code still being retried; see start()
        self._next_pair_try = 0.0
        self._pair_wait = 5
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
        self._pending_code = ""
        self._save()
        self.state, self.detail = "off", ""

    # -- pairing --------------------------------------------------------

    def pair(self, relay, code):
        """Exchange a pairing code for a token and save it. Returns None on success, or a
        sentence explaining what went wrong (shown to the person as is)."""
        return self._pair(relay, code)[0]

    def _pair(self, relay, code):
        """Do the work of pair(). Returns (message, final): message is None on success; final is
        True when trying the same code again cannot help, because the relay refused the code
        itself (wrong, used or expired). A busy relay (429), a relay fault, an unreachable relay
        or an unreadable answer are not final."""
        relay = (relay or self.cfg.get("relay", "")).strip().rstrip("/")
        if not relay.startswith(("http://", "https://")):
            relay = "https://" + relay
        try:
            resp = self._http("POST", relay + "/agent/pair", {"code": str(code).strip().upper()}, timeout=20)
        except urllib.error.HTTPError as e:
            final = 400 <= e.code < 500 and e.code not in (408, 429)
            try:
                return (json.loads(e.read()).get("error") or "Pairing failed."), final
            except Exception:
                return "Pairing failed (the relay rejected the code).", final
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            if is_cert_error(e):
                return CERT_HELP, False
            return "Couldn't reach the relay at that address.", False
        except (http.client.HTTPException, ValueError):
            return "The relay sent an answer QuietNet couldn't read.", False
        if not isinstance(resp, dict) or not resp.get("token"):
            return "Pairing failed.", False
        self.cfg = {"relay": relay, "token": resp["token"], "id": resp.get("id", "")}
        self._save()
        self.state = "connecting"
        return None, False

    # -- run loop -------------------------------------------------------

    def start(self):
        """Pair from the QUIETNET_PAIR environment variable if set and not yet paired, then
        start the background loop.

        If that first try fails for a reason that may pass (the relay is busy, faulty or can't be
        reached), the loop keeps trying the code with growing waits; see _retry_pairing. It gives
        up only when the relay says the code is wrong, used or expired."""
        code = os.environ.get("QUIETNET_PAIR", "").strip()
        if code and self.cfg.get("relay") and not self.cfg.get("token"):
            self._pending_code = code
            self._pair_wait = 5
            self._next_pair_try = 0.0
            self._retry_pairing()
        threading.Thread(target=self._run, daemon=True).start()

    def _retry_pairing(self):
        """Try the QUIETNET_PAIR code once, if one is waiting and its next try is due.

        On success, or when the relay refuses the code itself, the code is dropped. Otherwise the
        next try is put off: 5 seconds, then 10, 20, 40, and at most PAIR_RETRY_MAX seconds."""
        if not self._pending_code or time.time() < self._next_pair_try:
            return
        err, final = self._pair(self.cfg.get("relay", ""), self._pending_code)
        if err is None:
            self._pending_code = ""
            self.log("Cloud pairing: success")
        elif final:
            self._pending_code = ""
            self.state, self.detail = "error", err
            self.log("Cloud pairing: " + err)
        else:
            wait = self._pair_wait
            self._next_pair_try = time.time() + wait
            self._pair_wait = min(wait * 2, PAIR_RETRY_MAX)
            self.state = "error"
            self.detail = "Pairing didn't work yet: %s Trying again in %d seconds." % (err, wait)
            self.log("Cloud pairing: %s Trying again in %d seconds." % (err, wait))

    def stop(self):
        """Ask the background loop to end."""
        self._stop.set()

    def _run(self):
        """The background loop. While paired: wait on the relay for a request (the relay holds
        the call open for up to 25 seconds), run it, send the answer, repeat.

        While not paired, it retries a QUIETNET_PAIR code that failed for a reason that may pass.

        On 401 the relay no longer knows this Pi, so the token is discarded. On other failures the
        pairing is kept and the loop waits before retrying: 5 seconds after a relay error, and 1, 2,
        4 ... up to 30 seconds while the relay cannot be reached or something unexpected goes wrong.
        Nothing is allowed to end the loop except stop(), because on a Pi with no screen the relay
        is the only way in."""
        backoff = 1
        while not self._stop.is_set():
            try:
                if not (self.cfg.get("relay") and self.cfg.get("token")):
                    if self._pending_code and self.cfg.get("relay"):
                        self._retry_pairing()
                    else:
                        self._pending_code = ""
                        self.state = "off"
                    if not self.cfg.get("token"):
                        self._stop.wait(2)
                    continue
                self._pending_code = ""          # paired, by the code or by hand
                self.state = "connecting" if self.state != "online" else self.state
                call = self._http("GET", self.cfg["relay"] + "/agent/poll", None, timeout=35, token=True)
                self.state, self.detail, backoff = "online", "", 1
                if isinstance(call, dict) and call.get("id"):
                    # Answer in the background and go straight back to listening, so the several
                    # requests a dashboard page makes at once don't queue behind each other.
                    # At most MAX_AT_ONCE are in hand; beyond that, wait for one to finish.
                    self._slots.acquire()
                    try:
                        threading.Thread(target=self._handle_and_release, args=(call,), daemon=True).start()
                    except Exception:
                        self._slots.release()
                        raise
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    self.state, self.detail = "error", "This Pi was unpaired on the relay. Pair it again."
                    self.cfg.pop("token", None)
                    self._save()
                else:
                    self.state, self.detail = "error", "Relay error %d" % e.code
                self._stop.wait(5)
            except (urllib.error.URLError, socket.timeout, OSError) as e:
                if is_cert_error(e):
                    self.state, self.detail = "error", CERT_HELP
                else:
                    self.state, self.detail = "error", "Can't reach the relay (%s)" % e
                self._stop.wait(min(backoff, 30))
                backoff = min(backoff * 2, 30)
            except (http.client.HTTPException, ValueError):
                # A cut-off or garbled answer: the relay restarting, or a proxy page instead of JSON.
                self.state, self.detail = "error", "The relay sent an answer QuietNet couldn't read. Trying again."
                self._stop.wait(min(backoff, 30))
                backoff = min(backoff * 2, 30)
            except Exception as e:
                self.state, self.detail = "error", "Something unexpected went wrong with the relay link. Trying again."
                self.log("Cloud link: unexpected problem: %r" % (e,))
                self._stop.wait(min(backoff, 30))
                backoff = min(backoff * 2, 30)

    def _handle_and_release(self, call):
        """Handle one call, then free its slot for the next."""
        try:
            self._handle(call)
        finally:
            self._slots.release()

    def _handle(self, call):
        """Run one relayed request against our own local dashboard and send the answer back.
        An answer too big for the relay to accept is replaced by a short message saying so, so the
        browser hears straight away rather than waiting until it gives up."""
        status, body = self._local(call.get("method", "GET"), call.get("path", "/"), call.get("body"))
        if len(body) > MAX_ANSWER:
            status, body = 502, json.dumps({"error": "That's too much to send remotely. Try a shorter time range."})
        try:
            self._http("POST", self.cfg["relay"] + "/agent/respond",
                       {"id": call["id"], "status": status, "body": body}, timeout=60, token=True,
                       headers={"X-QuietNet-Call": str(call["id"])})
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError,
                http.client.HTTPException, ValueError):
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

    def _http(self, method, url, obj, timeout, token=False, headers=None):
        """One JSON request to the relay; returns the decoded answer ({} if empty). Raises
        urllib's errors for the caller to handle, and http.client.HTTPException or ValueError for
        a cut-off or garbled answer. https calls use tls_context(). token=True adds this Pi's token header;
        `headers` adds any others."""
        data = json.dumps(obj).encode() if obj is not None else None
        headers = dict(headers or {}, **{"Content-Type": "application/json"})
        if token and self.cfg.get("token"):
            headers["X-QuietNet-Token"] = self.cfg["token"]
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        context = tls_context() if url.lower().startswith("https://") else None
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
