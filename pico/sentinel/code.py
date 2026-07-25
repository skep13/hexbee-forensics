"""HexBee Sentinel — hardware evidence-seal token (Raspberry Pi Pico).

The second Pico's job is chain of custody, not attack. It is a physical
object you can hold up in front of a witness and press, and the press
produces a *signed* record that the Hive turns into a chain anchor.

Why a token rather than a plain button: a button press only proves that some
button was pressed. The Sentinel holds a per-device secret in its own flash
and HMACs each seal over (device id, counter, nonce, chain head). That makes
the seal attributable to one specific physical token — and because the
counter is monotonic and stored on the device, a replayed or fabricated seal
is detectable.

    Pico ── USB CDC serial ──> Queen ──> Hive `case_seal` event ──> anchor

Wiring:
    GP16 ── momentary button ── GND    seal
    GP17 ── momentary button ── GND    tamper mark (hold 2 s)
    GP25 (onboard LED)                 status

Constraints this design accepts:
  * A plain Pico has no radio and no real-time clock. It cannot timestamp its
    own seals and it cannot reach the Hive by itself. The Queen supplies the
    time and the transport; the token supplies the identity and the counter.
    That split is stated in the evidence record rather than papered over.
  * The secret lives in flash on a device with no secure element. It resists
    forgery by someone without the token; it does not resist someone who has
    the token and a debugger. This is a custody aid, not a HSM.
"""

import time

import board
import digitalio
import supervisor
import usb_cdc

try:
    import adafruit_hashlib as hashlib          # CircuitPython community lib
    HAVE_HASH = True
except ImportError:
    try:
        import hashlib
        HAVE_HASH = True
    except ImportError:
        HAVE_HASH = False

SECRET_FILE = "/sentinel_key.txt"
COUNTER_FILE = "/sentinel_counter.txt"
SEAL_PIN = board.GP16
TAMPER_PIN = board.GP17
HOLD_SECONDS = 2.0
BLOCK_SIZE = 64


# -- identity --------------------------------------------------------------

def device_id():
    """Stable per-board identity from the RP2040's unique flash ID."""
    try:
        import microcontroller
        return "".join("%02x" % b for b in microcontroller.cpu.uid)
    except Exception:
        return "unknown"


def load_secret():
    """Per-device HMAC key.

    Provisioned once by the operator (see README). If it is missing the token
    still works but says so in every seal — an unsigned seal is honest about
    being unsigned rather than silently worthless.
    """
    try:
        with open(SECRET_FILE, "rb") as fh:
            return fh.read().strip()
    except OSError:
        return b""


def load_counter():
    try:
        with open(COUNTER_FILE, "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return 0


def save_counter(value):
    """Persist the counter. Needs boot.py to have remounted the filesystem
    writable; if it did not, the counter cannot advance and the seal says so."""
    try:
        with open(COUNTER_FILE, "w") as fh:
            fh.write(str(value))
        return True
    except OSError:
        return False


# -- HMAC-SHA256 (hand-rolled: CircuitPython has no hmac module) ------------

def hmac_sha256(key, message):
    if not HAVE_HASH or not key:
        return ""
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
    key = key + b"\x00" * (BLOCK_SIZE - len(key))
    outer = bytes(b ^ 0x5C for b in key)
    inner = bytes(b ^ 0x36 for b in key)
    inner_digest = hashlib.sha256(inner + message).digest()
    return "".join("%02x" % b for b in hashlib.sha256(outer + inner_digest).digest())


def nonce():
    """Best-effort randomness. The RP2040's ROSC-based random is fine here:
    the nonce only needs to be non-repeating, not unpredictable."""
    try:
        import os
        return "".join("%02x" % b for b in os.urandom(8))
    except Exception:
        return "%016x" % int(time.monotonic_ns() & 0xFFFFFFFFFFFFFFFF)


# -- protocol --------------------------------------------------------------

def build_seal(uid, key, counter, kind, chain_head=""):
    """The line the Queen reads off the serial port.

    Deliberately one flat line of `key=value` pairs: it survives a serial
    glitch, it is readable by a human over a terminal, and the Queen parses it
    with a split. No JSON framing to lose sync on.
    """
    n = nonce()
    material = "%s|%s|%d|%s|%s" % (uid, kind, counter, n, chain_head)
    signature = hmac_sha256(key, material.encode())
    return ("HEXBEE-SEAL v=1 device=%s kind=%s counter=%d nonce=%s "
            "head=%s sig=%s uptime=%.1f" %
            (uid, kind, counter, n, chain_head or "-",
             signature or "unsigned", time.monotonic()))


def read_chain_head(serial):
    """Optional: the Queen may push the current chain head before a seal, so
    the signature binds this press to a specific state of the evidence log."""
    if serial is None or not serial.in_waiting:
        return ""
    try:
        line = serial.readline().decode().strip()
    except Exception:
        return ""
    if line.startswith("HEAD "):
        return line[5:].strip()[:64]
    return ""


# -- pins ------------------------------------------------------------------

def button(pin):
    io = digitalio.DigitalInOut(pin)
    io.direction = digitalio.Direction.INPUT
    io.pull = digitalio.Pull.UP
    return io


def pressed(btn):
    return not btn.value        # pull-up: closed to GND reads False


def held_for(btn, seconds):
    start = time.monotonic()
    while pressed(btn):
        if time.monotonic() - start >= seconds:
            return True
        time.sleep(0.05)
    return False


def main():
    led = digitalio.DigitalInOut(board.LED)
    led.direction = digitalio.Direction.OUTPUT

    seal_btn = button(SEAL_PIN)
    tamper_btn = button(TAMPER_PIN)
    serial = usb_cdc.data if usb_cdc.data else usb_cdc.console

    uid = device_id()
    key = load_secret()
    counter = load_counter()

    def say(text):
        print(text)
        if serial is not None and serial is not usb_cdc.console:
            try:
                serial.write((text + "\n").encode())
            except Exception:
                pass

    say("HEXBEE-SENTINEL ready device=%s signed=%s counter=%d" %
        (uid, "yes" if key and HAVE_HASH else "NO", counter))
    if not key:
        say("HEXBEE-WARN no key at %s — seals will be unsigned" % SECRET_FILE)
    if not HAVE_HASH:
        say("HEXBEE-WARN no hashlib in this CircuitPython build — "
            "seals will be unsigned")

    # Slow heartbeat so a token left plugged in is visibly alive.
    last_blink = 0
    while True:
        now = time.monotonic()
        if now - last_blink > 3:
            led.value = True
            time.sleep(0.03)
            led.value = False
            last_blink = now

        head = read_chain_head(serial)

        if pressed(seal_btn):
            # Require a deliberate hold: a knock on the table should not seal
            # a case in front of a witness.
            if held_for(seal_btn, 0.6):
                counter += 1
                persisted = save_counter(counter)
                line = build_seal(uid, key, counter, "case_seal", head)
                say(line)
                if not persisted:
                    say("HEXBEE-WARN counter not persisted (filesystem "
                        "read-only) — seal counter may repeat after reset")
                for _ in range(3):
                    led.value = True
                    time.sleep(0.12)
                    led.value = False
                    time.sleep(0.08)
                while pressed(seal_btn):
                    time.sleep(0.05)

        if pressed(tamper_btn):
            if held_for(tamper_btn, HOLD_SECONDS):
                counter += 1
                save_counter(counter)
                say(build_seal(uid, key, counter, "tamper_mark", head))
                led.value = True
                time.sleep(1.0)
                led.value = False
                while pressed(tamper_btn):
                    time.sleep(0.05)

        time.sleep(0.05)


main()
