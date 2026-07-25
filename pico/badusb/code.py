"""HexBee Stinger — Raspberry Pi Pico HID payload deployer (CircuitPython).

The Pico enumerates as a USB keyboard and types a DuckyScript payload into
the target. Payloads are plain `.txt` files on the Pico's own CIRCUITPY
drive, so selecting one is a drag-and-drop, not a reflash.

Two design decisions worth stating plainly:

**It will not fire on plug-in alone.** The arm pin (GP15 to GND, a jumper or
a momentary switch) must be closed. Without it the board enumerates, prints
what it *would* have run, and stops. An implant that fires the instant it
touches USB is a hazard to the operator's own machines first.

**It has no radio.** A plain Pico is not a Pico W, so there is no way to
report a deployment home in real time. Instead every run is appended to
`deploy.log` on the CIRCUITPY drive with a monotonic timestamp, and the
operator imports that log from the Queen afterwards:

    hexbee-queen pico hid /media/CIRCUITPY/deploy.log --case 3

Wiring:
    GP15 ── switch/jumper ── GND     arm (closed = will type)
    GP14 ── switch/jumper ── GND     safe mode (closed = never type, overrides)
    GP25 (onboard LED)               status
"""

import time

import board
import digitalio
import storage
import supervisor
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS
from adafruit_hid.keycode import Keycode

PAYLOAD_DIR = "/payloads"
SELECTED = "/payload.txt"        # drop the chosen payload here
LOG_FILE = "/deploy.log"
BOOT_GRACE = 3.0                 # seconds before typing: let the host enumerate

ARM_PIN = board.GP15
SAFE_PIN = board.GP14

KEYS = {
    "ENTER": Keycode.ENTER, "RETURN": Keycode.ENTER, "TAB": Keycode.TAB,
    "ESC": Keycode.ESCAPE, "ESCAPE": Keycode.ESCAPE, "SPACE": Keycode.SPACE,
    "BACKSPACE": Keycode.BACKSPACE, "DELETE": Keycode.DELETE,
    "DEL": Keycode.DELETE, "INSERT": Keycode.INSERT, "HOME": Keycode.HOME,
    "END": Keycode.END, "PAGEUP": Keycode.PAGE_UP, "PAGEDOWN": Keycode.PAGE_DOWN,
    "UP": Keycode.UP_ARROW, "UPARROW": Keycode.UP_ARROW,
    "DOWN": Keycode.DOWN_ARROW, "DOWNARROW": Keycode.DOWN_ARROW,
    "LEFT": Keycode.LEFT_ARROW, "LEFTARROW": Keycode.LEFT_ARROW,
    "RIGHT": Keycode.RIGHT_ARROW, "RIGHTARROW": Keycode.RIGHT_ARROW,
    "GUI": Keycode.GUI, "WINDOWS": Keycode.GUI, "COMMAND": Keycode.GUI,
    "CTRL": Keycode.CONTROL, "CONTROL": Keycode.CONTROL,
    "ALT": Keycode.ALT, "SHIFT": Keycode.SHIFT,
    "CAPSLOCK": Keycode.CAPS_LOCK, "PRINTSCREEN": Keycode.PRINT_SCREEN,
    "MENU": Keycode.APPLICATION, "APP": Keycode.APPLICATION,
}
for _n in range(1, 13):
    KEYS["F%d" % _n] = getattr(Keycode, "F%d" % _n)
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYS[_c] = getattr(Keycode, _c)
_DIGITS = ["ZERO", "ONE", "TWO", "THREE", "FOUR",
           "FIVE", "SIX", "SEVEN", "EIGHT", "NINE"]
for _d in range(10):
    KEYS[str(_d)] = getattr(Keycode, _DIGITS[_d])


def _pin(which):
    pin = digitalio.DigitalInOut(which)
    pin.direction = digitalio.Direction.INPUT
    pin.pull = digitalio.Pull.UP
    return pin


def status_led():
    led = digitalio.DigitalInOut(board.LED)
    led.direction = digitalio.Direction.OUTPUT
    return led


def blink(led, times, on=0.08, off=0.12):
    for _ in range(times):
        led.value = True
        time.sleep(on)
        led.value = False
        time.sleep(off)


class Ducky:
    """DuckyScript 1.0 interpreter.

    Supported: REM, DELAY, DEFAULTDELAY/DEFAULT_DELAY, STRING, STRINGLN,
    REPEAT, and any combination of modifier + key names (GUI r, CTRL ALT
    DELETE, SHIFT F10, ...).
    """

    def __init__(self, keyboard, layout):
        self.kbd = keyboard
        self.layout = layout
        self.default_delay = 0
        self.last_line = None
        self.lines_run = 0
        self.keys_sent = 0

    def run_line(self, line):
        line = line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped or stripped.upper().startswith(("REM", "#")):
            return
        head, _, rest = stripped.partition(" ")
        head = head.upper()

        if head == "DELAY":
            time.sleep(self._ms(rest) / 1000)
            return
        if head in ("DEFAULTDELAY", "DEFAULT_DELAY"):
            self.default_delay = self._ms(rest)
            return
        if head == "REPEAT":
            count = self._ms(rest)
            if self.last_line:
                for _ in range(min(count, 500)):   # bounded: no runaway loops
                    self.run_line(self.last_line)
            return
        if head in ("STRING", "STRINGLN"):
            self.layout.write(rest)
            self.keys_sent += len(rest)
            if head == "STRINGLN":
                self.kbd.send(Keycode.ENTER)
            self._pause()
            self.last_line = stripped
            self.lines_run += 1
            return

        codes = []
        for token in stripped.split():
            code = KEYS.get(token.upper())
            if code is None:
                # Single printable character used as a key, e.g. "GUI r"
                if len(token) == 1:
                    code = KEYS.get(token.upper())
                if code is None:
                    continue
            codes.append(code)
        if codes:
            self.kbd.send(*codes)
            self.keys_sent += 1
            self._pause()
        self.last_line = stripped
        self.lines_run += 1

    def _pause(self):
        if self.default_delay:
            time.sleep(self.default_delay / 1000)

    @staticmethod
    def _ms(value):
        try:
            return int(value.strip())
        except (ValueError, AttributeError):
            return 0

    def run_file(self, path):
        with open(path, "r") as fh:
            for line in fh:
                self.run_line(line)


def read_payload_name():
    try:
        with open(SELECTED, "r") as fh:
            first = fh.readline()
        if first.strip().upper().startswith("REM NAME "):
            return first.strip()[9:]
    except OSError:
        return None
    return SELECTED


def log_deployment(name, result, stats):
    """Append a deployment record to CIRCUITPY.

    Writing needs boot.py to have remounted the filesystem writable, which it
    only does when the arm pin is closed — so a disarmed board leaves no trace
    on its own drive either.
    """
    line = "%s\t%s\t%s\tlines=%d\tkeys=%d\tuptime=%.1f\n" % (
        name or "(none)", result, stats.get("payload_sha", ""),
        stats.get("lines", 0), stats.get("keys", 0), time.monotonic())
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(line)
        return True
    except OSError:
        print("deploy.log not writable (filesystem is read-only to the Pico)")
        return False


def payload_fingerprint(path):
    """Cheap content fingerprint so the log identifies *which* payload ran.

    CircuitPython has no hashlib on most builds, so this is an FNV-1a over
    the file — enough to tell two payloads apart in a report, and it is not
    presented as a cryptographic hash anywhere.
    """
    h = 0x811C9DC5
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(256)
                if not chunk:
                    break
                for byte in chunk:
                    h ^= byte
                    h = (h * 0x01000193) & 0xFFFFFFFF
    except OSError:
        return ""
    return "fnv1a:%08x" % h


def main():
    led = status_led()
    arm = _pin(ARM_PIN)
    safe = _pin(SAFE_PIN)

    name = read_payload_name()
    fingerprint = payload_fingerprint(SELECTED)

    # Pull-ups: closed to GND reads False.
    is_safe = not safe.value
    is_armed = not arm.value

    print("HexBee Stinger — HID payload deployer")
    print("payload:", name or "(none found at %s)" % SELECTED)
    print("fingerprint:", fingerprint or "(unreadable)")
    print("arm pin:", "CLOSED (armed)" if is_armed else "open (disarmed)")
    print("safe pin:", "CLOSED (safe mode)" if is_safe else "open")

    if is_safe or not is_armed:
        print("Not typing. Close the arm jumper (GP15-GND) to deploy.")
        blink(led, 2, 0.5, 0.5)
        log_deployment(name, "disarmed", {"payload_sha": fingerprint})
        return

    if name is None:
        print("No payload at %s — copy one from %s" % (SELECTED, PAYLOAD_DIR))
        blink(led, 6)
        return

    # Give the host time to finish enumerating the keyboard, and give the
    # operator a last chance to pull the board out.
    print("Deploying in %.0fs …" % BOOT_GRACE)
    for _ in range(int(BOOT_GRACE * 2)):
        blink(led, 1, 0.1, 0.4)

    keyboard = Keyboard(usb_hid.devices)
    ducky = Ducky(keyboard, KeyboardLayoutUS(keyboard))
    result = "ok"
    try:
        ducky.run_file(SELECTED)
    except Exception as exc:      # a bad payload must not brick the board
        result = "error: %s" % exc
        print(result)

    led.value = True
    log_deployment(name, result, {"payload_sha": fingerprint,
                                  "lines": ducky.lines_run,
                                  "keys": ducky.keys_sent})
    print("done:", result, "lines=%d" % ducky.lines_run)


main()
