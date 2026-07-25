# HexBee Picos

Two Raspberry Pi Picos, two jobs. Both are **plain Picos, not Pico Ws** —
there is no radio on either, and every design decision below follows from
that. Neither can talk to the Hive by itself; the Queen is their uplink.

| Board | Role | Reports via |
|---|---|---|
| `badusb/` — **Stinger** | USB HID payload deployer (DuckyScript) | `deploy.log` on its own drive, imported afterwards |
| `sentinel/` — **Sentinel** | Hardware evidence-seal token | USB serial to a Queen listener, live |

Both run [CircuitPython](https://circuitpython.org/board/raspberry_pi_pico/).
Copy `code.py` and `boot.py` onto the CIRCUITPY drive.

---

## Stinger — HID payload deployer

Enumerates as a USB keyboard and types a DuckyScript payload. Payload
selection is a file copy, not a reflash: drop your chosen `.txt` onto the
drive as `payload.txt`.

```
GP15 ── jumper ── GND     ARM   (closed = will type)
GP14 ── jumper ── GND     SAFE  (closed = never types; overrides ARM)
```

**It does not fire on plug-in alone.** Without the arm jumper it enumerates,
prints what it would have done, and stops. An implant that types the instant
it touches USB is a hazard to your own machines first — and to a client's,
if you forget which port you are in.

When armed, `boot.py` hides the mass-storage drive and enables only the
keyboard, then remounts the filesystem writable so the board can log its own
deployment. A target host cannot mount the drive or tamper with the log.

Setup:

```bash
# Install the HID library into /lib on the Pico (from the CircuitPython bundle)
cp -r adafruit_hid /media/$USER/CIRCUITPY/lib/
cp badusb/boot.py badusb/code.py /media/$USER/CIRCUITPY/
mkdir -p /media/$USER/CIRCUITPY/payloads
cp badusb/payloads/*.txt /media/$USER/CIRCUITPY/payloads/
cp badusb/payloads/00-proof-of-execution.txt /media/$USER/CIRCUITPY/payload.txt
```

Afterwards, import the log into the case:

```bash
hexbee-queen pico hid /media/$USER/CIRCUITPY/deploy.log --case 3 \
  --target RECEPTION-PC --operator jacob
```

Each line becomes a `hid_deployment` event (ATT&CK T1200 + T1059) in the
hash-chained evidence log.

### About the payloads

The supplied payloads are demonstrative: proof-of-execution, read-only host
enumeration, and workstation lock. The interpreter runs any DuckyScript 1.0
you write, so the capability is complete — but ready-to-run credential
harvesters and reverse-shell droppers are not shipped in the repo. Payloads
that only make sense as live attack tooling belong in your own engagement
notes, alongside the authorisation that covers them.

### Supported DuckyScript

`REM` · `DELAY` · `DEFAULT_DELAY` / `DEFAULTDELAY` · `STRING` · `STRINGLN` ·
`REPEAT` · modifier + key combinations (`GUI r`, `CTRL ALT DELETE`,
`SHIFT F10`) · `F1`–`F12`, arrows, `ENTER`, `TAB`, `ESC`, `DELETE`, `HOME`,
`END`, `PAGEUP`, `PAGEDOWN`.

`REPEAT` is capped at 500 iterations so a typo cannot lock up a target.

---

## Sentinel — hardware evidence-seal token

A physical object you hold up in front of a witness and press. The press
produces a *signed* record, and the Hive turns it into a chain anchor.

```
GP16 ── button ── GND     SEAL    (hold 0.6 s)
GP17 ── button ── GND     TAMPER  (hold 2 s)
```

Why a token instead of a plain button: a button press only proves that some
button was pressed. The Sentinel holds a per-device HMAC key in its own flash
and signs each seal over `(device id, kind, counter, nonce, chain head)`. The
seal is attributable to one specific physical token, the counter is monotonic
so replays are detectable, and — when the Queen pushes the current chain head
first — the signature binds the press to a specific state of the evidence log.

Setup:

```bash
cp sentinel/boot.py sentinel/code.py /media/$USER/CIRCUITPY/
hexbee-queen pico provision              # generates the key, prints the steps
# hold GP16 while replugging to make the drive host-writable, then:
cp ~/.hexbee-sentinel-key /media/$USER/CIRCUITPY/sentinel_key.txt
```

Listen for seals:

```bash
hexbee-queen pico seal --case 3 --operator jacob --witness "DS Miller"
```

Each press writes a `case_seal` event and requests a signed chain anchor.
A seal that fails verification is still recorded — with the failure reason —
because a failed seal is itself something the case should show.

### What this is not

The key lives in flash on a microcontroller with no secure element. It
resists forgery by someone who does not have the token. It does **not**
resist someone who has the token and a debugger. This is a custody aid, not
a hardware security module, and the evidence record says so.

A plain Pico also has no real-time clock, so the token cannot timestamp its
own seals. Time comes from the Queen, and every `case_seal` payload states
`timestamp_source: queen (token has no real-time clock)` rather than implying
otherwise.

---

## Why not use one Pico for both?

The Stinger's `boot.py` hides its own drive and disables the serial console
when armed; the Sentinel's needs the serial console and a writable
filesystem. The two configurations are mutually exclusive at boot, and a
board that is sometimes a keyboard and sometimes an evidence device is a
board you will eventually plug in wearing the wrong hat.
