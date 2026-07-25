"""Queen-side bridge for the two Raspberry Pi Picos.

Neither Pico has a radio — they are plain Picos, not Pico Ws — so neither can
reach the Hive on its own. The Queen is their uplink:

  * **Sentinel** (evidence-seal token) appears as a USB serial device and
    emits one `HEXBEE-SEAL` line per button press. `watch_sentinel()` reads
    that line, verifies the HMAC against the token's provisioned key, writes
    a `case_seal` event into the evidence chain, and asks the Hive to produce
    a signed chain anchor — so a physical press in front of a witness produces
    a cryptographic receipt.

  * **Stinger** (HID payload deployer) cannot report at all while it is
    plugged into a target. It appends to `deploy.log` on its own drive;
    `import_hid_log()` reads that file afterwards and turns each line into a
    `hid_deployment` event.

Serial access uses pyserial when available and falls back to reading the
character device directly, because a Kali live session may not have pyserial
installed and this should still work.
"""

from __future__ import annotations

import glob
import hashlib
import hmac
import logging
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hexbee.queen.pico")

SEAL_PREFIX = "HEXBEE-SEAL"
READY_PREFIX = "HEXBEE-SENTINEL"
WARN_PREFIX = "HEXBEE-WARN"

# Where a Pico's CDC data endpoint lands, per platform. Every OS names USB
# serial devices differently, and getting this wrong means the token is
# plugged in and working while the listener reports "no Sentinel found".
SERIAL_GLOBS = {
    "Linux": ["/dev/ttyACM*", "/dev/ttyUSB*"],
    # macOS exposes both a /dev/tty.* (blocking, waits for carrier detect) and
    # a /dev/cu.* (call-out, opens immediately) node for the same device. cu
    # is the one you want for a device that talks first.
    "Darwin": ["/dev/cu.usbmodem*", "/dev/cu.usbserial*", "/dev/cu.SLAB*"],
    "Windows": [],          # enumerated through pyserial, not globbed
}

# Where CIRCUITPY mounts, for the messages that tell an operator where to look.
CIRCUITPY_HINTS = {
    "Linux": "/media/$USER/CIRCUITPY",
    "Darwin": "/Volumes/CIRCUITPY",
    "Windows": "the CIRCUITPY drive (usually D: or E:)",
}


def circuitpy_hint() -> str:
    return CIRCUITPY_HINTS.get(platform.system(), "the CIRCUITPY drive")


def find_circuitpy() -> Path | None:
    """Locate a mounted CIRCUITPY drive, so the operator does not have to."""
    candidates: list[Path] = []
    system = platform.system()
    if system == "Darwin":
        candidates = [Path("/Volumes/CIRCUITPY")]
    elif system == "Linux":
        import os
        user = os.environ.get("USER", "")
        candidates = [Path(f"/media/{user}/CIRCUITPY"),
                      Path(f"/run/media/{user}/CIRCUITPY"),
                      Path("/media/CIRCUITPY")]
    else:
        candidates = [Path(f"{chr(letter)}:/") for letter in
                      range(ord("D"), ord("K"))]
    for path in candidates:
        try:
            if path.is_dir() and (path / "boot_out.txt").exists():
                return path
        except OSError:
            continue
    return None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- seal parsing and verification ----------------------------------------

def parse_seal(line: str) -> dict | None:
    """Parse one `HEXBEE-SEAL k=v ...` line into a dict."""
    line = line.strip()
    if not line.startswith(SEAL_PREFIX):
        return None
    fields = {}
    for token in line[len(SEAL_PREFIX):].split():
        key, _, value = token.partition("=")
        if key:
            fields[key] = value
    if "device" not in fields or "counter" not in fields:
        return None
    try:
        fields["counter"] = int(fields["counter"])
    except ValueError:
        return None
    fields.setdefault("kind", "case_seal")
    fields["head"] = "" if fields.get("head") in ("-", None) else fields["head"]
    return fields


def verify_seal(seal: dict, key: bytes) -> tuple[bool, str]:
    """Recompute the token's HMAC. Returns (ok, reason).

    The material must match `build_seal()` on the device exactly — device id,
    kind, counter, nonce, and chain head, pipe-separated.
    """
    signature = seal.get("sig", "")
    if signature in ("", "unsigned"):
        return False, "token produced an unsigned seal (no key provisioned)"
    if not key:
        return False, "no local key for this token — cannot verify"
    material = "%s|%s|%d|%s|%s" % (seal["device"], seal["kind"],
                                   seal["counter"], seal.get("nonce", ""),
                                   seal.get("head", ""))
    expected = hmac.new(key, material.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, signature):
        return True, "signature verified"
    return False, "SIGNATURE MISMATCH — seal was not produced by this token"


class CounterGuard:
    """Rejects replayed seals.

    The token's counter only ever increases. A seal whose counter is not
    greater than the last one accepted for that device is either a replay or
    a token that was reset, and either way it should not silently become
    evidence.
    """

    def __init__(self, state_file: Path | None = None):
        self.path = state_file or (Path.home() / ".hexbee-sentinel-counters")
        self._state: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                device, _, value = line.partition("=")
                if device and value.strip().isdigit():
                    self._state[device] = int(value)
        except OSError:
            pass

    def _save(self) -> None:
        try:
            self.path.write_text(
                "\n".join(f"{d}={c}" for d, c in sorted(self._state.items())),
                encoding="utf-8")
            self.path.chmod(0o600)
        except OSError:
            pass

    def check(self, device: str, counter: int) -> tuple[bool, str]:
        last = self._state.get(device)
        if last is not None and counter <= last:
            return False, (f"counter went backwards ({counter} <= {last}) — "
                           f"replayed seal or a reset token")
        self._state[device] = counter
        self._save()
        return True, "counter advanced"


# -- events ---------------------------------------------------------------

def seal_event(seal: dict, verified: bool, reason: str, device_name: str,
               case_id: int | None, operator: str, witness: str = "",
               note: str = "") -> dict:
    return {
        "device": device_name,
        "event_type": "case_seal",
        "occurred_at": _now(),
        "payload": {
            "seal_kind": seal["kind"],
            "token_id": seal["device"],
            "counter": seal["counter"],
            "nonce": seal.get("nonce", ""),
            "chain_head_at_seal": seal.get("head", ""),
            "signature": seal.get("sig", ""),
            "signature_verified": verified,
            "verification": reason,
            "operator": operator,
            "witness": witness,
            "note": note[:300],
            # Said plainly in the record: a plain Pico has no clock, so the
            # timestamp is the Queen's, not the token's.
            "timestamp_source": "queen (token has no real-time clock)",
        },
    }


def hid_event(entry: dict, device_name: str, case_id: int | None,
              operator: str, target: str = "") -> dict:
    return {
        "device": device_name,
        "event_type": "hid_deployment",
        "occurred_at": _now(),
        "payload": {
            "payload_name": entry.get("name", ""),
            "result": entry.get("result", ""),
            "payload_fingerprint": entry.get("fingerprint", ""),
            "lines": entry.get("lines"),
            "keystrokes": entry.get("keys"),
            "device_uptime": entry.get("uptime"),
            "target_host": target,
            "operator": operator,
            "case_id": case_id,
            "reported": "manually imported from the token (no radio on a "
                        "plain Pico)",
        },
    }


# -- Stinger: import deploy.log -------------------------------------------

def parse_hid_log(path: str | Path) -> list[dict]:
    """Parse the Stinger's tab-separated deploy.log."""
    entries = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        entry = {"name": parts[0], "result": parts[1], "fingerprint": parts[2]}
        for extra in parts[3:]:
            key, _, value = extra.partition("=")
            if key in ("lines", "keys"):
                entry[key] = int(value) if value.isdigit() else None
            elif key == "uptime":
                entry[key] = value
        entries.append(entry)
    return entries


def import_hid_log(client, path: str | Path, *, ingest_key: str,
                   device_name: str = "Pico-Stinger", case_id: int | None = None,
                   operator: str = "", target: str = "",
                   skip_disarmed: bool = True) -> dict:
    entries = parse_hid_log(path)
    if skip_disarmed:
        entries = [e for e in entries if e.get("result") != "disarmed"]
    events = [hid_event(e, device_name, case_id, operator, target) for e in entries]
    stored = client.ingest(events, ingest_key).get("stored", 0) if events else 0
    return {"entries": len(entries), "stored": stored, "deployments": entries}


# -- Sentinel: serial listener --------------------------------------------

def list_ports() -> list[str]:
    """Candidate serial devices on this platform, best guess first.

    Uses pyserial's enumeration when available — it is the only way to find
    the port on Windows, and it gives better ordering everywhere.
    """
    try:
        from serial.tools import list_ports as pyserial_ports  # type: ignore

        found = [p.device for p in pyserial_ports.comports()]
        if found:
            return sorted(found)
    except ImportError:
        pass
    ports: list[str] = []
    for pattern in SERIAL_GLOBS.get(platform.system(), []):
        ports.extend(sorted(glob.glob(pattern)))
    return ports


def find_port(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    ports = list_ports()
    if not ports:
        return None
    # The Sentinel exposes a console endpoint and a data endpoint. The data
    # one enumerates second, so the higher-numbered device is the one that
    # carries seals.
    return ports[-1]


def port_help() -> str:
    """What to tell an operator when no port was found."""
    system = platform.system()
    ports = list_ports()
    if ports:
        return ("Found these serial devices but none responded: "
                + ", ".join(ports)
                + "\nPass --port to choose one explicitly.")
    if system == "Windows":
        return ("No serial devices found. Install pyserial (pip install "
                "pyserial) so Windows COM ports can be enumerated, and check "
                "the Pico appears in Device Manager.")
    where = ", ".join(SERIAL_GLOBS.get(system, [])) or "the usual locations"
    return (f"No serial devices found at {where}.\n"
            f"Plug the Sentinel in and check it appears — on {system} it "
            f"should show up within a second or two of connecting.")


def _open_serial(port: str, baud: int = 115200):
    """pyserial if present, otherwise the raw character device."""
    try:
        import serial  # type: ignore
        return serial.Serial(port, baud, timeout=1), True
    except ImportError:
        return open(port, "rb", buffering=0), False
    except Exception as exc:
        raise RuntimeError(f"cannot open {port}: {exc}") from exc


def watch_sentinel(client, *, port: str | None = None, ingest_key: str,
                   key: bytes = b"", device_name: str = "Pico-Sentinel",
                   case_id: int | None = None, operator: str = "",
                   witness: str = "", anchor: bool = True,
                   guard: CounterGuard | None = None,
                   on_seal=None) -> None:
    """Read seals from the token until interrupted."""
    resolved = find_port(port)
    if resolved is None:
        raise RuntimeError(port_help())
    handle, is_pyserial = _open_serial(resolved)
    guard = guard or CounterGuard()
    log.info("listening for seals on %s", resolved)

    # Push the current chain head so the signature binds the press to a
    # specific state of the evidence log.
    try:
        head = client.anchor().get("head_hash", "")
        if head and is_pyserial:
            handle.write(f"HEAD {head}\n".encode())
    except Exception:
        head = ""

    try:
        while True:
            raw = handle.readline()
            if not raw:
                time.sleep(0.1)
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            if line.startswith((READY_PREFIX, WARN_PREFIX)):
                log.info("%s", line)
                continue
            seal = parse_seal(line)
            if seal is None:
                continue

            verified, reason = verify_seal(seal, key)
            ok_counter, counter_reason = guard.check(seal["device"], seal["counter"])
            if not ok_counter:
                verified = False
                reason = f"{reason}; {counter_reason}"

            event = seal_event(seal, verified, reason, device_name, case_id,
                               operator, witness)
            result = client.ingest([event], ingest_key)
            stored = result.get("stored", 0)
            log.info("%s from token %s (counter %d): %s -> %d event(s)",
                     seal["kind"], seal["device"][:12], seal["counter"],
                     "VERIFIED" if verified else reason, stored)

            receipt = None
            if anchor and stored:
                try:
                    receipt = client.anchor()
                    log.info("chain anchored at %s",
                             receipt.get("head_hash", "")[:16])
                except Exception as exc:
                    log.warning("anchor failed: %s", exc)
            if on_seal:
                on_seal(seal, verified, reason, receipt)
    except KeyboardInterrupt:
        log.info("stopped")
    finally:
        try:
            handle.close()
        except Exception:
            pass


def load_token_key(path: str | Path | None = None) -> bytes:
    """The operator's copy of a token's provisioned key."""
    path = Path(path or (Path.home() / ".hexbee-sentinel-key"))
    try:
        return path.read_bytes().strip()
    except OSError:
        return b""
