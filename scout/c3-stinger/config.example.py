"""Copy to config.py and edit before flashing.

    mpremote connect /dev/ttyACM0 fs cp config.py :config.py
"""

CONFIG = {
    # Identity in the Hive. Keep it unique per physical board.
    "device": "C3-Stinger-01",

    # scan   — passive recon; listens only, transmits nothing at targets
    # portal — rogue access point with a captive portal (TRANSMITS)
    # hid    — BLE keyboard injecting a DuckyScript payload (TRANSMITS)
    "mode": "scan",

    # Where findings go. Leave hive_url empty to run fully offline; events
    # spool to flash and upload on a later run.
    "hive_url": "http://192.168.1.10:8080",
    "ingest_key": "",

    # The operator's own uplink. The Stinger never associates with a target
    # network — this is only how it reports home.
    "wifi_ssid": "hexbee-field",
    "wifi_password": "",

    # -- scan mode --------------------------------------------------------
    "scan_interval": 60,        # seconds between sweeps
    "ble_seconds": 8,           # BLE listen window per sweep

    # -- portal mode ------------------------------------------------------
    # The SSID is yours to choose. Impersonating a specific organisation is
    # a decision for your engagement and your authorisation, not a default.
    "portal_ssid": "Guest WiFi",
    "portal_title": "Wi-Fi Login",
    "portal_subtitle": "Sign in to continue to the internet.",
    "portal_channel": 6,
    "portal_seconds": 900,      # None to run until reset
    # Off by default: a SHA-256 fingerprint proves someone typed a credential
    # without putting their password in an evidence log you will hand over.
    # Turn on only if your rules of engagement require the material itself.
    "portal_include_material": False,

    # -- hid mode ---------------------------------------------------------
    "hid_payload": "payload.txt",
    "hid_name": "Wireless Keyboard",
    "hid_pair_timeout": 120,    # seconds to advertise before giving up
    "hid_grace": 3,             # seconds after pairing before typing

    # Static position, if the board is deployed at a fixed point. Findings
    # carrying lat/lon plot on the Hive's offline evidence map.
    "lat": None,
    "lon": None,
}
