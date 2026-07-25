"""Copy to config.py and edit before flashing.

    mpremote connect /dev/ttyACM0 fs cp config.py :config.py
"""

CONFIG = {
    # Identity in the Hive. Keep it unique per physical board.
    "device": "C3-Scanner-01",

    # Hive REST ingest. Leave hive_url empty to run offline (sightings are
    # printed to the console and queued in RAM until a Hive appears).
    "hive_url": "http://192.168.1.10:8080",
    "ingest_key": "",

    # Uplink network. The scanner associates only with YOUR network — it
    # never associates with anything it is scanning.
    "wifi_ssid": "hexbee-field",
    "wifi_password": "",

    # Cadence. 60 s is a good balance: long enough that the radio is idle
    # most of the time, short enough to catch someone walking past.
    "scan_interval": 60,
    "ble_seconds": 8,

    # Static position, if the scanner is deployed at a fixed point. Sightings
    # carrying lat/lon plot on the Hive's offline evidence map.
    "lat": None,
    "lon": None,
}
