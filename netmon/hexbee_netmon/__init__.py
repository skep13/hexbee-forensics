"""HexBee Netmon — passive network monitoring for the Hive host.

Runs alongside the Hive on the Raspberry Pi and fills the one capability the
rest of the kit does not have: seeing the network itself. Three modes share
one capture loop:

    ids           passive detection, alerts only
    recon         inventory every MAC/IP/service observed
    diagnostics   active health checks (latency, DNS, routes, ARP table)

Findings are POSTed to the Hive's existing `/api/v1/ingest` endpoint, so they
land in the same hash-chained evidence log — and the same dashboard timeline
— as forensic artifacts.
"""

__version__ = "0.1.0"
