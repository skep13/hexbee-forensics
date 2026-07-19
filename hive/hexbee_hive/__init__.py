"""HexBee Hive — distributed DFIR evidence aggregation node.

The Hive receives events from Scout field agents over MQTT (or the REST
ingest endpoint), normalizes them, preserves them in an append-only
hash-chained SQLite evidence log, correlates them into incidents, and
serves an analyst-facing REST API and web dashboard.
"""

__version__ = "0.1.0"
