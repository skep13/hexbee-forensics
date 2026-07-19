"""HexBee Forager — autonomous live-response forensic collector.

A worker bee that forages evidence on its own. Runs on a live host and
collects volatile + persistent forensic artifacts, then streams them into the
Hive's hash-chained evidence log with no interactive input required.

Design principles (this is a DEFENSIVE DFIR triage tool):
    - READ-ONLY: it inspects the host, it never modifies it.
    - OVERT: it logs what it collects; it does not hide or evade.
    - SELF-CONTAINED: stdlib-first, with optional psutil for richer process
      and network data; degrades gracefully when a source is unavailable.
    - AUTONOMOUS: Hive location comes from env/config, every collector runs
      automatically, and `watch` mode monitors continuously — no prompts.

Intended for authorized forensic collection on systems you own or are
authorized to investigate.
"""

__version__ = "0.1.0"
