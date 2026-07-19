# 🐝 HexBee Forager

An **autonomous live-response forensic collector**. A worker bee that forages
evidence on its own: it runs on a live host, collects volatile and persistent
forensic artifacts, and streams them into the Hive's hash-chained evidence log
— **with no interactive input**.

> **Authorized use only.** Forager is a defensive DFIR triage tool for systems
> you own or are authorized to investigate. It is **read-only** (it never
> modifies the host), **overt** (it logs what it collects), and sends data only
> to *your* Hive.

## What it collects

| Collector | Artifacts | Volatile? |
|-----------|-----------|-----------|
| host_info | hostname, OS, arch, users, IPs, boot time | — |
| processes | running processes (pid, name, user, cmdline) | ✓ |
| network | active connections + listening ports (+ owning pid) | ✓ |
| logons | logged-on users / sessions | ✓ |
| usb | USB device history (Win USBSTOR registry / `lsusb`) | ✓ |
| autoruns | persistence: registry Run keys, startup, cron, systemd, shell init | — |
| recent_files | files modified recently in user locations | — |

Windows and Linux/macOS. Uses **psutil** when available for richer process /
network data, with pure-stdlib native fallbacks (`tasklist`/`ps`,
`netstat`/`ss`, `winreg`) so it runs on a bare target with no `pip`.

## Install

```sh
cd forager
pip install .            # or:  pip install ".[rich]"  to include psutil
```

## Autonomous operation

The Hive location is auto-discovered — **no prompts**:
`--hive/--key` → `HEXBEE_HIVE_URL` / `HEXBEE_INGEST_KEY` → a config file
(`~/.hexbee-forager.json` or `/etc/hexbee/forager.json`).

```sh
# One-time config so it can run completely unattended
hexbee-forager config --hive http://hive.local:8080 --key <INGEST_KEY>

# One-shot triage snapshot -> shipped to the Hive
hexbee-forager collect

# Continuous monitoring: emits *_new events when a process, connection,
# logon, or USB device appears. Runs until stopped.
hexbee-forager watch --interval 60

# Offline? No problem — collect anyway; events spool locally and flush
# automatically on the next run that reaches the Hive.
hexbee-forager collect                 # with no Hive reachable
hexbee-forager status                  # shows the spool backlog
```

Run it fully unattended as a service (Linux):

```sh
sudo cp systemd/hexbee-forager.service /etc/systemd/system/
sudo systemctl enable --now hexbee-forager
```

On Windows, register `hexbee-forager watch` as a Scheduled Task (at logon /
startup) for the same effect.

## How it fits HexBee

```
   live host ──▶ 🐝 Forager (this) ──REST /ingest──▶ 🏠 Hive evidence chain
                  read-only agent                      correlation → incidents
                  offline spool + retry                IOC match, timeline, map
```

Forager events enter through the same ingest path as Scout acquisitions and
Comb analysis, so they are hash-chained, correlated into incidents, matched
against IOC watchlists, and included in signed evidence exports — the same
chain-of-custody as everything else in the platform.
