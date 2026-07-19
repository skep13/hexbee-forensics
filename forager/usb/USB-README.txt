HexBee Forager - USB triage stick
=================================

WHAT THIS IS
  A no-install forensic collector. It gathers live evidence (running
  processes, network connections, logged-on users, autoruns/persistence,
  USB history, recent files) from the computer you run it on and saves it
  to this USB stick (and/or ships it to your HexBee Hive).

  It is READ-ONLY: it inspects the machine, it does NOT change it. It does
  not install itself, hide, or run on its own - you launch it by hand.

  Use only on computers you own or are authorized to investigate.

BEFORE YOU GO (one-time prep, on your own machine)
  1. Copy this whole folder onto a USB stick.
  2. (Optional) To auto-send results to your Hive, copy
     forager.example.json to forager.json and fill in your Hive URL and
     ingest key. Without it, evidence is captured to the stick only.

AT THE SCENE (on the target computer)
  Windows:  right-click RUN-WINDOWS.bat -> "Run as administrator"
  Linux/mac: sudo ./run-linux.sh

  Collections are written to  collections\<HOST>_<timestamp>.json  on this
  stick. If a Hive is configured and reachable, they are also submitted and
  hash-chained into the evidence log automatically.

BACK AT BASE (import offline captures)
  forager.exe --hive http://HIVE:8080 --key YOUR-KEY submit "collections\*.json"

  Every submitted collection is normalized, IOC-matched, correlated into
  incidents, and preserved in the Hive's tamper-evident hash chain - the same
  chain-of-custody as any other HexBee evidence.

NOTES
  - Run as Administrator/root for full process and network visibility.
  - Nothing is written to the target's disk; the offline spool stays on the USB.
  - forager.exe collect  -> one-shot snapshot
    forager.exe watch     -> continuous monitoring (emits new-activity events)
    forager.exe status    -> show config + spool backlog
