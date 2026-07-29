# HexBee Forensics — Build Journal

A distributed digital forensics & incident response (DFIR) platform.
**Detect · Isolate · Analyse.**

- **Builder:** skep13
- **Repo:** https://github.com/skep13/hexbee-forensics
- **Hardware:** ESP32-S3 (Scout) · ESP32-C3 (Stinger) · Raspberry Pi 3B+ (Hive) · ANY LAPTOP (Queen) · iPhone XR (field companion)

> **How to read this journal.** The upper section is a chronological
> **development log** of build sessions. The lower section is a complete
> **inventory** of every part built, plus the hardware, constraints, and end
> goal. Each log entry has a `Time:` line — fill in your actual working time
> per session, and add photos/screenshots as you go (drop images in a
> `journal/` folder and link them). Do **not** invent hours; log real ones.

---

## Development log

### Entry 1 — Platform core (Hive)
**Time:** _(fill in)_

Built the heart of the Hive on a Raspberry Pi–friendly, 1 GB-RAM-conscious
design:

- SQLite schema + thread-safe wrapper (WAL mode, single lock).
- **Evidence integrity via a SHA-256 hash chain** — each event commits to the
  entire history before it, so any edit/deletion breaks verification.
- Event **normalization** (accepts ISO-8601 or epoch timestamps; per-type
  severity table).
- Single write path (`store_event`) feeding an event-driven **incident
  correlation engine** (severity ≥ 2 opens/extends an incident and pulls in
  recent same-device context).
- **Timeline** reconstruction, **case management** (`HB-YYYY-NNNN`), **auth +
  RBAC** (PBKDF2, tokens, viewer/investigator/administrator), **search**, and
  an **append-only audit log**.

*Decision:* hash-chain over per-event hashes, because a single hash proves a
record wasn't corrupted but not that nothing was deleted or reordered.

### Entry 2 — Web dashboard + REST API
**Time:** _(fill in)_

One Flask app serving both the analyst dashboard and a versioned `/api/v1`
REST surface, sharing a single token auth path. HTML/JSON/CSV **report
engine**. Honey-on-black themed, server-rendered templates.

### Entry 3 — Queen analyst CLI + Scout firmware & simulator
**Time:** _(fill in)_

- **Queen** (`hexbee-queen`): stdlib-only REST client + CLI for cases,
  incidents, timeline, search, reports.
- **Scout firmware** (ESP-IDF, C): Wi-Fi station + auto-reconnect, SNTP,
  MQTT publish (QoS 1), heartbeat, and a RAM **offline event buffer** that
  flushes in order on reconnect. `usb_watch` runs in simulation mode until the
  TinyUSB acquisition path is validated on real silicon.
- **Scout simulator** (Python): emits the exact JSON a real Scout sends, so
  the full pipeline runs with no hardware (`quiet`/`usb`/`incident` scenarios).

### Entry 4 — Deployment + first end-to-end test
**Time:** _(fill in)_

Raspberry Pi `install.sh` (Mosquitto, dedicated user, virtualenv, DB init,
systemd services that auto-start headless), systemd units, and docs. Ran the
simulator against a live Hive: events → auto-correlated incident → case →
report → verified hash chain. First green test suite.

### Entry 5 — Branding + IOC engine
**Time:** _(fill in)_

- Integrated the official **HexBee Forensics logo** (favicon, navbar, login,
  embedded in reports) with generated size variants.
- **IOC engine**: watchlist (sha256/filename/ip/domain/substring) matched at
  ingest; a hit escalates to critical, opens/extends an incident, tags the
  event, and audit-logs it. Added Devices, IOCs, and Audit pages.

### Entry 6 — Comb forensic triage toolkit (Autopsy/AXIOM-class)
**Time:** _(fill in)_

Queen-side analysis toolkit whose findings upload into the Hive's evidence
chain: magic-byte typing + **extension-mismatch detection**, **file carving**
from raw images, **MBR/GPT** partition parsing, **EXIF/GPS** extraction,
**browser history** (Chrome/Firefox), optional **Sleuth Kit** integration, and
a scan pipeline + branded report.

### Entry 7 — Offline maps, reference library, and local AI
**Time:** _(fill in)_

- **Offline evidence map**: zero-dependency slippy map serving standard
  MBTiles, plotting GPS coordinates recovered from evidence.
- **Offline reference library**: serves ZIM archives (offline Wikipedia) plus
  local HTML/Markdown/PDF field docs.
- **Hive Mind local AI**: case summaries + evidence Q&A via a local Ollama
  model, with a deterministic rule-based fallback (fully offline).

### Entry 8 — iPhone XR field companion + QR evidence labels
**Time:** _(fill in)_

Installable **PWA** at `/field` (Add to Home Screen, no App Store): view open
incidents, photograph evidence **directly into the hash chain**, and per-case
**QR labels** the iPhone camera scans to open a case. Mobile-responsive across
all pages. Test suite grew to **48 passing tests**.

### Entry 9 — Ship prep: Kali setup, docs, LICENSE, hardware BOM
**Time:** _(fill in)_

Kali `setup-kali.sh` for the Queen (pipx + Sleuth Kit), disk-image mounting
workflow docs, a forensic-hygiene fix (browser DB copies are shredded after
reading), MIT `LICENSE`, and a hardware **bill of materials + wiring**
([docs/HARDWARE.md](docs/HARDWARE.md)). Published to GitHub.

### Entry 10 — Security & forensic hardening
**Time:** _(fill in)_

Raised the platform to a professional field-forensics standard:

- **OWASP Top 10 pass** (see [SECURITY.md](SECURITY.md) for the full mapping):
  strict Content-Security-Policy with **per-response script nonces**, full
  security-header set, **HMAC CSRF tokens** on all dashboard forms,
  **login rate-limiting + lockout**, constant-time secret comparison,
  a strong **password policy** (NIST 800-63B style), IP-stamped audit logging,
  secure-cookie/HSTS support, and a `hexbee-hive security-check` command.
- **Forensic evidence upgrades** (see [docs/FORENSICS.md](docs/FORENSICS.md)):
  **signed chain-anchor receipts** (pin the log head so history can't be
  rewound/truncated), **HMAC-signed evidence-export bundles** (manifest +
  per-file hashes + full audit trail, verifiable offline), and Comb
  **multi-hash** (MD5/SHA-1/SHA-256) for cross-tool verification.
- Test suite grew to **63 passing tests** (added `test_security.py`).

### Entry 11 — Forager: autonomous live-response collector
**Time:** _(fill in)_

Built **HexBee Forager** (`forager/`), a read-only agent that collects forensic
evidence from a live host on its own — no interactive input:

- Cross-platform collectors (psutil + stdlib/native fallbacks): host info,
  processes, network connections with owning process, logged-on users,
  persistence/autoruns (registry Run keys, startup, cron, systemd), USB
  history, and recent files.
- Autonomous by design: Hive location auto-discovered (args → env → config
  file); every collector runs automatically; a `watch` mode continuously
  samples and emits `process_new` / `network_new` / `logon_new` / `usb_new`
  events when something appears. Offline events **spool locally and retry**.
- Ships through the same `/ingest` path as everything else, so findings are
  hash-chained, correlated, IOC-matched, and export-ready.
- **Live-verified**: collected 460+ real artifacts from the dev host into the
  Hive (persistence entries, network connections with process names) — chain
  verified over 950+ events. New event types registered in the normalizer.
- Test suite now **73 passing** (added `test_forager.py`).

### Entry 12 — Point-and-click UIs (usability pass)
**Time:** _(fill in)_

Made the whole platform usable without the command line:

- **Hive Admin page** (`/admin`, administrators): point-and-click user
  management (create/enable/disable), a live security-posture report, chain
  verification, and one-click signed-anchor download.
- **Comb web UI** (`hexbee-comb serve`): a stdlib-only local browser page —
  paste a target path, click **Scan**, view the report, optionally push to the
  Hive. No commands, no extra dependencies.
- **Forager USB launcher** is now a **menu** (Collect / Monitor / Status) on
  Windows and Linux, so a responder just double-clicks and picks an option.
- Refactored the security posture into a shared `ops.py` used by both the CLI
  and the Admin page. Tests: **81 passing** (added `test_ui.py`).

### Entry 13 — Onboarding: make it usable by someone who has never done DFIR
**Time:** _(fill in)_

The platform had grown past what a README can carry. This entry is about the
first hour of a new operator's life:

- **`hexbee-hive setup`** ([setup_wizard.py](hive/hexbee_hive/setup_wizard.py)):
  an interactive first-run wizard that explains each step *before* doing it,
  gives every prompt a working default, and is safe to re-run (it reports what
  already exists instead of clobbering it).
- **`hexbee-hive doctor`** ([doctor.py](hive/hexbee_hive/doctor.py)) plus
  `/api/v1/doctor`: every check answers three questions in plain English —
  what is this, is it working, how do I fix it. Two rules it follows: a
  missing *optional* dependency is reported as a reduced capability, not a
  failure; and no check ever says "not found" without naming the command that
  fixes it.
- **Guided workflows** ([workflows.py](hive/hexbee_hive/workflows.py)) behind a
  **Start Here** page (`/start`): jobs phrased as situations ("someone handed
  me a USB stick") rather than features, with a `why` on every step. Defined
  once and consumed twice — the dashboard renders them and the assistant
  quotes them, so clicking and asking give the same answer.
- A **glossary** page and a `/collect` page for getting evidence in without a
  terminal.
- **`try-hexbee.sh` / `try-hexbee.ps1`**: one command creates a venv, installs
  all four Python components, initialises the DB, seeds a demo case, starts
  the Hive, runs the Scout simulator, and opens the dashboard.
- New docs: [INSTALL.md](docs/INSTALL.md), [OVERVIEW.md](docs/OVERVIEW.md), and
  [FIELD-GUIDE.md](docs/FIELD-GUIDE.md) (a start-to-finish kit runbook).

### Entry 14 — Hive Mind grounded on a generated operator's manual
**Time:** _(fill in)_

The local model is 1–3B on an 8 GB laptop. Asked ungrounded how to seal a
case, a model that size invents a plausible command that does not exist —
which is worse than refusing, because the operator will type it.

[knowledge.py](hive/hexbee_hive/knowledge.py) fixes that by never asking the
model to recall anything: it retrieves the exact reference material for the
question and instructs the model to answer only from it. Half the corpus is
**extracted from the running code** — event types and severities from
`normalize.EVENT_SEVERITY`, technique mappings from `attack`, CLI commands by
walking the argparse tree, API routes from the Flask app — so it cannot go
stale when someone adds a feature and forgets the docs. Surfaced as an
`/assistant` page, `hexbee-queen ai how`, and `/api/v1/knowledge/search`.

### Entry 15 — MITRE ATT&CK tagging
**Time:** _(fill in)_

[attack.py](hive/hexbee_hive/attack.py): every ingested event is matched against
an artifact-type → technique table and written to `event_techniques`, which
gives incidents and cases a tactic breakdown for free — the dashboard heatmap
(`/attack`) and the engagement report both read that one table.

Two offline data sources: a small hand-curated built-in mapping that is always
present (so tagging works on a fresh install with no data files), and
optionally a real ATT&CK STIX bundle on the external HDD, parsed lazily with
only the needed fields retained — the Pi never holds the whole 30 MB document.
Added `hexbee-hive attack backfill` / `coverage` for retro-tagging existing
events, and `/api/v1/attack/coverage`.

### Entry 16 — Offline threat intel + a lightweight SIEM
**Time:** _(fill in)_

- **`hexbee-hive sync-intel`** ([intel.py](hive/hexbee_hive/intel.py)) is a
  deliberately *pre-deployment* command: pull structured feeds while you still
  have internet; in the field the IOC engine queries the local copy and the
  Hive never touches the network. The intel DB is a **separate file** under
  the data dir, so pointing `HEXBEE_DATA_DIR` at the external HDD keeps a large
  feed off the SD card and keeps `hive.db` small enough to copy off fast.
  Feeds stream to a temp file and insert in batches — a full MalwareBazaar
  dump is millions of lines and is never read whole into RAM. Lookups are
  exact-match on an indexed column (unlike the analyst watchlist's substring
  matching).
- **Syslog / log anomaly detection** ([syslog.py](hive/hexbee_hive/syslog.py)):
  a UDP listener parsing both RFC 3164 and RFC 5424, plus `/api/v1/logs` for a
  Windows Event Log forwarder posting JSON. Regex rules with a small counter
  for threshold detections (brute force). **Raw lines are never stored** — only
  findings become events — so a chatty network cannot fill the Pi's card or
  its RAM.

### Entry 17 — Netmon: passive network monitoring
**Time:** _(fill in)_

New component [netmon/](netmon/) — the one thing the rest of the platform could
not see. Three modes: `ids` (passive detection — port scans, ARP spoofing, SMB
relay/poisoning, DNS tunnelling, suspicious destination ports, 802.11 deauth
floods), `recon` (passive inventory, one event per host rather than per packet,
randomised MACs flagged), and `diagnostics` (gateway latency/loss, DNS health,
route hops, ARP anomalies — the only mode that transmits).

*Decision:* **no scapy by default.** ~80 MB of resident set on a 1 GB Pi that is
already running the Hive is not affordable, so the default backend is a stdlib
`AF_PACKET` socket with a hand-written header decoder: single-digit MB
resident, a 256-byte snaplen so payloads are never copied out of the kernel,
decoding that stops at layer 4, and rule state that is explicitly bounded and
trimmed every 30 seconds. scapy remains an optional extra for exactly one
thing — 802.11 monitor mode, which `AF_PACKET` cannot provide.

### Entry 18 — Engagement mode: scope enforcement and offensive tooling
**Time:** _(fill in)_

The platform gained active tooling, so it first gained a gate.

- **Scope enforcement** ([scope.py](hive/hexbee_hive/scope.py)) is
  **fail-closed** by design, for legal defensibility: no scope rules at all
  means everything is denied; a match returns the rule *including its
  authorisation reference* for the report; a miss writes a `scope_violation`
  event into the evidence chain with the caller's context. Every
  traffic-generating tool calls the Queen-side `guard()` before it fires, and
  the authority lives in the Hive so one definition covers every operator and
  every tool. If the Hive is unreachable, the answer is no. Passive forensic
  collection is untouched by any of this.
- **Queen tooling**, all scope-gated and all landing in the same hash chain:
  `recon` (nmap → `recon_finding` events, gated target-by-target *before* the
  binary is invoked), `responder` (tails Responder's `Logs/` and records the
  *structure* of each capture — account, domain, source, hash format — plus a
  SHA-256 fingerprint, deliberately **not** the secret itself), `bloodhound`
  (parses SharpHound/bloodhound.py output for kerberoastable and AS-REP
  roastable accounts, unconstrained delegation, and DA membership), and
  `pivot` (renders a reviewable autossh reverse-SSH unit for a Pi drop box
  rather than silently reconfiguring a remote host).
- **Case sealing** ([seal.py](queen/hexbee_queen/seal.py)): an investigator's
  completion declaration pinned to a signed chain anchor taken at that instant,
  so it can later be shown the log has not been rewritten since.
- **Engagement report**: assembly lives in the Hive
  ([engagement.py](hive/hexbee_hive/engagement.py)) because the Hive owns the
  data — grouping five thousand events is a couple of SQLite reads there and a
  full API pull anywhere else — and is consumed by both the dashboard preview
  and `hexbee-queen engagement report`, which adds Hive Mind narration and
  HTML/PDF rendering. Ollama calls are strictly **sequential**: `phi3:mini`
  needs ~2.2 GB of the T470's 4 GB, so narration is queued one group at a time
  with a cap on how many groups get narrated.

### Entry 19 — Comb YARA · Forager memory acquisition · diagnostics mode
**Time:** _(fill in)_

- **Comb YARA** ([yara_scan.py](comb/hexbee_comb/yara_scan.py)): Comb already
  reads every file once for hashing, so rule evaluation is one extra pass over
  bytes already in hand — no extra traversal, no new I/O pattern. Rules compile
  once at scan start, never per file. Missing `yara-python` or missing rules
  degrade to "scans exactly as before, and the CLI says why".
- **Forager memory acquisition** ([memory.py](forager/hexbee_forager/memory.py)):
  the one capability that produces a large artifact. Every choice follows from
  one fact — the analyst laptop has 4 GB and the target may have 16 GB+. The
  acquisition tool writes straight to the external HDD (Forager never holds the
  image), hashing streams the file back in fixed chunks (peak memory for a
  64 GB dump is one chunk), and free space is checked *before* acquisition
  starts.
- **Forager diagnostics mode**
  ([diagnostics.py](forager/hexbee_forager/diagnostics.py)): the same agent
  pointed at machine health, reusing Hive discovery, batching, offline
  spooling, and watch mode — no second agent to deploy. Emits
  `diagnostic_snapshot` and `diagnostic_alert` events that thread through
  correlation and ATT&CK tagging like anything else.

### Entry 20 — Stinger: ESP32-C3 wireless implant
**Time:** _(fill in)_

[scout/c3-stinger/](scout/c3-stinger/) — one ~£4 MicroPython board, three modes
selected in `config.py` (only the active mode's module is imported, which
matters on ~100 KB of usable heap): `scan` (passive Wi-Fi beacon + BLE
advertisement recon into the evidence chain), `portal` (rogue AP with captive
portal), and `hid` (BLE keyboard injecting DuckyScript).

*Constraint that shaped it:* the C3 **cannot** be a USB BadUSB — its USB
peripheral is a fixed-function Serial/JTAG controller, so it physically cannot
enumerate as HID. No firmware fixes silicon. It does have BLE 5.0, and
HID-over-GATT gives the same capability over radio instead of a cable. That
trade is documented rather than hidden: you need radio range instead of port
access, and the target must pair — **a host that accepts an unauthenticated HID
connection is the finding, and a host that demands confirmed pairing is not
vulnerable, which is equally part of the deliverable.**

Two reporting-honesty decisions carried through: every sighting is flagged
`randomised_mac` when the address is locally-administered or a BLE random
address, because a randomised MAC cannot track a device across sessions and a
report must not imply it can; and since the C3 has no battery-backed RTC, it
sets `occurred_at` **only** when NTP actually succeeded, otherwise letting the
Hive record its own receipt time, with `time_synced` on every event. Stamping
everything 2000-01-01 would be worse than admitting it did not know.

Portal captures store a SHA-256 fingerprint by default, not the password —
enough to prove someone typed a real credential without putting it into an
evidence log you will hand over. `REPEAT` in the DuckyScript interpreter is
capped at 500 so a typo cannot lock a target up. Added `selftest.py`, a
one-shot non-transmitting smoke test that runs without editing `config.py`.

**Not validated on hardware** — written and contract-tested against the Hive,
but no board has run it yet.

### Entry 21 — Test suite and current state
**Time:** _(fill in)_

Suite is now **359 tests, 357 passing** on the macOS dev box. The two failures
are environment-specific, not defects: `test_exif_gps_roundtrip` needs the
optional `piexif` package, and `test_processes_collector_finds_self` asserts on
a process name that macOS `ps` truncates. Coverage grew with the features —
`test_attack.py`, `test_knowledge.py`, `test_netmon.py`, `test_onboarding.py`,
`test_queen_tools.py`, `test_scope.py`, `test_syslog_intel.py`,
`test_forager_diagnostics.py`, `test_new_api.py`, `test_hardware_contracts.py`
(firmware/board contracts tested without a board), and `test_regressions.py`.

### Entry 22 — Running the Queen on macOS, and shipping it as an app
**Time:** _(fill in)_

Stood the analyst workstation up on an Apple Silicon Mac, which meant writing
the macOS counterpart of everything that had assumed Kali.

- **`queen/setup-macos.sh`**: Homebrew + pipx installer for `hexbee-queen` and
  `hexbee-comb`, plus Sleuth Kit, libewf, nmap and smartmontools, with
  `--minimal` / `--with-ai` / `--no-yara`. Homebrew itself is deliberately
  *not* auto-installed — it asks for a password and writes to system
  directories, which is the operator's call. It also states plainly what macOS
  cannot do (memory capture, Netmon, PDF export) so those are planned around
  rather than debugged.
- **`HexBee.app`** (`scripts/make-macos-app.sh`): double-click to start the
  Hive dashboard and the Comb UI and open the browser; **quit it and both stop**.

Two macOS facts forced the design, and both were found by the thing failing:

*The app could not read its own code.* macOS **TCC** denies a double-clicked
app access to `~/Downloads`, `~/Desktop` and `~/Documents`, and denies it
*silently* — the venv failed to load with a bare `Operation not permitted` and
no prompt. So the app runs the **pipx-installed** Hive, whose code lives under
Application Support, and keeps evidence in
`~/Library/Application Support/HexBee`. Nothing it touches sits in a protected
folder. The build script warns at build time when the repo is in one.

*A shell script in an .app bundle cannot be quit.* The first version ignored
the Dock's Quit event entirely, leaving Force Quit — which SIGKILLs the
launcher and orphans the servers, exactly the failure the app was meant to
prevent. It is now an **AppleScript applet** (`osacompile -s`, stay-open),
which receives Quit properly; `on quit` stops the services it started. A
Force Quit still orphans them, so `start` clears any previous run's PIDs
first and the app self-heals on next launch.

Also fixed a packaging gap this surfaced: `knowledge_commands.json` was missing
from the Hive's `package-data`, so a non-editable install ran fine but the
assistant quietly lost the Queen/Comb/Forager/Netmon command docs.

### Entry 23 — One distribution is not "Linux": Asahi/Fedora support
**Time:** _(fill in)_

The Queen laptop is moving to **Asahi Linux** (Fedora Remix on Apple Silicon),
which broke an assumption threaded through the whole codebase: that Linux
means `apt`. On Fedora every install hint the platform printed was a command
the machine does not have — the same class of failure as saying "not found",
and a direct violation of the rule `doctor.py` is built around.

- **Package-manager detection** now drives every hint: apt, dnf, pacman,
  zypper and apk, detected by **which binary exists** rather than by parsing
  `/etc/os-release`, so derivatives need no entry. Replaced the hardcoded
  `sudo apt install …` strings in `doctor.py`, Comb (`tsk`, `cli`, `webui`)
  and Queen (`recon`, `cli`, `engagement`).
- The one apt command left is in `pivot.py`, and it is **correct** — those
  instructions run on the Raspberry Pi, which is Debian.
- Comb and Queen each carry their own copy of the ~20-line helper rather than
  importing one. They are independently installable packages by design; a
  shared import would mean Comb could not be installed without the Hive.
- **`queen/setup-linux.sh`** replaces the Kali-only installer and covers all
  four package managers from one code path, with per-distro package-name
  aliases and Asahi detection (via `/proc/device-tree/compatible`).
  `setup-kali.sh` is now a thin wrapper — two scripts doing the same job on
  different distributions is how they drift apart.
- **`scripts/make-linux-app.sh`** carries the app experience across: an
  applications-menu launcher and a Stop entry, backed by systemd **user**
  services — the Linux equivalent of an app owning its processes, tied to the
  login session with no root involved. Plus `hexbee-ctl`
  `{start|stop|restart|status|logs}` and an `--uninstall` that leaves evidence
  alone.

*Asahi specifics, documented rather than discovered later:* **Netmon works
here** — Linux gives raw packet capture that macOS does not, so the one
capability lost on the Mac comes back; memory acquisition needs LiME built
against the Asahi kernel; Asahi runs **16K pages**, which Python wheels do not
care about but a prebuilt third-party binary might; and wkhtmltopdf is absent
on Fedora just as it is on Homebrew, so the HTML report plus browser print is
the PDF path on both.

**CI now has one tab per operating system.** The existing matrix proved the
*tests* pass on Linux; it said nothing about whether the *installer* works on
Fedora, and that is the claim that actually broke. A new `installer` job runs
the real installer on macOS (arm64), Debian, Fedora, **Fedora aarch64** (the
closest a hosted runner gets to Asahi — same package manager, same
architecture) and Arch, then asserts two things: that `hexbee-queen` and
`hexbee-comb` exist and run afterwards, and that **the install hint the
platform prints names a package manager that machine actually has**. That last
check is the regression test for this entry's bug. The test matrix also gained
an `ubuntu-24.04-arm` runner, and all five shell scripts are now shellchecked
and LF-checked.

### Entry 24 — Three bugs found by actually running the thing
**Time:** _(fill in)_

The suite was green and the installers worked, so the platform *looked* fine.
Running each component against a live Hive on macOS found three defects the
tests could not have caught, because all three live where the tests were not:
in per-platform command output, and in the failure paths.

**Forager shipped nothing, silently.** It collected 819 artifacts and stored
zero: every event was rejected with `missing or invalid device name`. The Hive
requires `[A-Za-z0-9_-]{1,64}`; the agents derived a default name from
`socket.gethostname()`, which on macOS is `Jacobs-MacBook-Air.local`. One dot
made every event invalid. Nothing was lost — the spool caught all of it — but
the dashboard stayed empty while the CLI reported success, which is the worst
shape a failure can take. Both Forager and Netmon now sanitise the hostname
into something the Hive will accept. Asahi would have hit this too: Fedora
hosts routinely report an FQDN.

**The spool could never be replayed.** `_spool()` writes JSONL, because a
spool is appended to as sends fail and cannot be a well-formed array until it
is closed. `submit` parsed the whole file as one JSON document and died on
line 2. So the offline-collect-and-retry path — the thing that makes Forager
usable on a disconnected scene — had never actually worked end to end. It
reads both shapes now, and tolerates a spool truncated mid-write rather than
losing the events already in it.

**Netmon called a healthy gateway dead.** `hexbee-netmon check` raised a
severity-3 `gateway_unreachable` alert against a gateway answering in 4 ms.
`ping -W` is **seconds** on GNU/Linux and **milliseconds** on BSD, so the
Linux value gave macOS a 1 ms deadline: replies arrived "out of wait time",
every per-reply line vanished, and reachability — inferred from those lines
alone — came out false. Fixed twice over: the flag now carries the right unit
per platform, and reachability is read from the summary line, which is the
authority, rather than from timings that some pings simply do not print. A
false critical alert in an evidence log is worse than no alert.

Fourteen regression tests cover all three, including one that asserts the
Forager's own default device name passes the Hive's validator — the two had
drifted apart precisely because nothing tied them together. Suite: **373**.

### Entry 25 — The Explorer, and never needing a terminal
**Time:** _(fill in)_

Two complaints, one root cause: the platform was built by someone who lives in
a shell, for someone who does not.

**The Explorer** (`/explorer`) is the Autopsy layout over a hash-chained event
log: a navigator on the left, results in the middle, one artifact in detail on
the right. Autopsy's arrangement works because it matches the order an examiner
asks questions — *what have I got*, *what is in it*, *what is this one thing* —
and none of that is specific to filesystems.

Two design points. **The tree is derived, never stored**: every node is a saved
query, so ingesting a new artifact type grows a branch with no migration and
nothing to keep in sync. **Counts come from one grouped query per branch**, not
one per node, because a query per device per refresh is exactly what makes a UI
feel broken on a Pi.

Three bugs, all caught by opening it rather than by testing it:

- The script was in a `{% block scripts %}` that base.html does not define, so
  Jinja silently dropped it. The page returned 200 and rendered a dead
  three-pane shell. There is now a test asserting the page contains its own
  script, because "200 OK" proves nothing here.
- `max-width:1px` on the cells — a trick to force ellipsis — crushed every
  column to "202…", "Fora…", "pr…".
- Replacing it with rem widths overflowed instead: with `table-layout:fixed` a
  column set wider than the pane does not shrink, so Summary collapsed to zero
  width whenever the detail pane was open on a 1280px screen. Percentages fixed
  it for good.

**First run in the browser.** A fresh install had no account, and the only way
to make one was `hexbee-hive user add` in a terminal — a hard stop for anyone
running HexBee as an app. `/setup` creates the first administrator from the
login screen and then closes permanently: once any user exists the route
refuses, because an unauthenticated admin-creation endpoint that stays open is
a back door. It is CSRF-exempt for the same reason `/login` is — the token is
derived from the session cookie and there is no session yet — and the test that
matters is the one proving it shuts.

**A double-click on every OS.** `scripts/hexbee_launcher.py` is stdlib-only (the
thing that installs the dependencies cannot have any): it builds a private
environment if there isn't one, starts the Hive, waits for the port to actually
answer, and opens a browser. Wrapped per platform — `HexBee.app`,
`HexBee.bat` + Start Menu shortcuts via `make-windows-app.ps1`,
`try-hexbee.command`, and the Linux `.desktop` entry — with the macOS and Linux
launchers falling back to it when nothing is installed yet. Windows had no
launcher at all before this.

Two launcher bugs worth recording, both mine: `--port` was used for the
readiness check but never passed to the server, so it waited forever on a port
nothing was bound to; and `port_open(port=PORT)` captured the module default at
def time, so reassigning the global did nothing and it reported "already
running" against the wrong port. Defaults are evaluated once, not per call.

Suite: **395**.

### Entry 26 — Field provisioning, and the first hardware bring-up
**Time:** _(fill in)_

Took the kit off the bench. The Mac hosts the Hive; the Pi, the ESP32-C3, the
iPhone and the USB sticks are collectors reporting into it.

`scripts/provision-devices.py` writes the real config for each device rather
than describing what to type — a filled-in `config.py` for the C3,
`forager.json` for the sticks, a `pi-setup.sh`, and the iPhone's URL. It reads
this machine's address from the routing table, because a phone hotspot hands
out a new one every time it starts and a stale address in a flashed board is
indistinguishable from broken hardware. `demo-day.sh` wraps the whole
sequence and then *proves* it: Hive up, reachable on the LAN address, and an
ingest accepted with the key the devices actually carry. Checking matters —
"the config is written" and "the board can talk to it" are different claims.

**The ESP32-C3 ran for the first time.** MicroPython 1.27.0 flashed and
hash-verified, all seven modules copied, `selftest.py` passed on real silicon,
BLE returned 29 advertisements, and the board joined the hotspot and took a
DHCP lease. Everything in this repo about the Stinger had been theory until
this point.

Three things only hardware could have taught us:

- **The Wi-Fi scan needs a radio power-cycle.** `active(True)` followed by an
  immediate `scan()` returns zero networks; `active(False)` → sleep →
  `active(True)` → sleep → `scan()` returns eighteen. `scanner.py` will
  under-report on a cold start until this is fixed.
- **iOS stops beaconing the hotspot SSID** once something is connected to it.
  The board reported `NO_AP_FOUND` against a network sitting at −38 dBm. The
  Personal Hotspot settings screen has to be open for a new device to find it.
- **The SSID was not what anyone typed.** It is `Jacob’s iPhone` — U+2019
  curly apostrophe, lowercase i — so every hand-written variant failed. The
  scan result is now the source of truth for that string, not a human.

Also found: macOS registered the C3's USB Serial/JTAG interface as a *network
service* and ranked it above Wi-Fi, and separately the Mac's Wi-Fi associated
without ever completing DHCP (`192.0.0.2/32`, null netmask, no lease) because
of Private Wi-Fi Address against a phone hotspot. Neither is a HexBee bug, but
both look exactly like one from the operator's chair, which is why they are
written down here.

### Entry 27 — Proving the claim instead of making it
**Time:** _(fill in)_

The README had been asserting "tamper-evident" for twenty-six entries. An
examiner has no reason to believe that until they watch the tamper being
caught, so `/proof` now does the arithmetic live: the exact inputs one event's
hash commits to, an editable copy of any of them, the resulting hash, and how
many downstream records the change invalidates. On the development chain,
altering one field of event #100 invalidates 4,033 records.

**It cannot actually tamper.** `proof.py` contains no INSERT, UPDATE or DELETE;
the altered record exists only in memory, and a test asserts the chain still
verifies after previewing tampering on every hashed field. Shipping an
evidence editor to demonstrate tamper-detection would defeat the thing being
demonstrated.

The same page states where HexBee sits next to Autopsy and AXIOM **including
where they win** — deleted-file recovery, unallocated space, registry parsing,
keyword indexing at scale. Claiming to beat a court-tested disk suite at disk
forensics invites the one question that ends a conversation. The defensible
claim is narrower and true: a single-image workstation tool cannot collect
continuously from many live sources into one log and then prove the sequence
was not edited. That is the row the page demonstrates rather than asserts.

Suite: **402**.

### Entry 28 — Scout hardware bring-up (in progress)
**Time:** _(fill in)_

_Next hardware milestone — log as you go:_

- [ ] Flash the firmware onto a physical ESP32-S3 and confirm Wi-Fi + MQTT to
      the Pi (heartbeats appear on the dashboard).
- [ ] Implement the real **TinyUSB** device-mode enumeration on the target PC
      (replace the simulated insertion in `usb_watch.c`).
- [ ] MSC-host triage of an attached USB stick (file metadata → events).
- [ ] Flash the **C3 Stinger** and run `selftest.py` on real silicon; confirm
      BLE HID pairing behaviour against a test host.
- [ ] Photograph the assembled Scout + a live capture on the dashboard.
- [ ] (Stretch) per-Scout cryptographic identity + event signing; MQTT TLS.

---

## Hardware used

### Scout — ESP32-S3
USB-OTG field agent that plugs into a target computer. Flash storage only,
limited RAM, USB/battery powered. **Constraints:** acquisition and triage
only — no heavy analysis, no databases; everything it sends is small JSON.

### Stinger — ESP32-C3
Wireless implant running MicroPython on ~100 KB of usable heap. **Constraints:**
one radio shared between AP mode and the uplink; no battery-backed RTC; and no
USB HID at all — the C3's USB peripheral is a fixed-function Serial/JTAG
controller, so BLE HID-over-GATT replaces the BadUSB cable.

### Hive — Raspberry Pi 3B+
Always-on, headless evidence hub. Quad-core Cortex-A53, **1 GB RAM**, boots
from USB SSD. **Constraints:** 1 GB RAM forces SQLite over PostgreSQL,
event-driven processing over batch jobs, and memory-capped services.

### Queen — analyst workstation
Where heavy analysis (Comb) runs; no significant limits. Originally a Lenovo
ThinkPad T470 on Kali; now also an Apple Silicon Mac, moving to **Asahi Linux**
(Fedora Remix). Each OS costs something different: macOS gives up raw packet
capture and memory acquisition to the kernel's own restrictions, and confines
a double-clicked app away from `~/Downloads`; Asahi gets both capabilities back
but needs dnf rather than apt everywhere a fix-it hint is printed.

### iPhone XR — field validation terminal
Not an acquisition device: human validation, QR scanning, evidence
photography, and offline field reference via a home-screen web app.

See [docs/HARDWARE.md](docs/HARDWARE.md) for the full BOM, pinout, and
assembly.

---

## Software built (complete inventory)

Python 3 unless noted; Scout firmware is C/ESP-IDF; front-end is vanilla
HTML/CSS/JS.

### Hive — `hive/hexbee_hive/`
`config.py` (env config + data-dir layout), `db.py` (SQLite schema +
thread-safe wrapper), `integrity.py` (hash chain + verification),
`normalize.py` (canonical event shape), `store.py` (single write path),
`correlate.py` (incident correlation engine), `timeline.py` (narrative
timeline), `cases.py` (cases/notes/tags), `auth.py` (PBKDF2 + RBAC),
`search.py` (filter + stats), `reports.py` (HTML/JSON/CSV), `ingest.py`
(MQTT + REST pipeline), `ioc.py` (IOC watchlist + matching), `maps.py`
(MBTiles tile server + evidence points), `reference.py` (ZIM + document
library), `ai.py` (Hive Mind local AI + rule-based fallback),
`security.py` (CSP/nonces, security headers, HMAC CSRF, login rate limiter),
`evidence_export.py` (signed bundles + chain anchors), `ops.py` (shared
security posture), `attack.py` (offline MITRE ATT&CK tagging), `intel.py`
(offline threat-intel feeds in a separate DB), `syslog.py` (syslog listener +
log anomaly rules), `scope.py` (fail-closed engagement scope), `engagement.py`
(engagement report assembly), `knowledge.py` (generated operator's manual for
Hive Mind), `workflows.py` (guided beginner jobs), `doctor.py` (environment
self-diagnosis), `setup_wizard.py` (first-run wizard), `api.py` (Flask REST +
dashboard), `cli.py` (`hexbee-hive` command). Plus 27 HTML templates,
logo/PWA static assets, `install.sh`, two systemd units, packaging.

### Queen — `queen/hexbee_queen/`
`client.py` (stdlib REST client), `cli.py` (`hexbee-queen` command),
`scope.py` (client-side scope gate), `recon.py` (scope-gated nmap),
`responder.py` (credential-capture bridge), `bloodhound.py` (AD collector
parsing), `pivot.py` (reverse-SSH drop box), `seal.py` (case sealing),
`engagement.py` (narrated engagement report), `pkghint.py` (per-distro install
hints), `setup-linux.sh` (apt/dnf/pacman/zypper), `setup-macos.sh`,
`setup-kali.sh` (wrapper).

### Comb — `comb/hexbee_comb/`
`magic.py`, `inventory.py`, `carver.py`, `diskimage.py`, `exif.py`,
`browser.py`, `tsk.py`, `yara_scan.py`, `analysis.py`, `webui.py`
(stdlib point-and-click UI), `pkghint.py`, `cli.py` (`hexbee-comb` command).

### Forager — `forager/hexbee_forager/`
`collectors.py` (read-only host collectors), `agent.py` (autonomous
orchestration, offline spool, watch-mode deltas), `memory.py` (streaming
memory acquisition), `diagnostics.py` (machine-health mode), `cli.py`
(`hexbee-forager` command), USB launcher menu, systemd unit.

### Netmon — `netmon/hexbee_netmon/`
`capture.py` (stdlib `AF_PACKET` backend), `decode.py` (hand-written header
decoder), `rules.py` (IDS rules with bounded state), `diagnostics.py` (network
health probes), `agent.py`, `cli.py` (`hexbee-netmon` command), systemd unit.

### Scout — `scout/`
Firmware `main/scout_main.c`, `event_buffer.c/.h`, `usb_watch.c/.h`, CMake +
Kconfig + `sdkconfig.defaults`; Python simulator `scout/simulator/scout_sim.py`;
C3 Stinger (MicroPython) `c3-stinger/` — `main.py`, `link.py`, `scanner.py`,
`portal.py`, `hid.py`, `selftest.py`, DuckyScript payloads.

### Tests — `tests/` (402 tests)
`test_core.py`, `test_api.py`, `test_new_api.py`, `test_ioc.py`,
`test_comb.py`, `test_field_features.py`, `test_security.py`, `test_ui.py`,
`test_forager.py`, `test_forager_diagnostics.py`, `test_attack.py`,
`test_syslog_intel.py`, `test_netmon.py`, `test_scope.py`,
`test_queen_tools.py`, `test_knowledge.py`, `test_onboarding.py`,
`test_hardware_contracts.py`, `test_regressions.py`, `conftest.py`.

### Docs — `README.md`, `GETTING-STARTED.md`, `SECURITY.md`,
`RECOMMENDATIONS.md`, `docs/OVERVIEW.md`, `docs/INSTALL.md`,
`docs/FIELD-GUIDE.md`, `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`,
`docs/API.md`, `docs/COMB.md`, `docs/FORENSICS.md`, `docs/HARDWARE.md`,
`JOURNAL.md`, `LICENSE`. Plus `try-hexbee.sh` / `try-hexbee.ps1` one-command
local demo.

### Desktop launchers — `scripts/`
`make-macos-app.sh` (builds `HexBee.app`, a stay-open AppleScript applet that
owns the servers it starts), `make-linux-app.sh` (applications-menu launcher +
systemd user services + `hexbee-ctl`), `build_knowledge.py`, `demo_seed.py`.

---

## Design principles honoured
- **One write path** — MQTT and REST both funnel through `store_event`, which
  is what makes the hash chain trustworthy.
- **SQLite on 1 GB RAM** — WAL, single lock, event-driven correlation.
- **Stdlib-first** — auth, Queen client, map viewer, and AI/reference
  fallbacks avoid heavy deps so the air-gapped Pi and a bare Kali both work.
- **Fully offline** — maps, reference/Wikipedia, and AI run on the LAN; each
  degrades gracefully without its optional data/model.
- **Evidence hygiene** — browser DBs copied then shredded; targets never
  opened read-write; every analyst action audit-logged.
- **Fail closed on anything active** — no scope rules means nothing fires, and
  an unreachable Hive is a refusal, not a bypass. Refusals are recorded in the
  evidence chain, not just on a terminal.
- **Never store the secret** — captured credentials are recorded as structure
  plus a SHA-256 fingerprint, so an evidence log that gets handed over does not
  carry somebody's password.
- **Report what you don't know** — unsynced clocks are flagged rather than
  guessed, randomised MACs are marked as untrackable, and a target that
  *resists* an attack is written up as a finding.
- **Generated, not written, where it can go stale** — the assistant's manual is
  extracted from the running code, so a new event type documents itself.

---

## What HexBee does when done

A field-deployable DFIR platform where a **Scout** on a suspect machine streams
tamper-evident events to a headless **Hive**, which hash-chains and
auto-correlates them into incidents with timelines; **IOC** watchlists
auto-escalate known-bad indicators; the **Queen** runs **Comb** to triage
seized disk images (carving, partitions, EXIF/GPS, browser history, Sleuth Kit)
straight into the same evidence chain; analysts work cases via web + CLI, plot
GPS on an **offline map**, consult an **offline Wikipedia**, ask a **local AI**
to summarise, and export verifiable reports; and an **iPhone XR** serves as a
field companion for photographing evidence into the chain and scanning case QR
labels — every layer offline, from acquisition to signed report.

Beyond incident response, the same chain backs an **authorised engagement**:
scope rules gate every tool that generates traffic and record every refusal;
recon, credential capture, and AD collection land as evidence rather than
scratch files; **Netmon** watches the wire passively and a **Stinger** watches
the air; ATT&CK tagging turns the result into a tactic breakdown; and
`hexbee-queen engagement report` renders the narrated client deliverable from
the same events, sealed to a signed chain anchor. A beginner gets there via
`setup`, `doctor`, the **Start Here** workflows, and an assistant grounded on a
manual generated from the code itself.
