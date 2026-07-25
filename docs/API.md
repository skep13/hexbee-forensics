# Hive REST API (v1)

Base: `http://<hive>:8080/api/v1`. All endpoints return JSON unless noted.
Authenticate with `Authorization: Bearer <token>` (from `POST /login`).
Roles: **viewer** ⊂ **investigator** ⊂ **administrator**.

## Auth

| Method & path | Role | Body / params | Returns |
|---|---|---|---|
| `POST /login` | — | `{username, password}` | `{token, username, role}` |
| `POST /logout` | viewer | — | `{ok}` |
| `GET /health` | — | — | `{ok, version}` |

## Ingest (Scouts)

| Method & path | Auth | Body |
|---|---|---|
| `POST /ingest` | header `X-HexBee-Ingest-Key` | one event object or an array of them |

Returns `{stored, results: [{event_id, incident_id, techniques}], errors}`.
Disabled unless `HEXBEE_INGEST_KEY` is set. `techniques` lists the MITRE
ATT&CK ids attributed to the event at ingest.

## Log forwarding

| Method & path | Auth | Body |
|---|---|---|
| `POST /logs` | header `X-HexBee-Ingest-Key` | one JSON log record or an array (max 2000) |

For a Windows Event Log forwarder (NXLog `om_http`, winlogbeat). Records run
through the same anomaly rules as UDP syslog. Returns
`{received, anomalies, findings}`. **Only findings are stored** — the raw log
stream never enters the database.

## Engagement scope

Every active Queen tool checks this before it transmits. Fails closed: with no
rules defined, everything is denied (`HEXBEE_SCOPE_MODE=permissive` relaxes
that for lab use only).

| Method & path | Role | Notes |
|---|---|---|
| `GET /scope` | viewer | `?case_id=` — returns `{scope, summary, mode}` |
| `POST /scope` | investigator | `{kind: cidr\|host\|domain, value, auth_ref?, starts_at?, ends_at?, case_id?, note?}` |
| `DELETE /scope/<id>` | investigator | |
| `GET /scope/check` | viewer | `?target=&case_id=` → `{allowed, reason, auth_ref, rule}` |
| `POST /scope/violation` | investigator | `{target, tool, reason, extra?}` → writes a `scope_violation` event into the chain |

Hostnames are matched literally against host/domain rules; DNS is never
consulted, so an attacker-controlled record cannot widen the engagement.

## MITRE ATT&CK

| Method & path | Role | Notes |
|---|---|---|
| `GET /attack/coverage` | viewer | tactic/technique breakdown across all evidence |
| `GET /attack/coverage/<case_id>` | viewer | scoped to one case |
| `GET /events/<id>/techniques` | viewer | techniques attributed to one event |

Attribution lives in `event_techniques`, deliberately **outside** the hash
chain — it is Hive-side interpretation, not evidence.

## Engagement reporting

| Method & path | Role | Notes |
|---|---|---|
| `GET /cases/<id>/engagement` | viewer | structured report data: case, mode, stats, grouped findings, ATT&CK coverage, scope, timeline, chain verification, anchor |
| `POST /cases/<id>/mode` | investigator | `{mode: ir\|pentest\|diagnostics}` |
| `POST /incidents/<id>/triage` | investigator | structured triage prompt to Hive Mind; falls back to the rule engine |

The dashboard's `/cases/<id>/preview` page and `hexbee-queen engagement
report` both consume `/engagement`, so the preview and the delivered document
cannot drift apart.

## Live stream

| Method & path | Role | Notes |
|---|---|---|
| `GET /stream` | viewer | Server-Sent Events; `?since=<event_id>` |

`text/event-stream`. Emits `event: hello` then one `data:` frame per new
evidence record. The server closes the stream after 5 minutes; browsers
reconnect automatically.

## Operator assistance (grounded)

| Method & path | Role | Notes |
|---|---|---|
| `POST /ai/howto` | viewer | `{question}` → `{answer, engine, sources, grounded}` |
| `GET /knowledge/search` | viewer | `?q=&limit=` — raw retrieval, no model involved |

`/ai/howto` answers "how do I use HexBee" from a built-in manual rather than
from model memory. The model is handed the matching sections and instructed
that it may not go beyond them; `grounded: false` means the manual does not
cover the question and the assistant said so instead of guessing. `sources`
lists exactly the document ids the model was shown.

`/ai/ask` routes automatically: questions naming real artifacts (a filename,
an IP, a hash, a device name) go to the evidence path, instructional
questions go to the manual.

With no local model reachable, `/ai/howto` returns the matching manual
section verbatim — for a command lookup that is the correct answer, not a
degraded one.

## Threat intelligence

| Method & path | Role | Notes |
|---|---|---|
| `GET /intel/status` | viewer | local feed database: indicator counts by kind, per-feed sync state |

Populated offline by `hexbee-hive sync-intel` before deployment.

## Evidence

| Method & path | Role | Notes |
|---|---|---|
| `GET /stats` | viewer | counts + events-by-type |
| `GET /events` | viewer | filters: `text, device, event_type, incident_id, tag, since, until, min_severity, limit` |
| `GET /events/<id>` | viewer | includes `tags` |
| `POST /events/<id>/tags` | investigator | `{tag}` |
| `GET /devices` | viewer | Scout inventory |
| `GET /verify` | viewer | hash-chain verification `{ok, checked, first_bad_id}` |
| `GET /anchor` | viewer | signed chain-anchor receipt (tamper-evidence) |
| `POST /anchor/verify` | viewer | verify a previously saved anchor against the log |
| `POST /cases/<id>/export` | investigator | write a signed evidence bundle; returns `{bundle_dir, signature, ...}` |
| `GET /audit` | administrator | `?limit=` append-only audit trail |

**Security notes.** JSON API endpoints authenticate with a bearer token and are
CSRF-exempt; browser (cookie) form posts require an HMAC `_csrf` token. Login is
rate-limited (HTTP 429 on lockout). All responses carry a strict CSP and
security headers. See [SECURITY.md](../SECURITY.md).

## Incidents

| Method & path | Role | Notes |
|---|---|---|
| `GET /incidents` | viewer | `?status=open|triaged|closed` |
| `GET /incidents/<id>` | viewer | includes narrated `timeline` |
| `POST /incidents/<id>/status` | investigator | `{status}` |
| `POST /incidents/<id>/assign` | investigator | `{case_id}` |

## Cases

| Method & path | Role | Notes |
|---|---|---|
| `GET /cases` | viewer | `?status=` |
| `POST /cases` | investigator | `{title, description}` → case (auto number `HB-YYYY-NNNN`) |
| `GET /cases/<id>` | viewer | incidents + notes + `timeline` |
| `POST /cases/<id>/status` | investigator | `{status: open|active|closed}` |
| `POST /cases/<id>/notes` | investigator | `{body}` |
| `GET /cases/<id>/report?format=html\|json\|csv` | viewer | report document (non-JSON formats return their own MIME type) |

## IOCs

Indicators are matched against every incoming event's payload at ingest; a
match escalates the event to critical (opening/extending an incident), tags
it `ioc`, and records a hit.

| Method & path | Role | Notes |
|---|---|---|
| `GET /iocs` | viewer | watchlist with hit counts |
| `POST /iocs` | investigator | `{kind: sha256\|filename\|ip\|domain\|substring, value, note}` — 409 on duplicate |
| `DELETE /iocs/<id>` | investigator | removes indicator and its hits |
| `GET /iocs/hits` | viewer | `?limit=` recent matches with event/incident links |

## Example session

```sh
TOKEN=$(curl -s -X POST http://hive:8080/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"..."}' | jq -r .token)

curl -s http://hive:8080/api/v1/incidents?status=open \
  -H "Authorization: Bearer $TOKEN"

curl -s -X POST http://hive:8080/api/v1/cases \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"USB malware — front desk", "description":"Walk-in report"}'
```
