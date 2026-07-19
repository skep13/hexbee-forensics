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

Returns `{stored, results: [{event_id, incident_id}], errors}`. Disabled
unless `HEXBEE_INGEST_KEY` is set.

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
