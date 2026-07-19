# Security Policy

HexBee is a forensics platform: it handles evidence that must stay confidential
and provably intact. This document describes how HexBee is hardened and how to
report a vulnerability.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead, report
privately to the maintainer (via a GitHub private security advisory on this
repository, or direct message). Include reproduction steps and impact. We aim
to acknowledge within a few days.

## Threat model

HexBee is designed to run on an **isolated / air-gapped field network**: a
Scout, a Hive (Raspberry Pi), and a Queen (Kali laptop) on a private LAN, with
no internet exposure. The primary adversaries considered:

- A malicious USB target or hostile network the Scout is exposed to.
- An attacker on the local network attempting to reach the Hive dashboard/API.
- An insider or post-incident actor attempting to **alter or delete evidence**
  after collection (the integrity model is built specifically for this).

Physical security of the devices and the deployment of TLS on the LAN are the
operator's responsibility; see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## OWASP Top 10 (2021) mapping

| # | Risk | How HexBee addresses it |
|---|------|--------------------------|
| **A01** | Broken Access Control | Role-based access (viewer ⊂ investigator ⊂ administrator) enforced by a single `require()` decorator on every route; **HMAC CSRF tokens** bound to the session on all state-changing dashboard forms; `X-Frame-Options: DENY` + `frame-ancestors 'none'`; `next=` redirect is restricted to local paths (no open redirect). |
| **A02** | Cryptographic Failures | Passwords hashed with **PBKDF2-HMAC-SHA256 (600k iterations)** + per-user salt; session tokens from `secrets`; the ingest key and passwords compared with **constant-time `hmac.compare_digest`**; cookies are `HttpOnly`, `SameSite`, and `Secure` (behind HTTPS); HSTS when TLS is enabled. |
| **A03** | Injection | All SQL uses **parameterised queries**; Jinja auto-escaping on; reports/markdown HTML-escaped; a strict **Content-Security-Policy with per-response script nonces** (no `unsafe-inline` for scripts) blocks XSS execution; Sleuth Kit is invoked via `subprocess` argument lists (no shell). |
| **A04** | Insecure Design | Evidence is **append-only and hash-chained**; **login rate limiting + lockout** (gating *before* the expensive KDF, which also blunts CPU-exhaustion DoS on the Pi); single ingest write path. |
| **A05** | Security Misconfiguration | Hardened default response headers (CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP, `Cache-Control: no-store`); `MAX_CONTENT_LENGTH` cap; Flask debug never enabled in the server command; a **`hexbee-hive security-check`** command reports posture and exits non-zero on critical findings. |
| **A06** | Vulnerable / Outdated Components | Minimal dependency footprint (Flask, paho-mqtt, segno; Pillow only on the Queen); auth, tokens, CSRF, map viewer and AI/reference fallbacks are **stdlib-only**. Pin versions in `requirements.txt` for production. |
| **A07** | Identification & Auth Failures | Strong **password policy** (min 12 chars, known-bad/username screening, NIST 800-63B style); brute-force lockout; session tokens expire (TTL); disabling a user **revokes their tokens**; unknown-user logins run a dummy KDF to avoid a username-enumeration timing oracle; every login success/failure/lockout is audit-logged **with source IP**. |
| **A08** | Software & Data Integrity Failures | The **SHA-256 hash chain** makes any edit/deletion of a past event detectable; **signed evidence-export bundles** (HMAC-SHA256 over the manifest + per-file hashes); **signed chain-anchor receipts** pin a point-in-time head so history can't be silently rewound or truncated. |
| **A09** | Security Logging & Monitoring Failures | An **append-only audit log** records logins (with IP), lockouts, case actions, tagging, IOC changes, report/export generation, AI queries, and rejected events; the audit trail is included in every signed export bundle (chain of custody). |
| **A10** | Server-Side Request Forgery | No user-supplied URLs are fetched server-side; the only outbound calls (local AI, MQTT) go to **operator-configured** hosts, never request-derived ones; maps/reference read local files with path-traversal guards. |

## Cryptography summary

- Password hashing: PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte salt.
- Evidence integrity: SHA-256 hash chain (`event_hash = SHA-256(prev_hash ‖ canonical_event)`).
- Export/anchor/CSRF signing: HMAC-SHA256 with the Hive's persistent signing
  key (`HEXBEE_SIGNING_KEY`, or an auto-generated `0600` key file).
- Session/ingest secrets: `secrets.token_urlsafe`, constant-time comparison.

## Hardening checklist for production

Run `hexbee-hive security-check`, then:

- [ ] Serve the dashboard over **HTTPS** (reverse proxy) and set `HEXBEE_SECURE_COOKIES=1`.
- [ ] Set a strong `HEXBEE_INGEST_KEY` (≥ 16 chars) or disable REST ingest.
- [ ] Replace Mosquitto `allow_anonymous` with **per-Scout credentials + TLS**.
- [ ] Set an explicit `HEXBEE_SIGNING_KEY` and back it up (needed to verify old bundles).
- [ ] Enable **full-disk encryption** on the Hive's USB SSD and the Queen.
- [ ] Restrict the LAN; keep the kit air-gapped from the internet.
