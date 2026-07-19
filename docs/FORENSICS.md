# Forensic Evidence Handling

HexBee is built so that evidence collected in the field can stand up to
scrutiny. This document describes the integrity model and how HexBee aligns
with recognised digital-forensics principles.

## Guiding principles (ACPO / NIST aligned)

HexBee is designed around the **ACPO Good Practice** principles for digital
evidence and NIST SP 800-86 guidance:

1. **Don't alter the original.** Comb opens disk images and browser databases
   **read-only**, working on copies; the Scout is an acquisition device, not a
   modifier. Analysts should still use a **hardware or software write-blocker**
   when imaging original media (see below).
2. **Competence & auditability.** Every action an analyst takes is recorded in
   an append-only audit log, so a third party could follow what was done.
3. **An audit trail should exist and be preservable.** The evidence log is
   hash-chained and the audit trail travels inside signed export bundles.
4. **Case ownership.** Cases record who opened them and who added each note.

## The evidence integrity chain

Every event — whether from a Scout acquisition, a Comb analysis upload, or an
iPhone field photo — is appended to a single **append-only, hash-chained log**:

```
event_hash = SHA-256( prev_hash ‖ canonical_json(event) )
```

Because each hash commits to the entire history before it, **any** later edit,
reordering, or deletion of a past event breaks verification from that point
forward. Verify at any time:

```sh
hexbee-hive verify        # on the Hive
hexbee-queen verify       # remotely from the Queen
```

`received_at` (Hive bookkeeping) is deliberately excluded from the hashed
record, so a Scout's own logs can independently re-derive the chain.

## Chain-of-custody support

- **Who/when/what:** field photos and Comb findings carry the operator
  (`uploaded_by` / device), timestamps, and content hashes.
- **Audit trail:** logins (with IP), case changes, tagging, IOC edits, report
  and export generation are all recorded append-only.
- **Case QR labels** tie a physical evidence bag to its digital case record.

## Chain anchors (tamper-evidence receipts)

A **chain anchor** is a signed, point-in-time receipt of the log's head hash
and event count:

```sh
hexbee-hive anchor > engagement-start.anchor.json      # at the start
hexbee-queen anchor -o engagement-start.anchor.json
```

Store or print it (or show it as a QR). Later, prove the log still contains
that exact prefix and nobody rewound or truncated history:

```sh
hexbee-queen anchor-verify engagement-start.anchor.json
```

Verification checks the HMAC signature, that the anchored event still occupies
its position with the same hash, **and** re-runs the chain over the anchored
prefix to catch in-place edits.

## Signed evidence bundles (court-ready export)

Export a case as a self-contained, verifiable bundle:

```sh
hexbee-queen export 1            # or:  hexbee-hive export 1
```

Each bundle contains:

- `manifest.json` — the case, full timeline, chain-verification result, a chain
  anchor, the complete audit trail, and the SHA-256 of every included file
  (with a cross-check against the hash recorded in the chain).
- `files/` — the actual evidence files (e.g. field photos).
- `manifest.sig` — an **HMAC-SHA256** signature over the canonical manifest.
- `VERIFY.txt` — instructions.

Verify offline anywhere with only the signing key:

```sh
hexbee-hive verify-bundle <bundle-dir>
```

This re-checks the signature and **re-hashes every evidence file** against the
manifest, so any post-export tampering — altered manifest, swapped or edited
file, wrong key — is detected.

## Multi-hash for cross-tool verification

Comb records **MD5, SHA-1, and SHA-256** for every inventoried file. SHA-256 is
HexBee's primary integrity hash; MD5/SHA-1 are included so hashes can be
cross-checked against legacy hash sets and other forensic tools (e.g. NSRL).

## Recommended field workflow

1. **Anchor** the log at the start of the engagement; store the receipt safely.
2. Acquire with the **Scout** (or image media through a **write-blocker** and
   triage with **Comb**).
3. Work the **case** on the Queen; add notes as you go (all audit-logged).
4. **Photograph** physical evidence via the iPhone field app (hashed into the
   chain); print **QR labels** for the bags.
5. `verify` the chain, then **export** a signed bundle for hand-off.
6. Re-**anchor-verify** to prove nothing changed during the engagement.

## Limitations & operator responsibilities

- HexBee does not replace a **hardware write-blocker** for imaging original
  media — use one; Comb's read-only handling protects working copies, not the
  original device.
- The signing key must be **backed up and protected**: losing it means old
  bundles/anchors can't be verified; leaking it lets someone forge them.
- Time accuracy depends on the Scout's SNTP sync and the Hive clock; keep them
  synchronised (documented in deployment).
- Cryptographic **per-Scout identity / event signing** and **MQTT TLS** are on
  the roadmap (see JOURNAL.md) and should be enabled for high-assurance use.
