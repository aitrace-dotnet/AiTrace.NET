# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to semantic versioning (pre-release).

---

## [0.1.0-preview.8] – 2026-01-29

### Added
- **Audit-only evidence diffing**
  - New CLI mode `diff-audit` to compare *only* `audit/*.json` between two sealed evidence bundles.
  - Detects **added**, **removed**, and **modified** audit records independently of reports or metadata files.

- **Append-only audit verification**
  - Semantic classification of audit evolution:
    - `IDENTICAL`
    - `EXTENDED` (append-only, no alteration)
    - `ALTERED` (removal or modification detected)

- **Deterministic audit hash**
  - Stable SHA-256 hash computed from ordered `(path, sha256)` pairs of `audit/*.json`.
  - Allows fingerprinting the audit trail independently of bundle-level changes.

- **Machine-actionable exit codes**
  - `0` → identical (or append-only when asserted)
  - `10` → append-only extension detected
  - `20` → alteration or failed assertion
  - `2` → usage error
  - `3` → runtime error

- **Audit assertions for CI / compliance pipelines**
  - `--assert-identical` : fails unless audit trails are byte-for-byte equivalent.
  - `--assert-append-only` : fails unless audit trail is identical or strictly extended.
  - `--strict` : enforces identical audit state.

- **JSON output mode**
  - `--json` flag outputs a structured, machine-readable diff report.

- **File output support**
  - `--out <path>` writes diff results (text or JSON) to disk for archival or evidence export.

- **Improved CLI ergonomics**
  - Robust flag parsing (order-independent).
  - Clear human-readable summaries with explicit compliance meaning.
  - Explicit status messages for **IDENTICAL**, **APPEND-ONLY**, and **ALTERED** audit states.

### Notes
- This release finalizes the **audit diff & verification pipeline** and is considered **feature-complete for preview**.
- Designed for **forensic verification**, **compliance audits**, and **CI enforcement** of audit immutability.
- No breaking changes to existing evidence bundle formats.
- Fully backward-compatible with previous evidence bundles.

---