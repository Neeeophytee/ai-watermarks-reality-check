# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-14

### Added

- Recursive directory batching for provenance-survival tests, with stable relative labels, explicit deduplication, and no symlink traversal.
- Self-contained, script-free HTML reports and portable Markdown reports.
- Path-redacted shareable views that retain full-file hashes, verifier details, evidence states, reproducibility notes, and limitations.
- MCP directory batching through the same `map_provenance_survival` result contract.
- A repository `VERSION` file and `map_survival.py --version` release identifier.
- Report safety tests for escaping, path privacy, overwrite refusal, JSON schema parity, and CLI/MCP behavior.

### Clarified

- Survival reports evaluate C2PA evidence only. They do not imply that proprietary pixel, audio, video, or keyed text watermark detectors ran.
- `VALID` remains an integrity result; signer trust is not evaluated by the survival workflow.
- Directory discovery is workflow convenience, not proof of how any derivative was produced.

## [0.1.0] - 2026-08-13

First public release candidate. Nothing has been published before this, so the
entries below describe the state at launch rather than a delta for users.

### Skills

- `audit-provenance` — front door. Answers whether provenance was located,
  cryptographically verified, and trusted under a named policy, whether the
  scan was complete, and exactly what remains unknown.
- `inspect-content-provenance` — locates C2PA structure and hidden text channels.
- `verify-content-credentials` — wraps `c2patool`, keeping integrity and signer
  trust as independent results.
- `map-provenance-survival` — measures what a publishing pipeline does to
  provenance, with a reproducibility record.
- `audit-metadata-privacy` — read-only, value-redacted metadata audit.
- `check-ai-transparency` — disclosure-record checklist, no legal conclusion.
- `detect-text-watermark` — detector registry that reports what it could not check.

### C2PA carrier coverage

Structural detection at the locations the C2PA 2.4 specification defines:

| Container | Carrier |
| --- | --- |
| PNG | `caBX` chunk |
| JPEG | APP11 JUMBF segment |
| BMFF (MP4/HEIC/AVIF) | `uuid` box with the C2PA UUID, or `jumb` |
| WebP | RIFF `C2PA` chunk |
| TIFF/DNG | private tag `0xCD41`, type 7, in the last main IFD |
| GIF | `C2PA_GIF` application extension |
| PDF | Associated File, `/AFRelationship /C2PA_Manifest` |
| HTML | head `<script type="application/c2pa">` containing Base64; `<link rel="c2pa-manifest">` |
| Text | A.8 variation-selector wrapper (validated), A.9 block in host comments/front matter |
| Any | detached `.c2pa` sidecar |

### Guarantees

- **Fail closed.** `ABSENT` is returned only for formats whose C2PA carriers are
  all checked. A recognised container that cannot be walked exhaustively returns
  `UNKNOWN` with a stated reason.
- **Partial scans are never clean.** A bounded read cannot produce
  `NO_SIGNAL_OBSERVED`. Full-file hashes are always over every byte on disk and
  are reported separately from the hash of the scanned region.
- **Stable output.** Every branch of every entrypoint — success, error, timeout,
  malformed input, missing executable — returns the same top-level field set and
  validates against its published schema.
- **Unified exit codes.** `0` conclusive-good, `1` conclusive-bad,
  `2` inconclusive, across all seven entrypoints.
- **Binary-safe.** Verifier output is captured as bytes and decoded with
  replacement; arbitrary binary on stdout or stderr yields a structured
  inconclusive result.
- **MCP dual-era.** Implements the `2026-07-28` stateless revision including
  `server/discover`, `resultType`, and `UnsupportedProtocolVersionError`, while
  still answering the legacy `initialize` handshake.

### Deliberate non-goals

- No watermark removal, evasion, or provenance stripping.
- No statistical or stylometric AI-text classification.
- No authorship verdicts, and no legal-compliance conclusions.

### Known limitations at release

- PDF, BMFF, OOXML, ODF and ZIP are inspected but not exhaustively, so they
  return `UNKNOWN` rather than `ABSENT` when no marker is found.
- Keyed vendor text watermarks (Anthropic, SynthID-Text, KGW) cannot be checked
  without the provider's key; those adapters never claim to have looked.
- The self-signed trust tests require a `c2patool` whose signing path works.
- Python 3.9 and 3.10 verified locally; 3.11–3.13 are covered by CI only.
- Structured inspection is deliberately conservative: malformed carriers remain
  inconclusive hints, while readable examples outside a host comment or front
  matter are mentions rather than evidence.
