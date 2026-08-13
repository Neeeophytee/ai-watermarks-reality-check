# Contributor instructions

## Evidence discipline

- Preserve the fail-closed evidence states defined in `README.md`.
- Never infer AI authorship from the presence or absence of metadata.
- Never add watermark-removal, detector-evasion, or provenance-stripping features.
- Never add statistical or stylometric AI-text classification. This is a permanent non-goal.
- Treat C2PA integrity and signer trust as separate results.
- Only a conforming verifier may produce `PRESENT`, `VALID`, or `INVALID`.
- Locate C2PA evidence structurally. A literal string match in readable text is a
  mention, never a marker.
- A detector that could not run must never return `NOT_DETECTED`. Use
  `NOT_CONFIGURED`, `UNSUPPORTED`, `UNVERIFIABLE`, or `FAILED`.
- `ABSENT` requires that every C2PA carrier the specification defines for that
  format is actually checked. `FULLY_INSPECTABLE` in `shared/provenance_core.py`
  is a promise; adding a format to it without implementing its carriers is the
  most serious mistake you can make in this repository.
- A partial scan can never produce a conclusive clean result. A hash over a
  prefix must never be presented as the hash of the file.
- A standards-compliant C2PA text manifest is not a covert channel.
- Carrier identifiers are transcribed from the specification, never inferred.
  If you cannot confirm one, do not implement it.

## Code

- Keep all analyzers read-only and Python-standard-library-only. Optional
  dependencies must be imported lazily inside the adapter that needs them.
- Target Python 3.9. Do not use `match`, PEP 604 unions in runtime positions, or
  other 3.10+ syntax.
- Edit `shared/provenance_core.py`, never the vendored copies. Run
  `python3 scripts/sync_shared.py` afterwards; CI fails on drift.
- Every entrypoint honours the exit-code contract: `0` conclusive-good,
  `1` conclusive-bad, `2` inconclusive.
- Every branch of a tool must return the same top-level field set.

## Tests and schemas

- Add or update tests for every behavior change.
- Prefer real fixtures over synthetic dictionaries. Add new containers to
  `tests/make_fixtures.py`.
- Add a JSON Schema entry for any new output field, and encode evidence
  invariants in the schema so contradictions fail validation.
- `scripts/validate_schema.py` implements a keyword subset. If you use a new
  JSON Schema keyword, implement it there; `check_repo.py` asserts none are
  unimplemented.
- Live c2patool tests must remain skippable locally but are required in CI.

## Volatile claims

- Re-check product claims against official sources and record the review date in
  `SOURCES.md`.
- Do not turn a product announcement into a technical detection heuristic.
- If a vendor publishes a detector, add an adapter to the registry in
  `skills/detect-text-watermark/`; do not special-case it elsewhere.
