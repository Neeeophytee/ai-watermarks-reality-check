# Contributing

Thanks for helping. Read `AGENTS.md` first — it holds the invariants this
project exists to defend, and a change that weakens one will not be merged even
if every test passes.

## The short version

1. Analyzers are read-only, standard-library-only, and Python 3.9 compatible.
2. Edit `shared/provenance_core.py`, then run `python3 scripts/sync_shared.py`.
3. Fail closed. If a format cannot be inspected exhaustively, return `UNKNOWN` —
   never `ABSENT`, `NOT_DETECTED`, or another conclusive-good state.
4. Never infer authorship from the presence or absence of anything.
5. No watermark removal, evasion, provenance stripping, or statistical AI-text
   classification. These are permanent non-goals, not a backlog.

## Before opening a pull request

```bash
python3 tests/make_fixtures.py
python3 -m unittest discover -s tests -v
python3 scripts/check_repo.py
python3 scripts/sync_shared.py --check
```

Please also run the suite under Python 3.9 if you have it available.

## Adding a format or carrier

1. Cite the specification section in a comment. Do not infer an identifier.
2. Add a **real** fixture to `tests/make_fixtures.py`. Synthetic result
   dictionaries are not accepted for carrier work.
3. Add a positive and a negative test.
4. Only add the format to `FULLY_INSPECTABLE` when **every** carrier the
   specification defines for it is checked. That set is a promise.

## Adding a detector

Read `skills/detect-text-watermark/references/detector-registry.md`. A detector
that did not run must never return `NOT_DETECTED`; use `NOT_CONFIGURED`,
`UNSUPPORTED`, `UNVERIFIABLE`, or `FAILED`.

## Changing output

Every branch of an entrypoint returns the same top-level field set. Update the
schema in `schemas/`, add the invariant there so contradictions fail validation,
and extend `scripts/validate_schema.py` if you use a new keyword.

## Style

Match the surrounding code. Comments explain why, not what.
