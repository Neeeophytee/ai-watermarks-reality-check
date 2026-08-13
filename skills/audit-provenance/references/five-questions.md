# The five questions

## Why a front door exists

Users ask "is this verified?" and mean several different things at once. The
six analyzers answer precisely, but a caller has to compose them correctly to
avoid overclaiming. This skill does that composition once, in one place.

## Deriving each answer

| Question | Source | `YES` requires | `UNKNOWN` when |
| --- | --- | --- | --- |
| `located` | `inspect-content-provenance`, overridden by the verifier when one runs | a structural marker, or verifier `PRESENT` | the format's carriers are not all checked, or the scan was bounded |
| `verified` | `verify-content-credentials` | `integrity=VALID` | no verifier supplied, or a non-conclusive verifier result |
| `trusted` | `verify-content-credentials` with an explicit policy | `signer_trust=TRUSTED` | no trust policy named |
| `scan_complete` | `inspect-content-provenance` | the whole asset was read | never; it is always YES or NO |

## Rules

1. The verifier overrides byte inspection. Only a conforming verifier may move
   `located` from `POSSIBLE` to a definite answer.
2. `trusted` is meaningless without a named policy. Absent one, it is `UNKNOWN`
   and an unknown is recorded — never `NO`.
3. Every `UNKNOWN` must produce an entry in `unknowns` with a next step. An
   unknown with no explanation is a bug.
4. Exit `1` only for a conclusive negative (`verified: NO` or `trusted: NO`).
   Any `UNKNOWN` is exit `2`.
5. Text signals never contribute to the four answers. They are context.
