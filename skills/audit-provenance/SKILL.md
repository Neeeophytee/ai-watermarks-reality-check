---
name: audit-provenance
description: Answer the five provenance questions for a single asset in one pass - was provenance located, verified, and trusted, was the scan complete, and what remains unknown. Use when a user asks for an overall provenance verdict on a file and does not want to orchestrate the individual analyzers themselves.
---

# Audit Provenance

The front door. Composes the low-level analyzers and reports one summary. It
performs no new analysis of its own and issues no authorship classification.

All paths below are relative to this skill's directory. If you are running from
elsewhere, use an absolute path to `scripts/audit_provenance.py`.

## Workflow

1. Run:

   ```bash
   python3 scripts/audit_provenance.py /absolute/path/to/asset \
     --c2patool /path/to/c2patool \
     --trust-anchors /path/to/policy.pem
   ```

2. Report the four answers, then the unknowns. Never collapse them into a
   single "verified" claim.

| Answer | Means |
| --- | --- |
| `located` | Whether C2PA structure was found where the specification puts it |
| `verified` | Whether a conforming verifier cryptographically validated the claim |
| `trusted` | Whether the signer chained to the trust policy **you named** |
| `scan_complete` | Whether the whole asset was inspected |

3. Read `unknowns`. Each entry states the question, why it is unanswered, and
   the next step. Quote these; they are the point of the tool.
4. Cite `components` when a reviewer needs to re-run one analyzer directly.

## Boundaries

- Without `--c2patool`, the cryptographic questions stay `UNKNOWN`. That is not
  a pass.
- Without `--trust-anchors`, `trusted` stays `UNKNOWN`. Trust is only meaningful
  against a named policy.
- `located: NO` is a bounded observation about supported carriers, never proof
  that content is human-made.
- This skill does not hide the six analyzers; use them directly for detail.

Read `references/five-questions.md` before changing how an answer is derived.
