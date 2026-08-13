# Security policy

## Scope

These skills are read-only analyzers. They parse untrusted files and untrusted
verifier output, so the security surface is parsing and subprocess handling.

Security-relevant reports include:

- A crafted asset that causes a crash, hang, unbounded memory use, or path escape.
- A crafted asset or verifier output that produces a **conclusive** result it
  should not — most importantly `ABSENT`, `NOT_DETECTED`, `VALID`, or `TRUSTED`.
- Any path where an analyzer writes to, moves, or deletes an input.
- Value leakage: `audit-metadata-privacy` printing raw metadata values.

Reports about a vendor's watermark or about C2PA itself belong upstream, not here.

## Reporting

Open a **private** security advisory through the repository's GitHub Security
tab. Please include the input that triggers the behaviour, or a script that
generates it, plus the tool, the version, and the observed and expected states.

We aim to acknowledge within 7 days. This is a small volunteer project with no
paid on-call rotation; please do not expect a same-day response.

## The rule, stated once

The distinction is whether the tool **failed closed**:

| Situation | Classification |
| --- | --- |
| A carrier is not implemented and the tool returns `UNKNOWN` with a reason | **Coverage gap.** Open a normal issue. |
| A carrier is not implemented, or a scan was incomplete, and the tool returns `ABSENT`, `NOT_DETECTED`, `VALID`, `TRUSTED`, or exit `0` | **Fail-closed defect. Report privately as security-relevant.** |

An unjustified conclusive result is the most serious class of defect in this
project, because a downstream reader will act on it. An honest `UNKNOWN` is
never a vulnerability, however incomplete the coverage behind it.

## What is not a vulnerability

- The inability to detect a keyed vendor watermark. That is by construction.
- `c2patool` defects. Report those to the ContentAuth project.

## Supported versions

The most recent release only. There is no long-term support branch.
