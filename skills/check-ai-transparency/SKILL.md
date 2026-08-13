---
name: check-ai-transparency
description: Review a structured record of AI-generated outputs for provenance evidence, human-readable disclosure, model identification, and documented edits. Use when preparing for publication or policy review and teams need gaps and next actions without a legal conclusion.
---

# Check AI Transparency

Check whether a publication record is ready for human review. This is an evidence checklist, not legal advice or a compliance certification.

All paths below are relative to this skill's directory. If you are running from
elsewhere, use an absolute path to `scripts/check_transparency.py`.

## Workflow

1. Copy the schema from `references/record-schema.md` and describe each output.
2. Run:

   ```bash
   python3 scripts/check_transparency.py /absolute/path/to/record.json
   ```

3. Resolve each item in `gaps` or document why it is not applicable.
4. Keep machine-readable provenance and human-readable disclosure as separate controls.
5. Escalate jurisdiction-specific decisions to qualified counsel or the responsible policy owner.

## Interpretation

- `READY_FOR_REVIEW`: nothing is outstanding; it does not mean legally compliant.
- `READY_WITH_REVIEW_ITEMS`: nothing *required* is missing, but a human decision
  is outstanding (for example whether signer trust must be evaluated for this
  release). Advisory items never block readiness.
- `GAPS_FOUND`: one or more required evidence or disclosure fields are absent.
- `UNKNOWN`: the record could not be reliably evaluated.

Read `required_gap_count` and `review_item_count` separately; only the first
blocks. For Anthropic text, an `UNVERIFIABLE` detector state is acceptable only
when a truthful human-readable disclosure is present and the limitation is
retained. Text-bearing formats include PDF, DOCX, ODT, JSON and XML, not only
`text/*`.
