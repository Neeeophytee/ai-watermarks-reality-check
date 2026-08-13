---
name: verify-content-credentials
description: Verify C2PA Content Credentials in a local asset with the official c2patool, separating manifest presence, cryptographic integrity, and signer trust. Use when a user needs defensible validation instead of byte-marker guesses, including offline and unavailable-verifier cases.
---

# Verify Content Credentials

Use the official verifier and preserve uncertainty. A valid signature is not automatically a trusted signer.

All paths below are relative to this skill's directory. If you are running from
elsewhere, use an absolute path to `scripts/verify_c2pa.py`.

## Workflow

1. Preserve the source asset.
2. Confirm `c2patool -V` works, or pass its explicit path with `--c2patool`.
   The wrapper requires c2patool 0.20.0 or newer and reports
   `verifier_supported: false` with an actionable reason on older builds
   rather than degrading silently.
3. Run base integrity verification:

   ```bash
   python3 scripts/verify_c2pa.py /absolute/path/to/asset
   ```

4. When trust evaluation is required, pass a reviewed trust-anchor file or URL:

   ```bash
   python3 scripts/verify_c2pa.py asset.jpg --trust-anchors /absolute/path/to/anchors.pem
   ```

5. Interpret the three result fields independently. Keep `UNKNOWN` or `NOT_CHECKED` intact.
6. The wrapper disables remote-manifest fetching by default. Add `--allow-network` only when remote retrieval is authorized; URL-based trust anchors also require it.
7. Include the verifier version and file hash in any report. Every field exists
   on every code path, so these are always available to quote.
8. Report `manifest.claim_generator` and `manifest.actions` when explaining a
   result. Users usually want to know what the manifest *claims* — whether the
   asset was declared `c2pa.created` or `c2pa.edited` — not only that a
   signature verified.

## Captured-report review mode

Review the structure of captured `c2patool` JSON without executing a binary:

```bash
python3 scripts/verify_c2pa.py --report-json report.json --asset-sha256 SHA256
```

This mode always returns `integrity=NOT_VERIFIED` and a nonzero exit status. Its nested `reported_result` is informational because captured JSON cannot prove that the verifier ran or that the report belongs to the supplied hash.

## Boundaries

- Do not download remote manifests unless the user authorized network access.
- Do not map “verifier missing” to “manifest absent.”
- Do not map `signingCredential.untrusted` to invalid content; report integrity and trust separately.
- Only a successful live verifier run with a recognized summary schema and positive signature evidence can return `VALID`.
- Never expose certificate material unless requested.

Read `references/c2pa-verification.md` before changing classification rules.
