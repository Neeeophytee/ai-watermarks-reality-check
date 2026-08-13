---
name: inspect-content-provenance
description: Inspect local files or text for observable provenance metadata, possible C2PA markers, hashes, and text control characters. Use when a user asks whether an asset contains Content Credentials, an AI mark, provenance metadata, or suspicious invisible characters and a cautious inventory is needed before cryptographic verification.
---

# Inspect Content Provenance

Inventory evidence without making an authorship verdict. Treat located markers as clues and keep Anthropic text watermark status `UNVERIFIABLE` until Anthropic publishes a supported detector.

All paths below are relative to this skill's directory. If you are running from
elsewhere, use an absolute path to `scripts/inspect_file.py`.

## Workflow

1. Preserve the source; never rewrite it.
2. For a file, run:

   ```bash
   python3 scripts/inspect_file.py /absolute/path/to/asset
   ```

   For literal text, run:

   ```bash
   python3 scripts/inspect_file.py --text 'text to inspect'
   ```

   Literal input has no filename or host-language context, so this route checks
   the A.8 unstructured-text wrapper only. Use a file path when checking an A.9
   comment or front-matter carrier.

3. Read `manifest_presence` as an inventory result:
   - `POSSIBLE`: a structural carrier, sidecar, or format-appropriate malformed
     hint was located; inspect marker confidence and verify before relying on it.
   - `ABSENT`: the bounded local scan found no structure; this does not prove human authorship.
   - `UNKNOWN`: the input could not be meaningfully inspected, or the container is unsupported.
4. Check `c2pa_markers[].confidence`:
   - `STRUCTURAL`: found where a manifest belongs (PNG `caBX`, JPEG APP11 JUMBF, BMFF `uuid`, WebP `C2PA`).
   - `MODERATE`: a format-appropriate key or namespace reference.
   - `SIDECAR`: a detached `.c2pa` manifest beside the asset.
5. `c2pa_mentions` is separate and is never evidence. A document that discusses
   Content Credentials is not a signed asset and must not be routed to the verifier.
6. If any marker is present, use `verify-content-credentials`.
7. Report the SHA-256 hash so later derivatives can be compared.

## Non-negotiable language

- Say “possible C2PA marker,” never “valid credential,” unless a conforming verifier validates it.
- Say “Anthropic text watermark detection is unavailable,” never “no watermark found.”
- Invisible Unicode characters are a text-integrity signal, not an Anthropic watermark detector. Use `detect-text-watermark` to analyse them.
- Absence of metadata is not evidence of human creation.

Read `references/evidence-model.md` when explaining ambiguous or unknown states.
