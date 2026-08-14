# Provenance Survival Report

> This report evaluates C2PA provenance survival only. It does not test proprietary pixel, audio, video, or keyed text watermarks. It never assigns AI authorship or intent.

## Summary

| Measure | Result |
| --- | --- |
| Recorded at | 2026-08-14T06:29:13+00:00 |
| Tool version | 0.2.0 |
| Derivatives | 2 |
| Preserved and valid | 1 |
| Lost or unavailable | 1 |
| Unknown | 0 |
| Verifier | c2patool |
| Verifier version | c2patool 0.27.11 |
| Network allowed | False |
| Signer trust | NOT_CHECKED by this workflow |

## Survival matrix

| Asset | Source | Operation | Format | Bytes | Manifest | Integrity | Outcome | SHA-256 | Reason |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| Original | C.jpg | baseline | JPEG | 140346 | PRESENT | VALID | PRESERVED_VALID | 5f57bc22ad54aab1228874e831a6feb5514e5875307945c4e4b11aae6c53e8b7 | - |
| byte-copy | C.jpg | exact-copy | JPEG | 140346 | PRESENT | VALID | PRESERVED_VALID | 5f57bc22ad54aab1228874e831a6feb5514e5875307945c4e4b11aae6c53e8b7 | - |
| macos-export | ai-watermarks-v020-sips-export.jpg | sips-jpeg-export | JPEG | 101516 | ABSENT | NOT_VERIFIED | LOST_OR_UNAVAILABLE | 61f3693417037e8ec3c8053c137e675beac0066caabc30c7c14ca3bd9c1b0348 | The verifier reported no manifest. |

## Reproducibility and interpretation

- Absolute paths are redacted to filenames.
- File hashes cover the complete files, not scan prefixes.
- Operation labels are caller-supplied notes. The tool does not perform or infer transformations.
- `LOST_OR_UNAVAILABLE` is an observed outcome. It does not prove deliberate removal.
- `VALID` describes cryptographic integrity. Signer trust was not evaluated by this workflow.
- Remote manifests were not fetched unless already local.
- The command is omitted from this shareable view because it may contain local paths; it remains in the JSON output.

## Limitations

- This workflow validates integrity but does not evaluate signer trust; use verify-content-credentials with an explicit trust policy.
- An operation label is caller-supplied metadata, not a verified description.
- LOST_OR_UNAVAILABLE describes an observation, not intent.
- Remote manifests require separately authorized network access.
- A different hash alone does not mean provenance failed; a derivative is expected to differ.
