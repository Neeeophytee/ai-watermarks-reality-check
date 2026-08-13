---
name: audit-metadata-privacy
description: Audit supported metadata surfaces in images, SVG, PDF, and OOXML assets for privacy signals such as GPS, author, device, software, comments, and timestamps. Use when preparing a public release and metadata exposure must be assessed without altering or invalidating provenance.
---

# Audit Metadata Privacy

Find disclosure risks without modifying the file. Report categories and severity; do not print sensitive values by default.

Supported containers: PNG, JPEG (EXIF, XMP, IPTC-IIM, COM), WebP, BMFF
(MP4/HEIC/AVIF), TIFF, PDF, SVG, OOXML and ODF.

All paths below are relative to this skill's directory. If you are running from
elsewhere, use an absolute path to `scripts/audit_metadata.py`.

## Workflow

1. Run:

   ```bash
   python3 scripts/audit_metadata.py /absolute/path/to/asset
   ```

2. Review `findings`, which contain categories and evidence locations rather than raw values.
3. Treat `HIGH` findings such as GPS as requiring deliberate review before publication.
   GPS is also read from EXIF IFD1 (the embedded thumbnail), which commonly
   retains location after the primary IFD has been scrubbed.
4. If `format_supported` is false, say so explicitly rather than reporting a clean result.
5. Before removing anything, verify whether the field belongs to a signed C2PA manifest.
6. If a sanitized derivative is needed, preserve the original, document the transformation, and re-run provenance verification on the derivative.

## Boundaries

- This skill is audit-only and never rewrites the source.
- `NONE_OBSERVED` is not a guarantee; the bounded parser can miss encrypted, proprietary, malformed, unsupported, or remotely stored metadata.
- Provenance metadata is not automatically a privacy risk.
- Ordinary metadata removal can invalidate a signed asset.

Read `references/privacy-boundaries.md` before recommending a mutation workflow.
