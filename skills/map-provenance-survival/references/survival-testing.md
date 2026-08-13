# Survival testing

## Recommended derivatives

- Lossless resize or optimizer output
- JPEG/WebP/PNG conversion
- CMS upload and public download
- CDN URL download
- Social platform upload and download
- Screenshot
- Copy/paste or text edit, recorded separately for text

## Result states

- `PRESERVED_VALID`: derivative contains a manifest that validates.
- `PRESENT_INVALID`: derivative contains a manifest but validation fails.
- `POSSIBLE_NOT_VERIFIED`: local markers exist but no successful verifier result exists.
- `LOST_OR_UNAVAILABLE`: original showed evidence but the derivative does not locally expose it.
- `NO_BASELINE_EVIDENCE`: the original did not establish provenance evidence.
- `UNKNOWN`: tooling or input prevented a reliable comparison.

Do not assign intent. A platform may remove metadata through ordinary transcoding, optimization, privacy policy, or unsupported formats.
