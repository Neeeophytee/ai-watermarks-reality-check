# Provenance Survival Benchmark

Use this template beside a generated survival report when publishing a repeatable
test of an editor, CMS, CDN, social platform, or transformation tool.

## Test context

- Workflow or product:
- Product version or review date:
- Platform and operating system:
- Original asset source:
- Original asset license or permission:
- `c2patool` version:
- Network access allowed: yes / no
- Report filename:

## Transformations

| Label | Exact steps | Output format | Notes |
| --- | --- | --- | --- |
| example-resize | Resize to 1200 px using the product UI | JPEG | One transformation |

## Interpretation

- Report observed C2PA evidence states exactly as generated.
- Keep cryptographic integrity separate from signer trust.
- Treat `LOST_OR_UNAVAILABLE` as an outcome, not proof of deliberate stripping.
- State explicitly that proprietary pixel, audio, video, and keyed text watermarks were not tested unless an identified detector actually ran.
- Do not infer AI authorship from either the presence or absence of metadata.

## Reproduction

```bash
python3 skills/map-provenance-survival/scripts/map_survival.py \
  --original original.png \
  --derivatives-dir transformed-copies/ \
  --c2patool /path/to/c2patool \
  --report survival-report.html
```
