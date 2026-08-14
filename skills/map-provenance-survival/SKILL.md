---
name: map-provenance-survival
description: Compare an original asset with resized, converted, uploaded, or downloaded derivatives and produce a JSON, Markdown, or HTML provenance-survival report. Use when testing whether a CMS, image optimizer, social network, editor, screenshot, watermark-removal tool, or publishing workflow preserves Content Credentials.
---

# Map Provenance Survival

Measure a real pipeline instead of assuming that metadata survives it.

All paths below are relative to this skill's directory. If you are running from
elsewhere, use an absolute path to `scripts/map_survival.py`.

## Workflow

1. Keep an untouched original and record every transformation.
2. Obtain each derivative through the actual user-visible workflow.
3. Run:

   ```bash
   python3 scripts/map_survival.py \
     --original original.png \
     --derivative resized=resized.png \
     --derivative cms-download=downloaded.png
   ```

   For a directory of derivatives and a shareable report:

   ```bash
   python3 scripts/map_survival.py \
     --original original.png \
     --derivatives-dir transformed-copies/ \
     --report survival-report.html
   ```

4. Add `--c2patool /path/to/c2patool` for cryptographic validation. Remote-manifest fetching is disabled unless `--allow-network` is explicitly supplied.
5. Treat `LOST_OR_UNAVAILABLE` as an observed pipeline outcome, not proof of deliberate stripping.
6. Read `summary` for the counts, then quote individual rows for detail.
7. Re-run after pipeline, CDN, export, or platform changes.

## Shareable reports

- `--report` accepts a new `.html`, `.htm`, `.md`, or `.markdown` path and refuses to overwrite it.
- HTML reports are self-contained and script-free. Markdown reports have the same evidence and caveats.
- Absolute paths and the reproducibility command are redacted by default. `--include-paths` is an explicit opt-in.
- JSON always remains on stdout, even when a report is written.
- A report evaluates C2PA provenance survival only. It must not imply that proprietary pixel, audio, video, or keyed text watermark detectors ran.
- Directory batches skip hidden entries and symlinks, recursively sort files, and use relative labels. With multiple directories, labels are prefixed by the directory name.

## Evaluating a transformation tool

This skill also measures what a metadata-removal or optimisation tool actually
removes. Run the tool over a signed original, pass its output as a derivative,
and report the observed matrix. Report only what was observed: this skill does
not certify that any downstream detector will or will not fire.

## Experimental discipline

- Change one transformation per derivative where possible.
- Hash every artifact.
- Keep content comparison separate from provenance comparison.
- Record the app, command, platform, and date outside the generated matrix.
- A different hash alone does not mean provenance failed; a derivative is expected to differ.
- Use a conforming verifier before describing evidence as `PRESENT`, `VALID`, or `INVALID`.
- Evaluate signer trust separately with `verify-content-credentials`; this survival workflow does not select a trust policy.

Read `references/survival-testing.md` for the state model and test design.
