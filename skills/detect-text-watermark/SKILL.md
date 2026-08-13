---
name: detect-text-watermark
description: Run every available text-provenance detector over a document or string and report per-detector states, including hidden Unicode channels and detached C2PA manifests. Use when a user asks whether text carries an AI watermark, contains invisible or smuggled characters, or is safe to feed into an agent pipeline.
---

# Detect Text Watermark

Run the detector registry and report what each adapter could and could not
establish. The honest result for a keyed vendor watermark is that a third party
cannot check it.

All paths below are relative to this skill's directory. If you are running from
elsewhere, use an absolute path to `scripts/detect_text_watermark.py`.

## Workflow

1. List what is actually available before promising a result:

   ```bash
   python3 scripts/detect_text_watermark.py --list-detectors
   ```

2. Analyse a file or a literal string:

   ```bash
   python3 scripts/detect_text_watermark.py /absolute/path/to/draft.md
   python3 scripts/detect_text_watermark.py --text 'text to analyse'
   ```

3. Read each detector's `state` independently:
   - `DETECTED`: that specific signal is present.
   - `NOT_DETECTED`: that specific signal was searched for and not found.
   - `UNVERIFIABLE`: the scheme exists but cannot be checked without the provider's key.
   - `NOT_CONFIGURED`: required key or configuration was not supplied.
   - `UNSUPPORTED`: configuration was supplied, but this build has no scorer.
   - `FAILED`: the detector ran but errored.

4. Treat `status` as covering only the detectors that could run. Read
   `unverifiable_detectors` and `keyed_watermark_status` alongside it.

5. If `unicode-covert-channel` reports `DETECTED`, treat it as a text-integrity
   and prompt-injection finding. Escalate `HIGH` severity items (Unicode tag
   characters, bidi overrides) before the text enters any agent pipeline.

## Why keyed watermarks cannot be detected here

Model-level text watermarks bias token sampling using a secret key. Detection
requires that key and the exact context-hashing scheme. Anthropic has not
published a detector or specification; Google open-sourced a SynthID-Text
detector but production keys are not public. Any tool claiming to detect these
from text alone is guessing.

## Non-negotiable language

- Say "no official detector is available," never "no watermark found."
- Say "hidden character channel present," never "AI watermark present."
- Invisible Unicode is not vendor-specific and identifies no model.
- Absence of every signal never establishes human authorship.

## Deliberate non-goals

Statistical or stylometric AI-text classifiers (perplexity, burstiness,
DetectGPT-style scoring) are not implemented and will not be added. Their
false-positive rates make them unsafe for accusing a person of AI authorship.

Read `references/detector-registry.md` before adding an adapter.
