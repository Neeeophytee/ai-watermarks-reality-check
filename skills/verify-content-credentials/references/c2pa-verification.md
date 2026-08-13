# C2PA verification rules

Reviewed 2026-08-12 against the official c2patool usage guide:
https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/usage.md

## Classification

- Parse JSON only. Preserve the raw tool exit code, verifier version, and stderr summary.
- `VALID` requires a successful live tool exit, a manifest entry matching `active_manifest`, the current c2patool summary fields `validation_state` and `validation_results.activeManifest`, and positive claim-signature validation codes.
- A manifest with an integrity or asset-binding error is `INVALID`.
- A clear “no manifest/claim” result is `ABSENT` and `NOT_VERIFIED`.
- A tool failure, timeout, malformed output, missing external manifest, or network failure is `UNKNOWN`.
- `signingCredential.untrusted` changes signer trust to `UNTRUSTED`; it does not by itself make integrity invalid.
- Trust is `NOT_CHECKED` unless a trust evaluation was explicitly run.

The classifier intentionally recognizes the current summary schema conservatively. Unknown schemas, inconsistent states, or incomplete positive evidence produce `UNKNOWN`. Captured JSON is informational only and can never produce a verified result.

## Trust lists

Trust is contextual. Record the exact anchor set used. The official C2PA conformance trust list can be supplied to c2patool, but applications may use different policies.
