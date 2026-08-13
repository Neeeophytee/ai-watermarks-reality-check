# Detector registry

## Adapter contract

Every adapter is a function `(text, options) -> dict` returning:

| Field | Meaning |
| --- | --- |
| `detector` | Stable identifier used by `--detector` |
| `provider` | Who defines the scheme |
| `method` | How the signal is carried |
| `requires` | What is needed to run it; `"nothing"` if fully local |
| `state` | `DETECTED`, `NOT_DETECTED`, `NOT_CONFIGURED`, `UNVERIFIABLE`, `UNSUPPORTED`, or `FAILED` |
| `detail` | One honest sentence a reader can act on |
| `available` | Whether the adapter could actually run |

Only adapters with `available: true` contribute to the top-level `status`.
A keyed adapter must never return `NOT_DETECTED`: not being able to look is not
the same as having looked and found nothing.

## Current adapters

| Adapter | State today | Why |
| --- | --- | --- |
| `anthropic-official` | `UNVERIFIABLE` | No public detector or specification. Flip this one function when an official API ships. |
| `synthid-text` | `UNSUPPORTED` | Detector is open source in Transformers, but scoring needs the generation keys and n-gram length. Usable for a team scoring its own model output. |
| `kgw-research` | `UNSUPPORTED` | Red/green list detection needs the hash key, context width, and greenlist fraction. |
| `unicode-covert-channel` | Works locally | Structural Unicode analysis; no key needed. |
| `c2pa-text-manifest` | Works locally | Locates a conforming A.8 wrapper or a detached `.c2pa` sidecar; cryptographic verification remains separate. |

## Covert-channel classes

| Channel | Severity | Risk |
| --- | --- | --- |
| Unicode tag block `U+E0000`–`U+E007F` | HIGH | Smuggles a full ASCII payload invisibly; a live prompt-injection vector |
| Bidi controls `U+202A`–`U+202E`, `U+2066`–`U+2069` | HIGH | Rendered text can differ from byte order |
| Variation selectors `U+FE00`–`U+FE0F`, `U+E0100`–`U+E01EF` | MEDIUM | Invisible; can encode data positionally |
| Zero-width `U+200B`–`U+200D`, `U+2060`, `U+FEFF` | MEDIUM | Classic steganographic channel |
| Mixed-script words | MEDIUM | Homoglyph substitution can spoof names and domains |
| Exotic spaces | LOW | Often stylistic; can also encode data |

None of these identify a vendor or model. They are reported as text-integrity
signals only.

## Adding an adapter

1. Return `NOT_CONFIGURED` when required configuration is absent,
   `UNSUPPORTED` when this build has no implementation, and `FAILED` when an
   available detector errors. Never guess.
2. Keep the core standard-library only; optional dependencies must be imported
   lazily inside the adapter.
3. Add a test asserting the adapter degrades honestly when its input is absent.
4. Do not add a statistical AI-text classifier. That is a documented non-goal.
