# Sources and evidence boundaries

Reviewed on **2026-08-13**.

## Anthropic marking behavior

- [How Claude marks AI-generated content](https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content)
- [Anthropic voluntary commitments](https://www.anthropic.com/transparency/voluntary-commitments)

Anthropic says eligible Claude text can contain an imperceptible model-level watermark and supported image files can include signed C2PA provenance metadata. It also says detection details are forthcoming, edits can affect detectability, file transformations can strip metadata, and the presence or absence of a mark is not conclusive proof of origin.

Consequently, this repository always reports Anthropic text watermark detection as `UNVERIFIABLE`. It does not search for invented Unicode signatures or claim that an unmarked file is human-authored.

## Why keyed watermarks cannot be third-party detected

Model-level text watermarks bias token sampling using a secret key and a context-hashing scheme. Detection requires both. This is a property of the construction, not a gap in this implementation: without the provider's key, no local tool can check the mark, and any tool claiming otherwise is guessing.

- Google open-sourced a SynthID-Text detector in Hugging Face Transformers, but scoring requires the watermarking configuration used at generation time. Production keys are not public.
- Kirchenbauer-style red/green list schemes require the hash key, context width, and greenlist fraction.

## C2PA verification

- [Official c2patool usage guide](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/usage.md)
- [C2PA specification 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html)
- [C2PA conformance trust list](https://github.com/c2pa-org/conformance-public/tree/main/trust-list)

The official tool can read manifest JSON, report validation errors, inspect certificates, and evaluate a configured trust list. Cryptographic integrity and signer trust are separate dimensions in this repository.

### Verified verifier behavior

Validated against **c2patool 0.27.11** on 2026-08-13 using its bundled samples:

| Case | Observed |
| --- | --- |
| Unsigned `image.jpg` | exit 1, stderr `Error: No claim found`, no stdout |
| Signed `C.jpg` | exit 0, `validation_state: Valid`, failure code `signingCredential.untrusted` |
| Signed `C.jpg` with `trust --trust_anchors` | `validation_state: Trusted`, success code `signingCredential.trusted` |
| Tampered `C.jpg` | `validation_state: Invalid` |

The `--settings` flag and the `trust` subcommand are both present in 0.27.11. The supported floor is recorded as `MIN_C2PATOOL = (0, 20, 0)` in `shared/provenance_core.py`; older builds are rejected with an actionable reason rather than degraded silently.

## C2PA carrier identifiers

From the C2PA 2.4 specification, Appendix A ("Embedding manifests into ...").
Reviewed **2026-08-13**. Identifiers are transcribed, never inferred; a carrier
whose identifier we cannot confirm is not implemented.

| Container | Identifier |
| --- | --- |
| PNG | `caBX` chunk |
| JPEG | APP11 (`0xEB`) segment beginning `JP` (JUMBF) |
| BMFF | `uuid` box, UUID `d8fec3d6-1b0e-483c-9297-5828877ec481`; or `jumb` |
| WebP | RIFF `C2PA` chunk |
| TIFF/DNG | private tag `0xCD41` |
| GIF | Application Extension, identifier `C2PA_GIF` |
| PDF | Associated File; `/AFRelationship /C2PA_Manifest`, subtype `application/c2pa`, catalog `/AF` |
| HTML | `<script type="application/c2pa">` containing Base64, `<link rel="c2pa-manifest">` |
| Unstructured text | §A.8 wrapper: ZWNBSP `U+FEFF` then variation selectors `U+FE00`–`U+FE0F` and `U+E0100`–`U+E01EF`, magic `C2PATXT\x00` |
| Structured text | §A.9 ASCII-armoured block inside host front matter or a single comment line |

Reference implementation consulted for the text wrapper encoding:
[encypherai/c2pa-text](https://github.com/encypherai/c2pa-text).

### Placement rules checked

- C2PA 2.4 §A.7.1.1 defines the HTML inline media type as exactly
  `application/c2pa`; the element's trimmed text content must decode as Base64.
- §A.3.6 places TIFF tag `0xCD41` in the last IFD of the main-IFD chain; for a
  multi-IFD asset it is the only entry in that IFD.
- §A.9 requires structured-text armour to be inside supported front matter or a
  host-language comment. A readable documentation example is not a carrier.

**Consequence for the covert-channel scan:** a compliant C2PA text manifest is a
run of variation selectors after a ZWNBSP. It is located and excluded from
covert-channel findings. Reporting signed provenance as a suspicious hidden
channel would defame the standard this pack supports.

## Model Context Protocol

- [MCP versioning](https://modelcontextprotocol.io/specification/versioning)
- [MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP 2026-07-28 discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)

Reviewed **2026-08-13**. The current revision is `2026-07-28`: stateless, with
the protocol version carried per request in `_meta`, a mandatory
`server/discover`, `resultType` on results, and `UnsupportedProtocolVersionError`
(`-32022`). Unknown tools and malformed requests are JSON-RPC protocol errors
(`-32602`), not `isError` results.

## Agent Skills compatibility and discovery

- [Claude Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
- [Build skills for ChatGPT and Codex](https://learn.chatgpt.com/docs/build-skills)
- [Use Agent Skills with Gemini CLI](https://codelabs.developers.google.com/gemini-cli/how-to-create-agent-skills-for-gemini-cli)
- [skills.sh FAQ](https://skills.sh/docs/faq)

Reviewed **2026-08-13**. Claude Code, Codex, and Gemini CLI all document
filesystem-based skills built around `SKILL.md`. This establishes agent-host
compatibility, not universal watermark coverage. The analyzers remain
vendor-agnostic where evidence formats are public and explicitly inconclusive
where a proprietary detector, configuration, or key is unavailable.

The skills.sh leaderboard is populated from anonymous `skills` CLI installation
telemetry. A public GitHub repository is discoverable through
`npx skills add OWNER/REPO`; it does not need a manual directory submission.

## Updating this repository

Re-check the official pages before changing any claim about model coverage, detector availability, supported formats, trust lists, or legal obligations. Re-run the live smoke test against the current `c2patool` release and update the verified-behavior table above.
