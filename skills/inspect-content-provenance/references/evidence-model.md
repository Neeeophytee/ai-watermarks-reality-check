# Evidence model

## Observable layers

1. **Container clues**: strings, chunks, boxes, XML namespaces, or sidecars that may indicate C2PA. These support only `POSSIBLE`.
2. **Cryptographic integrity**: a conforming verifier validates the claim and asset bindings. This supports `VALID` or `INVALID`.
3. **Signer trust**: the signing chain is evaluated against an explicitly selected trust list. This supports `TRUSTED` or `UNTRUSTED`.
4. **Authorship interpretation**: provenance evidence can describe a process but cannot by itself prove that all visible content was produced by one human or model.

## Anthropic text

As of 2026-08-12, Anthropic describes an imperceptible model-level text watermark but says detection details are forthcoming. Always return `UNVERIFIABLE`. Unicode controls, whitespace, punctuation, or token statistics are not official detection methods.

Official source: https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content
