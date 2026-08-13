# Transparency record schema

```json
{
  "publication": "Example launch",
  "jurisdictions": ["EU", "US"],
  "reviewed_at": "2026-08-12T12:00:00Z",
  "outputs": [
    {
      "name": "hero-image",
      "media_type": "image/png",
      "ai_generated": true,
      "provider": "Anthropic",
      "model": "exact model identifier if known",
      "generated_at": "2026-08-12T10:00:00Z",
      "human_edits_documented": true,
      "disclosure": {
        "present": true,
        "text": "AI-generated image; edited by the Web After AI team."
      },
      "provenance": {
        "manifest_presence": "PRESENT",
        "integrity": "VALID",
        "signer_trust": "NOT_CHECKED",
        "text_watermark": "NOT_APPLICABLE",
        "asset_sha256": "64 lowercase hexadecimal characters"
      }
    }
  ]
}
```

For AI-generated text from Anthropic, use `"text_watermark": "UNVERIFIABLE"` until an official detector is available. A disclosure should still be readable without specialized tooling.
