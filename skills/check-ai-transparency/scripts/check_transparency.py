#!/usr/bin/env python3
"""Check an AI-output transparency record for evidence and disclosure gaps.

Required gaps block readiness. Advisory review items are surfaced but never
block, so a fully disclosed and cryptographically valid asset is not held
hostage by an optional decision.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import provenance_core as core  # noqa: E402

SHA256 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_STATES = {"PRESENT", "POSSIBLE", "ABSENT", "UNKNOWN", "NOT_APPLICABLE"}
INTEGRITY_STATES = {"VALID", "INVALID", "NOT_VERIFIED", "UNKNOWN", "NOT_APPLICABLE"}
TRUST_STATES = {"TRUSTED", "UNTRUSTED", "NOT_CHECKED", "UNKNOWN", "NOT_APPLICABLE"}
TEXT_STATES = {"UNVERIFIABLE", "NOT_APPLICABLE"}
MEDIA_TYPE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")

# Media types that carry human-readable text and therefore can, in principle,
# carry a model-level text watermark.
TEXT_BEARING_PREFIXES = ("text/",)
TEXT_BEARING_EXACT = {
    "application/pdf",
    "application/json",
    "application/xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.oasis.opendocument.text",
}


def gap(output: str, field: str, message: str, severity: str = "REQUIRED") -> dict:
    return {"output": output, "field": field, "severity": severity, "message": message}


def valid_timestamp(value) -> bool:
    if value == "UNKNOWN":
        return True
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def meaningful_text(value, minimum: int = 8) -> bool:
    return isinstance(value, str) and len(value.strip()) >= minimum and sum(c.isalnum() for c in value) >= 3


def is_text_bearing(media_type: str) -> bool:
    lowered = media_type.lower()
    return lowered.startswith(TEXT_BEARING_PREFIXES) or lowered in TEXT_BEARING_EXACT


def check_output(item, index: int) -> list:
    if not isinstance(item, dict):
        return [gap("output[{0}]".format(index), "record", "Output must be an object.")]
    name = str(item.get("name") or "output[{0}]".format(index))
    gaps = []
    if not meaningful_text(item.get("name"), 2):
        gaps.append(gap(name, "name", "Provide a meaningful output name."))
    media_type = item.get("media_type")
    if not isinstance(media_type, str) or not MEDIA_TYPE.fullmatch(media_type):
        gaps.append(gap(name, "media_type",
                        "Provide a syntactically valid media type such as text/markdown or image/png."))
        media_type = ""
    if not isinstance(item.get("ai_generated"), bool):
        gaps.append(gap(name, "ai_generated", "Record whether AI generation materially contributed."))
        return gaps
    if not item["ai_generated"]:
        return gaps

    for field in ("provider", "model"):
        if not isinstance(item.get(field), str) or not item[field].strip():
            gaps.append(gap(name, field, "Provide {0} or record an explicit UNKNOWN value.".format(field)))
    if not valid_timestamp(item.get("generated_at")):
        gaps.append(gap(name, "generated_at",
                        "Use an RFC 3339 timestamp with timezone or the explicit value UNKNOWN."))
    if item.get("human_edits_documented") is not True:
        gaps.append(gap(name, "human_edits_documented",
                        "Document the edit status, including explicitly recording that no edits occurred."))

    disclosure = item.get("disclosure")
    if not isinstance(disclosure, dict) or disclosure.get("present") is not True:
        gaps.append(gap(name, "disclosure.present", "Add a human-readable AI disclosure."))
    elif not meaningful_text(disclosure.get("text")):
        gaps.append(gap(name, "disclosure.text",
                        "Include a meaningful human-readable disclosure, not a token or punctuation placeholder."))

    provenance = item.get("provenance")
    if not isinstance(provenance, dict):
        gaps.append(gap(name, "provenance", "Attach a provenance result, including explicit unknown states."))
        return gaps

    for field, allowed in (
        ("manifest_presence", MANIFEST_STATES),
        ("integrity", INTEGRITY_STATES),
        ("signer_trust", TRUST_STATES),
        ("text_watermark", TEXT_STATES),
    ):
        if provenance.get(field) not in allowed:
            gaps.append(gap(name, "provenance.{0}".format(field),
                            "Use one of: {0}.".format(", ".join(sorted(allowed)))))

    text_state = provenance.get("text_watermark")
    text_bearing = is_text_bearing(media_type)
    provider = str(item.get("provider", "")).lower()
    if text_bearing and provider == "anthropic" and text_state != "UNVERIFIABLE":
        gaps.append(gap(name, "provenance.text_watermark",
                        "Anthropic text detection must remain UNVERIFIABLE until an official detector is available."))
    if not text_bearing and text_state != "NOT_APPLICABLE":
        gaps.append(gap(name, "provenance.text_watermark",
                        "Use NOT_APPLICABLE for output that carries no human-readable text."))

    asset_hash = provenance.get("asset_sha256")
    if not isinstance(asset_hash, str) or not SHA256.fullmatch(asset_hash):
        gaps.append(gap(name, "provenance.asset_sha256",
                        "Attach a lowercase SHA-256 hash for the reviewed artifact."))

    presence = provenance.get("manifest_presence")
    integrity = provenance.get("integrity")
    trust = provenance.get("signer_trust")
    if integrity in ("VALID", "INVALID") and presence != "PRESENT":
        gaps.append(gap(name, "provenance", "VALID or INVALID integrity requires manifest_presence=PRESENT."))
    if trust in ("TRUSTED", "UNTRUSTED") and not (presence == "PRESENT" and integrity == "VALID"):
        gaps.append(gap(name, "provenance.signer_trust",
                        "A trusted or untrusted signer requires a present, cryptographically valid manifest."))
    if presence == "ABSENT" and (integrity != "NOT_VERIFIED" or trust != "NOT_CHECKED"):
        gaps.append(gap(name, "provenance",
                        "ABSENT presence requires integrity=NOT_VERIFIED and signer_trust=NOT_CHECKED."))
    if presence == "NOT_APPLICABLE" and (integrity != "NOT_APPLICABLE" or trust != "NOT_APPLICABLE"):
        gaps.append(gap(name, "provenance",
                        "NOT_APPLICABLE presence requires matching integrity and signer-trust states."))
    if presence == "POSSIBLE" and integrity not in ("NOT_VERIFIED", "UNKNOWN"):
        gaps.append(gap(name, "provenance.integrity",
                        "POSSIBLE marker evidence cannot establish VALID or INVALID integrity."))
    if integrity == "INVALID" and trust not in ("NOT_CHECKED", "UNKNOWN"):
        gaps.append(gap(name, "provenance.signer_trust",
                        "Do not issue a signer-trust conclusion for an invalid manifest."))

    # Advisory: surfaced for a human decision, never blocking.
    if media_type.startswith(("image/", "video/", "audio/")) or media_type == "application/pdf":
        if integrity in ("UNKNOWN", "NOT_VERIFIED"):
            gaps.append(gap(name, "provenance.integrity",
                            "Run a conforming verifier or document why verification is unavailable.", "REVIEW"))
    if integrity == "VALID" and trust == "NOT_CHECKED":
        gaps.append(gap(name, "provenance.signer_trust",
                        "Decide whether signer trust must be evaluated for this release.", "REVIEW"))
    return gaps


TOOL_NAME = "check-ai-transparency"


def base_result(publication="UNKNOWN") -> dict:
    """The stable output contract. Every field exists on every path."""
    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "publication": publication,
        "jurisdictions": [],
        "status": "UNKNOWN",
        "output_count": 0,
        "required_gap_count": 0,
        "review_item_count": 0,
        "gaps": [],
        "legal_conclusion": "NOT_PROVIDED",
        "reason": None,
        "limitations": [
            "READY_FOR_REVIEW means this evidence checklist is complete, not that any law or policy is satisfied.",
            "READY_WITH_REVIEW_ITEMS means nothing required is missing but a human decision is outstanding.",
            "Requirements vary by jurisdiction, role, distribution method, and future guidance.",
            "Machine-readable provenance does not replace a clear human-readable disclosure.",
        ],
    }


def check(record) -> dict:
    if not isinstance(record, dict):
        raise ValueError("Top-level record must be a JSON object.")
    outputs = record.get("outputs")
    if not isinstance(outputs, list) or not outputs:
        raise ValueError("Record must contain a non-empty outputs array.")
    gaps = []
    if not meaningful_text(record.get("publication"), 2):
        gaps.append(gap("publication", "publication", "Provide a meaningful publication name."))
    if not valid_timestamp(record.get("reviewed_at")):
        gaps.append(gap("publication", "reviewed_at",
                        "Use an RFC 3339 review timestamp with timezone or UNKNOWN."))
    jurisdictions = record.get("jurisdictions")
    if jurisdictions is not None and (
        not isinstance(jurisdictions, list) or not all(isinstance(j, str) and j.strip() for j in jurisdictions)
    ):
        gaps.append(gap("publication", "jurisdictions",
                        "When present, jurisdictions must be a list of non-empty strings."))

    for index, item in enumerate(outputs):
        gaps.extend(check_output(item, index))

    required = sum(1 for item in gaps if item["severity"] == "REQUIRED")
    review = sum(1 for item in gaps if item["severity"] == "REVIEW")
    if required:
        status = "GAPS_FOUND"
    elif review:
        status = "READY_WITH_REVIEW_ITEMS"
    else:
        status = "READY_FOR_REVIEW"

    result = base_result(record.get("publication", "UNKNOWN"))
    result.update({
        "jurisdictions": jurisdictions if isinstance(jurisdictions, list) else [],
        "status": status,
        "output_count": len(outputs),
        "required_gap_count": required,
        "review_item_count": review,
        "gaps": gaps,
    })
    return result


def exit_code_for(result: dict) -> int:
    if result["status"] == "GAPS_FOUND":
        return core.EXIT_CONCLUSIVE_BAD
    return core.EXIT_CONCLUSIVE_GOOD


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=pathlib.Path)
    args = parser.parse_args()
    try:
        with args.record.open(encoding="utf-8") as handle:
            result = check(json.load(handle))
        print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code_for(result)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        failed = base_result()
        failed["reason"] = str(error)
        print(json.dumps(failed, indent=2, sort_keys=True))
        return core.EXIT_INCONCLUSIVE


if __name__ == "__main__":
    sys.exit(main())
