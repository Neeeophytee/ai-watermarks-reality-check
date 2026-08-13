#!/usr/bin/env python3
"""Read-only provenance inventory with deliberately conservative conclusions.

Locates C2PA evidence structurally rather than by substring search, so a
document that merely discusses Content Credentials is never mistaken for a
signed asset.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import provenance_core as core  # noqa: E402


TOOL_NAME = "inspect-content-provenance"


def base_result(source=None, kind="file") -> dict:
    """The stable output contract. Every field exists on every path."""
    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "source": source,
        "kind": kind,
        "bytes": None,
        "sha256": None,
        "format": None,
        "scan_complete": None,
        "manifest_presence": "UNKNOWN",
        "integrity": "NOT_VERIFIED",
        "signer_trust": "NOT_CHECKED",
        "c2pa_markers": [],
        "c2pa_mentions": [],
        "covert_channels": None,
        "text_watermark": {
            "provider": "Anthropic",
            "status": "NOT_APPLICABLE",
            "reason": "The asset was not analysed.",
        },
        "reason": None,
        "limitations": [
            "Structural marker inspection is not cryptographic C2PA verification.",
            "Absence of metadata does not establish human authorship.",
            "A literal mention of C2PA in readable text is recorded separately and is never evidence.",
        ],
        "recommended_next_step": "No analysis was performed.",
    }


def inspect_text(text: str, source: str) -> dict:
    covert = core.scan_covert_channels(text)
    encoded = text.encode("utf-8")
    wrapper = core.find_c2pa_text_wrapper(text)
    markers = []
    if wrapper is not None and wrapper["conforming"]:
        markers.append({
            "location": "text manifest wrapper at offset {0}".format(wrapper["offset"]),
            "kind": "C2PA unstructured-text manifest store",
            "confidence": "STRUCTURAL",
        })
    elif wrapper is not None and wrapper["magic_confirmed"]:
        markers.append({
            "location": "text manifest wrapper at offset {0}".format(wrapper["offset"]),
            "kind": "malformed C2PA text wrapper: {0}".format(wrapper["reason"]),
            "confidence": "MODERATE",
        })
    lowered = encoded.lower()
    mentions = [term.decode("ascii") for term in
                (b"c2pa", b"contentauth", b"content credentials") if term in lowered]
    result = base_result(source, "text")
    result.update({
        "bytes": len(encoded),
        "sha256": core.sha256_bytes(encoded),
        "format": "TEXT",
        "scan_complete": True,
        "manifest_presence": "POSSIBLE" if markers else "ABSENT",
        "c2pa_markers": markers,
        "c2pa_mentions": mentions,
        "covert_channels": covert,
        "text_watermark": {
            "provider": "Anthropic",
            "status": "UNVERIFIABLE",
            "reason": (
                "No official public detector or technical detection specification "
                "is available as of 2026-08-13."
            ),
        },
        "recommended_next_step": (
            "Run verify-content-credentials; a C2PA text wrapper or malformed carrier was located."
            if markers else
            "Review covert-channel findings before trusting this text in an agent pipeline."
            if covert["findings"]
            else "No further provenance step is available for this text."
        ),
    })
    return result


def inspect_path(path: pathlib.Path) -> dict:
    core.require_file(path)
    size = path.stat().st_size
    head = core.read_head(path)
    scan_complete = size <= core.SCAN_LIMIT
    fmt = core.sniff_format(path, head)
    evidence = core.locate_c2pa_evidence(path, head, fmt)
    presence = core.presence_from_evidence(evidence, scan_complete, fmt)

    textual = core.is_text_asset(path, head)
    covert = None
    if textual:
        covert = core.scan_covert_channels(head.decode("utf-8", "replace"))

    structural = [m for m in evidence["markers"] if m["confidence"] in ("STRUCTURAL", "SIDECAR")]
    why = core.presence_reason(evidence, scan_complete, fmt)
    if structural:
        next_step = "Run verify-content-credentials; structural C2PA evidence was located."
    elif evidence["markers"]:
        next_step = "Run verify-content-credentials; format-appropriate C2PA hints were located."
    elif presence == "UNKNOWN":
        next_step = "Presence is inconclusive: {0}".format(why or "the asset could not be fully inspected.")
    elif evidence["mentions"]:
        next_step = (
            "No C2PA structure was found. The text mentions Content Credentials, "
            "which is not evidence and does not warrant verification."
        )
    else:
        next_step = "Retain ABSENT as a bounded local observation for this fully inspected file."

    result = base_result(str(path.resolve()), "file")
    result.update({
        "bytes": size,
        "sha256": core.sha256_file(path),
        "format": fmt,
        "scan_complete": scan_complete,
        "manifest_presence": presence,
        "c2pa_markers": evidence["markers"],
        "c2pa_mentions": evidence["mentions"],
        "covert_channels": covert,
        "reason": why,
        "text_watermark": {
            "provider": "Anthropic",
            "status": "UNVERIFIABLE" if textual else "NOT_APPLICABLE",
            "reason": (
                "No official public detector or technical detection specification "
                "is available as of 2026-08-13."
            ) if textual else "This asset is not text.",
        },
        "limitations": [
            "Structural marker inspection is not cryptographic C2PA verification.",
            "Only the first {0} bytes are inspected for markers; remote or external "
            "manifests may not be available.".format(core.SCAN_LIMIT),
            "Absence of metadata does not establish human authorship.",
            "ABSENT is only returned for formats whose C2PA carriers are all checked.",
            "A literal mention of C2PA in readable text is recorded separately and is never evidence.",
        ],
        "recommended_next_step": next_step,
    })
    return result


def exit_code_for(result: dict) -> int:
    if result.get("manifest_presence") == "UNKNOWN":
        return core.EXIT_INCONCLUSIVE
    return core.EXIT_CONCLUSIVE_GOOD


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("path", nargs="?", help="File to inspect")
    group.add_argument("--text", help="Literal text to inspect")
    args = parser.parse_args()
    try:
        if args.text is not None:
            result = inspect_text(args.text, "literal")
        else:
            result = inspect_path(pathlib.Path(args.path))
        print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code_for(result)
    except (OSError, ValueError) as error:
        failed = base_result(args.path or "literal", "file" if args.path else "text")
        failed["reason"] = str(error)
        print(json.dumps(failed, indent=2, sort_keys=True))
        return core.EXIT_INCONCLUSIVE


if __name__ == "__main__":
    sys.exit(main())
