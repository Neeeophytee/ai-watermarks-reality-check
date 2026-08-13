#!/usr/bin/env python3
"""Run every available text-provenance detector and report honest states.

Detector registry design: each adapter declares what it needs and returns an
explicit state. Keyed model-level watermarks (Anthropic, SynthID-Text, KGW)
cannot be checked by a third party without the provider's secret key, so those
adapters report that they did not run rather than reporting a clean result.

This tool never estimates whether text is "AI-written". Statistical stylometry
detectors are a deliberate non-goal; see references/detector-registry.md.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import provenance_core as core  # noqa: E402

TOOL_NAME = "detect-text-watermark"

# Detector outcome vocabulary. The first two mean the detector ran; the rest
# mean it did not, and must never be read as a clean result.
STATE_DETECTED = "DETECTED"
STATE_NOT_DETECTED = "NOT_DETECTED"
STATE_NOT_CONFIGURED = "NOT_CONFIGURED"
STATE_UNSUPPORTED = "UNSUPPORTED"
STATE_UNVERIFIABLE = "UNVERIFIABLE"
STATE_FAILED = "FAILED"

RAN_STATES = (STATE_DETECTED, STATE_NOT_DETECTED)


def _adapter(detector, provider, method, requires, state, detail, ran, **extra):
    result = {
        "detector": detector,
        "provider": provider,
        "method": method,
        "requires": requires,
        "state": state,
        "detail": detail,
        "ran": bool(ran),
        # Retained for compatibility with the published schema: an adapter is
        # "available" exactly when it actually performed an analysis.
        "available": bool(ran),
    }
    result.update(extra)
    return result


def detector_anthropic(text, options):
    """Anthropic model-level text watermark.

    Anthropic states that eligible Claude text can carry an imperceptible
    watermark but has not published a detector or specification. A keyed
    watermark is undetectable without the provider's key by construction, so
    nothing is attempted and nothing is concluded.
    """
    return _adapter(
        "anthropic-official", "Anthropic", "keyed model-level watermark",
        "an official detector API (not yet published)",
        STATE_UNVERIFIABLE,
        "No official public detector or technical specification is available as of "
        "2026-08-13. A keyed watermark cannot be verified by a third party without "
        "the provider's key. This adapter did not analyse the text.",
        ran=False,
    )


def detector_synthid(text, options):
    """Google SynthID-Text.

    Google open-sourced a detector, but scoring requires the exact watermarking
    configuration used at generation time. This build ships no scoring
    implementation, so the adapter reports that it is an unavailable
    integration rather than implying it looked.
    """
    if not options.get("synthid_config"):
        return _adapter(
            "synthid-text", "Google", "keyed token-sampling watermark (SynthID-Text)",
            "a watermarking config with generation keys (--synthid-config)",
            STATE_NOT_CONFIGURED,
            "No watermarking configuration was supplied, so no analysis was attempted.",
            ran=False,
        )
    return _adapter(
        "synthid-text", "Google", "keyed token-sampling watermark (SynthID-Text)",
        "a vendor scoring implementation",
        STATE_UNSUPPORTED,
        "A configuration was supplied, but this build ships no SynthID scoring "
        "implementation and did not analyse the text. Score with the vendor's own "
        "detector and record the result rather than trusting a reimplementation.",
        ran=False,
    )


def detector_kgw(text, options):
    """Kirchenbauer-style red/green list watermark (open research schemes)."""
    if not options.get("kgw_key"):
        return _adapter(
            "kgw-research", "open research", "keyed red/green list watermark",
            "a hash key and scheme parameters (--kgw-key)",
            STATE_NOT_CONFIGURED,
            "No key was supplied, so no analysis was attempted.",
            ran=False,
        )
    return _adapter(
        "kgw-research", "open research", "keyed red/green list watermark",
        "a scoring implementation for the exact scheme",
        STATE_UNSUPPORTED,
        "A key was supplied, but this build ships no red/green list scorer and did "
        "not analyse the text. Use the reference implementation that produced the "
        "watermark.",
        ran=False,
    )


def detector_covert_channel(text, options):
    """Local, unkeyed, fully verifiable: hidden-data channels in the text itself."""
    try:
        scan = core.scan_covert_channels(text)
    except Exception as error:  # noqa: BLE001 - an adapter must not crash the run
        return _adapter(
            "unicode-covert-channel", "vendor-independent", "structural Unicode analysis",
            "nothing", STATE_FAILED,
            "The scan failed: {0}".format(error), ran=False,
        )
    detected = bool(scan["findings"])
    return _adapter(
        "unicode-covert-channel", "vendor-independent", "structural Unicode analysis",
        "nothing",
        STATE_DETECTED if detected else STATE_NOT_DETECTED,
        "Hidden-data channels were found. These are text-integrity and prompt-injection "
        "signals; they do not identify any model or vendor and are not watermark evidence."
        if detected else
        "No hidden-data channel was observed in the analysed text. This says nothing "
        "about authorship.",
        ran=True,
        risk=scan["risk"],
        findings=scan["findings"],
        c2pa_text_manifest=scan["c2pa_text_manifest"],
    )


def detector_c2pa_text(text, options):
    """C2PA text carriers: the A.8 wrapper, and a detached sidecar manifest."""
    wrapper = core.find_c2pa_text_wrapper(text)
    if wrapper is not None:
        return _adapter(
            "c2pa-text-manifest", "C2PA", "unstructured-text manifest wrapper (2.4 A.8)",
            "a conforming verifier for validation",
            STATE_DETECTED,
            "A C2PA text manifest wrapper was located at offset {0}. Presence is not "
            "validity: verify it with a conforming verifier.".format(wrapper["offset"]),
            ran=True, wrapper=wrapper,
        )
    path = options.get("asset_path")
    if not path:
        return _adapter(
            "c2pa-text-manifest", "C2PA", "unstructured-text manifest wrapper (2.4 A.8)",
            "nothing", STATE_NOT_DETECTED,
            "No embedded C2PA text manifest wrapper was found. Raw text has no file "
            "location, so no detached sidecar could be checked.",
            ran=True,
        )
    asset = pathlib.Path(path)
    for candidate in (asset.with_suffix(".c2pa"), asset.parent / (asset.name + ".c2pa")):
        if candidate.exists() and candidate.is_file():
            return _adapter(
                "c2pa-text-manifest", "C2PA", "detached sidecar manifest",
                "a conforming verifier for validation",
                STATE_DETECTED,
                "A detached C2PA manifest was found at {0}. Presence is not validity: "
                "run verify-content-credentials.".format(candidate.name),
                ran=True, sidecar=str(candidate),
            )
    return _adapter(
        "c2pa-text-manifest", "C2PA", "embedded wrapper and detached sidecar",
        "nothing", STATE_NOT_DETECTED,
        "No embedded C2PA text manifest and no detached sidecar were found.",
        ran=True,
    )


REGISTRY = (
    detector_anthropic,
    detector_synthid,
    detector_kgw,
    detector_covert_channel,
    detector_c2pa_text,
)


def base_result(source=None):
    """The stable output contract. Every field exists on every path."""
    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "source": source,
        "status": "UNKNOWN",
        "file_bytes": None,
        "scanned_bytes": None,
        "scan_complete": None,
        "file_sha256": None,
        "scanned_sha256": None,
        "detectors": [],
        "detector_count": 0,
        "ran_detector_count": 0,
        "did_not_run_detectors": [],
        "keyed_watermark_status": (
            "Keyed model-level watermarks (Anthropic, SynthID-Text, KGW) were not and "
            "cannot be evaluated here. No status above speaks to them."
        ),
        "reason": None,
        "non_goals": [
            "Statistical or stylometric 'AI text detection' is deliberately not implemented; "
            "its false-positive rate makes it unsafe for accusing a person of AI authorship.",
            "No detector here estimates the probability that text was machine-written.",
        ],
        "limitations": [
            "Keyed model-level watermarks cannot be verified without the provider's key.",
            "A NOT_DETECTED result never establishes human authorship.",
            "Editing, translation, and truncation can remove signals that were once present.",
        ],
    }


def overall(results, scan_complete):
    """Status reflects only detectors that actually ran, over a complete scan.

    A partial scan can never produce a clean verdict: evidence may sit in the
    bytes that were not read.
    """
    ran = [item for item in results if item["ran"]]
    if any(item["state"] == STATE_DETECTED for item in ran):
        return "SIGNAL_FOUND"
    if not ran:
        return "INCONCLUSIVE"
    if scan_complete is not True:
        return "INCONCLUSIVE"
    return "NO_SIGNAL_OBSERVED"


def analyse(text, source, options, selected=None, scan_info=None):
    result = base_result(source)
    results = []
    for detector in REGISTRY:
        item = detector(text, options)
        if selected and item["detector"] not in selected:
            continue
        results.append(item)

    info = scan_info or {}
    scan_complete = info.get("scan_complete", True)
    encoded = text.encode("utf-8")
    result.update({
        "file_bytes": info.get("file_bytes", len(encoded)),
        "scanned_bytes": info.get("scanned_bytes", len(encoded)),
        "scan_complete": scan_complete,
        "file_sha256": info.get("file_sha256", core.sha256_bytes(encoded)),
        "scanned_sha256": core.sha256_bytes(encoded),
        "detectors": results,
        "detector_count": len(results),
        "ran_detector_count": sum(1 for item in results if item["ran"]),
        "did_not_run_detectors": sorted(item["detector"] for item in results if not item["ran"]),
    })
    result["status"] = overall(results, scan_complete)
    if result["status"] == "INCONCLUSIVE":
        if scan_complete is not True:
            result["reason"] = (
                "Only the first {0} of {1} bytes were analysed, so a clean result cannot "
                "be asserted for this asset."
            ).format(info.get("scanned_bytes"), info.get("file_bytes"))
        else:
            result["reason"] = "No detector was able to run."
    return result


def exit_code_for(result):
    if result["status"] == "SIGNAL_FOUND":
        return core.EXIT_CONCLUSIVE_BAD
    if result["status"] == "NO_SIGNAL_OBSERVED":
        return core.EXIT_CONCLUSIVE_GOOD
    return core.EXIT_INCONCLUSIVE


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("path", nargs="?", help="Text file to analyse")
    group.add_argument("--text", help="Literal text to analyse")
    parser.add_argument("--detector", action="append", default=[],
                        help="Limit to named detectors (repeatable)")
    parser.add_argument("--synthid-config", help="Path to a SynthID watermarking configuration")
    parser.add_argument("--kgw-key", help="Key for a red/green list research watermark")
    parser.add_argument("--list-detectors", action="store_true", help="List registry entries and exit")
    args = parser.parse_args()

    if args.list_detectors:
        listing = [detector("", {}) for detector in REGISTRY]
        print(json.dumps({
            "schema_version": core.SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "detectors": [
                {k: item[k] for k in ("detector", "provider", "method", "requires", "ran")}
                for item in listing
            ],
        }, indent=2, sort_keys=True))
        return core.EXIT_CONCLUSIVE_GOOD

    if args.path is None and args.text is None:
        parser.error("provide a path, --text, or --list-detectors")

    options = {
        "synthid_config": args.synthid_config or os.environ.get("SYNTHID_CONFIG"),
        "kgw_key": args.kgw_key or os.environ.get("KGW_KEY"),
    }
    try:
        if args.text is not None:
            result = analyse(args.text, "literal", options, set(args.detector) or None)
        else:
            path = pathlib.Path(args.path)
            core.require_file(path)
            head = core.read_head(path, 8192)
            if not core.is_text_asset(path, head):
                raise ValueError("Not a text asset: {0}".format(path))
            stream = core.read_text_stream(path)
            options["asset_path"] = str(path.resolve())
            result = analyse(stream["text"], str(path.resolve()), options,
                             set(args.detector) or None, scan_info=stream)
        print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code_for(result)
    except (OSError, ValueError) as error:
        failed = base_result(args.path or "literal")
        failed["reason"] = str(error)
        print(json.dumps(failed, indent=2, sort_keys=True))
        return core.EXIT_INCONCLUSIVE


if __name__ == "__main__":
    sys.exit(main())
