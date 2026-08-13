#!/usr/bin/env python3
"""Front door: answer the five provenance questions for one asset.

Composes the low-level analyzers and reports a single summary:

  1. located   -- was provenance structurally located?
  2. verified  -- did a conforming verifier validate it?
  3. trusted   -- was the signer trusted under an explicitly named policy?
  4. complete  -- was the scan complete?
  5. unknown   -- what remains unknown, and why?

This adds no new analysis and no authorship classification. Each answer cites
the underlying tool so a reviewer can re-run it directly.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import provenance_core as core  # noqa: E402

TOOL_NAME = "audit-provenance"
SKILLS = HERE.parents[1]


def _load(name, relative):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, SKILLS / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def base_result(asset=None) -> dict:
    """The stable output contract. Every field exists on every path."""
    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "asset": asset,
        "asset_sha256": None,
        "format": None,
        "answers": {
            "located": "UNKNOWN",
            "verified": "UNKNOWN",
            "trusted": "UNKNOWN",
            "scan_complete": "UNKNOWN",
        },
        "unknowns": [],
        "evidence": {
            "manifest_presence": "UNKNOWN",
            "integrity": "UNKNOWN",
            "signer_trust": "UNKNOWN",
            "markers": [],
            "manifest": core.manifest_summary(None),
        },
        "trust_policy": None,
        "privacy_risk": "UNKNOWN",
        "text_signals": None,
        "components": [],
        "reason": None,
        "limitations": [
            "This is a composition of the underlying analyzers; it performs no new analysis.",
            "No answer here is an authorship classification.",
            "A trust answer is only meaningful relative to the named trust policy.",
        ],
    }


def _component(skill, ran, summary, detail=None):
    return {"skill": skill, "ran": bool(ran), "summary": summary, "detail": detail}


def audit(path, c2patool=None, trust_anchors=None, timeout=30, allow_network=False) -> dict:
    core.require_file(path)
    inspect_mod = _load("fd_inspect", "inspect-content-provenance/scripts/inspect_file.py")
    verify_mod = _load("fd_verify", "verify-content-credentials/scripts/verify_c2pa.py")
    privacy_mod = _load("fd_privacy", "audit-metadata-privacy/scripts/audit_metadata.py")
    watermark_mod = _load("fd_watermark", "detect-text-watermark/scripts/detect_text_watermark.py")

    result = base_result(str(path.resolve()))
    unknowns = []
    components = []

    # 1. Structural location.
    inspected = inspect_mod.inspect_path(path)
    components.append(_component(
        "inspect-content-provenance", True,
        "presence={0}".format(inspected["manifest_presence"]), inspected["recommended_next_step"]))
    result["asset_sha256"] = inspected["sha256"]
    result["format"] = inspected["format"]
    result["evidence"]["markers"] = inspected["c2pa_markers"]
    result["evidence"]["manifest_presence"] = inspected["manifest_presence"]

    presence = inspected["manifest_presence"]
    structural = any(marker.get("confidence") in ("STRUCTURAL", "SIDECAR")
                     for marker in inspected["c2pa_markers"])
    if presence == "POSSIBLE" and structural:
        located = "YES"
    elif presence == "POSSIBLE":
        located = "UNKNOWN"
        unknowns.append({
            "question": "located",
            "why": "Only a malformed or non-normative C2PA hint was found; structural presence is not established.",
            "next_step": "Run a conforming verifier and retain UNKNOWN if it cannot locate a manifest.",
        })
    elif presence == "ABSENT":
        located = "NO"
    else:
        located = "UNKNOWN"
        unknowns.append({
            "question": "located",
            "why": inspected["reason"] or "The asset could not be fully inspected.",
            "next_step": "Extend carrier support for this format, or inspect it manually.",
        })

    # 4. Scan completeness.
    scan_complete = "YES" if inspected["scan_complete"] else "NO"
    if not inspected["scan_complete"]:
        unknowns.append({
            "question": "scan_complete",
            "why": "Only the first {0} bytes were inspected.".format(core.SCAN_LIMIT),
            "next_step": "Re-run against a smaller asset or raise the scan limit deliberately.",
        })

    # 2 and 3. Cryptographic verification and signer trust.
    verified, trusted = "UNKNOWN", "UNKNOWN"
    if c2patool:
        verification = verify_mod.verify_asset(path, c2patool, trust_anchors, timeout, allow_network)
        components.append(_component(
            "verify-content-credentials", True,
            "integrity={0} trust={1}".format(verification["integrity"], verification["signer_trust"]),
            verification["reason"]))
        result["evidence"].update({
            "manifest_presence": verification["manifest_presence"],
            "integrity": verification["integrity"],
            "signer_trust": verification["signer_trust"],
            "manifest": verification["manifest"],
        })
        if verification["manifest_presence"] == "PRESENT":
            located = "YES"
        elif verification["manifest_presence"] == "ABSENT":
            located = "NO"

        integrity = verification["integrity"]
        if integrity == "VALID":
            verified = "YES"
        elif integrity == "INVALID":
            verified = "NO"
        else:
            unknowns.append({
                "question": "verified",
                "why": verification["reason"] or "The verifier did not return a conclusive result.",
                "next_step": "Check the verifier version and re-run.",
            })

        if not trust_anchors:
            unknowns.append({
                "question": "trusted",
                "why": "No trust policy was supplied, so signer trust was not evaluated.",
                "next_step": "Re-run with --trust-anchors naming the trust list this release requires.",
            })
        else:
            result["trust_policy"] = trust_anchors
            trust = verification["signer_trust"]
            if trust == "TRUSTED":
                trusted = "YES"
            elif trust == "UNTRUSTED":
                trusted = "NO"
            else:
                unknowns.append({
                    "question": "trusted",
                    "why": "Trust evaluation did not return a conclusive result.",
                    "next_step": "Confirm the trust anchors are the ones the policy names.",
                })
    else:
        components.append(_component(
            "verify-content-credentials", False, "not run",
            "No verifier was supplied; cryptographic questions cannot be answered."))
        for question in ("verified", "trusted"):
            unknowns.append({
                "question": question,
                "why": "No conforming verifier was supplied.",
                "next_step": "Re-run with --c2patool pointing at c2patool 0.20.0 or newer.",
            })

    # Supporting context: privacy exposure and text signals.
    try:
        privacy = privacy_mod.audit(path)
        result["privacy_risk"] = privacy["risk"]
        components.append(_component(
            "audit-metadata-privacy", True, "risk={0}".format(privacy["risk"]), privacy["reason"]))
    except (OSError, ValueError) as error:
        components.append(_component("audit-metadata-privacy", False, "failed", str(error)))

    head = core.read_head(path, 8192)
    if core.is_text_asset(path, head):
        stream = core.read_text_stream(path)
        signals = watermark_mod.analyse(
            stream["text"], str(path.resolve()), {"asset_path": str(path.resolve())},
            scan_info=stream)
        result["text_signals"] = {
            "status": signals["status"],
            "scan_complete": signals["scan_complete"],
            "did_not_run": signals["did_not_run_detectors"],
        }
        components.append(_component(
            "detect-text-watermark", True, "status={0}".format(signals["status"]), signals["reason"]))
        unknowns.append({
            "question": "text_watermark",
            "why": "Keyed model-level watermarks cannot be checked without the provider's key.",
            "next_step": "None available. Do not infer authorship from this.",
        })
    else:
        components.append(_component(
            "detect-text-watermark", False, "not applicable", "The asset is not text."))

    result["answers"] = {
        "located": located,
        "verified": verified,
        "trusted": trusted,
        "scan_complete": scan_complete,
    }
    result["unknowns"] = unknowns
    result["components"] = components
    return result


def exit_code_for(result: dict) -> int:
    answers = result["answers"]
    if answers["verified"] == "NO" or answers["trusted"] == "NO":
        return core.EXIT_CONCLUSIVE_BAD
    if "UNKNOWN" in (answers["located"], answers["verified"], answers["trusted"],
                     answers["scan_complete"]):
        return core.EXIT_INCONCLUSIVE
    return core.EXIT_CONCLUSIVE_GOOD


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset")
    parser.add_argument("--c2patool", help="c2patool executable or absolute path")
    parser.add_argument("--trust-anchors", help="PEM trust policy for the signer-trust question")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    try:
        result = audit(pathlib.Path(args.asset), args.c2patool, args.trust_anchors,
                       args.timeout, args.allow_network)
        print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code_for(result)
    except (OSError, ValueError) as error:
        failed = base_result(args.asset)
        failed["reason"] = str(error)
        print(json.dumps(failed, indent=2, sort_keys=True))
        return core.EXIT_INCONCLUSIVE


if __name__ == "__main__":
    sys.exit(main())
