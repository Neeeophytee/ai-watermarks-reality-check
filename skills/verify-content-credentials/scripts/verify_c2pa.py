#!/usr/bin/env python3
"""Wrap c2patool and classify integrity separately from signer trust.

Every return path emits the same top-level field set, so an orchestrating agent
can parse one schema regardless of which branch was taken.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import provenance_core as core  # noqa: E402

TOOL_NAME = "verify-content-credentials"


def base_result(asset: str = None, asset_sha256: str = None) -> dict:
    """The stable output contract. Every field exists on every path."""
    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": "live-verification",
        "asset": asset,
        "asset_sha256": asset_sha256,
        "verifier": None,
        "verifier_version": None,
        "verifier_supported": None,
        "network_allowed": False,
        "manifest_presence": "UNKNOWN",
        "integrity": "UNKNOWN",
        "signer_trust": "UNKNOWN",
        "validation_state": None,
        "success_codes": [],
        "failure_codes": [],
        "schema_recognized": False,
        "manifest": core.manifest_summary(None),
        "trust_anchors": None,
        "trust_exit_code": None,
        "trust_validation_state": None,
        "trust_success_codes": [],
        "trust_failure_codes": [],
        "tool_exit_code": None,
        "stderr_summary": "",
        "reason": None,
        "limitations": [
            "A valid signature is not a trusted signer; the two states are independent.",
            "A missing or unsupported verifier is never evidence that a manifest is absent.",
            "Remote manifests are not retrieved unless network access is explicitly allowed.",
        ],
    }


def verify_asset(path: pathlib.Path, tool_arg: str, trust_anchors: str = None,
                 timeout: int = 30, allow_network: bool = False) -> dict:
    core.require_file(path)
    result = base_result(str(path.resolve()), core.sha256_file(path))
    result["network_allowed"] = bool(allow_network)
    result["trust_anchors"] = trust_anchors

    tool = core.resolve_tool(tool_arg)
    if not tool:
        result["reason"] = (
            "c2patool is unavailable; absence of a verifier is not absence of a manifest."
        )
        return result
    result["verifier"] = pathlib.Path(tool).name

    probe = core.probe_tool(tool, timeout)
    result["verifier_version"] = probe["version_text"]
    result["verifier_supported"] = probe["supported"]
    if not probe["supported"]:
        result["reason"] = probe["reason"]
        return result

    import urllib.parse
    if trust_anchors and urllib.parse.urlparse(trust_anchors).scheme in ("http", "https") and not allow_network:
        result["reason"] = "A remote trust-anchor URL requires --allow-network."
        return result

    try:
        code, stdout, stderr = core.run_report(tool, path, timeout, allow_network)
    except core.ToolOutputTooLarge as error:
        result["reason"] = (
            "Verifier output limit exceeded: {0} Truncated output is never classified "
            "as evidence.".format(error))
        return result
    except (OSError, subprocess.TimeoutExpired) as error:
        result["reason"] = "c2patool failed or timed out: {0}".format(error)
        return result

    result["tool_exit_code"] = code
    result["stderr_summary"] = stderr.strip()[:1000]

    if core.is_no_manifest_failure(code, stderr):
        result.update({
            "manifest_presence": "ABSENT",
            "integrity": "NOT_VERIFIED",
            "signer_trust": "NOT_CHECKED",
            "reason": "The verifier reported no manifest in this asset.",
        })
        return result

    report, parse_error = core.parse_tool_json(stdout)
    if parse_error is not None:
        result["reason"] = "Could not classify c2patool output: {0}".format(parse_error)
        return result

    classified = core.classify(report, trust_checked=False, exit_code=code)
    result.update(classified)
    result["manifest"] = core.manifest_summary(report)
    if code != 0 and classified["integrity"] == "VALID":
        result.update({
            "integrity": "UNKNOWN",
            "reason": "c2patool returned a nonzero status despite a valid-looking report.",
        })
    elif classified["integrity"] == "UNKNOWN" and not classified["schema_recognized"]:
        result["reason"] = (
            "The verifier returned JSON that does not match the supported c2patool "
            "summary schema (validation_state plus validation_results.activeManifest). "
            "Integrity cannot be established from it."
        )

    if trust_anchors and result["manifest_presence"] == "PRESENT":
        try:
            trust_code, trust_stdout, trust_stderr = core.run_report(
                tool, path, timeout, allow_network, trust_anchors=trust_anchors
            )
            result["trust_exit_code"] = trust_code
            trust_report, trust_parse_error = core.parse_tool_json(trust_stdout)
            if trust_parse_error is not None:
                raise ValueError(trust_parse_error)
            trust_classified = core.classify(trust_report, trust_checked=True, exit_code=trust_code)
            result["trust_validation_state"] = trust_classified["validation_state"]
            result["trust_success_codes"] = trust_classified["success_codes"]
            result["trust_failure_codes"] = trust_classified["failure_codes"]
            result["signer_trust"] = trust_classified["signer_trust"] if trust_code == 0 else "UNKNOWN"
        except (OSError, subprocess.TimeoutExpired, ValueError,
                json.JSONDecodeError, core.ToolOutputTooLarge) as error:
            result["signer_trust"] = "UNKNOWN"
            result["reason"] = "Trust evaluation failed: {0}".format(error)

    return result


def classify_captured(report_path: pathlib.Path, asset_sha256: str = None) -> dict:
    """Review captured verifier JSON without treating it as proof."""
    with report_path.open(encoding="utf-8") as handle:
        report = json.load(handle)
    reported = core.classify(report, trust_checked=False, exit_code=0)
    result = base_result(None, asset_sha256)
    result.update({
        "mode": "captured-report",
        "manifest_presence": reported["manifest_presence"],
        "integrity": "NOT_VERIFIED",
        "signer_trust": "NOT_CHECKED",
        "manifest": core.manifest_summary(report),
        "reported_result": reported,
        "reason": "Captured JSON is informational only.",
        "limitations": [
            "Captured JSON cannot establish that a verifier ran or that the report belongs to the stated asset.",
            "Use live verification for a cryptographic VALID result.",
        ],
    })
    return result


def exit_code_for(result: dict) -> int:
    if result.get("mode") == "captured-report":
        return core.EXIT_INCONCLUSIVE
    integrity = result.get("integrity")
    if integrity == "VALID":
        return core.EXIT_CONCLUSIVE_GOOD
    if integrity in ("INVALID", "NOT_VERIFIED"):
        return core.EXIT_CONCLUSIVE_BAD
    return core.EXIT_INCONCLUSIVE


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset", nargs="?", help="Asset to verify")
    parser.add_argument("--c2patool", default="c2patool", help="c2patool executable or absolute path")
    parser.add_argument("--trust-anchors", help="Reviewed PEM file or URL for explicit trust evaluation")
    parser.add_argument("--allow-network", action="store_true", help="Allow remote manifests and URL trust anchors")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--report-json", type=pathlib.Path, help="Review captured c2patool JSON without trusting it")
    parser.add_argument("--asset-sha256", help="Asset hash associated with a captured report")
    args = parser.parse_args()
    try:
        if args.report_json:
            result = classify_captured(args.report_json, args.asset_sha256)
        elif args.asset:
            result = verify_asset(
                pathlib.Path(args.asset), args.c2patool, args.trust_anchors,
                args.timeout, args.allow_network,
            )
        else:
            parser.error("provide an asset or --report-json")
        print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code_for(result)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        failed = base_result()
        failed["reason"] = str(error)
        print(json.dumps(failed, indent=2, sort_keys=True))
        return core.EXIT_INCONCLUSIVE


if __name__ == "__main__":
    sys.exit(main())
