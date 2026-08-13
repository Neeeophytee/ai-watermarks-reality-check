#!/usr/bin/env python3
"""Build a read-only provenance survival matrix for an original and derivatives.

Measures what a real publishing pipeline does to provenance. Reports observed
outcomes; never assigns intent.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import provenance_core as core  # noqa: E402

TOOL_NAME = "map-provenance-survival"


def _timestamp():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _unknown_observation(path=""):
    return {
        "path": str(path), "sha256": None, "bytes": None, "format": None,
        "c2pa_markers": [], "scan_complete": False,
        "manifest_presence": "UNKNOWN", "integrity": "UNKNOWN",
        "state": "UNKNOWN", "reason": "Analysis did not complete.",
        "manifest": core.manifest_summary(None),
    }


def base_result(original="") -> dict:
    """Stable schema-valid result used by CLI and MCP error branches."""
    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "original": _unknown_observation(original),
        "derivatives": [],
        "verifier": "UNAVAILABLE",
        "verifier_version": "UNAVAILABLE",
        "verifier_supported": None,
        "verifier_requested": False,
        "network_allowed": False,
        "summary": {
            "derivative_count": 0, "preserved_valid": 0,
            "lost_or_unavailable": 0, "unknown": 0,
        },
        "reproducibility": {
            "recorded_at": _timestamp(), "verifier": "UNAVAILABLE",
            "verifier_version": "UNAVAILABLE", "core_schema_version": core.SCHEMA_VERSION,
            "python": "{0}.{1}.{2}".format(*sys.version_info[:3]),
            "platform": sys.platform, "network_allowed": False,
            "command": " ".join(sys.argv),
            "note": "The requested analysis did not complete.",
        },
        "limitations": [
            "Without c2patool, structural markers establish only POSSIBLE presence.",
            "An operation label is caller-supplied metadata, not a verified description.",
            "LOST_OR_UNAVAILABLE describes an observation, not intent.",
            "Remote manifests require separately authorized network access.",
            "A different hash alone does not mean provenance failed; a derivative is expected to differ.",
        ],
        "reason": None,
    }


def inspect(path: pathlib.Path, tool, timeout: int, allow_network: bool) -> dict:
    if not path.exists() or not path.is_file():
        return {
            "path": str(path), "sha256": None, "bytes": None, "format": None,
            "c2pa_markers": [], "scan_complete": False,
            "manifest_presence": "UNKNOWN", "integrity": "UNKNOWN",
            "state": "UNKNOWN", "reason": "File is missing or unreadable.",
            "manifest": core.manifest_summary(None),
        }
    size = path.stat().st_size
    head = core.read_head(path)
    fmt = core.sniff_format(path, head)
    evidence = core.locate_c2pa_evidence(path, head, fmt)
    scan_complete = size <= core.SCAN_LIMIT
    presence = core.presence_from_evidence(evidence, scan_complete, fmt)

    result = {
        "path": str(path.resolve()),
        "sha256": core.sha256_file(path),
        "bytes": size,
        "format": fmt,
        "c2pa_markers": evidence["markers"],
        "scan_complete": scan_complete,
        "manifest_presence": presence,
        "integrity": "NOT_VERIFIED" if presence != "UNKNOWN" else "UNKNOWN",
        "state": (
            "POSSIBLE_NOT_VERIFIED" if evidence["markers"]
            else "NO_EVIDENCE_OBSERVED" if presence == "ABSENT"
            else "UNKNOWN"
        ),
        "reason": None,
        "manifest": core.manifest_summary(None),
    }
    if not tool:
        return result

    try:
        code, stdout, stderr = core.run_report(tool, path, timeout, allow_network)
    except core.ToolOutputTooLarge as error:
        result.update({"manifest_presence": "UNKNOWN", "integrity": "UNKNOWN",
                       "state": "UNKNOWN",
                       "reason": "Verifier output limit exceeded: {0}".format(error)})
        return result
    except (OSError, subprocess.TimeoutExpired) as error:
        result.update({"manifest_presence": "UNKNOWN", "integrity": "UNKNOWN",
                       "state": "UNKNOWN", "reason": str(error)})
        return result

    result["tool_exit_code"] = code
    result["stderr_summary"] = stderr.strip()[:1000]

    if core.is_no_manifest_failure(code, stderr):
        result.update({"manifest_presence": "ABSENT", "integrity": "NOT_VERIFIED",
                       "state": "NO_EVIDENCE_OBSERVED",
                       "reason": "The verifier reported no manifest."})
        return result

    report, parse_error = core.parse_tool_json(stdout)
    if parse_error is not None:
        result.update({"manifest_presence": "UNKNOWN", "integrity": "UNKNOWN", "state": "UNKNOWN",
                       "reason": "Verifier output could not be parsed: {0}".format(parse_error)})
        return result

    classified = core.classify(report, trust_checked=False, exit_code=code)
    if not classified["schema_recognized"] and classified["manifest_presence"] != "ABSENT":
        result.update({"manifest_presence": "UNKNOWN", "integrity": "UNKNOWN", "state": "UNKNOWN",
                       "reason": "Verifier output did not match the supported c2patool summary schema."})
        return result

    result["manifest"] = core.manifest_summary(report)
    result["validation_state"] = classified["validation_state"]
    result["success_codes"] = classified["success_codes"]
    result["failure_codes"] = classified["failure_codes"]
    result["manifest_presence"] = classified["manifest_presence"]
    result["integrity"] = classified["integrity"]
    if classified["integrity"] == "VALID":
        result["state"] = "PRESERVED_VALID"
    elif classified["integrity"] == "INVALID":
        result["state"] = "PRESENT_INVALID"
    elif classified["manifest_presence"] == "ABSENT":
        result["state"] = "NO_EVIDENCE_OBSERVED"
    else:
        result["state"] = "UNKNOWN"
        result["reason"] = "Positive validation evidence was incomplete or contradicted the tool exit status."
    return result


def derivative_state(baseline: dict, derivative: dict) -> str:
    if baseline.get("state") == "UNKNOWN" or derivative.get("state") == "UNKNOWN":
        return "UNKNOWN"
    if baseline.get("manifest_presence") not in ("PRESENT", "POSSIBLE"):
        return "NO_BASELINE_EVIDENCE"
    if derivative.get("integrity") == "VALID":
        return "PRESERVED_VALID"
    if derivative.get("integrity") == "INVALID":
        return "PRESENT_INVALID"
    if derivative.get("manifest_presence") == "POSSIBLE":
        return "POSSIBLE_NOT_VERIFIED"
    return "LOST_OR_UNAVAILABLE"


def parse_derivative(value: str):
    """Parse LABEL=PATH, or LABEL:OPERATION=PATH to record the transformation."""
    if "=" not in value:
        raise argparse.ArgumentTypeError("derivative must be LABEL=PATH or LABEL:OPERATION=PATH")
    label, path = value.split("=", 1)
    if not label.strip() or not path.strip():
        raise argparse.ArgumentTypeError("derivative must contain a non-empty label and path")
    label = label.strip()
    operation = None
    if ":" in label:
        label, operation = label.split(":", 1)
        label, operation = label.strip(), operation.strip() or None
    return label, pathlib.Path(path), operation


def build(original: pathlib.Path, derivatives, tool_arg, timeout: int, allow_network: bool) -> dict:
    tool = None
    version_text = "UNAVAILABLE"
    supported = None
    unavailable_reason = None

    if tool_arg:
        tool = core.resolve_tool(tool_arg)
        if not tool:
            unavailable_reason = "The explicitly requested c2patool executable is unavailable."
        else:
            probe = core.probe_tool(tool, timeout)
            version_text = probe["version_text"]
            supported = probe["supported"]
            if not probe["supported"]:
                unavailable_reason = probe["reason"]
                tool = None

    if unavailable_reason:
        unknown = _unknown_observation(original)
        unknown["reason"] = unavailable_reason
        baseline = dict(unknown)
        rows = []
        for label, path, operation in derivatives:
            row = dict(unknown)
            row.update({"path": str(path), "label": label, "operation": operation,
                        "survival": "UNKNOWN"})
            rows.append(row)
    else:
        baseline = inspect(original, tool, timeout, allow_network)
        rows = []
        for label, path, operation in derivatives:
            observed = inspect(path, tool, timeout, allow_network)
            observed["label"] = label
            observed["operation"] = operation
            observed["survival"] = derivative_state(baseline, observed)
            rows.append(observed)

    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "original": baseline,
        "derivatives": rows,
        "verifier": tool or "UNAVAILABLE",
        "verifier_version": version_text,
        "verifier_supported": supported,
        "verifier_requested": bool(tool_arg),
        "network_allowed": bool(allow_network),
        "summary": {
            "derivative_count": len(rows),
            "preserved_valid": sum(1 for r in rows if r.get("survival") == "PRESERVED_VALID"),
            "lost_or_unavailable": sum(1 for r in rows if r.get("survival") == "LOST_OR_UNAVAILABLE"),
            "unknown": sum(1 for r in rows if r.get("survival") == "UNKNOWN"),
        },
        "reproducibility": {
            "recorded_at": _timestamp(),
            "verifier": tool or "UNAVAILABLE",
            "verifier_version": version_text,
            "core_schema_version": core.SCHEMA_VERSION,
            "python": "{0}.{1}.{2}".format(*sys.version_info[:3]),
            "platform": sys.platform,
            "network_allowed": bool(allow_network),
            "command": " ".join(sys.argv),
            "note": (
                "Operations are recorded as supplied by the caller; this tool does not "
                "perform or infer transformations. Re-running requires the same inputs, "
                "the same verifier version, and the same transformation steps."
            ),
        },
        "limitations": [
            "Without c2patool, structural markers establish only POSSIBLE presence.",
            "An operation label is caller-supplied metadata, not a verified description.",
            "LOST_OR_UNAVAILABLE describes an observation, not intent.",
            "Remote manifests require separately authorized network access.",
            "A different hash alone does not mean provenance failed; a derivative is expected to differ.",
        ],
        "reason": None,
    }


def exit_code_for(result: dict) -> int:
    if result["original"].get("state") == "UNKNOWN":
        return core.EXIT_INCONCLUSIVE
    if any(row.get("survival") == "UNKNOWN" for row in result["derivatives"]):
        return core.EXIT_INCONCLUSIVE
    if result["summary"]["lost_or_unavailable"]:
        return core.EXIT_CONCLUSIVE_BAD
    return core.EXIT_CONCLUSIVE_GOOD


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", required=True, type=pathlib.Path)
    parser.add_argument("--derivative", action="append", default=[], type=parse_derivative,
                        metavar="LABEL[:OPERATION]=PATH",
                        help="A derivative and, optionally, the transformation that produced it")
    parser.add_argument("--c2patool", default=None, help="Optional c2patool executable or absolute path")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--allow-network", action="store_true", help="Allow remote-manifest retrieval")
    args = parser.parse_args()
    result = build(args.original, args.derivative, args.c2patool, args.timeout, args.allow_network)
    print(json.dumps(result, indent=2, sort_keys=True))
    return exit_code_for(result)


if __name__ == "__main__":
    sys.exit(main())
