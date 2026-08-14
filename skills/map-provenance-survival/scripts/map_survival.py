#!/usr/bin/env python3
"""Build a read-only provenance survival matrix for an original and derivatives.

Measures what a real publishing pipeline does to provenance. Reports observed
outcomes; never assigns intent.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import pathlib
import subprocess
import sys
from string import Template

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import provenance_core as core  # noqa: E402

TOOL_NAME = "map-provenance-survival"
TOOL_VERSION = "0.2.0"
REPORT_SUFFIXES = {
    ".html": "html",
    ".htm": "html",
    ".md": "markdown",
    ".markdown": "markdown",
}


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


def _limitations(verifier_available=False):
    items = []
    if verifier_available:
        items.append(
            "This workflow validates integrity but does not evaluate signer trust; "
            "use verify-content-credentials with an explicit trust policy."
        )
    else:
        items.append(
            "Without c2patool, structural markers establish only POSSIBLE presence."
        )
    items.extend([
        "An operation label is caller-supplied metadata, not a verified description.",
        "LOST_OR_UNAVAILABLE describes an observation, not intent.",
        "Remote manifests require separately authorized network access.",
        "A different hash alone does not mean provenance failed; a derivative is expected to differ.",
    ])
    return items


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
        "limitations": _limitations(False),
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


def _resolved(path: pathlib.Path):
    """Resolve a path for deduplication without requiring it to exist."""
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def derivatives_from_directories(original: pathlib.Path, directories, existing=None,
                                 excluded=None):
    """Expand derivative directories into deterministic, relative labels.

    Hidden directories and symlinks are skipped. Symlinks are deliberately not
    followed so a shareable batch cannot unexpectedly read outside the selected
    tree. Explicit derivatives win when the same file is also inside a directory.
    """
    rows = list(existing or [])
    labels = set()
    for row in rows:
        if row[0] in labels:
            raise ValueError("Duplicate derivative label: {0}".format(row[0]))
        labels.add(row[0])
    seen = {_resolved(original)}
    seen.update(_resolved(row[1]) for row in rows)
    seen.update(_resolved(path) for path in (excluded or []))

    roots = [pathlib.Path(path) for path in directories]
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("Derivative directory is missing or unreadable: {0}".format(root))

    multiple_roots = len(roots) > 1

    def walk_error(error):
        raise ValueError("Could not read derivative directory: {0}".format(error))

    for root in roots:
        prefix = root.name or "derivatives"
        for dirpath, dirnames, filenames in os.walk(
                str(root), followlinks=False, onerror=walk_error):
            dirnames[:] = sorted(
                name for name in dirnames
                if not name.startswith(".")
                and not (pathlib.Path(dirpath) / name).is_symlink()
            )
            base = pathlib.Path(dirpath)
            for filename in sorted(filenames):
                if filename.startswith("."):
                    continue
                path = base / filename
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = _resolved(path)
                if resolved in seen:
                    continue
                relative = path.relative_to(root).as_posix()
                label = "{0}/{1}".format(prefix, relative) if multiple_roots else relative
                if label in labels:
                    raise ValueError("Duplicate derivative label: {0}".format(label))
                labels.add(label)
                seen.add(resolved)
                rows.append((label, path, None))
    return rows


def _report_text(value):
    if value is None or value == "":
        return "-"
    return str(value)


def _markdown_cell(value):
    text = _report_text(value).replace("\r", " ").replace("\n", " ")
    text = html.escape(text, quote=False)
    for character in "\\`*[]()!|":
        text = text.replace(character, "\\" + character)
    return text


def _display_path(value, include_paths):
    text = _report_text(value)
    if include_paths or text == "-":
        return text
    return pathlib.Path(text).name or "(redacted)"


def _report_rows(result, include_paths):
    original = result["original"]
    rows = [{
        "asset": "Original",
        "source": _display_path(original.get("path"), include_paths),
        "operation": "baseline",
        "format": original.get("format"),
        "bytes": original.get("bytes"),
        "manifest": original.get("manifest_presence"),
        "integrity": original.get("integrity"),
        "outcome": original.get("state"),
        "sha256": original.get("sha256"),
        "reason": original.get("reason"),
    }]
    for derivative in result["derivatives"]:
        rows.append({
            "asset": derivative.get("label"),
            "source": _display_path(derivative.get("path"), include_paths),
            "operation": derivative.get("operation"),
            "format": derivative.get("format"),
            "bytes": derivative.get("bytes"),
            "manifest": derivative.get("manifest_presence"),
            "integrity": derivative.get("integrity"),
            "outcome": derivative.get("survival"),
            "sha256": derivative.get("sha256"),
            "reason": derivative.get("reason"),
        })
    return rows


def render_markdown(result: dict, include_paths=False) -> str:
    """Render a portable Markdown survival report without changing its evidence."""
    summary = result["summary"]
    repro = result["reproducibility"]
    verifier = _display_path(result.get("verifier"), include_paths)
    lines = [
        "# Provenance Survival Report",
        "",
        "> This report evaluates C2PA provenance survival only. It does not test proprietary pixel, audio, video, or keyed text watermarks. It never assigns AI authorship or intent.",
        "",
        "## Summary",
        "",
        "| Measure | Result |",
        "| --- | --- |",
        "| Recorded at | {0} |".format(_markdown_cell(repro.get("recorded_at"))),
        "| Tool version | {0} |".format(_markdown_cell(TOOL_VERSION)),
        "| Derivatives | {0} |".format(_markdown_cell(summary.get("derivative_count"))),
        "| Preserved and valid | {0} |".format(_markdown_cell(summary.get("preserved_valid"))),
        "| Lost or unavailable | {0} |".format(_markdown_cell(summary.get("lost_or_unavailable"))),
        "| Unknown | {0} |".format(_markdown_cell(summary.get("unknown"))),
        "| Verifier | {0} |".format(_markdown_cell(verifier)),
        "| Verifier version | {0} |".format(_markdown_cell(result.get("verifier_version"))),
        "| Network allowed | {0} |".format(_markdown_cell(result.get("network_allowed"))),
        "| Signer trust | NOT_CHECKED by this workflow |",
        "",
        "## Survival matrix",
        "",
        "| Asset | Source | Operation | Format | Bytes | Manifest | Integrity | Outcome | SHA-256 | Reason |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for row in _report_rows(result, include_paths):
        lines.append("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |".format(
            *[_markdown_cell(row[key]) for key in (
                "asset", "source", "operation", "format", "bytes", "manifest",
                "integrity", "outcome", "sha256", "reason")]))

    lines.extend([
        "",
        "## Reproducibility and interpretation",
        "",
        "- Absolute paths are {0}.".format(
            "included by explicit request" if include_paths else "redacted to filenames"),
        "- File hashes cover the complete files, not scan prefixes.",
        "- Operation labels are caller-supplied notes. The tool does not perform or infer transformations.",
        "- `LOST_OR_UNAVAILABLE` is an observed outcome. It does not prove deliberate removal.",
        "- `VALID` describes cryptographic integrity. Signer trust was not evaluated by this workflow.",
        "- Remote manifests were {0}.".format(
            "allowed" if result.get("network_allowed") else "not fetched unless already local"),
    ])
    if include_paths:
        lines.append("- Command: `{0}`".format(
            str(repro.get("command", "")).replace("`", "\\`")))
    else:
        lines.append("- The command is omitted from this shareable view because it may contain local paths; it remains in the JSON output.")
    if result.get("limitations"):
        lines.extend(["", "## Limitations", ""])
        lines.extend("- {0}".format(_markdown_cell(item)) for item in result["limitations"])
    return "\n".join(lines) + "\n"


def render_html(result: dict, include_paths=False) -> str:
    """Render a self-contained, script-free HTML survival report."""
    summary = result["summary"]
    repro = result["reproducibility"]
    rows = []
    for row in _report_rows(result, include_paths):
        cells = "".join("<td>{0}</td>".format(html.escape(_report_text(row[key]))) for key in (
            "asset", "source", "operation", "format", "bytes", "manifest",
            "integrity", "outcome", "sha256", "reason"))
        rows.append("<tr>{0}</tr>".format(cells))

    limitations = "".join("<li>{0}</li>".format(html.escape(str(item)))
                          for item in result.get("limitations", []))
    command = ""
    if include_paths:
        command = "<li><strong>Command:</strong> <code>{0}</code></li>".format(
            html.escape(str(repro.get("command", ""))))
    else:
        command = ("<li>The command is omitted from this shareable view because it may contain "
                   "local paths; it remains in the JSON output.</li>")
    verifier = _display_path(result.get("verifier"), include_paths)
    template = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Provenance Survival Report</title>
<style>
:root { color-scheme: light dark; --bg:#f5f7fa; --card:#fff; --ink:#172033; --muted:#596579; --line:#dbe1ea; --accent:#3157d5; --warn:#fff4cc; }
* { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
main { max-width:1180px; margin:0 auto; padding:40px 24px 64px; } h1 { margin:0 0 8px; font-size:clamp(28px,5vw,46px); letter-spacing:-.03em; } h2 { margin-top:36px; }
.eyebrow { color:var(--accent); font-weight:750; text-transform:uppercase; letter-spacing:.09em; font-size:12px; } .scope { background:var(--warn); color:#3c3100; border:1px solid #e8cf66; padding:14px 16px; border-radius:10px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; } .metric,.panel { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; } .metric span { display:block; color:var(--muted); font-size:13px; } .metric strong { display:block; margin-top:4px; font-size:20px; overflow-wrap:anywhere; }
.table-wrap { overflow:auto; background:var(--card); border:1px solid var(--line); border-radius:12px; } table { border-collapse:collapse; min-width:1100px; width:100%; } th,td { padding:11px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; } th { position:sticky; top:0; background:var(--card); font-size:12px; text-transform:uppercase; letter-spacing:.04em; } td:nth-child(9) { font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; } tr:last-child td { border-bottom:0; } code { overflow-wrap:anywhere; }
@media (prefers-color-scheme:dark) { :root { --bg:#0f1420; --card:#171e2c; --ink:#edf1f7; --muted:#aab4c6; --line:#303a4c; --accent:#91a8ff; --warn:#352d12; } .scope { color:#ffeaa0; border-color:#695923; } }
@media print { :root { --bg:#fff; --card:#fff; --ink:#000; --muted:#444; --line:#bbb; } main { max-width:none; padding:12px; } .table-wrap { overflow:visible; } table { min-width:0; font-size:9px; } th { position:static; } }
</style>
</head>
<body><main>
<div class="eyebrow">AI Watermarks Reality Check</div>
<h1>Provenance Survival Report</h1>
<p>Recorded ${recorded}</p>
<p class="scope"><strong>Scope:</strong> This report evaluates C2PA provenance survival only. It does not test proprietary pixel, audio, video, or keyed text watermarks. It never assigns AI authorship or intent.</p>
<h2>Summary</h2>
<div class="grid">
<div class="metric"><span>Derivatives</span><strong>${count}</strong></div>
<div class="metric"><span>Preserved and valid</span><strong>${preserved}</strong></div>
<div class="metric"><span>Lost or unavailable</span><strong>${lost}</strong></div>
<div class="metric"><span>Unknown</span><strong>${unknown}</strong></div>
<div class="metric"><span>Tool version</span><strong>${tool_version}</strong></div>
<div class="metric"><span>Verifier</span><strong>${verifier}</strong></div>
<div class="metric"><span>Verifier version</span><strong>${version}</strong></div>
</div>
<h2>Survival matrix</h2>
<div class="table-wrap"><table>
<thead><tr><th>Asset</th><th>Source</th><th>Operation</th><th>Format</th><th>Bytes</th><th>Manifest</th><th>Integrity</th><th>Outcome</th><th>SHA-256</th><th>Reason</th></tr></thead>
<tbody>${rows}</tbody></table></div>
<h2>Reproducibility and interpretation</h2>
<div class="panel"><ul>
<li>Absolute paths are ${path_policy}.</li>
<li>File hashes cover the complete files, not scan prefixes.</li>
<li>Operation labels are caller-supplied notes. The tool does not perform or infer transformations.</li>
<li><code>LOST_OR_UNAVAILABLE</code> is an observed outcome. It does not prove deliberate removal.</li>
<li><code>VALID</code> describes cryptographic integrity. Signer trust was not evaluated by this workflow.</li>
<li>Remote manifests were ${network}.</li>
${command}
</ul></div>
<h2>Limitations</h2><div class="panel"><ul>${limitations}</ul></div>
</main></body></html>
""")
    return template.substitute(
        recorded=html.escape(_report_text(repro.get("recorded_at"))),
        count=html.escape(_report_text(summary.get("derivative_count"))),
        preserved=html.escape(_report_text(summary.get("preserved_valid"))),
        lost=html.escape(_report_text(summary.get("lost_or_unavailable"))),
        unknown=html.escape(_report_text(summary.get("unknown"))),
        tool_version=html.escape(TOOL_VERSION),
        verifier=html.escape(verifier),
        version=html.escape(_report_text(result.get("verifier_version"))),
        rows="".join(rows),
        path_policy=("included by explicit request" if include_paths else "redacted to filenames"),
        network=("allowed" if result.get("network_allowed") else "not fetched unless already local"),
        command=command,
        limitations=limitations,
    )


def write_report(path: pathlib.Path, result: dict, include_paths=False):
    """Write a new report without overwriting an existing file."""
    path = pathlib.Path(path)
    report_format = REPORT_SUFFIXES.get(path.suffix.lower())
    if not report_format:
        raise ValueError("Report path must end in .html, .htm, .md, or .markdown")
    if not path.parent.is_dir():
        raise ValueError("Report parent directory does not exist: {0}".format(path.parent))
    renderer = render_html if report_format == "html" else render_markdown
    try:
        document = renderer(result, include_paths=include_paths)
    except Exception as error:  # keep an ancillary report failure structured
        raise ValueError("Report rendering failed: {0}".format(error))
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(document)
    except FileExistsError:
        raise ValueError("Refusing to overwrite existing report: {0}".format(path))
    return report_format


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
        "limitations": _limitations(bool(tool)),
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
    parser.add_argument("--version", action="version",
                        version="%(prog)s {0}".format(TOOL_VERSION))
    parser.add_argument("--original", required=True, type=pathlib.Path)
    parser.add_argument("--derivative", action="append", default=[], type=parse_derivative,
                        metavar="LABEL[:OPERATION]=PATH",
                        help="A derivative and, optionally, the transformation that produced it")
    parser.add_argument("--derivatives-dir", action="append", default=[], type=pathlib.Path,
                        metavar="DIRECTORY",
                        help="Recursively add visible, non-symlink files as derivatives")
    parser.add_argument("--report", type=pathlib.Path, default=None,
                        help="Write a new self-contained .html or .md report; never overwrites")
    parser.add_argument("--include-paths", action="store_true",
                        help="Include absolute source paths and the command in the report")
    parser.add_argument("--c2patool", default=None, help="Optional c2patool executable or absolute path")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--allow-network", action="store_true", help="Allow remote-manifest retrieval")
    args = parser.parse_args()
    try:
        derivatives = derivatives_from_directories(
            args.original,
            args.derivatives_dir,
            existing=args.derivative,
            excluded=[args.report] if args.report else [],
        )
    except ValueError as error:
        result = base_result(args.original)
        result["reason"] = str(error)
        result["original"]["reason"] = str(error)
        print(json.dumps(result, indent=2, sort_keys=True))
        return core.EXIT_INCONCLUSIVE

    result = build(args.original, derivatives, args.c2patool, args.timeout, args.allow_network)
    report_error = None
    if args.report:
        try:
            write_report(args.report, result, include_paths=args.include_paths)
        except (OSError, ValueError) as error:
            report_error = "Report was not written: {0}".format(error)
            result["reason"] = report_error
    print(json.dumps(result, indent=2, sort_keys=True))
    if report_error:
        print(report_error, file=sys.stderr)
        return core.EXIT_INCONCLUSIVE
    return exit_code_for(result)


if __name__ == "__main__":
    sys.exit(main())
