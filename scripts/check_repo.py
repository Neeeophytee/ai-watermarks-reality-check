#!/usr/bin/env python3
"""Dependency-free repository structure, metadata, and contract validation."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
SCHEMAS = ROOT / "schemas"
NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

EXPECTED_SKILLS = {
    "inspect-content-provenance",
    "verify-content-credentials",
    "map-provenance-survival",
    "audit-metadata-privacy",
    "check-ai-transparency",
    "detect-text-watermark",
    "audit-provenance",
}

# Language that must never appear in skill guidance.
FORBIDDEN_PHRASES = (
    "no watermark found",
    "not ai generated",
    "proves human",
    "human-written",
    "guaranteed undetectable",
)


def frontmatter(text: str) -> dict:
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        return {}
    block = text.split("\n---\n", 1)[0][4:]
    values = {}
    for line in block.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values


def main() -> int:
    errors = []
    skill_dirs = sorted(path for path in SKILLS.iterdir() if path.is_dir())
    names = {path.name for path in skill_dirs}
    if names != EXPECTED_SKILLS:
        errors.append("Skill set mismatch. Missing: {0}. Unexpected: {1}".format(
            sorted(EXPECTED_SKILLS - names) or "none", sorted(names - EXPECTED_SKILLS) or "none"))

    for skill in skill_dirs:
        skill_file = skill / "SKILL.md"
        yaml_file = skill / "agents" / "openai.yaml"
        if not skill_file.exists():
            errors.append("{0}: missing SKILL.md".format(skill.name))
            continue
        text = skill_file.read_text(encoding="utf-8")
        metadata = frontmatter(text)
        if metadata.get("name") != skill.name or not NAME.fullmatch(skill.name) or len(skill.name) > 64:
            errors.append("{0}: invalid frontmatter name".format(skill.name))
        description = metadata.get("description", "")
        if len(description) < 40 or len(description) > 1024 or "Use when" not in description:
            errors.append("{0}: description must explain what and when".format(skill.name))
        if "TODO" in text:
            errors.append("{0}: unresolved TODO".format(skill.name))

        lowered = text.lower()
        for phrase in FORBIDDEN_PHRASES:
            # Allowed only when explicitly framed as language to avoid.
            if phrase in lowered and "never" not in lowered and "not " not in lowered:
                errors.append("{0}: overclaiming phrase '{1}'".format(skill.name, phrase))

        if "relative to this skill's directory" not in text:
            errors.append("{0}: SKILL.md must state how to resolve script paths".format(skill.name))

        if not yaml_file.exists():
            errors.append("{0}: missing agents/openai.yaml".format(skill.name))
        else:
            yaml_text = yaml_file.read_text(encoding="utf-8")
            if "${0}".format(skill.name) not in yaml_text:
                errors.append("{0}: default_prompt must mention ${0}".format(skill.name))
            for key in ("interface:", "display_name:", "short_description:", "default_prompt:"):
                if key not in yaml_text:
                    errors.append("{0}: agents/openai.yaml missing {1}".format(skill.name, key))

        vendored = skill / "scripts" / "provenance_core.py"
        if not vendored.exists():
            errors.append("{0}: missing vendored provenance_core.py".format(skill.name))

        schema_file = SCHEMAS / "{0}.json".format(skill.name)
        if not schema_file.exists():
            errors.append("{0}: missing schemas/{0}.json".format(skill.name))

        scripts = sorted(
            path for path in (skill / "scripts").glob("*.py")
            if path.name != "provenance_core.py"
        )
        if not scripts:
            errors.append("{0}: no entrypoint script".format(skill.name))
        for script in scripts:
            completed = subprocess.run(
                [sys.executable, str(script), "--help"], check=False, capture_output=True, text=True
            )
            if completed.returncode != 0:
                errors.append("{0}: {1} --help failed".format(skill.name, script.name))

    # Vendored copies must match the source of truth.
    sync = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_shared.py"), "--check"],
        check=False, capture_output=True, text=True,
    )
    if sync.returncode != 0:
        errors.append("vendored provenance_core.py copies are out of sync: {0}".format(sync.stdout.strip()))

    # Schemas must parse and use only implemented keywords.
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import validate_schema
        unsupported = validate_schema.unsupported_keywords()
        if unsupported:
            errors.append("schemas use unimplemented keywords: {0}".format(sorted(unsupported)))
    except Exception as error:  # noqa: BLE001
        errors.append("schema validator failed to load: {0}".format(error))

    for schema_file in sorted(SCHEMAS.glob("*.json")):
        try:
            json.loads(schema_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            errors.append("{0}: invalid JSON ({1})".format(schema_file.name, error))

    # The MCP server must expose exactly one tool per skill.
    try:
        sys.path.insert(0, str(ROOT / "mcp"))
        import importlib.util
        spec = importlib.util.spec_from_file_location("mcp_server_check", ROOT / "mcp" / "server.py")
        server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server)
        exposed = {tool["name"] for tool in server.TOOLS}
        expected = {name.replace("-", "_") for name in EXPECTED_SKILLS}
        if exposed != expected:
            errors.append("MCP tools do not match skills. Missing: {0}. Unexpected: {1}".format(
                sorted(expected - exposed) or "none", sorted(exposed - expected) or "none"))
    except Exception as error:  # noqa: BLE001
        errors.append("MCP server failed to load: {0}".format(error))

    if errors:
        print("Repository validation failed:")
        for error in errors:
            print("- {0}".format(error))
        return 1
    print("Repository validation passed: {0} skills, schemas, vendored core, MCP tools, and entrypoints OK.".format(
        len(skill_dirs)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
