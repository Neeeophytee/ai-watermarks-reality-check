#!/usr/bin/env python3
"""Vendor shared/provenance_core.py into every skill's scripts directory.

Each skill folder must stay independently copyable, so the shared module is
duplicated rather than imported across directories. This script is the only
supported way to update those copies; `check_repo.py` fails if they drift.

Usage:
    python3 scripts/sync_shared.py          # write copies
    python3 scripts/sync_shared.py --check  # verify copies match (CI)
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "shared" / "provenance_core.py"
SKILLS = ROOT / "skills"
VENDORED_NAME = "provenance_core.py"

BANNER = (
    "# ---------------------------------------------------------------------\n"
    "# VENDORED COPY - DO NOT EDIT.\n"
    "# Source of truth: shared/provenance_core.py\n"
    "# Regenerate with: python3 scripts/sync_shared.py\n"
    "# ---------------------------------------------------------------------\n"
)


def targets() -> list:
    found = []
    for skill in sorted(path for path in SKILLS.iterdir() if path.is_dir()):
        scripts = skill / "scripts"
        if scripts.is_dir():
            found.append(scripts / VENDORED_NAME)
    return found


def rendered() -> str:
    body = SOURCE.read_text(encoding="utf-8")
    marker = '"""'
    first = body.index(marker)
    second = body.index(marker, first + 3) + 3
    return body[:second] + "\n\n" + BANNER + body[second:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify copies instead of writing them")
    args = parser.parse_args()

    if not SOURCE.exists():
        print("Missing source module: {0}".format(SOURCE))
        return 1

    payload = rendered()
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    drifted = []
    for target in targets():
        if args.check:
            if not target.exists():
                drifted.append("{0}: missing".format(target.relative_to(ROOT)))
                continue
            actual = hashlib.sha256(target.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
            if actual != digest:
                drifted.append("{0}: out of date".format(target.relative_to(ROOT)))
        else:
            target.write_text(payload, encoding="utf-8")

    if args.check:
        if drifted:
            print("Vendored provenance_core.py copies are out of sync:")
            for item in drifted:
                print("- {0}".format(item))
            print("Run: python3 scripts/sync_shared.py")
            return 1
        print("Vendored copies match shared/provenance_core.py ({0} skills).".format(len(targets())))
        return 0

    print("Synced provenance_core.py into {0} skills.".format(len(targets())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
