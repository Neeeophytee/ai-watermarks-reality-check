#!/usr/bin/env python3
"""Run a live signed/unsigned/tampered smoke test with official c2patool assets."""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY_SCRIPT = ROOT / "skills/verify-content-credentials/scripts/verify_c2pa.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("live_verify_c2pa", VERIFY_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c2patool", required=True, type=pathlib.Path)
    parser.add_argument("--signed", required=True, type=pathlib.Path, help="Known signed sample, such as c2patool sample/C.jpg")
    parser.add_argument("--unsigned", required=True, type=pathlib.Path, help="Known unsigned sample, such as c2patool sample/image.jpg")
    parser.add_argument("--trust-anchors", type=pathlib.Path)
    args = parser.parse_args()
    verifier = load_verifier()
    signed = verifier.verify_asset(args.signed, str(args.c2patool), str(args.trust_anchors) if args.trust_anchors else None, 30)
    unsigned = verifier.verify_asset(args.unsigned, str(args.c2patool), None, 30)
    with tempfile.TemporaryDirectory(prefix="c2pa-tamper-test-") as directory:
        tampered_path = pathlib.Path(directory) / args.signed.name
        tampered = bytearray(args.signed.read_bytes())
        if len(tampered) < 2048:
            raise ValueError("Signed smoke-test asset is too small for a safe bounded mutation.")
        tampered[-1024] ^= 0x01
        tampered_path.write_bytes(tampered)
        tampered_result = verifier.verify_asset(tampered_path, str(args.c2patool), None, 30)
    checks = {
        "signed_valid": signed.get("integrity") == "VALID",
        "unsigned_absent": unsigned.get("manifest_presence") == "ABSENT" and unsigned.get("integrity") == "NOT_VERIFIED",
        "tampered_rejected": tampered_result.get("integrity") == "INVALID",
        "configured_signer_trusted": signed.get("signer_trust") == "TRUSTED" if args.trust_anchors else True,
    }
    print(json.dumps({
        "checks": checks,
        "passed": all(checks.values()),
        "signed": {key: signed.get(key) for key in ("manifest_presence", "integrity", "signer_trust", "verifier_version", "asset_sha256")},
        "unsigned": {key: unsigned.get(key) for key in ("manifest_presence", "integrity", "signer_trust", "asset_sha256")},
        "tampered": {key: tampered_result.get(key) for key in ("manifest_presence", "integrity", "signer_trust", "asset_sha256")},
    }, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
