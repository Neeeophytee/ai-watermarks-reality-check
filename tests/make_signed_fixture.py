#!/usr/bin/env python3
"""Generate a genuinely signed C2PA fixture using a certificate we control.

Produces, into `tests/fixtures/signed/` (gitignored):

    ca.pem            our test root
    chain.pem         signer + root, for c2patool
    signer_pkcs8.key  signing key (generated here, never committed)
    signed.jpg        a real, cryptographically signed asset
    tampered.jpg      the same asset with one flipped byte

This removes the test suite's dependence on contentauth's bundled samples for
the trust story: the trust anchor is ours, so `signer_trust: TRUSTED` is
demonstrated against a chain this repository created.

Nothing secret is committed. The key is generated on each run.

Requires `openssl` and a `c2patool` whose signing path works. Exits 3 (skip)
when either is unavailable, so callers can treat it as optional.

Usage:
    python3 tests/make_signed_fixture.py [--c2patool PATH] [--base IMAGE]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "fixtures" / "signed"

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_SKIP = 3

SIGNER_EXT = """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,emailProtection
"""

MANIFEST = {
    "claim_version": 2,
    "claim_generator_info": [
        {"name": "ai-watermarks-reality-check fixtures", "version": "0.1.0"}
    ],
    "title": "signed.jpg",
    "assertions": [
        {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created"}]}}
    ],
}


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, **kwargs)


def make_certificates() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ext.cnf").write_text(SIGNER_EXT, encoding="utf-8")

    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
         "-out", str(OUT / "ca.key")], check=True)
    run(["openssl", "req", "-new", "-x509", "-key", str(OUT / "ca.key"),
         "-out", str(OUT / "ca.pem"), "-days", "3650",
         "-subj", "/C=EE/O=AI Watermarks Reality Check/CN=Fixture Test Root CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True)

    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
         "-out", str(OUT / "signer.key")], check=True)
    run(["openssl", "req", "-new", "-key", str(OUT / "signer.key"),
         "-out", str(OUT / "signer.csr"),
         "-subj", "/C=EE/O=AI Watermarks Reality Check/CN=Fixture Signer"], check=True)
    run(["openssl", "x509", "-req", "-in", str(OUT / "signer.csr"),
         "-CA", str(OUT / "ca.pem"), "-CAkey", str(OUT / "ca.key"), "-CAcreateserial",
         "-out", str(OUT / "signer.pem"), "-days", "3650",
         "-extfile", str(OUT / "ext.cnf")], check=True)

    # c2pa-rs requires PKCS#8; `openssl ecparam` emits SEC1.
    run(["openssl", "pkcs8", "-topk8", "-nocrypt",
         "-in", str(OUT / "signer.key"), "-out", str(OUT / "signer_pkcs8.key")], check=True)

    chain = (OUT / "signer.pem").read_text(encoding="utf-8") + (OUT / "ca.pem").read_text(encoding="utf-8")
    (OUT / "chain.pem").write_text(chain, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c2patool", default="c2patool")
    parser.add_argument("--base", type=pathlib.Path,
                        default=ROOT / "tests" / "fixtures" / "jpeg_clean.jpg")
    args = parser.parse_args()

    if not shutil.which("openssl"):
        print("SKIP: openssl is not available.")
        return EXIT_SKIP
    tool = shutil.which(args.c2patool) or (
        args.c2patool if pathlib.Path(args.c2patool).is_file() else None)
    if not tool:
        print("SKIP: c2patool is not available.")
        return EXIT_SKIP
    if not args.base.exists():
        print("SKIP: base image {0} is missing; run tests/make_fixtures.py first.".format(args.base))
        return EXIT_SKIP

    make_certificates()
    (OUT / "manifest.json").write_text(json.dumps(MANIFEST, indent=2), encoding="utf-8")

    signed = OUT / "signed.jpg"
    completed = run(
        [tool, str(args.base), "-m", str(OUT / "manifest.json"), "-o", str(signed), "-f"],
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "C2PA_PRIVATE_KEY": str(OUT / "signer_pkcs8.key"),
            "C2PA_SIGN_CERT": str(OUT / "chain.pem"),
        },
    )
    if completed.returncode != 0 or not signed.exists():
        message = (completed.stderr or completed.stdout).strip()
        # The universal-apple-darwin build of c2patool 0.27.11 fails to decode
        # any signing certificate, including its own bundled sample. Treat an
        # environment that cannot sign as a skip, not a failure.
        print("SKIP: c2patool could not sign in this environment.")
        print("  {0}".format(message.splitlines()[0] if message else "no diagnostic"))
        return EXIT_SKIP

    tampered = OUT / "tampered.jpg"
    data = bytearray(signed.read_bytes())
    if len(data) < 2048:
        print("FAIL: signed asset is too small for a safe bounded mutation.")
        return EXIT_FAIL
    data[-1024] ^= 0x01
    tampered.write_bytes(bytes(data))

    print("Signed fixture written to {0}".format(OUT))
    for name in ("signed.jpg", "tampered.jpg", "chain.pem", "ca.pem"):
        path = OUT / name
        print("  {0:<18} {1} bytes".format(name, path.stat().st_size))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
