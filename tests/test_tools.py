"""Behavioural tests over real binary fixtures and, when present, real c2patool."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "shared"))

import provenance_core as core  # noqa: E402
import validate_schema  # noqa: E402


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


inspect_mod = load("t_inspect_file", "skills/inspect-content-provenance/scripts/inspect_file.py")
verify_mod = load("t_verify_c2pa", "skills/verify-content-credentials/scripts/verify_c2pa.py")
survival_mod = load("t_map_survival", "skills/map-provenance-survival/scripts/map_survival.py")
privacy_mod = load("t_audit_metadata", "skills/audit-metadata-privacy/scripts/audit_metadata.py")
transparency_mod = load("t_check_transparency", "skills/check-ai-transparency/scripts/check_transparency.py")
watermark_mod = load("t_detect_watermark", "skills/detect-text-watermark/scripts/detect_text_watermark.py")
frontdoor_mod = load("t_audit_provenance", "skills/audit-provenance/scripts/audit_provenance.py")
mcp_server = load("t_mcp_server", "mcp/server.py")
signed_fixture_mod = load("t_make_signed_fixture", "tests/make_signed_fixture.py")


def ensure_fixtures():
    if not (FIXTURES / "png_clean.png").exists():
        subprocess.run([sys.executable, str(ROOT / "tests" / "make_fixtures.py")], check=True,
                       capture_output=True)


ensure_fixtures()


def real_c2patool():
    """Return a path to a real c2patool if one is available, else None."""
    env = os.environ.get("C2PATOOL")
    if env and pathlib.Path(env).is_file():
        return env
    bundled = ROOT / ".tools" / "c2patool" / "c2patool"
    if bundled.is_file():
        return str(bundled)
    return shutil.which("c2patool")


def sample_dir():
    for candidate in (ROOT / ".tools" / "c2patool" / "sample",
                      pathlib.Path(os.environ.get("C2PA_SAMPLES", "/nonexistent"))):
        if candidate.is_dir() and (candidate / "C.jpg").exists():
            return candidate
    return None


TOOL = real_c2patool()
SAMPLES = sample_dir()
LIVE = TOOL is not None and SAMPLES is not None

# A fixture signed by a certificate this repository generated. Produced by
# tests/make_signed_fixture.py where c2patool's signing path works.
SIGNED_DIR = FIXTURES / "signed"
SELF_SIGNED = (
    TOOL is not None
    and (SIGNED_DIR / "signed.jpg").exists()
    and (SIGNED_DIR / "ca.pem").exists()
)


def c2pa_report(state="Valid", failures=None, extra_success=None):
    success = [
        {"code": "claimSignature.validated"},
        {"code": "claimSignature.insideValidity"},
        {"code": "assertion.dataHash.match"},
    ]
    success.extend(extra_success or [])
    return {
        "active_manifest": "urn:test",
        "manifests": {"urn:test": {"signature_info": {"alg": "Ps256"},
                                   "claim_generator": "test/1.0",
                                   "assertions": [{"label": "c2pa.actions.v2",
                                                   "data": {"actions": [{"action": "c2pa.created"}]}}]}},
        "validation_state": state,
        "validation_results": {
            "activeManifest": {"success": success, "informational": [], "failure": failures or []}
        },
    }


# ---------------------------------------------------------------------------
# D1: container-aware detection
# ---------------------------------------------------------------------------

class ContainerAwareDetectionTests(unittest.TestCase):
    def test_document_mentioning_c2pa_is_not_evidence(self):
        result = inspect_mod.inspect_path(FIXTURES / "text_mentions_c2pa.md")
        self.assertEqual(result["manifest_presence"], "ABSENT")
        self.assertEqual(result["c2pa_markers"], [])
        self.assertIn("c2pa", result["c2pa_mentions"])
        self.assertNotIn("Run verify-content-credentials", result["recommended_next_step"])

    def test_repository_sources_file_is_not_flagged(self):
        result = inspect_mod.inspect_path(ROOT / "SOURCES.md")
        self.assertEqual(result["manifest_presence"], "ABSENT")

    def test_png_cabx_chunk_is_structural(self):
        result = inspect_mod.inspect_path(FIXTURES / "png_c2pa_cabx.png")
        self.assertEqual(result["manifest_presence"], "POSSIBLE")
        self.assertEqual(result["c2pa_markers"][0]["confidence"], "STRUCTURAL")

    def test_jpeg_app11_jumbf_is_structural(self):
        result = inspect_mod.inspect_path(FIXTURES / "jpeg_c2pa_app11.jpg")
        self.assertEqual(result["manifest_presence"], "POSSIBLE")
        self.assertTrue(any(m["confidence"] == "STRUCTURAL" for m in result["c2pa_markers"]))

    def test_webp_and_bmff_c2pa_are_structural(self):
        for name in ("webp_c2pa.webp", "mp4_c2pa.mp4"):
            result = inspect_mod.inspect_path(FIXTURES / name)
            self.assertEqual(result["manifest_presence"], "POSSIBLE", name)
            self.assertEqual(result["c2pa_markers"][0]["confidence"], "STRUCTURAL", name)

    def test_clean_containers_are_absent(self):
        """ABSENT only for formats whose C2PA carriers are all checked."""
        for name in ("png_clean.png", "jpeg_clean.jpg", "webp_clean.webp",
                     "gif_clean.gif", "tiff_clean.tif", "html_clean.html", "text_clean.txt"):
            result = inspect_mod.inspect_path(FIXTURES / name)
            self.assertEqual(result["manifest_presence"], "ABSENT", name)

    def test_partially_inspectable_formats_never_say_absent(self):
        """Fail closed: a recognised container we cannot walk exhaustively is UNKNOWN."""
        for name in ("mp4_clean.mp4", "doc_meta.pdf", "doc_meta.docx"):
            result = inspect_mod.inspect_path(FIXTURES / name)
            self.assertEqual(result["manifest_presence"], "UNKNOWN", name)
            self.assertTrue(result["reason"], name)

    def test_spec_carriers_are_located(self):
        """C2PA 2.4 carriers: TIFF tag, GIF extension, PDF /AF, HTML, text wrapper."""
        for name in ("tiff_c2pa_one_ifd.tif", "gif_c2pa.gif", "pdf_c2pa_af.pdf",
                     "html_c2pa_script.html", "html_c2pa_link.html",
                     "text_c2pa_wrapper.txt", "text_c2pa_structured.md",
                     "text_c2pa_frontmatter.md", "text_c2pa_data_uri.md"):
            result = inspect_mod.inspect_path(FIXTURES / name)
            self.assertEqual(result["manifest_presence"], "POSSIBLE", name)
            self.assertTrue(result["c2pa_markers"], name)

    def test_c2pa_text_manifest_is_not_a_covert_channel(self):
        """A standards-compliant text manifest must not be reported as suspicious."""
        text = (FIXTURES / "text_c2pa_wrapper.txt").read_text(encoding="utf-8")
        scan = core.scan_covert_channels(text)
        self.assertEqual(scan["findings"], [])
        self.assertIsNotNone(scan["c2pa_text_manifest"])
        self.assertTrue(scan["c2pa_text_manifest"]["magic_confirmed"])

    def test_inspection_never_asserts_present_or_valid(self):
        for name in ("png_c2pa_cabx.png", "jpeg_c2pa_app11.jpg"):
            result = inspect_mod.inspect_path(FIXTURES / name)
            self.assertNotEqual(result["manifest_presence"], "PRESENT")
            self.assertEqual(result["integrity"], "NOT_VERIFIED")

    def test_incomplete_scan_is_unknown(self):
        original = core.SCAN_LIMIT
        core.SCAN_LIMIT = 8
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "large.bin"
                path.write_bytes(b"12345678" + b"x" * 100)
                result = inspect_mod.inspect_path(path)
        finally:
            core.SCAN_LIMIT = original
        self.assertEqual(result["manifest_presence"], "UNKNOWN")
        self.assertFalse(result["scan_complete"])


# ---------------------------------------------------------------------------
# D3: text applicability
# ---------------------------------------------------------------------------

class TextApplicabilityTests(unittest.TestCase):
    def test_markdown_keeps_watermark_question_open(self):
        result = inspect_mod.inspect_path(FIXTURES / "text_mentions_c2pa.md")
        self.assertEqual(result["text_watermark"]["status"], "UNVERIFIABLE")

    def test_plain_text_keeps_watermark_question_open(self):
        result = inspect_mod.inspect_path(FIXTURES / "text_clean.txt")
        self.assertEqual(result["text_watermark"]["status"], "UNVERIFIABLE")

    def test_images_are_not_applicable(self):
        result = inspect_mod.inspect_path(FIXTURES / "png_clean.png")
        self.assertEqual(result["text_watermark"]["status"], "NOT_APPLICABLE")

    def test_literal_text_is_unverifiable(self):
        result = inspect_mod.inspect_text("hello", "test")
        self.assertEqual(result["text_watermark"]["status"], "UNVERIFIABLE")

    def test_is_text_asset_does_not_depend_on_mimetypes(self):
        for name, expected in (("text_clean.txt", True), ("text_mentions_c2pa.md", True),
                               ("svg_clean.svg", True), ("png_clean.png", False),
                               ("mp4_clean.mp4", False), ("doc_meta.docx", False)):
            path = FIXTURES / name
            self.assertEqual(core.is_text_asset(path, core.read_head(path)), expected, name)


# ---------------------------------------------------------------------------
# D4: no-manifest matching
# ---------------------------------------------------------------------------

class NoManifestMatchingTests(unittest.TestCase):
    def test_known_renderings_are_recognised(self):
        for message in ("Error: No claim found",
                        "Error: no JUMBF data found",
                        "error: required JUMBF box not found",
                        "Error: C2PA provenance not found in XMP",
                        "  ERROR: No Claim Found  "):
            self.assertTrue(core.is_no_manifest_failure(1, message), message)

    def test_success_is_never_a_no_manifest_failure(self):
        self.assertFalse(core.is_no_manifest_failure(0, "Error: No claim found"))

    def test_unrelated_error_is_not_absent(self):
        self.assertFalse(core.is_no_manifest_failure(1, "Error: permission denied"))


# ---------------------------------------------------------------------------
# D5: transparency gating
# ---------------------------------------------------------------------------

class TransparencyTests(unittest.TestCase):
    def valid_record(self):
        return {
            "publication": "test",
            "reviewed_at": "2026-08-13T00:00:00Z",
            "outputs": [{
                "name": "copy",
                "media_type": "text/plain",
                "ai_generated": True,
                "provider": "Anthropic",
                "model": "UNKNOWN",
                "generated_at": "2026-08-13T00:00:00Z",
                "human_edits_documented": True,
                "disclosure": {"present": True, "text": "AI-assisted and human-edited."},
                "provenance": {
                    "manifest_presence": "NOT_APPLICABLE",
                    "integrity": "NOT_APPLICABLE",
                    "signer_trust": "NOT_APPLICABLE",
                    "text_watermark": "UNVERIFIABLE",
                    "asset_sha256": "a" * 64,
                },
            }],
        }

    def image_record(self):
        record = self.valid_record()
        output = record["outputs"][0]
        output["media_type"] = "image/png"
        output["provenance"] = {
            "manifest_presence": "PRESENT", "integrity": "VALID",
            "signer_trust": "NOT_CHECKED", "text_watermark": "NOT_APPLICABLE",
            "asset_sha256": "b" * 64,
        }
        return record

    def test_complete_record_is_ready(self):
        result = transparency_mod.check(self.valid_record())
        self.assertEqual(result["status"], "READY_FOR_REVIEW")
        self.assertEqual(result["legal_conclusion"], "NOT_PROVIDED")

    def test_advisory_items_do_not_block(self):
        result = transparency_mod.check(self.image_record())
        self.assertEqual(result["status"], "READY_WITH_REVIEW_ITEMS")
        self.assertEqual(result["required_gap_count"], 0)
        self.assertEqual(result["review_item_count"], 1)
        self.assertEqual(transparency_mod.exit_code_for(result), core.EXIT_CONCLUSIVE_GOOD)

    def test_required_gaps_still_block(self):
        record = self.image_record()
        record["outputs"][0]["disclosure"] = {"present": False, "text": ""}
        result = transparency_mod.check(record)
        self.assertEqual(result["status"], "GAPS_FOUND")
        self.assertEqual(transparency_mod.exit_code_for(result), core.EXIT_CONCLUSIVE_BAD)

    def test_pdf_is_text_bearing_for_anthropic(self):
        record = self.valid_record()
        output = record["outputs"][0]
        output["media_type"] = "application/pdf"
        output["provenance"]["text_watermark"] = "NOT_APPLICABLE"
        result = transparency_mod.check(record)
        self.assertTrue(any(g["field"] == "provenance.text_watermark" and g["severity"] == "REQUIRED"
                            for g in result["gaps"]))

    def test_anthropic_text_cannot_claim_absent(self):
        record = self.valid_record()
        record["outputs"][0]["provenance"]["text_watermark"] = "ABSENT"
        result = transparency_mod.check(record)
        self.assertTrue(any(g["field"] == "provenance.text_watermark" for g in result["gaps"]))

    def test_contradictory_provenance_is_rejected(self):
        record = self.valid_record()
        record["outputs"][0]["provenance"].update(
            {"manifest_presence": "ABSENT", "integrity": "VALID", "signer_trust": "TRUSTED"})
        result = transparency_mod.check(record)
        self.assertEqual(result["status"], "GAPS_FOUND")

    def test_placeholder_disclosure_and_bad_timestamp_are_rejected(self):
        record = self.valid_record()
        record["outputs"][0]["disclosure"]["text"] = "."
        record["outputs"][0]["generated_at"] = "sometime"
        fields = {g["field"] for g in transparency_mod.check(record)["gaps"]}
        self.assertIn("disclosure.text", fields)
        self.assertIn("generated_at", fields)

    def test_malformed_jurisdictions_are_rejected(self):
        record = self.valid_record()
        record["jurisdictions"] = [""]
        fields = {g["field"] for g in transparency_mod.check(record)["gaps"]}
        self.assertIn("jurisdictions", fields)

    def test_example_record_is_clean(self):
        with (ROOT / "examples" / "transparency-record.json").open(encoding="utf-8") as handle:
            result = transparency_mod.check(json.load(handle))
        self.assertEqual(result["status"], "READY_FOR_REVIEW")


# ---------------------------------------------------------------------------
# Verifier classification
# ---------------------------------------------------------------------------

class VerifyTests(unittest.TestCase):
    def test_valid_manifest_without_trust_check(self):
        result = core.classify(c2pa_report())
        self.assertEqual(result["integrity"], "VALID")
        self.assertEqual(result["signer_trust"], "NOT_CHECKED")

    def test_untrusted_signer_does_not_invalidate_integrity(self):
        result = core.classify(c2pa_report(failures=[{"code": "signingCredential.untrusted"}]),
                               trust_checked=True)
        self.assertEqual(result["integrity"], "VALID")
        self.assertEqual(result["signer_trust"], "UNTRUSTED")

    def test_trusted_requires_positive_code(self):
        result = core.classify(c2pa_report(state="Trusted",
                                           extra_success=[{"code": "signingCredential.trusted"}]),
                               trust_checked=True)
        self.assertEqual(result["signer_trust"], "TRUSTED")

    def test_trusted_state_without_code_is_unknown(self):
        result = core.classify(c2pa_report(state="Trusted"), trust_checked=True)
        self.assertEqual(result["signer_trust"], "UNKNOWN")

    def test_binding_error_is_invalid(self):
        result = core.classify(c2pa_report(state="Invalid",
                                           failures=[{"code": "assertion.dataHash.mismatch"}]))
        self.assertEqual(result["integrity"], "INVALID")

    def test_unrecognised_schema_is_unknown(self):
        result = core.classify({"active_manifest": "urn:test", "manifests": {"urn:test": {}}})
        self.assertEqual(result["integrity"], "UNKNOWN")

    def test_nonzero_exit_cannot_be_valid(self):
        result = core.classify(c2pa_report(), exit_code=1)
        self.assertEqual(result["integrity"], "UNKNOWN")

    def test_manifest_summary_surfaces_actions(self):
        summary = core.manifest_summary(c2pa_report())
        self.assertEqual(summary["claim_generator"], "test/1.0")
        self.assertIn("c2pa.created", summary["actions"])

    def test_captured_report_never_becomes_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "report.json"
            path.write_text(json.dumps(c2pa_report()))
            result = verify_mod.classify_captured(path, "a" * 64)
        self.assertEqual(result["integrity"], "NOT_VERIFIED")
        self.assertEqual(result["reported_result"]["integrity"], "VALID")
        self.assertEqual(verify_mod.exit_code_for(result), core.EXIT_INCONCLUSIVE)

    def test_missing_verifier_stays_unknown_with_full_schema(self):
        result = verify_mod.verify_asset(FIXTURES / "jpeg_clean.jpg", "/definitely/missing/c2patool")
        self.assertEqual(result["manifest_presence"], "UNKNOWN")
        self.assertEqual(set(result), set(verify_mod.base_result()))
        self.assertIsNotNone(result["asset_sha256"])

    def test_old_verifier_is_rejected_with_actionable_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = pathlib.Path(directory) / "c2patool"
            tool.write_text("#!/bin/sh\necho 'c2patool 0.9.0'\nexit 0\n")
            tool.chmod(0o755)
            result = verify_mod.verify_asset(FIXTURES / "jpeg_clean.jpg", str(tool))
        self.assertFalse(result["verifier_supported"])
        self.assertIn("older than the supported minimum", result["reason"])
        self.assertEqual(verify_mod.exit_code_for(result), core.EXIT_INCONCLUSIVE)

    def test_remote_trust_list_requires_network_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = pathlib.Path(directory) / "c2patool"
            tool.write_text("#!/bin/sh\necho 'c2patool 0.27.11'\nexit 0\n")
            tool.chmod(0o755)
            result = verify_mod.verify_asset(FIXTURES / "jpeg_clean.jpg", str(tool),
                                             "https://example.com/anchors.pem")
        self.assertIn("--allow-network", result["reason"])

    def test_every_branch_returns_the_same_keys(self):
        expected = set(verify_mod.base_result())
        missing = verify_mod.verify_asset(FIXTURES / "jpeg_clean.jpg", "/missing/tool")
        self.assertEqual(set(missing), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "report.json"
            path.write_text(json.dumps(c2pa_report()))
            captured = verify_mod.classify_captured(path, "a" * 64)
        self.assertTrue(expected.issubset(set(captured)))


# ---------------------------------------------------------------------------
# Privacy audit
# ---------------------------------------------------------------------------

class PrivacyTests(unittest.TestCase):
    def categories(self, name):
        result = privacy_mod.audit(FIXTURES / name)
        return result, {item["category"] for item in result["findings"]}

    def test_exif_gps_in_png(self):
        result, categories = self.categories("png_exif_gps.png")
        self.assertIn("location", categories)
        self.assertEqual(result["risk"], "HIGH")

    def test_exif_gps_in_jpeg(self):
        _, categories = self.categories("jpeg_exif_gps.jpg")
        self.assertIn("location", categories)

    def test_gps_hidden_in_thumbnail_ifd1_is_found(self):
        _, categories = self.categories("jpeg_exif_gps_ifd1.jpg")
        self.assertIn("location", categories)

    def test_iptc_datasets_are_parsed(self):
        result, categories = self.categories("jpeg_iptc.jpg")
        self.assertIn("identity", categories)
        self.assertIn("location", categories)
        self.assertIn("comment", categories)
        self.assertNotIn("Alice", json.dumps(result))
        self.assertNotIn("Tallinn", json.dumps(result))

    def test_webp_exif(self):
        _, categories = self.categories("webp_exif.webp")
        self.assertIn("location", categories)

    def test_bmff_location_atom(self):
        _, categories = self.categories("mp4_location.mp4")
        self.assertIn("location", categories)

    def test_pdf_and_ooxml(self):
        _, pdf = self.categories("doc_meta.pdf")
        self.assertIn("identity", pdf)
        _, docx = self.categories("doc_meta.docx")
        self.assertIn("identity", docx)

    def test_svg_reports_categories_without_values(self):
        result, categories = self.categories("svg_meta.svg")
        self.assertIn("identity", categories)
        self.assertIn("location", categories)
        self.assertTrue(result["values_redacted"])
        self.assertNotIn("Alice", json.dumps(result))

    def test_visible_allocation_text_is_not_location(self):
        _, categories = self.categories("svg_clean.svg")
        self.assertNotIn("location", categories)

    def test_clean_assets_report_none_observed(self):
        for name in ("png_clean.png", "webp_clean.webp", "svg_clean.svg"):
            result = privacy_mod.audit(FIXTURES / name)
            self.assertEqual(result["risk"], "NONE_OBSERVED", name)

    def test_source_is_never_modified(self):
        path = FIXTURES / "jpeg_iptc.jpg"
        before = core.sha256_file(path)
        privacy_mod.audit(path)
        self.assertEqual(core.sha256_file(path), before)


# ---------------------------------------------------------------------------
# Covert channels
# ---------------------------------------------------------------------------

class CovertChannelTests(unittest.TestCase):
    def test_detects_every_channel_class(self):
        text = (FIXTURES / "text_covert.txt").read_text(encoding="utf-8")
        scan = core.scan_covert_channels(text)
        channels = {item["channel"] for item in scan["findings"]}
        for expected in ("unicode_tag", "bidi_control", "variation_selector",
                         "zero_width", "exotic_space", "mixed_script"):
            self.assertIn(expected, channels, expected)
        self.assertEqual(scan["risk"], "HIGH")

    def test_ordinary_prose_is_clean(self):
        scan = core.scan_covert_channels(
            "It's a well-formed sentence — with an em dash, \"quotes\", and 100% normal text.")
        self.assertEqual(scan["status"], "NONE_OBSERVED")

    def test_newlines_and_tabs_are_not_findings(self):
        scan = core.scan_covert_channels("line one\nline two\tcolumn\r\n")
        self.assertEqual(scan["findings"], [])

    def test_never_claims_watermark_evidence(self):
        scan = core.scan_covert_channels("hidden​")
        self.assertIn("not watermark evidence", scan["interpretation"])


# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------

class DetectorRegistryTests(unittest.TestCase):
    def test_anthropic_is_always_unverifiable(self):
        result = watermark_mod.detector_anthropic("any text", {})
        self.assertEqual(result["state"], "UNVERIFIABLE")
        self.assertFalse(result["available"])

    def test_keyed_detectors_never_return_not_detected(self):
        for detector in (watermark_mod.detector_anthropic, watermark_mod.detector_synthid,
                         watermark_mod.detector_kgw):
            result = detector("text", {})
            self.assertFalse(result["ran"], result["detector"])
            self.assertNotEqual(result["state"], "NOT_DETECTED", result["detector"])

    def test_detectors_that_did_not_run_are_excluded_from_verdict(self):
        result = watermark_mod.analyse("plain text", "test", {})
        self.assertEqual(result["status"], "NO_SIGNAL_OBSERVED")
        self.assertGreaterEqual(result["ran_detector_count"], 1)
        self.assertIn("anthropic-official", result["did_not_run_detectors"])

    def test_not_configured_is_distinct_from_no_signal(self):
        results = watermark_mod.analyse("plain", "test", {})["detectors"]
        by_name = {item["detector"]: item for item in results}
        self.assertEqual(by_name["synthid-text"]["state"], "NOT_CONFIGURED")
        self.assertEqual(by_name["kgw-research"]["state"], "NOT_CONFIGURED")
        self.assertEqual(by_name["anthropic-official"]["state"], "UNVERIFIABLE")

    def test_configured_but_unimplemented_is_unsupported_not_clean(self):
        results = watermark_mod.analyse("plain", "test", {"synthid_config": "/tmp/x"})["detectors"]
        synthid = {item["detector"]: item for item in results}["synthid-text"]
        self.assertEqual(synthid["state"], "UNSUPPORTED")
        self.assertFalse(synthid["ran"])

    def test_covert_text_is_a_signal(self):
        text = (FIXTURES / "text_covert.txt").read_text(encoding="utf-8")
        result = watermark_mod.analyse(text, "test", {})
        self.assertEqual(result["status"], "SIGNAL_FOUND")
        self.assertEqual(watermark_mod.exit_code_for(result), core.EXIT_CONCLUSIVE_BAD)

    def test_sidecar_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = pathlib.Path(directory) / "draft.md"
            asset.write_text("hello")
            result = watermark_mod.detector_c2pa_text("hello", {"asset_path": str(asset)})
            self.assertEqual(result["state"], "NOT_DETECTED")
            (pathlib.Path(directory) / "draft.c2pa").write_bytes(b"manifest")
            result = watermark_mod.detector_c2pa_text("hello", {"asset_path": str(asset)})
            self.assertEqual(result["state"], "DETECTED")

    def test_statistical_detection_is_a_documented_non_goal(self):
        result = watermark_mod.analyse("text", "test", {})
        self.assertTrue(any("stylometric" in item for item in result["non_goals"]))


# ---------------------------------------------------------------------------
# Survival
# ---------------------------------------------------------------------------

class SurvivalTests(unittest.TestCase):
    def test_observed_marker_loss(self):
        baseline = {"manifest_presence": "POSSIBLE", "state": "POSSIBLE_NOT_VERIFIED"}
        derivative = {"manifest_presence": "ABSENT", "integrity": "NOT_VERIFIED",
                      "state": "NO_EVIDENCE_OBSERVED"}
        self.assertEqual(survival_mod.derivative_state(baseline, derivative), "LOST_OR_UNAVAILABLE")

    def test_no_baseline_prevents_survival_claim(self):
        baseline = {"manifest_presence": "ABSENT", "state": "NO_EVIDENCE_OBSERVED"}
        derivative = {"manifest_presence": "ABSENT", "integrity": "NOT_VERIFIED",
                      "state": "NO_EVIDENCE_OBSERVED"}
        self.assertEqual(survival_mod.derivative_state(baseline, derivative), "NO_BASELINE_EVIDENCE")

    def test_missing_verifier_is_inconclusive(self):
        result = survival_mod.build(FIXTURES / "jpeg_c2pa_app11.jpg", [], "definitely-missing", 5, False)
        self.assertEqual(result["original"]["state"], "UNKNOWN")
        self.assertEqual(survival_mod.exit_code_for(result), core.EXIT_INCONCLUSIVE)

    def test_error_contract_matches_success_contract(self):
        result = survival_mod.build(FIXTURES / "jpeg_clean.jpg", [], None, 5, False)
        failed = survival_mod.base_result("missing.jpg")
        self.assertEqual(set(result), set(failed))
        self.assertEqual(
            validate_schema.validate_document(failed, "map-provenance-survival.json"), [])

    def test_reproducibility_block_is_recorded(self):
        result = survival_mod.build(
            FIXTURES / "jpeg_c2pa_app11.jpg",
            [("cdn", FIXTURES / "jpeg_clean.jpg", "resize-1200w")], None, 5, False)
        repro = result["reproducibility"]
        for field in ("recorded_at", "verifier", "verifier_version", "core_schema_version",
                      "python", "platform", "network_allowed", "command", "note"):
            self.assertIn(field, repro)
        self.assertEqual(result["derivatives"][0]["operation"], "resize-1200w")

    def test_operation_is_optional(self):
        label, path, operation = survival_mod.parse_derivative("cdn=/tmp/x.jpg")
        self.assertEqual((label, operation), ("cdn", None))
        label, path, operation = survival_mod.parse_derivative("cdn:resize=/tmp/x.jpg")
        self.assertEqual((label, operation), ("cdn", "resize"))

    def test_structural_baseline_without_verifier(self):
        result = survival_mod.build(
            FIXTURES / "jpeg_c2pa_app11.jpg",
            [("stripped", FIXTURES / "jpeg_clean.jpg", "strip-app11")], None, 5, False)
        self.assertEqual(result["original"]["manifest_presence"], "POSSIBLE")
        self.assertEqual(result["derivatives"][0]["survival"], "LOST_OR_UNAVAILABLE")
        self.assertEqual(result["summary"]["lost_or_unavailable"], 1)

    def test_directory_batch_is_recursive_sorted_and_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "derivatives"
            (root / "nested").mkdir(parents=True)
            (root / ".hidden").mkdir()
            (root / "z.jpg").write_bytes(b"z")
            (root / "nested" / "a.png").write_bytes(b"a")
            (root / ".hidden" / "secret.png").write_bytes(b"secret")
            (root / ".ignored.jpg").write_bytes(b"hidden")
            try:
                (root / "outside-link").symlink_to(FIXTURES / "jpeg_clean.jpg")
            except (OSError, NotImplementedError):
                pass
            rows = survival_mod.derivatives_from_directories(
                FIXTURES / "jpeg_clean.jpg", [root])
        self.assertEqual([row[0] for row in rows], ["z.jpg", "nested/a.png"])
        self.assertTrue(all(row[2] is None for row in rows))

    def test_directory_batch_deduplicates_files_and_rejects_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            derivative = root / "copy.jpg"
            derivative.write_bytes(b"copy")
            rows = survival_mod.derivatives_from_directories(
                FIXTURES / "jpeg_clean.jpg", [root],
                existing=[("explicit", derivative, "copy")])
            self.assertEqual([row[0] for row in rows], ["explicit"])
            with self.assertRaisesRegex(ValueError, "Duplicate derivative label"):
                survival_mod.derivatives_from_directories(
                    FIXTURES / "jpeg_clean.jpg", [],
                    existing=[("same", derivative, None), ("same", derivative, None)])

    def test_multiple_directories_prefix_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            first = base / "editor"
            second = base / "cms"
            first.mkdir()
            second.mkdir()
            (first / "image.jpg").write_bytes(b"first")
            (second / "image.jpg").write_bytes(b"second")
            rows = survival_mod.derivatives_from_directories(
                FIXTURES / "jpeg_clean.jpg", [first, second])
        self.assertEqual([row[0] for row in rows], ["editor/image.jpg", "cms/image.jpg"])

    def test_shareable_reports_redact_paths_and_state_scope(self):
        result = survival_mod.build(
            FIXTURES / "jpeg_c2pa_app11.jpg",
            [("cdn", FIXTURES / "jpeg_clean.jpg", "resize")], None, 5, False)
        markdown = survival_mod.render_markdown(result)
        document = survival_mod.render_html(result)
        self.assertNotIn(str(ROOT), markdown)
        self.assertNotIn(str(ROOT), document)
        self.assertIn("jpeg_c2pa_app11.jpg", markdown)
        self.assertIn("C2PA provenance survival only", markdown)
        self.assertIn("proprietary pixel", document)
        self.assertIn("Signer trust was not evaluated", document)
        self.assertNotIn("<script", document.lower())

    def test_limitations_match_verifier_use(self):
        unavailable = survival_mod.build(FIXTURES / "jpeg_clean.jpg", [], None, 5, False)
        self.assertTrue(any("Without c2patool" in item for item in unavailable["limitations"]))
        verified = dict(unavailable)
        verified["limitations"] = survival_mod._limitations(True)
        self.assertFalse(any("Without c2patool" in item for item in verified["limitations"]))
        self.assertTrue(any("signer trust" in item for item in verified["limitations"]))

    def test_report_renderers_escape_caller_supplied_labels(self):
        result = survival_mod.build(
            FIXTURES / "jpeg_c2pa_app11.jpg",
            [("safe", FIXTURES / "jpeg_clean.jpg", None)], None, 5, False)
        result["derivatives"][0]["label"] = "<script>alert(1)</script>|x"
        document = survival_mod.render_html(result)
        markdown = survival_mod.render_markdown(result)
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn("\\|x", markdown)

    def test_report_writer_never_overwrites(self):
        result = survival_mod.build(FIXTURES / "jpeg_clean.jpg", [], None, 5, False)
        with tempfile.TemporaryDirectory() as directory:
            report = pathlib.Path(directory) / "report.md"
            report.write_text("keep me", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
                survival_mod.write_report(report, result)
            self.assertEqual(report.read_text(encoding="utf-8"), "keep me")

    def test_cli_writes_report_and_keeps_json_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            derivatives = pathlib.Path(directory) / "derivatives"
            derivatives.mkdir()
            shutil.copyfile(FIXTURES / "jpeg_clean.jpg", derivatives / "clean.jpg")
            report = derivatives / "survival.html"
            completed = subprocess.run([
                sys.executable,
                str(ROOT / "skills/map-provenance-survival/scripts/map_survival.py"),
                "--original", str(FIXTURES / "jpeg_c2pa_app11.jpg"),
                "--derivatives-dir", str(derivatives),
                "--report", str(report),
            ], check=False, capture_output=True, text=True)
            payload = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, core.EXIT_CONCLUSIVE_BAD)
            self.assertTrue(report.is_file())
            self.assertEqual(payload["summary"]["derivative_count"], 1)
            self.assertEqual(
                validate_schema.validate_document(payload, "map-provenance-survival.json"), [])

    def test_cli_report_failure_is_structured_and_inconclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            report = pathlib.Path(directory) / "existing.md"
            report.write_text("keep", encoding="utf-8")
            completed = subprocess.run([
                sys.executable,
                str(ROOT / "skills/map-provenance-survival/scripts/map_survival.py"),
                "--original", str(FIXTURES / "jpeg_clean.jpg"),
                "--report", str(report),
            ], check=False, capture_output=True, text=True)
            payload = json.loads(completed.stdout)
            retained = report.read_text(encoding="utf-8")
        self.assertEqual(completed.returncode, core.EXIT_INCONCLUSIVE)
        self.assertIn("Refusing to overwrite", payload["reason"])
        self.assertEqual(retained, "keep")
        self.assertEqual(
            validate_schema.validate_document(payload, "map-provenance-survival.json"), [])

    def test_missing_directory_is_structured_and_inconclusive(self):
        completed = subprocess.run([
            sys.executable,
            str(ROOT / "skills/map-provenance-survival/scripts/map_survival.py"),
            "--original", str(FIXTURES / "jpeg_clean.jpg"),
            "--derivatives-dir", "/definitely/missing/derivatives",
        ], check=False, capture_output=True, text=True)
        payload = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, core.EXIT_INCONCLUSIVE)
        self.assertTrue(payload["reason"])
        self.assertEqual(
            validate_schema.validate_document(payload, "map-provenance-survival.json"), [])

    def test_mcp_accepts_derivative_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            shutil.copyfile(FIXTURES / "jpeg_clean.jpg", root / "clean.jpg")
            payload = mcp_server.call_tool("map_provenance_survival", {
                "original": str(FIXTURES / "jpeg_c2pa_app11.jpg"),
                "derivative_directories": [str(root)],
            })
        self.assertEqual(payload["summary"]["derivative_count"], 1)
        self.assertEqual(payload["derivatives"][0]["label"], "clean.jpg")
        self.assertEqual(
            validate_schema.validate_document(payload, "map-provenance-survival.json"), [])


# ---------------------------------------------------------------------------
# Exit-code contract and schemas
# ---------------------------------------------------------------------------

class ContractTests(unittest.TestCase):
    def test_release_version_is_consistent(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(version, "0.2.0")
        self.assertEqual(mcp_server.SERVER_INFO["version"], version)
        self.assertEqual(survival_mod.TOOL_VERSION, version)
        self.assertIn("## [{0}]".format(version),
                      (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
        completed = subprocess.run([
            sys.executable,
            str(ROOT / "skills/map-provenance-survival/scripts/map_survival.py"),
            "--version",
        ], check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0)
        self.assertIn(version, completed.stdout)

    def test_exit_codes_are_the_documented_constants(self):
        self.assertEqual((core.EXIT_CONCLUSIVE_GOOD, core.EXIT_CONCLUSIVE_BAD,
                          core.EXIT_INCONCLUSIVE), (0, 1, 2))

    def test_every_entrypoint_uses_the_contract(self):
        cases = [
            ("skills/inspect-content-provenance/scripts/inspect_file.py",
             [str(FIXTURES / "png_clean.png")], 0),
            ("skills/audit-metadata-privacy/scripts/audit_metadata.py",
             [str(FIXTURES / "png_exif_gps.png")], 1),
            ("skills/audit-metadata-privacy/scripts/audit_metadata.py",
             [str(FIXTURES / "png_clean.png")], 0),
            ("skills/detect-text-watermark/scripts/detect_text_watermark.py",
             [str(FIXTURES / "text_covert.txt")], 1),
            ("skills/detect-text-watermark/scripts/detect_text_watermark.py",
             [str(FIXTURES / "text_clean.txt")], 0),
        ]
        for script, args, expected in cases:
            completed = subprocess.run([sys.executable, str(ROOT / script)] + args,
                                       check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, expected, "{0} {1}".format(script, args))

    def test_outputs_validate_against_schemas(self):
        documents = [
            (inspect_mod.inspect_path(FIXTURES / "jpeg_c2pa_app11.jpg"),
             "inspect-content-provenance.json"),
            (inspect_mod.inspect_text("hello", "literal"), "inspect-content-provenance.json"),
            (privacy_mod.audit(FIXTURES / "jpeg_iptc.jpg"), "audit-metadata-privacy.json"),
            (transparency_mod.check(TransparencyTests().valid_record()), "check-ai-transparency.json"),
            (transparency_mod.check(TransparencyTests().image_record()), "check-ai-transparency.json"),
            (watermark_mod.analyse("plain", "test", {}), "detect-text-watermark.json"),
            (verify_mod.verify_asset(FIXTURES / "jpeg_clean.jpg", "/missing/tool"),
             "verify-content-credentials.json"),
            (survival_mod.build(FIXTURES / "jpeg_c2pa_app11.jpg",
                                [("d", FIXTURES / "jpeg_clean.jpg", None)], None, 5, False),
             "map-provenance-survival.json"),
        ]
        for document, schema in documents:
            errors = validate_schema.validate_document(document, schema)
            self.assertEqual(errors, [], "{0}: {1}".format(schema, errors))

    def test_schema_rejects_a_contradictory_document(self):
        bad = verify_mod.base_result("x", "a" * 64)
        bad.update({"manifest_presence": "ABSENT", "integrity": "VALID"})
        errors = validate_schema.validate_document(bad, "verify-content-credentials.json")
        self.assertTrue(errors)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

class McpTests(unittest.TestCase):
    MODERN = {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {}}}
    LEGACY = {"capabilities": {}, "clientInfo": {"name": "tests", "version": "1.0"}}

    def test_current_revision_is_declared(self):
        self.assertEqual(mcp_server.PROTOCOL_VERSION, "2026-07-28")
        self.assertEqual(mcp_server.SUPPORTED_VERSIONS[0], "2026-07-28")

    def test_server_discover_is_implemented(self):
        result = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "server/discover",
                                    "params": dict(self.MODERN)})
        self.assertEqual(result["resultType"], "complete")
        self.assertIn("2026-07-28", result["supportedVersions"])
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "ai-watermarks-reality-check")

    def test_modern_request_with_meta_version(self):
        listing = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                                     "params": dict(self.MODERN)})
        self.assertEqual(len(listing["tools"]), len(mcp_server.TOOLS))

    def test_unsupported_version_raises_typed_error(self):
        with self.assertRaises(mcp_server.UnsupportedProtocolVersion) as caught:
            mcp_server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/list",
                "params": {"_meta": {
                    "io.modelcontextprotocol/protocolVersion": "1900-01-01",
                    "io.modelcontextprotocol/clientCapabilities": {}}},
            })
        self.assertEqual(caught.exception.requested, "1900-01-01")
        self.assertEqual(mcp_server.UNSUPPORTED_PROTOCOL_VERSION, -32022)

    def test_unsupported_version_wire_format(self):
        out = io.StringIO()
        request = json.dumps({
            "jsonrpc": "2.0", "id": 9, "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "1900-01-01",
                "io.modelcontextprotocol/clientCapabilities": {}}},
        })
        mcp_server.serve(io.StringIO(request + "\n"), out)
        message = json.loads(out.getvalue())
        self.assertEqual(message["error"]["code"], -32022)
        self.assertEqual(message["error"]["message"], "Unsupported protocol version")
        self.assertEqual(message["error"]["data"]["requested"], "1900-01-01")
        self.assertIn("2026-07-28", message["error"]["data"]["supported"])

    def test_legacy_initialize_still_negotiates(self):
        init = mcp_server.handle({"jsonrpc": "2.0", "id": 4, "method": "initialize",
                                  "params": dict(self.LEGACY, protocolVersion="2024-11-05")})
        self.assertEqual(init["protocolVersion"], "2024-11-05")
        self.assertIn("tools", init["capabilities"])

    def test_legacy_initialize_negotiates_down_instead_of_erroring(self):
        """The legacy lifecycle requires answering with a supported version."""
        init = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "initialize",
                                  "params": dict(self.LEGACY, protocolVersion="1900-01-01")})
        self.assertIn(init["protocolVersion"], mcp_server.LEGACY_VERSIONS)

    def test_modern_revision_is_never_negotiated_through_initialize(self):
        init = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "initialize",
                                  "params": dict(self.LEGACY, protocolVersion="2026-07-28")})
        self.assertIn(init["protocolVersion"], mcp_server.LEGACY_VERSIONS)

    def test_legacy_revision_is_rejected_in_modern_envelope(self):
        with self.assertRaises(mcp_server.UnsupportedProtocolVersion):
            mcp_server.handle({
                "jsonrpc": "2.0", "id": 5, "method": "tools/list",
                "params": {"_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                    "io.modelcontextprotocol/clientCapabilities": {}}},
            })

    def test_request_without_meta_is_accepted(self):
        listing = mcp_server.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/list"})
        self.assertEqual(len(listing["tools"]), len(mcp_server.TOOLS))

    def test_malformed_legacy_initialize_is_invalid_params(self):
        for params in ({"protocolVersion": "2024-11-05"},
                       dict(self.LEGACY, protocolVersion=None),
                       {"protocolVersion": "2024-11-05", "capabilities": [],
                        "clientInfo": self.LEGACY["clientInfo"]}):
            with self.assertRaises(mcp_server.ProtocolError) as caught:
                mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "initialize",
                                   "params": params})
            self.assertEqual(caught.exception.code, mcp_server.INVALID_PARAMS)

    def test_call_returns_parsable_json(self):
        response = mcp_server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "audit_metadata_privacy",
                       "arguments": {"path": str(FIXTURES / "jpeg_iptc.jpg")}},
        })
        self.assertFalse(response["isError"])
        payload = json.loads(response["content"][0]["text"])
        self.assertEqual(payload["risk"], "HIGH")

    def test_unknown_tool_is_a_protocol_error(self):
        with self.assertRaises(mcp_server.ProtocolError) as caught:
            mcp_server.handle({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "nope", "arguments": {}},
            })
        self.assertEqual(caught.exception.code, mcp_server.INVALID_PARAMS)

    def test_tool_execution_error_is_iserror_not_protocol_error(self):
        response = mcp_server.handle({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "audit_metadata_privacy", "arguments": {"path": "/nonexistent"}},
        })
        self.assertTrue(response["isError"])
        self.assertEqual(response["resultType"], "complete")

    def test_results_declare_result_type(self):
        listing = mcp_server.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/list"})
        self.assertEqual(listing["resultType"], "complete")
        call = mcp_server.handle({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "audit_metadata_privacy",
                       "arguments": {"path": str(FIXTURES / "png_clean.png")}},
        })
        self.assertEqual(call["resultType"], "complete")
        self.assertIn("structuredContent", call)

    def test_malformed_params_are_protocol_errors(self):
        for params in ({}, {"name": 123}, {"name": "audit_metadata_privacy", "arguments": "x"}):
            with self.assertRaises(mcp_server.ProtocolError):
                mcp_server.handle({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                                   "params": params})

    def test_unknown_method_is_method_not_found(self):
        with self.assertRaises(mcp_server.ProtocolError) as caught:
            mcp_server.handle({"jsonrpc": "2.0", "id": 9, "method": "bogus/method"})
        self.assertEqual(caught.exception.code, mcp_server.METHOD_NOT_FOUND)

    def test_notifications_produce_no_response(self):
        self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))


# ---------------------------------------------------------------------------
# Live verification (skipped when no real c2patool is present)
# ---------------------------------------------------------------------------

@unittest.skipUnless(LIVE, "no real c2patool and sample assets available")
class LiveC2paTests(unittest.TestCase):
    def test_signed_sample_is_valid(self):
        result = verify_mod.verify_asset(SAMPLES / "C.jpg", TOOL)
        self.assertEqual(result["manifest_presence"], "PRESENT")
        self.assertEqual(result["integrity"], "VALID")
        self.assertTrue(result["verifier_supported"])
        self.assertIn("c2pa.created", result["manifest"]["actions"])

    def test_unsigned_sample_is_absent(self):
        result = verify_mod.verify_asset(SAMPLES / "image.jpg", TOOL)
        self.assertEqual(result["manifest_presence"], "ABSENT")
        self.assertEqual(result["integrity"], "NOT_VERIFIED")

    def test_trust_anchors_promote_to_trusted(self):
        anchors = SAMPLES / "trust_anchors.pem"
        if not anchors.exists():
            self.skipTest("no trust anchors in sample directory")
        result = verify_mod.verify_asset(SAMPLES / "C.jpg", TOOL, str(anchors))
        self.assertEqual(result["integrity"], "VALID")
        self.assertEqual(result["signer_trust"], "TRUSTED")

    def test_untrusted_by_default(self):
        result = verify_mod.verify_asset(SAMPLES / "C.jpg", TOOL)
        self.assertEqual(result["signer_trust"], "NOT_CHECKED")
        self.assertIn("signingCredential.untrusted", result["failure_codes"])

    def test_tampered_asset_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tampered = pathlib.Path(directory) / "C.jpg"
            data = bytearray((SAMPLES / "C.jpg").read_bytes())
            data[-1024] ^= 0x01
            tampered.write_bytes(bytes(data))
            result = verify_mod.verify_asset(tampered, TOOL)
        self.assertEqual(result["integrity"], "INVALID")

    def test_structural_inspection_agrees_with_verifier(self):
        signed = inspect_mod.inspect_path(SAMPLES / "C.jpg")
        unsigned = inspect_mod.inspect_path(SAMPLES / "image.jpg")
        self.assertEqual(signed["manifest_presence"], "POSSIBLE")
        self.assertEqual(unsigned["manifest_presence"], "ABSENT")

    def test_live_output_validates_against_schema(self):
        result = verify_mod.verify_asset(SAMPLES / "C.jpg", TOOL)
        self.assertEqual(validate_schema.validate_document(result, "verify-content-credentials.json"), [])

    def test_survival_matrix_detects_stripping_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            original = SAMPLES / "C.jpg"
            data = original.read_bytes()
            copy = work / "copy.jpg"
            copy.write_bytes(data)
            tampered = work / "tampered.jpg"
            mutated = bytearray(data)
            mutated[-1024] ^= 0x01
            tampered.write_bytes(bytes(mutated))
            result = survival_mod.build(
                original,
                [("copy", copy, "byte-copy"), ("tampered", tampered, "pixel-edit")],
                TOOL, 30, False,
            )
        states = {row["label"]: row["survival"] for row in result["derivatives"]}
        self.assertEqual(states["copy"], "PRESERVED_VALID")
        self.assertEqual(states["tampered"], "PRESENT_INVALID")


class StableOutputShapeTests(unittest.TestCase):
    """Every branch of every entrypoint returns the same top-level field set."""

    ENTRYPOINTS = (
        ("inspect-content-provenance/scripts/inspect_file.py",
         "inspect-content-provenance.json",
         [str(FIXTURES / "png_clean.png")],
         [str(FIXTURES / "mp4_clean.mp4")],
         ["/nonexistent/asset.png"]),
        ("audit-metadata-privacy/scripts/audit_metadata.py",
         "audit-metadata-privacy.json",
         [str(FIXTURES / "png_exif_gps.png")],
         [str(FIXTURES / "png_clean.png")],
         ["/nonexistent/asset.png"]),
        ("detect-text-watermark/scripts/detect_text_watermark.py",
         "detect-text-watermark.json",
         [str(FIXTURES / "text_covert.txt")],
         [str(FIXTURES / "text_clean.txt")],
         ["/nonexistent/doc.txt"]),
        ("check-ai-transparency/scripts/check_transparency.py",
         "check-ai-transparency.json",
         [str(ROOT / "examples" / "transparency-record.json")],
         [str(ROOT / "examples" / "transparency-record.json")],
         ["/nonexistent/record.json"]),
    )

    def run_tool(self, script, args):
        completed = subprocess.run([sys.executable, str(ROOT / "skills" / script)] + args,
                                   check=False, capture_output=True, text=True)
        return completed.returncode, json.loads(completed.stdout)

    def test_field_sets_match_across_all_branches(self):
        for script, schema, good, other, bad in self.ENTRYPOINTS:
            _, ok = self.run_tool(script, good)
            _, mid = self.run_tool(script, other)
            code, err = self.run_tool(script, bad)
            self.assertEqual(set(ok), set(err), "{0}: success vs error".format(script))
            self.assertEqual(set(ok), set(mid), "{0}: success vs other".format(script))
            self.assertEqual(code, core.EXIT_INCONCLUSIVE, script)

    def test_every_branch_validates_against_its_schema(self):
        for script, schema, good, other, bad in self.ENTRYPOINTS:
            for label, args in (("good", good), ("other", other), ("bad", bad)):
                _, document = self.run_tool(script, args)
                errors = validate_schema.validate_document(document, schema)
                self.assertEqual(errors, [], "{0} [{1}]: {2}".format(script, label, errors))

    def test_error_branches_state_a_reason(self):
        for script, _, _, _, bad in self.ENTRYPOINTS:
            _, document = self.run_tool(script, bad)
            self.assertTrue(document.get("reason"), script)


class AdversarialVerifierTests(unittest.TestCase):
    """A hostile or broken verifier must never crash or become evidence."""

    def stub(self, directory, body):
        tool = pathlib.Path(directory) / "c2patool"
        tool.write_text("#!/bin/sh\ncase \"$*\" in *-V*) echo 'c2patool 0.27.11'; exit 0;; esac\n" + body)
        tool.chmod(0o755)
        return str(tool)

    def check_inconclusive(self, body, timeout=10):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.stub(directory, body)
            result = verify_mod.verify_asset(FIXTURES / "jpeg_c2pa_app11.jpg", tool, None, timeout)
        self.assertEqual(result["integrity"], "UNKNOWN")
        self.assertEqual(verify_mod.exit_code_for(result), core.EXIT_INCONCLUSIVE)
        self.assertTrue(result["reason"])
        self.assertEqual(set(result), set(verify_mod.base_result()))
        return result

    def test_invalid_utf8_on_stdout(self):
        self.check_inconclusive("printf '\\xff\\xfe\\x00binary garbage'\nexit 0\n")

    def test_invalid_utf8_on_stderr(self):
        self.check_inconclusive("printf '\\xff\\xfe bad' >&2\nexit 1\n")

    def test_mixed_diagnostics_then_valid_json(self):
        report = json.dumps(c2pa_report()).replace("'", "")
        with tempfile.TemporaryDirectory() as directory:
            tool = self.stub(directory, "echo 'warning: something'\ncat <<'EOF'\n" + report + "\nEOF\nexit 0\n")
            result = verify_mod.verify_asset(FIXTURES / "jpeg_c2pa_app11.jpg", tool, None, 10)
        # Leading diagnostics are tolerated; the JSON still classifies.
        self.assertEqual(result["integrity"], "VALID")

    def test_malformed_json(self):
        self.check_inconclusive("echo '{\"active_manifest\": '\nexit 0\n")

    def test_empty_output(self):
        self.check_inconclusive("exit 0\n")

    def test_timeout(self):
        result = self.check_inconclusive("sleep 30\n", timeout=2)
        self.assertIn("timed out", result["reason"].lower())

    def test_missing_executable(self):
        result = verify_mod.verify_asset(FIXTURES / "jpeg_clean.jpg", "/definitely/missing/c2patool")
        self.assertEqual(result["integrity"], "UNKNOWN")
        self.assertEqual(set(result), set(verify_mod.base_result()))

    def test_binary_output_does_not_raise(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.stub(directory, "head -c 4096 /dev/urandom\nexit 0\n")
            try:
                result = verify_mod.verify_asset(FIXTURES / "jpeg_clean.jpg", tool, None, 10)
            except UnicodeDecodeError:
                self.fail("binary verifier output raised UnicodeDecodeError")
        self.assertEqual(result["integrity"], "UNKNOWN")




class SpecCarrierTests(unittest.TestCase):
    """Normative C2PA 2.4 carriers, and the near-misses that must not pass."""

    def presence(self, name):
        result = inspect_mod.inspect_path(FIXTURES / name)
        structural = [m for m in result["c2pa_markers"] if m["confidence"] == "STRUCTURAL"]
        return result, structural

    # --- A.9 structured text ------------------------------------------------

    def test_structured_text_conforming_forms(self):
        for name, kind in (("text_c2pa_structured.md", "url"),
                           ("text_c2pa_frontmatter.md", "url"),
                           ("text_c2pa_data_uri.md", "data-uri"),
                           ("text_c2pa_python.py", "url"),
                           ("text_c2pa_javascript.js", "url"),
                           ("text_c2pa_css.css", "url"),
                           ("text_c2pa_xml.xml", "url")):
            result, structural = self.presence(name)
            self.assertEqual(result["manifest_presence"], "POSSIBLE", name)
            self.assertEqual(len(structural), 1, name)
            self.assertIn(kind, structural[0]["kind"], name)

    def test_structured_text_near_misses_are_not_structural(self):
        for name in ("text_struct_missing_end.md", "text_struct_reversed.md",
                     "text_struct_empty.md", "text_struct_invalid_uri.md",
                     "text_struct_bad_base64.md", "text_struct_multiple.md"):
            result, structural = self.presence(name)
            self.assertEqual(structural, [], name)
            self.assertNotEqual(result["manifest_presence"], "ABSENT", name)

    def test_discussing_delimiters_is_not_evidence(self):
        result, structural = self.presence("text_struct_discusses.md")
        self.assertEqual(result["manifest_presence"], "ABSENT")
        self.assertEqual(structural, [])

    def test_csv_is_not_a_structured_text_carrier(self):
        result, structural = self.presence("text_struct_csv.csv")
        self.assertEqual(structural, [])
        self.assertEqual(result["manifest_presence"], "ABSENT")

    def test_structured_text_via_literal_argument(self):
        text = (FIXTURES / "text_c2pa_structured.md").read_text(encoding="utf-8")
        block = core.find_c2pa_structured_text(text, ".md")
        self.assertTrue(block["conforming"])
        self.assertIsNone(core.find_c2pa_structured_text(text, ".csv"))

    def test_complete_block_outside_comment_or_front_matter_is_not_evidence(self):
        for name in ("text_struct_quoted_block.md", "text_struct_comment_example.md",
                     "text_struct_json.json", "text_struct_plain.txt"):
            result, structural = self.presence(name)
            self.assertEqual(result["manifest_presence"], "ABSENT", name)
            self.assertEqual(structural, [], name)

    def test_literal_route_requires_conforming_wrapper(self):
        bad = (FIXTURES / "text_wrapper_bad_magic.txt").read_text(encoding="utf-8")
        result = inspect_mod.inspect_text(bad, "literal")
        self.assertEqual(result["manifest_presence"], "ABSENT")
        self.assertEqual(result["c2pa_markers"], [])
        self.assertTrue(result["covert_channels"]["findings"])

        malformed = (FIXTURES / "text_wrapper_bad_version.txt").read_text(encoding="utf-8")
        result = inspect_mod.inspect_text(malformed, "literal")
        self.assertEqual(result["manifest_presence"], "POSSIBLE")
        self.assertEqual(result["c2pa_markers"][0]["confidence"], "MODERATE")

    def test_literal_route_records_mentions_without_promoting_them(self):
        result = inspect_mod.inspect_text("A readable C2PA documentation example.", "literal")
        self.assertEqual(result["manifest_presence"], "ABSENT")
        self.assertEqual(result["c2pa_mentions"], ["c2pa"])

    # --- A.8 unstructured text ----------------------------------------------

    def test_conforming_wrapper_is_excluded_from_covert_findings(self):
        text = (FIXTURES / "text_c2pa_wrapper.txt").read_text(encoding="utf-8")
        wrapper = core.find_c2pa_text_wrapper(text)
        self.assertTrue(wrapper["conforming"])
        self.assertEqual(wrapper["structure"], "CONFORMING")
        self.assertEqual(wrapper["declared_length"], wrapper["payload_bytes"])
        self.assertEqual(core.scan_covert_channels(text)["findings"], [])

    def test_malformed_wrappers_remain_covert_findings(self):
        """A hidden payload must not be launderable by prefixing U+FEFF."""
        for name, structure in (("text_wrapper_bad_magic.txt", "NOT_C2PA"),
                                ("text_wrapper_bad_version.txt", "MALFORMED"),
                                ("text_wrapper_truncated.txt", "MALFORMED"),
                                ("text_wrapper_short_payload.txt", "MALFORMED"),
                                ("text_wrapper_long_payload.txt", "MALFORMED"),
                                ("text_plain_selectors.txt", "NOT_C2PA")):
            text = (FIXTURES / name).read_text(encoding="utf-8")
            wrapper = core.find_c2pa_text_wrapper(text)
            self.assertFalse(wrapper["conforming"], name)
            self.assertEqual(wrapper["structure"], structure, name)
            scan = core.scan_covert_channels(text)
            self.assertTrue(scan["findings"], "{0} was laundered".format(name))
            self.assertFalse(scan["c2pa_text_manifest"]["conforming"], name)

    def test_malformed_wrapper_is_never_structural_evidence(self):
        for name in ("text_wrapper_bad_magic.txt", "text_wrapper_short_payload.txt",
                     "text_plain_selectors.txt"):
            _, structural = self.presence(name)
            self.assertEqual(structural, [], name)

    # --- A.7 HTML -----------------------------------------------------------

    def test_html_normative_carriers(self):
        for name in ("html_c2pa_script.html",
                     "html_c2pa_link.html", "html_c2pa_link_tokens.html",
                     "html_c2pa_reordered.html", "html_c2pa_mixed_case.html"):
            result, structural = self.presence(name)
            self.assertEqual(result["manifest_presence"], "POSSIBLE", name)
            self.assertGreaterEqual(len(structural), 1, name)

    def test_html_non_normative_or_malformed_scripts_are_not_structural(self):
        for name in ("html_c2pa_script_json.html", "html_c2pa_script_parameter.html",
                     "html_c2pa_script_empty.html",
                     "html_c2pa_script_bad_base64.html", "html_commented_script.html",
                     "html_unclosed_script.html"):
            _, structural = self.presence(name)
            self.assertEqual(structural, [], name)

    def test_html_non_normative_mime_is_not_structural(self):
        result, structural = self.presence("html_wrong_mime.html")
        self.assertEqual(structural, [])
        self.assertEqual(result["manifest_presence"], "ABSENT")

    def test_html_manifest_outside_head_is_not_evidence(self):
        result, structural = self.presence("html_manifest_in_body.html")
        self.assertEqual(structural, [])
        self.assertEqual(result["manifest_presence"], "ABSENT")

    def test_html_multiple_manifest_elements_are_flagged(self):
        result, _ = self.presence("html_c2pa_multiple.html")
        self.assertTrue(any("multiple" in m["kind"].lower() for m in result["c2pa_markers"]))

    def test_html_link_without_href_is_not_structural(self):
        _, structural = self.presence("html_link_no_href.html")
        self.assertEqual(structural, [])

    def test_html_without_parsable_head_is_unknown(self):
        result, _ = self.presence("html_no_head.html")
        self.assertEqual(result["manifest_presence"], "UNKNOWN")
        self.assertTrue(result["reason"])

    # --- A.3.6 TIFF ---------------------------------------------------------

    def test_tiff_tag_found_in_last_main_ifd(self):
        for name in ("tiff_c2pa_one_ifd.tif", "tiff_c2pa_two_ifd.tif",
                     "tiff_c2pa_three_ifd.tif"):
            result, structural = self.presence(name)
            self.assertEqual(result["manifest_presence"], "POSSIBLE", name)
            self.assertEqual(len(structural), 1, name)

    def test_tiff_tag_outside_last_ifd_is_not_structural(self):
        result, structural = self.presence("tiff_c2pa_first_ifd.tif")
        self.assertEqual(structural, [])
        self.assertEqual(result["manifest_presence"], "POSSIBLE")
        frontdoor = frontdoor_mod.audit(FIXTURES / "tiff_c2pa_first_ifd.tif")
        self.assertEqual(frontdoor["answers"]["located"], "UNKNOWN")

    def test_tiff_invalid_store_offset_is_not_structural(self):
        for name in ("tiff_bad_store_offset.tif", "tiff_c2pa_last_with_coentry.tif"):
            _, structural = self.presence(name)
            self.assertEqual(structural, [], name)

    def test_fully_traversed_clean_tiff_is_absent(self):
        for name in ("tiff_clean.tif", "tiff_clean_multi.tif"):
            result, _ = self.presence(name)
            self.assertEqual(result["manifest_presence"], "ABSENT", name)

    def test_incomplete_tiff_traversal_is_unknown(self):
        for name in ("tiff_bad_next.tif", "tiff_truncated.tif"):
            result, _ = self.presence(name)
            self.assertEqual(result["manifest_presence"], "UNKNOWN", name)
            self.assertIn("main-IFD chain", result["reason"], name)

    def test_tiff_wrong_field_type_is_not_structural(self):
        _, structural = self.presence("tiff_wrong_type.tif")
        self.assertEqual(structural, [])

    def test_tiff_chain_walker_reports_completeness(self):
        clean = core.walk_tiff((FIXTURES / "tiff_clean_multi.tif").read_bytes())
        self.assertTrue(clean["complete"])
        self.assertEqual(clean["main_ifd_count"], 3)
        cycle = core.walk_tiff((FIXTURES / "tiff_cycle.tif").read_bytes())
        self.assertFalse(cycle["complete"])
        self.assertIn("cycle", cycle["reason"])


class BoundedOutputTests(unittest.TestCase):
    """MAX_TOOL_OUTPUT must bound memory during capture, not slice afterwards."""

    def flooder(self, directory, count, stream="stdout"):
        tool = pathlib.Path(directory) / "c2patool"
        redirect = "" if stream == "stdout" else ">&2"
        tool.write_text(
            "#!/bin/sh\ncase \"$*\" in *-V*) echo 'c2patool 0.27.11'; exit 0;; esac\n"
            "{0} -c \"import sys;[sys.stdout.write('A'*4096) for _ in range({1})]\" {2}\n"
            .format(sys.executable, count, redirect))
        tool.chmod(0o755)
        return str(tool)

    def test_just_below_limit_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.flooder(directory, 10)
            code, out, err = core.run_tool([tool], 30, max_output=64 * 1024)
            self.assertEqual(len(out), 40960)

    def test_at_limit_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.flooder(directory, 16)
            code, out, err = core.run_tool([tool], 30, max_output=16 * 4096)
            self.assertEqual(len(out), 16 * 4096)

    def test_above_limit_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.flooder(directory, 40)
            with self.assertRaises(core.ToolOutputTooLarge):
                core.run_tool([tool], 30, max_output=16 * 4096)

    def test_excessive_stderr_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.flooder(directory, 40, stream="stderr")
            with self.assertRaises(core.ToolOutputTooLarge):
                core.run_tool([tool], 30, max_output=16 * 4096)

    def test_memory_is_bounded_during_capture(self):
        import resource
        with tempfile.TemporaryDirectory() as directory:
            tool = self.flooder(directory, 8192)  # 32 MB
            before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            with self.assertRaises(core.ToolOutputTooLarge):
                core.run_tool([tool], 60, max_output=256 * 1024)
            after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        scale = 1024 * 1024 if sys.platform == "darwin" else 1024
        self.assertLess((after - before) / scale, 16,
                        "capture retained the flood instead of bounding it")

    def test_flood_then_hang_is_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = pathlib.Path(directory) / "c2patool"
            tool.write_text(
                "#!/bin/sh\ncase \"$*\" in *-V*) echo 'c2patool 0.27.11'; exit 0;; esac\n"
                "{0} -c \"import sys;[sys.stdout.write('A'*4096) for _ in range(200)];sys.stdout.flush()\"\n"
                "sleep 60\n".format(sys.executable))
            tool.chmod(0o755)
            with self.assertRaises((core.ToolOutputTooLarge, subprocess.TimeoutExpired)):
                core.run_tool([str(tool)], 3, max_output=64 * 1024)

    def test_output_limit_produces_structured_inconclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.flooder(directory, 200)
            original = core.MAX_TOOL_OUTPUT
            core.MAX_TOOL_OUTPUT = 32 * 1024
            try:
                result = verify_mod.verify_asset(FIXTURES / "jpeg_c2pa_app11.jpg", tool, None, 30)
            finally:
                core.MAX_TOOL_OUTPUT = original
        self.assertEqual(result["integrity"], "UNKNOWN")
        self.assertIn("output limit exceeded", result["reason"].lower())
        self.assertEqual(verify_mod.exit_code_for(result), core.EXIT_INCONCLUSIVE)
        self.assertEqual(set(result), set(verify_mod.base_result()))


class McpRouteParityTests(unittest.TestCase):
    """CLI, library, front-door and MCP must agree on scan metadata."""

    def make_file(self, directory, offset_from_limit, limit):
        path = pathlib.Path(directory) / "doc.txt"
        filler = b"a" * max(0, limit + offset_from_limit)
        path.write_bytes(filler + "\u202e".encode("utf-8") + b"b" * 128)
        return path

    def routes(self, path):
        cli = subprocess.run(
            [sys.executable,
             str(ROOT / "skills/detect-text-watermark/scripts/detect_text_watermark.py"),
             str(path)], check=False, capture_output=True, text=True)
        return json.loads(cli.stdout), cli.returncode, mcp_server.call_tool(
            "detect_text_watermark", {"path": str(path)})

    def test_all_routes_agree_at_boundaries(self):
        fields = ("file_bytes", "scanned_bytes", "scan_complete",
                  "file_sha256", "scanned_sha256", "status")
        with tempfile.TemporaryDirectory() as directory:
            for offset in (-32, 0, 32):
                path = self.make_file(directory, offset, core.SCAN_LIMIT)
                cli, code, mcp = self.routes(path)
                for field in fields:
                    self.assertEqual(cli[field], mcp[field],
                                     "offset {0} field {1}".format(offset, field))
                self.assertEqual(cli["status"], "SIGNAL_FOUND", offset)
                self.assertEqual(code, core.EXIT_CONCLUSIVE_BAD)

    def test_mcp_reports_full_file_hash_not_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_file(directory, 32, core.SCAN_LIMIT)
            payload = mcp_server.call_tool("detect_text_watermark", {"path": str(path)})
            self.assertEqual(payload["file_sha256"], core.sha256_file(path))
            self.assertTrue(payload["scan_complete"])

    def test_beyond_streaming_ceiling_is_inconclusive(self):
        original = core.STREAM_LIMIT
        core.STREAM_LIMIT = 512
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "big.txt"
                path.write_bytes(b"a" * 4096)
                payload = mcp_server.call_tool("detect_text_watermark", {"path": str(path)})
        finally:
            core.STREAM_LIMIT = original
        self.assertEqual(payload["status"], "INCONCLUSIVE")
        self.assertFalse(payload["scan_complete"])
        self.assertNotEqual(payload["file_sha256"], payload["scanned_sha256"])
        self.assertEqual(watermark_mod.exit_code_for(payload), core.EXIT_INCONCLUSIVE)


class McpWireTests(unittest.TestCase):
    """Wire-level JSON-RPC behaviour, not just direct handle() calls."""

    MODERN = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
              "io.modelcontextprotocol/clientCapabilities": {}}

    def wire(self, *messages):
        out = io.StringIO()
        mcp_server.serve(io.StringIO("\n".join(messages) + "\n"), out)
        return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]

    def request(self, request_id, method, params=None):
        body = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            body["params"] = params
        return json.dumps(body)

    def test_conforming_modern_request(self):
        rows = self.wire(self.request(1, "tools/list", {"_meta": dict(self.MODERN)}))
        self.assertEqual(rows[0]["result"]["resultType"], "complete")
        self.assertIn("io.modelcontextprotocol/serverInfo", rows[0]["result"]["_meta"])

    def test_missing_client_capabilities_is_invalid_params(self):
        rows = self.wire(self.request(1, "tools/list", {
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}))
        self.assertEqual(rows[0]["error"]["code"], -32602)

    def test_wrong_capabilities_shape_is_invalid_params(self):
        rows = self.wire(self.request(1, "tools/list", {
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                      "io.modelcontextprotocol/clientCapabilities": "nope"}}))
        self.assertEqual(rows[0]["error"]["code"], -32602)

    def test_unsupported_version_is_32022(self):
        rows = self.wire(self.request(1, "tools/list", {
            "_meta": {"io.modelcontextprotocol/protocolVersion": "1900-01-01",
                      "io.modelcontextprotocol/clientCapabilities": {}}}))
        self.assertEqual(rows[0]["error"]["code"], -32022)
        self.assertIn("2026-07-28", rows[0]["error"]["data"]["supported"])

    def test_invalid_json_is_parse_error(self):
        rows = self.wire("{not json")
        self.assertEqual(rows[0]["error"]["code"], -32700)

    def test_non_object_json_is_invalid_request(self):
        for message in ("[1,2,3]", '"a string"', "42", "null", "true"):
            rows = self.wire(message)
            self.assertEqual(rows[0]["error"]["code"], -32600, message)

    def test_bad_jsonrpc_and_method_are_invalid_request(self):
        rows = self.wire('{"jsonrpc":"1.0","id":1,"method":"tools/list"}')
        self.assertEqual(rows[0]["error"]["code"], -32600)
        rows = self.wire('{"jsonrpc":"2.0","id":1}')
        self.assertEqual(rows[0]["error"]["code"], -32600)

    def test_notifications_receive_no_response(self):
        rows = self.wire('{"jsonrpc":"2.0","method":"notifications/initialized"}')
        self.assertEqual(rows, [])

    def test_server_survives_malformed_and_continues(self):
        rows = self.wire(
            "{broken",
            "[1,2]",
            self.request(9, "tools/list", {"_meta": dict(self.MODERN)}),
        )
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[-1]["result"]["resultType"], "complete")
        self.assertEqual(rows[-1]["id"], 9)

    def test_no_traceback_reaches_the_client(self):
        rows = self.wire(self.request(1, "tools/call", {
            "_meta": dict(self.MODERN),
            "name": "audit_metadata_privacy", "arguments": {"path": "/nonexistent"}}))
        text = json.dumps(rows)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("File \"", text)

    def test_legacy_initialize_has_no_modern_envelope_requirement(self):
        rows = self.wire(self.request(1, "initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "tests", "version": "1.0"}}))
        self.assertEqual(rows[0]["result"]["protocolVersion"], "2024-11-05")


class McpSchemaParityTests(unittest.TestCase):
    """MCP tool payloads validate against the same schemas as the CLI."""

    CASES = (
        ("audit_provenance", {"path": str(FIXTURES / "png_clean.png")},
         "audit-provenance.json"),
        ("audit_metadata_privacy", {"path": str(FIXTURES / "png_exif_gps.png")},
         "audit-metadata-privacy.json"),
        ("inspect_content_provenance", {"path": str(FIXTURES / "png_clean.png")},
         "inspect-content-provenance.json"),
        ("detect_text_watermark", {"path": str(FIXTURES / "text_clean.txt")},
         "detect-text-watermark.json"),
        ("check_ai_transparency", {"path": str(ROOT / "examples" / "transparency-record.json")},
         "check-ai-transparency.json"),
        ("verify_content_credentials", {"path": str(FIXTURES / "jpeg_clean.jpg"),
                                        "c2patool": "/missing/tool"},
         "verify-content-credentials.json"),
        ("map_provenance_survival", {"original": str(FIXTURES / "jpeg_clean.jpg")},
         "map-provenance-survival.json"),
    )

    def test_successful_payloads_validate(self):
        for name, arguments, schema in self.CASES:
            payload = mcp_server.call_tool(name, arguments)
            errors = validate_schema.validate_document(payload, schema)
            self.assertEqual(errors, [], "{0}: {1}".format(name, errors))

    def test_failed_payloads_validate_against_the_same_schema(self):
        for name, _, schema in self.CASES:
            response = mcp_server.handle({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": {"path": "/nonexistent/asset"}},
            })
            self.assertTrue(response["isError"], name)
            payload = response["structuredContent"]
            errors = validate_schema.validate_document(payload, schema)
            self.assertEqual(errors, [], "{0}: {1}".format(name, errors))
            self.assertTrue(payload.get("reason"), name)


class GeneratedCertificateProfileTests(unittest.TestCase):
    """The generated signing credential follows the C2PA X.509 profile."""

    @unittest.skipUnless(shutil.which("openssl"), "openssl is not available")
    def test_signing_chain_excludes_root_and_uses_required_extensions(self):
        with tempfile.TemporaryDirectory() as temp:
            previous_out = signed_fixture_mod.OUT
            signed_fixture_mod.OUT = pathlib.Path(temp)
            try:
                signed_fixture_mod.make_certificates()
                signing_env = signed_fixture_mod.signing_environment()
            finally:
                signed_fixture_mod.OUT = previous_out

            output = pathlib.Path(temp)
            chain = (output / "chain.pem").read_text(encoding="utf-8")
            signer = (output / "signer.pem").read_text(encoding="utf-8")
            root = (output / "ca.pem").read_text(encoding="utf-8")
            self.assertEqual(chain, signer)
            self.assertEqual(chain.count("-----BEGIN CERTIFICATE-----"), 1)
            self.assertNotEqual(chain, root)
            self.assertTrue(signing_env["C2PA_SIGN_CERT"].startswith(
                "-----BEGIN CERTIFICATE-----"))
            self.assertTrue(signing_env["C2PA_PRIVATE_KEY"].startswith(
                "-----BEGIN PRIVATE KEY-----"))

            details = subprocess.run(
                ["openssl", "x509", "-in", str(output / "signer.pem"),
                 "-text", "-noout"],
                check=True, capture_output=True, text=True).stdout
            self.assertIn("ecdsa-with-SHA256", details)
            self.assertIn("X509v3 Authority Key Identifier", details)
            self.assertIn("X509v3 Subject Key Identifier", details)
            self.assertIn("E-mail Protection", details)
            self.assertIn("Digital Signature", details)


@unittest.skipUnless(SELF_SIGNED, "no self-signed fixture; run tests/make_signed_fixture.py")
class SelfSignedTrustTests(unittest.TestCase):
    """Trust evaluated against a chain this repository created, not a vendor sample."""

    def test_our_signed_asset_is_valid(self):
        result = verify_mod.verify_asset(SIGNED_DIR / "signed.jpg", TOOL)
        self.assertEqual(result["manifest_presence"], "PRESENT")
        self.assertEqual(result["integrity"], "VALID")

    def test_our_trust_anchor_promotes_to_trusted(self):
        result = verify_mod.verify_asset(
            SIGNED_DIR / "signed.jpg", TOOL, str(SIGNED_DIR / "ca.pem"))
        self.assertEqual(result["integrity"], "VALID")
        self.assertEqual(result["signer_trust"], "TRUSTED")

    def test_our_signer_is_untrusted_without_our_anchor(self):
        result = verify_mod.verify_asset(SIGNED_DIR / "signed.jpg", TOOL)
        self.assertEqual(result["signer_trust"], "NOT_CHECKED")

    def test_tampering_our_asset_is_detected(self):
        result = verify_mod.verify_asset(SIGNED_DIR / "tampered.jpg", TOOL)
        self.assertEqual(result["integrity"], "INVALID")

    def test_manifest_declares_our_generator(self):
        result = verify_mod.verify_asset(SIGNED_DIR / "signed.jpg", TOOL)
        self.assertIn("c2pa.created", result["manifest"]["actions"])

    def test_structural_inspection_finds_our_manifest(self):
        result = inspect_mod.inspect_path(SIGNED_DIR / "signed.jpg")
        self.assertEqual(result["manifest_presence"], "POSSIBLE")
        self.assertTrue(any(m["confidence"] == "STRUCTURAL" for m in result["c2pa_markers"]))


if __name__ == "__main__":
    unittest.main()
