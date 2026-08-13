#!/usr/bin/env python3
"""Read-only, value-redacted audit of privacy-sensitive metadata.

Covers PNG, JPEG (including APP13/IPTC and EXIF IFD1), WebP, BMFF video and
still containers, TIFF, PDF, SVG, OOXML and ODF. Never mutates the asset.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import provenance_core as core  # noqa: E402

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ZIP_RATIO = 100

KEYS = {
    "location": ("gps", "latitude", "longitude", "location", "geotag", "coordinates"),
    "identity": ("author", "creator", "owner", "email", "lastmodifiedby", "byline", "artist", "copyright"),
    "device": ("make", "model", "serialnumber", "lensmodel", "cameraowner"),
    "software": ("software", "producer", "creatortool", "photoshop", "generator"),
    "timeline": ("createdate", "modifydate", "creationdate", "moddate", "timestamp", "datetimeoriginal"),
    "comment": ("comment", "description", "subject", "keywords", "caption", "headline"),
}

SEVERITY = {
    "location": "HIGH", "identity": "MEDIUM", "device": "MEDIUM",
    "software": "LOW", "timeline": "LOW", "comment": "MEDIUM",
}

# IPTC IIM dataset numbers within record 2 that carry personal data.
IPTC_DATASETS = {
    5: "comment",     # Object Name
    80: "identity",   # By-line
    85: "identity",   # By-line Title
    90: "location",   # City
    92: "location",   # Sub-location
    95: "location",   # Province/State
    101: "location",  # Country
    105: "comment",   # Headline
    110: "identity",  # Credit
    115: "identity",  # Source
    116: "identity",  # Copyright Notice
    120: "comment",   # Caption
    122: "identity",  # Writer/Editor
    55: "timeline",   # Date Created
}


def finding(category: str, location: str, method: str) -> dict:
    return {"category": category, "severity": SEVERITY[category], "location": location, "method": method}


def scan_terms(data: bytes, location: str, method: str) -> list:
    lower = data.lower()
    results = []
    for category, terms in KEYS.items():
        for term in terms:
            pattern = rb"(?<![a-z0-9])" + re.escape(term.encode()) + rb"(?![a-z0-9])"
            if re.search(pattern, lower):
                results.append(finding(category, location, method))
                break
    return results


def tiff_findings(payload: bytes, location: str) -> list:
    results = []
    for ifd_name, tag in core.parse_tiff_tags(payload):
        if ifd_name == "GPS IFD":
            category = core.GPS_TAG_CATEGORIES.get(tag, "location")
            results.append(finding(category, "{0} {1} tag 0x{2:04X}".format(location, ifd_name, tag),
                                   "TIFF/EXIF GPS tag inventory"))
        elif tag == 0x8825:
            results.append(finding("location", "{0} GPS IFD pointer".format(location),
                                   "TIFF/EXIF GPS pointer"))
        elif tag in core.TIFF_TAG_CATEGORIES:
            results.append(finding(core.TIFF_TAG_CATEGORIES[tag],
                                   "{0} {1} tag 0x{2:04X}".format(location, ifd_name, tag),
                                   "TIFF/EXIF tag inventory"))
    return results


def iptc_findings(payload: bytes, location: str) -> list:
    """Parse Photoshop IRB APP13 for IPTC-IIM record 2 datasets."""
    results = []
    if b"Photoshop 3.0" not in payload[:32]:
        return results
    index = payload.find(b"8BIM")
    seen = set()
    while index != -1 and index + 12 < len(payload):
        try:
            resource_id = int.from_bytes(payload[index + 4:index + 6], "big")
            # Pascal string: one length byte plus the name, padded to even length.
            name_len = payload[index + 6]
            name_field = 1 + name_len
            if name_field % 2:
                name_field += 1
            size_at = index + 6 + name_field
            size = int.from_bytes(payload[size_at:size_at + 4], "big")
            body = payload[size_at + 4:size_at + 4 + size]
        except (IndexError, ValueError):
            break
        if resource_id == 0x0404:  # IPTC-IIM
            offset = 0
            while offset + 5 <= len(body):
                if body[offset] != 0x1C:
                    break
                record = body[offset + 1]
                dataset = body[offset + 2]
                length = int.from_bytes(body[offset + 3:offset + 5], "big")
                if length & 0x8000:
                    break
                if record == 2 and dataset in IPTC_DATASETS and dataset not in seen:
                    seen.add(dataset)
                    results.append(finding(
                        IPTC_DATASETS[dataset],
                        "{0} IPTC 2:{1:03d}".format(location, dataset),
                        "IPTC-IIM dataset inventory",
                    ))
                offset += 5 + length
        next_index = payload.find(b"8BIM", index + 4)
        index = next_index
    return results


def png_findings(data: bytes) -> tuple:
    results = []
    chunks = []
    for name, payload, _ in core.iter_png_chunks(data):
        chunks.append(name)
        if name in ("tEXt", "iTXt") and len(payload) <= core.MAX_METADATA_ENTRY:
            results.extend(scan_terms(payload, "PNG {0} chunk".format(name), "metadata keyword inventory"))
        elif name == "zTXt":
            results.append(finding("comment", "PNG zTXt chunk",
                                   "compressed text metadata present; values not decompressed"))
        elif name == "eXIf" and len(payload) <= core.MAX_METADATA_ENTRY:
            results.extend(tiff_findings(payload, "PNG eXIf chunk"))
    return results, chunks


def jpeg_findings(data: bytes) -> list:
    results = []
    for marker, payload, _ in core.iter_jpeg_segments(data):
        if len(payload) > core.MAX_METADATA_ENTRY:
            continue
        if marker == 0xE1:
            if payload.startswith(b"Exif\x00\x00"):
                results.extend(tiff_findings(payload, "JPEG APP1 EXIF"))
            elif b"xmpmeta" in payload[:512].lower() or b"xap/1.0" in payload[:128].lower():
                results.extend(scan_terms(payload, "JPEG APP1 XMP", "XMP keyword inventory"))
        elif marker == 0xED:
            results.extend(iptc_findings(payload, "JPEG APP13"))
        elif marker == 0xFE:
            results.append(finding("comment", "JPEG COM segment", "free-form comment segment present"))
    return results


def webp_findings(data: bytes) -> list:
    results = []
    for name, payload, _ in core.iter_riff_chunks(data):
        upper = name.upper()
        if upper == "EXIF" and len(payload) <= core.MAX_METADATA_ENTRY:
            results.extend(tiff_findings(payload, "WebP EXIF chunk"))
        elif upper == "XMP " and len(payload) <= core.MAX_METADATA_ENTRY:
            results.extend(scan_terms(payload, "WebP XMP chunk", "XMP keyword inventory"))
    return results


def bmff_findings(data: bytes) -> list:
    results = []
    for box_type, payload, _, _ in core.iter_bmff_boxes(data):
        if box_type in ("©xyz", "xyz ") or box_type.endswith("xyz"):
            results.append(finding("location", "BMFF {0} box".format(box_type), "BMFF location atom"))
        elif box_type == "udta" and len(payload) <= core.MAX_METADATA_ENTRY:
            results.extend(scan_terms(payload, "BMFF udta box", "BMFF user-data keyword inventory"))
        elif box_type == "meta" and len(payload) <= core.MAX_METADATA_ENTRY:
            results.extend(scan_terms(payload, "BMFF meta box", "BMFF metadata keyword inventory"))
        elif box_type == "uuid" and payload[:16] != core.C2PA_BMFF_UUID and len(payload) <= core.MAX_METADATA_ENTRY:
            if b"xmpmeta" in payload[:2048].lower():
                results.extend(scan_terms(payload, "BMFF uuid XMP box", "XMP keyword inventory"))
    return results


def pdf_findings(data: bytes) -> list:
    mapping = {
        "identity": (rb"/(Author|Creator)\s*[<(]",),
        "software": (rb"/Producer\s*[<(]",),
        "timeline": (rb"/(CreationDate|ModDate)\s*[<(]",),
        "comment": (rb"/(Subject|Keywords|Title)\s*[<(]",),
    }
    results = [
        finding(category, "PDF document information", "format-aware key inventory")
        for category, patterns in mapping.items()
        if any(re.search(pattern, data, re.IGNORECASE) for pattern in patterns)
    ]
    if re.search(rb"<\?xpacket|<x:xmpmeta", data):
        results.extend(scan_terms(data, "PDF XMP packet", "XMP keyword inventory"))
    if data.count(b"%%EOF") > 1:
        results.append(finding("comment", "PDF incremental update",
                               "multiple %%EOF markers: earlier document revisions may be retained in-file"))
    return results


def archive_findings(path: pathlib.Path, names: tuple) -> list:
    results = []
    with zipfile.ZipFile(path) as archive:
        entries = {info.filename: info for info in archive.infolist()}
        for name in names:
            info = entries.get(name)
            if info is None:
                continue
            ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size > core.MAX_METADATA_ENTRY or ratio > MAX_ZIP_RATIO:
                results.append(finding("comment", name,
                                       "metadata entry skipped because decompression limits were exceeded"))
                continue
            results.extend(scan_terms(archive.read(info), name, "packaged property inventory"))
    return results


def svg_findings(data: bytes) -> list:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return []
    results = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag in ("metadata", "desc", "title"):
            payload = ET.tostring(element, encoding="utf-8")
            results.extend(scan_terms(payload, "SVG {0} element".format(tag), "XML metadata keyword inventory"))
            results.append(finding("comment", "SVG {0} element".format(tag), "free-form metadata element present"))
    return results


def deduplicate(items: list) -> list:
    unique = {(item["category"], item["location"], item["method"]): item for item in items}
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(unique.values(), key=lambda item: (order[item["severity"]], item["category"], item["location"]))


TOOL_NAME = "audit-metadata-privacy"


def base_result(asset=None) -> dict:
    """The stable output contract. Every field exists on every path."""
    return {
        "schema_version": core.SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "asset": asset,
        "asset_sha256": None,
        "format": None,
        "format_supported": False,
        "risk": "UNKNOWN",
        "findings": [],
        "values_redacted": True,
        "inspected_surfaces": [],
        "source_modified": False,
        "reason": None,
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_metadata_entry_bytes": core.MAX_METADATA_ENTRY,
            "max_zip_ratio": MAX_ZIP_RATIO,
        },
        "limitations": [
            "This bounded audit can miss encrypted, proprietary, remote, malformed, or unsupported metadata.",
            "NONE_OBSERVED means no supported metadata field was observed; it is not a guarantee that none exists.",
            "Do not remove metadata before determining whether it is covered by a provenance signature.",
        ],
    }


def audit(path: pathlib.Path) -> dict:
    core.require_file(path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError("Asset is {0} bytes; the safe audit limit is {1} bytes.".format(size, MAX_FILE_BYTES))
    data = path.read_bytes()
    fmt = core.sniff_format(path, data)

    findings = []
    inspected = []
    if fmt == "PNG":
        png_results, chunks = png_findings(data)
        findings.extend(png_results)
        inspected.append("PNG chunks ({0})".format(len(chunks)))
    elif fmt == "JPEG":
        findings.extend(jpeg_findings(data))
        inspected.append("JPEG APP segments, EXIF tags, IPTC datasets")
    elif fmt == "WEBP":
        findings.extend(webp_findings(data))
        inspected.append("WebP RIFF chunks")
    elif fmt.startswith("BMFF"):
        findings.extend(bmff_findings(data))
        inspected.append("BMFF boxes")
    elif fmt == "TIFF":
        findings.extend(tiff_findings(data, "TIFF"))
        inspected.append("TIFF IFDs")
    elif fmt == "PDF":
        findings.extend(pdf_findings(data))
        inspected.append("PDF document information and XMP")
    elif fmt == "SVG":
        findings.extend(svg_findings(data))
        inspected.append("SVG metadata elements")
    elif fmt == "OOXML":
        findings.extend(archive_findings(path, ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml")))
        inspected.append("OOXML document properties")
    elif fmt == "ODF":
        findings.extend(archive_findings(path, ("meta.xml",)))
        inspected.append("ODF document properties")

    findings = deduplicate(findings)
    if any(item["severity"] == "HIGH" for item in findings):
        risk = "HIGH"
    elif any(item["severity"] == "MEDIUM" for item in findings):
        risk = "MEDIUM"
    elif findings:
        risk = "LOW"
    else:
        risk = "NONE_OBSERVED"

    result = base_result(str(path.resolve()))
    result.update({
        "asset_sha256": core.sha256_file(path),
        "format": fmt,
        "format_supported": bool(inspected),
        "risk": risk if inspected else "UNKNOWN",
        "findings": findings,
        "inspected_surfaces": inspected,
        "reason": None if inspected else
        "Format {0} has no supported metadata parser in this build, so no "
        "privacy conclusion can be drawn.".format(fmt),
    })
    return result


def exit_code_for(result: dict) -> int:
    if not result.get("format_supported"):
        return core.EXIT_INCONCLUSIVE
    if result.get("risk") == "HIGH":
        return core.EXIT_CONCLUSIVE_BAD
    return core.EXIT_CONCLUSIVE_GOOD


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset")
    args = parser.parse_args()
    try:
        result = audit(pathlib.Path(args.asset))
        print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code_for(result)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        failed = base_result(args.asset)
        failed["reason"] = str(error)
        print(json.dumps(failed, indent=2, sort_keys=True))
        return core.EXIT_INCONCLUSIVE


if __name__ == "__main__":
    sys.exit(main())
