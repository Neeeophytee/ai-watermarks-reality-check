#!/usr/bin/env python3
"""Shared, dependency-free provenance primitives.

This module is the single source of truth for container parsing, C2PA evidence
location, text-covert-channel scanning, and c2patool invocation. It is vendored
verbatim into every skill's ``scripts/`` directory so that a single skill folder
remains independently copyable. Run ``python3 scripts/sync_shared.py`` after
editing; CI fails if the copies drift.

Design rules:
- Standard library only.
- Read-only: nothing here ever mutates an asset.
- Evidence is located structurally, never by naive substring search.
- Every classification can return an explicit unknown state.
"""

from __future__ import annotations

import hashlib
import base64
from html.parser import HTMLParser
import json
import pathlib
import re
import shutil
import struct
import subprocess
import tempfile
import unicodedata
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

SCHEMA_VERSION = "2.0"

# Unified exit-code contract, honoured by every entrypoint in this repository.
EXIT_CONCLUSIVE_GOOD = 0
EXIT_CONCLUSIVE_BAD = 1
EXIT_INCONCLUSIVE = 2

SCAN_LIMIT = 16 * 1024 * 1024
MAX_METADATA_ENTRY = 2 * 1024 * 1024

# Minimum c2patool that is known to expose `--settings`, the `trust`
# subcommand, and the validation_state/validation_results summary schema.
MIN_C2PATOOL = (0, 20, 0)

# The C2PA BMFF UUID box identifier (ISO/IEC base media file format).
C2PA_BMFF_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")

# TIFF/DNG private tag carrying a manifest store (C2PA 2.4 Appendix A).
C2PA_TIFF_TAG = 0xCD41

# GIF Application Extension identifier (11 bytes: 8 id + 3 auth code).
C2PA_GIF_APP_ID = b"C2PA_GIF"

# C2PA text manifest wrapper (C2PA 2.4 A.8, "Embedding Manifests into
# Unstructured Text"). The store is appended to the text, prefixed by a
# ZWNBSP, and encoded as non-rendering Unicode variation selectors.
C2PA_TEXT_MAGIC = "C2PATXT\x00"
C2PA_TEXT_PREFIX = "﻿"
VS_BASIC_START, VS_BASIC_END = 0xFE00, 0xFE0F
VS_SUPP_START, VS_SUPP_END = 0xE0100, 0xE01EF

# Formats this module can inspect exhaustively enough to justify ABSENT.
# Anything else -- a recognised container we cannot fully walk, or an
# unrecognised one -- must return UNKNOWN instead of a conclusive clean
# result. Adding a format here is a claim that every carrier the C2PA
# specification defines for it is checked above.
FULLY_INSPECTABLE = frozenset({
    "PNG", "JPEG", "WEBP", "GIF", "TIFF", "SVG", "HTML", "TEXT",
})

# Renderings emitted by c2pa-rs / c2patool when an asset carries no manifest.
# Matched as normalised substrings so that wrapper prefixes and casing drift
# do not silently turn "no manifest" into "unknown".
NO_MANIFEST_SIGNALS = (
    "no claim found",
    "no jumbf data found",
    "required jumbf box not found",
    "c2pa provenance not found in xmp",
    "no manifest found",
    "manifest not found",
    "no c2pa manifest",
)

REQUIRED_INTEGRITY_CODES = {"claimSignature.validated", "claimSignature.insideValidity"}

TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".rst", ".csv", ".tsv", ".json", ".jsonl",
    ".yaml", ".yml", ".html", ".htm", ".xml", ".svg", ".log", ".srt", ".vtt",
    ".adoc", ".asciidoc", ".toml", ".ini", ".cfg", ".py", ".js", ".ts",
    ".rb", ".go", ".rs", ".c", ".h", ".cpp", ".java", ".css", ".sh",
    ".bash", ".zsh", ".sql", ".tex",
}

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".heic", ".heif",
    ".mp4", ".mov", ".m4a", ".m4v", ".pdf", ".docx", ".xlsx", ".pptx",
    ".odt", ".ods", ".odp", ".zip", ".tif", ".tiff", ".wav", ".mp3",
}


# --------------------------------------------------------------------------
# Hashing and IO
# --------------------------------------------------------------------------

def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_head(path: pathlib.Path, limit: int = SCAN_LIMIT) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def require_file(path: pathlib.Path) -> None:
    if not path.exists() or not path.is_file():
        raise ValueError("Not a readable file: {0}".format(path))


# Streaming ceiling for whole-file text analysis. Well above SCAN_LIMIT: text
# assets are read in full wherever practical so that a clean result describes
# the whole file rather than its first bytes.
STREAM_LIMIT = 256 * 1024 * 1024


def read_text_stream(path: pathlib.Path, limit: int = None) -> Dict[str, Any]:
    """Read a text asset in full where practical, reporting exactly what was read.

    Returns the decoded text, the full-file SHA-256 (always over every byte on
    disk, never over a prefix), the file size, the number of bytes actually
    analysed, and whether the analysis covered the whole file.
    """
    if limit is None:
        limit = STREAM_LIMIT       # resolved at call time, not at definition
    size = path.stat().st_size
    digest = hashlib.sha256()
    chunks = []
    scanned = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            if scanned < limit:
                take = min(len(block), limit - scanned)
                chunks.append(block[:take])
                scanned += take
    data = b"".join(chunks)
    return {
        "text": data.decode("utf-8", "replace"),
        "file_sha256": digest.hexdigest(),
        "file_bytes": size,
        "scanned_bytes": scanned,
        "scan_complete": scanned >= size,
        "scan_limit": limit,
    }


# --------------------------------------------------------------------------
# Container sniffing
# --------------------------------------------------------------------------

def sniff_format(path: pathlib.Path, head: bytes) -> str:
    """Identify a container from magic bytes, falling back to the suffix."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if head.startswith(b"%PDF-"):
        return "PDF"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "GIF"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WEBP"
    if head[:2] in (b"II", b"MM") and len(head) >= 4:
        try:
            endian = "<" if head[:2] == b"II" else ">"
            if struct.unpack(endian + "H", head[2:4])[0] == 42:
                return "TIFF"
        except struct.error:
            pass
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12].decode("ascii", "replace").strip()
        return "BMFF:{0}".format(brand)
    if head[:2] == b"PK":
        suffix = path.suffix.lower()
        if suffix in {".docx", ".xlsx", ".pptx"}:
            return "OOXML"
        if suffix in {".odt", ".ods", ".odp"}:
            return "ODF"
        return "ZIP"
    suffix = path.suffix.lower()
    if suffix == ".svg" or head[:400].lstrip()[:5].lower() == b"<svg ":
        return "SVG"
    if suffix in {".html", ".htm"}:
        return "HTML"
    lowered_head = head[:1024].lstrip().lower()
    if lowered_head.startswith(b"<!doctype html") or lowered_head.startswith(b"<html"):
        return "HTML"
    if suffix in TEXT_SUFFIXES:
        return "TEXT"
    return "UNKNOWN"


def looks_textual(head: bytes) -> bool:
    """Heuristic: decodable as UTF-8 with no NUL and few control bytes."""
    sample = head[:8192]
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    controls = sum(1 for ch in text if unicodedata.category(ch) == "Cc" and ch not in "\n\r\t")
    return controls <= max(1, len(text) // 200)


def is_text_asset(path: pathlib.Path, head: bytes) -> bool:
    """Decide whether text-watermark questions apply.

    Deliberately does not rely on ``mimetypes``: it returns ``None`` for
    ``.md`` on several Python builds, which previously caused Claude-authored
    Markdown to be reported as NOT_APPLICABLE.
    """
    suffix = path.suffix.lower()
    if suffix in BINARY_SUFFIXES:
        return False
    if suffix in TEXT_SUFFIXES:
        return True
    return looks_textual(head)


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------

def iter_png_chunks(data: bytes) -> Iterator[Tuple[str, bytes, int]]:
    """Yield (name, payload, offset) for every well-formed PNG chunk."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    offset = 8
    while offset + 12 <= len(data):
        try:
            length = struct.unpack(">I", data[offset:offset + 4])[0]
        except struct.error:
            return
        if length > len(data):
            return
        end = offset + 12 + length
        if end > len(data):
            return
        name = data[offset + 4:offset + 8].decode("ascii", "replace")
        yield name, data[offset + 8:offset + 8 + length], offset
        if name == "IEND":
            return
        offset = end


# --------------------------------------------------------------------------
# JPEG
# --------------------------------------------------------------------------

def iter_jpeg_segments(data: bytes) -> Iterator[Tuple[int, bytes, int]]:
    """Yield (marker, payload, offset) for JPEG segments before the scan."""
    if not data.startswith(b"\xff\xd8"):
        return
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            return
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return
        marker = data[offset]
        offset += 1
        if marker in (0xD8, 0xD9):
            continue
        if marker == 0xDA:  # start of scan: metadata segments are complete
            return
        if offset + 2 > len(data):
            return
        try:
            length = struct.unpack(">H", data[offset:offset + 2])[0]
        except struct.error:
            return
        if length < 2 or offset + length > len(data):
            return
        yield marker, data[offset + 2:offset + length], offset
        offset += length


# --------------------------------------------------------------------------
# RIFF / WebP
# --------------------------------------------------------------------------

def iter_riff_chunks(data: bytes) -> Iterator[Tuple[str, bytes, int]]:
    if data[:4] != b"RIFF" or len(data) < 12:
        return
    offset = 12
    while offset + 8 <= len(data):
        name = data[offset:offset + 4].decode("ascii", "replace")
        try:
            size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
        except struct.error:
            return
        payload = data[offset + 8:offset + 8 + size]
        if offset + 8 + size > len(data):
            yield name, payload, offset
            return
        yield name, payload, offset
        offset += 8 + size + (size & 1)


# --------------------------------------------------------------------------
# BMFF (MP4 / HEIC / AVIF)
# --------------------------------------------------------------------------

def iter_bmff_boxes(data: bytes, depth: int = 0, base: int = 0) -> Iterator[Tuple[str, bytes, int, int]]:
    """Yield (type, payload, absolute_offset, depth) for BMFF boxes.

    Recurses one level into the containers that can hold C2PA data so that a
    `uuid` box nested inside `meta` is still located.
    """
    container_types = {"moov", "meta", "udta", "trak", "mdia", "minf", "stbl", "iprp", "ipco"}
    offset = 0
    while offset + 8 <= len(data):
        try:
            size = struct.unpack(">I", data[offset:offset + 4])[0]
        except struct.error:
            return
        box_type = data[offset + 4:offset + 8].decode("ascii", "replace")
        header = 8
        if size == 1:
            if offset + 16 > len(data):
                return
            size = struct.unpack(">Q", data[offset + 8:offset + 16])[0]
            header = 16
        elif size == 0:
            size = len(data) - offset
        if size < header or offset + size > len(data):
            return
        payload = data[offset + header:offset + size]
        yield box_type, payload, base + offset, depth
        if depth < 3 and box_type in container_types:
            skip = 4 if box_type == "meta" else 0
            for item in iter_bmff_boxes(payload[skip:], depth + 1, base + offset + header + skip):
                yield item
        offset += size


# --------------------------------------------------------------------------
# TIFF / EXIF
# --------------------------------------------------------------------------

TIFF_TAG_CATEGORIES = {
    0x010F: "device",    # Make
    0x0110: "device",    # Model
    0x0131: "software",
    0x0132: "timeline",
    0x013B: "identity",  # Artist
    0x8298: "identity",  # Copyright
    0x9003: "timeline",
    0x9004: "timeline",
    0x9286: "comment",   # UserComment
    0xA430: "identity",  # CameraOwnerName
    0xA431: "device",    # BodySerialNumber
    0xA433: "device",    # LensMake
    0xA434: "device",    # LensModel
    0xA435: "device",    # LensSerialNumber
}

# GPS IFD tags that carry location directly.
GPS_TAG_CATEGORIES = {
    0x0001: "location", 0x0002: "location",  # latitude ref/value
    0x0003: "location", 0x0004: "location",  # longitude ref/value
    0x0005: "location", 0x0006: "location",  # altitude
    0x0012: "location", 0x001D: "location",  # map datum, date stamp
}

MAX_IFD_ENTRIES = 512
MAX_IFDS = 16


def walk_tiff(payload: bytes) -> Dict[str, Any]:
    """Walk the complete main-IFD chain plus the sub-IFDs.

    Returns entries as (ifd_name, tag, field_type, value_count, value_or_offset)
    and, critically, whether the traversal completed. A chain cut short by
    corruption, a cycle, an out-of-bounds pointer, or the IFD limit cannot
    support a claim of absence.
    """
    result = {
        "entries": [],
        "complete": False,
        "main_ifd_count": 0,
        "reason": None,
    }
    if payload.startswith(b"Exif\x00\x00"):
        payload = payload[6:]
    if len(payload) < 8 or payload[:2] not in (b"II", b"MM"):
        result["reason"] = "Not a TIFF header."
        return result
    endian = "<" if payload[:2] == b"II" else ">"
    try:
        if struct.unpack(endian + "H", payload[2:4])[0] != 42:
            result["reason"] = "TIFF magic 42 not present."
            return result
        first = struct.unpack(endian + "I", payload[4:8])[0]
    except struct.error:
        result["reason"] = "TIFF header truncated."
        return result

    entries = result["entries"]
    visited = set()
    sub_queue: List[Tuple[int, str]] = []

    def read_ifd(offset, name):
        """Read one IFD; return the next-IFD offset, or None on failure."""
        if offset + 2 > len(payload):
            return None, "IFD offset {0} is out of bounds.".format(offset)
        try:
            count = struct.unpack(endian + "H", payload[offset:offset + 2])[0]
        except struct.error:
            return None, "IFD entry count unreadable at {0}.".format(offset)
        if count > MAX_IFD_ENTRIES:
            return None, "IFD at {0} declares {1} entries, above the limit.".format(offset, count)
        end_of_entries = offset + 2 + count * 12
        if end_of_entries + 4 > len(payload):
            return None, "IFD at {0} is truncated.".format(offset)
        for index in range(count):
            start = offset + 2 + index * 12
            entry = payload[start:start + 12]
            if len(entry) != 12:
                return None, "IFD entry {0} truncated.".format(index)
            tag, field_type, value_count = struct.unpack(endian + "HHI", entry[:8])
            value = struct.unpack(endian + "I", entry[8:12])[0]
            entries.append((name, tag, field_type, value_count, value))
            is_pointer = field_type == 4 and value_count == 1
            if tag == 0x8825 and is_pointer:
                sub_queue.append((value, "GPS IFD"))
            elif tag == 0x8769 and is_pointer:
                sub_queue.append((value, "Exif IFD"))
            elif tag == 0xA005 and is_pointer:
                sub_queue.append((value, "Interop IFD"))
        try:
            nxt = struct.unpack(endian + "I", payload[end_of_entries:end_of_entries + 4])[0]
        except struct.error:
            return None, "Next-IFD pointer unreadable."
        return nxt, None

    # Main chain: IFD0 -> IFD1 -> ... until a zero pointer.
    offset = first
    index = 0
    while True:
        if index >= MAX_IFDS:
            result["reason"] = "Main IFD chain exceeded the {0}-IFD limit.".format(MAX_IFDS)
            return result
        if offset in visited:
            result["reason"] = "Main IFD chain contains a cycle at offset {0}.".format(offset)
            return result
        visited.add(offset)
        nxt, error = read_ifd(offset, "IFD{0}".format(index))
        if error is not None:
            result["reason"] = error
            return result
        result["main_ifd_count"] = index + 1
        index += 1
        if not nxt:
            break
        offset = nxt

    # Sub-IFDs are best-effort; a bad sub-IFD does not invalidate the main chain.
    seen_sub = set()
    while sub_queue and len(seen_sub) < MAX_IFDS:
        sub_offset, sub_name = sub_queue.pop(0)
        if sub_offset in seen_sub or sub_offset in visited:
            continue
        seen_sub.add(sub_offset)
        read_ifd(sub_offset, sub_name)

    result["complete"] = True
    return result


def parse_tiff_tags(payload: bytes) -> List[Tuple[str, int]]:
    """Backwards-compatible (ifd_name, tag) view used by the privacy audit."""
    walked = walk_tiff(payload)
    return [(name, tag) for name, tag, _, _, _ in walked["entries"]]


# --------------------------------------------------------------------------
# C2PA evidence location (container-aware)
# --------------------------------------------------------------------------

def _marker(location: str, kind: str, confidence: str) -> Dict[str, str]:
    return {"location": location, "kind": kind, "confidence": confidence}


def iter_gif_blocks(data: bytes) -> Iterator[Tuple[str, bytes, int]]:
    """Yield (kind, payload, offset) for GIF extension and image blocks."""
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return
    offset = 6
    if offset + 7 > len(data):
        return
    packed = data[offset + 4]
    offset += 7
    if packed & 0x80:  # global colour table
        offset += 3 * (2 ** ((packed & 0x07) + 1))

    def read_sub_blocks(start: int) -> Tuple[bytes, int]:
        chunks = []
        pos = start
        while pos < len(data):
            size = data[pos]
            pos += 1
            if size == 0:
                break
            chunks.append(data[pos:pos + size])
            pos += size
        return b"".join(chunks), pos

    while offset < len(data):
        marker = data[offset]
        if marker == 0x3B:  # trailer
            return
        if marker == 0x21:  # extension introducer
            if offset + 2 > len(data):
                return
            label = data[offset + 1]
            start = offset + 2
            if label == 0xFF:  # application extension
                if start >= len(data):
                    return
                size = data[start]
                identifier = data[start + 1:start + 1 + size]
                payload, end = read_sub_blocks(start + 1 + size)
                yield "application:" + identifier.decode("ascii", "replace"), payload, offset
                offset = end
                continue
            payload, end = read_sub_blocks(start)
            yield "extension:0x{0:02X}".format(label), payload, offset
            offset = end
            continue
        if marker == 0x2C:  # image descriptor
            return
        return


C2PA_TEXT_VERSION = 1
C2PA_TEXT_HEADER_LEN = 8 + 1 + 4  # magic + version + big-endian manifestLength


def find_c2pa_text_wrapper(text: str) -> Optional[Dict[str, Any]]:
    """Locate and structurally validate a C2PA 2.4 A.8 text manifest wrapper.

    The decoded wrapper is:

        8 bytes   magic     ``C2PATXT\\x00``
        1 byte    version   1
        4 bytes   manifestLength, big-endian
        N bytes   JUMBF manifest store

    Returns ``None`` when no variation-selector run follows a ZWNBSP at all.
    Otherwise returns a record whose ``conforming`` flag says whether every
    structural requirement held. A non-conforming run is **not** provenance:
    callers must keep treating it as an ordinary hidden-character sequence.

    The JUMBF payload is located and length-checked only. Nothing here decodes
    or validates it; that requires a conforming verifier.
    """
    index = text.rfind(C2PA_TEXT_PREFIX)
    if index == -1:
        return None
    tail = text[index + 1:]
    if not tail:
        return None

    decoded = bytearray()
    for char in tail:
        codepoint = ord(char)
        if VS_BASIC_START <= codepoint <= VS_BASIC_END:
            decoded.append(codepoint - VS_BASIC_START)
        elif VS_SUPP_START <= codepoint <= VS_SUPP_END:
            decoded.append((codepoint - VS_SUPP_START) + 16)
        else:
            # The run is interrupted by rendering text, so this is not a
            # trailing wrapper at all.
            return None
    if not decoded:
        return None

    record = {
        "offset": index,
        "selector_count": len(decoded),
        "decoded_bytes": len(decoded),
        "magic_confirmed": False,
        "version": None,
        "declared_length": None,
        "payload_bytes": None,
        "conforming": False,
        "structure": "UNKNOWN",
        "reason": None,
    }

    magic = C2PA_TEXT_MAGIC.encode("latin-1")
    if bytes(decoded[:len(magic)]) != magic:
        record["structure"] = "NOT_C2PA"
        record["reason"] = (
            "The decoded bytes do not begin with the C2PA text-manifest magic; "
            "this is an ordinary hidden-character sequence, not provenance."
        )
        return record
    record["magic_confirmed"] = True

    if len(decoded) < C2PA_TEXT_HEADER_LEN:
        record["structure"] = "MALFORMED"
        record["reason"] = "The wrapper header is truncated ({0} of {1} bytes).".format(
            len(decoded), C2PA_TEXT_HEADER_LEN)
        return record

    version = decoded[len(magic)]
    record["version"] = version
    if version != C2PA_TEXT_VERSION:
        record["structure"] = "MALFORMED"
        record["reason"] = "Unsupported wrapper version {0}; only version {1} is recognised.".format(
            version, C2PA_TEXT_VERSION)
        return record

    declared = struct.unpack(">I", bytes(decoded[len(magic) + 1:C2PA_TEXT_HEADER_LEN]))[0]
    record["declared_length"] = declared
    payload = len(decoded) - C2PA_TEXT_HEADER_LEN
    record["payload_bytes"] = payload
    if declared == 0:
        record["structure"] = "MALFORMED"
        record["reason"] = "The wrapper declares a zero-length manifest store."
        return record
    if payload != declared:
        record["structure"] = "MALFORMED"
        record["reason"] = (
            "The wrapper declares {0} manifest bytes but carries {1}."
        ).format(declared, payload)
        return record

    record["conforming"] = True
    record["structure"] = "CONFORMING"
    record["reason"] = (
        "The wrapper is structurally complete. Structural presence is not validity: "
        "a conforming verifier must validate the manifest store."
    )
    return record


# --------------------------------------------------------------------------
# C2PA 2.4 A.9 structured text: ASCII-armoured manifest block
# --------------------------------------------------------------------------

C2PA_ARMOUR_BEGIN = "-----BEGIN C2PA MANIFEST-----"
C2PA_ARMOUR_END = "-----END C2PA MANIFEST-----"
C2PA_DATA_URI_PREFIX = "data:application/c2pa;base64,"

# Formats where an ASCII-armoured block is the defined carrier. HTML and SVG
# are excluded: they have their own format-specific carriers. CSV and other
# tabular text are excluded: they have no comment syntax to host a block.
STRUCTURED_TEXT_COMMENT_FORMS = {
    ".md": (("<!--", "-->"),),
    ".markdown": (("<!--", "-->"),),
    ".rst": (("..", ""),),
    ".adoc": (("//", ""),),
    ".asciidoc": (("//", ""),),
    ".yaml": (("#", ""),),
    ".yml": (("#", ""),),
    ".toml": (("#", ""),),
    ".ini": ((";", ""), ("#", "")),
    ".cfg": ((";", ""), ("#", "")),
    ".py": (("#", ""),),
    ".rb": (("#", ""),),
    ".sh": (("#", ""),),
    ".bash": (("#", ""),),
    ".zsh": (("#", ""),),
    ".js": (("//", ""), ("/*", "*/")),
    ".ts": (("//", ""), ("/*", "*/")),
    ".go": (("//", ""), ("/*", "*/")),
    ".rs": (("//", ""), ("/*", "*/")),
    ".c": (("//", ""), ("/*", "*/")),
    ".h": (("//", ""), ("/*", "*/")),
    ".cpp": (("//", ""), ("/*", "*/")),
    ".java": (("//", ""), ("/*", "*/")),
    ".css": (("/*", "*/"),),
    ".sql": (("--", ""),),
    ".tex": (("%", ""),),
    ".xml": (("<!--", "-->"),),
}

STRUCTURED_TEXT_FRONT_MATTER = {
    ".md": ("---", "+++"),
    ".markdown": ("---", "+++"),
}

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _valid_c2pa_reference(value: str) -> Tuple[bool, Optional[str]]:
    """A manifest block must carry an external URL or a C2PA data URI."""
    stripped = value.strip()
    if not stripped:
        return False, "The manifest block is empty."
    if stripped.startswith(C2PA_DATA_URI_PREFIX):
        payload = stripped[len(C2PA_DATA_URI_PREFIX):]
        if not payload:
            return False, "The data URI carries no base64 payload."
        if not _BASE64_RE.match(payload):
            return False, "The data URI payload is not valid base64."
        if len(payload) % 4 != 0:
            return False, "The data URI payload has an invalid base64 length."
        try:
            base64.b64decode(payload.encode("ascii"), validate=True)
        except (ValueError, TypeError):
            return False, "The data URI payload is not valid base64."
        return True, None
    if stripped.startswith("https://") or stripped.startswith("http://"):
        if len(stripped.split()) != 1:
            return False, "The manifest URL contains whitespace."
        import urllib.parse
        parsed = urllib.parse.urlparse(stripped)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False, "The manifest URL is incomplete."
        return True, None
    if stripped.startswith("data:"):
        return False, "The data URI does not declare the application/c2pa media type."
    return False, "The manifest block is neither an external URL nor a C2PA data URI."


def find_c2pa_structured_text(text: str, suffix: str) -> Optional[Dict[str, Any]]:
    """Locate an ASCII-armoured C2PA manifest block in structured text.

    Handles both normative forms: one complete host-language comment line, and
    a multi-line block inside supported front matter. The host syntax is
    validated before the delimiters can become a carrier candidate.

    Returns ``None`` when no delimiter appears at all. Otherwise the record's
    ``conforming`` flag says whether the arrangement and contents are valid;
    a malformed block is never positive evidence.
    """
    suffix = suffix.lower()
    if suffix not in STRUCTURED_TEXT_COMMENT_FORMS and suffix not in STRUCTURED_TEXT_FRONT_MATTER:
        return None
    begins = [m.start() for m in re.finditer(re.escape(C2PA_ARMOUR_BEGIN), text)]
    ends = [m.start() for m in re.finditer(re.escape(C2PA_ARMOUR_END), text)]
    if not begins and not ends:
        return None

    record = {
        "begin_count": len(begins),
        "end_count": len(ends),
        "offset": begins[0] if begins else ends[0],
        "reference_kind": None,
        "carrier_candidate": False,
        "conforming": False,
        "structure": "MALFORMED",
        "reason": None,
    }

    lines = text.splitlines(keepends=True)

    # A.9 single-line form: both delimiters and the reference must be inside
    # one syntactically valid comment for the host format.
    comment_reference = None
    for raw_line in lines:
        line = raw_line.rstrip("\r\n").strip()
        for prefix, terminator in STRUCTURED_TEXT_COMMENT_FORMS.get(suffix, ()):
            if not line.startswith(prefix):
                continue
            if terminator and not line.endswith(terminator):
                continue
            content = line[len(prefix):]
            if terminator:
                content = content[:-len(terminator)]
            content = content.strip()
            if content.startswith(C2PA_ARMOUR_BEGIN) or content.startswith(C2PA_ARMOUR_END):
                record["carrier_candidate"] = True
            if (content.startswith(C2PA_ARMOUR_BEGIN) and
                    content.endswith(C2PA_ARMOUR_END) and
                    content.count(C2PA_ARMOUR_BEGIN) == 1 and
                    content.count(C2PA_ARMOUR_END) == 1):
                start = content.find(C2PA_ARMOUR_BEGIN) + len(C2PA_ARMOUR_BEGIN)
                finish = content.find(C2PA_ARMOUR_END, start)
                if finish >= start:
                    comment_reference = content[start:finish].strip()
            break

    # A.9 front-matter form: the file must start with the host fence, the
    # delimiters must each occupy their own line inside it, and the reference
    # must be the sole non-empty line between them.
    front_reference = None
    if lines and suffix in STRUCTURED_TEXT_FRONT_MATTER:
        first = lines[0].lstrip("\ufeff").strip()
        if first in STRUCTURED_TEXT_FRONT_MATTER[suffix]:
            closing = next((i for i in range(1, len(lines)) if lines[i].strip() == first), None)
            if closing is not None:
                inside = [line.strip() for line in lines[1:closing]]
                if C2PA_ARMOUR_BEGIN in inside or C2PA_ARMOUR_END in inside:
                    record["carrier_candidate"] = True
                if inside.count(C2PA_ARMOUR_BEGIN) == 1 and inside.count(C2PA_ARMOUR_END) == 1:
                    start = inside.index(C2PA_ARMOUR_BEGIN)
                    finish = inside.index(C2PA_ARMOUR_END)
                    between = [line for line in inside[start + 1:finish] if line]
                    if finish > start and len(between) == 1:
                        front_reference = between[0]

    if not record["carrier_candidate"]:
        record["structure"] = "NOT_C2PA"
        record["reason"] = (
            "The delimiters are readable text outside the host format's comment or front matter."
        )
        return record

    if len(begins) > 1 or len(ends) > 1:
        record["reason"] = "Multiple C2PA manifest blocks are present; at most one is permitted."
        return record
    if not begins:
        record["reason"] = "An end delimiter is present without a begin delimiter."
        return record
    if not ends:
        record["reason"] = "The manifest block has no end delimiter."
        return record
    if ends[0] < begins[0]:
        record["reason"] = "The delimiters are reversed."
        return record

    reference = comment_reference if comment_reference is not None else front_reference
    if reference is None:
        record["reason"] = "The manifest block does not use a conforming single-line comment or front-matter form."
        return record

    valid, why = _valid_c2pa_reference(reference)
    if not valid:
        record["reason"] = why
        return record

    record["reference_kind"] = (
        "data-uri" if reference.strip().startswith(C2PA_DATA_URI_PREFIX) else "url")
    record["conforming"] = True
    record["structure"] = "CONFORMING"
    record["reason"] = (
        "A well-formed manifest block is present. Structural presence is not validity."
    )
    return record


# C2PA 2.4 A.7 defines exactly `application/c2pa` for an inline store.
HTML_C2PA_SCRIPT_TYPES = ("application/c2pa",)

def locate_html_c2pa(head: bytes) -> Dict[str, Any]:
    """Structurally locate C2PA carriers in an HTML document's head element.

    Conservative by construction: only the head element is inspected, the
    script type must match a normative media type exactly, and `rel` is
    treated as a token list. A document whose head cannot be delimited yields
    an incompleteness reason rather than a clean negative.
    """
    result = {"markers": [], "incomplete_reason": None, "script_count": 0, "link_count": 0}

    class C2PAHTMLParser(HTMLParser):
        def __init__(self):
            HTMLParser.__init__(self, convert_charrefs=True)
            self.in_head = False
            self.saw_head = False
            self.closed_head = False
            self.script_media = None
            self.script_data = []

        def handle_starttag(self, tag, attrs):
            lowered = tag.lower()
            attributes = {str(key).lower(): (value or "").strip() for key, value in attrs}
            if lowered == "head":
                self.in_head = True
                self.saw_head = True
                return
            if not self.in_head:
                return
            if lowered == "script":
                media = attributes.get("type", "").lower().strip()
                if media in HTML_C2PA_SCRIPT_TYPES:
                    self.script_media = media
                    self.script_data = []
                    result["script_count"] += 1
            elif lowered == "link":
                rel_tokens = {token.lower() for token in attributes.get("rel", "").split()}
                if "c2pa-manifest" in rel_tokens:
                    result["link_count"] += 1
                    if attributes.get("href"):
                        result["markers"].append(_marker(
                            "HTML head <link rel=c2pa-manifest>",
                            "linked manifest store", "STRUCTURAL"))
                    else:
                        result["markers"].append(_marker(
                            "HTML head <link rel=c2pa-manifest> without href",
                            "incomplete linked manifest reference", "MODERATE"))

        def handle_data(self, data):
            if self.in_head and self.script_media is not None:
                self.script_data.append(data)

        def handle_endtag(self, tag):
            lowered = tag.lower()
            if lowered == "script" and self.script_media is not None:
                encoded = "".join(self.script_data).strip().encode("ascii", "replace")
                valid = False
                if encoded and b"?" not in encoded:
                    try:
                        base64.b64decode(encoded, validate=True)
                        valid = True
                    except (ValueError, TypeError):
                        pass
                result["markers"].append(_marker(
                    "HTML head <script type={0}>".format(self.script_media),
                    "embedded manifest store" if valid else
                    "malformed inline manifest: empty or invalid Base64",
                    "STRUCTURAL" if valid else "MODERATE"))
                self.script_media = None
                self.script_data = []
            elif lowered == "head" and self.in_head:
                if self.script_media is not None:
                    result["markers"].append(_marker(
                        "HTML head <script type={0}>".format(self.script_media),
                        "malformed inline manifest: script element is not closed", "MODERATE"))
                    self.script_media = None
                self.in_head = False
                self.closed_head = True

    parser = C2PAHTMLParser()
    try:
        parser.feed(head.decode("utf-8", "replace"))
        parser.close()
    except (ValueError, TypeError):
        pass
    if not parser.saw_head or not parser.closed_head:
        result["incomplete_reason"] = (
            "The HTML head element could not be delimited within the inspected bytes, "
            "so a complete negative conclusion is not supported."
        )

    if result["script_count"] + result["link_count"] > 1:
        result["markers"].append(_marker(
            "HTML head", "multiple C2PA manifest elements present", "MODERATE"))
    return result


def locate_c2pa_evidence(path: pathlib.Path, head: bytes, fmt: str) -> Dict[str, Any]:
    """Locate C2PA evidence structurally.

    Returns markers with a confidence of STRUCTURAL (found at a position the
    C2PA specification defines), MODERATE (format-appropriate key or namespace),
    SIDECAR, or MENTION (the literal string appears in human-readable text and
    carries no evidentiary weight at all).
    """
    markers: List[Dict[str, str]] = []
    evidence_incomplete: List[str] = []

    if fmt == "PNG":
        for name, payload, _ in iter_png_chunks(head):
            if name == "caBX":
                markers.append(_marker("PNG caBX chunk", "embedded manifest store", "STRUCTURAL"))
            elif name in ("iTXt", "tEXt") and b"c2pa" in payload[:128].lower():
                markers.append(_marker("PNG {0} chunk".format(name), "C2PA reference in text chunk", "MODERATE"))

    elif fmt == "JPEG":
        for marker_id, payload, _ in iter_jpeg_segments(head):
            if marker_id == 0xEB and payload[:2] == b"JP":  # APP11 JUMBF
                markers.append(_marker("JPEG APP11 segment", "JUMBF box", "STRUCTURAL"))
            elif marker_id == 0xE1 and b"c2pa" in payload[:2048].lower() and b"xmpmeta" in payload[:512].lower():
                markers.append(_marker("JPEG APP1 XMP", "C2PA reference in XMP", "MODERATE"))

    elif fmt.startswith("BMFF"):
        for box_type, payload, _, _ in iter_bmff_boxes(head):
            if box_type == "uuid" and payload[:16] == C2PA_BMFF_UUID:
                markers.append(_marker("BMFF uuid box", "C2PA manifest box", "STRUCTURAL"))
            elif box_type == "jumb":
                markers.append(_marker("BMFF jumb box", "JUMBF box", "STRUCTURAL"))

    elif fmt == "WEBP":
        for name, _, _ in iter_riff_chunks(head):
            if name.upper() == "C2PA":
                markers.append(_marker("WebP C2PA chunk", "embedded manifest store", "STRUCTURAL"))

    elif fmt == "TIFF":
        walked = walk_tiff(head)
        last_ifd = "IFD{0}".format(walked["main_ifd_count"] - 1)
        main_entry_counts: Dict[str, int] = {}
        for entry_name, _, _, _, _ in walked["entries"]:
            if entry_name.startswith("IFD"):
                main_entry_counts[entry_name] = main_entry_counts.get(entry_name, 0) + 1
        for name, tag, field_type, value_count, value_or_offset in walked["entries"]:
            if tag != C2PA_TIFF_TAG:
                continue
            # C2PA 2.4 A.3.6: type 7 (UNDEFINED) carrying the manifest store.
            storage_valid = value_count <= 4 or value_or_offset + value_count <= len(head)
            placement_valid = (
                name == last_ifd and
                (walked["main_ifd_count"] == 1 or main_entry_counts.get(name) == 1)
            )
            if placement_valid and field_type == 7 and value_count > 0 and storage_valid:
                markers.append(_marker(
                    "TIFF {0} tag 0x{1:04X}".format(name, C2PA_TIFF_TAG),
                    "embedded manifest store", "STRUCTURAL"))
            else:
                markers.append(_marker(
                    "TIFF {0} tag 0x{1:04X}".format(name, C2PA_TIFF_TAG),
                    "C2PA tag outside the normative last IFD or with malformed type/storage",
                    "MODERATE"))
        if not walked["complete"]:
            evidence_incomplete.append(
                "The TIFF main-IFD chain could not be fully traversed: {0}".format(
                    walked["reason"] or "unknown reason"))

    elif fmt == "GIF":
        for kind, _, _ in iter_gif_blocks(head):
            if kind.startswith("application:") and kind[len("application:"):].startswith(
                    C2PA_GIF_APP_ID.decode("ascii")):
                markers.append(_marker(
                    "GIF application extension {0}".format(C2PA_GIF_APP_ID.decode("ascii")),
                    "embedded manifest store", "STRUCTURAL"))
                break

    elif fmt == "PDF":
        # C2PA 2.4 embeds the store as an Associated File: an embedded file
        # stream with subtype application/c2pa and AFRelationship
        # /C2PA_Manifest, referenced from the catalog /AF array.
        has_af = re.search(rb"/AF\s*[\[<]", head) is not None
        has_relationship = re.search(rb"/AFRelationship\s*/C2PA_Manifest", head) is not None
        has_subtype = re.search(rb"/Subtype\s*/application#2Fc2pa", head) is not None or \
            re.search(rb"application/c2pa", head) is not None
        if has_relationship and (has_af or has_subtype):
            markers.append(_marker(
                "PDF associated file /C2PA_Manifest", "embedded manifest store", "STRUCTURAL"))
        elif has_relationship or (has_af and has_subtype):
            markers.append(_marker(
                "PDF associated file reference", "partial C2PA associated-file structure", "MODERATE"))

    elif fmt == "HTML":
        html = locate_html_c2pa(head)
        markers.extend(html["markers"])
        if html["incomplete_reason"]:
            evidence_incomplete.append(html["incomplete_reason"])

    elif fmt == "SVG":
        if re.search(rb"xmlns:c2pa\s*=", head) or re.search(rb"<\s*c2pa:", head):
            markers.append(_marker("SVG c2pa namespace", "C2PA XML namespace", "MODERATE"))

    elif fmt in ("OOXML", "ODF", "ZIP"):
        try:
            import zipfile
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if name.lower().endswith(".c2pa") or "c2pa" in name.lower():
                        markers.append(_marker("archive entry {0}".format(name), "packaged manifest", "MODERATE"))
        except Exception:  # noqa: BLE001 - a malformed archive is not evidence
            pass

    # Text carriers: the C2PA 2.4 A.8 wrapper (variation selectors appended
    # after a ZWNBSP) and the structured-text block sentinel. Both are located
    # by structure or by the binary magic sequence -- never by matching the
    # readable string "C2PA", which is not evidence of anything.
    # Gate on the asset being text, not on `looks_textual`: the structured-text
    # magic sequence legitimately contains a NUL, which `looks_textual` treats
    # as a binary signal and would reject.
    if fmt in ("TEXT", "UNKNOWN") and is_text_asset(path, head):
        decoded = head.decode("utf-8", "replace")

        # A.8 unstructured text: only a structurally complete wrapper counts.
        wrapper = find_c2pa_text_wrapper(decoded)
        if wrapper is not None and wrapper["conforming"]:
            markers.append(_marker(
                "text manifest wrapper at offset {0}".format(wrapper["offset"]),
                "C2PA unstructured-text manifest store", "STRUCTURAL"))
        elif wrapper is not None and wrapper["magic_confirmed"]:
            markers.append(_marker(
                "text manifest wrapper at offset {0}".format(wrapper["offset"]),
                "malformed C2PA text wrapper: {0}".format(wrapper["reason"]), "MODERATE"))

        # A.9 structured text: ASCII-armoured manifest block.
        block = find_c2pa_structured_text(decoded, path.suffix)
        if block is not None and block["conforming"]:
            markers.append(_marker(
                "structured-text manifest block at offset {0}".format(block["offset"]),
                "C2PA {0} manifest reference".format(block["reference_kind"]), "STRUCTURAL"))
        elif block is not None and block.get("carrier_candidate"):
            markers.append(_marker(
                "structured-text manifest block at offset {0}".format(block["offset"]),
                "malformed C2PA manifest block: {0}".format(block["reason"]), "MODERATE"))

    # A detached manifest stored beside the asset.
    for candidate in (path.with_suffix(".c2pa"), path.parent / (path.name + ".c2pa")):
        if candidate.exists() and candidate.is_file():
            markers.append(_marker(candidate.name, "detached sidecar manifest", "SIDECAR"))
            break

    # Literal mentions in human-readable text are recorded separately and never
    # promoted to evidence: a policy document about C2PA is not a signed asset.
    mentions: List[str] = []
    if fmt in ("TEXT", "SVG", "PDF", "UNKNOWN") and looks_textual(head):
        lowered = head.lower()
        for term in (b"c2pa", b"contentauth", b"content credentials"):
            if term in lowered:
                mentions.append(term.decode("ascii"))

    return {"markers": markers, "mentions": mentions,
            "evidence_incomplete": evidence_incomplete}


def presence_from_evidence(evidence: Dict[str, Any], scan_complete: bool, fmt: str) -> str:
    """Map located evidence to a manifest-presence state.

    Only a conforming verifier may return PRESENT; structural bytes support at
    most POSSIBLE. ABSENT requires a complete scan of a format whose C2PA
    carriers are all actually checked -- a recognised container we cannot walk
    exhaustively yields UNKNOWN, never a conclusive clean result.
    """
    if evidence["markers"]:
        return "POSSIBLE"
    if not scan_complete:
        return "UNKNOWN"
    if evidence.get("evidence_incomplete"):
        return "UNKNOWN"
    base = fmt.split(":", 1)[0]
    if base in FULLY_INSPECTABLE:
        return "ABSENT"
    return "UNKNOWN"


def presence_reason(evidence: Dict[str, Any], scan_complete: bool, fmt: str) -> Optional[str]:
    """Explain an inconclusive presence state."""
    if evidence["markers"]:
        return None
    if not scan_complete:
        return "The scan was bounded and did not cover the whole asset."
    if evidence.get("evidence_incomplete"):
        return " ".join(evidence["evidence_incomplete"])
    base = fmt.split(":", 1)[0]
    if base not in FULLY_INSPECTABLE:
        return (
            "Format {0} is recognised but this build does not check every C2PA carrier "
            "the specification defines for it, so absence cannot be asserted."
        ).format(fmt)
    return None


# --------------------------------------------------------------------------
# Text covert channels
# --------------------------------------------------------------------------

EXOTIC_SPACES = {
    0x00A0: "NO-BREAK SPACE", 0x2000: "EN QUAD", 0x2001: "EM QUAD",
    0x2002: "EN SPACE", 0x2003: "EM SPACE", 0x2004: "THREE-PER-EM SPACE",
    0x2005: "FOUR-PER-EM SPACE", 0x2006: "SIX-PER-EM SPACE",
    0x2007: "FIGURE SPACE", 0x2008: "PUNCTUATION SPACE", 0x2009: "THIN SPACE",
    0x200A: "HAIR SPACE", 0x202F: "NARROW NO-BREAK SPACE",
    0x205F: "MEDIUM MATHEMATICAL SPACE", 0x3000: "IDEOGRAPHIC SPACE",
}

BIDI_CONTROLS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}

# Scripts that commonly supply homoglyphs for Latin text.
HOMOGLYPH_SCRIPTS = ("CYRILLIC", "GREEK")


def _channel(kind: str, codepoint: int, name: str, count: int, severity: str, note: str) -> Dict[str, Any]:
    return {
        "channel": kind,
        "codepoint": "U+{0:04X}".format(codepoint),
        "name": name,
        "count": count,
        "severity": severity,
        "note": note,
    }


def scan_covert_channels(text: str) -> Dict[str, Any]:
    """Inventory hidden-data channels in text.

    This is a text-integrity and prompt-injection control. It is explicitly NOT
    a watermark detector: none of these signals identify a model or a vendor,
    and their absence proves nothing about authorship.

    A standards-compliant C2PA unstructured-text manifest (C2PA 2.4 A.8) is
    itself a run of variation selectors after a ZWNBSP. It is recognised and
    excluded here: reporting a signed provenance manifest as a suspicious
    covert channel would defame the standard this pack exists to support.
    """
    wrapper = find_c2pa_text_wrapper(text)
    # Only a structurally complete wrapper is provenance. A run with the wrong
    # magic, a bad version, or a length mismatch stays a hidden-character
    # finding -- otherwise prefixing a payload with U+FEFF would launder it.
    conforming = bool(wrapper and wrapper["conforming"])
    c2pa_span_start = wrapper["offset"] if conforming else None
    if c2pa_span_start is not None:
        scanned = text[:c2pa_span_start]
    else:
        scanned = text

    counts: Dict[int, int] = {}
    for char in scanned:
        counts[ord(char)] = counts.get(ord(char), 0) + 1

    findings: List[Dict[str, Any]] = []
    for codepoint, count in sorted(counts.items()):
        char = chr(codepoint)
        name = unicodedata.name(char, "UNNAMED")
        category = unicodedata.category(char)

        if 0xE0000 <= codepoint <= 0xE007F:
            findings.append(_channel(
                "unicode_tag", codepoint, name, count, "HIGH",
                "Unicode tag characters can smuggle a full ASCII payload past human review.",
            ))
        elif codepoint in BIDI_CONTROLS:
            findings.append(_channel(
                "bidi_control", codepoint, name, count, "HIGH",
                "Bidirectional controls can make rendered text differ from its byte order.",
            ))
        elif 0xFE00 <= codepoint <= 0xFE0F or 0xE0100 <= codepoint <= 0xE01EF:
            findings.append(_channel(
                "variation_selector", codepoint, name, count, "MEDIUM",
                "Variation selectors are invisible and can encode data positionally.",
            ))
        elif codepoint in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
            findings.append(_channel(
                "zero_width", codepoint, name, count, "MEDIUM",
                "Zero-width characters are a common steganographic channel.",
            ))
        elif codepoint in EXOTIC_SPACES:
            findings.append(_channel(
                "exotic_space", codepoint, EXOTIC_SPACES[codepoint], count, "LOW",
                "Non-standard spaces may be stylistic or may encode data.",
            ))
        elif category in ("Cf", "Cc") and char not in "\n\r\t":
            findings.append(_channel(
                "control", codepoint, name, count, "LOW",
                "Uncommon control or format character.",
            ))

    mixed_script = _mixed_script_words(text)
    for word, scripts in mixed_script[:20]:
        findings.append({
            "channel": "mixed_script",
            "codepoint": None,
            "name": "MIXED SCRIPT WORD",
            "count": 1,
            "severity": "MEDIUM",
            "note": "Word mixes {0}; homoglyph substitution can hide or spoof text.".format(", ".join(sorted(scripts))),
            "sample_length": len(word),
        })

    severities = {item["severity"] for item in findings}
    if "HIGH" in severities:
        risk = "HIGH"
    elif "MEDIUM" in severities:
        risk = "MEDIUM"
    elif findings:
        risk = "LOW"
    else:
        risk = "NONE_OBSERVED"

    return {
        "status": "COVERT_CHANNEL_PRESENT" if findings else "NONE_OBSERVED",
        "risk": risk,
        "findings": findings,
        "c2pa_text_manifest": None if wrapper is None else {
            "offset": wrapper["offset"],
            "selector_count": wrapper["selector_count"],
            "magic_confirmed": wrapper["magic_confirmed"],
            "version": wrapper["version"],
            "declared_length": wrapper["declared_length"],
            "payload_bytes": wrapper["payload_bytes"],
            "structure": wrapper["structure"],
            "conforming": wrapper["conforming"],
            "reason": wrapper["reason"],
            "note": (
                "A structurally complete C2PA text manifest wrapper was located and "
                "excluded from covert-channel findings. Structural presence is not "
                "validity; verify it with a conforming verifier."
                if conforming else
                "A trailing hidden-character sequence was found but is NOT a conforming "
                "C2PA text manifest. It remains a covert-channel finding."
            ),
        },
        "interpretation": (
            "These are text-integrity and prompt-injection signals. They are not "
            "watermark evidence, do not identify any model or vendor, and their "
            "absence does not indicate human authorship."
        ),
    }


def _script_of(char: str) -> Optional[str]:
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    for script in ("LATIN",) + HOMOGLYPH_SCRIPTS:
        if name.startswith(script + " "):
            return script
    return None


def _mixed_script_words(text: str) -> List[Tuple[str, set]]:
    results: List[Tuple[str, set]] = []
    for word in re.findall(r"\w{2,}", text, flags=re.UNICODE):
        scripts = set()
        for char in word:
            script = _script_of(char)
            if script:
                scripts.add(script)
        if len(scripts) > 1:
            results.append((word, scripts))
    return results


# --------------------------------------------------------------------------
# c2patool invocation and classification
# --------------------------------------------------------------------------

def resolve_tool(tool_arg: str) -> Optional[str]:
    """Resolve an executable name or path, or return None."""
    if not tool_arg:
        return None
    if pathlib.Path(tool_arg).name == tool_arg:
        found = shutil.which(tool_arg)
        return found
    candidate = pathlib.Path(tool_arg)
    if candidate.is_file():
        return str(candidate)
    return None


MAX_TOOL_OUTPUT = 32 * 1024 * 1024


class ToolOutputTooLarge(Exception):
    """Raised when a verifier exceeds the output ceiling."""


def _drain(stream, sink, limit, overflow, lock):
    """Read a pipe in bounded chunks, stopping once the ceiling is passed.

    Memory is bounded during capture: bytes beyond the limit are counted and
    discarded rather than accumulated, so a verifier that floods gigabytes
    cannot exhaust this process.
    """
    total = 0
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                with lock:
                    overflow.append(True)
                # Keep draining so the child does not block on a full pipe,
                # but stop retaining anything.
                sink_len = sum(len(part) for part in sink)
                if sink_len < limit:
                    sink.append(chunk[:limit - sink_len])
                continue
            sink.append(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def run_tool(command: Sequence[str], timeout: int,
             max_output: int = None) -> Tuple[int, str, str]:
    """Run a subprocess with a real memory ceiling on captured output.

    Output is read incrementally in bounded chunks and decoded with
    replacement, so arbitrary binary never raises and a flooding verifier
    never exhausts memory. Exceeding the ceiling terminates the child and
    raises ``ToolOutputTooLarge``.
    """
    import threading

    if max_output is None:
        max_output = MAX_TOOL_OUTPUT   # resolved at call time
    process = subprocess.Popen(
        list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
    )
    out_parts, err_parts = [], []
    overflow = []
    lock = threading.Lock()
    threads = [
        threading.Thread(target=_drain, args=(process.stdout, out_parts, max_output, overflow, lock)),
        threading.Thread(target=_drain, args=(process.stderr, err_parts, max_output, overflow, lock)),
    ]
    for thread in threads:
        thread.daemon = True
        thread.start()

    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        for thread in threads:
            thread.join(timeout=5)
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    for thread in threads:
        thread.join(timeout=10)

    if overflow:
        raise ToolOutputTooLarge(
            "The verifier produced more than {0} bytes on a single stream.".format(max_output))

    stdout = b"".join(out_parts).decode("utf-8", "replace")
    stderr = b"".join(err_parts).decode("utf-8", "replace")
    return code, stdout, stderr


def parse_tool_json(stdout: str) -> Tuple[Any, Optional[str]]:
    """Parse verifier stdout, tolerating leading diagnostics before the JSON.

    Returns (document, error). A document is only returned when the whole
    remaining text parses; a partial or ambiguous parse is an error, because
    silently reinterpreting corrupt output as evidence is exactly the failure
    this pack exists to prevent.
    """
    if not stdout.strip():
        return None, "Verifier returned no JSON output."
    if "�" in stdout:
        return None, "Verifier stdout was not valid UTF-8."
    try:
        return json.loads(stdout), None
    except ValueError:
        pass
    start = min((i for i in (stdout.find("{"), stdout.find("[")) if i != -1), default=-1)
    if start == -1:
        return None, "Verifier output contained no JSON document."
    try:
        return json.loads(stdout[start:]), None
    except ValueError as error:
        return None, "Verifier output could not be parsed as JSON: {0}".format(error)


VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> Optional[Tuple[int, int, int]]:
    match = VERSION_RE.search(text or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def probe_tool(tool: str, timeout: int) -> Dict[str, Any]:
    """Return version information and whether it meets the supported floor."""
    try:
        code, out, err = run_tool([tool, "-V"], timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"version_text": "UNKNOWN", "version": None, "supported": False,
                "reason": "Could not execute the verifier: {0}".format(error)}
    text = (out or err).strip()
    if code != 0:
        return {"version_text": "UNKNOWN", "version": None, "supported": False,
                "reason": "Verifier did not report a version."}
    version = parse_version(text)
    if version is None:
        return {"version_text": text, "version": None, "supported": False,
                "reason": "Verifier version string was not recognised."}
    if version < MIN_C2PATOOL:
        return {
            "version_text": text,
            "version": ".".join(str(part) for part in version),
            "supported": False,
            "reason": (
                "c2patool {0} is older than the supported minimum {1}; it lacks the "
                "--settings flag and the validation_results summary schema. Upgrade "
                "the verifier rather than trusting a degraded result."
            ).format(text, ".".join(str(part) for part in MIN_C2PATOOL)),
        }
    return {"version_text": text, "version": ".".join(str(part) for part in version),
            "supported": True, "reason": None}


def is_no_manifest_failure(code: int, stderr: str) -> bool:
    """Normalised substring match against known no-manifest renderings."""
    if code == 0:
        return False
    lowered = " ".join(stderr.lower().split())
    return any(signal in lowered for signal in NO_MANIFEST_SIGNALS)


def codes_in(value: Any) -> List[str]:
    found: List[str] = []
    if isinstance(value, dict):
        code = value.get("code")
        if isinstance(code, str):
            found.append(code)
        for key, item in value.items():
            if key != "code":
                found.extend(codes_in(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(codes_in(item))
    return found


def has_manifest(report: Any) -> bool:
    if not isinstance(report, dict):
        return False
    active = report.get("active_manifest")
    manifests = report.get("manifests")
    return isinstance(active, str) and bool(active) and isinstance(manifests, dict) and active in manifests


def validation_evidence(report: Any) -> Optional[Dict[str, Any]]:
    """Extract the c2patool summary schema, or reject an unrecognised shape."""
    if not isinstance(report, dict):
        return None
    state = report.get("validation_state")
    results = report.get("validation_results")
    if state not in ("Valid", "Trusted", "Invalid") or not isinstance(results, dict):
        return None
    active = results.get("activeManifest")
    if not isinstance(active, dict):
        return None
    if not all(isinstance(active.get(key), list) for key in ("success", "informational", "failure")):
        return None
    return {
        "validation_state": state,
        "success_codes": sorted(set(codes_in(active["success"]))),
        "failure_codes": sorted(set(codes_in(active["failure"]))),
    }


def manifest_summary(report: Any) -> Dict[str, Any]:
    """Surface what the active manifest actually claims.

    A caller usually wants to know the generator and whether the asset was
    declared as created or edited, not merely that a signature verified.
    """
    empty = {
        "claim_generator": None,
        "title": None,
        "format": None,
        "signature_alg": None,
        "signature_issuer": None,
        "signature_time": None,
        "actions": [],
        "assertion_labels": [],
        "ingredient_count": 0,
    }
    if not has_manifest(report):
        return empty
    manifest = report["manifests"][report["active_manifest"]]
    if not isinstance(manifest, dict):
        return empty
    signature = manifest.get("signature_info") or {}
    actions: List[str] = []
    labels: List[str] = []
    for assertion in manifest.get("assertions", []) or []:
        if not isinstance(assertion, dict):
            continue
        label = assertion.get("label")
        if isinstance(label, str):
            labels.append(label)
            if label.startswith("c2pa.actions"):
                data = assertion.get("data") or {}
                for entry in (data.get("actions") or []):
                    if isinstance(entry, dict) and isinstance(entry.get("action"), str):
                        actions.append(entry["action"])
    ingredients = manifest.get("ingredients") or []
    return {
        "claim_generator": manifest.get("claim_generator"),
        "title": manifest.get("title"),
        "format": manifest.get("format"),
        "signature_alg": signature.get("alg") if isinstance(signature, dict) else None,
        "signature_issuer": signature.get("issuer") if isinstance(signature, dict) else None,
        "signature_time": signature.get("time") if isinstance(signature, dict) else None,
        "actions": sorted(set(actions)),
        "assertion_labels": sorted(set(labels)),
        "ingredient_count": len(ingredients) if isinstance(ingredients, list) else 0,
    }


def classify(report: Any, trust_checked: bool = False, exit_code: int = 0) -> Dict[str, Any]:
    """Classify integrity and signer trust as independent dimensions."""
    manifest = has_manifest(report)
    evidence = validation_evidence(report)
    base = {
        "manifest_presence": "ABSENT",
        "integrity": "NOT_VERIFIED",
        "signer_trust": "NOT_CHECKED",
        "validation_state": None,
        "success_codes": [],
        "failure_codes": [],
        "schema_recognized": evidence is not None,
    }
    if not manifest:
        return base
    if evidence is None:
        base.update({
            "manifest_presence": "PRESENT",
            "integrity": "UNKNOWN",
            "signer_trust": "UNKNOWN" if trust_checked else "NOT_CHECKED",
            "schema_recognized": False,
        })
        return base

    state = str(evidence["validation_state"])
    success = set(evidence["success_codes"])
    failure = list(evidence["failure_codes"])
    only_untrusted = bool(failure) and all(code == "signingCredential.untrusted" for code in failure)
    positive = REQUIRED_INTEGRITY_CODES.issubset(success)

    if state == "Invalid":
        integrity = "INVALID"
    elif state in ("Valid", "Trusted") and positive and exit_code == 0 and (not failure or only_untrusted):
        integrity = "VALID"
    else:
        integrity = "UNKNOWN"

    if not trust_checked:
        trust = "NOT_CHECKED"
    elif state == "Trusted" and "signingCredential.trusted" in success and not failure:
        trust = "TRUSTED"
    elif state == "Valid" and only_untrusted:
        trust = "UNTRUSTED"
    else:
        trust = "UNKNOWN"

    base.update({
        "manifest_presence": "PRESENT",
        "integrity": integrity,
        "signer_trust": trust,
        "validation_state": state,
        "success_codes": sorted(success),
        "failure_codes": failure,
        "schema_recognized": True,
    })
    return base


def settings_file(directory: str, allow_network: bool) -> str:
    path = pathlib.Path(directory) / "c2pa-settings.json"
    path.write_text(json.dumps({"verify": {"remote_manifest_fetch": bool(allow_network)}}), encoding="utf-8")
    return str(path)


def run_report(tool: str, asset: pathlib.Path, timeout: int, allow_network: bool,
               trust_anchors: Optional[str] = None) -> Tuple[int, str, str]:
    """Run c2patool over an asset with network access disabled by default."""
    with tempfile.TemporaryDirectory(prefix="provenance-core-") as directory:
        command = [tool, "--settings", settings_file(directory, allow_network), str(asset)]
        if trust_anchors:
            command += ["trust", "--trust_anchors={0}".format(trust_anchors)]
        return run_tool(command, timeout)


__all__ = [name for name in dir() if not name.startswith("_")]
