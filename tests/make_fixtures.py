#!/usr/bin/env python3
"""Generate real binary fixtures for the test suite.

Every fixture is a byte-accurate container built with the standard library, so
the parsers are exercised against real structure rather than synthetic dicts.
Run: python3 tests/make_fixtures.py
"""

from __future__ import annotations

import json
import pathlib
import struct
import zipfile
import zlib

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


# --------------------------------------------------------------------------
# TIFF / EXIF builders
# --------------------------------------------------------------------------

def tiff_with_gps(in_ifd1: bool = False) -> bytes:
    """Little-endian TIFF. GPS pointer lives in IFD0 or only in IFD1."""
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    gps_ifd_offset = 200

    def ifd(entries, next_offset):
        out = struct.pack("<H", len(entries))
        for tag, ftype, count, value in entries:
            out += struct.pack("<HHI", tag, ftype, count) + struct.pack("<I", value)
        out += struct.pack("<I", next_offset)
        return out

    gps_entries = [
        (0x0001, 2, 2, 0x004E),          # GPSLatitudeRef "N"
        (0x0002, 5, 3, 260),             # GPSLatitude
        (0x0003, 2, 2, 0x0045),          # GPSLongitudeRef "E"
        (0x0004, 5, 3, 284),             # GPSLongitude
    ]
    gps_block = ifd(gps_entries, 0)

    if in_ifd1:
        ifd0_entries = [
            (0x010F, 2, 6, 0x0000),      # Make
            (0x0131, 2, 6, 0x0000),      # Software
        ]
        ifd1_entries = [(0x8825, 4, 1, gps_ifd_offset)]
        ifd0_block = ifd(ifd0_entries, 100)
        body = bytearray(b"\x00" * 400)
        body[0:len(ifd0_block)] = ifd0_block
        ifd1_block = ifd(ifd1_entries, 0)
        body[100 - 8:100 - 8 + len(ifd1_block)] = ifd1_block
        body[gps_ifd_offset - 8:gps_ifd_offset - 8 + len(gps_block)] = gps_block
        return header + bytes(body)

    ifd0_entries = [
        (0x010F, 2, 6, 0x0000),
        (0x8825, 4, 1, gps_ifd_offset),
    ]
    ifd0_block = ifd(ifd0_entries, 0)
    body = bytearray(b"\x00" * 400)
    body[0:len(ifd0_block)] = ifd0_block
    body[gps_ifd_offset - 8:gps_ifd_offset - 8 + len(gps_block)] = gps_block
    return header + bytes(body)


def exif_payload(in_ifd1: bool = False) -> bytes:
    return b"Exif\x00\x00" + tiff_with_gps(in_ifd1)


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------

def png_chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))


def build_png(extra_chunks=()) -> bytes:
    idat = zlib.compress(b"\x00" + b"\xff\x00\x00" * 4)
    out = b"\x89PNG\r\n\x1a\n"
    out += png_chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 1, 8, 2, 0, 0, 0))
    for kind, payload in extra_chunks:
        out += png_chunk(kind, payload)
    out += png_chunk(b"IDAT", idat)
    out += png_chunk(b"IEND", b"")
    return out


# --------------------------------------------------------------------------
# JPEG
# --------------------------------------------------------------------------

def jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def iptc_app13() -> bytes:
    def dataset(number: int, value: bytes) -> bytes:
        return b"\x1c\x02" + bytes([number]) + struct.pack(">H", len(value)) + value

    iim = (
        dataset(80, b"Alice Example")      # By-line
        + dataset(90, b"Tallinn")          # City
        + dataset(101, b"Estonia")         # Country
        + dataset(120, b"A private caption")  # Caption
    )
    resource = b"8BIM" + struct.pack(">H", 0x0404) + b"\x00\x00" + struct.pack(">I", len(iim)) + iim
    if len(iim) % 2:
        resource += b"\x00"
    return b"Photoshop 3.0\x00" + resource


def build_jpeg(segments=()) -> bytes:
    out = b"\xff\xd8"
    for marker, payload in segments:
        out += jpeg_segment(marker, payload)
    # Minimal scan so parsers terminate naturally.
    out += b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    out += b"\x00" * 16
    out += b"\xff\xd9"
    return out


# --------------------------------------------------------------------------
# WebP / RIFF
# --------------------------------------------------------------------------

def riff_chunk(name: bytes, payload: bytes) -> bytes:
    out = name + struct.pack("<I", len(payload)) + payload
    if len(payload) % 2:
        out += b"\x00"
    return out


def build_webp(chunks=()) -> bytes:
    body = b"WEBP"
    body += riff_chunk(b"VP8 ", b"\x00" * 16)
    for name, payload in chunks:
        body += riff_chunk(name, payload)
    return b"RIFF" + struct.pack("<I", len(body)) + body


# --------------------------------------------------------------------------
# BMFF
# --------------------------------------------------------------------------

C2PA_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")


def bmff_box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + kind + payload


def build_mp4(with_c2pa: bool = False, with_location: bool = False) -> bytes:
    out = bmff_box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2mp41")
    if with_c2pa:
        out += bmff_box(b"uuid", C2PA_UUID + b"\x00fake-manifest-store")
    udta = b""
    if with_location:
        udta += bmff_box(b"\xa9xyz", b"\x00\x0d\x15\x00+59.4370+024.7536/")
    if udta:
        out += bmff_box(b"moov", bmff_box(b"udta", udta))
    else:
        out += bmff_box(b"moov", b"")
    return out


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# C2PA carriers defined by the 2.4 specification
# --------------------------------------------------------------------------

C2PA_TIFF_TAG = 0xCD41
C2PA_TEXT_MAGIC = "C2PATXT\x00"


def tiff_with_c2pa_tag() -> bytes:
    """TIFF carrying a manifest store in private tag 0xCD41."""
    store = b"\x00fake-jumbf-manifest-store"
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    entries = [
        (0x010F, 2, 6, 0x0000),
        (C2PA_TIFF_TAG, 7, len(store), 200),  # UNDEFINED, offset-based
    ]
    ifd = struct.pack("<H", len(entries))
    for tag, ftype, count, value in entries:
        ifd += struct.pack("<HHI", tag, ftype, count) + struct.pack("<I", value)
    ifd += struct.pack("<I", 0)
    body = bytearray(b"\x00" * 400)
    body[0:len(ifd)] = ifd
    body[200 - 8:200 - 8 + len(store)] = store
    return header + bytes(body)


def gif_with_c2pa_extension(include_c2pa: bool = True) -> bytes:
    """GIF carrying a manifest store in a C2PA_GIF application extension."""
    out = b"GIF89a"
    out += struct.pack("<HH", 4, 1) + bytes([0x00, 0x00, 0x00])  # no global colour table
    if include_c2pa:
        store = b"\x00fake-jumbf-store"
        # Application Extension: 0x21 0xFF, block size 11, 8-byte id + 3-byte auth
        out += b"\x21\xff\x0b" + b"C2PA_GIF" + b"1.0"
        while store:
            chunk, store = store[:255], store[255:]
            out += bytes([len(chunk)]) + chunk
        out += b"\x00"
    # A benign comment extension so the walker has something else to see.
    out += b"\x21\xfe\x05hello\x00"
    out += b"\x3b"
    return out


def pdf_with_associated_file() -> bytes:
    """PDF carrying a manifest as an Associated File with /C2PA_Manifest."""
    return (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R/AF[4 0 R]>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 99 99]>>endobj\n"
        b"4 0 obj<</Type/Filespec/AFRelationship/C2PA_Manifest"
        b"/F(manifest.c2pa)/EF<</F 5 0 R>>>>endobj\n"
        b"5 0 obj<</Type/EmbeddedFile/Subtype/application#2Fc2pa/Length 24>>"
        b"stream\n\x00fake-jumbf-store-bytes\nendstream endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def _encode_variation_selectors(payload: bytes) -> str:
    out = []
    for byte in payload:
        out.append(chr(0xFE00 + byte) if byte < 16 else chr(0xE0100 + byte - 16))
    return "".join(out)


def text_with_c2pa_wrapper() -> bytes:
    """C2PA 2.4 A.8 unstructured-text manifest: ZWNBSP + variation selectors."""
    store = C2PA_TEXT_MAGIC.encode("latin-1") + b"\x01" + b"fake-jumbf-manifest-store"
    body = "A signed article with ordinary prose and nothing hidden in the body.\n"
    return (body + "﻿" + _encode_variation_selectors(store)).encode("utf-8")


def structured_text_with_c2pa_block() -> bytes:
    """Structured text (Markdown) carrying the text-manifest magic sentinel."""
    return (
        "# Release notes\n\n"
        "Ordinary Markdown content.\n\n"
        "<!-- " + C2PA_TEXT_MAGIC + "AAAAfake-store -->\n"
    ).encode("utf-8")



# --------------------------------------------------------------------------
# C2PA 2.4 A.8 unstructured-text wrapper (magic + version + BE length + store)
# --------------------------------------------------------------------------

C2PA_TEXT_MAGIC = b"C2PATXT\x00"


def _vs(payload: bytes) -> str:
    return "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in payload)


def text_wrapper(store=b"fake-jumbf-manifest-store", magic=C2PA_TEXT_MAGIC,
                 version=1, declared=None, truncate_header=False) -> bytes:
    """Build an A.8 wrapper, optionally malformed in one specific way."""
    body = "A signed article with ordinary prose and nothing hidden in the body.\n"
    if truncate_header:
        decoded = magic + bytes([version]) + b"\x00\x00"      # length field cut short
    else:
        length = len(store) if declared is None else declared
        decoded = magic + bytes([version]) + struct.pack(">I", length) + store
    return (body + "\ufeff" + _vs(decoded)).encode("utf-8")


def plain_variation_selectors() -> bytes:
    """An ordinary hidden-character run after ZWNBSP - not a C2PA wrapper."""
    return ("Ordinary text.\n" + "\ufeff" + _vs(bytes(range(8)))).encode("utf-8")


# --------------------------------------------------------------------------
# C2PA 2.4 A.9 structured text: ASCII-armoured manifest block
# --------------------------------------------------------------------------

BEGIN = "-----BEGIN C2PA MANIFEST-----"
END = "-----END C2PA MANIFEST-----"
MANIFEST_URL = "https://example.org/manifests/article.c2pa"
DATA_URI = "data:application/c2pa;base64,QzJQQWZha2VtYW5pZmVzdHN0b3JlAAAA"


def md_single_line(reference=MANIFEST_URL) -> bytes:
    return ("# Release notes\n\nOrdinary Markdown.\n\n"
            "<!-- {0}{1}{2} -->\n".format(BEGIN, reference, END)).encode("utf-8")


def md_front_matter(reference=MANIFEST_URL) -> bytes:
    return ("---\n"
            "title: Release notes\n"
            "{0}\n"
            "{1}\n"
            "{2}\n"
            "---\n\n"
            "Ordinary Markdown body.\n".format(BEGIN, reference, END)).encode("utf-8")


def md_missing_end() -> bytes:
    return ("# Notes\n\n<!-- {0}{1} -->\n".format(BEGIN, MANIFEST_URL)).encode("utf-8")


def md_reversed() -> bytes:
    return ("# Notes\n\n<!-- {0}{1}{2} -->\n".format(END, MANIFEST_URL, BEGIN)).encode("utf-8")


def md_empty_reference() -> bytes:
    return ("# Notes\n\n<!-- {0}{1} -->\n".format(BEGIN, END)).encode("utf-8")


def md_invalid_reference() -> bytes:
    return ("# Notes\n\n<!-- {0}ftp://example.org/x.c2pa{1} -->\n".format(BEGIN, END)).encode("utf-8")


def md_invalid_data_uri() -> bytes:
    return ("# Notes\n\n<!-- {0}data:application/c2pa;base64,!!!not base64!!!{1} -->\n"
            .format(BEGIN, END)).encode("utf-8")


def md_multiple_blocks() -> bytes:
    block = "<!-- {0}{1}{2} -->\n".format(BEGIN, MANIFEST_URL, END)
    return ("# Notes\n\n" + block + "\nMore text.\n\n" + block).encode("utf-8")


def md_discusses_delimiters() -> bytes:
    return ("# How C2PA structured text works\n\n"
            "A manifest block opens with a line reading BEGIN C2PA MANIFEST in\n"
            "ASCII armour and closes with the matching END line. This document\n"
            "only describes the format; it carries no manifest of its own.\n").encode("utf-8")


def md_quotes_complete_block() -> bytes:
    """Exact delimiters and a URL in prose are a mention, not a carrier."""
    return ("# Documentation example\n\n"
            "The following lines show the wire spelling but are not in front matter "
            "or a comment:\n\n"
            "{0}\n{1}\n{2}\n".format(BEGIN, MANIFEST_URL, END)).encode("utf-8")


def md_comment_discusses_complete_block() -> bytes:
    return ("# Documentation example\n\n"
            "<!-- Example spelling: {0}{1}{2} -->\n"
            .format(BEGIN, MANIFEST_URL, END)).encode("utf-8")


def json_with_block() -> bytes:
    """JSON has neither comments nor front matter and is not an A.9 carrier."""
    return json.dumps({
        "example": "{0} {1} {2}".format(BEGIN, MANIFEST_URL, END),
    }, sort_keys=True).encode("utf-8")


def plain_text_with_block() -> bytes:
    """Unstructured plain text uses the A.8 wrapper, not A.9 armour."""
    return ("{0}\n{1}\n{2}\n".format(BEGIN, MANIFEST_URL, END)).encode("utf-8")


def commented_block(prefix: str, suffix: str = "") -> bytes:
    return ("{0} {1}{2}{3} {4}\n".format(
        prefix, BEGIN, MANIFEST_URL, END, suffix)).encode("utf-8")


def csv_with_block() -> bytes:
    """CSV is not an eligible structured-text carrier."""
    return ("id,note\n1,{0}{1}{2}\n".format(BEGIN, MANIFEST_URL, END)).encode("utf-8")


# --------------------------------------------------------------------------
# TIFF main-IFD chains
# --------------------------------------------------------------------------

C2PA_TIFF_TAG = 0xCD41


def tiff_chain(ifd_count=1, tag_in=None, field_type=7, cycle=False,
               bad_next=False, truncate_last=False, bad_store_offset=False,
               force_coentry=False) -> bytes:
    """Build a little-endian TIFF with a main-IFD chain of `ifd_count` IFDs.

    `tag_in` is the zero-based index of the IFD carrying tag 0xCD41.
    """
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    store = b"\x00fake-jumbf-manifest-store"
    store_at = 1024

    stride = 64
    offsets = [8 + i * stride for i in range(ifd_count)]
    body = bytearray(b"\x00" * 2048)

    for index, offset in enumerate(offsets):
        entries = [(0x0131, 2, 6, 0)]  # Software, so ordinary IFDs have content
        if tag_in == index and index == ifd_count - 1 and ifd_count > 1 and not force_coentry:
            entries = []  # In a multi-IFD TIFF, C2PA must be alone in the last IFD.
        if tag_in is not None and index == tag_in:
            value = 0x7FFFFFFF if bad_store_offset else store_at
            entries.append((C2PA_TIFF_TAG, field_type, len(store), value))
        entries.sort()
        block = struct.pack("<H", len(entries))
        for tag, ftype, count, value in entries:
            block += struct.pack("<HHI", tag, ftype, count) + struct.pack("<I", value)

        if index == ifd_count - 1:
            if cycle:
                nxt = offsets[0]
            elif bad_next:
                nxt = 0x7FFFFFFF
            else:
                nxt = 0
        else:
            nxt = offsets[index + 1]
        block += struct.pack("<I", nxt)

        start = offset - 8
        body[start:start + len(block)] = block

    body[store_at - 8:store_at - 8 + len(store)] = store
    data = header + bytes(body)
    if truncate_last:
        data = data[:offsets[-1] - 8 + 6]
    return data


# --------------------------------------------------------------------------
# HTML carriers (C2PA 2.4 A.7)
# --------------------------------------------------------------------------

def html(head_inner: str, body_inner: str = "<p>An article.</p>") -> bytes:
    return ("<!doctype html><html><head>{0}</head><body>{1}</body></html>"
            .format(head_inner, body_inner)).encode("utf-8")


HTML_CASES = {
    "html_c2pa_script.html": html('<script type="application/c2pa">QzJQQWZha2U=</script>'),
    "html_c2pa_script_json.html": html('<script type="application/c2pa+json">{"x":1}</script>'),
    "html_c2pa_script_parameter.html": html(
        '<script type="application/c2pa; charset=us-ascii">QzJQQQ==</script>'),
    "html_c2pa_script_empty.html": html('<script type="application/c2pa"></script>'),
    "html_c2pa_script_bad_base64.html": html(
        '<script type="application/c2pa">not base64 !!!</script>'),
    "html_commented_script.html": html(
        '<!-- <script type="application/c2pa">QzJQQQ==</script> -->'),
    "html_unclosed_script.html": html('<script type="application/c2pa">QzJQQQ=='),
    "html_c2pa_link.html": html('<link rel="c2pa-manifest" href="/m/article.c2pa">'),
    "html_c2pa_link_tokens.html": html('<link rel="preload c2pa-manifest" href="/m/a.c2pa">'),
    "html_c2pa_reordered.html": html("<link href='/m/a.c2pa' REL='c2pa-manifest'>"),
    "html_c2pa_mixed_case.html": html('<SCRIPT  TYPE = "APPLICATION/C2PA" >QzJQQQ==</SCRIPT>'),
    "html_c2pa_multiple.html": html('<script type="application/c2pa">A</script>'
                                    '<link rel="c2pa-manifest" href="/m/a.c2pa">'),
    "html_wrong_mime.html": html('<script type="application/c2pa-manifest-store">A</script>'),
    "html_link_no_href.html": html('<link rel="c2pa-manifest">'),
    "html_manifest_in_body.html": html("<title>t</title>",
                                       '<script type="application/c2pa">A</script>'),
    "html_clean.html": html("<title>Plain</title>"),
    "html_no_head.html": b"<html><p>Fragment with no head element at all.</p></html>",
}

MINIMAL_PDF = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 99 99]>>endobj
4 0 obj<</Author(Alice Example)/Producer(Test Suite)/CreationDate(D:20260813000000Z)>>endobj
trailer<</Root 1 0 R/Info 4 0 R>>
%%EOF
"""

SVG_WITH_METADATA = (
    b'<svg xmlns="http://www.w3.org/2000/svg"><metadata>'
    b"Creator: Alice Example; GPS: 59.437,24.7536</metadata>"
    b"<text>Choose an allocation</text></svg>"
)

SVG_CLEAN = b'<svg xmlns="http://www.w3.org/2000/svg"><text>Choose an allocation</text></svg>'

DOCX_CORE = (
    '<?xml version="1.0"?><cp:coreProperties '
    'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/">'
    "<dc:creator>Alice Example</dc:creator>"
    "<cp:lastModifiedBy>Bob Example</cp:lastModifiedBy>"
    "</cp:coreProperties>"
)


def build_docx(path: pathlib.Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        archive.writestr("docProps/core.xml", DOCX_CORE)
        archive.writestr("word/document.xml", "<document/>")


# --------------------------------------------------------------------------
# Text
# --------------------------------------------------------------------------

COVERT_TEXT = (
    "This looks like ordinary text.\n"
    "Zero width here:​ and a joiner:‍\n"
    "Tag smuggling:\U000e0041\U000e0042\U000e0043\n"
    "Bidi override:‮ reversed ‬\n"
    "Variation selector:️\n"
    "Exotic space and  nbsp\n"
    "Homoglyph: paуpal versus paypal\n"
)

CLEAN_TEXT = "This is entirely ordinary prose with nothing hidden in it at all.\n"

MENTIONS_C2PA = (
    "# Notes on Content Credentials\n\n"
    "This document explains how C2PA manifests work and mentions contentauth "
    "repeatedly, but it is not itself a signed asset.\n"
)


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    written = []

    def write(name: str, data: bytes) -> None:
        (FIXTURES / name).write_bytes(data)
        written.append(name)

    # PNG
    write("png_text_author.png", build_png([(b"tEXt", b"Author\x00Alice Example")]))
    write("png_exif_gps.png", build_png([(b"eXIf", tiff_with_gps())]))
    write("png_c2pa_cabx.png", build_png([(b"caBX", b"\x00fake-jumbf-store")]))
    write("png_clean.png", build_png())

    # JPEG
    write("jpeg_exif_gps.jpg", build_jpeg([(0xE1, exif_payload())]))
    write("jpeg_exif_gps_ifd1.jpg", build_jpeg([(0xE1, exif_payload(in_ifd1=True))]))
    write("jpeg_iptc.jpg", build_jpeg([(0xED, iptc_app13())]))
    write("jpeg_c2pa_app11.jpg", build_jpeg([(0xEB, b"JP\x00\x01\x00\x00\x00\x01jumbfake")]))
    write("jpeg_clean.jpg", build_jpeg())

    # WebP
    write("webp_exif.webp", build_webp([(b"EXIF", tiff_with_gps())]))
    write("webp_c2pa.webp", build_webp([(b"C2PA", b"\x00fake-manifest-store")]))
    write("webp_clean.webp", build_webp())

    # BMFF
    write("mp4_c2pa.mp4", build_mp4(with_c2pa=True))
    write("mp4_location.mp4", build_mp4(with_location=True))
    write("mp4_clean.mp4", build_mp4())

    # --- C2PA carriers from the 2.4 specification -------------------------
    write("gif_c2pa.gif", gif_with_c2pa_extension(True))
    write("gif_clean.gif", gif_with_c2pa_extension(False))
    write("pdf_c2pa_af.pdf", pdf_with_associated_file())

    # A.3.6 TIFF main-IFD chains
    write("tiff_c2pa_one_ifd.tif", tiff_chain(1, tag_in=0))
    write("tiff_c2pa_two_ifd.tif", tiff_chain(2, tag_in=1))
    write("tiff_c2pa_three_ifd.tif", tiff_chain(3, tag_in=2))
    write("tiff_c2pa_first_ifd.tif", tiff_chain(3, tag_in=0))
    write("tiff_clean_multi.tif", tiff_chain(3))
    write("tiff_clean.tif", tiff_chain(1))
    write("tiff_cycle.tif", tiff_chain(2, tag_in=1, cycle=True))
    write("tiff_bad_next.tif", tiff_chain(2, bad_next=True))
    write("tiff_truncated.tif", tiff_chain(3, tag_in=2, truncate_last=True))
    write("tiff_wrong_type.tif", tiff_chain(1, tag_in=0, field_type=2))
    write("tiff_bad_store_offset.tif", tiff_chain(1, tag_in=0, bad_store_offset=True))
    write("tiff_c2pa_last_with_coentry.tif", tiff_chain(
        2, tag_in=1, force_coentry=True))

    # A.7 HTML
    for name, data in sorted(HTML_CASES.items()):
        write(name, data)

    # A.8 unstructured text
    write("text_c2pa_wrapper.txt", text_wrapper())
    write("text_wrapper_bad_magic.txt", text_wrapper(magic=b"XXXXXXX\x00"))
    write("text_wrapper_bad_version.txt", text_wrapper(version=9))
    write("text_wrapper_truncated.txt", text_wrapper(truncate_header=True))
    write("text_wrapper_short_payload.txt", text_wrapper(declared=999))
    write("text_wrapper_long_payload.txt", text_wrapper(declared=4))
    write("text_plain_selectors.txt", plain_variation_selectors())

    # A.9 structured text
    write("text_c2pa_structured.md", md_single_line())
    write("text_c2pa_frontmatter.md", md_front_matter())
    write("text_c2pa_data_uri.md", md_single_line(DATA_URI))
    write("text_c2pa_python.py", commented_block("#"))
    write("text_c2pa_javascript.js", commented_block("//"))
    write("text_c2pa_css.css", commented_block("/*", "*/"))
    write("text_c2pa_xml.xml", commented_block("<!--", "-->"))
    write("text_struct_missing_end.md", md_missing_end())
    write("text_struct_reversed.md", md_reversed())
    write("text_struct_empty.md", md_empty_reference())
    write("text_struct_invalid_uri.md", md_invalid_reference())
    write("text_struct_bad_base64.md", md_invalid_data_uri())
    write("text_struct_multiple.md", md_multiple_blocks())
    write("text_struct_discusses.md", md_discusses_delimiters())
    write("text_struct_quoted_block.md", md_quotes_complete_block())
    write("text_struct_comment_example.md", md_comment_discusses_complete_block())
    write("text_struct_csv.csv", csv_with_block())
    write("text_struct_json.json", json_with_block())
    write("text_struct_plain.txt", plain_text_with_block())

    # Documents
    write("doc_meta.pdf", MINIMAL_PDF)
    write("svg_meta.svg", SVG_WITH_METADATA)
    write("svg_clean.svg", SVG_CLEAN)
    build_docx(FIXTURES / "doc_meta.docx")
    written.append("doc_meta.docx")

    # Text
    write("text_covert.txt", COVERT_TEXT.encode("utf-8"))
    write("text_clean.txt", CLEAN_TEXT.encode("utf-8"))
    write("text_mentions_c2pa.md", MENTIONS_C2PA.encode("utf-8"))

    print("Wrote {0} fixtures to {1}".format(len(written), FIXTURES))
    for name in sorted(written):
        print("  {0}".format(name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
