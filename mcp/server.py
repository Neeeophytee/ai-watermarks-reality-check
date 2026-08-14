#!/usr/bin/env python3
"""Standard-library MCP stdio server exposing every skill as a tool.

Dual-era: speaks both the modern stateless revision (2026-07-28) and the
legacy `initialize` handshake revisions (2025-11-25 and earlier), so it works
with current and older clients on the same process.

Modern behaviour, per the 2026-07-28 specification:
- `server/discover` is implemented (the specification says servers MUST).
- Every request may declare its version in
  `params._meta["io.modelcontextprotocol/protocolVersion"]`.
- An unsupported version returns `UnsupportedProtocolVersionError` (-32022)
  carrying the `supported` list and the `requested` value.

Legacy behaviour is retained: an `initialize` request selects the handshake
semantics of the negotiated revision.

No third-party dependency, matching the rest of the repository.

Run:
    python3 mcp/server.py

Register with an MCP client, for example in claude_desktop_config.json:
    {"mcpServers": {"provenance": {"command": "python3",
     "args": ["/absolute/path/to/mcp/server.py"]}}}
"""

from __future__ import annotations

import io
import json
import pathlib
import sys
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))

# The modern, stateless revision this server prefers.
PROTOCOL_VERSION = "2026-07-28"

# Legacy handshake revisions still accepted via `initialize`.
LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

# `server/discover` advertises per-request (modern-era) revisions only. Legacy
# revisions are negotiated exclusively through `initialize`.
SUPPORTED_VERSIONS = [PROTOCOL_VERSION]

SERVER_INFO = {"name": "ai-watermarks-reality-check", "version": "0.2.0"}

META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"

UNSUPPORTED_PROTOCOL_VERSION = -32022
PARSE_ERROR = -32700
INVALID_REQUEST = -32600

SERVER_CAPABILITIES = {"tools": {}}

INSTRUCTIONS = (
    "Read-only AI provenance auditing. Locate C2PA evidence structurally, verify it "
    "cryptographically with c2patool, measure whether a publishing pipeline preserves it, "
    "audit metadata for privacy exposure, check disclosure records, and run text-provenance "
    "detectors. Nothing here removes marks, and no tool asserts human or AI authorship."
)


METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602


class UnsupportedProtocolVersion(Exception):
    """Raised when a request declares a protocol revision this server lacks."""

    def __init__(self, requested):
        super().__init__("Unsupported protocol version")
        self.requested = requested


class ProtocolError(Exception):
    """A JSON-RPC protocol error: unknown tool, malformed request, bad method.

    The specification distinguishes these from tool execution errors. Unknown
    tools and malformed requests are protocol errors the model cannot fix by
    retrying with different arguments, so they are returned as JSON-RPC errors
    rather than as `isError: true` results.
    """

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def request_meta(request):
    params = request.get("params")
    if not isinstance(params, dict):
        return {}
    meta = params.get("_meta")
    return meta if isinstance(meta, dict) else {}


def check_modern_envelope(request):
    """Validate the per-request protocol fields for a modern request.

    In 2026-07-28 the protocol is stateless: every request carries its own
    version and client capabilities. `protocolVersion` and `clientCapabilities`
    are required; a request missing either is malformed and must be rejected
    with -32602. Nothing is inferred from earlier requests on the connection.

    A request carrying no `_meta` at all is treated as legacy-era traffic and
    served leniently, rather than being silently accepted as conforming modern
    traffic.
    """
    meta = request_meta(request)
    version = meta.get(META_VERSION_KEY)
    if version is None:
        return None  # legacy-era request; not modern traffic

    if not isinstance(version, str):
        raise ProtocolError(INVALID_PARAMS,
                            "_meta['{0}'] must be a string".format(META_VERSION_KEY))
    if version not in SUPPORTED_VERSIONS:
        raise UnsupportedProtocolVersion(version)

    if version == PROTOCOL_VERSION:
        if META_CLIENT_CAPS_KEY not in meta:
            raise ProtocolError(
                INVALID_PARAMS,
                "_meta['{0}'] is required in {1}".format(META_CLIENT_CAPS_KEY, PROTOCOL_VERSION))
        caps = meta.get(META_CLIENT_CAPS_KEY)
        if not isinstance(caps, dict):
            raise ProtocolError(
                INVALID_PARAMS,
                "_meta['{0}'] must be an object".format(META_CLIENT_CAPS_KEY))
        info = meta.get(META_CLIENT_INFO_KEY)
        if info is not None and not isinstance(info, dict):
            raise ProtocolError(
                INVALID_PARAMS,
                "_meta['{0}'] must be an object when present".format(META_CLIENT_INFO_KEY))
    return version


def with_server_info(result):
    """Servers SHOULD identify themselves in every result's `_meta`."""
    if not isinstance(result, dict):
        return result
    meta = dict(result.get("_meta") or {})
    meta[META_SERVER_INFO_KEY] = SERVER_INFO
    result["_meta"] = meta
    return result


def _load(module_name: str, relative: str):
    import importlib.util
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_MODULES = {}


def module(name: str):
    if name not in _MODULES:
        _MODULES[name] = _load(*{
            "inspect": ("mcp_inspect_file", "skills/inspect-content-provenance/scripts/inspect_file.py"),
            "verify": ("mcp_verify_c2pa", "skills/verify-content-credentials/scripts/verify_c2pa.py"),
            "survival": ("mcp_map_survival", "skills/map-provenance-survival/scripts/map_survival.py"),
            "privacy": ("mcp_audit_metadata", "skills/audit-metadata-privacy/scripts/audit_metadata.py"),
            "transparency": ("mcp_check_transparency", "skills/check-ai-transparency/scripts/check_transparency.py"),
            "watermark": ("mcp_detect_watermark", "skills/detect-text-watermark/scripts/detect_text_watermark.py"),
            "frontdoor": ("mcp_audit_provenance", "skills/audit-provenance/scripts/audit_provenance.py"),
        }[name])
    return _MODULES[name]


TOOLS = [
    {
        "name": "audit_provenance",
        "description": (
            "Front door. Answers whether provenance was located, cryptographically verified, "
            "and trusted under a named policy, whether the scan was complete, and what remains "
            "unknown. Composes the other tools; performs no authorship classification."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "c2patool": {"type": "string", "description": "Executable name or absolute path"},
                "trust_anchors": {"type": "string", "description": "PEM trust policy"},
                "allow_network": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "inspect_content_provenance",
        "description": (
            "Inventory a file or string for structurally located C2PA evidence, hashes, and "
            "hidden Unicode channels. Never asserts authorship; a literal mention of C2PA in "
            "text is recorded separately and is not evidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to a file"},
                "text": {"type": "string", "description": "Literal text to inspect instead of a file"},
            },
        },
    },
    {
        "name": "verify_content_credentials",
        "description": (
            "Verify C2PA Content Credentials with the official c2patool, reporting manifest "
            "presence, cryptographic integrity, and signer trust as independent results. "
            "Requires c2patool 0.20.0+."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "c2patool": {"type": "string", "description": "Executable name or absolute path"},
                "trust_anchors": {"type": "string", "description": "PEM file for trust evaluation"},
                "allow_network": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "map_provenance_survival",
        "description": (
            "Compare an original with derivatives to measure whether a publishing pipeline "
            "preserves Content Credentials. Reports observed outcomes, never intent."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["original"],
            "properties": {
                "original": {"type": "string"},
                "derivatives": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Entries shaped LABEL=PATH",
                },
                "derivative_directories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Directories whose visible, non-symlink files are added recursively "
                        "with deterministic relative labels"
                    ),
                },
                "c2patool": {"type": "string"},
                "allow_network": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "audit_metadata_privacy",
        "description": (
            "Audit PNG, JPEG, WebP, BMFF, TIFF, PDF, SVG, OOXML and ODF assets for GPS, "
            "identity, device, software and comment metadata. Read-only; values are redacted."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
        },
    },
    {
        "name": "check_ai_transparency",
        "description": (
            "Check a transparency record for evidence and disclosure gaps. Returns required "
            "gaps separately from advisory review items. Never issues a legal conclusion."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to a record JSON file"},
                "record": {"type": "object", "description": "Inline record object"},
            },
        },
    },
    {
        "name": "detect_text_watermark",
        "description": (
            "Run every available text-provenance detector. Keyed vendor watermarks report "
            "UNVERIFIABLE or UNSUPPORTED because they cannot be checked without the provider's "
            "key. Detects hidden Unicode channels and detached C2PA sidecars locally."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "text": {"type": "string"},
            },
        },
    },
]


TOOL_NAMES = frozenset(tool["name"] for tool in TOOLS)

# Each tool's own base_result constructor, so an MCP execution error returns
# the same schema-valid inconclusive document a CLI caller would receive.
_BASE_RESULT_SOURCE = {
    "audit_provenance": ("frontdoor", "base_result"),
    "inspect_content_provenance": ("inspect", "base_result"),
    "verify_content_credentials": ("verify", "base_result"),
    "map_provenance_survival": ("survival", "base_result"),
    "audit_metadata_privacy": ("privacy", "base_result"),
    "check_ai_transparency": ("transparency", "base_result"),
    "detect_text_watermark": ("watermark", "base_result"),
}


def tool_error_payload(name, error):
    """Build a schema-valid inconclusive result for a failed tool call."""
    key, factory = _BASE_RESULT_SOURCE.get(name, (None, None))
    message = str(error) or error.__class__.__name__
    if key is None:
        return {"status": "UNKNOWN", "tool": name, "reason": message}
    try:
        payload = getattr(module(key), factory)()
        payload["reason"] = message
        return payload
    except Exception:  # noqa: BLE001 - never let error handling raise
        return {"status": "UNKNOWN", "tool": name, "reason": message}


def call_tool(name: str, arguments: dict) -> dict:
    if name == "audit_provenance":
        return module("frontdoor").audit(
            pathlib.Path(arguments["path"]),
            arguments.get("c2patool"),
            arguments.get("trust_anchors"),
            int(arguments.get("timeout", 30)),
            bool(arguments.get("allow_network", False)),
        )

    if name == "inspect_content_provenance":
        mod = module("inspect")
        if arguments.get("text") is not None:
            return mod.inspect_text(arguments["text"], "literal")
        return mod.inspect_path(pathlib.Path(arguments["path"]))

    if name == "verify_content_credentials":
        mod = module("verify")
        return mod.verify_asset(
            pathlib.Path(arguments["path"]),
            arguments.get("c2patool", "c2patool"),
            arguments.get("trust_anchors"),
            int(arguments.get("timeout", 30)),
            bool(arguments.get("allow_network", False)),
        )

    if name == "map_provenance_survival":
        mod = module("survival")
        explicit = [mod.parse_derivative(item) for item in arguments.get("derivatives", [])]
        derivatives = mod.derivatives_from_directories(
            pathlib.Path(arguments["original"]),
            [pathlib.Path(path) for path in arguments.get("derivative_directories", [])],
            existing=explicit,
        )
        return mod.build(
            pathlib.Path(arguments["original"]),
            derivatives,
            arguments.get("c2patool"),
            int(arguments.get("timeout", 30)),
            bool(arguments.get("allow_network", False)),
        )

    if name == "audit_metadata_privacy":
        return module("privacy").audit(pathlib.Path(arguments["path"]))

    if name == "check_ai_transparency":
        mod = module("transparency")
        if arguments.get("record") is not None:
            return mod.check(arguments["record"])
        with open(arguments["path"], encoding="utf-8") as handle:
            return mod.check(json.load(handle))

    if name == "detect_text_watermark":
        mod = module("watermark")
        import provenance_core as core
        if arguments.get("text") is not None:
            return mod.analyse(arguments["text"], "literal", {})
        path = pathlib.Path(arguments["path"])
        core.require_file(path)
        head = core.read_head(path, 8192)
        if not core.is_text_asset(path, head):
            raise ValueError("Not a text asset: {0}".format(path))
        # Must match the CLI and front-door routes exactly: stream the whole
        # file and pass scan metadata, so a bounded read can never be reported
        # as a complete clean result with a prefix hash.
        stream = core.read_text_stream(path)
        return mod.analyse(stream["text"], str(path.resolve()),
                           {"asset_path": str(path.resolve())}, scan_info=stream)

    raise ValueError("Unknown tool: {0}".format(name))


def handle(request: dict):
    method = request.get("method")

    # Modern requests declare their revision per request; reject unknown ones
    # before doing any work. `initialize` is exempt: it is the legacy entry
    # point and negotiates its own version.
    if method != "initialize":
        check_modern_envelope(request)

    if method == "server/discover":
        # Mandatory in the 2026-07-28 revision.
        return with_server_info({
            "resultType": "complete",
            "supportedVersions": SUPPORTED_VERSIONS,
            "capabilities": SERVER_CAPABILITIES,
            "instructions": INSTRUCTIONS,
        })

    if method == "initialize":
        # Legacy era: `initialize` never carries modern per-request metadata.
        # Legacy handshake. The legacy lifecycle requires the server to answer
        # with a version it supports rather than erroring, so that a client
        # with no fall-forward mechanism can still decide what to do.
        params = request.get("params") or {}
        if not isinstance(params, dict):
            raise ProtocolError(INVALID_PARAMS, "initialize requires a params object")
        asked = params.get("protocolVersion")
        capabilities = params.get("capabilities")
        client_info = params.get("clientInfo")
        if not isinstance(asked, str) or not asked:
            raise ProtocolError(INVALID_PARAMS, "initialize requires a string protocolVersion")
        if not isinstance(capabilities, dict):
            raise ProtocolError(INVALID_PARAMS, "initialize requires a capabilities object")
        if not isinstance(client_info, dict):
            raise ProtocolError(INVALID_PARAMS, "initialize requires a clientInfo object")
        if not isinstance(client_info.get("name"), str) or not client_info.get("name"):
            raise ProtocolError(INVALID_PARAMS, "clientInfo requires a non-empty name")
        if not isinstance(client_info.get("version"), str) or not client_info.get("version"):
            raise ProtocolError(INVALID_PARAMS, "clientInfo requires a non-empty version")
        negotiated = asked if asked in LEGACY_VERSIONS else LEGACY_VERSIONS[0]
        return {
            "protocolVersion": negotiated,
            "capabilities": SERVER_CAPABILITIES,
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        }

    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return with_server_info({"resultType": "complete"})

    if method == "tools/list":
        return with_server_info({"resultType": "complete", "tools": TOOLS})

    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict):
            raise ProtocolError(INVALID_PARAMS, "tools/call requires a params object")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise ProtocolError(INVALID_PARAMS, "tools/call requires a string 'name'")
        if name not in TOOL_NAMES:
            raise ProtocolError(INVALID_PARAMS, "Unknown tool: {0}".format(name))
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise ProtocolError(INVALID_PARAMS, "'arguments' must be an object")
        try:
            payload = call_tool(name, arguments)
        except Exception as error:  # noqa: BLE001 - a tool execution error, not a protocol error
            # Return the tool's own schema-valid inconclusive output, so an MCP
            # caller parses the same shape as a CLI caller. Internal tracebacks
            # are never exposed.
            payload = tool_error_payload(name, error)
            return with_server_info({
                "resultType": "complete",
                "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}],
                "structuredContent": payload,
                "isError": True,
            })
        return with_server_info({
            "resultType": "complete",
            "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}],
            "structuredContent": payload,
            "isError": False,
        })

    raise ProtocolError(METHOD_NOT_FOUND, "Unknown method: {0}".format(method))


def serve(stdin=None, stdout=None) -> int:
    """Read JSON-RPC messages from stdin and write responses to stdout.

    Hardened against malformed traffic: a bad message is answered with the
    correct JSON-RPC error and the loop continues. No malformed input can
    terminate the server, and no internal traceback reaches a client.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout

    def emit(message):
        stdout.write(json.dumps(message) + "\n")
        stdout.flush()

    def error(request_id, code, message, data=None):
        payload = {"code": code, "message": message}
        if data is not None:
            payload["data"] = data
        emit({"jsonrpc": "2.0", "id": request_id, "error": payload})

    for line in stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except ValueError:
            error(None, PARSE_ERROR, "Parse error")
            continue

        # A valid JSON value that is not a request object.
        if not isinstance(request, dict):
            error(None, INVALID_REQUEST, "Invalid Request: expected a JSON object")
            continue

        request_id = request.get("id")
        if request_id is not None and not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
            error(None, INVALID_REQUEST, "Invalid Request: id must be a string or integer")
            continue

        if request.get("jsonrpc") != "2.0":
            error(request_id, INVALID_REQUEST, "Invalid Request: jsonrpc must be \"2.0\"")
            continue

        method = request.get("method")
        if not isinstance(method, str) or not method:
            error(request_id, INVALID_REQUEST, "Invalid Request: method must be a non-empty string")
            continue

        params = request.get("params")
        if params is not None and not isinstance(params, (dict, list)):
            error(request_id, INVALID_PARAMS, "Invalid params: must be an object or array")
            continue

        is_notification = "id" not in request

        try:
            result = handle(request)
        except UnsupportedProtocolVersion as unsupported:
            if not is_notification:
                error(request_id, UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version",
                      {"supported": SUPPORTED_VERSIONS, "requested": unsupported.requested})
            continue
        except ProtocolError as protocol_error:
            if not is_notification:
                error(request_id, protocol_error.code, protocol_error.message)
            continue
        except Exception as unexpected:  # noqa: BLE001
            # Internal detail is logged to stderr, never returned to the client.
            traceback.print_exc(file=sys.stderr)
            if not is_notification:
                error(request_id, -32603, "Internal error: {0}".format(
                    unexpected.__class__.__name__))
            continue

        if is_notification or result is None:
            continue
        emit({"jsonrpc": "2.0", "id": request_id, "result": result})
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
