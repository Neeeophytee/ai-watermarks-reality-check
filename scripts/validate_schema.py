#!/usr/bin/env python3
"""A minimal JSON Schema validator covering the subset used by this repository.

The repository is standard-library only, so an external validator is not
available. This supports exactly the keywords used in `schemas/`:

    type, enum, const, required, properties, items, contains, minItems,
    maxItems, minimum, pattern, allOf, oneOf, anyOf, not, if/then/else,
    $ref (local `#/...` and sibling-file `name.json#/...`), $defs

Unsupported keywords are ignored rather than silently passing a bad document:
`check_repo.py` asserts that every keyword present in `schemas/` is handled.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Dict, List

SCHEMA_DIR = pathlib.Path(__file__).resolve().parents[1] / "schemas"

SUPPORTED_KEYWORDS = {
    "$schema", "$id", "$defs", "$ref", "$comment", "title", "type", "enum",
    "const", "required", "properties", "items", "contains", "minItems",
    "maxItems", "minimum", "pattern", "allOf", "oneOf", "anyOf", "not",
    "if", "then", "else",
}

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}

_cache: Dict[str, Any] = {}


def load_schema(name: str) -> Any:
    if name not in _cache:
        _cache[name] = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    return _cache[name]


def resolve(ref: str, root: Any, root_name: str) -> Any:
    if ref.startswith("#"):
        document, pointer = root, ref[1:]
    else:
        file_part, _, fragment = ref.partition("#")
        document = load_schema(file_part)
        pointer = fragment
    node = document
    for part in [p for p in pointer.split("/") if p]:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node


def check_type(value: Any, expected: Any) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        python_type = TYPES.get(name)
        if python_type is None:
            continue
        if name == "integer":
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                return True
            continue
        if name == "number" and isinstance(value, bool):
            continue
        if name == "boolean":
            if isinstance(value, bool):
                return True
            continue
        if isinstance(value, python_type):
            return True
    return False


def validate(instance: Any, schema: Any, root: Any = None, root_name: str = "",
             path: str = "$") -> List[str]:
    if root is None:
        root = schema
    errors: List[str] = []
    if not isinstance(schema, dict):
        return errors

    if "$ref" in schema:
        target = resolve(schema["$ref"], root, root_name)
        return validate(instance, target, root, root_name, path)

    if "type" in schema and not check_type(instance, schema["type"]):
        errors.append("{0}: expected type {1}, got {2}".format(path, schema["type"], type(instance).__name__))
        return errors

    if "const" in schema and instance != schema["const"]:
        errors.append("{0}: expected const {1!r}, got {2!r}".format(path, schema["const"], instance))

    if "enum" in schema and instance not in schema["enum"]:
        errors.append("{0}: {1!r} not in {2}".format(path, instance, schema["enum"]))

    if "pattern" in schema and isinstance(instance, str):
        if not re.search(schema["pattern"], instance):
            errors.append("{0}: {1!r} does not match {2}".format(path, instance, schema["pattern"]))

    if "minimum" in schema and isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if instance < schema["minimum"]:
            errors.append("{0}: {1} < minimum {2}".format(path, instance, schema["minimum"]))

    if isinstance(instance, dict):
        for field in schema.get("required", []):
            if field not in instance:
                errors.append("{0}: missing required field '{1}'".format(path, field))
        for field, subschema in (schema.get("properties") or {}).items():
            if field in instance:
                errors.extend(validate(instance[field], subschema, root, root_name,
                                       "{0}.{1}".format(path, field)))

    if isinstance(instance, list):
        if "items" in schema:
            for index, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], root, root_name,
                                       "{0}[{1}]".format(path, index)))
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("{0}: {1} items < minItems {2}".format(path, len(instance), schema["minItems"]))
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append("{0}: {1} items > maxItems {2}".format(path, len(instance), schema["maxItems"]))
        if "contains" in schema:
            if not any(not validate(item, schema["contains"], root, root_name, path) for item in instance):
                errors.append("{0}: no item satisfies 'contains'".format(path))

    for subschema in schema.get("allOf", []):
        errors.extend(validate(instance, subschema, root, root_name, path))

    if "anyOf" in schema:
        if all(validate(instance, sub, root, root_name, path) for sub in schema["anyOf"]):
            errors.append("{0}: does not satisfy any branch of anyOf".format(path))

    if "oneOf" in schema:
        passing = sum(1 for sub in schema["oneOf"] if not validate(instance, sub, root, root_name, path))
        if passing != 1:
            errors.append("{0}: satisfies {1} branches of oneOf, expected exactly 1".format(path, passing))

    if "not" in schema:
        if not validate(instance, schema["not"], root, root_name, path):
            errors.append("{0}: must not satisfy the 'not' schema".format(path))

    if "if" in schema:
        condition_failed = validate(instance, schema["if"], root, root_name, path)
        branch = "else" if condition_failed else "then"
        if branch in schema:
            errors.extend(validate(instance, schema[branch], root, root_name, path))

    return errors


def collect_keywords(node: Any, found: set) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            if key == "properties" and isinstance(value, dict):
                for sub in value.values():
                    collect_keywords(sub, found)
            elif key in ("$defs",) and isinstance(value, dict):
                for sub in value.values():
                    collect_keywords(sub, found)
            else:
                collect_keywords(value, found)
    elif isinstance(node, list):
        for item in node:
            collect_keywords(item, found)


def unsupported_keywords() -> set:
    """Keywords used in schemas/ that this validator does not implement."""
    used: set = set()
    for schema_file in sorted(SCHEMA_DIR.glob("*.json")):
        document = json.loads(schema_file.read_text(encoding="utf-8"))
        found: set = set()
        collect_keywords(document, found)
        # Property names are not keywords; only inspect keys in schema position.
        used |= found
    return {kw for kw in used if kw.startswith("$") or kw in {
        "type", "enum", "const", "required", "properties", "items", "contains",
        "minItems", "maxItems", "minimum", "maximum", "pattern", "allOf",
        "oneOf", "anyOf", "not", "if", "then", "else", "additionalProperties",
        "patternProperties", "uniqueItems", "format", "dependentSchemas",
        "propertyNames", "prefixItems", "multipleOf", "exclusiveMinimum",
        "exclusiveMaximum", "minLength", "maxLength", "minProperties",
        "maxProperties",
    }} - SUPPORTED_KEYWORDS


def validate_document(instance: Any, schema_name: str) -> List[str]:
    schema = load_schema(schema_name)
    return validate(instance, schema, schema, schema_name)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: validate_schema.py <document.json> <schema-name.json>")
        raise SystemExit(2)
    document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    problems = validate_document(document, sys.argv[2])
    if problems:
        print("Validation failed:")
        for problem in problems:
            print("- {0}".format(problem))
        raise SystemExit(1)
    print("Valid against {0}".format(sys.argv[2]))
