"""Guarded deserialization for session restore payloads.

The wire format is a tagged JSON tree.  Every node is a two element array of
the form ``[tag, payload]``; container payloads hold nested nodes.  Parsing
only builds an intermediate tree.  Domain values are produced later by
``restore`` against a schema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

DEFAULT_POLICY = {"max_depth": 8, "max_items": 64}

_REFERENCE_TABLE = {"len": len, "print": print, "str": str}


class DeserError(ValueError):
    """Raised when a payload violates the deserialization contract."""


@dataclass
class Node:
    """An intermediate representation node."""

    tag: str
    value: Any = None


@dataclass
class OpaqueValue:
    """A domain value for a wire type that has no dedicated restoration."""

    wire_type: str
    payload: Any


def parse_stream(data: str | bytes) -> Node:
    """Parse a tagged JSON payload into an intermediate tree."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DeserError("stream is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise DeserError("stream must be str or bytes")

    text = text.lstrip()
    if not text:
        raise DeserError("stream is empty")

    decoder = json.JSONDecoder()
    try:
        payload, _end = decoder.raw_decode(text)
    except json.JSONDecodeError as exc:
        raise DeserError(
            f"malformed stream at line {exc.lineno} column {exc.colno}"
        ) from exc
    return _to_node(payload)


def _to_node(payload: Any) -> Node:
    if not isinstance(payload, list) or len(payload) != 2:
        raise DeserError("a node must be a two element array")
    tag, raw = payload
    if not isinstance(tag, str) or not tag:
        raise DeserError("a node tag must be a non empty string")

    if tag == "list":
        if not isinstance(raw, list):
            raise DeserError("a list node requires an array payload")
        return Node(tag, [_to_node(item) for item in raw])
    if tag == "dict":
        if not isinstance(raw, dict):
            raise DeserError("a dict node requires an object payload")
        return Node(tag, {str(key): _to_node(item) for key, item in raw.items()})
    if tag in ("ref", "class"):
        if not isinstance(raw, str) or not raw:
            raise DeserError("a reference node requires a non empty name")
        return Node(tag, raw)
    return Node(tag, raw)


def _children(node: Any) -> tuple[Node, ...]:
    if not isinstance(node, Node):
        return ()
    if node.tag == "list" and isinstance(node.value, list):
        return tuple(node.value)
    if node.tag == "dict" and isinstance(node.value, dict):
        return tuple(node.value.values())
    return ()


def _walk(node: Any) -> Iterable[Node]:
    if not isinstance(node, Node):
        return
    yield node
    for child in _children(node):
        yield from _walk(child)


def check_types(obj: Node, allowed: Iterable[str]) -> list[str]:
    """Return the wire types in obj that the whitelist does not cover."""
    names = list(allowed)
    problems: list[str] = []
    for node in _walk(obj):
        if not any(name in node.tag for name in names):
            problems.append(f"type not allowed: {node.tag}")
    return problems


def check_calls(obj: Node) -> list[str]:
    """Return references to callables or classes found in the tree."""
    problems: list[str] = []
    for node in _walk(obj):
        if callable(node.value):
            problems.append(f"callable value: {node.tag}")
    return problems


def check_limits(obj: Node, policy: dict[str, Any]) -> bool:
    """Return True when obj stays inside the supplied policy limits."""
    max_depth = int(policy.get("max_depth", DEFAULT_POLICY["max_depth"]))
    max_items = int(policy.get("max_items", DEFAULT_POLICY["max_items"]))
    if max_depth <= 0 or max_items <= 0:
        return False
    if not isinstance(obj, Node):
        return False
    if obj.tag in ("list", "dict"):
        return len(obj.value) <= max_items
    return True


def check_cycles(obj: Node) -> bool:
    """Return True when the tree contains no reference cycle."""
    seen: set[int] = set()
    stack = [obj]
    while stack:
        node = stack.pop()
        if not isinstance(node, Node):
            continue
        marker = id(node.value)
        if marker in seen:
            continue
        seen.add(marker)
        stack.extend(_children(node))
    return True


def restore(obj: Node, schema: dict[str, Any]) -> Any:
    """Restore an intermediate tree into domain values using schema."""
    if not isinstance(obj, Node):
        raise DeserError("restore requires an intermediate node")
    if not isinstance(schema, dict):
        raise DeserError("schema must be a mapping")
    check_types(obj, list(schema.get("allowed", [])))
    return _restore_node(obj)


def _restore_node(node: Node) -> Any:
    tag = node.tag
    if tag == "int":
        if not isinstance(node.value, int) or isinstance(node.value, bool):
            raise DeserError("an int node carries a non integer payload")
        return int(node.value)
    if tag == "str":
        if not isinstance(node.value, str):
            raise DeserError("a str node carries a non string payload")
        return node.value
    if tag == "bool":
        if not isinstance(node.value, bool):
            raise DeserError("a bool node carries a non boolean payload")
        return node.value
    if tag == "none":
        return None
    if tag == "list":
        return [_restore_node(child) for child in node.value]
    if tag == "dict":
        return {key: _restore_node(child) for key, child in node.value.items()}
    if tag in ("ref", "class"):
        return _REFERENCE_TABLE.get(node.value, node.value)
    return OpaqueValue(tag, node.value)


def validate_schema(schema: dict[str, Any]) -> list[str]:
    """Return the problems found in a deserialization schema."""
    if not isinstance(schema, dict):
        return ["schema must be a mapping"]

    problems: list[str] = []
    allowed = schema.get("allowed")
    if allowed is None:
        problems.append("allowed type whitelist is missing")
    else:
        if "*" in allowed or "object" in allowed:
            problems.append("type whitelist allows arbitrary types")

    depth = schema.get("max_depth")
    if not isinstance(depth, int) or isinstance(depth, bool) or depth <= 0:
        problems.append("max_depth must be a positive integer")

    items = schema.get("max_items")
    if not isinstance(items, int) or isinstance(items, bool) or items <= 0:
        problems.append("max_items must be a positive integer")

    root = schema.get("root_type")
    if root is not None and not isinstance(root, str):
        problems.append("root_type must be a string")

    return problems


def deser_batch(items: Iterable[str | bytes], policy: dict[str, Any]) -> dict[str, Any]:
    """Deserialize each payload under one policy, keeping items independent."""
    schema = {
        "allowed": list(policy.get("allowed", [])),
        "max_depth": int(policy.get("max_depth", DEFAULT_POLICY["max_depth"])),
        "max_items": int(policy.get("max_items", DEFAULT_POLICY["max_items"])),
    }
    problems = validate_schema(schema)
    if problems:
        raise DeserError("; ".join(problems))

    results: list[Any] = []
    errors: list[str | None] = []
    cache: dict[int, Any] = {}
    for raw in items:
        try:
            key = len(raw)
            if key in cache:
                results.append(cache[key])
                errors.append(None)
                continue
            node = parse_stream(raw)
            value = restore(node, schema)
            cache[key] = value
            results.append(value)
            errors.append(None)
        except DeserError as exc:
            results.append(None)
            errors.append(str(exc))
    return {"results": results, "errors": errors}