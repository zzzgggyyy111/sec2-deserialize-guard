"""Public contract tests for deser.guard."""

from __future__ import annotations

import pytest

from deser.guard import (
    DeserError,
    check_calls,
    check_cycles,
    check_limits,
    check_types,
    deser_batch,
    parse_stream,
    restore,
)


def test_plain_payload_parses_and_restores() -> None:
    raw = '["list", [["int", 7], ["str", "ok"], ["list", [["bool", true]]]]]'
    ir = parse_stream(raw)
    assert ir.tag == "list"
    assert ir.value[0].value == 7
    schema = {
        "allowed": ["int", "str", "bool", "list"],
        "root_type": "list",
        "max_depth": 8,
        "max_items": 16,
    }
    assert restore(ir, schema) == [7, "ok", [True]]
    assert check_cycles(ir) is True
    with pytest.raises(DeserError):
        parse_stream(raw + ' ["int", 1]')


def test_type_whitelist_rejects_unlisted_type() -> None:
    ir = parse_stream('["printer", {"x": 1}]')
    assert check_types(ir, ["int"]) != []
    with pytest.raises(DeserError):
        restore(ir, {"allowed": ["int"], "max_depth": 4, "max_items": 8})


def test_callable_reference_is_rejected() -> None:
    ir = parse_stream('["ref", "builtins.eval"]')
    assert check_calls(ir) != []
    with pytest.raises(DeserError):
        restore(ir, {"allowed": ["ref"], "max_depth": 4, "max_items": 8})


def test_depth_limit_rejects_deep_nesting() -> None:
    raw = '["int", 0]'
    for _ in range(6):
        raw = '["list", [' + raw + "]]"
    ir = parse_stream(raw)
    assert check_limits(ir, {"max_depth": 3, "max_items": 100}) is False


def test_batch_items_are_independent() -> None:
    payloads = ['["list", [["int", 1]]]', '["list", [["int", 2]]]']
    out = deser_batch(
        payloads,
        {"allowed": ["int", "list"], "max_depth": 5, "max_items": 8},
    )
    assert out["errors"] == [None, None]
    assert out["results"] == [[1], [2]]
    assert out["results"][0] is not out["results"][1]