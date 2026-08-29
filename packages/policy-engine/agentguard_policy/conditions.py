"""Safe, declarative condition evaluation.

A condition is a JSON tree:

    {"all": [ <cond>, ... ]}          # AND
    {"any": [ <cond>, ... ]}          # OR
    {"not": <cond>}                   # NOT
    {"field": "parameters.amount", "op": "gt", "value": 5000}   # leaf

Fields are dotted paths into the evaluation namespace
(``parameters``, ``context``, ``agent``, ``tool``, ``action``, ``environment``,
``data``). No Python expressions are ever evaluated.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

_MISSING = object()

_OPS = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "startswith",
    "endswith",
    "matches",
    "glob",
    "exists",
}


class ConditionError(ValueError):
    """Raised when a condition tree is malformed."""


def resolve_field(path: str, namespace: dict[str, Any]) -> Any:
    node: Any = namespace
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _MISSING
    return node


def _compare(op: str, actual: Any, expected: Any) -> bool:
    if op == "exists":
        return (actual is not _MISSING) == bool(expected)
    if actual is _MISSING:
        return op in {"ne", "not_in"}

    try:
        match op:
            case "eq":
                return actual == expected
            case "ne":
                return actual != expected
            case "gt":
                return actual > expected
            case "gte":
                return actual >= expected
            case "lt":
                return actual < expected
            case "lte":
                return actual <= expected
            case "in":
                return actual in expected
            case "not_in":
                return actual not in expected
            case "contains":
                return expected in actual
            case "startswith":
                return str(actual).startswith(str(expected))
            case "endswith":
                return str(actual).endswith(str(expected))
            case "matches":
                return re.search(str(expected), str(actual)) is not None
            case "glob":
                return fnmatch.fnmatch(str(actual), str(expected))
    except TypeError:
        return False
    return False


def evaluate_condition(node: dict[str, Any] | None, namespace: dict[str, Any]) -> bool:
    """Evaluate a condition tree. ``None`` / ``{}`` means "always true"."""
    if not node:
        return True
    if not isinstance(node, dict):
        raise ConditionError(f"condition must be an object, got {type(node).__name__}")

    if "all" in node:
        return all(evaluate_condition(c, namespace) for c in node["all"])
    if "any" in node:
        return any(evaluate_condition(c, namespace) for c in node["any"])
    if "not" in node:
        return not evaluate_condition(node["not"], namespace)

    if "field" not in node or "op" not in node:
        raise ConditionError(f"leaf condition needs 'field' and 'op': {node!r}")
    op = node["op"]
    if op not in _OPS:
        raise ConditionError(f"unknown operator {op!r} (allowed: {sorted(_OPS)})")

    actual = resolve_field(node["field"], namespace)
    return _compare(op, actual, node.get("value"))


def validate_condition(node: dict[str, Any] | None) -> None:
    """Raise ConditionError if the tree is structurally invalid (full traversal)."""
    if not node:
        return
    if not isinstance(node, dict):
        raise ConditionError(f"condition must be an object, got {type(node).__name__}")
    for key in ("all", "any"):
        if key in node:
            if not isinstance(node[key], list):
                raise ConditionError(f"'{key}' must be a list")
            for child in node[key]:
                validate_condition(child)
            return
    if "not" in node:
        validate_condition(node["not"])
        return
    if "field" not in node or "op" not in node:
        raise ConditionError(f"leaf condition needs 'field' and 'op': {node!r}")
    if node["op"] not in _OPS:
        raise ConditionError(f"unknown operator {node['op']!r} (allowed: {sorted(_OPS)})")
