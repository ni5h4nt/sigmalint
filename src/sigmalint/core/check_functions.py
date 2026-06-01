"""Built-in check function registry for the custom rules DSL.

Each function is a predicate: returns True if the check passes (no finding),
False if it fails. Finding construction is handled by the Rule subclass built
in custom_rule.py.

Signature: (value: Any, options: dict, parsed: ParsedRule, ctx: RunContext) -> bool
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

CheckFn = Callable[[Any, dict[str, Any], Any, Any], bool]

_REGISTRY: dict[str, CheckFn] = {}


def register_function(name: str, fn: CheckFn) -> None:
    """Register a check function by name. Overwrites existing entries."""
    _REGISTRY[name] = fn


def get_function(name: str) -> CheckFn | None:
    """Return the check function registered under `name`, or None."""
    return _REGISTRY.get(name)


# ── Structural checks ────────────────────────────────────────────────────────

def _required(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    return value is not None


def _pattern(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    return bool(re.search(options.get("match", ""), str(value)))


def _enum(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    return value in options.get("values", [])


def _min_length(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    length = len(value) if isinstance(value, (str, list)) else 0
    min_val: int = options.get("min", 0)
    return length >= min_val


def _max_length(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    length = len(value) if isinstance(value, (str, list)) else 0
    max_val: float = options.get("max", float("inf"))
    return length <= max_val


register_function("required", _required)
register_function("pattern", _pattern)
register_function("enum", _enum)
register_function("min_length", _min_length)
register_function("max_length", _max_length)
