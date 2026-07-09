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
    # Fires only when the field is absent (None). Empty string/list are considered present.
    return value is not None


def _pattern(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    return bool(re.search(options["match"], str(value)))


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


# ── List membership checks ───────────────────────────────────────────────────

def _contains_match(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    items = value if isinstance(value, list) else [value]
    return any(re.search(options["pattern"], str(item)) for item in items)


def _all_match(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    items = value if isinstance(value, list) else [value]
    return all(re.search(options["pattern"], str(item)) for item in items)


register_function("contains_match", _contains_match)
register_function("all_match", _all_match)


# ── Condition-aware checks ───────────────────────────────────────────────────

def _condition_has_filter(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    condition = str((parsed.data.get("detection") or {}).get("condition", ""))
    return bool(re.search(r"\band\s+not\s+filter", condition, re.IGNORECASE))


def _condition_references_selector(
    value: Any, options: dict[str, Any], parsed: Any, ctx: Any
) -> bool:
    name_pattern = options["name"]
    condition = str((parsed.data.get("detection") or {}).get("condition", ""))
    return bool(re.search(name_pattern, condition))


register_function("condition_has_filter", _condition_has_filter)
register_function("condition_references_selector", _condition_references_selector)


# ── Cross-field checks ───────────────────────────────────────────────────────

def _field_required(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    """Check a field at options['field'] (doc-root path), independent of `given`."""
    field_path = options["field"]
    current: Any = parsed.data
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return current is not None


register_function("field_required", _field_required)
