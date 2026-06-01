"""Compile custom rule definitions from .sigmalintrc.yml into Rule subclasses."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sigmalint.core.types import Dimension, Severity


def resolve_path(data: dict[str, Any], path: str) -> Any:
    """Walk a dot-notation path in a dict. Returns None if any key is missing."""
    if path == ".":
        return data
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def evaluate_when(value: Any, when: dict[str, Any]) -> bool:
    """Return True if the when guard holds for value."""
    if "equals" in when:
        target = when["equals"]
        if isinstance(value, list):
            return bool(target in value)
        return bool(value == target)
    if "matches" in when:
        pattern = when["matches"]
        if isinstance(value, list):
            return any(re.search(pattern, str(item)) for item in value)
        return bool(re.search(pattern, str(value)))
    if "in" in when:
        return bool(value in when["in"])
    if "exists" in when:
        return bool((value is not None) == when["exists"])
    if "not_exists" in when:
        return bool((value is None) == when["not_exists"])
    return True


@dataclass(frozen=True, slots=True)
class CustomRuleDefinition:
    id: str
    message: str
    severity: Severity = Severity.WARNING
    dimension: Dimension = Dimension.METADATA
    given: str = "."
    when: dict[str, Any] | None = None
    then_function: str = ""
    then_options: dict[str, Any] = field(default_factory=dict)
    fix_hint: str | None = None
