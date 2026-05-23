"""Shared frozen data types: Severity, Dimension, Finding, ParsedRule, LintResult."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Dimension(str, Enum):
    SCHEMA = "schema"
    ATTACK = "attack"
    TAXONOMY = "taxonomy"
    FP_RISK = "fp_risk"
    METADATA = "metadata"
    REDUNDANCY = "redundancy"
    STYLE = "style"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    dimension: Dimension
    severity: Severity
    message: str
    file: str
    line: int | None = None
    col: int | None = None
    fix_hint: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedRule:
    path: str
    raw_text: str
    data: dict[str, Any]
    # Map from "/" -separated key path (e.g. "detection/selection/Image") to
    # 1-based (line, col). Populated by the runner from ruamel.yaml's
    # CommentedMap before the doc is flattened to a plain dict.
    positions: dict[str, tuple[int, int]] = field(default_factory=dict)
    yaml_error: str | None = None

    def position_for(
        self, *path: str, default: tuple[int, int] = (1, 1)
    ) -> tuple[int, int]:
        return self.positions.get("/".join(path), default)


@dataclass(frozen=True, slots=True)
class LintResult:
    parsed: ParsedRule
    findings: tuple[Finding, ...]
    suppressions: tuple[str, ...] = field(default_factory=tuple)
