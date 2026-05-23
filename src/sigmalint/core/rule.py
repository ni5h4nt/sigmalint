"""Rule base class: the unit a registry registers and the runner executes."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Protocol

from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


class CheckContext(Protocol):
    """Injected per-run context; concrete shape lives in core.runner."""

    attack: object
    sigma_schema: object
    taxonomy: object
    corpus: object | None
    config: object
    filters: list[object]


class Rule(ABC):
    """Abstract base for all sigmalint rules.

    Subclasses must declare id, dimension, default_severity, default_weight,
    and implement check().
    """

    id: str
    dimension: Dimension
    default_severity: Severity
    default_weight: float = 1.0
    summary: str = ""

    @abstractmethod
    def check(self, parsed: ParsedRule, ctx: CheckContext) -> Iterable[Finding]:
        """Yield zero or more Findings for the given parsed rule."""
