"""FP001-004 - false-positive risk rules."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sigmalint.core.condition import (
    ConditionParseError,
    has_negated_selector,
    parse,
)
from sigmalint.core.filters import filters_for_rule
from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity

_NOISY_CATEGORIES = {
    "process_creation",
    "registry_event",
    "file_event",
    "network_connection",
}


def _is_filter_selector(name: str) -> bool:
    return name == "filter" or name.startswith("filter_") or name.startswith("_")


def _selectors(detection: dict) -> dict[str, dict]:
    return {k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)}


@register
class Fp001SingleBroadSelection(Rule):
    id = "FP001"
    dimension = Dimension.FP_RISK
    default_severity = Severity.WARNING
    summary = "Single broad selection with no filter."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        detection = parsed.data.get("detection") or {}
        sels = _selectors(detection)
        if len(sels) != 1:
            return
        (name, body) = next(iter(sels.items()))
        if _is_filter_selector(name):
            return
        if len(body) != 1:
            return
        (field, value) = next(iter(body.items()))
        if isinstance(value, list):
            return
        if isinstance(value, str) and len(value) < 6:
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                f"single selection on {field}={value!r} likely too broad",
                parsed.path,
                fix_hint="Add additional selectors or a filter clause.",
            )


@register
class Fp002PreferModifiers(Rule):
    id = "FP002"
    dimension = Dimension.FP_RISK
    default_severity = Severity.INFO
    summary = "Prefer modifiers over leading/trailing wildcards."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        for selname, body in _selectors(parsed.data.get("detection") or {}).items():
            for field, value in body.items():
                if "|" in field:
                    continue  # already using a modifier
                values = value if isinstance(value, list) else [value]
                for v in values:
                    if not isinstance(v, str):
                        continue
                    if v.startswith("*") and v.endswith("*"):
                        yield Finding(
                            self.id,
                            self.dimension,
                            self.default_severity,
                            f"{selname}.{field}={v!r}: prefer `{field}|contains: {v.strip('*')!r}`",
                            parsed.path,
                            fix_hint="Replace with modifier `|contains`.",
                        )
                    elif v.endswith("*") and not v.startswith("*"):
                        yield Finding(
                            self.id,
                            self.dimension,
                            self.default_severity,
                            f"{selname}.{field}={v!r}: prefer `{field}|startswith`",
                            parsed.path,
                            fix_hint="Use `|startswith`.",
                        )
                    elif v.startswith("*") and not v.endswith("*"):
                        yield Finding(
                            self.id,
                            self.dimension,
                            self.default_severity,
                            f"{selname}.{field}={v!r}: prefer `{field}|endswith`",
                            parsed.path,
                            fix_hint="Use `|endswith`.",
                        )


@register
class Fp003NoFilterOnNoisy(Rule):
    id = "FP003"
    dimension = Dimension.FP_RISK
    default_severity = Severity.WARNING
    summary = "Noisy log source has no negated filter selector."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category = ls.get("category")
        if category not in _NOISY_CATEGORIES:
            return
        detection = parsed.data.get("detection") or {}
        condition = detection.get("condition")
        if condition is None:
            return
        try:
            ast = parse(condition)
        except ConditionParseError:
            return
        if has_negated_selector(ast, _is_filter_selector):
            return
        ext_filters = getattr(ctx, "filters", None) or []
        ext = filters_for_rule(
            ext_filters,
            parsed.data.get("id"),
            parsed.data.get("name"),
            parsed.data.get("title"),
        )
        for f in ext:
            try:
                ext_ast = parse(f.condition)
            except ConditionParseError:
                continue
            if has_negated_selector(ext_ast, _is_filter_selector):
                return
        yield Finding(
            self.id,
            self.dimension,
            self.default_severity,
            f"category={category!r} rule has no negated filter selector",
            parsed.path,
            fix_hint=(
                "Add `filter:` selector and reference as `selection and not "
                "filter` (or add a Sigma Filter file)."
            ),
        )


_HARDCODED_PATTERNS = [
    re.compile(r"C:\\Users\\[A-Za-z0-9._-]+"),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
]


@register
class Fp004HardcodedLiterals(Rule):
    id = "FP004"
    dimension = Dimension.FP_RISK
    default_severity = Severity.INFO
    summary = "Hardcoded environment-specific literals."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        for pat in _HARDCODED_PATTERNS:
            m = pat.search(parsed.raw_text)
            if m:
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"likely environment-specific literal: {m.group(0)!r}",
                    parsed.path,
                    fix_hint=("Generalize (e.g., `C:\\Users\\*\\...`) or move to a filter."),
                )
