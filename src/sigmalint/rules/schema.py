"""SCHEMA001-004 — Sigma 2.1.0 validity rules.

SCHEMA001 (YAML parses) is emitted by the runner directly. The rules below
run only on successfully-parsed files.
"""
from __future__ import annotations

from collections.abc import Iterable

from sigmalint.core.condition import (
    ConditionParseError,
    expand_patterns,
    is_wildcard_pattern,
    parse,
    referenced_selectors,
)
from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


@register
class Schema002SigmaSchema(Rule):
    id = "SCHEMA002"
    dimension = Dimension.SCHEMA
    default_severity = Severity.ERROR
    summary = "Validates against the bundled Sigma JSON schema."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        errors = ctx.sigma_schema.validate(parsed.data)
        for msg in errors:
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                f"schema: {msg}",
                parsed.path,
                fix_hint="See the Sigma 2.1.0 rule schema.",
            )


@register
class Schema003RequiredKeys(Rule):
    id = "SCHEMA003"
    dimension = Dimension.SCHEMA
    default_severity = Severity.ERROR
    summary = "Required top-level + detection.condition keys present."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        data = parsed.data
        for key in ("title", "logsource", "detection"):
            if key not in data:
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"missing required top-level key: {key}",
                    parsed.path,
                    fix_hint=f"Add a `{key}:` block.",
                )
        det = data.get("detection") or {}
        if isinstance(det, dict) and "condition" not in det:
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                "missing required key: detection.condition",
                parsed.path,
                fix_hint="Add `condition: <selector-expression>` under detection.",
            )


@register
class Schema004ConditionParseable(Rule):
    id = "SCHEMA004"
    dimension = Dimension.SCHEMA
    default_severity = Severity.ERROR
    summary = "detection.condition parses and references only existing selectors."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        det = parsed.data.get("detection")
        if not isinstance(det, dict):
            return
        condition = det.get("condition")
        if condition is None:
            return
        try:
            ast = parse(condition)
        except ConditionParseError as e:
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                f"detection.condition does not parse: {e}",
                parsed.path,
                fix_hint="Check operator/parens/keywords against Sigma 2.1.0.",
            )
            return
        available = {k for k in det if k != "condition"}
        referenced = referenced_selectors(ast)
        # Wildcards (`*` or `?`) may appear at any position.
        wildcards = {r for r in referenced if is_wildcard_pattern(r)}
        non_wild = referenced - wildcards
        unknown = (non_wild - available) | {
            w for w in wildcards if not expand_patterns({w}, available)
        }
        for u in sorted(unknown):
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                f"detection.condition references unknown selector: {u}",
                parsed.path,
                fix_hint=f"Define `{u}:` under detection or remove the reference.",
            )
