"""ATK001-004 - MITRE ATT&CK alignment rules."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity
from sigmalint.data.attack import technique_from_tag


def _technique_tags(tags: Any) -> list[tuple[str, str]]:
    """Return [(raw_tag, normalized_technique_id)] for ATT&CK-technique tags only."""
    if not isinstance(tags, list):
        return []
    out: list[tuple[str, str]] = []
    for t in tags:
        if not isinstance(t, str):
            continue
        tid = technique_from_tag(t)
        if tid:
            out.append((t, tid))
    return out


@register
class Atk001ValidTechnique(Rule):
    id = "ATK001"
    dimension = Dimension.ATTACK
    default_severity = Severity.ERROR
    summary = "Every attack.t#### tag resolves to a known technique."

    def check(self, parsed: ParsedRule, ctx: Any) -> Iterable[Finding]:
        for raw, tid in _technique_tags(parsed.data.get("tags")):
            if not ctx.attack.is_valid_technique(tid):
                yield Finding(
                    rule_id=self.id,
                    dimension=self.dimension,
                    severity=self.default_severity,
                    message=f"unknown ATT&CK technique: {raw}",
                    file=parsed.path,
                    fix_hint="Verify the technique id at attack.mitre.org.",
                )


@register
class Atk002NotRevoked(Rule):
    id = "ATK002"
    dimension = Dimension.ATTACK
    default_severity = Severity.WARNING
    summary = "No revoked/deprecated ATT&CK techniques."

    def check(self, parsed: ParsedRule, ctx: Any) -> Iterable[Finding]:
        for raw, tid in _technique_tags(parsed.data.get("tags")):
            if ctx.attack.is_valid_technique(tid) and ctx.attack.is_revoked(tid):
                yield Finding(
                    rule_id=self.id,
                    dimension=self.dimension,
                    severity=self.default_severity,
                    message=f"technique {raw} is revoked or deprecated",
                    file=parsed.path,
                    fix_hint="Replace with the current successor technique.",
                )


@register
class Atk003LogsourcePlausible(Rule):
    id = "ATK003"
    dimension = Dimension.ATTACK
    default_severity = Severity.INFO
    summary = "logsource is plausible for cited techniques (weak signal)."

    def check(self, parsed: ParsedRule, ctx: Any) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category, product = ls.get("category"), ls.get("product")
        if not (category or product):
            return
        for raw, tid in _technique_tags(parsed.data.get("tags")):
            if not ctx.attack.is_valid_technique(tid):
                continue
            if not ctx.attack_logsource.plausible(tid, category, product):
                yield Finding(
                    rule_id=self.id,
                    dimension=self.dimension,
                    severity=self.default_severity,
                    message=(
                        f"logsource (category={category!r}, product={product!r}) "
                        f"is unusual for {raw}"
                    ),
                    file=parsed.path,
                    fix_hint="Confirm the telemetry source is appropriate for this technique.",
                )


@register
class Atk004SubtechniqueSpecificity(Rule):
    id = "ATK004"
    dimension = Dimension.ATTACK
    default_severity = Severity.INFO
    summary = "Sub-technique specificity heuristic."

    # Heuristic: if a rule tags a parent and the rule body mentions a known
    # specifier (e.g. powershell.exe -> T1059.001), suggest the sub-technique.
    _PARENT_HINTS: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "T1059": [
            ("powershell", "T1059.001"),
            ("cmd.exe", "T1059.003"),
            ("bash", "T1059.004"),
            ("python", "T1059.006"),
        ],
    }

    def check(self, parsed: ParsedRule, ctx: Any) -> Iterable[Finding]:
        tags = [tid for _, tid in _technique_tags(parsed.data.get("tags"))]
        text = parsed.raw_text.lower()
        for tid in tags:
            if "." in tid:
                continue
            hints = self._PARENT_HINTS.get(tid, [])
            for needle, sub in hints:
                if needle in text and sub not in tags:
                    yield Finding(
                        rule_id=self.id,
                        dimension=self.dimension,
                        severity=self.default_severity,
                        message=f"parent technique {tid} cited; rule body suggests {sub}",
                        file=parsed.path,
                        fix_hint=f"Add `attack.{sub.lower()}` to tags.",
                    )
                    break
