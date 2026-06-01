"""TAX001-003 - Sigma taxonomy correctness rules."""

from __future__ import annotations

from collections.abc import Iterable

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


def _walk_detection_fields(detection: dict) -> Iterable[str]:
    """Walk all detection field-name keys, including list-of-dict selectors.

    Sigma 2.1.0 allows two selector shapes:
      - dict:         selection: { Image: foo, CommandLine: bar }
      - list-of-dict: selection: [ { Image: foo }, { CommandLine: bar } ]

    The list-of-dict shape is structurally an OR over each dict's keys.
    sigmalint 0.1.x walked only dict selectors; list-of-dict selectors
    were silently skipped, masking taxonomy and modifier defects in
    rules that used that shape.
    """
    for name, sel in detection.items():
        if name == "condition":
            continue
        if isinstance(sel, dict):
            yield from sel.keys()
        elif isinstance(sel, list):
            for item in sel:
                if isinstance(item, dict):
                    yield from item.keys()


@register
class Tax001KnownFields(Rule):
    id = "TAX001"
    dimension = Dimension.TAXONOMY
    default_severity = Severity.WARNING
    summary = "All detection field names exist in the configured taxonomy."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category = ls.get("category")
        if not category:
            return
        taxonomy = parsed.data.get("taxonomy") or ctx.config.taxonomy  # type: ignore[attr-defined]
        for field in _walk_detection_fields(parsed.data.get("detection") or {}):
            bare = field.split("|", 1)[0]
            if not ctx.taxonomy.is_known(taxonomy, category, bare):  # type: ignore[attr-defined]
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"unknown field for logsource.category={category}: {bare}",
                    parsed.path,
                    fix_hint=(
                        "Confirm field exists for this log source or set "
                        "`taxonomy:` to a custom value."
                    ),
                )


@register
class Tax002ValidModifiers(Rule):
    id = "TAX002"
    dimension = Dimension.TAXONOMY
    default_severity = Severity.WARNING
    summary = "Field-name modifiers are spelled correctly per Sigma 2.1.0."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        for field in _walk_detection_fields(parsed.data.get("detection") or {}):
            if "|" not in field:
                continue
            _, *mods = field.split("|")
            for mod in mods:
                if not ctx.modifiers.is_known(mod):  # type: ignore[attr-defined]
                    yield Finding(
                        self.id,
                        self.dimension,
                        self.default_severity,
                        f"unknown modifier: {field}",
                        parsed.path,
                        fix_hint="Check Sigma 2.1.0 modifier appendix.",
                    )


@register
class Tax003CanonicalField(Rule):
    id = "TAX003"
    dimension = Dimension.TAXONOMY
    default_severity = Severity.INFO
    summary = "Prefer canonical field over known aliases."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category = ls.get("category")
        if not category:
            return
        taxonomy = parsed.data.get("taxonomy") or ctx.config.taxonomy  # type: ignore[attr-defined]
        for field in _walk_detection_fields(parsed.data.get("detection") or {}):
            bare = field.split("|", 1)[0]
            canonical = ctx.taxonomy.canonical(taxonomy, category, bare)  # type: ignore[attr-defined]
            if canonical:
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"prefer canonical field {canonical!r} over {bare!r}",
                    parsed.path,
                    fix_hint=f"Rename `{bare}` to `{canonical}`.",
                )
