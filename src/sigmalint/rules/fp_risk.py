"""FP001-004 - false-positive risk rules."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sigmalint.core.condition import (
    ConditionParseError,
    expand_patterns,
    has_negated_selector,
    is_wildcard_pattern,
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


def _selectors_iter(detection: object) -> Iterable[tuple[str, dict]]:
    """Yield (selector_name, body) for every dict-shaped detection branch.

    Sigma 2.1.0 allows two selector shapes:
      - dict:         selection: { Image: foo, CommandLine: bar }
      - list-of-dict: selection: [ { Image: foo }, { CommandLine: bar } ]

    A dict selector yields one (name, body). A list-of-dict selector
    yields one (name, body) per dict member - same selector name, multiple
    bodies (an OR semantic). Rules that need to distinguish "one selector"
    from "one branch" must inspect both the distinct-name set and the
    tuple count.

    v0.1.x used `_selectors()` which filtered out list-of-dict selectors
    entirely, masking FP001/FP002 defects in rules that used that shape.
    """
    if not isinstance(detection, dict):
        # A non-dict `detection:` is a SCHEMA003 defect, not an FP defect.
        # Yield nothing rather than raising AttributeError out of a rule
        # whose callers only catch ConditionParseError (cf. the 0.1.6
        # non-string-condition fix).
        return
    for k, v in detection.items():
        if k == "condition":
            continue
        if isinstance(v, dict):
            yield k, v
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    yield k, item


@register
class Fp001SingleBroadSelection(Rule):
    id = "FP001"
    dimension = Dimension.FP_RISK
    default_severity = Severity.WARNING
    summary = "Single broad selection with no filter."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        detection = parsed.data.get("detection") or {}
        sels = list(_selectors_iter(detection))
        # A list-of-dict selector contributes N tuples sharing one name.
        # "Single broad selection" requires exactly one distinct selector
        # AND exactly one branch within it.
        distinct_names = {n for n, _ in sels}
        if len(distinct_names) != 1:
            return
        if len(sels) != 1:
            # Multi-branch OR: same name but >1 tuple, not "single broad".
            return
        (name, body) = sels[0]
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
        # _selectors_iter yields one (name, body) per dict branch; for
        # list-of-dict selectors each branch contributes its own findings,
        # so duplicate wildcards across OR-branches each warrant their own
        # modifier suggestion (correct semantics).
        for selname, body in _selectors_iter(parsed.data.get("detection") or {}):
            for field, value in body.items():
                if "|" in field:
                    continue  # already using a modifier
                values = value if isinstance(value, list) else [value]
                for v in values:
                    if not isinstance(v, str):
                        continue
                    if v.strip("*") == "":
                        # `field: '*'` is the field-existence idiom. No
                        # modifier expresses "any value", so the only
                        # suggestion available (`|contains: ''`) would be
                        # meaningless and would change the rule's semantics.
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
        if not isinstance(detection, dict):
            # Non-dict `detection:` is a SCHEMA003 defect. Bail rather than
            # raise AttributeError out of a rule whose callers catch only
            # ConditionParseError (cf. the 0.1.6 non-string-condition fix).
            return
        condition = detection.get("condition")
        if condition is None:
            return
        try:
            ast = parse(condition)
        except ConditionParseError:
            return

        selector_names = {k for k in detection if k != "condition"}

        def _references_filter(name: str) -> bool:
            """True if `name` is, or a glob resolving to, a filter-class selector.

            `has_negated_selector` hands this both selector names
            (`Ident.name`) and `N of <pattern>` globs (`Quantifier.pattern`).
            A glob is resolved against the selectors this rule actually
            declares, using the same `expand_patterns` the condition layer
            uses, so `1 of filter*` matches a declared `filter_admin` while
            `1 of other*` does not. `them` is not a wildcard pattern and
            falls through to the name check, where it correctly fails: `not
            1 of them` negates the search itself rather than excluding from
            it, which is not the shape FP003 asks for.
            """
            if is_wildcard_pattern(name):
                return any(_is_filter_selector(s) for s in expand_patterns([name], selector_names))
            return _is_filter_selector(name)

        if has_negated_selector(ast, _references_filter):
            return
        # External filter conditions reference selectors declared in the
        # filter file, not in this rule, so their globs cannot be resolved
        # against `selector_names`. Name matching only.
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


def _detection_value_text(detection: object) -> str:
    """Newline-joined string values of every detection field.

    Reads values only - not field names, not `condition`, and not the
    prose keys or YAML comments a raw-text scan would sweep up. List
    values are flattened; non-string values are skipped, since a
    hardcoded literal is by definition textual.

    The walk is deliberately flat: dict-valued and list-of-dict-valued
    detection fields are skipped rather than recursed into. Both shapes
    occur zero times across the SigmaHQ corpus snapshot - every selector
    field holds a scalar or a list of scalars - so recursion would be
    code for a shape that does not exist. If one ever appears FP004
    under-reports on it, never over-reports, so the finding set stays a
    subset either way.
    """
    values: list[str] = []
    for _selname, body in _selectors_iter(detection):
        for value in body.values():
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str):
                    values.append(item)
    return "\n".join(values)


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
        text = _detection_value_text(parsed.data.get("detection"))
        for pat in _HARDCODED_PATTERNS:
            m = pat.search(text)
            if m:
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"likely environment-specific literal: {m.group(0)!r}",
                    parsed.path,
                    fix_hint=("Generalize (e.g., `C:\\Users\\*\\...`) or move to a filter."),
                )
