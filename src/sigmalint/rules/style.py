"""STY001-003 - Sigma interoperability style."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


@register
class Sty001LowercaseTopLevelKeys(Rule):
    id = "STY001"
    dimension = Dimension.STYLE
    default_severity = Severity.INFO
    summary = "Top-level keys are lowercase."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for k in parsed.data:
            if isinstance(k, str) and k != k.lower():
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"top-level key not lowercase: {k!r}",
                    parsed.path,
                    fix_hint=f"Rename to `{k.lower()}`.",
                )


@register
class Sty002LfAndYml(Rule):
    id = "STY002"
    dimension = Dimension.STYLE
    default_severity = Severity.INFO
    summary = "File uses LF line endings and .yml extension."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        if "\r\n" in parsed.raw_text:
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                "CRLF line endings",
                parsed.path,
                fix_hint="Convert to LF.",
            )
        if Path(parsed.path).suffix == ".yaml":
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                "use .yml extension (Sigma convention)",
                parsed.path,
                fix_hint="Rename to .yml.",
            )


@register
class Sty003FourSpaceIndent(Rule):
    id = "STY003"
    dimension = Dimension.STYLE
    default_severity = Severity.INFO
    summary = "Four-space indentation (list-item continuation at 4n+2 also accepted)."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        """Flag lines whose indent is neither 4n nor 4n+2.

        Sigma's documented convention is 4-space step indentation. Under YAML
        list syntax, list items use a 2-char "- " prefix, so subsequent keys
        of a list-item mapping naturally land at column (level * 4 + 2), as
        in a SigmaHQ-canonical `related:` block whose entries each have an
        id field and a relation-kind field one row below at 6 spaces.

        Allowing ``indent % 4 in (0, 2)`` covers both straight 4-space-step
        mappings and 4n+2 list-item continuations. An empirical sweep over
        the SigmaHQ public corpus (3,132 rules) showed the previous
        ``indent % 4 != 0`` rule fired on 1053 rules of which 1048 were
        false positives (list-item continuations) and only 5 were real
        off-step indents (3, 5, 9, 15 spaces). See
        ``docs/rules/STY003.md`` for the worked example.
        """
        for lineno, line in enumerate(parsed.raw_text.splitlines(), 1):
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            if indent and indent % 4 not in (0, 2):
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"indent of {indent} spaces is not a 4-space step "
                    f"(nor a 4n+2 list-item continuation)",
                    parsed.path,
                    line=lineno,
                    col=1,
                    fix_hint="Reindent with 4-space steps; list-item keys at 4n+2 are fine.",
                )
                return
