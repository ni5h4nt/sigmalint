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
    summary = "Four-space indentation."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for lineno, line in enumerate(parsed.raw_text.splitlines(), 1):
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            if indent and indent % 4:
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"indent of {indent} spaces is not a multiple of 4",
                    parsed.path,
                    line=lineno,
                    col=1,
                    fix_hint="Reindent with 4-space steps.",
                )
                return
