"""RED001-002 - overlap with SigmaHQ public corpus."""
from __future__ import annotations

from collections.abc import Iterable

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity
from sigmalint.data.corpus import fingerprint_for_rule


@register
class Red001NearDuplicateFingerprint(Rule):
    id = "RED001"
    dimension = Dimension.REDUNDANCY
    default_severity = Severity.INFO
    summary = (
        "Detection fingerprint near-duplicates an existing SigmaHQ rule "
        "(>=0.85 Jaccard)."
    )

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        corpus = getattr(ctx, "corpus", None)
        if corpus is None or not corpus.available:
            return
        fp = fingerprint_for_rule(parsed.data)
        if not fp:
            return
        matches = corpus.near_duplicates(fp, threshold=0.85)
        for m in matches[:3]:
            if m.path == parsed.path:
                continue
            yield Finding(
                self.id,
                self.dimension,
                self.default_severity,
                f"near-duplicate of public rule {m.title!r} ({m.path})",
                parsed.path,
                fix_hint=(
                    "If this is a meaningful extension, document the delta "
                    "in description."
                ),
            )


@register
class Red002TitleOrIdCollision(Rule):
    id = "RED002"
    dimension = Dimension.REDUNDANCY
    default_severity = Severity.INFO
    summary = "Title or id collides with a SigmaHQ public rule."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        corpus = getattr(ctx, "corpus", None)
        if corpus is None or not corpus.available:
            return
        rid = parsed.data.get("id")
        title = parsed.data.get("title")
        for e in corpus.entries():
            if rid and e.id == rid:
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"id collides with {e.path}",
                    parsed.path,
                    fix_hint="Regenerate a unique UUIDv4.",
                )
                return
            if title and e.title == title:
                yield Finding(
                    self.id,
                    self.dimension,
                    self.default_severity,
                    f"title collides with {e.path}: {title!r}",
                    parsed.path,
                    fix_hint="Rename your rule.",
                )
                return
