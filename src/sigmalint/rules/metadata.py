"""META001a/b-META005 - metadata completeness rules.

Pattern note: rules pass key paths (e.g. "id", "logsource/category") to
`_finding(..., *path)` so Findings carry line/col extracted from
ParsedRule.positions. Findings without a meaningful path may omit it; the
formatter defaults to file-level (line=None).
"""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity

VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


def _finding(
    rule: Rule,
    msg: str,
    parsed: ParsedRule,
    hint: str,
    *path: str,
    severity: Severity | None = None,
) -> Finding:
    """Build a Finding with line/col looked up from parsed.positions.

    `severity` overrides `rule.default_severity` when supplied. A single rule
    may emit findings at different severities (e.g. META001b emits ERROR for
    an unparseable id but WARNING for a parseable non-v4 UUID).
    """
    if path:
        line: int | None
        col: int | None
        line, col = parsed.position_for(*path)
    else:
        line, col = None, None
    return Finding(
        rule.id,
        rule.dimension,
        severity or rule.default_severity,
        msg,
        parsed.path,
        line=line,
        col=col,
        fix_hint=hint,
    )


@register
class Meta001aIdPresent(Rule):
    id = "META001a"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "Rule has an id."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        if "id" not in parsed.data or not parsed.data.get("id"):
            yield _finding(
                self,
                "missing id (Sigma marks id optional but strongly recommended)",
                parsed,
                "Add `id: <uuid4>` (e.g. `python -c 'import uuid;print(uuid.uuid4())'`).",
            )


@register
class Meta001bIdValidUuid4(Rule):
    id = "META001b"
    dimension = Dimension.METADATA
    # Default is WARNING — the common real-world case (legacy UUIDv1 from
    # `uuidgen` without -r) is technically a non-spec id but still globally
    # unique, and SigmaHQ has 37 such rules. The unparseable case is emitted
    # at ERROR severity inline (see check()).
    default_severity = Severity.WARNING
    summary = "id, if present, is a valid UUID (UUIDv4 recommended)."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        rid = parsed.data.get("id")
        if rid is None:
            return
        try:
            u = UUID(str(rid))
        except (ValueError, TypeError):
            # Not a UUID at all — hard error, no SIEM will treat this as a
            # stable identifier.
            yield _finding(
                self,
                f"id {rid!r} is not a valid UUID",
                parsed,
                "Use a UUIDv4: `python -c 'import uuid;print(uuid.uuid4())'`.",
                "id",
                severity=Severity.ERROR,
            )
            return
        if u.version != 4:
            # Parses as a UUID but not v4 — Sigma recommends v4 specifically.
            # Emit at the default (warning), since the rule still has a
            # stable identifier and existing tools accept it.
            yield _finding(
                self,
                f"id {rid!r} is UUIDv{u.version}, Sigma recommends UUIDv4",
                parsed,
                "Regenerate with UUIDv4.",
                "id",
            )


@register
class Meta002CorePopulated(Rule):
    id = "META002"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "author, date, description, level populated."

    REQUIRED = ("author", "date", "description", "level")

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        for key in self.REQUIRED:
            v = parsed.data.get(key)
            if v is None or (isinstance(v, str) and not v.strip()):
                yield _finding(
                    self,
                    f"metadata field empty or missing: {key}",
                    parsed,
                    f"Populate `{key}:`.",
                    key,
                )


@register
class Meta003ReferencesForHigh(Rule):
    id = "META003"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "references non-empty when level is high or critical."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        level_raw = parsed.data.get("level")
        level = (level_raw or "").lower() if isinstance(level_raw, str) else ""
        if level not in {"high", "critical"}:
            return
        refs = parsed.data.get("references") or []
        if not isinstance(refs, list) or not any(isinstance(r, str) and r.strip() for r in refs):
            yield _finding(
                self,
                f"level={level} but references is empty",
                parsed,
                "Cite at least one source URL under `references:`.",
                "references",
            )


@register
class Meta004FalsepositivesPopulated(Rule):
    id = "META004"
    dimension = Dimension.METADATA
    default_severity = Severity.INFO
    summary = "falsepositives non-empty and not literally 'Unknown'."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        fps_raw = parsed.data.get("falsepositives") or []
        fps: list[object]
        if isinstance(fps_raw, str):
            fps = [fps_raw]
        elif isinstance(fps_raw, list):
            fps = list(fps_raw)
        else:
            fps = []
        meaningful = [
            f for f in fps if isinstance(f, str) and f.strip() and f.strip().lower() != "unknown"
        ]
        if not meaningful:
            yield _finding(
                self,
                "falsepositives is empty or only 'Unknown'",
                parsed,
                "List realistic false-positive sources or 'None known'.",
                "falsepositives",
            )


@register
class Meta005StatusVocabulary(Rule):
    id = "META005"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "status (if present) is a Sigma-2.1.0 vocabulary value."

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        status = parsed.data.get("status")
        if status is None:
            return
        if status not in VALID_STATUS:
            yield _finding(
                self,
                f"status={status!r} not in {sorted(VALID_STATUS)}",
                parsed,
                "Use one of: stable, test, experimental, deprecated, unsupported.",
                "status",
            )
