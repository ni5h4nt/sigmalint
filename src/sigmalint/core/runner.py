"""Rule-agnostic runner: parses files, dispatches rules, collects findings."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from sigmalint.core.rule import Rule
from sigmalint.core.types import (
    Dimension,
    Finding,
    LintResult,
    ParsedRule,
    Severity,
)

_yaml = YAML(typ="rt")  # round-trip preserves line/col


def _extract_positions(node: Any, prefix: str = "") -> dict[str, tuple[int, int]]:
    """Walk a ruamel.yaml CommentedMap, returning {key_path: (line, col)}.

    Lines/columns from ruamel.yaml are 0-based; we convert to 1-based.
    """
    out: dict[str, tuple[int, int]] = {}
    if not hasattr(node, "items"):
        return out
    lc = getattr(node, "lc", None)
    for key, value in node.items():
        path = f"{prefix}/{key}" if prefix else str(key)
        if lc is not None:
            try:
                line, col = lc.key(key)
                out[path] = (line + 1, col + 1)
            except (KeyError, TypeError):
                pass
        if hasattr(value, "items"):
            out.update(_extract_positions(value, path))
    return out


@dataclass(slots=True)
class RunContext:
    attack: object | None = None
    sigma_schema: object | None = None
    taxonomy: object | None = None
    corpus: object | None = None
    config: object | None = None
    filters: list[object] | None = None
    modifiers: object | None = None
    attack_logsource: object | None = None


_SUPPRESS = re.compile(r"#\s*sigmalint:\s*disable\s*=\s*([A-Z0-9_,\s]+)")


def _plain(x: Any) -> Any:
    """Recursively flatten ruamel.yaml CommentedMap/CommentedSeq to plain types."""
    if hasattr(x, "items"):
        return {k: _plain(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_plain(i) for i in x]
    return x


def _parse_file(path: Path) -> ParsedRule:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        node = _yaml.load(text) or {}
        if not hasattr(node, "items"):
            return ParsedRule(
                path=str(path),
                raw_text=text,
                data={},
                yaml_error="root must be a mapping",
            )
        positions = _extract_positions(node)
        return ParsedRule(
            path=str(path),
            raw_text=text,
            data=_plain(node),
            positions=positions,
        )
    except YAMLError as e:
        return ParsedRule(path=str(path), raw_text=text, data={}, yaml_error=str(e))


def _collect_suppressions(text: str) -> set[str]:
    out: set[str] = set()
    for m in _SUPPRESS.finditer(text):
        for raw in m.group(1).split(","):
            tok = raw.strip()
            if tok:
                out.add(tok)
    return out


def _safe_check(rule: Rule, parsed: ParsedRule, ctx: RunContext) -> Iterable[Finding]:
    try:
        yield from rule.check(parsed, ctx)  # type: ignore[arg-type]
    except Exception as e:
        yield Finding(
            rule_id="INTERNAL001",
            dimension=Dimension.SCHEMA,
            severity=Severity.ERROR,
            message=f"rule {rule.id} raised {type(e).__name__}: {e}",
            file=parsed.path,
        )


def lint(paths: Sequence[Path], rules: Sequence[Rule], ctx: RunContext) -> list[LintResult]:
    """Lint files. `rules` should already be filtered by enable/disable."""
    results: list[LintResult] = []
    for p in paths:
        parsed = _parse_file(p)
        suppressed = _collect_suppressions(parsed.raw_text)
        if parsed.yaml_error:
            results.append(
                LintResult(
                    parsed=parsed,
                    findings=(
                        Finding(
                            rule_id="SCHEMA001",
                            dimension=Dimension.SCHEMA,
                            severity=Severity.ERROR,
                            message=f"YAML parse error: {parsed.yaml_error}",
                            file=parsed.path,
                            line=1,
                            col=1,
                            fix_hint="Fix the YAML syntax.",
                        ),
                    ),
                    suppressions=tuple(sorted(suppressed)),
                )
            )
            continue
        findings: list[Finding] = []
        for rule in rules:
            if rule.id in suppressed:
                continue
            findings.extend(_safe_check(rule, parsed, ctx))
        results.append(
            LintResult(
                parsed=parsed,
                findings=tuple(findings),
                suppressions=tuple(sorted(suppressed)),
            )
        )
    return results
