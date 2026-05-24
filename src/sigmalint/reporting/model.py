"""Canonical report builder.

`build_report` consolidates per-file lint results + scores into the canonical
JSON shape described in the design spec §12. All four formatters
(text/json/sarif/github) render purely from this dict.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from sigmalint import __version__ as _sigmalint_version
from sigmalint.core.scoring import FileScore
from sigmalint.core.types import LintResult


def _rule_title(result: LintResult) -> str | None:
    title = result.parsed.data.get("title") if isinstance(result.parsed.data, dict) else None
    return title if isinstance(title, str) else None


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "dimension": finding.dimension.value,
        "severity": finding.severity.value,
        "message": finding.message,
        "line": finding.line,
        "col": finding.col,
        "fix_hint": finding.fix_hint,
    }


def _score_block(score: FileScore) -> dict[str, Any] | None:
    if score.status != "valid":
        return None
    block: dict[str, Any] = dict(score.dimension_scores)
    block["total"] = score.total
    return block


def build_report(
    results: Iterable[LintResult],
    scores: Iterable[FileScore],
    profile: str,
    data_versions: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the canonical report dict (spec §12)."""
    results_list = list(results)
    scores_by_path = {s.path: s for s in scores}

    files: list[dict[str, Any]] = []
    severity_counts = {"error": 0, "warning": 0, "info": 0}
    valid_totals: list[float] = []
    valid_count = 0
    invalid_count = 0
    finding_count = 0

    for result in results_list:
        path = result.parsed.path
        score = scores_by_path.get(path)
        status = score.status if score is not None else "invalid"

        findings_dicts = [_finding_to_dict(f) for f in result.findings]
        for f in findings_dicts:
            sev = f["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1
        finding_count += len(findings_dicts)

        files.append(
            {
                "path": path,
                "rule_title": _rule_title(result),
                "status": status,
                "findings": findings_dicts,
                "suppressions": list(result.suppressions),
                "scores": _score_block(score) if score is not None else None,
            }
        )

        if status == "valid":
            valid_count += 1
            if score is not None and score.total is not None:
                valid_totals.append(score.total)
        else:
            invalid_count += 1

    mean_score: float | None = (
        round(sum(valid_totals) / len(valid_totals), 2) if valid_totals else None
    )

    return {
        "sigmalint_version": _sigmalint_version,
        "profile": profile,
        "data_versions": dict(data_versions),
        "files": files,
        "summary": {
            "files": len(files),
            "valid": valid_count,
            "invalid": invalid_count,
            "findings": finding_count,
            "by_severity": severity_counts,
            "mean_score": mean_score,
        },
    }
