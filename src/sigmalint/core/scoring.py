"""Two-layer scoring: validity gate + weighted quality dimensions."""
from __future__ import annotations

from dataclasses import dataclass

from sigmalint.core.config import Config
from sigmalint.core.types import Dimension, LintResult, Severity

_BASE_SEVERITY_WEIGHT = {
    Severity.ERROR: 10.0,
    Severity.WARNING: 3.0,
    Severity.INFO: 1.0,
}
_QUALITY_DIMENSIONS = (
    Dimension.ATTACK,
    Dimension.TAXONOMY,
    Dimension.FP_RISK,
    Dimension.METADATA,
    Dimension.REDUNDANCY,
    Dimension.STYLE,
)


@dataclass(frozen=True, slots=True)
class FileScore:
    path: str
    status: str  # "valid" | "invalid"
    dimension_scores: dict[str, float]  # empty if invalid
    total: float | None  # None if invalid


def score_file(result: LintResult, cfg: Config) -> FileScore:
    """Compute a FileScore using the validity gate + weighted quality dimensions."""
    # Validity gate: any SCHEMA error => invalid.
    schema_errors = [
        f
        for f in result.findings
        if f.dimension == Dimension.SCHEMA and f.severity == Severity.ERROR
    ]
    if schema_errors:
        return FileScore(
            path=result.parsed.path,
            status="invalid",
            dimension_scores={},
            total=None,
        )

    # Quality scoring.
    penalties: dict[Dimension, float] = {d: 0.0 for d in _QUALITY_DIMENSIONS}
    for f in result.findings:
        if f.dimension not in _QUALITY_DIMENSIONS:
            continue
        sev = _BASE_SEVERITY_WEIGHT[f.severity]
        mult = cfg.rule_weights.get(f.rule_id, 1.0)
        penalties[f.dimension] += sev * mult

    dim_scores = {
        d.value: max(0.0, 100.0 - penalties[d]) for d in _QUALITY_DIMENSIONS
    }

    # Normalize weights over enabled dimensions only.
    weights = {
        d.value: cfg.dimension_weights.get(d.value, 0.0) for d in _QUALITY_DIMENSIONS
    }
    total_weight = sum(weights.values())
    if total_weight == 0:
        total = 0.0
    else:
        total = sum(
            dim_scores[d] * (weights[d] / total_weight) for d in dim_scores
        )

    return FileScore(
        path=result.parsed.path,
        status="valid",
        dimension_scores=dim_scores,
        total=round(total, 2),
    )
