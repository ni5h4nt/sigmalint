"""Two-layer scoring: validity gate + weighted quality dimensions.

Dimension scoring uses size-invariant normalization (paper-prep calibration):

    dim_score(d) = 100 * (1 - sum(penalty in d) / max_penalty(d))

where `max_penalty(d)` is the penalty that would be incurred if every rule
in dimension `d` fired at ERROR severity with its configured rule_weight.
This makes the score invariant to the number of rules registered in a
dimension: a single firing rule produces the same dim_score regardless of
whether the dimension has 2 or 20 sibling rules. Under the old anchor
(`100 - sum`), dimensions with more rules were structurally easier to
penalize and dimensions with fewer rules structurally harder to drop.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sigmalint.core.config import Config
from sigmalint.core.rule import Rule
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


def _max_penalty(dim: Dimension, rules: Iterable[Rule], cfg: Config) -> float:
    """Max possible penalty for `dim` if every rule in it fired at error severity."""
    return sum(
        _BASE_SEVERITY_WEIGHT[Severity.ERROR] * cfg.rule_weights.get(r.id, 1.0)
        for r in rules
        if r.dimension == dim
    )


def score_file(result: LintResult, cfg: Config, rules: Iterable[Rule]) -> FileScore:
    """Compute a FileScore using the validity gate + weighted quality dimensions.

    `rules` is the list of enabled rules for this run; it is consumed
    once to compute per-dimension max penalties for size-invariant
    normalization (see module docstring).
    """
    # Materialize so we can iterate multiple times.
    rules_list = list(rules)

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

    # Size-invariant normalization. If a dimension has no enabled rules
    # (max_penalty == 0), it can never be penalized — score 100.0.
    dim_scores: dict[str, float] = {}
    for d in _QUALITY_DIMENSIONS:
        cap = _max_penalty(d, rules_list, cfg)
        if cap <= 0:
            dim_scores[d.value] = 100.0
        else:
            dim_scores[d.value] = max(0.0, 100.0 * (1.0 - penalties[d] / cap))

    # Normalize weights over enabled dimensions only.
    weights = {d.value: cfg.dimension_weights.get(d.value, 0.0) for d in _QUALITY_DIMENSIONS}
    total_weight = sum(weights.values())
    if total_weight == 0:
        total = 0.0
    else:
        total = sum(dim_scores[d] * (weights[d] / total_weight) for d in dim_scores)

    return FileScore(
        path=result.parsed.path,
        status="valid",
        dimension_scores=dim_scores,
        total=round(total, 2),
    )
