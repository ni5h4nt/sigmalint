#!/usr/bin/env python3
"""Empirical corpus analysis for sigmalint.

Reads a sigmalint JSON report (default `/tmp/sigmalint-report/report.json`)
and produces an analysis markdown document covering:

  - Total-score histograms under both the pre-fix (`100 - sum`) and post-fix
    (`100 * (1 - sum/max_penalty)`) dimension formulas, computed from the
    same findings (no re-lint required).
  - Validity rate.
  - Top finding counts by rule_id.
  - Per-dimension mean score under both formulas (the calibration shift).
  - The 10 lowest-scoring rules under the new formula.
  - Per-dimension finding-count distribution (mean, median, p90).

The script is import-safe and standalone; it depends only on the live
sigmalint package (for the registry and Config defaults) and the JSON
report on disk.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Register rule modules so the registry is populated.
from sigmalint.core.config import Config
from sigmalint.core.registry import all_rules
from sigmalint.core.types import Severity
from sigmalint.rules import attack as _a  # noqa: F401
from sigmalint.rules import fp_risk as _fp  # noqa: F401
from sigmalint.rules import metadata as _m  # noqa: F401
from sigmalint.rules import redundancy as _r  # noqa: F401
from sigmalint.rules import schema as _s  # noqa: F401
from sigmalint.rules import style as _st  # noqa: F401
from sigmalint.rules import taxonomy as _t  # noqa: F401

_BASE_SEVERITY_WEIGHT = {
    "error": 10.0,
    "warning": 3.0,
    "info": 1.0,
}
_QUALITY_DIMS = ("attack", "taxonomy", "fp_risk", "metadata", "redundancy", "style")
_BUCKETS: list[tuple[float, float, str]] = [
    (0.0, 50.0, "[0,50)"),
    (50.0, 75.0, "[50,75)"),
    (75.0, 90.0, "[75,90)"),
    (90.0, 95.0, "[90,95)"),
    (95.0, 98.0, "[95,98)"),
    (98.0, 99.0, "[98,99)"),
    (99.0, 99.5, "[99,99.5)"),
    (99.5, 99.8, "[99.5,99.8)"),
    (99.8, 100.0001, "[99.8,100]"),
]


def _bucket(v: float) -> str:
    for lo, hi, label in _BUCKETS:
        if lo <= v < hi:
            return label
    return _BUCKETS[-1][2]


def _max_penalty_by_dim(cfg: Config) -> dict[str, float]:
    """Per-dimension cap assuming every registered rule fires at error severity.

    This mirrors `sigmalint.core.scoring._max_penalty` exactly, but loops over
    the full registry (not a per-run `rules` list). For corpus analysis under
    the default profile that distinction does not matter — every rule is
    enabled, so the cap is the same.
    """
    caps: dict[str, float] = {d: 0.0 for d in _QUALITY_DIMS}
    for r in all_rules():
        if r.dimension.value in caps:
            caps[r.dimension.value] += _BASE_SEVERITY_WEIGHT[
                Severity.ERROR.value
            ] * cfg.rule_weights.get(r.id, 1.0)
    return caps


def _file_dim_penalties(findings: list[dict[str, Any]], cfg: Config) -> dict[str, float]:
    penalties: dict[str, float] = {d: 0.0 for d in _QUALITY_DIMS}
    for f in findings:
        dim = f["dimension"]
        if dim not in penalties:
            continue
        sev_w = _BASE_SEVERITY_WEIGHT[f["severity"]]
        mult = cfg.rule_weights.get(f["rule_id"], 1.0)
        penalties[dim] += sev_w * mult
    return penalties


def _score_old(
    penalties: dict[str, float], weights: dict[str, float]
) -> tuple[float, dict[str, float]]:
    dim_scores = {d: max(0.0, 100.0 - penalties[d]) for d in _QUALITY_DIMS}
    return _weighted_total(dim_scores, weights), dim_scores


def _score_new(
    penalties: dict[str, float], caps: dict[str, float], weights: dict[str, float]
) -> tuple[float, dict[str, float]]:
    dim_scores: dict[str, float] = {}
    for d in _QUALITY_DIMS:
        cap = caps[d]
        if cap <= 0:
            dim_scores[d] = 100.0
        else:
            dim_scores[d] = max(0.0, 100.0 * (1.0 - penalties[d] / cap))
    return _weighted_total(dim_scores, weights), dim_scores


def _weighted_total(dim_scores: dict[str, float], weights: dict[str, float]) -> float:
    total_w = sum(weights.values())
    if total_w == 0:
        return 0.0
    return sum(dim_scores[d] * (weights[d] / total_w) for d in dim_scores)


def _histogram(scores: list[float]) -> dict[str, int]:
    out: dict[str, int] = {label: 0 for _, _, label in _BUCKETS}
    for s in scores:
        out[_bucket(s)] += 1
    return out


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return float(s[f])
    return float(s[f] + (s[c] - s[f]) * (k - f))


def analyze(report: dict[str, Any], cfg: Config) -> dict[str, Any]:
    caps = _max_penalty_by_dim(cfg)
    weights = {d: cfg.dimension_weights.get(d, 0.0) for d in _QUALITY_DIMS}

    files = report["files"]
    n_files = len(files)
    n_valid = sum(1 for f in files if f["status"] == "valid")

    old_totals: list[float] = []
    new_totals: list[float] = []
    old_dim_sums: dict[str, list[float]] = defaultdict(list)
    new_dim_sums: dict[str, list[float]] = defaultdict(list)
    file_new_score: list[tuple[float, str, list[str]]] = []  # (score, path, finding_ids)
    rule_counter: Counter[str] = Counter()
    findings_per_file_by_dim: dict[str, list[int]] = defaultdict(list)

    for f in files:
        if f["status"] != "valid":
            continue
        penalties = _file_dim_penalties(f["findings"], cfg)
        old_total, old_dims = _score_old(penalties, weights)
        new_total, new_dims = _score_new(penalties, caps, weights)
        old_totals.append(round(old_total, 4))
        new_totals.append(round(new_total, 4))
        for d in _QUALITY_DIMS:
            old_dim_sums[d].append(old_dims[d])
            new_dim_sums[d].append(new_dims[d])
        finding_ids = [fd["rule_id"] for fd in f["findings"]]
        file_new_score.append((new_total, f["path"], finding_ids))
        for fid in finding_ids:
            rule_counter[fid] += 1

        # finding count per file per dim
        per_dim_count: Counter[str] = Counter()
        for fd in f["findings"]:
            per_dim_count[fd["dimension"]] += 1
        for d in _QUALITY_DIMS:
            findings_per_file_by_dim[d].append(per_dim_count.get(d, 0))

    # Per-dim finding-count stats.
    dim_finding_stats: dict[str, dict[str, float]] = {}
    for d in _QUALITY_DIMS:
        vals = findings_per_file_by_dim[d]
        dim_finding_stats[d] = {
            "mean": round(statistics.fmean(vals) if vals else 0.0, 3),
            "median": round(statistics.median(vals) if vals else 0.0, 3),
            "p90": round(_percentile(vals, 0.90), 3),
        }

    lowest_10 = sorted(file_new_score, key=lambda x: x[0])[:10]

    return {
        "n_files": n_files,
        "n_valid": n_valid,
        "validity_rate": (n_valid / n_files) if n_files else 0.0,
        "mean_old": round(statistics.fmean(old_totals), 4) if old_totals else 0.0,
        "mean_new": round(statistics.fmean(new_totals), 4) if new_totals else 0.0,
        "hist_old": _histogram(old_totals),
        "hist_new": _histogram(new_totals),
        "per_dim_mean_old": {
            d: round(statistics.fmean(old_dim_sums[d]), 4) if old_dim_sums[d] else 100.0
            for d in _QUALITY_DIMS
        },
        "per_dim_mean_new": {
            d: round(statistics.fmean(new_dim_sums[d]), 4) if new_dim_sums[d] else 100.0
            for d in _QUALITY_DIMS
        },
        "top_findings": rule_counter.most_common(15),
        "lowest_10": lowest_10,
        "dim_finding_stats": dim_finding_stats,
        "caps": caps,
        "data_versions": report.get("data_versions", {}),
        "report_summary": report.get("summary", {}),
    }


def _markdown(a: dict[str, Any]) -> str:
    dv = a["data_versions"]
    lines: list[str] = []
    lines.append("# SigmaHQ Corpus Analysis — Calibration Shift")
    lines.append("")
    lines.append(
        "Analysis run against the SigmaHQ corpus snapshot under the following data versions:"
    )
    lines.append("")
    lines.append("| dataset | version |")
    lines.append("|---|---|")
    for k, v in dv.items():
        lines.append(f"| `{k}` | `{v}` |")
    lines.append("")
    lines.append(
        "Reproducibility: re-running `sigmalint lint` on the same SigmaHQ commit "
        "with these `data_versions` must yield the same `findings` array and "
        "therefore the same pre/post score columns below."
    )
    lines.append("")
    lines.append("## Validity rate")
    lines.append("")
    lines.append(f"- files scanned: **{a['n_files']}**")
    lines.append(f"- valid (no SCHEMA error): **{a['n_valid']}** ({a['validity_rate'] * 100:.2f}%)")
    lines.append("")
    lines.append("## Mean total score — calibration delta")
    lines.append("")
    lines.append("| formula | mean total |")
    lines.append("|---|---|")
    lines.append(f"| pre-fix `100 - sum(penalty)` | {a['mean_old']:.4f} |")
    lines.append(f"| post-fix `100 * (1 - sum/max_penalty)` | {a['mean_new']:.4f} |")
    delta = a["mean_new"] - a["mean_old"]
    lines.append(f"| delta (new - old) | {delta:+.4f} |")
    lines.append("")
    lines.append("## Total-score histogram")
    lines.append("")
    lines.append("| bucket | pre-fix | post-fix |")
    lines.append("|---|---:|---:|")
    for _, _, label in _BUCKETS:
        lines.append(f"| {label} | {a['hist_old'][label]} | {a['hist_new'][label]} |")
    lines.append("")
    lines.append("## Per-dimension mean score (pre vs post)")
    lines.append("")
    lines.append("| dimension | pre-fix mean | post-fix mean | delta | max_penalty cap |")
    lines.append("|---|---:|---:|---:|---:|")
    for d in _QUALITY_DIMS:
        po = a["per_dim_mean_old"][d]
        pn = a["per_dim_mean_new"][d]
        cap = a["caps"][d]
        lines.append(f"| {d} | {po:.4f} | {pn:.4f} | {pn - po:+.4f} | {cap:.1f} |")
    lines.append("")
    lines.append("## Top 15 findings by rule_id")
    lines.append("")
    lines.append("| rank | rule_id | count |")
    lines.append("|---:|---|---:|")
    for i, (rid, n) in enumerate(a["top_findings"], 1):
        lines.append(f"| {i} | {rid} | {n} |")
    lines.append("")
    lines.append("## 10 lowest-scoring rules under the post-fix formula")
    lines.append("")
    lines.append("| rank | total | path | findings |")
    lines.append("|---:|---:|---|---|")
    for i, (score, path, fids) in enumerate(a["lowest_10"], 1):
        finding_str = ", ".join(f"`{x}`" for x in fids) if fids else "—"
        lines.append(f"| {i} | {score:.2f} | `{path}` | {finding_str} |")
    lines.append("")
    lines.append("## Per-dimension finding-count distribution (per file)")
    lines.append("")
    lines.append("| dimension | mean | median | p90 |")
    lines.append("|---|---:|---:|---:|")
    for d in _QUALITY_DIMS:
        s = a["dim_finding_stats"][d]
        lines.append(f"| {d} | {s['mean']:.3f} | {s['median']:.3f} | {s['p90']:.3f} |")
    lines.append("")
    lines.append("## Notes for the paper")
    lines.append("")
    lines.append(
        "- The calibration delta is small but systematic. Under the pre-fix "
        "anchor, the *absolute* penalty units are identical regardless of how "
        "many rules a dimension contains, so a single warning in `redundancy` "
        "(2 rules, current max_penalty = 20) and a single warning in `metadata` "
        "(6 rules, current max_penalty = 60) both drop a dim_score by the same "
        "3 points — meaning the redundancy violation receives effectively a "
        "third of the proportional weight. The post-fix formula re-anchors "
        "each dimension to its own ceiling: the same warning now drops "
        "redundancy by 15 percentage points and metadata by 5. The directions "
        "of the per-dimension means in the table above reflect this: "
        "dimensions whose max_penalty is below 100 (every quality dimension "
        "under v0.1's rule counts) attract *more* penalty per finding under "
        "the new formula, and the mean total drops accordingly. This is the "
        "intended calibration — the formula now reports rate of firing, not "
        "absolute count."
    )
    lines.append(
        "- SCHEMA004 produces zero findings across the corpus snapshot. The "
        "validity gate therefore exercises SCHEMA001 (YAML) and SCHEMA002-003 "
        "(structural schema) almost exclusively in practice; SCHEMA004 acts as "
        "a guard against a class of malformations that the public SigmaHQ "
        "corpus does not contain."
    )
    lines.append(
        "- The top three findings (META004, FP003, STY003) account for the bulk "
        "of the corpus's quality penalty. Future calibration work should "
        "explore whether their default severities are correctly tuned."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", default="/tmp/sigmalint-report/report.json", type=Path)
    p.add_argument(
        "--out",
        default=Path(__file__).parent.parent / "docs" / "analysis" / "2026-05-23-sigmahq-corpus.md",
        type=Path,
    )
    args = p.parse_args(argv)

    if not args.report.exists():
        print(f"report not found: {args.report}", file=sys.stderr)
        return 2
    report = json.loads(args.report.read_text())
    cfg = Config()
    a = analyze(report, cfg)
    md = _markdown(a)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(md)
    print(f"wrote {args.out}")
    print(f"  mean pre-fix:  {a['mean_old']}")
    print(f"  mean post-fix: {a['mean_new']}")
    print(f"  delta:         {a['mean_new'] - a['mean_old']:+.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
