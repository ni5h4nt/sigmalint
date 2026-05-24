from sigmalint.core.config import Config
from sigmalint.core.rule import Rule
from sigmalint.core.scoring import score_file
from sigmalint.core.types import Dimension, Finding, LintResult, ParsedRule, Severity


class _StubRule(Rule):
    """Minimal Rule for scoring tests — never invoked, only inspected for id/dimension."""

    def __init__(self, rid: str, dim: Dimension) -> None:
        self.id = rid
        self.dimension = dim
        self.default_severity = Severity.WARNING

    def check(self, parsed, ctx):  # pragma: no cover - never called in scoring tests
        return ()


def _result(findings):
    return LintResult(
        parsed=ParsedRule(path="f.yml", raw_text="", data={}),
        findings=tuple(findings),
    )


def _rules_for(*dims_and_counts: tuple[Dimension, int]) -> list[Rule]:
    out: list[Rule] = []
    for dim, n in dims_and_counts:
        for i in range(n):
            out.append(_StubRule(f"{dim.value.upper()}{i:03d}", dim))
    return out


# A typical rules list mirroring the live registry shape (4 rules per quality
# dim) so the normalized math has a stable denominator to assert against.
_TYPICAL = _rules_for(
    (Dimension.ATTACK, 4),
    (Dimension.TAXONOMY, 3),
    (Dimension.FP_RISK, 4),
    (Dimension.METADATA, 6),
    (Dimension.REDUNDANCY, 2),
    (Dimension.STYLE, 3),
)


def test_invalid_when_schema_error():
    fs = score_file(
        _result([Finding("SCHEMA001", Dimension.SCHEMA, Severity.ERROR, "m", "f.yml")]),
        Config(),
        _TYPICAL,
    )
    assert fs.status == "invalid" and fs.total is None


def test_valid_when_no_schema_error():
    fs = score_file(_result([]), Config(), _TYPICAL)
    assert fs.status == "valid" and fs.total == 100.0


def test_warning_penalty_normalized():
    # ATTACK dim has 4 rules; max_penalty = 4 * 10 * 1.0 = 40.
    # Single warning penalty = 3. dim_score = 100 * (1 - 3/40) = 92.5.
    fs = score_file(
        _result([Finding("ATK002", Dimension.ATTACK, Severity.WARNING, "m", "f.yml")]),
        Config(),
        _TYPICAL,
    )
    assert fs.dimension_scores["attack"] == 92.5


def test_rule_weight_multiplier_applied():
    # FP_RISK has 4 rules; FP003 weighted 2.0 so:
    #   max_penalty = 10 * (1.0 + 1.0 + 2.0 + 1.0) = 50
    #   warning with weight 2.0 = 3 * 2 = 6
    #   dim_score = 100 * (1 - 6/50) = 88.0
    cfg = Config(rule_weights={"FP003": 2.0})
    fs = score_file(
        _result([Finding("FP003", Dimension.FP_RISK, Severity.WARNING, "m", "f.yml")]),
        cfg,
        [
            *_rules_for(
                (Dimension.ATTACK, 4),
                (Dimension.TAXONOMY, 3),
                (Dimension.FP_RISK, 3),
                (Dimension.METADATA, 6),
                (Dimension.REDUNDANCY, 2),
                (Dimension.STYLE, 3),
            ),
            _StubRule("FP003", Dimension.FP_RISK),  # explicit FP003 to match the configured weight
        ],
    )
    assert fs.dimension_scores["fp_risk"] == 88.0


def test_empty_dimension_scores_full_marks():
    # If a dimension has no enabled rules, it cannot be penalized — score 100.0.
    rules = _rules_for((Dimension.ATTACK, 4))  # no taxonomy/fp/etc rules
    fs = score_file(_result([]), Config(), rules)
    assert fs.dimension_scores["taxonomy"] == 100.0
    assert fs.dimension_scores["redundancy"] == 100.0


def test_size_invariance_property():
    """A single warning in a dimension produces the same dim_score regardless of
    the number of sibling rules in that dimension — because both penalty and
    max_penalty scale by `r.id` lookup but the per-finding penalty is fixed and
    max_penalty scales linearly with rule count. The ratio penalty/max_penalty
    therefore depends only on (rules-firing / total-rules)."""
    finding = Finding("ATK002", Dimension.ATTACK, Severity.WARNING, "m", "f.yml")

    # 1 firing rule out of 4 → 1/4 fraction at full severity.
    fs_small = score_file(
        _result([finding]),
        Config(),
        _rules_for((Dimension.ATTACK, 4)),
    )
    # 1 firing rule out of 4 again, just in a different dim sizing — the
    # firing-dimension still has 4 rules so dim_score must match exactly.
    fs_large = score_file(
        _result([finding]),
        Config(),
        _rules_for((Dimension.ATTACK, 4), (Dimension.METADATA, 20)),
    )
    assert fs_small.dimension_scores["attack"] == fs_large.dimension_scores["attack"]

    # The invariance we really want: the *fraction* (penalty / max_penalty) is
    # what determines the score. Doubling N_rules without changing firing rate
    # leaves the fraction unchanged. Two warnings out of 4 ATK rules should
    # produce the same dim_score as four warnings out of 8 ATK rules.
    f1 = score_file(
        _result(
            [
                Finding("ATK001", Dimension.ATTACK, Severity.WARNING, "m", "f.yml"),
                Finding("ATK002", Dimension.ATTACK, Severity.WARNING, "m", "f.yml"),
            ]
        ),
        Config(),
        _rules_for((Dimension.ATTACK, 4)),
    )
    f2 = score_file(
        _result(
            [
                Finding("ATK001", Dimension.ATTACK, Severity.WARNING, "m", "f.yml"),
                Finding("ATK002", Dimension.ATTACK, Severity.WARNING, "m", "f.yml"),
                Finding("ATK003", Dimension.ATTACK, Severity.WARNING, "m", "f.yml"),
                Finding("ATK004", Dimension.ATTACK, Severity.WARNING, "m", "f.yml"),
            ]
        ),
        Config(),
        _rules_for((Dimension.ATTACK, 8)),
    )
    assert f1.dimension_scores["attack"] == f2.dimension_scores["attack"]
