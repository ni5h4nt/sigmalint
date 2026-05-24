from sigmalint.core.config import Config
from sigmalint.core.scoring import score_file
from sigmalint.core.types import Dimension, Finding, LintResult, ParsedRule, Severity


def _result(findings):
    return LintResult(
        parsed=ParsedRule(path="f.yml", raw_text="", data={}),
        findings=tuple(findings),
    )


def test_invalid_when_schema_error():
    fs = score_file(
        _result(
            [Finding("SCHEMA001", Dimension.SCHEMA, Severity.ERROR, "m", "f.yml")]
        ),
        Config(),
    )
    assert fs.status == "invalid" and fs.total is None


def test_valid_when_no_schema_error():
    fs = score_file(_result([]), Config())
    assert fs.status == "valid" and fs.total == 100.0


def test_warning_penalty():
    fs = score_file(
        _result(
            [Finding("ATK002", Dimension.ATTACK, Severity.WARNING, "m", "f.yml")]
        ),
        Config(),
    )
    assert fs.dimension_scores["attack"] == 97.0


def test_rule_weight_multiplier_applied():
    cfg = Config(rule_weights={"FP003": 2.0})
    fs = score_file(
        _result(
            [Finding("FP003", Dimension.FP_RISK, Severity.WARNING, "m", "f.yml")]
        ),
        cfg,
    )
    assert fs.dimension_scores["fp_risk"] == 94.0  # 100 - 3*2
