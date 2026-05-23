import pytest

from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


def test_finding_is_frozen():
    f = Finding(
        rule_id="X1",
        dimension=Dimension.SCHEMA,
        severity=Severity.ERROR,
        message="m",
        file="f.yml",
    )
    with pytest.raises(AttributeError):
        f.message = "new"  # type: ignore[misc]


def test_severity_str_value():
    assert Severity.ERROR.value == "error"
    assert Dimension.FP_RISK.value == "fp_risk"


def test_parsed_rule_position_for_default():
    p = ParsedRule(path="f.yml", raw_text="", data={})
    assert p.position_for("id") == (1, 1)


def test_parsed_rule_position_for_known():
    p = ParsedRule(
        path="f.yml",
        raw_text="",
        data={},
        positions={"detection/selection/Image": (12, 5)},
    )
    assert p.position_for("detection", "selection", "Image") == (12, 5)


def test_parsed_rule_position_for_unknown_uses_default():
    p = ParsedRule(path="f.yml", raw_text="", data={})
    assert p.position_for("nope", default=(99, 99)) == (99, 99)


def test_errors_hierarchy():
    from sigmalint.core.errors import (
        ConfigError,
        DataLoadError,
        RuleCheckError,
        SigmalintError,
    )

    assert issubclass(ConfigError, SigmalintError)
    assert issubclass(DataLoadError, SigmalintError)
    assert issubclass(RuleCheckError, SigmalintError)
