from __future__ import annotations

import pytest
from sigmalint.core.custom_rule import evaluate_when, resolve_path


# ── resolve_path ──────────────────────────────────────────────────────────────

def test_resolve_path_dot_returns_whole_doc():
    data = {"title": "Test", "level": "high"}
    assert resolve_path(data, ".") == data


def test_resolve_path_top_level_key():
    data = {"title": "Test"}
    assert resolve_path(data, "title") == "Test"


def test_resolve_path_nested_key():
    data = {"logsource": {"category": "process_creation"}}
    assert resolve_path(data, "logsource.category") == "process_creation"


def test_resolve_path_missing_key_returns_none():
    data = {"title": "Test"}
    assert resolve_path(data, "missing") is None


def test_resolve_path_missing_intermediate_returns_none():
    data = {"logsource": {"category": "process_creation"}}
    assert resolve_path(data, "logsource.product.os") is None


def test_resolve_path_list_terminal():
    data = {"tags": ["attack.t1059", "org.ref.1"]}
    assert resolve_path(data, "tags") == ["attack.t1059", "org.ref.1"]


# ── evaluate_when ─────────────────────────────────────────────────────────────

def test_when_equals_scalar_match():
    assert evaluate_when("process_creation", {"equals": "process_creation"}) is True


def test_when_equals_scalar_no_match():
    assert evaluate_when("network", {"equals": "process_creation"}) is False


def test_when_equals_list_any_match():
    assert evaluate_when(["process_creation", "network"], {"equals": "network"}) is True


def test_when_equals_list_no_match():
    assert evaluate_when(["process_creation", "network"], {"equals": "dns"}) is False


def test_when_matches_scalar():
    assert evaluate_when("process_creation", {"matches": "^process_"}) is True


def test_when_matches_scalar_no_match():
    assert evaluate_when("network", {"matches": "^process_"}) is False


def test_when_matches_list_any():
    assert evaluate_when(["proc", "net"], {"matches": "^net"}) is True


def test_when_in_passes():
    assert evaluate_when("high", {"in": ["high", "critical"]}) is True


def test_when_in_fails():
    assert evaluate_when("low", {"in": ["high", "critical"]}) is False


def test_when_in_passes_when_list_item_in_set():
    assert evaluate_when(["high", "critical"], {"in": ["critical", "medium"]}) is True


def test_when_in_fails_when_no_list_item_in_set():
    assert evaluate_when(["low", "info"], {"in": ["critical", "medium"]}) is False


def test_when_exists_true_passes():
    assert evaluate_when("something", {"exists": True}) is True


def test_when_exists_true_fails_on_none():
    assert evaluate_when(None, {"exists": True}) is False


def test_when_not_exists_passes_on_none():
    assert evaluate_when(None, {"not_exists": True}) is True


def test_when_not_exists_fails_on_value():
    assert evaluate_when("something", {"not_exists": True}) is False


import pytest
from sigmalint.core.check_functions import register_function
from sigmalint.core.custom_rule import CustomRuleLoader
from sigmalint.core.errors import ConfigError
from sigmalint.core.registry import all_rules, reset_registry_for_tests
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


@pytest.fixture(autouse=True)
def clean_registry():
    """Reset rule registry between tests to avoid ID collision."""
    yield
    reset_registry_for_tests()


def _minimal_rule_dict() -> dict:
    return {
        "message": "Tags must include org.ref",
        "given": "tags",
        "then": {"function": "contains_match", "options": {"pattern": "^org\\.ref\\."}},
    }


def test_compile_produces_registered_rule():
    CustomRuleLoader.compile({"ORG001": _minimal_rule_dict()})
    ids = [r.id for r in all_rules()]
    assert "ORG001" in ids


def test_compiled_rule_has_correct_dimension_and_severity():
    d = {**_minimal_rule_dict(), "severity": "error", "dimension": "fp_risk"}
    CustomRuleLoader.compile({"ORG001": d})
    rule = next(r for r in all_rules() if r.id == "ORG001")
    assert rule.default_severity == Severity.ERROR
    assert rule.dimension == Dimension.FP_RISK


def test_compiled_rule_check_yields_finding_on_fail():
    CustomRuleLoader.compile({"ORG001": _minimal_rule_dict()})
    rule = next(r for r in all_rules() if r.id == "ORG001")
    parsed = ParsedRule(
        path="test.yml", raw_text="", data={"tags": ["attack.t1059"]}
    )
    findings = list(rule.check(parsed, None))
    assert len(findings) == 1
    assert findings[0].rule_id == "ORG001"
    assert findings[0].severity == Severity.WARNING


def test_compiled_rule_check_no_finding_on_pass():
    CustomRuleLoader.compile({"ORG001": _minimal_rule_dict()})
    rule = next(r for r in all_rules() if r.id == "ORG001")
    parsed = ParsedRule(
        path="test.yml", raw_text="", data={"tags": ["org.ref.123"]}
    )
    findings = list(rule.check(parsed, None))
    assert findings == []


def test_compiled_rule_when_guard_skips_when_condition_not_met():
    d = {
        "message": "process_creation needs filter",
        "given": "logsource.category",
        "when": {"equals": "process_creation"},
        "then": {"function": "condition_has_filter"},
    }
    CustomRuleLoader.compile({"ORG002": d})
    rule = next(r for r in all_rules() if r.id == "ORG002")
    # logsource.category = "network" — when guard not met → no finding
    parsed = ParsedRule(
        path="test.yml",
        raw_text="",
        data={
            "logsource": {"category": "network"},
            "detection": {"condition": "selection"},
        },
    )
    assert list(rule.check(parsed, None)) == []


def test_missing_message_raises_config_error():
    with pytest.raises(ConfigError, match="missing required key 'message'"):
        CustomRuleLoader.compile(
            {"ORG001": {"then": {"function": "required"}}}
        )


def test_missing_then_function_raises_config_error():
    with pytest.raises(ConfigError, match="missing required key 'then.function'"):
        CustomRuleLoader.compile({"ORG001": {"message": "x", "then": {}}})


def test_unknown_function_raises_config_error():
    with pytest.raises(ConfigError, match="unknown function 'no_such_fn'"):
        CustomRuleLoader.compile(
            {"ORG001": {"message": "x", "then": {"function": "no_such_fn"}}}
        )


def test_invalid_severity_raises_config_error():
    with pytest.raises(ConfigError):
        CustomRuleLoader.compile(
            {
                "ORG001": {
                    "message": "x",
                    "then": {"function": "required"},
                    "severity": "super_error",
                }
            }
        )
