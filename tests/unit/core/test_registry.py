from collections.abc import Iterable

import pytest

from sigmalint.core.errors import ConfigError
from sigmalint.core.registry import all_rules, enabled_rules, register, reset_registry_for_tests
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


def _make_rule(rid: str):
    @register
    class _R(Rule):
        id = rid
        dimension = Dimension.SCHEMA
        default_severity = Severity.WARNING
        summary = "t"

        def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
            return ()
    return _R


@pytest.fixture(autouse=True)
def _reset():
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()


def test_register_adds_rule():
    _make_rule("X001")
    assert {r.id for r in all_rules()} == {"X001"}


def test_register_rejects_duplicate_id():
    _make_rule("X001")
    with pytest.raises(ConfigError):
        _make_rule("X001")


def test_register_rejects_missing_id():
    with pytest.raises(ConfigError):
        @register
        class _Bad(Rule):
            dimension = Dimension.SCHEMA
            default_severity = Severity.INFO

            def check(self, p, c):
                return ()


def test_enabled_rules_disable_filter():
    _make_rule("X001")
    _make_rule("X002")
    rules = enabled_rules(disabled=["X001"], enable_only=None)
    assert [r.id for r in rules] == ["X002"]


def test_enabled_rules_enable_only_filter():
    _make_rule("X001")
    _make_rule("X002")
    rules = enabled_rules(disabled=[], enable_only=["X001"])
    assert [r.id for r in rules] == ["X001"]


def test_unknown_rule_id_in_disable_raises():
    _make_rule("X001")
    with pytest.raises(ConfigError):
        enabled_rules(disabled=["NOPE"], enable_only=None)
