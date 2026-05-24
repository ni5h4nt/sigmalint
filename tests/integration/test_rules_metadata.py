"""Integration tests for META001a/b-META005 against pass/fail fixtures."""
from __future__ import annotations

import pytest

from sigmalint.core.runner import RunContext, lint
from sigmalint.rules.metadata import (
    Meta001aIdPresent,
    Meta001bIdValidUuid4,
    Meta002CorePopulated,
    Meta003ReferencesForHigh,
    Meta004FalsepositivesPopulated,
    Meta005StatusVocabulary,
)

RULE_MAP = {
    "META001a": Meta001aIdPresent,
    "META001b": Meta001bIdValidUuid4,
    "META002": Meta002CorePopulated,
    "META003": Meta003ReferencesForHigh,
    "META004": Meta004FalsepositivesPopulated,
    "META005": Meta005StatusVocabulary,
}


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_pass_fixture(rule_id, fixtures_dir):
    f = fixtures_dir / rule_id / "pass.yml"
    ctx = RunContext()
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert all(x.rule_id != rule_id for x in results[0].findings), (
        f"{rule_id} pass fixture unexpectedly produced findings: "
        f"{results[0].findings}"
    )


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_fail_fixture(rule_id, fixtures_dir):
    f = fixtures_dir / rule_id / "fail.yml"
    ctx = RunContext()
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert any(x.rule_id == rule_id for x in results[0].findings), (
        f"{rule_id} fail fixture did not produce a {rule_id} finding"
    )
