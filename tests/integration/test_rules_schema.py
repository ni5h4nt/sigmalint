"""Integration tests for SCHEMA002-004 against pass/fail fixtures."""

from __future__ import annotations

import pytest

from sigmalint.core.runner import RunContext, lint
from sigmalint.data.sigma_schema import SigmaSchema
from sigmalint.rules.schema import (
    Schema002SigmaSchema,
    Schema003RequiredKeys,
    Schema004ConditionParseable,
)

RULE_MAP = {
    "SCHEMA002": Schema002SigmaSchema,
    "SCHEMA003": Schema003RequiredKeys,
    "SCHEMA004": Schema004ConditionParseable,
}


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_pass_fixture(rule_id, fixtures_dir, tmp_path):
    f = fixtures_dir / rule_id / "pass.yml"
    ctx = RunContext(sigma_schema=SigmaSchema(tmp_path))
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert all(x.rule_id != rule_id for x in results[0].findings), (
        f"{rule_id} pass fixture unexpectedly produced findings: {results[0].findings}"
    )


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_fail_fixture(rule_id, fixtures_dir, tmp_path):
    f = fixtures_dir / rule_id / "fail.yml"
    ctx = RunContext(sigma_schema=SigmaSchema(tmp_path))
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert any(x.rule_id == rule_id for x in results[0].findings), (
        f"{rule_id} fail fixture did not produce a {rule_id} finding"
    )


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_pass_lookalike_does_not_fire(rule_id, fixtures_dir, tmp_path):
    """Lookalike fixture resembles the fail case but is NOT a violation
    of THIS rule. Verifies no false positives on superficially-similar inputs."""
    f = fixtures_dir / rule_id / "pass_lookalike.yml"
    if not f.exists():
        pytest.skip(f"no pass_lookalike fixture for {rule_id}")
    ctx = RunContext(sigma_schema=SigmaSchema(tmp_path))
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert all(x.rule_id != rule_id for x in results[0].findings), (
        f"{rule_id} pass_lookalike unexpectedly produced a {rule_id} finding: "
        f"{results[0].findings}"
    )
