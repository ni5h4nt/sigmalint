"""Integration tests for FP001-004 against pass/fail fixtures."""

from __future__ import annotations

import pytest

from sigmalint.core.runner import RunContext, lint
from sigmalint.rules.fp_risk import (
    Fp001SingleBroadSelection,
    Fp002PreferModifiers,
    Fp003NoFilterOnNoisy,
    Fp004HardcodedLiterals,
)

RULE_MAP = {
    "FP001": Fp001SingleBroadSelection,
    "FP002": Fp002PreferModifiers,
    "FP003": Fp003NoFilterOnNoisy,
    "FP004": Fp004HardcodedLiterals,
}


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_pass_fixture(rule_id, fixtures_dir):
    f = fixtures_dir / rule_id / "pass.yml"
    ctx = RunContext()
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert all(x.rule_id != rule_id for x in results[0].findings), (
        f"{rule_id} pass fixture unexpectedly produced findings: {results[0].findings}"
    )


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_fail_fixture(rule_id, fixtures_dir):
    f = fixtures_dir / rule_id / "fail.yml"
    ctx = RunContext()
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert any(x.rule_id == rule_id for x in results[0].findings), (
        f"{rule_id} fail fixture did not produce a {rule_id} finding"
    )


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_pass_lookalike_does_not_fire(rule_id, fixtures_dir):
    """Lookalike fixture resembles the fail case but is NOT a violation
    of THIS rule. Verifies no false positives on superficially-similar inputs."""
    f = fixtures_dir / rule_id / "pass_lookalike.yml"
    if not f.exists():
        pytest.skip(f"no pass_lookalike fixture for {rule_id}")
    ctx = RunContext()
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert all(x.rule_id != rule_id for x in results[0].findings), (
        f"{rule_id} pass_lookalike unexpectedly produced a {rule_id} finding: "
        f"{results[0].findings}"
    )
