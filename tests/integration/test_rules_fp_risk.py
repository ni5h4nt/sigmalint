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
