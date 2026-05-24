"""Integration tests for STY001-003 rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigmalint.core.runner import RunContext, lint
from sigmalint.rules.style import (
    Sty001LowercaseTopLevelKeys,
    Sty002LfAndYml,
    Sty003FourSpaceIndent,
)


def _findings_for(rule_id: str, fixture: Path) -> list:
    rule_cls = {
        "STY001": Sty001LowercaseTopLevelKeys,
        "STY002": Sty002LfAndYml,
        "STY003": Sty003FourSpaceIndent,
    }[rule_id]
    results = lint([fixture], [rule_cls()], RunContext())
    return [f for r in results for f in r.findings if f.rule_id == rule_id]


def test_sty001_pass(fixtures_dir: Path):
    assert _findings_for("STY001", fixtures_dir / "STY001" / "pass.yml") == []


def test_sty001_fail(fixtures_dir: Path):
    findings = _findings_for("STY001", fixtures_dir / "STY001" / "fail.yml")
    assert len(findings) == 1
    assert "Title" in findings[0].message


def test_sty002_pass(fixtures_dir: Path):
    assert _findings_for("STY002", fixtures_dir / "STY002" / "pass.yml") == []


def test_sty002_fail(fixtures_dir: Path):
    findings = _findings_for("STY002", fixtures_dir / "STY002" / "fail.yaml")
    assert len(findings) == 1
    assert ".yml" in findings[0].message


def test_sty003_pass(fixtures_dir: Path):
    assert _findings_for("STY003", fixtures_dir / "STY003" / "pass.yml") == []


def test_sty003_fail(fixtures_dir: Path):
    findings = _findings_for("STY003", fixtures_dir / "STY003" / "fail.yml")
    assert len(findings) == 1
    assert "4-space step" in findings[0].message


@pytest.mark.parametrize("rule_id", ["STY001", "STY002", "STY003"])
def test_pass_lookalike_does_not_fire(rule_id: str, fixtures_dir: Path):
    """Lookalike fixture resembles the fail case but is NOT a violation
    of THIS rule. Verifies no false positives on superficially-similar inputs."""
    f = fixtures_dir / rule_id / "pass_lookalike.yml"
    if not f.exists():
        pytest.skip(f"no pass_lookalike fixture for {rule_id}")
    assert _findings_for(rule_id, f) == []
