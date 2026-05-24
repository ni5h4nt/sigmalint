"""Integration tests for ATK001-004 rules."""

from __future__ import annotations

from pathlib import Path

from sigmalint.core.runner import RunContext, lint
from sigmalint.data.attack import AttackTaxonomy
from sigmalint.data.taxonomy import AttackLogsourceMap
from sigmalint.rules.attack import (
    Atk001ValidTechnique,
    Atk002NotRevoked,
    Atk003LogsourcePlausible,
    Atk004SubtechniqueSpecificity,
)


def _ctx(tmp_path: Path) -> RunContext:
    return RunContext(
        attack=AttackTaxonomy(tmp_path),
        attack_logsource=AttackLogsourceMap(tmp_path),
    )


def _findings_for(rule_id: str, fixture: Path, tmp_path: Path) -> list:
    rule_cls = {
        "ATK001": Atk001ValidTechnique,
        "ATK002": Atk002NotRevoked,
        "ATK003": Atk003LogsourcePlausible,
        "ATK004": Atk004SubtechniqueSpecificity,
    }[rule_id]
    results = lint([fixture], [rule_cls()], _ctx(tmp_path))
    return [f for r in results for f in r.findings if f.rule_id == rule_id]


def test_atk001_pass(fixtures_dir: Path, tmp_path: Path):
    assert _findings_for("ATK001", fixtures_dir / "ATK001" / "pass.yml", tmp_path) == []


def test_atk001_fail(fixtures_dir: Path, tmp_path: Path):
    findings = _findings_for("ATK001", fixtures_dir / "ATK001" / "fail.yml", tmp_path)
    assert len(findings) == 1
    assert "t9999" in findings[0].message.lower()


def test_atk002_pass(fixtures_dir: Path, tmp_path: Path):
    assert _findings_for("ATK002", fixtures_dir / "ATK002" / "pass.yml", tmp_path) == []


def test_atk002_fail(fixtures_dir: Path, tmp_path: Path):
    findings = _findings_for("ATK002", fixtures_dir / "ATK002" / "fail.yml", tmp_path)
    assert len(findings) == 1
    assert "revoked" in findings[0].message.lower() or "deprecated" in findings[0].message.lower()


def test_atk003_pass(fixtures_dir: Path, tmp_path: Path):
    assert _findings_for("ATK003", fixtures_dir / "ATK003" / "pass.yml", tmp_path) == []


def test_atk003_fail(fixtures_dir: Path, tmp_path: Path):
    findings = _findings_for("ATK003", fixtures_dir / "ATK003" / "fail.yml", tmp_path)
    assert len(findings) == 1
    assert "registry_event" in findings[0].message


def test_atk004_pass(fixtures_dir: Path, tmp_path: Path):
    assert _findings_for("ATK004", fixtures_dir / "ATK004" / "pass.yml", tmp_path) == []


def test_atk004_fail(fixtures_dir: Path, tmp_path: Path):
    findings = _findings_for("ATK004", fixtures_dir / "ATK004" / "fail.yml", tmp_path)
    assert len(findings) == 1
    assert "T1059.001" in findings[0].message
