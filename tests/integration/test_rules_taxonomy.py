"""Integration tests for TAX001-003 against fixture YAMLs."""
from __future__ import annotations

from pathlib import Path

import pytest

from sigmalint.core.config import Config
from sigmalint.core.registry import reset_registry_for_tests
from sigmalint.core.runner import RunContext, lint
from sigmalint.data.taxonomy import SigmaModifiers, SigmaTaxonomy
from sigmalint.rules.taxonomy import (
    Tax001KnownFields,
    Tax002ValidModifiers,
    Tax003CanonicalField,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_registry_for_tests()


def _ctx(tmp_path: Path) -> RunContext:
    return RunContext(
        taxonomy=SigmaTaxonomy(tmp_path),
        modifiers=SigmaModifiers(tmp_path),
        config=Config(),
    )


def _findings(rule, fixture_dir: str, name: str, tmp_path: Path) -> list:
    path = FIXTURES / fixture_dir / name
    results = lint([path], [rule], _ctx(tmp_path))
    return [f for f in results[0].findings if f.rule_id == rule.id]


def test_tax001_pass(tmp_path: Path) -> None:
    assert _findings(Tax001KnownFields(), "TAX001", "pass.yml", tmp_path) == []


def test_tax001_fail(tmp_path: Path) -> None:
    fs = _findings(Tax001KnownFields(), "TAX001", "fail.yml", tmp_path)
    assert len(fs) == 1
    assert "BogusField" in fs[0].message


def test_tax002_pass(tmp_path: Path) -> None:
    assert _findings(Tax002ValidModifiers(), "TAX002", "pass.yml", tmp_path) == []


def test_tax002_fail(tmp_path: Path) -> None:
    fs = _findings(Tax002ValidModifiers(), "TAX002", "fail.yml", tmp_path)
    assert len(fs) == 1
    assert "contianz" in fs[0].message


def test_tax003_pass(tmp_path: Path) -> None:
    assert _findings(Tax003CanonicalField(), "TAX003", "pass.yml", tmp_path) == []


def test_tax003_fail(tmp_path: Path) -> None:
    fs = _findings(Tax003CanonicalField(), "TAX003", "fail.yml", tmp_path)
    assert len(fs) == 1
    assert "Image" in fs[0].message
    assert "ImagePath" in fs[0].message
