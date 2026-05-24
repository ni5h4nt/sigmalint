from collections.abc import Iterable
from pathlib import Path

import pytest

from sigmalint.core.registry import reset_registry_for_tests
from sigmalint.core.rule import Rule
from sigmalint.core.runner import RunContext, lint
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


class AlwaysWarn(Rule):
    id = "TST001"
    dimension = Dimension.SCHEMA
    default_severity = Severity.WARNING
    summary = "always emits a warning"

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        yield Finding(
            self.id,
            self.dimension,
            self.default_severity,
            "boom",
            parsed.path,
        )


class Crashy(Rule):
    id = "TST002"
    dimension = Dimension.SCHEMA
    default_severity = Severity.WARNING
    summary = "raises"

    def check(self, parsed: ParsedRule, ctx: object) -> Iterable[Finding]:
        raise RuntimeError("nope")


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_registry_for_tests()


def _write(p: Path, body: str) -> Path:
    p.write_text(body, encoding="utf-8")
    return p


def test_runs_simple_rule(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.yml",
        "title: t\nlogsource: {category: foo}\n"
        "detection: {selection: {a: 1}, condition: selection}\n",
    )
    results = lint([f], [AlwaysWarn()], RunContext())
    assert len(results) == 1
    assert len(results[0].findings) == 1
    assert results[0].findings[0].rule_id == "TST001"


def test_yaml_error_becomes_schema001(tmp_path: Path) -> None:
    f = _write(tmp_path / "bad.yml", "title: : :\n")
    results = lint([f], [AlwaysWarn()], RunContext())
    assert results[0].findings[0].rule_id == "SCHEMA001"


def test_rule_exception_becomes_internal001(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.yml",
        "title: t\ndetection: {a: {b: 1}, condition: a}\n"
        "logsource: {category: foo}\n",
    )
    results = lint([f], [Crashy()], RunContext())
    rids = [fi.rule_id for fi in results[0].findings]
    assert "INTERNAL001" in rids


def test_inline_suppression(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.yml",
        "title: t  # sigmalint: disable=TST001\n"
        "detection: {a: {b: 1}, condition: a}\n"
        "logsource: {category: foo}\n",
    )
    results = lint([f], [AlwaysWarn()], RunContext())
    assert results[0].findings == ()
    assert "TST001" in results[0].suppressions
