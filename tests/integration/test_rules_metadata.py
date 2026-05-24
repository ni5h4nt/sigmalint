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
        f"{rule_id} pass_lookalike unexpectedly produced a {rule_id} finding: {results[0].findings}"
    )


def test_meta001b_unparseable_id_is_error(tmp_path):
    # Severity-split: an unparseable id (no UUID at all) stays at ERROR.
    from sigmalint.core.types import Severity

    f = tmp_path / "r.yml"
    f.write_text(
        "title: t\nid: not-a-uuid-at-all\nlogsource: {category: foo}\n"
        "detection: {a: {b: 1}, condition: a}\n"
    )
    results = lint([f], [Meta001bIdValidUuid4()], RunContext())
    meta = [x for x in results[0].findings if x.rule_id == "META001b"]
    assert len(meta) == 1
    assert meta[0].severity == Severity.ERROR


def test_meta001b_uuidv1_is_warning(tmp_path):
    # Severity-split: a parseable non-v4 UUID is WARNING (not ERROR).
    # The string `572b12d4-9062-11ed-a1eb-0242ac120002` is a real UUIDv1
    # (the `11ed` after `9062-` marks version 1).
    from sigmalint.core.types import Severity

    f = tmp_path / "r.yml"
    f.write_text(
        "title: t\nid: 572b12d4-9062-11ed-a1eb-0242ac120002\n"
        "logsource: {category: foo}\n"
        "detection: {a: {b: 1}, condition: a}\n"
    )
    results = lint([f], [Meta001bIdValidUuid4()], RunContext())
    meta = [x for x in results[0].findings if x.rule_id == "META001b"]
    assert len(meta) == 1
    assert meta[0].severity == Severity.WARNING
    assert "UUIDv1" in meta[0].message
