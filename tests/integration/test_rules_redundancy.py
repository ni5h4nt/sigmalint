"""Integration tests for RED001-002 rules."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sigmalint.core.runner import RunContext, lint
from sigmalint.data.corpus import CorpusEntry
from sigmalint.rules.redundancy import (
    Red001NearDuplicateFingerprint,
    Red002TitleOrIdCollision,
)


@dataclass
class _StubCorpus:
    """Test stub mimicking the RuleCorpus surface used by RED rules."""

    _entries: list[CorpusEntry]
    available: bool = True

    def entries(self) -> list[CorpusEntry]:
        return self._entries

    def near_duplicates(
        self, fingerprint: frozenset[str], threshold: float = 0.85
    ) -> list[CorpusEntry]:
        return list(self._entries)


def _ctx(corpus: object | None = None) -> RunContext:
    return RunContext(corpus=corpus)


def _findings_for(
    rule_cls, fixture: Path, ctx: RunContext, rule_id: str
) -> list:
    results = lint([fixture], [rule_cls()], ctx)
    return [f for r in results for f in r.findings if f.rule_id == rule_id]


def test_red001_no_corpus_emits_nothing(fixtures_dir: Path):
    # When ctx.corpus is None, the rule must run without error and emit nothing.
    findings = _findings_for(
        Red001NearDuplicateFingerprint,
        fixtures_dir / "RED001" / "fail.yml",
        _ctx(corpus=None),
        "RED001",
    )
    assert findings == []


def test_red001_pass_with_stub_corpus_no_match(fixtures_dir: Path):
    stub = _StubCorpus(_entries=[])
    findings = _findings_for(
        Red001NearDuplicateFingerprint,
        fixtures_dir / "RED001" / "pass.yml",
        _ctx(corpus=stub),
        "RED001",
    )
    assert findings == []


def test_red001_fail_with_stub_corpus(fixtures_dir: Path):
    entry = CorpusEntry(
        path="public/rules/dup.yml",
        title="Public Duplicate",
        id="00000000-0000-0000-0000-000000000000",
        fingerprint=frozenset({"image::\\duplicate.exe"}),
    )
    stub = _StubCorpus(_entries=[entry])
    findings = _findings_for(
        Red001NearDuplicateFingerprint,
        fixtures_dir / "RED001" / "fail.yml",
        _ctx(corpus=stub),
        "RED001",
    )
    assert len(findings) == 1
    assert "Public Duplicate" in findings[0].message


def test_red002_no_corpus_emits_nothing(fixtures_dir: Path):
    findings = _findings_for(
        Red002TitleOrIdCollision,
        fixtures_dir / "RED002" / "fail.yml",
        _ctx(corpus=None),
        "RED002",
    )
    assert findings == []


def test_red002_pass_with_stub_corpus_no_collision(fixtures_dir: Path):
    entry = CorpusEntry(
        path="public/rules/other.yml",
        title="Some Other Rule",
        id="99999999-9999-9999-9999-999999999999",
        fingerprint=frozenset({"image::\\other.exe"}),
    )
    stub = _StubCorpus(_entries=[entry])
    findings = _findings_for(
        Red002TitleOrIdCollision,
        fixtures_dir / "RED002" / "pass.yml",
        _ctx(corpus=stub),
        "RED002",
    )
    assert findings == []


def test_red002_fail_title_collision(fixtures_dir: Path):
    entry = CorpusEntry(
        path="public/rules/collide.yml",
        title="RED002 collision title",
        id="00000000-0000-0000-0000-000000000000",
        fingerprint=frozenset({"image::\\collision.exe"}),
    )
    stub = _StubCorpus(_entries=[entry])
    findings = _findings_for(
        Red002TitleOrIdCollision,
        fixtures_dir / "RED002" / "fail.yml",
        _ctx(corpus=stub),
        "RED002",
    )
    assert len(findings) == 1
    assert "collides" in findings[0].message
