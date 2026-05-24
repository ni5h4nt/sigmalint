"""Unit tests for Sigma Filter discovery and rule matching."""

from __future__ import annotations

from pathlib import Path

from sigmalint.core.filters import SigmaFilter, discover_filters, filters_for_rule


def _write(p: Path, body: str) -> Path:
    p.write_text(body, encoding="utf-8")
    return p


def test_discover_filters_finds_top_level_filter_mapping(tmp_path: Path) -> None:
    _write(
        tmp_path / "f.yml",
        "title: My filter\n"
        "logsource:\n  category: process_creation\n"
        "filter:\n"
        "  rules:\n    - 12345678-1234-1234-1234-1234567890ab\n"
        "  selection:\n    Image: bar\n"
        "  condition: not selection\n",
    )
    found = discover_filters(["*.yml"], tmp_path)
    assert len(found) == 1
    assert "12345678-1234-1234-1234-1234567890ab" in found[0].targets_ids
    assert found[0].condition == "not selection"


def test_discover_filters_no_kind_field_required(tmp_path: Path) -> None:
    # Real Sigma spec does NOT include a `kind: filter` field.
    _write(
        tmp_path / "f.yml",
        "title: t\nfilter:\n  rules:\n    - some-rule-name\n  condition: not x\n",
    )
    found = discover_filters(["*.yml"], tmp_path)
    assert len(found) == 1
    assert found[0].targets_names == ("some-rule-name",)


def test_discover_filters_ignores_non_filter_docs(tmp_path: Path) -> None:
    _write(
        tmp_path / "rule.yml",
        "title: regular rule\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image: a\n  condition: selection\n",
    )
    _write(
        tmp_path / "bad.yml",
        "filter:\n  rules: []\n  condition: not x\n",
    )
    _write(
        tmp_path / "missing_condition.yml",
        "filter:\n  rules:\n    - foo\n",
    )
    found = discover_filters(["*.yml"], tmp_path)
    assert found == []


def test_discover_filters_ignores_malformed_yaml(tmp_path: Path) -> None:
    _write(tmp_path / "bad.yml", "title: : :\n")
    found = discover_filters(["*.yml"], tmp_path)
    assert found == []


def test_filters_for_rule_matches_by_id() -> None:
    f = SigmaFilter(
        path="/x.yml",
        targets_ids=("12345678-1234-1234-1234-1234567890ab",),
        targets_names=(),
        condition="not selection",
    )
    out = filters_for_rule([f], "12345678-1234-1234-1234-1234567890ab", None, None)
    assert out == [f]


def test_filters_for_rule_matches_by_name() -> None:
    f = SigmaFilter(
        path="/x.yml",
        targets_ids=(),
        targets_names=("the-rule-name",),
        condition="not selection",
    )
    assert filters_for_rule([f], None, "the-rule-name", None) == [f]


def test_filters_for_rule_matches_by_title_fallback() -> None:
    f = SigmaFilter(
        path="/x.yml",
        targets_ids=(),
        targets_names=("Some Rule Title",),
        condition="not selection",
    )
    assert filters_for_rule([f], None, None, "Some Rule Title") == [f]


def test_filters_for_rule_no_match() -> None:
    f = SigmaFilter(
        path="/x.yml",
        targets_ids=("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",),
        targets_names=("other-name",),
        condition="not selection",
    )
    assert filters_for_rule([f], "different-id", "different", "Different") == []


def test_filters_for_rule_handles_none_inputs() -> None:
    f = SigmaFilter(
        path="/x.yml",
        targets_ids=("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",),
        targets_names=(),
        condition="not selection",
    )
    assert filters_for_rule([f], None, None, None) == []
