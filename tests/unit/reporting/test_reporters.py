"""Tests for the reporting layer: model builder + 4 formatters."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from sigmalint.core.scoring import FileScore
from sigmalint.core.types import Dimension, Finding, LintResult, ParsedRule, Severity
from sigmalint.reporting import github as github_fmt
from sigmalint.reporting import json as json_fmt
from sigmalint.reporting import model as model_mod
from sigmalint.reporting import sarif as sarif_fmt
from sigmalint.reporting import text as text_fmt

GOLDEN_PATH = (
    Path(__file__).resolve().parents[2] / "fixtures" / "reports" / "golden.json"
)


@pytest.fixture
def golden_report() -> dict:
    return json.loads(GOLDEN_PATH.read_text())


def _make_results_and_scores() -> tuple[list[LintResult], list[FileScore]]:
    valid_parsed = ParsedRule(
        path="rules/win_susp_foo.yml",
        raw_text="",
        data={"title": "Suspicious Foo"},
        positions={},
    )
    valid_result = LintResult(
        parsed=valid_parsed,
        findings=(
            Finding(
                rule_id="FP003",
                dimension=Dimension.FP_RISK,
                severity=Severity.WARNING,
                message=(
                    "process_creation rule has no negated filter "
                    "selector in detection.condition"
                ),
                file="rules/win_susp_foo.yml",
                line=12,
                col=3,
                fix_hint=(
                    "Add a filter selector and exclude it in the condition, "
                    "e.g. `selection and not filter_known_admin`"
                ),
            ),
        ),
    )
    invalid_parsed = ParsedRule(
        path="rules/broken.yml", raw_text="", data={}, positions={}
    )
    invalid_result = LintResult(
        parsed=invalid_parsed,
        findings=(
            Finding(
                rule_id="SCHEMA002",
                dimension=Dimension.SCHEMA,
                severity=Severity.ERROR,
                message="missing required property 'detection'",
                file="rules/broken.yml",
                line=1,
                col=1,
                fix_hint="Add a 'detection:' block.",
            ),
        ),
    )

    valid_score = FileScore(
        path="rules/win_susp_foo.yml",
        status="valid",
        dimension_scores={
            "attack": 97,
            "taxonomy": 100,
            "fp_risk": 91,
            "metadata": 94,
            "redundancy": 100,
            "style": 100,
        },
        total=95.8,
    )
    invalid_score = FileScore(
        path="rules/broken.yml",
        status="invalid",
        dimension_scores={},
        total=None,
    )
    return [valid_result, invalid_result], [valid_score, invalid_score]


# --- model.build_report --------------------------------------------------


def test_build_report_matches_golden(golden_report: dict) -> None:
    results, scores = _make_results_and_scores()
    report = model_mod.build_report(
        results,
        scores,
        profile="sigmahq",
        data_versions=golden_report["data_versions"],
    )
    assert report == golden_report


def test_build_report_empty_inputs() -> None:
    report = model_mod.build_report(
        [],
        [],
        profile="sigmahq",
        data_versions={"sigma_schema": "2.1.0"},
    )
    assert report["files"] == []
    assert report["summary"]["files"] == 0
    assert report["summary"]["mean_score"] is None
    assert report["summary"]["by_severity"] == {"error": 0, "warning": 0, "info": 0}
    assert report["sigmalint_version"]


def test_build_report_mean_over_valid_only() -> None:
    results, scores = _make_results_and_scores()
    report = model_mod.build_report(
        results, scores, profile="sigmahq", data_versions={}
    )
    # invalid file's None total must not pollute mean
    assert report["summary"]["mean_score"] == 95.8


# --- json formatter ------------------------------------------------------


def test_json_formatter_roundtrip(golden_report: dict) -> None:
    stream = io.StringIO()
    json_fmt.render(golden_report, stream)
    parsed = json.loads(stream.getvalue())
    assert parsed == golden_report


# --- text formatter ------------------------------------------------------


def test_text_formatter_renders_paths_and_summary(golden_report: dict) -> None:
    stream = io.StringIO()
    text_fmt.render(golden_report, stream)
    out = stream.getvalue()
    assert "rules/win_susp_foo.yml" in out
    assert "rules/broken.yml" in out
    assert "FP003" in out
    assert "files=2" in out
    assert "valid=1" in out
    assert "invalid=1" in out
    assert "mean_score=95.80" in out


# --- sarif formatter -----------------------------------------------------


def test_sarif_formatter_structure(golden_report: dict) -> None:
    stream = io.StringIO()
    sarif_fmt.render(golden_report, stream)
    doc = json.loads(stream.getvalue())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "sigmalint"
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"FP003", "SCHEMA002"}
    # severity → level mapping
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["FP003"] == "warning"
    assert levels["SCHEMA002"] == "error"
    # physical location populated
    loc = results[0]["locations"][0]["physicalLocation"]
    assert "artifactLocation" in loc
    assert loc["artifactLocation"]["uri"].startswith("rules/")


def test_sarif_collects_unique_rules(golden_report: dict) -> None:
    doc = sarif_fmt.build_sarif(golden_report)
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert sorted(rule_ids) == ["FP003", "SCHEMA002"]


# --- github formatter ----------------------------------------------------


def test_github_formatter_emits_workflow_commands(golden_report: dict) -> None:
    stream = io.StringIO()
    github_fmt.render(golden_report, stream)
    out = stream.getvalue()
    # warning → ::warning, error → ::error
    assert "::warning " in out
    assert "::error " in out
    assert "file=rules/win_susp_foo.yml" in out
    assert "line=12" in out
    assert "col=3" in out
    assert "file=rules/broken.yml" in out
    # summary line
    assert "sigmalint: files=2" in out
    assert "errors=1" in out
    assert "warnings=1" in out


def test_github_formatter_severity_mapping() -> None:
    report = {
        "files": [
            {
                "path": "x.yml",
                "findings": [
                    {
                        "rule_id": "R1",
                        "severity": "info",
                        "message": "hi",
                        "line": 1,
                        "col": 1,
                    }
                ],
            }
        ],
        "summary": {
            "files": 1,
            "valid": 1,
            "invalid": 0,
            "findings": 1,
            "by_severity": {"error": 0, "warning": 0, "info": 1},
            "mean_score": 100.0,
        },
    }
    stream = io.StringIO()
    github_fmt.render(report, stream)
    out = stream.getvalue()
    assert "::notice " in out
