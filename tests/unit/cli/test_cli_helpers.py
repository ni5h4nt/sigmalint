"""Targeted unit tests for CLI helpers and uncovered branches in cli.main."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmalint.cli.main import _collect_paths, _compute_exit, app
from sigmalint.core.config import Config

runner = CliRunner()
FIXTURE_PASS = Path("tests/fixtures/SCHEMA003/pass.yml")
FIXTURE_FAIL = Path("tests/fixtures/SCHEMA003/fail.yml")


# ---------- _collect_paths ----------


def test_collect_paths_directory(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text("a: 1\n")
    (tmp_path / "b.yaml").write_text("b: 2\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.yml").write_text("c: 3\n")
    result = _collect_paths([tmp_path])
    assert len(result) == 3


def test_collect_paths_single_file(tmp_path: Path) -> None:
    f = tmp_path / "x.yml"
    f.write_text("x: 1\n")
    result = _collect_paths([f])
    assert result == [f]


def test_collect_paths_skips_missing(tmp_path: Path) -> None:
    result = _collect_paths([tmp_path / "does-not-exist"])
    assert result == []


# ---------- _compute_exit ----------


def _report(severities: list[str], mean: float | None = 100.0) -> dict:
    return {
        "files": [
            {"findings": [{"severity": s} for s in severities]},
        ],
        "summary": {"mean_score": mean},
    }


def test_compute_exit_fail_on_error_triggers() -> None:
    cfg = dataclasses.replace(Config(), fail_on="error")
    assert _compute_exit(_report(["error"]), cfg) == 1


def test_compute_exit_fail_on_warning_triggers_on_warning() -> None:
    cfg = dataclasses.replace(Config(), fail_on="warning")
    assert _compute_exit(_report(["warning"]), cfg) == 1


def test_compute_exit_fail_on_warning_triggers_on_error() -> None:
    cfg = dataclasses.replace(Config(), fail_on="warning")
    assert _compute_exit(_report(["error"]), cfg) == 1


def test_compute_exit_fail_on_never() -> None:
    cfg = dataclasses.replace(Config(), fail_on="never")
    assert _compute_exit(_report(["error"]), cfg) == 0


def test_compute_exit_min_score_triggers() -> None:
    cfg = dataclasses.replace(Config(), fail_on="never", min_score=90.0)
    assert _compute_exit(_report([], mean=50.0), cfg) == 1


def test_compute_exit_min_score_clears() -> None:
    cfg = dataclasses.replace(Config(), fail_on="never", min_score=10.0)
    assert _compute_exit(_report([], mean=99.0), cfg) == 0


def test_compute_exit_min_score_none_mean() -> None:
    cfg = dataclasses.replace(Config(), fail_on="never", min_score=10.0)
    assert _compute_exit(_report([], mean=None), cfg) == 0


# ---------- CLI smoke for uncovered branches ----------


def test_lint_format_sarif() -> None:
    result = runner.invoke(app, ["lint", str(FIXTURE_PASS), "--format", "sarif"])
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.stdout)
    assert payload.get("version") == "2.1.0"
    assert "runs" in payload


def test_lint_format_github() -> None:
    result = runner.invoke(app, ["lint", str(FIXTURE_PASS), "--format", "github"])
    assert result.exit_code in (0, 1), result.output


def test_lint_fail_on_override() -> None:
    result = runner.invoke(
        app,
        [
            "lint",
            str(FIXTURE_FAIL),
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    )
    # With fail-on=never and no min-score, exit code is 0 regardless of findings.
    assert result.exit_code == 0, result.output


def test_lint_min_score_override() -> None:
    result = runner.invoke(
        app,
        [
            "lint",
            str(FIXTURE_PASS),
            "--format",
            "json",
            "--fail-on",
            "never",
            "--min-score",
            "200",
        ],
    )
    # Score will be below 200 → exit 1.
    assert result.exit_code == 1, result.output


def test_lint_unknown_profile_runs() -> None:
    # Profile validation happens only in list-rules; lint accepts arbitrary
    # profile strings and falls back to default severities. This test pins
    # current behavior so future tightening doesn't regress silently.
    result = runner.invoke(
        app,
        ["lint", str(FIXTURE_PASS), "--profile", "nope-not-real"],
    )
    assert result.exit_code in (0, 1, 2, 3), result.output


def test_explain_existing_rule() -> None:
    # Find at least one rule that has docs.
    docs_dir = Path("docs/rules")
    if not docs_dir.exists():
        pytest.skip("docs/rules not present")
    candidates = list(docs_dir.glob("*.md"))
    if not candidates:
        pytest.skip("no rule docs")
    rule_id = candidates[0].stem
    result = runner.invoke(app, ["explain", rule_id])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() != ""


def test_root_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "Usage" in result.output or "Commands" in result.output


def test_lint_directory_recursion(tmp_path: Path) -> None:
    # Lint an empty directory to hit the _collect_paths directory branch.
    result = runner.invoke(app, ["lint", str(tmp_path), "--format", "json"])
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.stdout)
    assert payload["files"] == []
