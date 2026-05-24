"""Smoke tests for the sigmalint Typer app."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sigmalint.cli.main import app

runner = CliRunner()
FIXTURE_PASS = Path("tests/fixtures/SCHEMA003/pass.yml")
FIXTURE_FAIL = Path("tests/fixtures/SCHEMA003/fail.yml")


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert "sigmalint " in result.stdout


def test_list_rules_default_profile() -> None:
    result = runner.invoke(app, ["list-rules"])
    assert result.exit_code == 0, result.output
    # Spot-check that at least a few rules are listed.
    assert "SCHEMA003" in result.stdout
    assert "META001a" in result.stdout


def test_list_rules_with_profile() -> None:
    result = runner.invoke(app, ["list-rules", "--profile", "local"])
    assert result.exit_code == 0, result.output
    # In `local`, RED001 is disabled (OFF).
    assert "RED001" in result.stdout
    assert "OFF" in result.stdout


def test_list_rules_unknown_profile() -> None:
    result = runner.invoke(app, ["list-rules", "--profile", "nope"])
    assert result.exit_code == 2


def test_profiles_command() -> None:
    result = runner.invoke(app, ["profiles"])
    assert result.exit_code == 0, result.output
    assert "## strict" in result.stdout
    assert "## sigmahq" in result.stdout
    assert "## local" in result.stdout


def test_explain_missing_rule_exits_2() -> None:
    result = runner.invoke(app, ["explain", "NONEXISTENT999"])
    assert result.exit_code == 2


def test_lint_json_emits_canonical_report() -> None:
    result = runner.invoke(
        app, ["lint", str(FIXTURE_PASS), "--format", "json"]
    )
    # Exit may be 0 or 1 depending on quality findings; output must parse.
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.stdout)
    assert "sigmalint_version" in payload
    assert "profile" in payload
    assert "data_versions" in payload
    assert "files" in payload
    assert "summary" in payload
    assert len(payload["files"]) == 1
    assert payload["files"][0]["path"].endswith("pass.yml")


def test_lint_text_format() -> None:
    result = runner.invoke(app, ["lint", str(FIXTURE_PASS)])
    assert result.exit_code in (0, 1), result.output


def test_lint_disable_flag() -> None:
    result = runner.invoke(
        app,
        [
            "lint",
            str(FIXTURE_PASS),
            "--format",
            "json",
            "--disable",
            "META001a",
        ],
    )
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.stdout)
    for f in payload["files"]:
        for finding in f["findings"]:
            assert finding["rule_id"] != "META001a"


def test_lint_profile_override() -> None:
    result = runner.invoke(
        app,
        [
            "lint",
            str(FIXTURE_PASS),
            "--format",
            "json",
            "--profile",
            "local",
        ],
    )
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.stdout)
    assert payload["profile"] == "local"
