from __future__ import annotations

from pathlib import Path

import pytest

from sigmalint.core.config import load_config
from sigmalint.core.errors import ConfigError
from sigmalint.core.types import Severity


def test_defaults(tmp_path: Path) -> None:
    c = load_config(tmp_path / "missing.yml")
    assert c.profile == "sigmahq"
    assert c.taxonomy == "sigma"
    assert c.filters_paths == ("filters/**/*.yml",)
    assert c.dimension_weights["attack"] == 0.22


def test_unknown_profile_raises(tmp_path: Path) -> None:
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("profile: nope\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_severity_override(tmp_path: Path) -> None:
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("severities:\n  TAX003: warning\n")
    c = load_config(p)
    assert c.severities["TAX003"] == Severity.WARNING


def test_bad_fail_on(tmp_path: Path) -> None:
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("fail_on: maybe\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_filters_paths_round_trip(tmp_path: Path) -> None:
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("filters_paths: ['x/*.yml','y/*.yml']\n")
    c = load_config(p)
    assert c.filters_paths == ("x/*.yml", "y/*.yml")


def test_target_sigma_version_default(tmp_path: Path) -> None:
    c = load_config(tmp_path / "missing.yml")
    assert c.target_sigma_version == "2.1.0"


def test_target_sigma_version_accepted(tmp_path: Path) -> None:
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("target_sigma_version: 2.1.0\n")
    c = load_config(p)
    assert c.target_sigma_version == "2.1.0"


def test_target_sigma_version_unsupported_raises(tmp_path: Path) -> None:
    # v0.1 reserves the key but only ships 2.1.0. v0.2+ widens this.
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("target_sigma_version: 2.2.0\n")
    with pytest.raises(ConfigError):
        load_config(p)
