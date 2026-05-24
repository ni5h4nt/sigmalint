"""Tests for built-in profiles."""

from __future__ import annotations

import pytest

from sigmalint.core.errors import ConfigError
from sigmalint.core.profiles import resolve_severity
from sigmalint.core.types import Severity


def test_unknown_profile_raises() -> None:
    with pytest.raises(ConfigError):
        resolve_severity("nope", "ATK001", Severity.WARNING)


def test_default_falls_through() -> None:
    # ATK001 is not in any profile -> falls back to default.
    assert resolve_severity("sigmahq", "ATK001", Severity.ERROR) == Severity.ERROR


def test_local_disables_red001() -> None:
    assert resolve_severity("local", "RED001", Severity.INFO) is None


def test_strict_promotes_meta001a_to_error() -> None:
    assert resolve_severity("strict", "META001a", Severity.WARNING) == Severity.ERROR
