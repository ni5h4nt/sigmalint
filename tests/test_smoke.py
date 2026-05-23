"""Smoke test so pytest has at least one test to collect in Phase 1.

pytest exits with code 5 if no tests are collected, which would fail the
Phase 1 CI matrix before the rest of the codebase exists. This file may be
extended in later phases but the version check stays.
"""
from sigmalint import __version__


def test_version_string():
    assert __version__ == "0.1.0"
