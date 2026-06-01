from __future__ import annotations

import pytest
from sigmalint.core.custom_rule import evaluate_when, resolve_path


# ── resolve_path ──────────────────────────────────────────────────────────────

def test_resolve_path_dot_returns_whole_doc():
    data = {"title": "Test", "level": "high"}
    assert resolve_path(data, ".") == data


def test_resolve_path_top_level_key():
    data = {"title": "Test"}
    assert resolve_path(data, "title") == "Test"


def test_resolve_path_nested_key():
    data = {"logsource": {"category": "process_creation"}}
    assert resolve_path(data, "logsource.category") == "process_creation"


def test_resolve_path_missing_key_returns_none():
    data = {"title": "Test"}
    assert resolve_path(data, "missing") is None


def test_resolve_path_missing_intermediate_returns_none():
    data = {"logsource": {"category": "process_creation"}}
    assert resolve_path(data, "logsource.product.os") is None


def test_resolve_path_list_terminal():
    data = {"tags": ["attack.t1059", "org.ref.1"]}
    assert resolve_path(data, "tags") == ["attack.t1059", "org.ref.1"]


# ── evaluate_when ─────────────────────────────────────────────────────────────

def test_when_equals_scalar_match():
    assert evaluate_when("process_creation", {"equals": "process_creation"}) is True


def test_when_equals_scalar_no_match():
    assert evaluate_when("network", {"equals": "process_creation"}) is False


def test_when_equals_list_any_match():
    assert evaluate_when(["process_creation", "network"], {"equals": "network"}) is True


def test_when_equals_list_no_match():
    assert evaluate_when(["process_creation", "network"], {"equals": "dns"}) is False


def test_when_matches_scalar():
    assert evaluate_when("process_creation", {"matches": "^process_"}) is True


def test_when_matches_scalar_no_match():
    assert evaluate_when("network", {"matches": "^process_"}) is False


def test_when_matches_list_any():
    assert evaluate_when(["proc", "net"], {"matches": "^net"}) is True


def test_when_in_passes():
    assert evaluate_when("high", {"in": ["high", "critical"]}) is True


def test_when_in_fails():
    assert evaluate_when("low", {"in": ["high", "critical"]}) is False


def test_when_exists_true_passes():
    assert evaluate_when("something", {"exists": True}) is True


def test_when_exists_true_fails_on_none():
    assert evaluate_when(None, {"exists": True}) is False


def test_when_not_exists_passes_on_none():
    assert evaluate_when(None, {"not_exists": True}) is True


def test_when_not_exists_fails_on_value():
    assert evaluate_when("something", {"not_exists": True}) is False
