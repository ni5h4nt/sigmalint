from __future__ import annotations

from sigmalint.core.check_functions import (
    get_function,
    register_function,
)


def test_register_and_get():
    name = "_test_fn_unique_12345"
    register_function(name, lambda v, o, p, c: True)
    assert get_function(name) is not None
    # Clean up to avoid polluting registry for other tests
    from sigmalint.core.check_functions import _REGISTRY
    _REGISTRY.pop(name, None)


def test_get_unknown_returns_none():
    assert get_function("no_such_fn") is None


def test_required_passes_when_value_present():
    fn = get_function("required")
    assert fn("hello", {}, None, None) is True


def test_required_fails_when_value_none():
    fn = get_function("required")
    assert fn(None, {}, None, None) is False


def test_pattern_passes_when_matches():
    fn = get_function("pattern")
    assert fn("proc_creation", {"match": "^proc_"}, None, None) is True


def test_pattern_fails_when_no_match():
    fn = get_function("pattern")
    assert fn("other", {"match": "^proc_"}, None, None) is False


def test_enum_passes_when_in_set():
    fn = get_function("enum")
    assert fn("stable", {"values": ["stable", "test"]}, None, None) is True


def test_enum_fails_when_not_in_set():
    fn = get_function("enum")
    assert fn("unknown", {"values": ["stable", "test"]}, None, None) is False


def test_min_length_passes_string():
    fn = get_function("min_length")
    assert fn("hello", {"min": 3}, None, None) is True


def test_min_length_fails_string():
    fn = get_function("min_length")
    assert fn("hi", {"min": 3}, None, None) is False


def test_min_length_passes_list():
    fn = get_function("min_length")
    assert fn(["a", "b"], {"min": 2}, None, None) is True


def test_min_length_fails_list():
    fn = get_function("min_length")
    assert fn(["a"], {"min": 2}, None, None) is False


def test_max_length_passes():
    fn = get_function("max_length")
    assert fn("hi", {"max": 5}, None, None) is True


def test_max_length_fails():
    fn = get_function("max_length")
    assert fn("toolongstring", {"max": 5}, None, None) is False


def test_max_length_passes_list():
    fn = get_function("max_length")
    assert fn(["a", "b"], {"max": 3}, None, None) is True


def test_max_length_fails_list():
    fn = get_function("max_length")
    assert fn(["a", "b", "c", "d"], {"max": 3}, None, None) is False


def test_contains_match_passes_when_any_item_matches():
    fn = get_function("contains_match")
    assert fn(["attack.defense", "org.ref.123"], {"pattern": "^org\\.ref\\."}, None, None) is True


def test_contains_match_fails_when_no_item_matches():
    fn = get_function("contains_match")
    assert fn(["attack.defense", "attack.t1059"], {"pattern": "^org\\.ref\\."}, None, None) is False


def test_contains_match_works_on_scalar():
    fn = get_function("contains_match")
    assert fn("org.ref.123", {"pattern": "^org\\.ref\\."}, None, None) is True


def test_all_match_passes_when_all_items_match():
    fn = get_function("all_match")
    assert fn(["org.ref.1", "org.ref.2"], {"pattern": "^org\\."}, None, None) is True


def test_all_match_fails_when_any_item_mismatches():
    fn = get_function("all_match")
    assert fn(["org.ref.1", "attack.t1059"], {"pattern": "^org\\."}, None, None) is False


def test_all_match_works_on_scalar():
    fn = get_function("all_match")
    assert fn("org.ref.1", {"pattern": "^org\\."}, None, None) is True


from sigmalint.core.types import ParsedRule


def _make_parsed(detection: dict) -> ParsedRule:
    return ParsedRule(path="test.yml", raw_text="", data={"detection": detection})


def test_condition_has_filter_passes_when_negated_filter_present():
    fn = get_function("condition_has_filter")
    parsed = _make_parsed({"condition": "selection and not filter_known"})
    assert fn(None, {}, parsed, None) is True


def test_condition_has_filter_fails_when_no_negated_filter():
    fn = get_function("condition_has_filter")
    parsed = _make_parsed({"condition": "selection"})
    assert fn(None, {}, parsed, None) is False


def test_condition_has_filter_fails_when_no_detection():
    fn = get_function("condition_has_filter")
    parsed = ParsedRule(path="test.yml", raw_text="", data={})
    assert fn(None, {}, parsed, None) is False


def test_condition_references_selector_passes_when_name_found():
    fn = get_function("condition_references_selector")
    parsed = _make_parsed({"condition": "selection and not filter_admin"})
    assert fn(None, {"name": "filter_admin"}, parsed, None) is True


def test_condition_references_selector_fails_when_name_absent():
    fn = get_function("condition_references_selector")
    parsed = _make_parsed({"condition": "selection"})
    assert fn(None, {"name": "filter_admin"}, parsed, None) is False


def test_condition_references_selector_supports_regex():
    fn = get_function("condition_references_selector")
    parsed = _make_parsed({"condition": "selection and not filter_known_admin"})
    assert fn(None, {"name": "filter_.*"}, parsed, None) is True
