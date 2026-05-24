import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from sigmalint.core.condition import (
    And,
    ConditionParseError,
    Ident,
    Or,
    Quantifier,
    expand_patterns,
    has_negated_selector,
    parse,
    referenced_selectors,
)


@pytest.mark.parametrize(
    "c,expected_type",
    [
        ("selection", Ident),
        ("selection and filter", And),
        ("selection or other", Or),
        ("selection and not filter", And),
        ("1 of selection*", Quantifier),
        ("all of them", Quantifier),
        ("(a or b) and not c", And),
    ],
)
def test_parses_common_forms(c, expected_type):
    assert isinstance(parse(c), expected_type)


def test_list_valued_condition():
    ast = parse(["selection", "other"])
    assert isinstance(ast, Or)


def test_bad_condition_raises():
    with pytest.raises(ConditionParseError):
        parse("selection and and")


def test_referenced_selectors_basic():
    ast = parse("selection and not filter_admin")
    assert referenced_selectors(ast) == {"selection", "filter_admin"}


def test_expand_patterns():
    assert expand_patterns({"filter*"}, {"filter_a", "filter_b", "selection"}) == {
        "filter_a",
        "filter_b",
    }


def test_has_negated_selector_true():
    ast = parse("selection and not filter_a")
    assert has_negated_selector(ast, lambda n: n.startswith("filter"))


def test_has_negated_selector_false():
    ast = parse("selection and filter_a")
    assert not has_negated_selector(ast, lambda n: n.startswith("filter"))


def test_has_negated_selector_grouped():
    # `not (filter1 or filter2)` — negation must propagate through Or.
    ast = parse("selection and not (filter1 or filter2)")
    assert has_negated_selector(ast, lambda n: n.startswith("filter"))


def test_has_negated_selector_grouped_quantifier():
    ast = parse("selection and not 1 of filter*")
    assert has_negated_selector(ast, lambda n: n.startswith("filter"))


_RESERVED = {"or", "and", "not", "of", "all", "them"}


@given(st.from_regex(r"^[a-z][a-z0-9_]{0,8}$", fullmatch=True))
def test_single_ident_round_trip(name):
    # Skip reserved condition keywords which are not valid bare identifiers.
    assume(name not in _RESERVED)
    ast = parse(name)
    assert ast == Ident(name)


@given(st.binary(min_size=0, max_size=200))
@settings(max_examples=500, deadline=None)
def test_parse_is_total_no_unexpected_exception(payload: bytes):
    """Totality property: parse() over any byte string either returns an AST
    or raises ConditionParseError. No other exception escapes.

    This underwrites the validity gate: SCHEMA004 uses parse() to determine
    whether detection.condition is well-formed; if parse() could raise something
    other than ConditionParseError on a malformed condition, the runner's
    _safe_check wrapper would catch it as INTERNAL001 instead of producing the
    intended SCHEMA004 finding.
    """
    try:
        text = payload.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""
    try:
        parse(text)
    except ConditionParseError:
        pass  # expected on malformed input
    except Exception as e:  # pragma: no cover - property-test guard
        raise AssertionError(
            f"parse() raised non-ConditionParseError on {text!r}: {type(e).__name__}: {e}"
        ) from e
