"""Sigma detection.condition parser.

Grammar (Sigma 2.1.0):
    expr     := or_expr
    or_expr  := and_expr ("or" and_expr)*
    and_expr := not_expr ("and" not_expr)*
    not_expr := "not"? primary
    primary  := "(" expr ")"
              | quantifier
              | IDENT
    quantifier := ("1" | "all") "of" (IDENT_WITH_WILDCARD | "them")
    IDENT             := selector name; may be underscore-prefixed for "filter"
    IDENT_WITH_WILDCARD := IDENT with optional trailing "*"

The runner also accepts a list of strings under `condition`, OR-joined.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import pyparsing as pp

from sigmalint.core.errors import SigmalintError


class ConditionParseError(SigmalintError):
    pass


# AST
@dataclass(frozen=True, slots=True)
class Ident:
    name: str


@dataclass(frozen=True, slots=True)
class Quantifier:
    n: str  # "1" or "all"
    pattern: str  # selector name with optional wildcards, or "them"


@dataclass(frozen=True, slots=True)
class Not:
    expr: object


@dataclass(frozen=True, slots=True)
class And:
    items: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class Or:
    items: tuple[object, ...]


# Grammar
#
# Selector identifiers may include `*` and `?` wildcards anywhere (Sigma allows
# patterns like `*selection`, `sel*tion`, `filter_?`). We also accept an
# underscore-prefixed identifier for filter-exclusion convention.
def _build_grammar() -> pp.ParserElement:
    # Exclude reserved condition keywords from bare identifiers so that
    # malformed input like "selection and and" fails to parse instead of
    # being treated as `and` selector.
    reserved = {"and", "or", "not", "of", "them", "1", "all"}
    ident = pp.Regex(r"[A-Za-z_*?][A-Za-z0-9_*?]*").add_condition(
        lambda toks: toks[0] not in reserved
    )
    n_keyword = pp.one_of("1 all")
    quant = pp.Group(n_keyword + pp.Keyword("of") + (ident | pp.Keyword("them")))
    expr = pp.Forward()
    primary = pp.Suppress("(") + expr + pp.Suppress(")") | quant | ident
    not_expr = pp.Group(pp.Keyword("not") + primary) | primary
    and_expr = pp.Group(not_expr + pp.OneOrMore(pp.Keyword("and") + not_expr)) | not_expr
    or_expr = pp.Group(and_expr + pp.OneOrMore(pp.Keyword("or") + and_expr)) | and_expr
    expr <<= or_expr
    return expr


_GRAMMAR = _build_grammar()


def _to_ast(node: object) -> object:
    if isinstance(node, str):
        return Ident(node)
    items = list(node)  # type: ignore[call-overload]
    if items and items[0] == "not":
        return Not(_to_ast(items[1]))
    if items and items[0] in ("1", "all"):
        return Quantifier(n=items[0], pattern=items[2])
    if "or" in items:
        return Or(tuple(_to_ast(x) for x in items if x != "or"))
    if "and" in items:
        return And(tuple(_to_ast(x) for x in items if x != "and"))
    if len(items) == 1:
        return _to_ast(items[0])
    raise ConditionParseError(f"Unrecognized parse node: {items!r}")


def parse(condition: str | list[str]) -> object:
    """Parse a Sigma condition string (or list of strings, OR-joined) to AST."""
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    try:
        result = _GRAMMAR.parse_string(condition, parse_all=True)
    except pp.ParseException as e:
        raise ConditionParseError(f"Bad condition {condition!r}: {e}") from e
    return _to_ast(result[0] if len(result) == 1 else list(result))


def referenced_selectors(ast: object) -> set[str]:
    """Return the set of selector name patterns referenced (wildcards expanded later)."""
    if isinstance(ast, Ident):
        return {ast.name}
    if isinstance(ast, Quantifier):
        return {ast.pattern} if ast.pattern != "them" else set()
    if isinstance(ast, Not):
        return referenced_selectors(ast.expr)
    if isinstance(ast, (And, Or)):
        out: set[str] = set()
        for item in ast.items:
            out |= referenced_selectors(item)
        return out
    return set()


def is_wildcard_pattern(pat: str) -> bool:
    """Return True if `pat` contains a Sigma selector-pattern wildcard (`*` or `?`)."""
    return "*" in pat or "?" in pat


def _wildcard_to_regex(pat: str) -> re.Pattern[str]:
    # Escape the pattern then translate Sigma globs into regex.
    escaped = re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{escaped}$")


def expand_patterns(referenced: Iterable[str], available: Iterable[str]) -> set[str]:
    """Expand wildcard selector patterns against the available selector set.

    Supports `*` (any) and `?` (single char) at any position, matching Sigma's
    selector-pattern semantics — not just trailing wildcards.
    """
    available_set = set(available)
    out: set[str] = set()
    for ref in referenced:
        if is_wildcard_pattern(ref):
            rx = _wildcard_to_regex(ref)
            out |= {s for s in available_set if rx.match(s)}
        elif ref in available_set:
            out.add(ref)
    return out


def has_negated_selector(
    ast: object,
    predicate: Callable[[str], bool],
    *,
    _negated: bool = False,
) -> bool:
    """True if any selector matching predicate(name) appears under a `not` in the AST.

    Negation is propagated through recursion so grouped forms like
    `not (filter1 or filter2)` correctly report the inner selectors as negated.
    Sigma's condition grammar does not include explicit double negation; if the
    `not` keyword nests, each Not toggles the carried flag.
    """
    if isinstance(ast, Not):
        return has_negated_selector(ast.expr, predicate, _negated=not _negated)
    if isinstance(ast, (And, Or)):
        return any(has_negated_selector(item, predicate, _negated=_negated) for item in ast.items)
    if isinstance(ast, Ident):
        return _negated and predicate(ast.name)
    if isinstance(ast, Quantifier):
        return _negated and predicate(ast.pattern)
    return False
