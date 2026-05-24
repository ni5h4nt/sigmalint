from pathlib import Path

from sigmalint.data.corpus import RuleCorpus, fingerprint_for_rule


def test_no_corpus_returns_empty(tmp_path: Path):
    rc = RuleCorpus(tmp_path)
    assert not rc.available
    assert rc.entries() == []


def test_fingerprint_stable():
    a = {"detection": {"sel": {"Image": "x"}, "condition": "sel"}}
    b = {"detection": {"different_name": {"Image": "x"}, "condition": "different_name"}}
    assert fingerprint_for_rule(a) == fingerprint_for_rule(b)


def test_jaccard_basic():
    assert RuleCorpus.jaccard(frozenset({"a", "b"}), frozenset({"a", "c"})) == 1 / 3
