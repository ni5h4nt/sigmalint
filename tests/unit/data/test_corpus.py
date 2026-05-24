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


def test_jaccard_empty_edges():
    assert RuleCorpus.jaccard(frozenset(), frozenset()) == 1.0
    assert RuleCorpus.jaccard(frozenset({"a"}), frozenset()) == 0.0
    assert RuleCorpus.jaccard(frozenset(), frozenset({"a"})) == 0.0


def test_corpus_indexes_real_rules(tmp_path: Path):
    rules = tmp_path / "corpus" / "rules"
    rules.mkdir(parents=True)
    (rules / "ok.yml").write_text(
        "title: Rule A\n"
        "id: 00000000-0000-0000-0000-000000000001\n"
        "detection:\n"
        "  selection:\n"
        "    EventID: 4625\n"
        "    Image:\n"
        "      - cmd.exe\n"
        "      - powershell.exe\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    # Invalid yaml — skipped silently.
    (rules / "bad.yml").write_text("::: not yaml :::\n", encoding="utf-8")
    # Non-dict yaml — skipped.
    (rules / "list.yml").write_text("- a\n- b\n", encoding="utf-8")
    # Empty detection — skipped (no tokens).
    (rules / "empty.yml").write_text("title: E\ndetection: {}\n", encoding="utf-8")
    # Non-dict selector — branch coverage.
    (rules / "mixed.yml").write_text(
        "title: M\ndetection:\n  sel:\n    F: v\n  other: scalar\n  condition: sel\n",
        encoding="utf-8",
    )

    rc = RuleCorpus(tmp_path)
    assert rc.available
    entries = rc.entries()
    # Two entries with non-empty fingerprints.
    assert len(entries) == 2
    fps = {tok for e in entries for tok in e.fingerprint}
    assert "eventid::4625" in fps
    assert "image::cmd.exe" in fps
    # entries() is cached.
    assert rc.entries() is entries


def test_near_duplicates_threshold(tmp_path: Path):
    rules = tmp_path / "corpus" / "rules"
    rules.mkdir(parents=True)
    (rules / "r.yml").write_text(
        "title: T\ndetection:\n  s:\n    A: x\n    B: y\n  condition: s\n",
        encoding="utf-8",
    )
    rc = RuleCorpus(tmp_path)
    assert rc.near_duplicates(frozenset({"a::x", "b::y"}), threshold=0.9)
    assert rc.near_duplicates(frozenset({"z::z"}), threshold=0.9) == []


def test_data_version_no_corpus(tmp_path: Path):
    assert RuleCorpus(tmp_path).data_version is None


def test_data_version_no_git_in_corpus(tmp_path: Path):
    # Corpus dir exists but is not a git repo → data_version returns None.
    (tmp_path / "corpus" / "rules").mkdir(parents=True)
    assert RuleCorpus(tmp_path).data_version is None
