from pathlib import Path

from sigmalint.data.attack import AttackTaxonomy, technique_from_tag


def test_known_technique(tmp_path: Path):
    a = AttackTaxonomy(tmp_path)
    assert a.is_valid_technique("T1059")


def test_unknown_technique(tmp_path: Path):
    a = AttackTaxonomy(tmp_path)
    assert not a.is_valid_technique("T9999")


def test_tag_parser():
    assert technique_from_tag("attack.t1059") == "T1059"
    assert technique_from_tag("attack.t1059.001") == "T1059.001"
    assert technique_from_tag("attack.execution") is None
    assert technique_from_tag("attack.g0007") is None
