from pathlib import Path

from sigmalint.data.taxonomy import AttackLogsourceMap, SigmaModifiers, SigmaTaxonomy


def test_known_field(tmp_path: Path):
    t = SigmaTaxonomy(tmp_path)
    assert t.is_known("sigma", "process_creation", "Image")


def test_unknown_field_in_known_logsource(tmp_path: Path):
    t = SigmaTaxonomy(tmp_path)
    assert not t.is_known("sigma", "process_creation", "Bogus")


def test_modifier_strip(tmp_path: Path):
    t = SigmaTaxonomy(tmp_path)
    assert t.is_known("sigma", "process_creation", "Image|contains")


def test_alias(tmp_path: Path):
    t = SigmaTaxonomy(tmp_path)
    assert t.canonical("sigma", "process_creation", "ImagePath") == "Image"


def test_modifiers(tmp_path: Path):
    m = SigmaModifiers(tmp_path)
    assert m.is_known("contains") and not m.is_known("bogus")


def test_attack_logsource_plausible(tmp_path: Path):
    a = AttackLogsourceMap(tmp_path)
    assert a.plausible("T1059", "process_creation", None)
    assert not a.plausible("T1059", "registry_event", None)
    assert a.plausible("T9999", "anything", None)  # unknown -> no signal
