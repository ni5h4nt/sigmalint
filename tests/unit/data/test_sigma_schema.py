from pathlib import Path

from sigmalint.data.sigma_schema import SigmaSchema


def test_valid_rule_has_no_errors(tmp_path: Path):
    schema = SigmaSchema(tmp_path)
    good = {
        "title": "T",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": {"Image": "x"}, "condition": "selection"},
    }
    assert schema.validate(good) == []


def test_missing_required_field_returns_error(tmp_path: Path):
    schema = SigmaSchema(tmp_path)
    bad = {"title": "T"}
    errs = schema.validate(bad)
    assert any("logsource" in e or "detection" in e for e in errs)
