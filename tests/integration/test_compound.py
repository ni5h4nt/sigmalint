"""Golden tests on compound-defect fixtures.

Per-rule fixtures only exercise rules in isolation. Real Sigma rules
typically trigger several findings simultaneously across dimensions.
These golden tests assert that, on hand-crafted multi-defect fixtures:

- every expected (rule_id, severity) pair appears,
- forbidden rule_ids never fire (false-positive guard),
- the total score stays within a calibrated [floor, ceiling] band.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigmalint.core.config import Config
from sigmalint.core.profiles import resolve_severity
from sigmalint.core.registry import enabled_rules
from sigmalint.core.runner import RunContext, lint
from sigmalint.core.scoring import score_file
from sigmalint.data.attack import AttackTaxonomy
from sigmalint.data.corpus import RuleCorpus
from sigmalint.data.sigma_schema import SigmaSchema
from sigmalint.data.taxonomy import AttackLogsourceMap, SigmaModifiers, SigmaTaxonomy

# Import rule modules so they register with the global registry. The cli
# normally owns this; tests must do it explicitly.
from sigmalint.rules import attack as _a  # noqa: F401
from sigmalint.rules import fp_risk as _fp  # noqa: F401
from sigmalint.rules import metadata as _m  # noqa: F401
from sigmalint.rules import redundancy as _r  # noqa: F401
from sigmalint.rules import schema as _s  # noqa: F401
from sigmalint.rules import style as _st  # noqa: F401
from sigmalint.rules import taxonomy as _t  # noqa: F401

COMPOUND_DIR = Path(__file__).parent.parent / "fixtures" / "compound"
EXPECTED: dict = json.loads((COMPOUND_DIR / "expected.json").read_text())


def _build_ctx(cfg: Config) -> RunContext:
    data_dir = Path(cfg.data_dir).expanduser()
    v = cfg.target_sigma_version
    return RunContext(
        attack=AttackTaxonomy(data_dir),
        sigma_schema=SigmaSchema(data_dir, version=v),
        taxonomy=SigmaTaxonomy(data_dir, version=v),
        modifiers=SigmaModifiers(data_dir, version=v),
        attack_logsource=AttackLogsourceMap(data_dir),
        corpus=RuleCorpus(data_dir),
        config=cfg,
        filters=[],
    )


def _resolved_rules(cfg: Config):
    """Replicate the cli's severity-resolution + drop-disabled-rules step."""
    rules = enabled_rules(disabled=(), enable_only=None)
    kept = []
    for r in rules:
        eff = resolve_severity(cfg.profile, r.id, r.default_severity)
        if eff is None:
            continue
        if r.id in cfg.severities:
            eff = cfg.severities[r.id]
        r.default_severity = eff
        kept.append(r)
    return kept


@pytest.mark.parametrize("filename", sorted(EXPECTED.keys()))
def test_compound_fixture(filename: str) -> None:
    f = COMPOUND_DIR / filename
    spec = EXPECTED[filename]
    cfg = Config()
    rules = _resolved_rules(cfg)
    ctx = _build_ctx(cfg)
    results = lint([f], rules, ctx)
    result = results[0]
    score = score_file(result, cfg)

    assert result.parsed.yaml_error is None, (
        f"{filename}: YAML parse failed: {result.parsed.yaml_error}"
    )

    found = {(x.rule_id, x.severity.value) for x in result.findings}
    found_ids = {x.rule_id for x in result.findings}

    for entry in spec["must_include"]:
        match = (entry["rule_id"], entry["severity"])
        assert match in found, (
            f"{filename}: expected finding {match} not in actual: {sorted(found)}"
        )

    for rid in spec.get("must_not_include", []):
        assert rid not in found_ids, (
            f"{filename}: forbidden rule {rid} fired: "
            f"{[fnd for fnd in result.findings if fnd.rule_id == rid]}"
        )

    if "status" in spec:
        assert score.status == spec["status"], (
            f"{filename}: expected status {spec['status']!r}, got {score.status!r}"
        )
    if "score_floor" in spec and score.total is not None:
        assert score.total >= spec["score_floor"], (
            f"{filename}: score {score.total} below floor {spec['score_floor']}"
        )
    if "score_ceiling" in spec and score.total is not None:
        assert score.total <= spec["score_ceiling"], (
            f"{filename}: score {score.total} above ceiling {spec['score_ceiling']}"
        )
