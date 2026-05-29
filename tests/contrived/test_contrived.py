"""Contrived rule-shape distribution tests.

For each rule, a `tests/contrived/<RULE_ID>/` directory contains:

- `manifest.yml`: machine-readable ground truth per fixture (positives,
  negatives, edges) with expected finding counts and short summaries.
- One YAML fixture per case, with `pos_*`, `neg_*`, or `edge_*` filename
  prefix matching the manifest category.

The parametrized loader below collects every case from every dimension's
manifest and asserts the rule under test fires the expected number of
times. Negative + edge cases default to `expect: 0`; positive cases
declare `expect:` explicitly.

This complements the code-coverage tests in `tests/unit/`: code coverage
checks every line was executed; shape coverage checks every rule input
shape was exercised. The TAX walker bug (v0.1.x) was a code-coverage
success and a shape-coverage failure - the walker line ran, but the
list-of-dict selector shape was never input.

To add a new dimension's coverage, drop a manifest + fixtures into
`tests/contrived/<RULE_ID>/` and extend `_RULE_MAP` below.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from sigmalint.core.config import Config
from sigmalint.core.registry import reset_registry_for_tests
from sigmalint.core.runner import RunContext, lint
from sigmalint.data.taxonomy import SigmaModifiers, SigmaTaxonomy
from sigmalint.rules.taxonomy import (
    Tax001KnownFields,
    Tax002ValidModifiers,
    Tax003CanonicalField,
)

CONTRIVED_DIR = Path(__file__).parent

# Extend per-dimension as contrived coverage is added (v0.2: TAX only;
# v0.3: + FP + META; v0.4: + ATK + RED + STY; v0.5: + SCHEMA).
_RULE_MAP: dict[str, type] = {
    "TAX001": Tax001KnownFields,
    "TAX002": Tax002ValidModifiers,
    "TAX003": Tax003CanonicalField,
}


def _load_manifest(rule_dir: Path) -> dict[str, Any]:
    with (rule_dir / "manifest.yml").open() as f:
        return yaml.safe_load(f)


def _collect_cases() -> list[tuple[str, str, Path, dict]]:
    cases: list[tuple[str, str, Path, dict]] = []
    for manifest_path in sorted(CONTRIVED_DIR.glob("*/manifest.yml")):
        rule_dir = manifest_path.parent
        manifest = _load_manifest(rule_dir)
        rule_id = manifest["rule_id"]
        for category in ("positives", "negatives", "edges"):
            for case in manifest.get(category, []) or []:
                cases.append((rule_id, category, rule_dir, case))
    return cases


def _case_id(val: Any) -> str:
    if isinstance(val, dict):
        return val.get("file", "?")
    if isinstance(val, Path):
        return val.name
    return str(val)


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_registry_for_tests()


def _ctx(tmp_path: Path) -> RunContext:
    return RunContext(
        taxonomy=SigmaTaxonomy(tmp_path),
        modifiers=SigmaModifiers(tmp_path),
        config=Config(),
    )


@pytest.mark.parametrize(
    "rule_id, category, rule_dir, case",
    _collect_cases(),
    ids=_case_id,
)
def test_contrived_rule_shape(
    rule_id: str, category: str, rule_dir: Path, case: dict, tmp_path: Path
) -> None:
    rule_cls = _RULE_MAP.get(rule_id)
    if rule_cls is None:
        pytest.fail(
            f"manifest references {rule_id} but no rule class is registered "
            f"in _RULE_MAP. Add it to tests/contrived/test_contrived.py."
        )
    fixture_path = rule_dir / case["file"]
    if not fixture_path.exists():
        pytest.fail(f"manifest references missing fixture: {fixture_path}")
    rule = rule_cls()
    results = lint([fixture_path], [rule], _ctx(tmp_path))
    findings = [f for f in results[0].findings if f.rule_id == rule_id]
    default_expect = 1 if category == "positives" else 0
    expected = case.get("expect", default_expect)
    summary = case.get("summary", case["file"])
    assert len(findings) == expected, (
        f"{rule_id} {category[:-1]} '{summary}' ({case['file']}): "
        f"expected {expected} {rule_id} findings, got {len(findings)} - "
        f"{[f.message for f in findings]}"
    )
