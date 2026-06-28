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

Rollout cadence (patches, not minors): v0.1.2 ships TAX; v0.1.3 adds
FP + META; v0.1.4 adds ATK + RED + STY; v0.1.5 adds SCHEMA (this
release, completing the v0.1.x contrived rollout). The README Roadmap
remains canonical for v0.2 (formats + AI) and v0.3 (multi-version
Sigma) scope.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from sigmalint.core.config import Config
from sigmalint.core.filters import SigmaFilter
from sigmalint.core.runner import RunContext, lint
from sigmalint.data.attack import AttackTaxonomy
from sigmalint.data.corpus import CorpusEntry
from sigmalint.data.sigma_schema import SigmaSchema
from sigmalint.data.taxonomy import (
    AttackLogsourceMap,
    SigmaModifiers,
    SigmaTaxonomy,
)
from sigmalint.rules.attack import (
    Atk001ValidTechnique,
    Atk002NotRevoked,
    Atk003LogsourcePlausible,
    Atk004SubtechniqueSpecificity,
)
from sigmalint.rules.fp_risk import (
    Fp001SingleBroadSelection,
    Fp002PreferModifiers,
    Fp003NoFilterOnNoisy,
    Fp004HardcodedLiterals,
)
from sigmalint.rules.metadata import (
    Meta001aIdPresent,
    Meta001bIdValidUuid4,
    Meta002CorePopulated,
    Meta003ReferencesForHigh,
    Meta004FalsepositivesPopulated,
    Meta005StatusVocabulary,
)
from sigmalint.rules.redundancy import (
    Red001NearDuplicateFingerprint,
    Red002TitleOrIdCollision,
)
from sigmalint.rules.schema import (
    Schema002SigmaSchema,
    Schema003RequiredKeys,
    Schema004ConditionParseable,
)
from sigmalint.rules.style import (
    Sty001LowercaseTopLevelKeys,
    Sty002LfAndYml,
    Sty003FourSpaceIndent,
)
from sigmalint.rules.taxonomy import (
    Tax001KnownFields,
    Tax002ValidModifiers,
    Tax003CanonicalField,
)

CONTRIVED_DIR = Path(__file__).parent

# Extend per-dimension as contrived coverage is added (v0.1.2: TAX only;
# v0.1.3: + FP + META; v0.1.4: + ATK + RED + STY; v0.1.5: + SCHEMA).
_RULE_MAP: dict[str, type] = {
    "TAX001": Tax001KnownFields,
    "TAX002": Tax002ValidModifiers,
    "TAX003": Tax003CanonicalField,
    "FP001": Fp001SingleBroadSelection,
    "FP002": Fp002PreferModifiers,
    "FP003": Fp003NoFilterOnNoisy,
    "FP004": Fp004HardcodedLiterals,
    "META001a": Meta001aIdPresent,
    "META001b": Meta001bIdValidUuid4,
    "META002": Meta002CorePopulated,
    "META003": Meta003ReferencesForHigh,
    "META004": Meta004FalsepositivesPopulated,
    "META005": Meta005StatusVocabulary,
    "ATK001": Atk001ValidTechnique,
    "ATK002": Atk002NotRevoked,
    "ATK003": Atk003LogsourcePlausible,
    "ATK004": Atk004SubtechniqueSpecificity,
    "RED001": Red001NearDuplicateFingerprint,
    "RED002": Red002TitleOrIdCollision,
    "STY001": Sty001LowercaseTopLevelKeys,
    "STY002": Sty002LfAndYml,
    "STY003": Sty003FourSpaceIndent,
    "SCHEMA002": Schema002SigmaSchema,
    "SCHEMA003": Schema003RequiredKeys,
    "SCHEMA004": Schema004ConditionParseable,
    # SCHEMA001 is runner-emitted (no Rule class); see the branch in
    # test_contrived_rule_shape.
}

# The ATT&CK + logsource providers fall back to the pinned vendored bundle
# (ATTACK v19.1) when the data_dir holds no override, so they are
# deterministic. Build once at import to avoid re-parsing the STIX bundle
# for every parametrized case.
_ATTACK = AttackTaxonomy(Path("<contrived-no-override>"))
_ATTACK_LOGSOURCE = AttackLogsourceMap(Path("<contrived-no-override>"))

# SigmaSchema falls back to the pinned vendored 2.1.0 bundle when the
# data_dir holds no override, so it is deterministic. Build once at import,
# mirroring _ATTACK above, so SCHEMA002 can validate without a cloned data_dir.
_SCHEMA = SigmaSchema(Path("<contrived-no-override>"))


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


def _build_filters(specs: list[dict] | None) -> list[SigmaFilter]:
    """Materialise SigmaFilter objects from manifest `filters:` specs.

    Each spec maps directly to the SigmaFilter dataclass:
      - targets_ids:   list of rule IDs the filter applies to (UUIDs)
      - targets_names: list of rule names the filter applies to
      - condition:     the filter's appended condition string
    The `path` field is set to a sentinel since contrived fixtures
    don't load filters from real .yml files.
    """
    return [
        SigmaFilter(
            path="<contrived>",
            targets_ids=tuple(spec.get("targets_ids") or ()),
            targets_names=tuple(spec.get("targets_names") or ()),
            condition=spec["condition"],
        )
        for spec in (specs or [])
    ]


class _FakeCorpus:
    """Duck-typed stand-in for RuleCorpus, driven by a manifest `corpus:` block.

    RED001 reads `available` + `near_duplicates(fp, threshold)`; RED002 reads
    `available` + `entries()`. The fake returns the manifest-declared matches
    verbatim, decoupling RED001's shape coverage from the Jaccard metric (which
    is unit-tested separately). Without a `corpus:` block `ctx.corpus` is None,
    preserving the early-return behaviour every non-RED dimension relies on.
    """

    def __init__(self, near: list[CorpusEntry], entries: list[CorpusEntry]):
        self.available = True
        self._near = near
        self._entries = entries

    def near_duplicates(self, fingerprint, threshold: float = 0.85) -> list[CorpusEntry]:
        return self._near

    def entries(self) -> list[CorpusEntry]:
        return self._entries


def _corpus_entry(spec: dict, self_path: str | None) -> CorpusEntry:
    # `<self>` resolves to the fixture's own path so RED001's self-skip
    # (m.path == parsed.path) can be exercised.
    path = spec.get("path") or "<contrived-corpus>"
    if path == "<self>" and self_path is not None:
        path = self_path
    return CorpusEntry(
        path=path,
        title=str(spec.get("title", "")),
        id=spec.get("id"),
        fingerprint=frozenset(),
    )


def _build_corpus(spec: dict | None, self_path: str | None) -> _FakeCorpus | None:
    if not spec:
        return None
    near = [_corpus_entry(d, self_path) for d in (spec.get("near_duplicates") or [])]
    entries = [_corpus_entry(d, self_path) for d in (spec.get("entries") or [])]
    return _FakeCorpus(near, entries)


def _ctx(
    tmp_path: Path,
    filter_specs: list[dict] | None = None,
    corpus_spec: dict | None = None,
    self_path: str | None = None,
) -> RunContext:
    return RunContext(
        taxonomy=SigmaTaxonomy(tmp_path),
        modifiers=SigmaModifiers(tmp_path),
        config=Config(),
        filters=_build_filters(filter_specs),
        attack=_ATTACK,
        attack_logsource=_ATTACK_LOGSOURCE,
        sigma_schema=_SCHEMA,
        corpus=_build_corpus(corpus_spec, self_path),
    )


@pytest.mark.parametrize(
    "rule_id, category, rule_dir, case",
    _collect_cases(),
    ids=_case_id,
)
def test_contrived_rule_shape(
    rule_id: str, category: str, rule_dir: Path, case: dict, tmp_path: Path
) -> None:
    # SCHEMA001 is emitted by lint() directly on YAML parse failure and has no
    # Rule class, so it is intentionally absent from _RULE_MAP. Run with an
    # empty rules list; the runner emits SCHEMA001 from the malformed fixture.
    # This branch MUST precede the _RULE_MAP lookup below.
    if rule_id == "SCHEMA001":
        rules: list = []
    else:
        rule_cls = _RULE_MAP.get(rule_id)
        if rule_cls is None:
            pytest.fail(
                f"manifest references {rule_id} but no rule class is registered "
                f"in _RULE_MAP. Add it to tests/contrived/test_contrived.py."
            )
        rules = [rule_cls()]
    fixture_path = rule_dir / case["file"]
    if not fixture_path.exists():
        pytest.fail(f"manifest references missing fixture: {fixture_path}")
    ctx = _ctx(tmp_path, case.get("filters"), case.get("corpus"), str(fixture_path))
    results = lint([fixture_path], rules, ctx)
    findings = [f for f in results[0].findings if f.rule_id == rule_id]
    default_expect = 1 if category == "positives" else 0
    expected = case.get("expect", default_expect)
    summary = case.get("summary", case["file"])
    assert len(findings) == expected, (
        f"{rule_id} {category[:-1]} '{summary}' ({case['file']}): "
        f"expected {expected} {rule_id} findings, got {len(findings)} - "
        f"{[f.message for f in findings]}"
    )
    # Optional per-fixture severity assertion. Used by rules like META001b
    # that emit at multiple severities depending on input shape.
    expected_severity = case.get("expect_severity")
    if expected_severity is not None:
        for f in findings:
            assert f.severity.value == expected_severity, (
                f"{rule_id} {category[:-1]} '{summary}' ({case['file']}): "
                f"expected severity={expected_severity!r}, got {f.severity.value!r} "
                f"on finding: {f.message}"
            )
