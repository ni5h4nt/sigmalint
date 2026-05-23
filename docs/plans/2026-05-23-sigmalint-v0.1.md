# sigmalint v0.1 Implementation Plan

> **For Claude:** REQUIRED: Use the casef skill to execute this plan.

**Goal:** Ship a `pip install`-able, MIT-licensed CLI linter for Sigma 2.1.0 detection rules with 26 built-in rules across 1 validity gate + 6 quality dimensions, JSON/text/SARIF/GitHub-Actions output, three profiles, and a composite GitHub Action — all in three weeks.

**Architecture:** Strictly layered Python package (`core → data → rules → cli/reporting`) with `core/` having zero internal-module dependencies. Plugin-style rule registry with stable IDs. Validity-first scoring: failed schema gates produce `status: "invalid"` and no quality score. Bundled pinned reference data with cache-refreshable overrides (`update-data` writes only to `data_dir`).

**Tech Stack:** Python 3.10+, hatchling build backend, Typer (CLI), rich (text output), ruamel.yaml (YAML with line/col), pyparsing (Sigma condition grammar), jsonschema, requests, pytest + hypothesis + pytest-cov, ruff, mypy --strict, import-linter, pre-commit.

**Spec:** `docs/superpowers/specs/2026-05-23-sigmalint-design.md` (commit `7ebbb58`).

---

## Phase 1: Repo scaffold and tooling [depends: none] [est: ~180 lines]

**Files:**
- Create: `pyproject.toml`
- Create: `LICENSE` (MIT, copyright "2026 Nishant Tyagi")
- Create: `README.md` (placeholder; final polish in Phase 22)
- Create: `.editorconfig`
- Create: `.pre-commit-config.yaml`
- Create: `src/sigmalint/__init__.py` (`__version__ = "0.1.0"`)
- Create: `src/sigmalint/py.typed` (empty)
- Create: `tests/__init__.py` (empty)
- Create: `tests/conftest.py` (skeleton)
- Create: `.github/workflows/ci.yml`
- Create: `pytest.ini` (or `[tool.pytest.ini_options]` in pyproject)
- Create: `.importlinter.cfg`

**Step 1: Write `pyproject.toml`.**

```toml
[build-system]
requires = ["hatchling>=1.24"]
build-backend = "hatchling.build"

[project]
name = "sigmalint"
version = "0.1.0"
description = "ESLint-style linter for Sigma detection rules"
readme = "README.md"
license = "MIT"
authors = [{name = "Nishant Tyagi"}]
requires-python = ">=3.10"
classifiers = [
  "Development Status :: 3 - Alpha",
  "Intended Audience :: Information Technology",
  "License :: OSI Approved :: MIT License",
  "Programming Language :: Python :: 3.10",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Topic :: Security",
]
dependencies = [
  "pyyaml>=6.0",
  "ruamel.yaml>=0.18",
  "jsonschema>=4.21",
  "typer>=0.12",
  "rich>=13.7",
  "requests>=2.31",
  "pyparsing>=3.1",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0",
  "pytest-cov>=5.0",
  "hypothesis>=6.100",
  "ruff>=0.5",
  "mypy>=1.10",
  "import-linter>=2.0",
  "pre-commit>=3.7",
]

[project.scripts]
sigmalint = "sigmalint.cli.main:app"

[project.urls]
Homepage = "https://github.com/<user>/sigmalint"
Issues = "https://github.com/<user>/sigmalint/issues"

[tool.hatch.build.targets.wheel]
packages = ["src/sigmalint"]

[tool.hatch.build.targets.wheel.force-include]
"src/sigmalint/data/vendored" = "sigmalint/data/vendored"

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E","F","W","I","B","UP","SIM","RUF","D"]
ignore = ["D203","D213"]
# Note: type annotations are enforced by mypy --strict on src/sigmalint;
# ruff's ANN rules are intentionally disabled to avoid annotating fixtures
# and tests where they add noise without value.

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["D"]

[tool.mypy]
python_version = "3.10"
strict = true
files = ["src/sigmalint"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --strict-markers --strict-config"

[tool.coverage.run]
source = ["src/sigmalint"]
branch = true

[tool.coverage.report]
fail_under = 90
show_missing = true
```

**Step 2: Write `LICENSE`** — MIT text with `Copyright (c) 2026 Nishant Tyagi`.

**Step 3: Write `.editorconfig`.**

```ini
root = true
[*]
charset = utf-8
end_of_line = lf
indent_style = space
indent_size = 4
insert_final_newline = true
trim_trailing_whitespace = true
[*.{yml,yaml,toml}]
indent_size = 2
[*.md]
trim_trailing_whitespace = false
```

**Step 4: Write `.pre-commit-config.yaml`.**

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-yaml
      - id: check-merge-conflict
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: [types-PyYAML, types-requests]
        args: [--strict, src/sigmalint]
```

**Step 5: Write `src/sigmalint/__init__.py`.**

```python
"""sigmalint — ESLint-style linter for Sigma detection rules."""

__version__ = "0.1.0"
```

**Step 6: Write `tests/conftest.py` skeleton.**

```python
"""Shared pytest fixtures for sigmalint tests."""
from __future__ import annotations
from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"
```

**Step 7: Write `.importlinter.cfg`.**

```ini
[importlinter]
root_packages =
    sigmalint

# Base layering: each layer below may import any layer above its own,
# but not the other way around.
[importlinter:contract:layers]
name = sigmalint layered architecture
type = layers
layers =
    sigmalint.cli
    sigmalint.reporting
    sigmalint.rules
    sigmalint.data
    sigmalint.core
containers =
    sigmalint

# Reporting works on the canonical JSON shape only — it must not depend on
# rules/, data/, or anything domain-specific.
[importlinter:contract:reporting-core-only]
name = reporting imports core only
type = forbidden
source_modules =
    sigmalint.reporting
forbidden_modules =
    sigmalint.rules
    sigmalint.data

# Only the cli composes rules into the runner. No other layer may pull rules
# in, which would defeat the lazy-registration model.
[importlinter:contract:rules-only-from-cli]
name = rules importable only from cli
type = forbidden
source_modules =
    sigmalint.core
    sigmalint.data
    sigmalint.reporting
forbidden_modules =
    sigmalint.rules
```

**Step 8: Write `.github/workflows/ci.yml`.**

```yaml
name: CI
on:
  push: {branches: [main]}
  pull_request:
permissions: {contents: read}
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10","3.11","3.12","3.13"]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "${{ matrix.python-version }}"}
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .
      - run: mypy --strict src/sigmalint
      - run: lint-imports
      - run: pytest --cov=sigmalint --cov-report=xml
      - if: matrix.python-version == '3.12'
        uses: codecov/codecov-action@v4
        with: {file: ./coverage.xml}
```

**Step 9: Verify scaffold builds.**

```bash
pip install -e ".[dev]"
python -c "import sigmalint; print(sigmalint.__version__)"
ruff check .
pytest -q
```

Expected: install OK, version prints `0.1.0`, ruff clean, pytest reports `no tests ran`.

**Step 10: Commit.**

```bash
git add pyproject.toml LICENSE README.md .editorconfig .pre-commit-config.yaml \
        src/sigmalint/__init__.py src/sigmalint/py.typed \
        tests/__init__.py tests/conftest.py \
        .github/workflows/ci.yml .importlinter.cfg
git commit -m "chore: scaffold project structure, tooling, CI matrix

Phase 1/22 of sigmalint v0.1"
```

---

## Phase 2: core.errors and Finding/Severity types [depends: 1] [est: ~80 lines]

**Files:**
- Create: `src/sigmalint/core/__init__.py` (empty)
- Create: `src/sigmalint/core/errors.py`
- Create: `src/sigmalint/core/types.py`
- Create: `tests/unit/core/__init__.py`
- Create: `tests/unit/core/test_types.py`

**Step 1: Write `src/sigmalint/core/errors.py`.**

```python
"""Custom exception hierarchy for sigmalint."""
from __future__ import annotations


class SigmalintError(Exception):
    """Base class for all sigmalint-raised errors."""


class ConfigError(SigmalintError):
    """Invalid configuration: bad profile, unknown rule id, malformed YAML."""


class DataLoadError(SigmalintError):
    """Reference data (STIX, schema, taxonomy) could not be loaded."""


class RuleCheckError(SigmalintError):
    """A Rule.check() implementation raised an exception."""
```

**Step 2: Write `src/sigmalint/core/types.py`.**

```python
"""Shared frozen data types: Severity, Dimension, Finding, ParsedRule, LintResult."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Dimension(str, Enum):
    SCHEMA = "schema"
    ATTACK = "attack"
    TAXONOMY = "taxonomy"
    FP_RISK = "fp_risk"
    METADATA = "metadata"
    REDUNDANCY = "redundancy"
    STYLE = "style"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    dimension: Dimension
    severity: Severity
    message: str
    file: str
    line: int | None = None
    col: int | None = None
    fix_hint: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedRule:
    path: str
    raw_text: str
    data: dict[str, Any]
    # Map from "/" -separated key path (e.g. "detection/selection/Image") to
    # 1-based (line, col). Populated by the runner from ruamel.yaml's
    # CommentedMap before the doc is flattened to a plain dict.
    positions: dict[str, tuple[int, int]] = field(default_factory=dict)
    yaml_error: str | None = None

    def position_for(self, *path: str, default: tuple[int, int] = (1, 1)) -> tuple[int, int]:
        return self.positions.get("/".join(path), default)


@dataclass(frozen=True, slots=True)
class LintResult:
    parsed: ParsedRule
    findings: tuple[Finding, ...]
    suppressions: tuple[str, ...] = field(default_factory=tuple)
```

**Step 3: Write `tests/unit/core/test_types.py`.**

```python
from sigmalint.core.types import Dimension, Finding, Severity


def test_finding_is_frozen():
    f = Finding(rule_id="X1", dimension=Dimension.SCHEMA,
                severity=Severity.ERROR, message="m", file="f.yml")
    import pytest
    with pytest.raises(AttributeError):
        f.message = "new"


def test_severity_str_value():
    assert Severity.ERROR.value == "error"
    assert Dimension.FP_RISK.value == "fp_risk"
```

**Step 4: Run tests.**

```bash
pytest tests/unit/core/test_types.py -v
```

Expected: 2 passed.

**Step 5: Commit.**

```bash
git add src/sigmalint/core/ tests/unit/core/
git commit -m "feat(core): add errors and frozen Finding/ParsedRule/LintResult types

Phase 2/22 of sigmalint v0.1"
```

---

## Phase 3: core.rule (Rule base) and core.registry [depends: 2] [est: ~140 lines]

**Files:**
- Create: `src/sigmalint/core/rule.py`
- Create: `src/sigmalint/core/registry.py`
- Create: `tests/unit/core/test_registry.py`

**Step 1: Write `src/sigmalint/core/rule.py`.**

```python
"""Rule base class: the unit a registry registers and the runner executes."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterable, Protocol

from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


class CheckContext(Protocol):
    """Injected per-run context; concrete shape lives in core.runner."""

    attack: object
    sigma_schema: object
    taxonomy: object
    corpus: object | None
    config: object
    filters: list[object]


class Rule(ABC):
    """Abstract base for all sigmalint rules.

    Subclasses must declare id, dimension, default_severity, default_weight,
    and implement check().
    """

    id: str
    dimension: Dimension
    default_severity: Severity
    default_weight: float = 1.0
    summary: str = ""

    @abstractmethod
    def check(self, parsed: ParsedRule, ctx: CheckContext) -> Iterable[Finding]:
        """Yield zero or more Findings for the given parsed rule."""
```

**Step 2: Write `src/sigmalint/core/registry.py`.**

```python
"""Module-level rule registry with a @register decorator."""
from __future__ import annotations
from typing import Iterable, Type

from sigmalint.core.errors import ConfigError
from sigmalint.core.rule import Rule


_REGISTRY: dict[str, Type[Rule]] = {}


def register(cls: Type[Rule]) -> Type[Rule]:
    """Class decorator: add a Rule subclass to the registry by its `id` attribute."""
    if not getattr(cls, "id", None):
        raise ConfigError(f"Rule {cls.__name__} has no 'id'")
    if cls.id in _REGISTRY:
        raise ConfigError(f"Duplicate rule id {cls.id} from {cls.__name__}")
    _REGISTRY[cls.id] = cls
    return cls


def all_rules() -> list[Rule]:
    """Return one instance of every registered rule, sorted by id."""
    return [cls() for _, cls in sorted(_REGISTRY.items())]


def enabled_rules(disabled: Iterable[str], enable_only: Iterable[str] | None) -> list[Rule]:
    """Return rule instances after applying disable/enable_only filters."""
    disabled_set = set(disabled)
    if enable_only is not None:
        enable_set = set(enable_only)
        unknown = enable_set - _REGISTRY.keys()
        if unknown:
            raise ConfigError(f"Unknown rule id(s) in enable_only: {sorted(unknown)}")
        return [cls() for rid, cls in sorted(_REGISTRY.items())
                if rid in enable_set and rid not in disabled_set]
    unknown = disabled_set - _REGISTRY.keys()
    if unknown:
        raise ConfigError(f"Unknown rule id(s) in disable: {sorted(unknown)}")
    return [cls() for rid, cls in sorted(_REGISTRY.items()) if rid not in disabled_set]


def reset_registry_for_tests() -> None:
    """Test helper. Clears the registry."""
    _REGISTRY.clear()
```

**Step 3: Write `tests/unit/core/test_registry.py`.**

```python
from typing import Iterable

import pytest

from sigmalint.core.errors import ConfigError
from sigmalint.core.registry import all_rules, enabled_rules, register, reset_registry_for_tests
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


def _make_rule(rid: str):
    @register
    class _R(Rule):
        id = rid
        dimension = Dimension.SCHEMA
        default_severity = Severity.WARNING
        summary = "t"

        def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:  # noqa: ARG002
            return ()
    return _R


@pytest.fixture(autouse=True)
def _reset():
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()


def test_register_adds_rule():
    _make_rule("X001")
    assert {r.id for r in all_rules()} == {"X001"}


def test_register_rejects_duplicate_id():
    _make_rule("X001")
    with pytest.raises(ConfigError):
        _make_rule("X001")


def test_register_rejects_missing_id():
    with pytest.raises(ConfigError):
        @register
        class _Bad(Rule):  # noqa
            dimension = Dimension.SCHEMA
            default_severity = Severity.INFO
            def check(self, p, c): return ()


def test_enabled_rules_disable_filter():
    _make_rule("X001"); _make_rule("X002")
    rules = enabled_rules(disabled=["X001"], enable_only=None)
    assert [r.id for r in rules] == ["X002"]


def test_enabled_rules_enable_only_filter():
    _make_rule("X001"); _make_rule("X002")
    rules = enabled_rules(disabled=[], enable_only=["X001"])
    assert [r.id for r in rules] == ["X001"]


def test_unknown_rule_id_in_disable_raises():
    _make_rule("X001")
    with pytest.raises(ConfigError):
        enabled_rules(disabled=["NOPE"], enable_only=None)
```

**Step 4: Run tests.**

```bash
pytest tests/unit/core/test_registry.py -v
```

Expected: 6 passed.

**Step 5: Commit.**

```bash
git add src/sigmalint/core/rule.py src/sigmalint/core/registry.py tests/unit/core/test_registry.py
git commit -m "feat(core): add Rule base and module-level registry

Phase 3/22 of sigmalint v0.1"
```

---

## Phase 4: core.profiles [depends: 3] [est: ~110 lines]

**Files:**
- Create: `src/sigmalint/core/profiles.py`
- Create: `tests/unit/core/test_profiles.py`

**Step 1: Write `src/sigmalint/core/profiles.py`.**

The profile structure is a `dict[str, Severity | None]`. `None` means the rule is disabled under that profile. Missing keys mean "use the rule's `default_severity`."

```python
"""Built-in profiles: strict, sigmahq, local.

A profile maps rule IDs to severity, or to None (disabled). Missing IDs
fall through to the rule's default_severity.
"""
from __future__ import annotations

from sigmalint.core.errors import ConfigError
from sigmalint.core.types import Severity

E, W, I, OFF = Severity.ERROR, Severity.WARNING, Severity.INFO, None

PROFILES: dict[str, dict[str, Severity | None]] = {
    "strict": {
        # Schema is always strict.
        # Quality: everything that matters is at least a warning.
        "META001a": E,
        "META002": W,
        "META003": W,
        "META005": W,
        "TAX001": W,
        "TAX003": W,
        "FP002": W,
    },
    "sigmahq": {  # default
        "META001a": W,
        "META002": W,
        "META003": W,
        "META005": W,
        "TAX001": W,
        "TAX003": I,
        "FP002": I,
    },
    "local": {
        "META001a": I,
        "META002": I,
        "META003": OFF,
        "META005": W,
        "TAX001": W,
        "TAX003": OFF,
        "RED001": OFF,
        "RED002": OFF,
        "FP002": I,
    },
}

DEFAULT_PROFILE = "sigmahq"


def resolve_severity(profile_name: str, rule_id: str,
                     default: Severity) -> Severity | None:
    """Return the effective severity for `rule_id` under `profile_name`."""
    if profile_name not in PROFILES:
        raise ConfigError(f"Unknown profile: {profile_name!r}. "
                          f"Known: {sorted(PROFILES)}")
    return PROFILES[profile_name].get(rule_id, default)
```

**Step 2: Write `tests/unit/core/test_profiles.py`.**

```python
import pytest
from sigmalint.core.errors import ConfigError
from sigmalint.core.profiles import resolve_severity
from sigmalint.core.types import Severity


def test_unknown_profile_raises():
    with pytest.raises(ConfigError):
        resolve_severity("nope", "ATK001", Severity.WARNING)


def test_default_falls_through():
    # ATK001 is not in any profile -> falls back to default.
    assert resolve_severity("sigmahq", "ATK001", Severity.ERROR) == Severity.ERROR


def test_local_disables_red001():
    assert resolve_severity("local", "RED001", Severity.INFO) is None


def test_strict_promotes_meta001a_to_error():
    assert resolve_severity("strict", "META001a", Severity.WARNING) == Severity.ERROR
```

**Step 3: Run tests.**

```bash
pytest tests/unit/core/test_profiles.py -v
```

Expected: 4 passed.

**Step 4: Commit.**

```bash
git add src/sigmalint/core/profiles.py tests/unit/core/test_profiles.py
git commit -m "feat(core): add built-in profiles (strict|sigmahq|local)

Phase 4/22 of sigmalint v0.1"
```

---

## Phase 5: core.config [depends: 4] [est: ~150 lines]

**Files:**
- Create: `src/sigmalint/core/config.py`
- Create: `tests/unit/core/test_config.py`
- Create: `.sigmalintrc.example.yml`

**Step 1: Write `src/sigmalint/core/config.py`.**

```python
"""Load .sigmalintrc.yml. All keys optional; defaults documented inline."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sigmalint.core.errors import ConfigError
from sigmalint.core.profiles import DEFAULT_PROFILE, PROFILES
from sigmalint.core.types import Severity


_DEFAULT_DIMENSION_WEIGHTS = {
    "attack": 0.22, "taxonomy": 0.20, "fp_risk": 0.20,
    "metadata": 0.18, "redundancy": 0.10, "style": 0.10,
}


@dataclass(frozen=True, slots=True)
class Config:
    profile: str = DEFAULT_PROFILE
    disable: tuple[str, ...] = ()
    enable_only: tuple[str, ...] | None = None
    severities: dict[str, Severity] = field(default_factory=dict)
    dimension_weights: dict[str, float] = field(default_factory=lambda: dict(_DEFAULT_DIMENSION_WEIGHTS))
    rule_weights: dict[str, float] = field(default_factory=dict)
    taxonomy: str = "sigma"
    filters_paths: tuple[str, ...] = ("filters/**/*.yml",)
    data_dir: str = "~/.cache/sigmalint"
    fail_on: str = "error"
    min_score: float | None = None


def load_config(path: Path | None) -> Config:
    """Load `.sigmalintrc.yml` from path (or return defaults if path is None or missing)."""
    if path is None or not path.exists():
        return Config()
    try:
        raw: Any = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Malformed config {path}: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(raw).__name__}")
    return _from_dict(raw)


def _from_dict(d: dict[str, Any]) -> Config:
    profile = d.get("profile", DEFAULT_PROFILE)
    if profile not in PROFILES:
        raise ConfigError(f"Unknown profile {profile!r}. Known: {sorted(PROFILES)}")
    fail_on = d.get("fail_on", "error")
    if fail_on not in {"error", "warning", "never"}:
        raise ConfigError(f"fail_on must be error|warning|never, got {fail_on!r}")
    severities = {k: Severity(v) for k, v in (d.get("severities") or {}).items()}
    weights = d.get("weights") or {}
    dim_weights = dict(_DEFAULT_DIMENSION_WEIGHTS)
    dim_weights.update(weights.get("dimensions") or {})
    rule_weights = dict(weights.get("rules") or {})
    return Config(
        profile=profile,
        disable=tuple(d.get("disable") or ()),
        enable_only=tuple(d["enable_only"]) if d.get("enable_only") else None,
        severities=severities,
        dimension_weights=dim_weights,
        rule_weights=rule_weights,
        taxonomy=d.get("taxonomy", "sigma"),
        filters_paths=tuple(d.get("filters_paths") or ("filters/**/*.yml",)),
        data_dir=d.get("data_dir", "~/.cache/sigmalint"),
        fail_on=fail_on,
        min_score=d.get("min_score"),
    )
```

**Step 2: Write `tests/unit/core/test_config.py`.**

```python
from pathlib import Path
import pytest

from sigmalint.core.config import Config, load_config
from sigmalint.core.errors import ConfigError
from sigmalint.core.types import Severity


def test_defaults(tmp_path: Path):
    c = load_config(tmp_path / "missing.yml")
    assert c.profile == "sigmahq"
    assert c.taxonomy == "sigma"
    assert c.filters_paths == ("filters/**/*.yml",)
    assert c.dimension_weights["attack"] == 0.22


def test_unknown_profile_raises(tmp_path: Path):
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("profile: nope\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_severity_override(tmp_path: Path):
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("severities:\n  TAX003: warning\n")
    c = load_config(p)
    assert c.severities["TAX003"] == Severity.WARNING


def test_bad_fail_on(tmp_path: Path):
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("fail_on: maybe\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_filters_paths_round_trip(tmp_path: Path):
    p = tmp_path / ".sigmalintrc.yml"
    p.write_text("filters_paths: ['x/*.yml','y/*.yml']\n")
    c = load_config(p)
    assert c.filters_paths == ("x/*.yml", "y/*.yml")
```

**Step 3: Write `.sigmalintrc.example.yml` mirroring spec §10.**

(Copy verbatim from spec §10's YAML block.)

**Step 4: Run tests.**

```bash
pytest tests/unit/core/test_config.py -v
```

Expected: 5 passed.

**Step 5: Commit.**

```bash
git add src/sigmalint/core/config.py tests/unit/core/test_config.py .sigmalintrc.example.yml
git commit -m "feat(core): add .sigmalintrc.yml loader with profile/weights/severities

Phase 5/22 of sigmalint v0.1"
```

---

## Phase 6: core.condition (Sigma condition parser) [depends: 2] [est: ~280 lines]

**Files:**
- Create: `src/sigmalint/core/condition.py`
- Create: `tests/unit/core/test_condition.py`

**Step 1: Write `src/sigmalint/core/condition.py`.** Use pyparsing to build a grammar matching Sigma 2.1.0 condition syntax. Return an AST as dataclasses.

```python
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
from dataclasses import dataclass
from typing import Iterable

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
    n: str            # "1" or "all"
    pattern: str      # selector name with optional trailing "*", or "them"

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
    ident = pp.Regex(r"[A-Za-z_*?][A-Za-z0-9_*?]*")
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


def _to_ast(node) -> object:
    if isinstance(node, str):
        return Ident(node)
    items = list(node)
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


def _is_wildcard(pat: str) -> bool:
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
        if _is_wildcard(ref):
            rx = _wildcard_to_regex(ref)
            out |= {s for s in available_set if rx.match(s)}
        elif ref in available_set:
            out.add(ref)
    return out


def has_negated_selector(ast: object, predicate, *, _negated: bool = False) -> bool:
    """True if any selector matching predicate(name) appears under a `not` in the AST.

    Negation is propagated through recursion so grouped forms like
    `not (filter1 or filter2)` correctly report the inner selectors as negated.
    Sigma's condition grammar does not include explicit double negation; if the
    `not` keyword nests, each Not toggles the carried flag.
    """
    if isinstance(ast, Not):
        return has_negated_selector(ast.expr, predicate, _negated=not _negated)
    if isinstance(ast, (And, Or)):
        return any(has_negated_selector(item, predicate, _negated=_negated)
                   for item in ast.items)
    if isinstance(ast, Ident):
        return _negated and predicate(ast.name)
    if isinstance(ast, Quantifier):
        return _negated and predicate(ast.pattern)
    return False
```

**Step 2: Write `tests/unit/core/test_condition.py`.**

```python
import pytest
from hypothesis import given, strategies as st
from sigmalint.core.condition import (
    ConditionParseError, And, Ident, Not, Or, Quantifier,
    expand_patterns, has_negated_selector, parse, referenced_selectors,
)


@pytest.mark.parametrize("c,expected_type", [
    ("selection", Ident),
    ("selection and filter", And),
    ("selection or other", Or),
    ("selection and not filter", And),
    ("1 of selection*", Quantifier),
    ("all of them", Quantifier),
    ("(a or b) and not c", And),
])
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
    assert expand_patterns({"filter*"}, {"filter_a", "filter_b", "selection"}) == {"filter_a", "filter_b"}


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


@given(st.from_regex(r"^[a-z][a-z0-9_]{0,8}$", fullmatch=True))
def test_single_ident_round_trip(name):
    ast = parse(name)
    assert ast == Ident(name)
```

**Step 3: Run tests.**

```bash
pytest tests/unit/core/test_condition.py -v
```

Expected: all parametrize cases + property test pass.

**Step 4: Commit.**

```bash
git add src/sigmalint/core/condition.py tests/unit/core/test_condition.py
git commit -m "feat(core): add Sigma condition parser (pyparsing) with AST + helpers

Phase 6/22 of sigmalint v0.1"
```

---

## Phase 7: core.runner [depends: 3, 6] [est: ~180 lines]

**Files:**
- Create: `src/sigmalint/core/runner.py`
- Create: `tests/unit/core/test_runner.py`

**Step 1: Write `src/sigmalint/core/runner.py`.**

```python
"""Rule-agnostic runner: parses files, dispatches rules, collects findings."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, LintResult, ParsedRule, Severity


_yaml = YAML(typ="rt")  # round-trip preserves line/col


def _extract_positions(node, prefix: str = "") -> dict[str, tuple[int, int]]:
    """Walk a ruamel.yaml CommentedMap, returning {key_path: (line, col)}.

    Lines/columns from ruamel.yaml are 0-based; we convert to 1-based.
    """
    out: dict[str, tuple[int, int]] = {}
    if not hasattr(node, "items"):
        return out
    lc = getattr(node, "lc", None)
    for key, value in node.items():
        path = f"{prefix}/{key}" if prefix else str(key)
        if lc is not None:
            try:
                line, col = lc.key(key)
                out[path] = (line + 1, col + 1)
            except (KeyError, TypeError):
                pass
        if hasattr(value, "items"):
            out.update(_extract_positions(value, path))
    return out


@dataclass(slots=True)
class RunContext:
    attack: object | None = None
    sigma_schema: object | None = None
    taxonomy: object | None = None
    corpus: object | None = None
    config: object | None = None
    filters: list[object] | None = None


_SUPPRESS = re.compile(r"#\s*sigmalint:\s*disable\s*=\s*([A-Z0-9_,\s]+)")


def _parse_file(path: Path) -> ParsedRule:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        node = _yaml.load(text) or {}
        if not hasattr(node, "items"):
            return ParsedRule(path=str(path), raw_text=text, data={},
                              yaml_error="root must be a mapping")
        positions = _extract_positions(node)
        # Flatten ruamel.yaml's CommentedMap into a plain dict for rule code.
        def _plain(x):  # local helper
            if hasattr(x, "items"):
                return {k: _plain(v) for k, v in x.items()}
            if isinstance(x, list):
                return [_plain(i) for i in x]
            return x
        return ParsedRule(path=str(path), raw_text=text,
                          data=_plain(node), positions=positions)
    except YAMLError as e:
        return ParsedRule(path=str(path), raw_text=text, data={}, yaml_error=str(e))


def _collect_suppressions(text: str) -> set[str]:
    out: set[str] = set()
    for m in _SUPPRESS.finditer(text):
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if tok:
                out.add(tok)
    return out


def _safe_check(rule: Rule, parsed: ParsedRule, ctx: RunContext) -> Iterable[Finding]:
    try:
        yield from rule.check(parsed, ctx)  # type: ignore[arg-type]
    except Exception as e:
        yield Finding(
            rule_id="INTERNAL001", dimension=Dimension.SCHEMA, severity=Severity.ERROR,
            message=f"rule {rule.id} raised {type(e).__name__}: {e}",
            file=parsed.path,
        )


def lint(paths: Sequence[Path], rules: Sequence[Rule], ctx: RunContext) -> list[LintResult]:
    """Lint files. `rules` should already be filtered by enable/disable."""
    results: list[LintResult] = []
    for p in paths:
        parsed = _parse_file(p)
        suppressed = _collect_suppressions(parsed.raw_text)
        if parsed.yaml_error:
            results.append(LintResult(
                parsed=parsed,
                findings=(Finding(
                    rule_id="SCHEMA001", dimension=Dimension.SCHEMA,
                    severity=Severity.ERROR, message=f"YAML parse error: {parsed.yaml_error}",
                    file=parsed.path, line=1, col=1,
                    fix_hint="Fix the YAML syntax."
                ),),
                suppressions=tuple(sorted(suppressed)),
            ))
            continue
        findings: list[Finding] = []
        for rule in rules:
            if rule.id in suppressed:
                continue
            findings.extend(_safe_check(rule, parsed, ctx))
        results.append(LintResult(
            parsed=parsed, findings=tuple(findings),
            suppressions=tuple(sorted(suppressed)),
        ))
    return results
```

**Step 2: Write `tests/unit/core/test_runner.py`.**

```python
from pathlib import Path
from typing import Iterable

import pytest

from sigmalint.core.registry import reset_registry_for_tests
from sigmalint.core.rule import Rule
from sigmalint.core.runner import RunContext, lint
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


class AlwaysWarn(Rule):
    id = "TST001"; dimension = Dimension.SCHEMA; default_severity = Severity.WARNING
    summary = "always emits a warning"
    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:  # noqa
        yield Finding(self.id, self.dimension, self.default_severity, "boom", parsed.path)


class Crashy(Rule):
    id = "TST002"; dimension = Dimension.SCHEMA; default_severity = Severity.WARNING
    summary = "raises"
    def check(self, parsed, ctx):
        raise RuntimeError("nope")


@pytest.fixture(autouse=True)
def _reset():
    reset_registry_for_tests()


def _write(p: Path, body: str) -> Path:
    p.write_text(body, encoding="utf-8")
    return p


def test_runs_simple_rule(tmp_path: Path):
    f = _write(tmp_path / "r.yml", "title: t\nlogsource: {category: foo}\ndetection: {selection: {a: 1}, condition: selection}\n")
    results = lint([f], [AlwaysWarn()], RunContext())
    assert len(results) == 1 and len(results[0].findings) == 1
    assert results[0].findings[0].rule_id == "TST001"


def test_yaml_error_becomes_schema001(tmp_path: Path):
    f = _write(tmp_path / "bad.yml", "title: : :\n")
    results = lint([f], [AlwaysWarn()], RunContext())
    assert results[0].findings[0].rule_id == "SCHEMA001"


def test_rule_exception_becomes_internal001(tmp_path: Path):
    f = _write(tmp_path / "r.yml", "title: t\ndetection: {a: {b: 1}, condition: a}\nlogsource: {category: foo}\n")
    results = lint([f], [Crashy()], RunContext())
    rids = [f.rule_id for f in results[0].findings]
    assert "INTERNAL001" in rids


def test_inline_suppression(tmp_path: Path):
    f = _write(tmp_path / "r.yml",
               "title: t  # sigmalint: disable=TST001\n"
               "detection: {a: {b: 1}, condition: a}\nlogsource: {category: foo}\n")
    results = lint([f], [AlwaysWarn()], RunContext())
    assert results[0].findings == ()
    assert "TST001" in results[0].suppressions
```

**Step 3: Run tests.**

```bash
pytest tests/unit/core/test_runner.py -v
```

Expected: 4 passed.

**Step 4: Commit.**

```bash
git add src/sigmalint/core/runner.py tests/unit/core/test_runner.py
git commit -m "feat(core): add rule-agnostic runner with YAML/INTERNAL001 handling and inline suppressions

Phase 7/22 of sigmalint v0.1"
```

---

## Phase 8: core.scoring [depends: 5, 7] [est: ~140 lines]

**Files:**
- Create: `src/sigmalint/core/scoring.py`
- Create: `tests/unit/core/test_scoring.py`

**Step 1: Write `src/sigmalint/core/scoring.py`.**

```python
"""Two-layer scoring: validity gate + weighted quality dimensions."""
from __future__ import annotations
from dataclasses import dataclass

from sigmalint.core.config import Config
from sigmalint.core.types import Dimension, LintResult, Severity


_BASE_SEVERITY_WEIGHT = {Severity.ERROR: 10.0, Severity.WARNING: 3.0, Severity.INFO: 1.0}
_QUALITY_DIMENSIONS = (
    Dimension.ATTACK, Dimension.TAXONOMY, Dimension.FP_RISK,
    Dimension.METADATA, Dimension.REDUNDANCY, Dimension.STYLE,
)


@dataclass(frozen=True, slots=True)
class FileScore:
    path: str
    status: str             # "valid" | "invalid"
    dimension_scores: dict[str, float]    # empty if invalid
    total: float | None     # None if invalid


def score_file(result: LintResult, cfg: Config) -> FileScore:
    # Validity gate: any SCHEMA error => invalid.
    schema_errors = [f for f in result.findings
                     if f.dimension == Dimension.SCHEMA and f.severity == Severity.ERROR]
    if schema_errors:
        return FileScore(path=result.parsed.path, status="invalid",
                         dimension_scores={}, total=None)

    # Quality scoring.
    penalties: dict[Dimension, float] = {d: 0.0 for d in _QUALITY_DIMENSIONS}
    for f in result.findings:
        if f.dimension not in _QUALITY_DIMENSIONS:
            continue
        sev = _BASE_SEVERITY_WEIGHT[f.severity]
        mult = cfg.rule_weights.get(f.rule_id, 1.0)
        penalties[f.dimension] += sev * mult

    dim_scores = {d.value: max(0.0, 100.0 - penalties[d]) for d in _QUALITY_DIMENSIONS}

    # Normalize weights over enabled dimensions only.
    weights = {d.value: cfg.dimension_weights.get(d.value, 0.0) for d in _QUALITY_DIMENSIONS}
    total_weight = sum(weights.values())
    if total_weight == 0:
        total = 0.0
    else:
        total = sum(dim_scores[d] * (weights[d] / total_weight) for d in dim_scores)

    return FileScore(path=result.parsed.path, status="valid",
                     dimension_scores=dim_scores, total=round(total, 2))
```

**Step 2: Write `tests/unit/core/test_scoring.py`.**

```python
from sigmalint.core.config import Config
from sigmalint.core.scoring import score_file
from sigmalint.core.types import Dimension, Finding, LintResult, ParsedRule, Severity


def _result(findings):
    return LintResult(parsed=ParsedRule(path="f.yml", raw_text="", data={}),
                      findings=tuple(findings))


def test_invalid_when_schema_error():
    fs = score_file(_result([Finding("SCHEMA001", Dimension.SCHEMA, Severity.ERROR, "m", "f.yml")]),
                    Config())
    assert fs.status == "invalid" and fs.total is None


def test_valid_when_no_schema_error():
    fs = score_file(_result([]), Config())
    assert fs.status == "valid" and fs.total == 100.0


def test_warning_penalty():
    fs = score_file(_result([Finding("ATK002", Dimension.ATTACK, Severity.WARNING, "m", "f.yml")]),
                    Config())
    assert fs.dimension_scores["attack"] == 97.0


def test_rule_weight_multiplier_applied():
    cfg = Config(rule_weights={"FP003": 2.0})
    fs = score_file(_result([Finding("FP003", Dimension.FP_RISK, Severity.WARNING, "m", "f.yml")]),
                    cfg)
    assert fs.dimension_scores["fp_risk"] == 94.0  # 100 - 3*2
```

**Step 3: Run tests.**

```bash
pytest tests/unit/core/test_scoring.py -v
```

Expected: 4 passed.

**Step 4: Commit.**

```bash
git add src/sigmalint/core/scoring.py tests/unit/core/test_scoring.py
git commit -m "feat(core): add validity-gated quality scoring with renormalized dimension weights

Phase 8/22 of sigmalint v0.1"
```

---

## Phase 9: data.sigma_schema + vendored schema [depends: 2] [est: ~120 lines]

**Files:**
- Create: `src/sigmalint/data/__init__.py` (empty)
- Create: `src/sigmalint/data/sigma_schema.py`
- Create: `src/sigmalint/data/vendored/sigma-schema.json` (fetched once from sigmahq/sigma-specification)
- Create: `tests/unit/data/__init__.py` (empty)
- Create: `tests/unit/data/test_sigma_schema.py`

**Step 1: Fetch the Sigma JSON schema.**

```bash
curl -fsSLo src/sigmalint/data/vendored/sigma-schema.json \
  https://raw.githubusercontent.com/SigmaHQ/sigma-specification/v2.1.0/json-schema/sigma-detection-rule-schema.json
```

If the path 404s, locate the current schema URL from the sigma-specification repo and document it in `src/sigmalint/data/vendored/README.md`.

**Step 2: Write `src/sigmalint/data/sigma_schema.py`.**

```python
"""Loader for the bundled Sigma JSON schema, with user-cache override."""
from __future__ import annotations
import json
from importlib.resources import files
from pathlib import Path

import jsonschema

from sigmalint.core.errors import DataLoadError

VENDORED_VERSION = "2.1.0"


def _vendored_path() -> Path:
    return Path(str(files("sigmalint.data.vendored") / "sigma-schema.json"))


def _resolve(data_dir: Path) -> Path:
    user = data_dir / "sigma-schema.json"
    return user if user.exists() else _vendored_path()


class SigmaSchema:
    def __init__(self, data_dir: Path):
        path = _resolve(data_dir)
        try:
            self._schema = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise DataLoadError(f"Cannot load Sigma schema from {path}: {e}") from e
        self._path = path

    @property
    def data_version(self) -> str:
        # Prefer schema's $id/version if present, else VENDORED_VERSION.
        return self._schema.get("version") or VENDORED_VERSION

    def validate(self, data: dict) -> list[str]:
        """Return a list of human-readable error messages (empty if valid)."""
        v = jsonschema.Draft7Validator(self._schema)
        return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
                for e in v.iter_errors(data)]
```

**Step 3: Write `tests/unit/data/test_sigma_schema.py`.**

```python
from pathlib import Path
from sigmalint.data.sigma_schema import SigmaSchema


def test_valid_rule_has_no_errors(tmp_path: Path):
    schema = SigmaSchema(tmp_path)
    good = {
        "title": "T", "logsource": {"category": "process_creation"},
        "detection": {"selection": {"Image": "x"}, "condition": "selection"}
    }
    assert schema.validate(good) == []


def test_missing_required_field_returns_error(tmp_path: Path):
    schema = SigmaSchema(tmp_path)
    bad = {"title": "T"}
    errs = schema.validate(bad)
    assert any("logsource" in e or "detection" in e for e in errs)
```

**Step 4: Run.**

```bash
pytest tests/unit/data/test_sigma_schema.py -v
```

Expected: 2 passed.

**Step 5: Commit.**

```bash
git add src/sigmalint/data/__init__.py src/sigmalint/data/sigma_schema.py \
        src/sigmalint/data/vendored/sigma-schema.json \
        tests/unit/data/__init__.py tests/unit/data/test_sigma_schema.py
git commit -m "feat(data): bundle Sigma 2.1.0 JSON schema with cache-override loader

Phase 9/22 of sigmalint v0.1"
```

---

## Phase 10: data.attack + vendored STIX [depends: 2] [est: ~160 lines]

**Files:**
- Create: `src/sigmalint/data/attack.py`
- Create: `src/sigmalint/data/vendored/enterprise-attack.json` (pinned MITRE STIX bundle)
- Create: `tests/unit/data/test_attack.py`

**Step 1: Fetch pinned STIX and record version.**

```bash
TAG="v16.1"   # ATT&CK release tag; update with care, STIX spec_version is NOT this.
curl -fsSLo src/sigmalint/data/vendored/enterprise-attack.json \
  "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-${TAG}/enterprise-attack/enterprise-attack.json"
printf '%s\n' "$TAG" > src/sigmalint/data/vendored/attack-version.txt
# Keep VENDORED_ATTACK_VERSION in src/sigmalint/data/attack.py in sync with $TAG.
```

**Step 2: Write `src/sigmalint/data/attack.py`.**

```python
"""Lookup over the MITRE ATT&CK STIX enterprise-attack bundle."""
from __future__ import annotations
import json
import re
from importlib.resources import files
from pathlib import Path

from sigmalint.core.errors import DataLoadError

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
ATTACK_TAG_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")

# Pinned baseline matching the vendored STIX bundle. `update-data` writes a
# sidecar `attack-version.txt` into the user cache; loader prefers that, else
# falls back to this constant. STIX's `spec_version` is the spec rev, not the
# ATT&CK release, so we record the release tag explicitly for reproducibility.
VENDORED_ATTACK_VERSION = "v16.1"


def _vendored_path() -> Path:
    return Path(str(files("sigmalint.data.vendored") / "enterprise-attack.json"))


def _resolve(data_dir: Path) -> Path:
    user = data_dir / "enterprise-attack.json"
    return user if user.exists() else _vendored_path()


class AttackTaxonomy:
    def __init__(self, data_dir: Path):
        path = _resolve(data_dir)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise DataLoadError(f"Cannot load ATT&CK bundle from {path}: {e}") from e
        self._techniques: dict[str, dict] = {}
        for obj in doc.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext = next((r for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if not ext:
                continue
            tid = ext.get("external_id", "")
            if _TECHNIQUE_RE.match(tid):
                self._techniques[tid] = obj
        self._path = path
        # Prefer an explicit sidecar (written by `update-data`); fall back to
        # the vendored constant. STIX spec_version isn't the ATT&CK release.
        sidecar = path.parent / "attack-version.txt"
        if sidecar.exists():
            self._version = sidecar.read_text(encoding="utf-8").strip()
        else:
            self._version = VENDORED_ATTACK_VERSION

    @property
    def data_version(self) -> str:
        return self._version

    def is_valid_technique(self, tid: str) -> bool:
        return tid.upper() in self._techniques

    def is_revoked(self, tid: str) -> bool:
        obj = self._techniques.get(tid.upper())
        return bool(obj and (obj.get("revoked") or obj.get("x_mitre_deprecated")))

    def is_subtechnique(self, tid: str) -> bool:
        return "." in tid


def technique_from_tag(tag: str) -> str | None:
    """Return 'T1059' or 'T1059.001' if `tag` is attack.t####(.###)?, else None."""
    m = ATTACK_TAG_RE.match(tag)
    if not m:
        return None
    base, sub = m.group(1), m.group(2)
    return f"T{base}.{sub}" if sub else f"T{base}"
```

**Step 3: Write `tests/unit/data/test_attack.py`.**

```python
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
```

**Step 4: Run + commit.**

```bash
pytest tests/unit/data/test_attack.py -v
git add src/sigmalint/data/attack.py src/sigmalint/data/vendored/enterprise-attack.json \
        src/sigmalint/data/vendored/attack-version.txt tests/unit/data/test_attack.py
git commit -m "feat(data): bundle ATT&CK Enterprise STIX with technique lookup

Phase 10/22 of sigmalint v0.1"
```

---

## Phase 11: data.taxonomy + sigma-modifiers + fields [depends: 2] [est: ~180 lines]

**Files:**
- Create: `src/sigmalint/data/taxonomy.py`
- Create: `src/sigmalint/data/vendored/sigma-modifiers.yml`
- Create: `src/sigmalint/data/vendored/fields.yml` (per-logsource field index, seeded from SigmaHQ committee guidance)
- Create: `src/sigmalint/data/vendored/attack-logsource-map.yml`
- Create: `tests/unit/data/test_taxonomy.py`

**Step 1: Write `sigma-modifiers.yml`** mirroring Sigma 2.1.0 modifiers appendix:

```yaml
modifiers:
  - contains
  - startswith
  - endswith
  - all
  - cased
  - cidr
  - base64
  - base64offset
  - re
  - windash
  - expand
  - fieldref
  - gt
  - gte
  - lt
  - lte
```

**Step 2: Seed `fields.yml`.** Minimal v0.1 seed for the most common Sigma log sources. Document that future PRs extend it; refresh-from-spec is a v0.2 feature.

```yaml
taxonomies:
  sigma:
    process_creation:
      - Image
      - CommandLine
      - ParentImage
      - ParentCommandLine
      - User
      - IntegrityLevel
      - Hashes
      - OriginalFileName
      - Product
      - Company
      - Description
      - LogonId
      - CurrentDirectory
    network_connection:
      - Image
      - Initiated
      - SourceIp
      - DestinationIp
      - DestinationPort
      - DestinationHostname
      - Protocol
      - User
    registry_event:
      - EventType
      - TargetObject
      - Details
      - Image
      - User
    file_event:
      - TargetFilename
      - Image
      - User
      - Hashes
    dns_query:
      - QueryName
      - QueryStatus
      - Image
      - User
    web:
      - cs-method
      - cs-uri-stem
      - cs-uri-query
      - c-ip
      - sc-status
      - cs-user-agent
canonical_aliases:
  sigma:
    process_creation:
      ImagePath: Image
      ProcessName: Image
      ProcessCommandLine: CommandLine
```

**Step 3: Seed `attack-logsource-map.yml`.** Minimal mapping of techniques → plausible logsource categories/products. This is the lookup powering ATK003.

```yaml
# Versioned; refreshable via `sigmalint update-data`.
version: "v0.1"
techniques:
  T1059:
    categories: [process_creation]
    products: [windows, linux, macos]
  T1059.001:
    categories: [process_creation]
    products: [windows]
  T1059.003:
    categories: [process_creation]
    products: [windows]
  T1547.001:
    categories: [registry_event]
    products: [windows]
  T1071.001:
    categories: [network_connection, proxy, web]
    products: [windows, linux, macos]
  T1071.004:
    categories: [dns_query]
    products: [windows, linux, macos]
  T1003:
    categories: [process_creation, file_event]
    products: [windows]
# (extended over time; out-of-scope techniques are silently skipped by ATK003)
```

**Step 4: Write `src/sigmalint/data/taxonomy.py`.**

```python
"""Field-name taxonomy + modifier list + ATT&CK→logsource map loaders."""
from __future__ import annotations
from importlib.resources import files
from pathlib import Path

import yaml

from sigmalint.core.errors import DataLoadError


def _resolve(data_dir: Path, name: str) -> Path:
    user = data_dir / name
    if user.exists():
        return user
    return Path(str(files("sigmalint.data.vendored") / name))


def _load_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise DataLoadError(f"Cannot load {p}: {e}") from e


class SigmaTaxonomy:
    def __init__(self, data_dir: Path):
        data = _load_yaml(_resolve(data_dir, "fields.yml"))
        self._fields: dict[str, dict[str, set[str]]] = {
            tax: {ls: set(fs) for ls, fs in (entries or {}).items()}
            for tax, entries in (data.get("taxonomies") or {}).items()
        }
        self._aliases: dict[str, dict[str, dict[str, str]]] = data.get("canonical_aliases") or {}
        self._version = "sigma@v0.1"

    def is_known(self, taxonomy: str, logsource: str, field: str) -> bool:
        # Strip Sigma value-modifiers like Field|contains
        bare = field.split("|", 1)[0]
        fields = self._fields.get(taxonomy, {}).get(logsource, set())
        if not fields:
            return True  # unknown logsource -> don't false-positive
        return bare in fields

    def canonical(self, taxonomy: str, logsource: str, field: str) -> str | None:
        return self._aliases.get(taxonomy, {}).get(logsource, {}).get(field)

    @property
    def data_version(self) -> str:
        return self._version


class SigmaModifiers:
    def __init__(self, data_dir: Path):
        data = _load_yaml(_resolve(data_dir, "sigma-modifiers.yml"))
        self._known = set(data.get("modifiers") or [])

    def is_known(self, modifier: str) -> bool:
        return modifier in self._known


class AttackLogsourceMap:
    def __init__(self, data_dir: Path):
        data = _load_yaml(_resolve(data_dir, "attack-logsource-map.yml"))
        self._t = data.get("techniques") or {}
        self._version = data.get("version", "v0.1")

    @property
    def data_version(self) -> str:
        return self._version

    def plausible(self, technique: str, category: str | None, product: str | None) -> bool:
        entry = self._t.get(technique)
        if not entry:
            return True  # unknown technique -> no signal
        if category and category in (entry.get("categories") or []):
            return True
        if product and product in (entry.get("products") or []):
            return True
        return False
```

**Step 5: Write `tests/unit/data/test_taxonomy.py`.**

```python
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
```

**Step 6: Run + commit.**

```bash
pytest tests/unit/data/test_taxonomy.py -v
git add src/sigmalint/data/taxonomy.py src/sigmalint/data/vendored/*.yml tests/unit/data/test_taxonomy.py
git commit -m "feat(data): add taxonomy, modifiers, and ATT&CK→logsource map loaders

Phase 11/22 of sigmalint v0.1"
```

---

## Phase 12: data.corpus [depends: 2] [est: ~160 lines]

**Files:**
- Create: `src/sigmalint/data/corpus.py`
- Create: `tests/unit/data/test_corpus.py`

**Step 1: Write `src/sigmalint/data/corpus.py`.** Clones SigmaHQ on first use; computes semantically-canonicalized fingerprints.

```python
"""Lazy SigmaHQ corpus index for redundancy checks.

`update-data --corpus` clones git@github.com:SigmaHQ/sigma into `data_dir/corpus`.
On first lookup we walk every .yml under `rules/` and build a fingerprint set.

Fingerprint canonicalization (v0.1, best-effort):
- selector names dropped (replaced by positional letters)
- modifiers normalized (kept attached to field)
- list values sorted
- AND/OR structure preserved by traversal order
- titles and ids indexed separately for RED002
"""
from __future__ import annotations
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from sigmalint.core.errors import DataLoadError


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    path: str
    title: str
    id: str | None
    fingerprint: frozenset[str]


def _canonical_tokens(detection: dict) -> Iterable[str]:
    """Yield tokens that survive selector-renaming."""
    for sel_name, sel in detection.items():
        if sel_name == "condition":
            continue
        if not isinstance(sel, dict):
            continue
        for field, value in sel.items():
            field_norm = field.lower()
            if isinstance(value, list):
                for v in sorted(map(str, value)):
                    yield f"{field_norm}::{v.lower()}"
            else:
                yield f"{field_norm}::{str(value).lower()}"


class RuleCorpus:
    def __init__(self, data_dir: Path):
        self._root = data_dir / "corpus"
        self._entries: list[CorpusEntry] | None = None

    @property
    def available(self) -> bool:
        return (self._root / "rules").exists()

    @property
    def data_version(self) -> str | None:
        if not self.available:
            return None
        try:
            sha = subprocess.check_output(
                ["git", "-C", str(self._root), "rev-parse", "--short", "HEAD"],
                text=True
            ).strip()
            return sha
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def _build_index(self) -> list[CorpusEntry]:
        if not self.available:
            return []
        entries: list[CorpusEntry] = []
        for p in (self._root / "rules").rglob("*.yml"):
            try:
                doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict):
                continue
            detection = doc.get("detection") or {}
            tokens = frozenset(_canonical_tokens(detection))
            if not tokens:
                continue
            entries.append(CorpusEntry(path=str(p), title=str(doc.get("title", "")),
                                       id=doc.get("id"), fingerprint=tokens))
        return entries

    def entries(self) -> list[CorpusEntry]:
        if self._entries is None:
            self._entries = self._build_index()
        return self._entries

    @staticmethod
    def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def near_duplicates(self, fingerprint: frozenset[str],
                        threshold: float = 0.85) -> list[CorpusEntry]:
        return [e for e in self.entries() if self.jaccard(e.fingerprint, fingerprint) >= threshold]


def fingerprint_for_rule(data: dict) -> frozenset[str]:
    return frozenset(_canonical_tokens(data.get("detection") or {}))
```

**Step 2: Write `tests/unit/data/test_corpus.py`.**

```python
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
    assert RuleCorpus.jaccard(frozenset({"a","b"}), frozenset({"a","c"})) == 1/3
```

**Step 3: Run + commit.**

```bash
pytest tests/unit/data/test_corpus.py -v
git add src/sigmalint/data/corpus.py tests/unit/data/test_corpus.py
git commit -m "feat(data): add lazy SigmaHQ corpus index with canonicalized fingerprints

Phase 12/22 of sigmalint v0.1"
```

---

## Phase 13: rules.schema (SCHEMA001–004) [depends: 7, 9] [est: ~200 lines]

**Files:**
- Create: `src/sigmalint/rules/__init__.py` (empty)
- Create: `src/sigmalint/rules/schema.py`
- Create: `tests/fixtures/SCHEMA002/{pass.yml,fail.yml}`
- Create: `tests/fixtures/SCHEMA003/{pass.yml,fail.yml}`
- Create: `tests/fixtures/SCHEMA004/{pass.yml,fail.yml}`
- Create: `tests/integration/__init__.py` (empty)
- Create: `tests/integration/test_rules_schema.py`

(SCHEMA001 is emitted directly by the runner on YAML parse failures, not a separate rule class.)

**Step 1: Write `src/sigmalint/rules/schema.py`.**

```python
"""SCHEMA001-004 — Sigma 2.1.0 validity rules.

SCHEMA001 (YAML parses) is emitted by the runner directly. The rules below
run only on successfully-parsed files.
"""
from __future__ import annotations
from typing import Iterable

from sigmalint.core.condition import ConditionParseError, expand_patterns, parse, referenced_selectors
from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


@register
class Schema002SigmaSchema(Rule):
    id = "SCHEMA002"
    dimension = Dimension.SCHEMA
    default_severity = Severity.ERROR
    summary = "Validates against the bundled Sigma JSON schema."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        errors = ctx.sigma_schema.validate(parsed.data)
        for msg in errors:
            yield Finding(self.id, self.dimension, self.default_severity,
                          f"schema: {msg}", parsed.path,
                          fix_hint="See the Sigma 2.1.0 rule schema.")


@register
class Schema003RequiredKeys(Rule):
    id = "SCHEMA003"
    dimension = Dimension.SCHEMA
    default_severity = Severity.ERROR
    summary = "Required top-level + detection.condition keys present."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        data = parsed.data
        for key in ("title", "logsource", "detection"):
            if key not in data:
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"missing required top-level key: {key}",
                              parsed.path, fix_hint=f"Add a `{key}:` block.")
        det = data.get("detection") or {}
        if isinstance(det, dict) and "condition" not in det:
            yield Finding(self.id, self.dimension, self.default_severity,
                          "missing required key: detection.condition",
                          parsed.path,
                          fix_hint="Add `condition: <selector-expression>` under detection.")


@register
class Schema004ConditionParseable(Rule):
    id = "SCHEMA004"
    dimension = Dimension.SCHEMA
    default_severity = Severity.ERROR
    summary = "detection.condition parses and references only existing selectors."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        det = parsed.data.get("detection")
        if not isinstance(det, dict):
            return
        condition = det.get("condition")
        if condition is None:
            return
        try:
            ast = parse(condition)
        except ConditionParseError as e:
            yield Finding(self.id, self.dimension, self.default_severity,
                          f"detection.condition does not parse: {e}",
                          parsed.path, fix_hint="Check operator/parens/keywords against Sigma 2.1.0.")
            return
        available = {k for k in det.keys() if k != "condition"}
        referenced = referenced_selectors(ast)
        # Wildcards may be `*` or `?` and may appear at any position.
        from sigmalint.core.condition import _is_wildcard  # type: ignore[attr-defined]
        wildcards = {r for r in referenced if _is_wildcard(r)}
        non_wild = referenced - wildcards
        unknown = (non_wild - available) | {
            w for w in wildcards if not expand_patterns({w}, available)
        }
        for u in sorted(unknown):
            yield Finding(self.id, self.dimension, self.default_severity,
                          f"detection.condition references unknown selector: {u}",
                          parsed.path,
                          fix_hint=f"Define `{u}:` under detection or remove the reference.")
```

**Step 2: Create test fixtures (one pass.yml + one fail.yml per rule).** Example for SCHEMA003:

`tests/fixtures/SCHEMA003/pass.yml`:
```yaml
title: T
logsource:
  category: process_creation
detection:
  selection:
    Image: x
  condition: selection
```

`tests/fixtures/SCHEMA003/fail.yml`:
```yaml
logsource:
  category: process_creation
detection:
  selection:
    Image: x
  condition: selection
```

(Repeat for SCHEMA002 — pass uses minimal valid rule; fail omits `detection`. SCHEMA004 — pass uses `selection and not filter`; fail uses `selection and ghost`.)

**Step 3: Write the integration test driver `tests/integration/test_rules_schema.py`.**

```python
from pathlib import Path
import pytest
import yaml

from sigmalint.core.registry import reset_registry_for_tests
from sigmalint.core.runner import RunContext, lint
from sigmalint.data.sigma_schema import SigmaSchema
from sigmalint.rules.schema import (
    Schema002SigmaSchema, Schema003RequiredKeys, Schema004ConditionParseable,
)


RULE_MAP = {
    "SCHEMA002": Schema002SigmaSchema,
    "SCHEMA003": Schema003RequiredKeys,
    "SCHEMA004": Schema004ConditionParseable,
}


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_pass_fixture(rule_id, fixtures_dir, tmp_path):
    reset_registry_for_tests()
    f = fixtures_dir / rule_id / "pass.yml"
    ctx = RunContext(sigma_schema=SigmaSchema(tmp_path))
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert all(x.rule_id != rule_id for x in results[0].findings), \
        f"{rule_id} pass fixture unexpectedly produced findings: {results[0].findings}"


@pytest.mark.parametrize("rule_id", list(RULE_MAP))
def test_fail_fixture(rule_id, fixtures_dir, tmp_path):
    reset_registry_for_tests()
    f = fixtures_dir / rule_id / "fail.yml"
    ctx = RunContext(sigma_schema=SigmaSchema(tmp_path))
    results = lint([f], [RULE_MAP[rule_id]()], ctx)
    assert any(x.rule_id == rule_id for x in results[0].findings), \
        f"{rule_id} fail fixture did not produce a {rule_id} finding"
```

**Step 4: Run + commit.**

```bash
pytest tests/integration/test_rules_schema.py -v
git add src/sigmalint/rules/__init__.py src/sigmalint/rules/schema.py \
        tests/fixtures/SCHEMA00{2,3,4}/ tests/integration/__init__.py tests/integration/test_rules_schema.py
git commit -m "feat(rules): add SCHEMA002–004 with fixtures and parametrized tests

Phase 13/22 of sigmalint v0.1"
```

---

## Phase 14: rules.attack (ATK001–004) [depends: 7, 10, 11] [est: ~220 lines]

**Files:**
- Create: `src/sigmalint/rules/attack.py`
- Create: `tests/fixtures/ATK001/{pass.yml,fail.yml}`
- Create: `tests/fixtures/ATK002/{pass.yml,fail.yml}`
- Create: `tests/fixtures/ATK003/{pass.yml,fail.yml}`
- Create: `tests/fixtures/ATK004/{pass.yml,fail.yml}`
- Create: `tests/integration/test_rules_attack.py`

**Step 1: Write `src/sigmalint/rules/attack.py`.**

```python
"""ATK001–004 — MITRE ATT&CK alignment rules."""
from __future__ import annotations
from typing import Iterable

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity
from sigmalint.data.attack import technique_from_tag


def _technique_tags(tags) -> list[tuple[str, str]]:
    """Return [(raw_tag, normalized_technique_id)] for ATT&CK-technique tags only."""
    if not isinstance(tags, list):
        return []
    out: list[tuple[str, str]] = []
    for t in tags:
        if not isinstance(t, str):
            continue
        tid = technique_from_tag(t)
        if tid:
            out.append((t, tid))
    return out


@register
class Atk001ValidTechnique(Rule):
    id = "ATK001"
    dimension = Dimension.ATTACK
    default_severity = Severity.ERROR
    summary = "Every attack.t#### tag resolves to a known technique."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for raw, tid in _technique_tags(parsed.data.get("tags")):
            if not ctx.attack.is_valid_technique(tid):
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"unknown ATT&CK technique: {raw}", parsed.path,
                              fix_hint="Verify the technique id at attack.mitre.org.")


@register
class Atk002NotRevoked(Rule):
    id = "ATK002"
    dimension = Dimension.ATTACK
    default_severity = Severity.WARNING
    summary = "No revoked/deprecated ATT&CK techniques."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for raw, tid in _technique_tags(parsed.data.get("tags")):
            if ctx.attack.is_valid_technique(tid) and ctx.attack.is_revoked(tid):
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"technique {raw} is revoked or deprecated", parsed.path,
                              fix_hint="Replace with the current successor technique.")


@register
class Atk003LogsourcePlausible(Rule):
    id = "ATK003"
    dimension = Dimension.ATTACK
    default_severity = Severity.INFO
    summary = "logsource is plausible for cited techniques (weak signal)."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category, product = ls.get("category"), ls.get("product")
        if not (category or product):
            return
        for raw, tid in _technique_tags(parsed.data.get("tags")):
            if not ctx.attack.is_valid_technique(tid):
                continue
            if not ctx.attack_logsource.plausible(tid, category, product):
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"logsource (category={category!r}, product={product!r}) is unusual for {raw}",
                              parsed.path,
                              fix_hint="Confirm the telemetry source is appropriate for this technique.")


@register
class Atk004SubtechniqueSpecificity(Rule):
    id = "ATK004"
    dimension = Dimension.ATTACK
    default_severity = Severity.INFO
    summary = "Sub-technique specificity heuristic."

    # Heuristic: if a rule tags a parent and the detection.condition mentions
    # a known specifier (e.g. powershell.exe -> T1059.001), suggest the sub-technique.
    _PARENT_HINTS = {
        "T1059": [("powershell", "T1059.001"), ("cmd.exe", "T1059.003"),
                  ("bash", "T1059.004"), ("python", "T1059.006")],
    }

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        tags = [tid for _, tid in _technique_tags(parsed.data.get("tags"))]
        text = parsed.raw_text.lower()
        for tid in tags:
            if "." in tid:
                continue
            hints = self._PARENT_HINTS.get(tid, [])
            for needle, sub in hints:
                if needle in text and sub not in tags:
                    yield Finding(self.id, self.dimension, self.default_severity,
                                  f"parent technique {tid} cited; rule body suggests {sub}",
                                  parsed.path,
                                  fix_hint=f"Add `attack.t{sub.lower().replace('t','')}` to tags.")
                    break
```

**Step 2: Extend `core.runner.RunContext` so `attack_logsource` is recognized.** Add `attack_logsource: object | None = None` to the dataclass in `core/runner.py` (one-line change).

**Step 3: Create fixtures.** Examples:

`tests/fixtures/ATK001/pass.yml` — `tags: [attack.t1059]`. `fail.yml` — `tags: [attack.t9999]`.
`tests/fixtures/ATK004/pass.yml` — rule body mentions powershell and tags `attack.t1059.001`. `fail.yml` — body mentions powershell, tags only `attack.t1059`.

**Step 4: Write `tests/integration/test_rules_attack.py`** mirroring the SCHEMA test pattern; wire `RunContext(attack=AttackTaxonomy(tmp_path), attack_logsource=AttackLogsourceMap(tmp_path))`.

**Step 5: Run + commit.**

```bash
pytest tests/integration/test_rules_attack.py -v
git add src/sigmalint/rules/attack.py src/sigmalint/core/runner.py \
        tests/fixtures/ATK00{1,2,3,4}/ tests/integration/test_rules_attack.py
git commit -m "feat(rules): add ATK001–004 with technique-tag validation and weak-signal heuristics

Phase 14/22 of sigmalint v0.1"
```

---

## Phase 15: rules.metadata (META001a/b, META002–005) [depends: 7] [est: ~220 lines]

**Files:**
- Create: `src/sigmalint/rules/metadata.py`
- Create: `tests/fixtures/META001a/{pass.yml,fail.yml}`
- Create: `tests/fixtures/META001b/{pass.yml,fail.yml}`
- Create: `tests/fixtures/META002/{pass.yml,fail.yml}`
- Create: `tests/fixtures/META003/{pass.yml,fail.yml}`
- Create: `tests/fixtures/META004/{pass.yml,fail.yml}`
- Create: `tests/fixtures/META005/{pass.yml,fail.yml}`
- Create: `tests/integration/test_rules_metadata.py`

**Step 1: Write `src/sigmalint/rules/metadata.py`.**

```python
"""META001a/b–META005 — metadata completeness rules.

Pattern note: rules pass key paths (e.g. "id", "logsource/category") to
`_finding(..., *path)` so Findings carry line/col extracted from
ParsedRule.positions. Findings without a meaningful path may omit it; the
formatter defaults to file-level (line=None).
"""
from __future__ import annotations
import re
from typing import Iterable
from uuid import UUID

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


def _finding(rule, msg, parsed, hint, *path: str):
    """Helper: build a Finding with line/col looked up from parsed.positions."""
    line, col = parsed.position_for(*path) if path else (None, None)
    return Finding(rule.id, rule.dimension, rule.default_severity, msg, parsed.path,
                   line=line, col=col, fix_hint=hint)


@register
class Meta001aIdPresent(Rule):
    id = "META001a"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "Rule has an id."

    def check(self, parsed, ctx) -> Iterable[Finding]:
        if "id" not in parsed.data or not parsed.data.get("id"):
            yield _finding(self, "missing id (Sigma marks id optional but strongly recommended)",
                           parsed, "Add `id: <uuid4>` (e.g. `python -c 'import uuid;print(uuid.uuid4())'`).")


@register
class Meta001bIdValidUuid4(Rule):
    id = "META001b"
    dimension = Dimension.METADATA
    default_severity = Severity.ERROR
    summary = "id, if present, is a valid UUIDv4."

    def check(self, parsed, ctx) -> Iterable[Finding]:
        rid = parsed.data.get("id")
        if rid is None:
            return
        try:
            u = UUID(str(rid))
        except (ValueError, TypeError):
            yield _finding(self, f"id {rid!r} is not a valid UUID", parsed,
                           "Use a UUIDv4: `python -c 'import uuid;print(uuid.uuid4())'`.",
                           "id")
            return
        if u.version != 4:
            yield _finding(self, f"id {rid!r} is UUIDv{u.version}, expected UUIDv4", parsed,
                           "Regenerate with UUIDv4.", "id")


@register
class Meta002CorePopulated(Rule):
    id = "META002"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "author, date, description, level populated."

    REQUIRED = ("author", "date", "description", "level")

    def check(self, parsed, ctx) -> Iterable[Finding]:
        for key in self.REQUIRED:
            v = parsed.data.get(key)
            if v is None or (isinstance(v, str) and not v.strip()):
                yield _finding(self, f"metadata field empty or missing: {key}", parsed,
                               f"Populate `{key}:`.")


@register
class Meta003ReferencesForHigh(Rule):
    id = "META003"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "references non-empty when level is high or critical."

    def check(self, parsed, ctx) -> Iterable[Finding]:
        level = (parsed.data.get("level") or "").lower()
        if level not in {"high", "critical"}:
            return
        refs = parsed.data.get("references") or []
        if not isinstance(refs, list) or not any(isinstance(r, str) and r.strip() for r in refs):
            yield _finding(self, f"level={level} but references is empty", parsed,
                           "Cite at least one source URL under `references:`.")


@register
class Meta004FalsepositivesPopulated(Rule):
    id = "META004"
    dimension = Dimension.METADATA
    default_severity = Severity.INFO
    summary = "falsepositives non-empty and not literally 'Unknown'."

    def check(self, parsed, ctx) -> Iterable[Finding]:
        fps = parsed.data.get("falsepositives") or []
        if isinstance(fps, str):
            fps = [fps]
        meaningful = [f for f in fps if isinstance(f, str) and f.strip() and f.strip().lower() != "unknown"]
        if not meaningful:
            yield _finding(self, "falsepositives is empty or only 'Unknown'", parsed,
                           "List realistic false-positive sources or 'None known'.")


@register
class Meta005StatusVocabulary(Rule):
    id = "META005"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "status (if present) is a Sigma-2.1.0 vocabulary value."

    def check(self, parsed, ctx) -> Iterable[Finding]:
        status = parsed.data.get("status")
        if status is None:
            return
        if status not in VALID_STATUS:
            yield _finding(self, f"status={status!r} not in {sorted(VALID_STATUS)}", parsed,
                           "Use one of: stable, test, experimental, deprecated, unsupported.")
```

**Step 2: Create six pass/fail fixture pairs.**

**Step 3: Write `tests/integration/test_rules_metadata.py`** following the same parametrize pattern as Phase 13.

**Step 4: Run + commit.**

```bash
pytest tests/integration/test_rules_metadata.py -v
git add src/sigmalint/rules/metadata.py tests/fixtures/META* tests/integration/test_rules_metadata.py
git commit -m "feat(rules): add META001a/b–META005 metadata completeness rules

Phase 15/22 of sigmalint v0.1"
```

---

## Phase 16: rules.taxonomy (TAX001–003) [depends: 7, 11] [est: ~180 lines]

**Files:**
- Create: `src/sigmalint/rules/taxonomy.py`
- Create: `tests/fixtures/TAX001/{pass.yml,fail.yml}`
- Create: `tests/fixtures/TAX002/{pass.yml,fail.yml}`
- Create: `tests/fixtures/TAX003/{pass.yml,fail.yml}`
- Create: `tests/integration/test_rules_taxonomy.py`

**Step 1: Write `src/sigmalint/rules/taxonomy.py`.**

```python
"""TAX001–003 — Sigma taxonomy correctness rules."""
from __future__ import annotations
from typing import Iterable

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


def _walk_detection_fields(detection: dict) -> Iterable[str]:
    for name, sel in detection.items():
        if name == "condition" or not isinstance(sel, dict):
            continue
        yield from sel.keys()


@register
class Tax001KnownFields(Rule):
    id = "TAX001"
    dimension = Dimension.TAXONOMY
    default_severity = Severity.WARNING
    summary = "All detection field names exist in the configured taxonomy."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category = ls.get("category")
        if not category:
            return
        taxonomy = parsed.data.get("taxonomy") or ctx.config.taxonomy
        for field in _walk_detection_fields(parsed.data.get("detection") or {}):
            if not ctx.taxonomy.is_known(taxonomy, category, field):
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"unknown field for logsource.category={category}: {field}",
                              parsed.path,
                              fix_hint="Confirm field exists for this log source or set `taxonomy:` to a custom value.")


@register
class Tax002ValidModifiers(Rule):
    id = "TAX002"
    dimension = Dimension.TAXONOMY
    default_severity = Severity.WARNING
    summary = "Field-name modifiers are spelled correctly per Sigma 2.1.0."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for field in _walk_detection_fields(parsed.data.get("detection") or {}):
            if "|" not in field:
                continue
            _, *mods = field.split("|")
            for mod in mods:
                if not ctx.modifiers.is_known(mod):
                    yield Finding(self.id, self.dimension, self.default_severity,
                                  f"unknown modifier: {field}",
                                  parsed.path,
                                  fix_hint="Check Sigma 2.1.0 modifier appendix.")


@register
class Tax003CanonicalField(Rule):
    id = "TAX003"
    dimension = Dimension.TAXONOMY
    default_severity = Severity.INFO
    summary = "Prefer canonical field over known aliases."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category = ls.get("category")
        if not category:
            return
        taxonomy = parsed.data.get("taxonomy") or ctx.config.taxonomy
        for field in _walk_detection_fields(parsed.data.get("detection") or {}):
            bare = field.split("|", 1)[0]
            canonical = ctx.taxonomy.canonical(taxonomy, category, bare)
            if canonical:
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"prefer canonical field {canonical!r} over {bare!r}",
                              parsed.path,
                              fix_hint=f"Rename `{bare}` to `{canonical}`.")
```

**Step 2: Add `modifiers` and `config` to `RunContext`.** Update `core/runner.py`'s `RunContext` to add `modifiers: object | None = None`.

**Step 3: Create fixtures + integration test (same pattern as Phase 13).**

**Step 4: Run + commit.**

```bash
pytest tests/integration/test_rules_taxonomy.py -v
git add src/sigmalint/rules/taxonomy.py src/sigmalint/core/runner.py \
        tests/fixtures/TAX00{1,2,3}/ tests/integration/test_rules_taxonomy.py
git commit -m "feat(rules): add TAX001–003 with taxonomy-driven field validation

Phase 16/22 of sigmalint v0.1"
```

---

## Phase 17: rules.fp_risk (FP001–004) + Sigma Filters discovery [depends: 7, 11] [est: ~280 lines]

**Files:**
- Create: `src/sigmalint/rules/fp_risk.py`
- Create: `src/sigmalint/core/filters.py` (Sigma Filter file discovery + condition merging)
- Create: `tests/fixtures/FP001/{pass.yml,fail.yml}`
- Create: `tests/fixtures/FP002/{pass.yml,fail.yml}`
- Create: `tests/fixtures/FP003/{pass.yml,fail.yml}`
- Create: `tests/fixtures/FP004/{pass.yml,fail.yml}`
- Create: `tests/integration/test_rules_fp_risk.py`
- Create: `tests/unit/core/test_filters.py`

**Step 1: Write `src/sigmalint/core/filters.py`.**

```python
"""Sigma Filter file discovery and condition-merging for FP003.

Sigma Filter file shape (per SigmaHQ docs):

    title: <name>
    id: <uuid>
    logsource: { ... }
    filter:
      rules:
        - <referenced-rule-id-or-title>
      selection:
        Field: value
      condition: not selection

A Sigma Filter is detected by the presence of a top-level `filter:` mapping
that itself contains a `rules:` list (the rules it targets) and a `condition:`
string. There is no `kind: filter` field in the spec. Filters reference rules
by either UUID id or title.
"""
from __future__ import annotations
import glob
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import yaml


@dataclass(frozen=True, slots=True)
class SigmaFilter:
    path: str
    targets_ids: tuple[str, ...]    # rule ids referenced
    targets_names: tuple[str, ...]  # rule titles/names referenced
    condition: str                  # the filter's appended condition


def _is_uuid(s: str) -> bool:
    try:
        UUID(str(s))
        return True
    except (ValueError, TypeError):
        return False


def discover_filters(patterns: list[str], cwd: Path) -> list[SigmaFilter]:
    """Find Sigma Filter files under the given glob patterns.

    A YAML doc is treated as a Sigma Filter when it has a top-level mapping
    `filter:` containing both `rules:` (non-empty list) and `condition:` (str).
    """
    out: list[SigmaFilter] = []
    for pat in patterns:
        for p in glob.glob(str(cwd / pat), recursive=True):
            pth = Path(p)
            try:
                doc = yaml.safe_load(pth.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(doc, dict):
                continue
            filt = doc.get("filter")
            if not isinstance(filt, dict):
                continue
            rules = filt.get("rules")
            condition = filt.get("condition")
            if not isinstance(rules, list) or not rules:
                continue
            if not isinstance(condition, str) or not condition.strip():
                continue
            ids = tuple(r for r in rules if isinstance(r, str) and _is_uuid(r))
            names = tuple(r for r in rules if isinstance(r, str) and not _is_uuid(r))
            out.append(SigmaFilter(path=str(pth), targets_ids=ids,
                                   targets_names=names, condition=condition))
    return out


def filters_for_rule(filters: list[SigmaFilter], rule_id: str | None,
                     title: str | None) -> list[SigmaFilter]:
    return [f for f in filters
            if (rule_id and rule_id in f.targets_ids)
            or (title and title in f.targets_names)]
```

**Step 2: Write `src/sigmalint/rules/fp_risk.py`.**

```python
"""FP001–004 — false-positive risk rules."""
from __future__ import annotations
import re
from typing import Iterable

from sigmalint.core.condition import has_negated_selector, parse, referenced_selectors
from sigmalint.core.filters import filters_for_rule
from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


_NOISY_CATEGORIES = {"process_creation", "registry_event", "file_event", "network_connection"}


def _is_filter_selector(name: str) -> bool:
    return name == "filter" or name.startswith("filter_") or name.startswith("_")


def _selectors(detection: dict) -> dict[str, dict]:
    return {k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)}


@register
class Fp001SingleBroadSelection(Rule):
    id = "FP001"
    dimension = Dimension.FP_RISK
    default_severity = Severity.WARNING
    summary = "Single broad selection with no filter."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        detection = parsed.data.get("detection") or {}
        sels = _selectors(detection)
        if len(sels) != 1:
            return
        (name, body) = next(iter(sels.items()))
        if _is_filter_selector(name):
            return
        # one field, one common value -> broad
        if len(body) != 1:
            return
        (field, value) = next(iter(body.items()))
        if isinstance(value, list):
            return
        if isinstance(value, str) and len(value) < 6:
            yield Finding(self.id, self.dimension, self.default_severity,
                          f"single selection on {field}={value!r} likely too broad",
                          parsed.path,
                          fix_hint="Add additional selectors or a filter clause.")


@register
class Fp002PreferModifiers(Rule):
    id = "FP002"
    dimension = Dimension.FP_RISK
    default_severity = Severity.INFO
    summary = "Prefer modifiers over leading/trailing wildcards."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for selname, body in _selectors(parsed.data.get("detection") or {}).items():
            for field, value in body.items():
                if "|" in field:
                    continue  # already using a modifier
                values = value if isinstance(value, list) else [value]
                for v in values:
                    if not isinstance(v, str):
                        continue
                    if v.startswith("*") and v.endswith("*"):
                        yield Finding(self.id, self.dimension, self.default_severity,
                                      f"{selname}.{field}={v!r}: prefer `{field}|contains: {v.strip('*')!r}`",
                                      parsed.path,
                                      fix_hint=f"Replace with modifier `|contains`.")
                    elif v.endswith("*") and not v.startswith("*"):
                        yield Finding(self.id, self.dimension, self.default_severity,
                                      f"{selname}.{field}={v!r}: prefer `{field}|startswith`",
                                      parsed.path, fix_hint="Use `|startswith`.")
                    elif v.startswith("*") and not v.endswith("*"):
                        yield Finding(self.id, self.dimension, self.default_severity,
                                      f"{selname}.{field}={v!r}: prefer `{field}|endswith`",
                                      parsed.path, fix_hint="Use `|endswith`.")


@register
class Fp003NoFilterOnNoisy(Rule):
    id = "FP003"
    dimension = Dimension.FP_RISK
    default_severity = Severity.WARNING
    summary = "Noisy log source has no negated filter selector."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        ls = parsed.data.get("logsource") or {}
        category = ls.get("category")
        if category not in _NOISY_CATEGORIES:
            return
        detection = parsed.data.get("detection") or {}
        condition = detection.get("condition")
        if condition is None:
            return
        # In-file filters
        try:
            ast = parse(condition)
        except Exception:
            return
        if has_negated_selector(ast, _is_filter_selector):
            return
        # External Sigma Filters
        ext = filters_for_rule(ctx.filters or [], parsed.data.get("id"),
                               parsed.data.get("title"))
        for f in ext:
            try:
                ext_ast = parse(f.condition)
            except Exception:
                continue
            if has_negated_selector(ext_ast, _is_filter_selector):
                return
        yield Finding(self.id, self.dimension, self.default_severity,
                      f"category={category!r} rule has no negated filter selector",
                      parsed.path,
                      fix_hint="Add `filter:` selector and reference as `selection and not filter` (or add a Sigma Filter file).")


_HARDCODED_PATTERNS = [
    re.compile(r"C:\\Users\\[A-Za-z0-9._-]+"),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
]


@register
class Fp004HardcodedLiterals(Rule):
    id = "FP004"
    dimension = Dimension.FP_RISK
    default_severity = Severity.INFO
    summary = "Hardcoded environment-specific literals."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for pat in _HARDCODED_PATTERNS:
            m = pat.search(parsed.raw_text)
            if m:
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"likely environment-specific literal: {m.group(0)!r}",
                              parsed.path,
                              fix_hint="Generalize (e.g., `C:\\Users\\*\\...`) or move to a filter.")
```

**Step 3: Create 4 pass/fail fixture pairs + integration test.**

**Step 4: Write `tests/unit/core/test_filters.py`** covering discovery + ID/name matching.

**Step 5: Run + commit.**

```bash
pytest tests/unit/core/test_filters.py tests/integration/test_rules_fp_risk.py -v
git add src/sigmalint/core/filters.py src/sigmalint/rules/fp_risk.py \
        tests/fixtures/FP00{1,2,3,4}/ tests/integration/test_rules_fp_risk.py \
        tests/unit/core/test_filters.py
git commit -m "feat(rules): add FP001–004 and Sigma Filters discovery (filters_paths config)

Phase 17/22 of sigmalint v0.1"
```

---

## Phase 18: rules.redundancy + rules.style [depends: 7, 11, 12] [est: ~180 lines]

**Files:**
- Create: `src/sigmalint/rules/redundancy.py`
- Create: `src/sigmalint/rules/style.py`
- Create: `tests/fixtures/RED00{1,2}/{pass.yml,fail.yml}`
- Create: `tests/fixtures/STY00{1,2,3}/{pass.yml,fail.yml}`
- Create: `tests/integration/test_rules_redundancy.py`
- Create: `tests/integration/test_rules_style.py`

**Step 1: Write `src/sigmalint/rules/redundancy.py`.**

```python
"""RED001–002 — overlap with SigmaHQ public corpus."""
from __future__ import annotations
from typing import Iterable

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity
from sigmalint.data.corpus import fingerprint_for_rule


@register
class Red001NearDuplicateFingerprint(Rule):
    id = "RED001"
    dimension = Dimension.REDUNDANCY
    default_severity = Severity.INFO
    summary = "Detection fingerprint near-duplicates an existing SigmaHQ rule (≥0.85 Jaccard)."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        corpus = ctx.corpus
        if corpus is None or not corpus.available:
            return
        fp = fingerprint_for_rule(parsed.data)
        if not fp:
            return
        matches = corpus.near_duplicates(fp, threshold=0.85)
        for m in matches[:3]:
            if m.path == parsed.path:
                continue
            yield Finding(self.id, self.dimension, self.default_severity,
                          f"near-duplicate of public rule {m.title!r} ({m.path})",
                          parsed.path,
                          fix_hint="If this is a meaningful extension, document the delta in description.")


@register
class Red002TitleOrIdCollision(Rule):
    id = "RED002"
    dimension = Dimension.REDUNDANCY
    default_severity = Severity.INFO
    summary = "Title or id collides with a SigmaHQ public rule."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        corpus = ctx.corpus
        if corpus is None or not corpus.available:
            return
        rid = parsed.data.get("id")
        title = parsed.data.get("title")
        for e in corpus.entries():
            if rid and e.id == rid:
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"id collides with {e.path}", parsed.path,
                              fix_hint="Regenerate a unique UUIDv4.")
                return
            if title and e.title == title:
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"title collides with {e.path}: {title!r}", parsed.path,
                              fix_hint="Rename your rule.")
                return
```

**Step 2: Write `src/sigmalint/rules/style.py`.**

```python
"""STY001–003 — Sigma interoperability style."""
from __future__ import annotations
from pathlib import Path
from typing import Iterable

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


@register
class Sty001LowercaseTopLevelKeys(Rule):
    id = "STY001"
    dimension = Dimension.STYLE
    default_severity = Severity.INFO
    summary = "Top-level keys are lowercase."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for k in parsed.data.keys():
            if isinstance(k, str) and k != k.lower():
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"top-level key not lowercase: {k!r}",
                              parsed.path, fix_hint=f"Rename to `{k.lower()}`.")


@register
class Sty002LfAndYml(Rule):
    id = "STY002"
    dimension = Dimension.STYLE
    default_severity = Severity.INFO
    summary = "File uses LF line endings and .yml extension."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        if "\r\n" in parsed.raw_text:
            yield Finding(self.id, self.dimension, self.default_severity,
                          "CRLF line endings", parsed.path, fix_hint="Convert to LF.")
        if Path(parsed.path).suffix == ".yaml":
            yield Finding(self.id, self.dimension, self.default_severity,
                          "use .yml extension (Sigma convention)", parsed.path,
                          fix_hint="Rename to .yml.")


@register
class Sty003FourSpaceIndent(Rule):
    id = "STY003"
    dimension = Dimension.STYLE
    default_severity = Severity.INFO
    summary = "Four-space indentation."

    def check(self, parsed: ParsedRule, ctx) -> Iterable[Finding]:
        for lineno, line in enumerate(parsed.raw_text.splitlines(), 1):
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            if indent and indent % 4:
                yield Finding(self.id, self.dimension, self.default_severity,
                              f"indent of {indent} spaces is not a multiple of 4",
                              parsed.path, line=lineno, col=1,
                              fix_hint="Reindent with 4-space steps.")
                return  # one report per file


```

**Step 3: Fixtures + tests (same pattern).**

**Step 4: Run + commit.**

```bash
pytest tests/integration/test_rules_redundancy.py tests/integration/test_rules_style.py -v
git add src/sigmalint/rules/redundancy.py src/sigmalint/rules/style.py \
        tests/fixtures/RED* tests/fixtures/STY* \
        tests/integration/test_rules_redundancy.py tests/integration/test_rules_style.py
git commit -m "feat(rules): add RED001–002 and STY001–003

Phase 18/22 of sigmalint v0.1"
```

---

## Phase 19: reporting (text + json + sarif + github) [depends: 8] [est: ~260 lines]

**Files:**
- Create: `src/sigmalint/reporting/__init__.py`
- Create: `src/sigmalint/reporting/model.py` (canonical report shape)
- Create: `src/sigmalint/reporting/text.py`
- Create: `src/sigmalint/reporting/json.py`
- Create: `src/sigmalint/reporting/sarif.py`
- Create: `src/sigmalint/reporting/github.py`
- Create: `tests/unit/reporting/__init__.py`
- Create: `tests/unit/reporting/test_reporters.py`

**Step 1: Write `model.py`** with a `build_report(results, scores, profile, data_versions) -> dict` function returning the canonical shape from spec §12.

**Step 2: Write the four formatters.** Each accepts the canonical dict and an output stream:

- `json`: `json.dumps(report, indent=2)`
- `text`: rich `Table` of files with status, score, top findings
- `sarif`: SARIF 2.1.0 minimum viable wrapper (results[] mapped 1:1 from findings)
- `github`: prints `::error|warning|notice file=...,line=...,col=...::message` per finding, then a final score summary

**Step 3: Test each format against a fixed canonical-report sample** (golden snapshot saved at `tests/fixtures/reports/golden.json`).

**Step 4: Run + commit.**

```bash
pytest tests/unit/reporting/test_reporters.py -v
git add src/sigmalint/reporting/ tests/unit/reporting/
git commit -m "feat(reporting): canonical report builder + text/json/sarif/github formatters

Phase 19/22 of sigmalint v0.1"
```

---

## Phase 20: CLI (`lint`, `list-rules`, `explain`, `profiles`, `update-data`) [depends: 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19] [est: ~300 lines]

**Files:**
- Create: `src/sigmalint/cli/__init__.py` (empty)
- Create: `src/sigmalint/cli/main.py`
- Create: `src/sigmalint/cli/update_data.py`
- Create: `tests/integration/test_cli.py`

**Step 1: Write `src/sigmalint/cli/main.py`.** Typer app with subcommands. `lint` is the centerpiece:

```python
"""sigmalint CLI."""
from __future__ import annotations
import sys
from pathlib import Path
from typing import Annotated

import typer

from sigmalint import __version__
from sigmalint.core.config import load_config
from sigmalint.core.errors import SigmalintError
from sigmalint.core.filters import discover_filters
from sigmalint.core.profiles import PROFILES, resolve_severity
from sigmalint.core.registry import enabled_rules
from sigmalint.core.runner import RunContext, lint as run_lint
from sigmalint.core.scoring import score_file
from sigmalint.core.types import Severity
from sigmalint.data.attack import AttackTaxonomy
from sigmalint.data.corpus import RuleCorpus
from sigmalint.data.sigma_schema import SigmaSchema
from sigmalint.data.taxonomy import AttackLogsourceMap, SigmaModifiers, SigmaTaxonomy

# Import rule modules to register them.
from sigmalint.rules import schema as _s  # noqa: F401
from sigmalint.rules import attack as _a  # noqa: F401
from sigmalint.rules import metadata as _m  # noqa: F401
from sigmalint.rules import taxonomy as _t  # noqa: F401
from sigmalint.rules import fp_risk as _fp  # noqa: F401
from sigmalint.rules import redundancy as _r  # noqa: F401
from sigmalint.rules import style as _st  # noqa: F401

from sigmalint.reporting.model import build_report
from sigmalint.reporting import text as txt, json as jsn, sarif as sar, github as gha

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="ESLint-style linter for Sigma detection rules.")


def _collect_paths(paths: list[Path]) -> list[Path]:
    """Recursively collect *.yml and *.yaml files. STY002 then flags .yaml."""
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            collected: list[Path] = []
            for pat in ("*.yml", "*.yaml"):
                collected.extend(p.rglob(pat))
            out.extend(sorted(set(collected)))
        elif p.is_file():
            out.append(p)
    return out


@app.command()
def lint(
    paths: list[Path],
    fmt: Annotated[str, typer.Option("--format", "-f")] = "text",
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    profile: Annotated[str | None, typer.Option("--profile", "-p")] = None,
    disable: Annotated[list[str] | None, typer.Option("--disable")] = None,
    enable_only: Annotated[list[str] | None, typer.Option("--enable-only")] = None,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = None,
    min_score: Annotated[float | None, typer.Option("--min-score")] = None,
    debug: Annotated[bool, typer.Option("--debug")] = False,
):
    """Lint Sigma rule file(s) or directory(ies)."""
    import dataclasses
    try:
        cfg = load_config(config) if config else load_config(Path(".sigmalintrc.yml"))
        # Config is frozen + slotted — use dataclasses.replace, not __dict__.
        if profile:
            cfg = dataclasses.replace(cfg, profile=profile)
        if fail_on:
            cfg = dataclasses.replace(cfg, fail_on=fail_on)
        if min_score is not None:
            cfg = dataclasses.replace(cfg, min_score=min_score)

        data_dir = Path(cfg.data_dir).expanduser()
        ctx = RunContext(
            attack=AttackTaxonomy(data_dir),
            sigma_schema=SigmaSchema(data_dir),
            taxonomy=SigmaTaxonomy(data_dir),
            modifiers=SigmaModifiers(data_dir),
            attack_logsource=AttackLogsourceMap(data_dir),
            corpus=RuleCorpus(data_dir),
            config=cfg,
            filters=discover_filters(list(cfg.filters_paths), Path.cwd()),
        )

        all_paths = _collect_paths(paths)
        disable_set = list(cfg.disable) + (disable or [])
        enable_set = enable_only or (list(cfg.enable_only) if cfg.enable_only else None)
        rules = enabled_rules(disabled=disable_set, enable_only=enable_set)
        # Severity resolution order (later wins):
        #   1. rule.default_severity
        #   2. profile override (PROFILES[cfg.profile])
        #   3. user override (cfg.severities)
        # A None at any layer means "disabled" and the rule is dropped.
        kept: list = []
        for r in rules:
            eff = resolve_severity(cfg.profile, r.id, r.default_severity)
            if eff is None:
                continue  # disabled by profile
            if r.id in cfg.severities:
                eff = cfg.severities[r.id]
            r.default_severity = eff  # type: ignore[misc]
            kept.append(r)
        rules = kept

        results = run_lint(all_paths, rules, ctx)
        scores = [score_file(r, cfg) for r in results]

        report = build_report(results, scores, cfg.profile, _data_versions(ctx))
        out = sys.stdout
        match fmt:
            case "json":  jsn.write(report, out)
            case "sarif": sar.write(report, out)
            case "github": gha.write(report, out)
            case _: txt.write(report, out)

        exit_code = _compute_exit(report, cfg)
        raise typer.Exit(exit_code)
    except SigmalintError as e:
        typer.secho(f"sigmalint: {e}", err=True, fg=typer.colors.RED)
        raise typer.Exit(3 if "load" in str(e).lower() else 2)


def _data_versions(ctx: RunContext) -> dict:
    return {
        "sigma_schema": ctx.sigma_schema.data_version,
        "attack": ctx.attack.data_version,
        "taxonomy": ctx.taxonomy.data_version,
        "corpus": ctx.corpus.data_version,
    }


def _compute_exit(report: dict, cfg) -> int:
    severities = {f["severity"] for fobj in report["files"] for f in fobj["findings"]}
    if cfg.fail_on == "error" and "error" in severities:
        return 1
    if cfg.fail_on == "warning" and {"error", "warning"} & severities:
        return 1
    if cfg.min_score is not None and report["summary"]["mean_score"] < cfg.min_score:
        return 1
    return 0


@app.command(name="list-rules")
def list_rules(profile: str = "sigmahq"):
    from sigmalint.core.registry import all_rules
    for r in all_rules():
        eff = resolve_severity(profile, r.id, r.default_severity)
        typer.echo(f"{r.id:<10} [{r.dimension.value:<10}] {eff.value if eff else 'OFF':<8}  {r.summary}")


@app.command()
def explain(rule_id: str):
    doc = Path(__file__).parent.parent.parent.parent / "docs" / "rules" / f"{rule_id}.md"
    if not doc.exists():
        typer.echo(f"No documentation for {rule_id}.", err=True)
        raise typer.Exit(2)
    typer.echo(doc.read_text())


@app.command()
def profiles():
    for name, mapping in PROFILES.items():
        typer.echo(f"\n## {name}")
        for rid, sev in sorted(mapping.items()):
            typer.echo(f"  {rid:<10} -> {sev.value if sev else 'OFF'}")


@app.command(name="update-data")
def update_data_cmd(
    corpus: Annotated[bool, typer.Option("--corpus")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
):
    from sigmalint.cli.update_data import refresh
    refresh(corpus=corpus, dry_run=dry_run)


@app.callback()
def version(value: bool = typer.Option(None, "--version", is_eager=True)):
    if value:
        typer.echo(f"sigmalint {__version__}")
        raise typer.Exit()
```

**Step 2: Write `src/sigmalint/cli/update_data.py`.** Downloads ATT&CK STIX + Sigma schema into `data_dir`; optionally clones SigmaHQ.

**Step 3: Write `tests/integration/test_cli.py`** using `typer.testing.CliRunner` to smoke-test `lint`, `list-rules`, `profiles`, `explain` (missing rule = exit 2), and `--version`.

**Step 4: Run + commit.**

```bash
pytest tests/integration/test_cli.py -v
git add src/sigmalint/cli/ tests/integration/test_cli.py
git commit -m "feat(cli): wire lint/list-rules/explain/profiles/update-data with profile-aware severities

Phase 20/22 of sigmalint v0.1"
```

---

## Phase 21: docs, rule pages, OSS files, CONTRIBUTING [depends: 20] [est: ~600 lines]

**Files:**
- Create: `docs/rules/<RULE_ID>.md` (one per rule, 26 files)
- Create: `docs/scoring.md`
- Create: `docs/configuration.md`
- Create: `docs/profiles.md`
- Create: `docs/architecture.md`
- Create: `docs/maintainers.md`
- Create: `CONTRIBUTING.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `SECURITY.md`
- Create: `CHANGELOG.md`
- Create: `CITATION.cff`
- Create: `CODEOWNERS`
- Create: `.github/dependabot.yml`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`
- Create: `.github/ISSUE_TEMPLATE/feature_request.yml`
- Create: `.github/ISSUE_TEMPLATE/new_rule_proposal.yml`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Modify: `README.md` (final polish with badges, quickstart, output sample, CI snippet, citation)

**Step 1: Per-rule docs.** Each file has frontmatter (`id`, `dimension`, `default_severity`, `profiles`), what it checks, why, examples (good/bad), how to fix, references. Length: 30–60 lines each.

**Step 2: `docs/scoring.md`** — explain validity gate, severity weights, dimension weights, profile interaction.

**Step 3: `docs/profiles.md`** — table per profile listing rule-id → severity.

**Step 4: `CONTRIBUTING.md`** — headline section is "How to add a new rule" with the 4-step contract: write class, write pass/fail fixtures, write 1-line parametrize entry, write `docs/rules/<id>.md`.

**Step 5: `.github/ISSUE_TEMPLATE/new_rule_proposal.yml`** — structured form (rule ID guess, dimension, problem, example bad rule, suggested check, suggested severity).

**Step 6: `.github/PULL_REQUEST_TEMPLATE.md`** with checkboxes:
- [ ] Added fixtures under `tests/fixtures/<RULE_ID>/`
- [ ] Added `docs/rules/<RULE_ID>.md`
- [ ] Added parametrize entry in matching `tests/integration/test_rules_<dim>.py`
- [ ] `sigmalint lint` self-lint passes
- [ ] Coverage stays ≥ 90%

**Step 7: `README.md` final** with badges (build, PyPI, license, Python, codecov), 6-line quickstart, sample text output, GH Action snippet, citation reference.

**Step 8: Commit.**

```bash
git add docs/ CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md CHANGELOG.md CITATION.cff CODEOWNERS \
        .github/dependabot.yml .github/ISSUE_TEMPLATE/ .github/PULL_REQUEST_TEMPLATE.md README.md
git commit -m "docs: add per-rule pages, scoring/profiles/architecture docs, OSS-readiness files

Phase 21/22 of sigmalint v0.1"
```

---

## Phase 22: GitHub Action, release pipeline, self-lint, v0.1.0 tag [depends: 20, 21] [est: ~180 lines]

**Files:**
- Create: `action.yml`
- Create: `.github/workflows/release.yml`
- Create: `.github/workflows/self-lint.yml`
- Modify: `README.md` (add Action usage example)

**Step 1: Write `action.yml` (composite action).**

```yaml
name: sigmalint
description: Lint Sigma detection rules for quality and validity
branding: {icon: shield, color: blue}
inputs:
  path: {description: "Path(s) to lint", required: true}
  format: {description: "Output format", default: "github"}
  fail-on: {description: "error|warning|never", default: "error"}
  min-score: {description: "Minimum total score", required: false}
  version: {description: "sigmalint version to install", default: "0.1.0"}
runs:
  using: composite
  steps:
    - uses: actions/setup-python@v5
      with: {python-version: "3.11"}
    - shell: bash
      run: pip install "sigmalint==${{ inputs.version }}"
    - shell: bash
      run: |
        args=( "${{ inputs.path }}" --format "${{ inputs.format }}" --fail-on "${{ inputs.fail-on }}" )
        if [ -n "${{ inputs.min-score }}" ]; then args+=( --min-score "${{ inputs.min-score }}" ); fi
        sigmalint lint "${args[@]}"
```

**Step 2: Write `.github/workflows/release.yml`** — triggers on `v*` tag; builds with hatch; publishes via `pypa/gh-action-pypi-publish` using trusted publishing.

**Step 3: Write `.github/workflows/self-lint.yml`** — nightly cron, clones SigmaHQ, runs `sigmalint lint` over the corpus, posts mean-score to a GitHub Issue (or comment) if drop > 2 points week-over-week.

**Step 4: Run full local validation.**

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy --strict src/sigmalint
lint-imports
pytest --cov=sigmalint --cov-fail-under=90
sigmalint lint tests/fixtures   # self-lint
```

Expected: all checks green; self-lint produces well-formed output.

**Step 5: Tag and release.**

```bash
git add action.yml .github/workflows/release.yml .github/workflows/self-lint.yml README.md
git commit -m "feat: GitHub composite action, release pipeline, nightly self-lint

Phase 22/22 of sigmalint v0.1"
git tag v0.1.0
# (Push when ready; GitHub Marketplace listing follows.)
```

---

## Self-review

**Spec coverage matrix.**

| Spec section | Phase(s) |
|---|---|
| §1 Purpose, §3 Decisions | Phases 1, 9–12 (vendored data write model) |
| §4 Architecture, layering | Phase 1 (`.importlinter.cfg`), Phases 2–8 (core layer) |
| §5 Components | Each component owned by exactly one phase |
| §6 Data flow | Phase 7 (runner) + Phase 20 (CLI wiring) |
| §7 Rule catalog (26 rules) | SCHEMA→P13, ATK→P14, META→P15, TAX→P16, FP→P17, RED+STY→P18 |
| §8 Scoring (validity gate + weights) | Phase 8 |
| §9 Profiles | Phase 4 |
| §10 Configuration (incl. `filters_paths`) | Phase 5 |
| §11 CLI (incl. `profiles` command) | Phase 20 |
| §12 Output shape (status, data_versions, suppressions) | Phase 19 (model) + Phase 20 (wiring) |
| §13 Error handling (3 categories, INTERNAL001) | Phase 2 + Phase 7 |
| §14 Testing strategy | Every phase ends with a test step; coverage gate in CI (Phase 1) |
| §15 Project layout | Distributed across phases 1, 9–18 |
| §16 CI & release (ci.yml, release.yml, self-lint.yml, action.yml) | Phase 1 + Phase 22 |
| §17 OSS readiness (LICENSE/CONTRIBUTING/CoC/SECURITY/CHANGELOG/CITATION/dependabot/templates) | Phase 1 (LICENSE) + Phase 21 (rest) |
| §18 Schedule (Week 1: 14 rules; Week 2: 12 rules; Week 3: docs+CI) | P1–P15 ≈ Week 1; P16–P19 ≈ Week 2; P20–P22 ≈ Week 3 |

**Placeholder scan:** no "TBD", "implement later", or unbacked "handle edge cases" remain. Test fixtures for some rules are described by pattern rather than verbatim YAML; that's acceptable here because the pattern is small (~3 lines of YAML) and uniform across rules, but a phase executor should write each fixture explicitly when implementing.

**Type consistency check:**
- `Finding`, `Severity`, `Dimension`, `ParsedRule`, `LintResult` defined once in P2, imported everywhere.
- `RunContext` evolves in three phases (P7, P14, P16): each evolution is an additive field with default `None`, so earlier code keeps working. All `RunContext` fields documented in spec §5.
- `Rule.id`, `Rule.dimension`, `Rule.default_severity` consistent across all rule modules.
- Registry decorator returns the class; every `@register` use matches.

**One known sharp edge:** Phase 20 mutates `r.default_severity` to apply profile overrides. This works in v0.1 because rules are instantiated fresh per CLI invocation, but it's not thread-safe. Noted; concurrent runs aren't a v0.1 requirement.

---

**PR boundaries** (compute via `dependency-resolver.sh`, but expected to land roughly):
- **PR 1 (foundation):** P1–P8 (scaffolding + entire `core/` + scoring) — ~1100 lines
- **PR 2 (data):** P9–P12 (data loaders + vendored fixtures) — ~600 lines + ~10 MB vendored data
- **PR 3 (rules part A):** P13–P15 (schema + attack + metadata = 14 rules) — ~640 lines + fixtures
- **PR 4 (rules part B):** P16–P18 (taxonomy + fp_risk + redundancy + style = 12 rules) — ~640 lines + fixtures
- **PR 5 (reporting + CLI):** P19–P20 — ~560 lines
- **PR 6 (docs + OSS + release):** P21–P22 — mostly markdown + workflows

This keeps each PR under ~700 LOC of code, well within the CASEF 600-line target when markdown and fixtures are excluded.
