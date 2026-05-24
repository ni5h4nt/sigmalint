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
    "attack": 0.22,
    "taxonomy": 0.20,
    "fp_risk": 0.20,
    "metadata": 0.18,
    "redundancy": 0.10,
    "style": 0.10,
}


# Sigma spec versions sigmalint can validate against. v0.1 ships exactly one;
# the key is reserved and accepted in config so v0.2's multi-version support
# does not require a config-schema bump.
SUPPORTED_SIGMA_VERSIONS = ("2.1.0",)
DEFAULT_SIGMA_VERSION = "2.1.0"


@dataclass(frozen=True, slots=True)
class Config:
    profile: str = DEFAULT_PROFILE
    disable: tuple[str, ...] = ()
    enable_only: tuple[str, ...] | None = None
    severities: dict[str, Severity] = field(default_factory=dict)
    dimension_weights: dict[str, float] = field(
        default_factory=lambda: dict(_DEFAULT_DIMENSION_WEIGHTS)
    )
    rule_weights: dict[str, float] = field(default_factory=dict)
    taxonomy: str = "sigma"
    target_sigma_version: str = DEFAULT_SIGMA_VERSION
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
    tsv = d.get("target_sigma_version", DEFAULT_SIGMA_VERSION)
    if tsv not in SUPPORTED_SIGMA_VERSIONS:
        raise ConfigError(
            f"target_sigma_version={tsv!r} not supported by this sigmalint "
            f"release. Supported: {list(SUPPORTED_SIGMA_VERSIONS)}. "
            f"Multi-version support arrives in v0.2."
        )
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
        target_sigma_version=tsv,
        filters_paths=tuple(d.get("filters_paths") or ("filters/**/*.yml",)),
        data_dir=d.get("data_dir", "~/.cache/sigmalint"),
        fail_on=fail_on,
        min_score=d.get("min_score"),
    )
