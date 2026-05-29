"""Field-name taxonomy + modifier list + ATT&CK->logsource map loaders."""

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
    def __init__(self, data_dir: Path, version: str | None = None):
        # `version` is reserved for v0.3's multi-Sigma-version support.
        self._requested_version = version
        data = _load_yaml(_resolve(data_dir, "fields.yml"))
        self._fields: dict[str, dict[str, set[str]]] = {
            tax: {ls: set(fs) for ls, fs in (entries or {}).items()}
            for tax, entries in (data.get("taxonomies") or {}).items()
        }
        self._aliases: dict[str, dict[str, dict[str, str]]] = data.get("canonical_aliases") or {}

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
        return "sigma@v0.1"


class SigmaModifiers:
    def __init__(self, data_dir: Path, version: str | None = None):
        # `version` is reserved for v0.3's multi-Sigma-version support.
        self._requested_version = version
        data = _load_yaml(_resolve(data_dir, "sigma-modifiers.yml"))
        self._known = set(data.get("modifiers") or [])
        # Track which on-disk source was used so reports can include the
        # modifier-list version under data_versions.modifiers.
        self._file_version = data.get("version")

    def is_known(self, modifier: str) -> bool:
        return modifier in self._known

    @property
    def data_version(self) -> str:
        return self._requested_version or self._file_version or "sigma-2.1.0"


class AttackLogsourceMap:
    def __init__(self, data_dir: Path, version: str | None = None):
        # `version` is reserved for v0.3's multi-version support.
        self._requested_version = version
        data = _load_yaml(_resolve(data_dir, "attack-logsource-map.yml"))
        self._t: dict = data.get("techniques") or {}
        self._version: str = data.get("version", "v0.1")

    @property
    def data_version(self) -> str:
        return self._version

    def plausible(self, technique: str, category: str | None, product: str | None) -> bool:
        entry = self._t.get(technique)
        if not entry:
            return True  # unknown technique -> no signal
        if category and category in (entry.get("categories") or []):
            return True
        return bool(product and product in (entry.get("products") or []))
