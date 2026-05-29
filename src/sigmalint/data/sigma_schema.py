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
    def __init__(self, data_dir: Path, version: str | None = None):
        # v0.1 ships a single Sigma version; the `version` parameter is
        # accepted now so v0.3's multi-version loader does not change the
        # signature. When set, it is recorded in `data_version` to preserve
        # report reproducibility; resolution against versioned vendored
        # bundles arrives in v0.3.
        self._requested_version = version
        path = _resolve(data_dir)
        try:
            self._schema = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise DataLoadError(f"Cannot load Sigma schema from {path}: {e}") from e
        self._path = path

    @property
    def data_version(self) -> str:
        # If a version was requested, that's the canonical answer (used in
        # multi-version mode). Else prefer the schema's own $id/version, else
        # fall back to the vendored baseline.
        return self._requested_version or self._schema.get("version") or VENDORED_VERSION

    def validate(self, data: dict) -> list[str]:
        """Return a list of human-readable error messages (empty if valid)."""
        v = jsonschema.Draft7Validator(self._schema)
        return [
            f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in v.iter_errors(data)
        ]
