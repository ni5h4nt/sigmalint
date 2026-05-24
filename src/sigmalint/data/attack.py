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
    def __init__(self, data_dir: Path, version: str | None = None):
        # `version` is reserved for v0.2's multi-version support; v0.1 ignores
        # it for resolution but plumbs it through the API.
        self._requested_version = version
        path = _resolve(data_dir)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise DataLoadError(f"Cannot load ATT&CK bundle from {path}: {e}") from e
        self._techniques: dict[str, dict] = {}
        for obj in doc.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext = next(
                (
                    r
                    for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"
                ),
                None,
            )
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
