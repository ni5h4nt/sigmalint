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

import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml


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
                text=True,
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
            entries.append(
                CorpusEntry(
                    path=str(p),
                    title=str(doc.get("title", "")),
                    id=doc.get("id"),
                    fingerprint=tokens,
                )
            )
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

    def near_duplicates(
        self, fingerprint: frozenset[str], threshold: float = 0.85
    ) -> list[CorpusEntry]:
        return [e for e in self.entries() if self.jaccard(e.fingerprint, fingerprint) >= threshold]


def fingerprint_for_rule(data: dict) -> frozenset[str]:
    return frozenset(_canonical_tokens(data.get("detection") or {}))
