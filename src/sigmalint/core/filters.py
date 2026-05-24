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
    """A Sigma Filter file (top-level `filter:` mapping) and its targets.

    Sigma Filters reference rules by either UUID `id` or by the rule's `name`
    field. The `name` field is Sigma's cross-reference identifier, distinct
    from the human-readable `title`. We match against both `name` and `title`
    for pragmatic coverage of corpora that don't yet populate `name`.
    """

    path: str
    targets_ids: tuple[str, ...]    # UUID ids referenced
    targets_names: tuple[str, ...]  # `name` (or `title` fallback) values referenced
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
            names = tuple(
                r for r in rules if isinstance(r, str) and not _is_uuid(r)
            )
            out.append(
                SigmaFilter(
                    path=str(pth),
                    targets_ids=ids,
                    targets_names=names,
                    condition=condition,
                )
            )
    return out


def filters_for_rule(
    filters: list[SigmaFilter],
    rule_id: str | None,
    name: str | None,
    title: str | None,
) -> list[SigmaFilter]:
    """Return filters that reference this rule by id, name, or title.

    Per SigmaHQ filter docs: filters reference rules by id or name. We also
    accept title as a fallback for rules that have no name field, since many
    real-world rules omit it.
    """
    return [
        f
        for f in filters
        if (rule_id and rule_id in f.targets_ids)
        or (name and name in f.targets_names)
        or (title and title in f.targets_names)
    ]
