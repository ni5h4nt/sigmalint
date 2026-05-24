# Versioning Policy

Sigmalint uses semantic versioning (`MAJOR.MINOR.PATCH`).

## What changes at which level

### Patch — `0.X.Y → 0.X.(Y+1)`

- Bug fixes that do not change findings on previously-clean rules.
- Internal refactors.
- Performance improvements.
- Documentation-only changes.
- **Vendored data snapshots** (ATT&CK, SigmaHQ corpus) — these may
  produce new ATK/RED findings; they ship as patches because rule IDs
  and the data refresh mechanism are unchanged.

### Minor — `0.X.Y → 0.(X+1).0`

- New rules (new rule IDs).
- New config keys (additive).
- New CLI commands or flags (additive).
- New output JSON fields (additive — see below).
- Profile changes that *relax* an existing rule's severity.

### Major — `0.X.Y → (X+1).0.0`

- Removed or renamed rule IDs.
- Removed or renamed config keys.
- Removed CLI commands or flags.
- Removed JSON output fields.
- Profile changes that *tighten* a rule above warning by default.
- Sigma spec version bumps that change semantics (Tier 3 — see
  [maintainers.md](./maintainers.md)).

## Rule-ID stability guarantee

A rule ID, once shipped, is a stable identifier. Renaming or repurposing
an existing ID is a major-version break. If a rule is replaced, the old
ID is retired (still parsed, but yields no findings and is documented
as such) for one major cycle.

## Output JSON: additive-only

The JSON output schema is treated as a public API. New fields may be
added in minor releases; removing or repurposing existing fields is a
major-version break. Consumers should ignore unknown fields.

## Pre-1.0 caveat

While the project is `0.x`, breaking changes may still occur in minor
releases when forced by upstream Sigma spec evolution. We will flag
these prominently in `CHANGELOG.md` and provide a one-release migration
window where practical.
