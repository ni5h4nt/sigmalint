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

## Reference-data refreshes

Vendored reference data (MITRE ATT&CK STIX, Sigma JSON schema, modifier
appendix, taxonomy, ATT&CK→logsource map) is refreshed periodically. A
refresh **can change the score** sigmalint emits for an unchanged Sigma
rule. The most common cause is MITRE marking a technique as `revoked`
or `deprecated` — a rule previously emitting no ATT&CK finding now
emits an `ATK002` warning, dropping its quality score by ~3 points.

### Why we ship refreshes as patch releases

Reference-data refreshes are conceptually backwards-compatible: rule
IDs are unchanged, output shape is unchanged, the CLI surface is
unchanged. The only observable shift is the numeric score. Treating
this as a major bump would punish users who *want* fresh data; treating
it as silent would punish users running CI gates on the score.

We split the difference by:

1. **Recording the SigmaHQ-corpus mean-score delta** for every release
   that refreshes reference data. See the "Score impact" subsection in
   `CHANGELOG.md` per release.
2. **Pinning behaviour** — `pip install sigmalint==0.1.0` always loads
   the bundled-data snapshot that shipped with `0.1.0`. The package
   version is sufficient to pin the score for a corpus, provided the
   user does not run `sigmalint update-data` to write a newer copy
   into the user cache.
3. **Per-report `data_versions` block** — every JSON report records
   the exact dataset versions that contributed to the findings. Two
   reports with the same `data_versions` and the same input MUST
   produce the same findings.

### Score-floor stability promise

Within a sigmalint **minor** version (`0.1.x` series), a patch release
that refreshes reference data must not drop the SigmaHQ-corpus mean
score by more than **2.0 points** from the previous patch's baseline.
If a refresh would cause a larger drop, the release becomes a minor
bump (`0.1.x → 0.2.0`) so users can opt in deliberately. Each release's
"Score impact" entry documents the actual delta.

### What users do when a refresh disrupts their CI

1. **Pin the package version.** In `requirements.txt`, `pyproject.toml`,
   or the GitHub Action's `with: version: 0.1.0`, lock to a specific
   sigmalint release. The bundled data is then frozen for that version.
2. **Diff the `data_versions` block** in the new vs old report to see
   exactly which dataset changed.
3. **Adjust `--min-score`** in CI to the new baseline if the drop is
   acceptable.
4. **Disable specific rules** for a legacy corpus via `disable:` in
   `.sigmalintrc.yml` while migrating (e.g. `disable: [ATK002]` to
   ignore newly-revoked techniques for a release cycle).
5. **Refresh the cache deliberately** via `sigmalint update-data` only
   when the user is ready to absorb the change. The package-bundled
   snapshot is never mutated.

### Future direction (v0.2+)

The patterns above are the v0.1 contract. v0.2 plans to add:

- **`.sigmalint-lock.json`** — record exact `data_versions` for a corpus,
  commit it. CI uses the lock; refresh becomes an explicit lockfile
  update (analogous to `package-lock.json`, `Cargo.lock`, `uv.lock`).
- **`sigmalint diff <baseline.json>`** — compare two reports, show
  which findings changed because of data drift vs rule changes.
- **Revoked-technique grace period** — a newly-revoked ATT&CK technique
  starts at `info` severity for the first 90 days, escalating to
  `warning` after, so a fresh MITRE release does not cause an immediate
  CI score crash.
