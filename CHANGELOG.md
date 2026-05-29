# Changelog

All notable changes to sigmalint are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
See `docs/versioning.md` for the full backward-compatibility policy.

## [Unreleased]

### Added

- **Contrived rule-shape test methodology** (`tests/contrived/`). For
  each rule a manifest-driven distribution of positive, negative, and
  edge fixtures asserts the rule fires the expected number of times on
  each shape. Complements code-coverage tests (which check every line
  was executed) with shape-coverage tests (which check every legal
  input shape was exercised). This patch ships full coverage for the
  taxonomy dimension (TAX001/TAX002/TAX003) - 39 fixtures total. Other
  dimensions follow on a v0.1.x patch cadence: v0.1.3 (FP, META),
  v0.1.4 (ATK, RED, STY), v0.1.5 (SCHEMA). The README Roadmap remains
  the source of truth for v0.2+ scope (additional rule formats,
  expanded FP heuristics, AI-assisted explanations) and v0.3+
  (multi-version Sigma support).

### Fixed

- **TAX001/TAX002/TAX003 walker now traverses list-of-dict selectors.**
  Sigma 2.1.0 allows two selector shapes - `dict` and `list-of-dict` -
  but `_walk_detection_fields` in v0.1.x iterated dict-valued selectors
  only. Taxonomy and modifier defects in list-of-dict-shaped rules
  silently passed. Paper §6.6 acknowledged this as a v0.1.0 coverage
  gap; the contrived shape distribution surfaced it in 5 positive
  fixtures, and the walker fix makes all 39 contrived TAX cases pass.

### Score impact

Per the docs/versioning.md convention for fixes that change finding
counts on previously-clean rules: rules using list-of-dict selectors
with unknown field names were silently passing TAX001 pre-fix and now
correctly fire post-fix.

**SigmaHQ corpus (commit `994da16`, 3,132 rules, sigmahq profile,
ATT&CK v19.1 / Sigma 2.1.0 / taxonomy sigma@v0.1):**

| Metric | v0.1.1 | post-fix | Delta |
|---|---|---|---|
| Mean total score | 99.18 | 99.18 | +0.00 (Δ < 0.0001) |
| Total findings | 2,881 | 2,888 | +7 |
| TAX001 findings | 35 | 42 | +7 |
| TAX002 findings | 1 | 1 | 0 |
| TAX003 findings | 0 | 0 | 0 |

Five SigmaHQ rules with newly-surfaced TAX001 findings (all use
list-of-dict selectors with unknown field names):

- `windows/file/file_event/file_event_win_susp_wdac_policy_creation.yml` (+3)
- `windows/file/file_event/file_event_win_office_macro_files_from_susp_process.yml` (+1)
- `windows/registry/registry_event/registry_event_disable_security_events_logging_adding_reg_key_minint.yml` (+1)
- `windows/registry/registry_event/registry_event_new_dll_added_to_appcertdlls_registry_key.yml` (+1)
- `windows/registry/registry_event/registry_event_new_dll_added_to_appinit_dlls_registry_key.yml` (+1)

The mean-score delta is comfortably within the 2.0-point patch-release
score-floor stability promise documented in docs/versioning.md, so
this releases as a patch.

### Notes for future releases

Every release that refreshes vendored reference data (ATT&CK STIX, Sigma
schema, modifier appendix, taxonomy, ATT&CK→logsource map) must include a
**Score impact** subsection here documenting the mean-score delta against
the SigmaHQ public corpus. The format is:

> **Score impact:** SigmaHQ corpus mean score X.XX → Y.YY (Δ ±Z.ZZ).
> Largest contributors: ...

This is part of the backward-compat contract — see `docs/versioning.md`,
"Reference-data refreshes" section, for why score-drift is a release-note
concern.

## [0.1.1] — 2026-05-24

### Fixed

- `sigmalint explain <ID>` returned `"No documentation for <ID>."` on
  PyPI-installed copies because the per-rule docs at `docs/rules/` were
  not bundled into the wheel. The command now reads the docs from a
  wheel-bundled `sigmalint/rule_docs/` directory (via Hatchling
  `force-include`) with a fallback to the dev-tree `docs/rules/` path
  so editable installs continue to work. Only `sigmalint explain` was
  affected; `lint`, `list-rules`, `profiles`, and the GitHub Action
  worked correctly in 0.1.0.

## [0.1.0] — 2026-05-23

### Added

- Validity gate against Sigma 2.1.0 JSON schema (`SCHEMA001`–`SCHEMA004`).
- Six quality dimensions with 22 quality rules:
  - **attack** (4): `ATK001` valid technique, `ATK002` not revoked, `ATK003` logsource plausibility, `ATK004` sub-technique specificity
  - **taxonomy** (3): `TAX001` known fields, `TAX002` modifier spelling, `TAX003` canonical field aliases
  - **fp_risk** (4): `FP001` single broad selection, `FP002` prefer modifiers, `FP003` no filter on noisy sources, `FP004` hardcoded literals
  - **metadata** (6): `META001a` id presence, `META001b` UUIDv4 validity, `META002` core fields populated, `META003` references for high/critical, `META004` realistic falsepositives, `META005` status vocabulary
  - **redundancy** (2): `RED001` near-duplicate fingerprint, `RED002` title/id collision
  - **style** (3): `STY001` lowercase top-level keys, `STY002` LF and `.yml` extension, `STY003` four-space indent
- Three built-in profiles: `strict`, `sigmahq` (default), `local`.
- Sigma condition grammar parser (boolean ops, parens, negation, `1/all of <pattern>`, `1/all of them`, list-valued conditions).
- Sigma Filters discovery via `filters_paths` config glob.
- Cache-then-vendored data resolution for ATT&CK STIX (`v19.1`), Sigma JSON schema (`v2.1.0`), modifier appendix (Sigma 2.1.0), field taxonomy (`sigma@v0.1`), ATT&CK→logsource map (`v0.1`).
- `sigmalint update-data` command for cache refresh, never mutating the installed package.
- Output formats: `text`, `json`, `sarif` (2.1.0), `github` (workflow annotations).
- CLI subcommands: `lint`, `list-rules`, `explain`, `profiles`, `update-data`.
- Reserved `target_sigma_version` config key for v0.2 multi-Sigma-version support.
- Inline suppression via `# sigmalint: disable=RULE_ID` comments.
- Per-finding line/col extracted from ruamel.yaml CommentedMap positions.

### Documentation

- Per-rule pages under `docs/rules/<ID>.md` surfaced by `sigmalint explain <ID>`.
- Concept docs: `scoring`, `configuration`, `profiles`, `architecture`, `versioning`, `maintainers`.
- Contributing guide centered on the rule-authoring workflow.

### Score impact (baseline)

Initial release; no prior baseline to compare against. The SigmaHQ public
corpus (3,132 rules) lints cleanly at **mean score 99.61** with 0 errors,
1,384 warnings, and 2,543 info findings. This is the baseline that future
reference-data refreshes will be compared against in the "Score impact"
subsection of each release.

[Unreleased]: https://github.com/ni5h4nt/sigmalint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ni5h4nt/sigmalint/releases/tag/v0.1.0
