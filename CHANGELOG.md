# Changelog

All notable changes to sigmalint are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
See `docs/versioning.md` for the full backward-compatibility policy.

## [Unreleased]

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
