# Changelog

All notable changes to sigmalint are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
See `docs/versioning.md` for the full backward-compatibility policy.

## [Unreleased]

## [0.1.5] — 2026-06-27

### Added

- **Contrived shape coverage for the SCHEMA dimension**
  (SCHEMA001-004) under `tests/contrived/`, completing the v0.1.x
  contrived rollout (TAX shipped in v0.1.2; FP + META in v0.1.3;
  ATK + RED + STY in v0.1.4). 34 fixtures total: 8 SCHEMA001, 7 SCHEMA002,
  8 SCHEMA003, 11 SCHEMA004. The contrived harness gained two test-side
  extensions: it builds the bundled Sigma 2.1.0 schema via the
  vendored-fallback `SigmaSchema` (mirroring the pinned-ATT&CK pattern) and
  passes it through `RunContext` so SCHEMA002 validates deterministically
  without a cloned data dir, and it special-cases the runner-emitted
  SCHEMA001 (which has no `Rule` class) by linting with an empty rules list
  so the malformed-YAML fixtures exercise the parse-error path. The
  SCHEMA001 fixtures also document that the runner rejects a non-mapping
  YAML root ("root must be a mapping").

## [0.1.4] — 2026-06-21

### Added

- **Contrived shape coverage for the ATT&CK, redundancy, and style
  dimensions** (ATK001-004, RED001-002, STY001-003) under
  `tests/contrived/`. 67 fixtures total: 9 ATK001, 6 ATK002, 7 ATK003,
  8 ATK004, 8 RED001, 8 RED002, 7 STY001, 6 STY002, 8 STY003. Closes the
  v0.1.x contrived rollout for ATK + RED + STY (TAX shipped in v0.1.2;
  FP + META in v0.1.3); v0.1.5 adds SCHEMA. The contrived harness gained
  two test-side context extensions, both reusing the v0.1.3 `filters:`
  pattern: the `attack`/`attack_logsource` providers are now populated
  from the pinned vendored ATT&CK bundle (v19.1) so ATK001-003 can be
  exercised deterministically, and an optional per-case `corpus:` field
  materialises a duck-typed fake `RuleCorpus` (declaring `near_duplicates`
  and `entries`) so RED001/002 can be exercised without cloning SigmaHQ.

### Fixed

- **STY002 now detects CRLF line endings.** The runner read rule files
  with `Path.read_text()`, which opens in universal-newline mode and
  translates `\r\n` to `\n` before the text reaches `parsed.raw_text`.
  STY002's `"\r\n" in raw_text` check was therefore dead code that could
  never fire on a real file. Switched `_parse_file` to
  `path.read_bytes().decode("utf-8", errors="replace")` so line endings
  reach raw-text rules intact; YAML parsing tolerates CRLF unchanged. A
  reader-class gap analogous to the TAX/FP list-of-dict walker gaps of
  prior releases, surfaced by the new STY002 contrived shape coverage.
  Score impact on the SigmaHQ corpus (3,370 rules): +1 INFO finding
  (the single CRLF rule now triggers STY002), mean-score Δ 0.00.

## [0.1.3] — 2026-06-01

### Added

- **Contrived shape coverage for the false-positive-risk dimension**
  (FP001 + FP002 + FP003 + FP004) under `tests/contrived/`. 49
  fixtures total: 14 each for FP001 and FP002, 11 for FP003, 10 for
  FP004. Documents all four rules' behaviour across dict, list-of-dict,
  condition-AST, raw-text-regex, single-branch, multi-branch,
  modifier-bearing, and edge shapes. The contrived test loader gained
  a `filters:` manifest field that materialises `SigmaFilter` dataclass
  instances in-process so FP003's external-Sigma-Filter path can be
  exercised without writing real filter YAML files. Part of the v0.1.x
  contrived-rollout (TAX shipped in v0.1.2; META002-005 next in v0.1.3
  patch series).
- **Contrived shape coverage for the metadata id rules** (META001a +
  META001b). 18 fixtures: 8 for META001a (4 positives, 3 negatives,
  1 edge) and 10 for META001b (7 positives at mixed severities,
  3 negatives). The contrived test loader gained an optional
  `expect_severity:` manifest field that asserts each finding's
  severity matches the declared value, used to lock in META001b's
  ERROR-vs-WARNING split that depends on whether the id parses as
  a UUID at all.
- **Contrived shape coverage for the metadata content rules**
  (META002 + META003 + META004 + META005). 51 fixtures: 11 for
  META002, 13 for META003, 12 for META004, 15 for META005.
  Documents per-field missing-vs-empty behaviour for META002,
  level-gated reference requirements for META003, the
  false-positives `Unknown` magic-string casing for META004, and
  the Sigma 2.1.0 status vocabulary for META005. Closes the v0.1.x
  contrived rollout for the FP and META dimensions; v0.1.4 will add
  ATK, RED, and STY; v0.1.5 SCHEMA.

### Fixed

- **META005 no longer crashes on non-string status values.** A list-
  or dict-valued `status:` would trip `status not in VALID_STATUS`
  with a `TypeError: unhashable type` which the runner converted to
  an opaque `INTERNAL001` finding rather than a clean META005. Added
  an `isinstance(status, str)` guard so non-string status now fires
  a regular META005 warning. No SigmaHQ corpus rule was triggering
  the crash; this is a defensive fix surfaced by the contrived
  shape coverage in `tests/contrived/META005/edge_status_list.yml`.
- **FP001 and FP002 walker traverses list-of-dict selectors.** Both
  rules used `_selectors()` which filtered out list-of-dict selectors,
  the same walker-class gap that TAX001/2/3 had in v0.1.2 (paper §6.6).
  Switched to `_selectors_iter()` returning `Iterable[tuple[str, dict]]`
  so list-of-dict yields one (name, body) tuple per dict member,
  preserving OR-branch semantics:

  - FP001 now uses both `distinct_names` and tuple count to recognise
    "single broad selection": list-of-dict with exactly one item is
    a single OR branch and fires; list-of-dict with N>1 items is
    multi-branch and does not fire.
  - FP002 iterates per-tuple so duplicate wildcards across OR-branches
    each warrant their own modifier suggestion.

### Score impact

SigmaHQ corpus (commit `994da16`, 3,132 rules, sigmahq profile,
ATT&CK v19.1 / Sigma 2.1.0 / taxonomy sigma@v0.1):

| Metric | v0.1.2 | post-fix | Δ |
|---|---|---|---|
| Mean total score | 99.1800 | 99.1900 | **+0.0100** |
| Total findings | 2,888 | 2,864 | -24 |
| FP001 findings | 38 | 13 | **-25** (false positives removed) |
| FP002 findings | 30 | 31 | **+1** (true positive surfaced) |

The -25 FP001 delta is the noteworthy direction-change: pre-fix the
walker silently dropped list-of-dict filter selectors, causing FP001
to wrongly conclude rules with a dict `selection` plus a list-of-dict
`filter` were "single broad selection" (because the filter wasn't
counted). Post-fix the walker sees both, recognises >1 distinct
selector, and correctly does not fire. 25 SigmaHQ rules' false-positive
FP001 findings dissolve as a result; mean score moves +0.0100 instead
of dropping. Within the 2.0-point patch-release stability promise per
`docs/versioning.md`.

## [0.1.2] — 2026-06-01

### Added

- **Contrived rule-shape test methodology** (`tests/contrived/`). For
  each rule a manifest-driven distribution of positive, negative, and
  edge fixtures asserts the rule fires the expected number of times on
  each shape. Complements code-coverage tests (which check every line
  was executed) with shape-coverage tests (which check every legal
  input shape was exercised). This patch ships full coverage for the
  taxonomy dimension (TAX001/TAX002/TAX003) - 41 fixtures total. Other
  dimensions follow on a v0.1.x patch cadence: v0.1.3 (FP, META),
  v0.1.4 (ATK, RED, STY), v0.1.5 (SCHEMA). The README Roadmap remains
  the source of truth for v0.2+ scope (additional rule formats,
  expanded FP heuristics, AI-assisted explanations) and v0.3+
  (multi-version Sigma support).
- **Zenodo DOI** for citation: concept DOI
  [`10.5281/zenodo.20371168`](https://doi.org/10.5281/zenodo.20371168)
  always resolves to the latest archived version; versioned DOI
  `10.5281/zenodo.20371169` pins to v0.1.1 specifically. README badge
  + Citation section + `CITATION.cff` `identifiers` block point at
  both. Future releases auto-deposit via the new `.zenodo.json`
  metadata file (sets title, description, creators with ORCID,
  license, keywords, related identifiers — overrides Zenodo's
  defaults that would otherwise use release notes as the abstract).

### Changed

- **Multi-Sigma-version target aligned with README Roadmap.** Inline
  comments in the example config (`README.md` Configuration block,
  `.sigmalintrc.example.yml`), three internal source-code comments
  (`config.py`, `taxonomy.py`, `attack.py`, `sigma_schema.py`), and
  one externally-observable `ConfigError` message ("Multi-version
  support arrives in v0.3.") moved from `v0.2` to `v0.3` to match
  the canonical Roadmap statement. v0.2 ships rule-format expansion;
  multi-Sigma-version support is v0.3 scope.

### Fixed

- **TAX001/TAX002/TAX003 walker now traverses list-of-dict selectors.**
  Sigma 2.1.0 allows two selector shapes - `dict` and `list-of-dict` -
  but `_walk_detection_fields` in v0.1.x iterated dict-valued selectors
  only. Taxonomy and modifier defects in list-of-dict-shaped rules
  silently passed. Paper §6.6 acknowledged this as a v0.1.0 coverage
  gap; the contrived shape distribution surfaced it in 5 positive
  fixtures, and the walker fix makes all 41 contrived TAX cases pass.

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
