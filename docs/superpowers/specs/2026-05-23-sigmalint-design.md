# sigmalint v0.1 — Design Spec

**Date:** 2026-05-23 (revised same day to address spec-review findings)
**Status:** Approved (brainstorming complete; awaiting plan)
**Author:** Nishant Tyagi
**Scope:** v0.1.0 release, three-week build.
**Target Sigma specification:** v2.1.0 (2025-08-02).

---

## 1. Purpose

A command-line linter for Sigma detection rules. Given a Sigma YAML file (or directory of files), `sigmalint` emits ESLint-shaped findings, gates each rule on Sigma-2.1.0 validity (a hard pass/fail), and — for valid rules — derives a quality score across six quality dimensions: MITRE ATT&CK alignment, field-name correctness against the Sigma taxonomy, false-positive risk, metadata completeness, redundancy with the public SigmaHQ corpus, and Sigma interoperability style.

This repository is the reference implementation cited by the author's SoK paper on detection-rule quality assessment.

## 2. Goals and non-goals

### Goals
- Ship a `pip install`-able CLI tool in three weeks.
- Findings-first output model — each finding carries a stable, citable rule ID.
- Score derived from findings via configurable per-dimension weights.
- Composite GitHub Action so detection teams can adopt in CI with three lines of YAML.
- Built-in rule catalog of 26 rules across 7 dimensions (1 validity + 6 quality).
- Plugin-shaped internal architecture so external rule packages are possible post-v0.1 (no plugin loading shipped in v0.1).

### Non-goals (v0.1)
- Cross-SIEM translation (Splunk, Sentinel, Elastic). Out of scope; conflicts with author's patent portfolio.
- Generating new detection rules. This is a quality assessor, not a rule author.
- External plugin loading. Architecture supports it; the loader is deferred.
- Auto-fix. Findings include `fix_hint` text only; no in-place edits.
- Signed releases, SLSA provenance, public roadmap, governance docs.

## 3. Key decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | New repo `sigmalint` | Clean MIT history; portfolio-grade; no scaffold baggage. |
| 2 | Bundled pinned MITRE ATT&CK STIX baseline; cache-refreshable overrides via `sigmalint update-data` (writes only to user cache, never the installed package) | Deterministic default, offline-capable, CI-friendly; supports newer-than-baseline data without mutating the wheel. |
| 3 | Bundled pinned Sigma JSON schema baseline; cache-refreshable override; on-demand SigmaHQ corpus clone for redundancy (user cache only) | Fast deterministic core; heavy and mutable data lives in `data_dir`, not the package. |
| 4 | Findings-first output; score is derived | Actionable, matches detection-engineer mental model, CI-friendly. |
| 5 | Plugin-style rule registry (decorator-based) | Per-rule enable/disable, stable IDs, future extensibility for ~50 LOC overhead. |
| 6 | Python 3.10+ | Pattern matching, modern type hints, broad install reach. |
| 7 | Composite GitHub Action wrapping `pip install` | Minimal YAML, fast warm cache, version-pinned via marketplace tag. |
| 8 | All four FP heuristics in v0.1 | FP001 (broad selection), FP002 (unanchored wildcards), FP003 (no filter on noisy sources), FP004 (env-specific literals). |

## 4. Architecture

A small Python package with strict layering. `core/` holds the rule framework, runner, and scoring logic and has zero internal-module dependencies. `data/` owns reference data (Sigma JSON schema, MITRE ATT&CK STIX bundle, taxonomy field list) and exposes loader functions. `rules/` contains one module per dimension; each registers `Rule` subclasses at import time. `cli/` is the Typer-based entry point and the only module that imports `rules/` — importing `rules/` is what triggers rule registration. `reporting/` formats output (text, json, sarif, github).

The runner is rule-agnostic: `Runner.lint(paths, rules, ctx)` accepts the iterable of enabled rules as an argument. This keeps `core/` decoupled from `rules/` and preserves the import-linter contract.

Strict layering enforced by `import-linter` in CI:
- `core/` may not import from any other sigmalint module.
- `data/` may import from `core/`.
- `rules/` may import from `core/` and `data/`.
- `reporting/` may import from `core/` only (works on the canonical JSON shape).
- `cli/` is the only module that may import from `rules/`; it composes everything.

**Vendored data write model.** The package ships pinned reference data under `src/sigmalint/data/vendored/` — read-only, ships in the wheel, never mutated by `update-data`. The loaders prefer a freshly-refreshed copy in the user cache (`data_dir`, default `~/.cache/sigmalint/<version>/`) if present and newer, else fall back to the vendored copy. `sigmalint update-data` writes only to the user cache. Output records `data_versions` for every dataset consulted so a score is reproducible.

Runtime deps: `pyyaml`, `ruamel.yaml` (line/col tracking), `jsonschema`, `typer`, `rich`, `requests` (`update-data` + corpus fetch), `pyparsing` (Sigma condition grammar).

## 5. Components

| Component | Responsibility | Depends on |
|---|---|---|
| `core.rule.Rule` | Abstract base. Declares `id`, `dimension`, `severity`, `default_weight`, `profiles`, `check(parsed_rule, ctx) -> Iterable[Finding]` | nothing |
| `core.registry.Registry` | Module-level singleton. `@register` decorator. `all_rules()`, `enabled(config)` | nothing |
| `core.runner.Runner` | `lint(paths, rules, ctx) -> list[LintResult]`. Rule-agnostic: receives the enabled rules from the caller. Parses YAML via `ruamel.yaml`. | core |
| `core.condition.ConditionParser` | `pyparsing`-based grammar for Sigma `detection.condition`: boolean ops, parens, negation, `1/all of <pattern>`, `1/all of them`, list-valued conditions, underscore-prefixed selector exclusion. Returns an AST consumed by SCHEMA004 and the FP/redundancy checks. | pyparsing |
| `core.scoring.Scorer` | `LintResult → ScoredReport`. Two-layer: if SCHEMA dimension has any error, total score is `null` and `status: "invalid"`; otherwise compute per-dimension quality scores and weighted total. | core |
| `core.config.Config` | Loads `.sigmalintrc.yml` (profile selection, per-rule enable/disable, weight overrides, severity overrides, data_dir) | nothing |
| `core.profiles` | Built-in profiles: `strict`, `sigmahq`, `local`. Maps rule IDs to severity per profile. | nothing |
| `core.errors` | `SigmalintError` → `ConfigError`, `DataLoadError`, `RuleCheckError` | nothing |
| `data.attack.AttackTaxonomy` | Loads STIX (cache-then-vendored). `is_valid_technique(id)`, `is_revoked(id)`, `is_subtechnique(id)`, `data_version()` | jsonschema |
| `data.sigma_schema.SigmaSchema` | Loads Sigma JSON schema, exposes `validate(parsed)`, `data_version()` | jsonschema |
| `data.taxonomy.SigmaTaxonomy` | Loads the field-name taxonomy. Supports `taxonomy: sigma` (default) and named custom taxonomies. Exposes `field_for(logsource, field)` and `is_known(taxonomy, logsource, field)`. | nothing |
| `data.corpus.RuleCorpus` | Lazy SigmaHQ clone+index for redundancy. Semantically-canonicalized fingerprint index (selector-name-agnostic, modifier-aware, AND/OR-aware). | requests, git |
| `rules.schema`, `rules.attack`, `rules.taxonomy`, `rules.fp_risk`, `rules.redundancy`, `rules.metadata`, `rules.style` | One module per dimension; each registers its rules at import | core, data |
| `cli.main` | Typer commands: `lint`, `update-data`, `explain <rule_id>`, `list-rules`, `profiles`. Imports `rules/` to trigger registration. | core, data, rules, rich |
| `reporting.text` / `.json` / `.sarif` / `.github` | Output formatters | rich |

## 6. Data flow

```
input paths (CLI args)
      │
      ▼
load .sigmalintrc.yml ──► Config
      │
      ▼
for each *.yml file:
   read+parse YAML  ──► (ParsedRule | YAMLError finding)
        │
        ▼
   Registry.enabled(config) → list[Rule]
        │
        ▼
   for each Rule: rule.check(parsed, ctx) → list[Finding]
        │  (ctx carries AttackTaxonomy, SigmaSchema, SigmaTaxonomy, RuleCorpus)
        ▼
   LintResult(file, parsed, findings)
      │
      ▼
Scorer(results, config.weights) → ScoredReport
      │
      ▼
Formatter (text/json/sarif/github) → stdout / file
      │
      ▼
exit code per --fail-on / --min-score policy
```

`Finding` is a frozen dataclass: `rule_id, dimension, severity, message, file, line, col, fix_hint`. `ParsedRule` carries the YAML node tree with line/col preserved via `ruamel.yaml`.

## 7. Rule catalog (v0.1)

Two-layer model. **Schema rules** (`SCHEMA###`) are strict Sigma-2.1.0 validity checks: a rule that fails any schema check is reported `status: "invalid"` and receives no quality score. **Quality rules** layer on top across six quality dimensions. Severities shown are defaults; profiles (§9) override per-rule.

### Validity gate

| ID | Severity | Check |
|---|---|---|
| `SCHEMA001` | error | YAML parses (no syntax errors). |
| `SCHEMA002` | error | Validates against the bundled Sigma JSON schema (v2.1.0). |
| `SCHEMA003` | error | Required top-level keys present (`title`, `logsource`, `detection`); required nested key `detection.condition` present. |
| `SCHEMA004` | error | `detection.condition` parses cleanly via the Sigma condition grammar (boolean ops, parens, negation, `1/all of <pattern>`, `1/all of them`, list-valued conditions, underscore-prefixed selector exclusion) AND every selector referenced exists in `detection` (wildcard patterns expanded). |

### Quality dimensions

| ID | Dimension | Severity | Check |
|---|---|---|---|
| `ATK001` | attack | error | Every tag matching `attack.t<NNNN>(.<NNN>)?` resolves to a known technique ID. Non-technique `attack.*` tags (tactics, groups, software) are ignored by this rule. |
| `ATK002` | attack | warning | No technique tag references a revoked or deprecated technique. |
| `ATK003` | attack | info | `logsource.category/product` is plausible for cited techniques per a versioned lookup table. Documented as a weak signal. |
| `ATK004` | attack | info | Sub-technique vs. parent specificity — flag rules tagged with parents where a specific sub-technique would be more appropriate (heuristic on `detection.condition` content). |
| `TAX001` | taxonomy | warning | All `detection` field names are known in the configured taxonomy for the declared `logsource`. Configured taxonomy defaults to `sigma` (settable via the rule's `taxonomy:` attribute or `.sigmalintrc.yml`). Unknown fields produce a warning, not an error, because Sigma permits log-source-specific fields. |
| `TAX002` | taxonomy | warning | Field-name modifiers are spelled correctly. The accepted modifier set is sourced from the **Sigma 2.1.0 Modifiers Appendix** and shipped as a fixture (`src/sigmalint/data/vendored/sigma-modifiers.yml`) so the list is generated/fixture-backed rather than hand-maintained. Refreshable via `sigmalint update-data` like other reference data. |
| `TAX003` | taxonomy | info | Preferred canonical field used over known aliases (e.g., `Image` over `ImagePath`). |
| `FP001` | fp_risk | warning | Single-selection rule on a common field/value with no negated/filter selector referenced in `detection.condition`. |
| `FP002` | fp_risk | info | Prefer modifiers (`\|contains`, `\|startswith`, `\|endswith`) over raw leading/trailing wildcards when semantically equivalent. |
| `FP003` | fp_risk | warning | Noisy log source (e.g., `process_creation`) with no negated filter selector in `detection.condition`. Recognizes in-file filters (`filter`, `filter_*`, grouped filter constructs) AND Sigma Filters — separate YAML files of `kind: filter` that reference a rule by `id` and append exclusion conditions during conversion. Sigma-Filter discovery is config-driven: `.sigmalintrc.yml` accepts a `filters_paths: [<glob>, ...]` list (default `["filters/**/*.yml"]`); each linted rule joins its referencing filters' conditions for the FP003 evaluation. Does NOT treat the `falsepositives:` metadata field as a filter. |
| `FP004` | fp_risk | info | Hardcoded environment-specific literals (drive letters with usernames, specific hostnames, MAC/IP fragments). |
| `RED001` | redundancy | info | Semantically-canonicalized detection fingerprint matches an existing SigmaHQ rule (Jaccard ≥ 0.85). Canonicalization: selector names dropped, AND/OR structure preserved, modifiers normalized, condition wildcards expanded. v0.1 is best-effort; documented as a near-duplicate hint, not a definitive match. |
| `RED002` | redundancy | info | Title or `id` collides with a public SigmaHQ rule. |
| `META001a` | metadata | warning | `id` is present. (Sigma marks `id` optional but strongly recommended for public sharing — severity is `warning` under the `sigmahq` profile, `info` under `local`, `error` under `strict`.) |
| `META001b` | metadata | error | If `id` is present, it is a valid UUIDv4. |
| `META002` | metadata | warning | `author`, `date`, `description`, `level` populated (per-field severity tunable by profile; all optional per Sigma spec, treated as quality signal). |
| `META003` | metadata | warning | `references:` non-empty when `level` ∈ {high, critical}. `sigmahq` profile only. |
| `META004` | metadata | info | `falsepositives:` non-empty and not literally the string "Unknown". |
| `META005` | metadata | warning | If `status` is present, its value is one of {`stable`, `test`, `experimental`, `deprecated`, `unsupported`}. Older wordings like "in-development", "in-testing", "ready" are flagged. |
| `STY001` | style | info | Top-level keys are lowercase. |
| `STY002` | style | info | File uses LF line endings and `.yml` extension (not `.yaml`). |
| `STY003` | style | info | 4-space indentation throughout. |

Total: 26 rules across 7 dimensions (1 validity dimension + 6 quality dimensions). Plus the synthetic `INTERNAL001` (severity: error) emitted by the runner when a rule's `check()` raises.

## 8. Scoring model

**Validity gate.** If any `SCHEMA###` rule emits an `error` finding for a file, that file is reported as `status: "invalid"` and receives no quality score (`total: null`, per-dimension scores omitted). The reporter still lists all schema findings so the author can fix them.

**Quality scoring** (only when validity gate passes):

- **Severity → base weight:** `error=10`, `warning=3`, `info=1`.
- **Per-finding penalty:** `severity_weight × rule.default_weight` (default 1.0).
- **Per-dimension score:** `max(0, 100 − Σ penalties in dimension)`.
- **Total score:** `Σ(dimension_weight × dimension_score)` over the six quality dimensions.

Default dimension weights (sum to 1.0):

| Dimension | Default weight |
|---|---|
| attack | 0.22 |
| taxonomy | 0.20 |
| fp_risk | 0.20 |
| metadata | 0.18 |
| redundancy | 0.10 |
| style | 0.10 |

Users override via `.sigmalintrc.yml`. Disabling a dimension drops it and remaining weights renormalize. Profiles set sensible defaults (§9). Documented in `docs/scoring.md`.

## 9. Profiles

Three built-in profiles tune the rule set for different use cases. A profile maps rule IDs to severity (or disables them outright). Users select a profile in `.sigmalintrc.yml` and may override individual rules.

| Profile | Intent | Notable settings |
|---|---|---|
| `strict` | Maximum policy enforcement; treats every quality signal as actionable. | `META001a` = error; all warnings stay warnings; `STY*` stay info but contribute to score. |
| `sigmahq` (default) | Match SigmaHQ submission expectations: id required (warning), references required for high/critical, status must be a known value. | `META001a` = warning; `META003` enabled; `META005` enabled. |
| `local` | Internal corpus where ids/authors aren't shared and naming conventions are organization-specific. | `META001a` = info; `META003`, `RED001`, `RED002` disabled; `TAX003` disabled. |

Profiles are pure data (`core.profiles`), defined as `{rule_id: severity_or_None}` maps. Adding a new profile in v0.1 is a 10-line PR.

## 10. Configuration

`.sigmalintrc.yml` schema (all optional):

```yaml
profile: sigmahq                     # strict | sigmahq | local (default: sigmahq)
disable: [RED001, RED002]            # rule IDs to skip (overrides profile)
enable_only: null                    # if set, only these run
severities:                          # per-rule severity overrides (overrides profile)
  TAX003: warning
weights:
  dimensions:                        # override default dimension weights
    redundancy: 0.10
  rules:                             # per-rule default_weight multiplier
    FP003: 2.0
taxonomy: sigma                      # sigma | <custom-name>
filters_paths:                       # globs for Sigma Filter files (kind: filter)
  - filters/**/*.yml
data_dir: ~/.cache/sigmalint         # corpus + STIX cache location (writable)
fail_on: error                       # error | warning | never
min_score: null                      # numeric or null
```

In-line suppression: `# sigmalint: disable=FP003` as a YAML comment on the offending line or block. Suppressions are emitted in the report under `suppressions:` so reviewers can spot them.

## 11. CLI

| Command | Behavior |
|---|---|
| `sigmalint lint <paths...>` | Lint one or more files/dirs. Honors `--format`, `--fail-on`, `--min-score`, `--config`, `--profile`, `--disable`, `--enable-only`. |
| `sigmalint list-rules` | Print all built-in rules with ID, dimension, severity (under the active profile), one-line summary. |
| `sigmalint explain <rule_id>` | Print full documentation for a rule (sourced from `docs/rules/<id>.md`). |
| `sigmalint profiles` | List built-in profiles and the effective rule severities under each. |
| `sigmalint update-data` | Refresh ATT&CK STIX and Sigma schema into the user cache (`data_dir`); with `--corpus` also clones SigmaHQ. **Never** mutates files inside the installed package. |
| `sigmalint --version` | Print version. |

Exit codes: `0` clean, `1` findings above threshold or score below threshold, `2` user error, `3` data load error, `>3` internal bug (uncaught exception).

## 12. Output shape (canonical JSON)

```json
{
  "sigmalint_version": "0.1.0",
  "profile": "sigmahq",
  "data_versions": {
    "sigma_schema": "2.1.0",
    "attack": "16.1",
    "taxonomy": "sigma@2025-08-02",
    "corpus": null
  },
  "files": [
    {
      "path": "rules/win_susp_foo.yml",
      "rule_title": "Suspicious Foo",
      "status": "valid",
      "findings": [
        {"rule_id":"FP003","dimension":"fp_risk","severity":"warning",
         "message":"process_creation rule has no negated filter selector in detection.condition",
         "line":12,"col":3,
         "fix_hint":"Add a filter selector and exclude it in the condition, e.g. `selection and not filter_known_admin`"}
      ],
      "suppressions": [],
      "scores": {"attack":97,"taxonomy":100,"fp_risk":91,"metadata":94,"redundancy":100,"style":100,"total":95.8}
    },
    {
      "path": "rules/broken.yml",
      "rule_title": null,
      "status": "invalid",
      "findings": [
        {"rule_id":"SCHEMA002","dimension":"schema","severity":"error",
         "message":"missing required property 'detection'","line":1,"col":1,"fix_hint":"Add a 'detection:' block."}
      ],
      "suppressions": [],
      "scores": null
    }
  ],
  "summary": {
    "files": 2, "valid": 1, "invalid": 1,
    "findings": 2, "by_severity": {"error":1,"warning":1,"info":0},
    "mean_score": 95.8
  }
}
```

`text`, `sarif`, and `github` formatters all render from this same shape. The `github` formatter additionally emits `::warning file=…,line=…::…` workflow commands so findings annotate PRs inline. The `mean_score` summary is computed only over files with `status: "valid"`.

## 13. Error handling

Three categories:
1. **User errors** (bad input, malformed config, unknown rule ID): stderr message with file/line if available, exit 2. No partial report.
2. **Rule check errors** (a `Rule.check()` raises): caught by runner; converted into a synthetic `INTERNAL001` error finding against the offending file; traceback hidden unless `--debug`. One bad rule never aborts a multi-file run.
3. **Data load errors** (STIX missing, schema unreadable): fail fast with "run `sigmalint update-data`" message, exit 3.

Custom exception hierarchy in `core.errors`. CLI catches `SigmalintError` at the top level and maps to exit codes; anything else unwinds normally (it's a bug).

## 14. Testing strategy

| Layer | Target | Tooling |
|---|---|---|
| Unit per rule | 100% branch on `Rule.check()` | pytest, parametrized fixtures |
| Unit (scoring, config, registry) | 95%+ line | pytest |
| Integration (runner end-to-end) | Golden-file tests on ~20 hand-curated Sigma rules covering pass/fail per rule ID across all three profiles | pytest + JSON diff |
| Condition parser | Property-based tests on the Sigma condition grammar (round-trip a sampled grammar, reject malformed strings) | pytest + hypothesis |
| CLI smoke | `lint`, `list-rules`, `explain`, `profiles`, `update-data --dry-run`, exit codes | `typer.testing.CliRunner` |
| Fuzz (optional) | 50 random valid + malformed YAMLs per CI run, must not crash | hypothesis behind `--with-fuzz` |

Each rule: `tests/fixtures/<rule_id>/{pass.yml,fail.yml}` + one parametrize entry. Adding a rule = rule class + 2 fixtures + 1 line in the parametrize list + 1 doc file. That's the contract enforced by the PR template.

Overall coverage gate: `--cov-fail-under=90`.

## 15. Project layout

```
sigmalint/
├── README.md
├── LICENSE                    # MIT
├── CONTRIBUTING.md            # includes rule-authoring guide
├── CODE_OF_CONDUCT.md         # Contributor Covenant 2.1
├── SECURITY.md                # private disclosure process
├── CHANGELOG.md               # Keep a Changelog format
├── CITATION.cff               # ties to SoK paper
├── CODEOWNERS
├── pyproject.toml             # PEP 621, hatchling backend
├── .sigmalintrc.example.yml
├── .pre-commit-config.yaml
├── .editorconfig
├── .gitignore
├── action.yml                 # GitHub composite action
├── src/sigmalint/
│   ├── __init__.py
│   ├── core/
│   ├── data/
│   │   └── vendored/          # enterprise-attack.json, sigma-schema.json, fields.yml, attack-logsource-map.yml
│   ├── rules/                 # schema.py, attack.py, taxonomy.py, fp_risk.py, redundancy.py, metadata.py, style.py
│   ├── reporting/
│   └── cli/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   └── conftest.py
├── docs/
│   ├── rules/                 # one .md per rule ID; surfaced by `sigmalint explain`
│   ├── scoring.md
│   ├── configuration.md
│   ├── architecture.md
│   └── maintainers.md         # branch protection, release process
└── .github/
    ├── dependabot.yml
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.yml
    │   ├── feature_request.yml
    │   └── new_rule_proposal.yml
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        ├── ci.yml
        ├── release.yml
        └── self-lint.yml
```

## 16. CI and release

- **`ci.yml`** — matrix on Python 3.10–3.13: `ruff check`, `ruff format --check`, `mypy --strict`, `pytest --cov=sigmalint --cov-fail-under=90`, `import-linter`. Codecov upload on main. Required for merge.
- **`release.yml`** — triggers on `v*` tags: builds wheel + sdist, publishes to PyPI via OIDC trusted publishing.
- **`self-lint.yml`** — nightly cron: clones SigmaHQ, runs `sigmalint lint` over the corpus, opens an issue if mean score drops >2 points week-over-week.
- **`action.yml`** — composite action; inputs `path`, `format` (default `github`), `fail-on`, `min-score`. Steps: setup-python → `pip install sigmalint==<action-tag>` (action major/minor pins to the released package version) → `sigmalint lint ...`. Published to GitHub Marketplace at v0.1.0.

## 17. Open-source readiness checklist

In v0.1:
- MIT LICENSE
- README with badges (build, PyPI, license, Python versions, codecov), quickstart, example output, CI integration snippet, citation
- CONTRIBUTING.md (rule-authoring guide is the headline section)
- CODE_OF_CONDUCT.md (Contributor Covenant 2.1)
- SECURITY.md (private disclosure email, GitHub Security Advisories enabled)
- CHANGELOG.md (Keep a Changelog)
- CITATION.cff (ties to SoK paper)
- CODEOWNERS (owner default; `src/sigmalint/data/vendored/` reserved for explicit review)
- ISSUE_TEMPLATE/bug_report.yml, feature_request.yml, new_rule_proposal.yml
- PULL_REQUEST_TEMPLATE.md (checkboxes for fixtures, docs, self-lint)
- .pre-commit-config.yaml (ruff, ruff-format, mypy, end-of-file-fixer)
- .editorconfig
- .github/dependabot.yml (weekly: pip, github-actions)
- Branch protection + required checks configured (documented in `docs/maintainers.md`)
- Repo topics on GitHub: `sigma-rules`, `detection-engineering`, `siem`, `linter`, `mitre-attack`, `security`

Deferred past v0.1: GOVERNANCE.md, signed releases (sigstore/cosign), public roadmap, Discussions, translations, SLSA provenance.

## 18. Three-week schedule

| Week | Deliverables |
|---|---|
| 1 | Repo scaffolding (LICENSE, pyproject, src layout, pre-commit, CI skeleton). `core/` (rule, registry, runner, scoring, config, profiles, errors). `core/condition` parser with property-based tests. `data/sigma_schema` + `data/attack`. Validity gate SCHEMA001–004 (4) + ATT&CK ATK001–004 (4) + metadata META001a/b, 002, 003, 004, 005 (6) = **14 rules**. JSON + text reporters. `sigmalint lint` + `list-rules` + `profiles`. Golden tests. |
| 2 | Taxonomy TAX001–003 (3) + fp_risk FP001–004 (4) + redundancy RED001–002 (2) + style STY001–003 (3) = **12 rules**. `data/taxonomy` + `data/corpus`. Sigma-Filters discovery (`filters_paths`). `update-data` command with vendored-vs-cache fall-through. SARIF + `github` reporters. `explain` command. Coverage to 90%. Profile coverage tests. |
| 3 | All docs (per-rule .md files, scoring, configuration, profiles, architecture, maintainers). GH composite action + Marketplace listing. release.yml + PyPI trusted publishing. self-lint.yml. Full OSS readiness checklist. README polish + badges. v0.1.0 tag and release. |

## 19. Out-of-scope items (recorded so they are not forgotten)

- External plugin loading (architecture supports it; loader deferred).
- Auto-fix.
- Cross-SIEM translation.
- Rule generation.
- Signed releases / SLSA provenance.
- GOVERNANCE.md, public roadmap, community channels.

---

**Approval:** brainstorming complete; ready for plan-writing in CASEF Stage 2.
