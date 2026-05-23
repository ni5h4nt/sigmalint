# sigmalint v0.1 — Design Spec

**Date:** 2026-05-23
**Status:** Approved (brainstorming complete; awaiting plan)
**Author:** Nishant Tyagi
**Scope:** v0.1.0 release, three-week build.

---

## 1. Purpose

A command-line linter for Sigma detection rules. Given a Sigma YAML file (or directory of files), `sigmalint` emits ESLint-shaped findings plus a derived quality score across six dimensions: schema validity, MITRE ATT&CK alignment, field-name correctness against the Sigma taxonomy, false-positive risk, redundancy with the public SigmaHQ corpus, and metadata completeness.

This repository is the reference implementation cited by the author's SoK paper on detection-rule quality assessment.

## 2. Goals and non-goals

### Goals
- Ship a `pip install`-able CLI tool in three weeks.
- Findings-first output model — each finding carries a stable, citable rule ID.
- Score derived from findings via configurable per-dimension weights.
- Composite GitHub Action so detection teams can adopt in CI with three lines of YAML.
- Built-in rule catalog of 21 rules across 6 dimensions.
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
| 2 | Vendored MITRE ATT&CK STIX bundle, refreshable via `sigmalint update-data` | Deterministic scoring, offline-capable, CI-friendly. |
| 3 | Vendored Sigma JSON schema; on-demand SigmaHQ corpus clone for redundancy | Fast deterministic core; heavy data is opt-in. |
| 4 | Findings-first output; score is derived | Actionable, matches detection-engineer mental model, CI-friendly. |
| 5 | Plugin-style rule registry (decorator-based) | Per-rule enable/disable, stable IDs, future extensibility for ~50 LOC overhead. |
| 6 | Python 3.10+ | Pattern matching, modern type hints, broad install reach. |
| 7 | Composite GitHub Action wrapping `pip install` | Minimal YAML, fast warm cache, version-pinned via marketplace tag. |
| 8 | All four FP heuristics in v0.1 | FP001 (broad selection), FP002 (unanchored wildcards), FP003 (no filter on noisy sources), FP004 (env-specific literals). |

## 4. Architecture

A small Python package with strict layering. `core/` holds the rule framework and scoring logic and has zero external dependencies. `data/` owns vendored reference data (Sigma JSON schema, MITRE ATT&CK STIX bundle, taxonomy field list) and exposes loader functions. `rules/` contains one module per dimension; each registers `Rule` subclasses at import time. `cli/` is the Typer-based entry point. `reporting/` formats output (text, json, sarif, github).

Strict layering is enforced by `import-linter` in CI:
- `core/` may not import from any other sigmalint module.
- `data/` may import from `core/`.
- `rules/` may import from `core/` and `data/`.
- `reporting/` may import from `core/` only (works on the canonical JSON shape).
- `cli/` is the only module that may import from everywhere.

Runtime deps: `pyyaml`, `ruamel.yaml` (for line/col tracking), `jsonschema`, `typer`, `rich`, `requests` (for `update-data` and corpus fetch).

## 5. Components

| Component | Responsibility | Depends on |
|---|---|---|
| `core.rule.Rule` | Abstract base. Declares `id`, `dimension`, `severity`, `default_weight`, `check(parsed_rule, ctx) -> Iterable[Finding]` | nothing |
| `core.registry.Registry` | Module-level singleton. `@register` decorator. `all_rules()`, `enabled(config)` | nothing |
| `core.runner.Runner` | Loads a rule file, parses YAML, runs all enabled rules, returns `LintResult` | core, rules |
| `core.scoring.Scorer` | `LintResult → ScoredReport` per-dimension + total, per configurable weights | core |
| `core.config.Config` | Loads `.sigmalintrc.yml` (rule enable/disable, weight overrides, severity overrides) | nothing |
| `core.errors` | `SigmalintError` → `ConfigError`, `DataLoadError`, `RuleCheckError` | nothing |
| `data.attack.AttackTaxonomy` | Loads vendored STIX, exposes `is_valid_technique(id)`, `is_revoked(id)`, `is_subtechnique(id)` | jsonschema |
| `data.sigma_schema.SigmaSchema` | Loads vendored Sigma JSON schema, exposes `validate(parsed)` | jsonschema |
| `data.taxonomy.SigmaTaxonomy` | Loads the field-name taxonomy (per-logsource expected fields) | nothing |
| `data.corpus.RuleCorpus` | Lazy SigmaHQ clone+index for redundancy. Fingerprint index. | requests, git |
| `rules.schema`, `rules.attack`, `rules.taxonomy`, `rules.fp_risk`, `rules.redundancy`, `rules.metadata` | One module per dimension; each registers its rules at import | core, data |
| `cli.main` | Typer commands: `lint`, `update-data`, `explain <rule_id>`, `list-rules` | core, data, rich |
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

| ID | Dimension | Severity | Check |
|---|---|---|---|
| `SCHEMA001` | schema | error | YAML parses |
| `SCHEMA002` | schema | error | Validates against Sigma JSON schema |
| `SCHEMA003` | schema | error | Required keys present (`title`, `logsource`, `detection`, `condition`) |
| `SCHEMA004` | schema | warning | `condition` references only selectors defined in `detection` |
| `ATK001` | attack | error | Every `tags:` ATT&CK reference resolves to a known technique ID |
| `ATK002` | attack | warning | No reference to a revoked or deprecated technique |
| `ATK003` | attack | warning | `logsource.category/product` is plausible for the cited techniques (lookup table) |
| `ATK004` | attack | info | Sub-technique vs. parent specificity check |
| `TAX001` | taxonomy | error | All `detection` field names exist for the declared `logsource` |
| `TAX002` | taxonomy | warning | Field-name modifiers (`\|contains`, `\|endswith`, `\|re`, …) spelled correctly |
| `TAX003` | taxonomy | info | Preferred canonical field used (e.g., `Image` not `ImagePath`) |
| `FP001` | fp_risk | warning | Single-selection rule on a common field/value with no `filter` |
| `FP002` | fp_risk | warning | Wildcards without anchors on exact-match fields |
| `FP003` | fp_risk | warning | Noisy log source (e.g., `process_creation`) with no `filter`/`not selection` |
| `FP004` | fp_risk | info | Hardcoded env-specific literals |
| `RED001` | redundancy | info | Detection fingerprint matches a SigmaHQ rule (Jaccard ≥ 0.85) |
| `RED002` | redundancy | info | Title or `id` collides with a public rule |
| `META001` | metadata | error | `id:` is a valid UUID |
| `META002` | metadata | warning | `author`, `date`, `description`, `level`, `status` populated |
| `META003` | metadata | warning | `references:` non-empty when `level` ∈ {high, critical} |
| `META004` | metadata | info | `falsepositives:` non-empty and not literally "Unknown" |

Plus the synthetic `INTERNAL001` (severity: error) emitted by the runner when a rule's `check()` raises.

## 8. Scoring model

**Severity → base weight:** `error=10`, `warning=3`, `info=1`.
**Per-finding penalty:** `severity_weight × rule.default_weight` (default 1.0).
**Per-dimension score:** `max(0, 100 − Σ penalties in dimension)`.
**Total score:** `Σ(dimension_weight × dimension_score)`, dimension weights default to:

| Dimension | Default weight |
|---|---|
| schema | 0.25 |
| attack | 0.20 |
| taxonomy | 0.20 |
| fp_risk | 0.15 |
| metadata | 0.15 |
| redundancy | 0.05 |

Weights sum to 1.0. Users override via `.sigmalintrc.yml`. Disabling a dimension drops it and remaining weights renormalize. Documented in `docs/scoring.md`.

## 9. Configuration

`.sigmalintrc.yml` schema (all optional):

```yaml
disable: [RED001, RED002]            # rule IDs to skip
enable_only: null                    # if set, only these run
severities:                          # per-rule severity overrides
  TAX003: warning
weights:
  dimensions:                        # override defaults
    redundancy: 0.10
  rules:                             # per-rule default_weight multiplier
    FP003: 2.0
data_dir: ~/.cache/sigmalint         # corpus + STIX cache location
fail_on: error                       # error | warning | never
min_score: null                      # numeric or null
```

In-line suppression: `# sigmalint: disable=FP003` as a YAML comment on the offending line or block.

## 10. CLI

| Command | Behavior |
|---|---|
| `sigmalint lint <paths...>` | Lint one or more files/dirs. Honors `--format`, `--fail-on`, `--min-score`, `--config`, `--disable`, `--enable-only`. |
| `sigmalint list-rules` | Print all built-in rules with ID, dimension, severity, one-line summary. |
| `sigmalint explain <rule_id>` | Print full documentation for a rule (sourced from `docs/rules/<id>.md`). |
| `sigmalint update-data` | Refresh vendored ATT&CK STIX and Sigma schema; with `--corpus` also clones SigmaHQ. |
| `sigmalint --version` | Print version. |

Exit codes: `0` clean, `1` findings above threshold or score below threshold, `2` user error, `3` data load error, `>3` internal bug (uncaught exception).

## 11. Output shape (canonical JSON)

```json
{
  "version": "0.1.0",
  "files": [
    {
      "path": "rules/win_susp_foo.yml",
      "rule_title": "Suspicious Foo",
      "findings": [
        {"rule_id":"FP003","dimension":"fp_risk","severity":"warning",
         "message":"process_creation rule has no filter clause",
         "line":12,"col":3,"fix_hint":"Add a filter: section excluding known benign processes"}
      ],
      "scores": {"schema":100,"attack":97,"taxonomy":100,"fp_risk":91,"metadata":94,"redundancy":100,"total":97.1}
    }
  ],
  "summary": {"files":1,"findings":1,"by_severity":{"error":0,"warning":1,"info":0},"mean_score":97.1}
}
```

`text`, `sarif`, and `github` formatters all render from this same shape. The `github` formatter additionally emits `::warning file=…,line=…::…` workflow commands so findings annotate PRs inline.

## 12. Error handling

Three categories:
1. **User errors** (bad input, malformed config, unknown rule ID): stderr message with file/line if available, exit 2. No partial report.
2. **Rule check errors** (a `Rule.check()` raises): caught by runner; converted into a synthetic `INTERNAL001` error finding against the offending file; traceback hidden unless `--debug`. One bad rule never aborts a multi-file run.
3. **Data load errors** (STIX missing, schema unreadable): fail fast with "run `sigmalint update-data`" message, exit 3.

Custom exception hierarchy in `core.errors`. CLI catches `SigmalintError` at the top level and maps to exit codes; anything else unwinds normally (it's a bug).

## 13. Testing strategy

| Layer | Target | Tooling |
|---|---|---|
| Unit per rule | 100% branch on `Rule.check()` | pytest, parametrized fixtures |
| Unit (scoring, config, registry) | 95%+ line | pytest |
| Integration (runner end-to-end) | Golden-file tests on ~15 hand-curated Sigma rules covering pass/fail per rule ID | pytest + JSON diff |
| CLI smoke | `lint`, `list-rules`, `explain`, `update-data --dry-run`, exit codes | `typer.testing.CliRunner` |
| Fuzz (optional) | 50 random valid + malformed YAMLs per CI run, must not crash | hypothesis behind `--with-fuzz` |

Each rule: `tests/fixtures/<rule_id>/{pass.yml,fail.yml}` + one parametrize entry. Adding a rule = rule class + 2 fixtures + 1 line in the parametrize list + 1 doc file. That's the contract enforced by the PR template.

Overall coverage gate: `--cov-fail-under=90`.

## 14. Project layout

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
│   │   └── vendored/          # enterprise-attack.json, sigma-schema.json, fields.yml
│   ├── rules/
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

## 15. CI and release

- **`ci.yml`** — matrix on Python 3.10–3.13: `ruff check`, `ruff format --check`, `mypy --strict`, `pytest --cov=sigmalint --cov-fail-under=90`, `import-linter`. Codecov upload on main. Required for merge.
- **`release.yml`** — triggers on `v*` tags: builds wheel + sdist, publishes to PyPI via OIDC trusted publishing.
- **`self-lint.yml`** — nightly cron: clones SigmaHQ, runs `sigmalint lint` over the corpus, opens an issue if mean score drops >2 points week-over-week.
- **`action.yml`** — composite action; inputs `path`, `format` (default `github`), `fail-on`, `min-score`. Steps: setup-python → `pip install sigmalint==<action-tag>` (action major/minor pins to the released package version) → `sigmalint lint ...`. Published to GitHub Marketplace at v0.1.0.

## 16. Open-source readiness checklist

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

## 17. Three-week schedule

| Week | Deliverables |
|---|---|
| 1 | Repo scaffolding (LICENSE, pyproject, src layout, pre-commit, CI skeleton). `core/` (rule, registry, runner, scoring, config, errors). `data/sigma_schema` + `data/attack`. Schema + metadata + ATT&CK dimensions (11 rules). JSON + text reporters. `sigmalint lint` + `list-rules`. Golden tests. |
| 2 | Taxonomy + fp_risk + redundancy dimensions (10 rules). `data/taxonomy` + `data/corpus`. `update-data` command. SARIF + github reporters. `explain` command. Coverage to 90%. |
| 3 | All docs (per-rule .md files, scoring, configuration, architecture, maintainers). GH composite action + Marketplace listing. release.yml + PyPI trusted publishing. self-lint.yml. Full OSS readiness checklist. README polish + badges. v0.1.0 tag and release. |

## 18. Out-of-scope items (recorded so they are not forgotten)

- External plugin loading (architecture supports it; loader deferred).
- Auto-fix.
- Cross-SIEM translation.
- Rule generation.
- Signed releases / SLSA provenance.
- GOVERNANCE.md, public roadmap, community channels.

---

**Approval:** brainstorming complete; ready for plan-writing in CASEF Stage 2.
