# sigmalint

[![CI](https://github.com/ni5h4nt/sigmalint/actions/workflows/ci.yml/badge.svg)](https://github.com/ni5h4nt/sigmalint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sigmalint-cli.svg)](https://pypi.org/project/sigmalint-cli/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![codecov](https://codecov.io/gh/ni5h4nt/sigmalint/branch/main/graph/badge.svg)](https://codecov.io/gh/ni5h4nt/sigmalint)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20371168.svg)](https://doi.org/10.5281/zenodo.20371168)

Created and maintained by [Nishant Tyagi](https://github.com/ni5h4nt).

ESLint-style linter for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.
Validates against Sigma 2.1.0, scores rules across six quality dimensions, and
emits findings with stable rule IDs that you can cite, suppress, or tune.

## Why sigmalint

Detection teams routinely ship Sigma rules through pull requests, but existing
tooling stops at schema validity. SigmaHQ's `sigma-cli check` and `pySigma`
verify that a rule parses; they don't measure whether it is well-attributed
(MITRE ATT&CK alignment), free of common false-positive patterns, redundant
with existing public rules, or stylistically consistent. sigmalint fills that
gap with 22 deterministic quality checks across six dimensions, designed to
run on every PR — the same way ESLint runs on JavaScript or RuboCop runs on
Ruby.

## Quickstart

```bash
pip install sigmalint-cli
sigmalint lint rules/
```

> The PyPI package is named **`sigmalint-cli`** because the bare name
> `sigmalint` was already taken by an unrelated project. The CLI binary,
> the Python import (`import sigmalint`), and the GitHub repository are
> all named `sigmalint`.

Example output:

```
                                sigmalint 0.1.0
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ file                    ┃ status ┃ score ┃ findings ┃ top findings           ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ rules/win_susp_foo.yml  │ valid  │  95.8 │ 9        │ FP001 (warning), FP003 │
│                         │        │       │          │ (warning), META001a    │
│                         │        │       │          │ (warning), +6 more     │
└─────────────────────────┴────────┴───────┴──────────┴────────────────────────┘
files=1 valid=1 invalid=0 findings=9 errors=0 warnings=7 info=2 mean_score=95.82
```

Every finding has a stable rule ID. `sigmalint explain <ID>` prints the
full rule documentation — what it checks, why it matters, bad/good
examples, and the fix:

```
$ sigmalint explain FP001
---
id: FP001
dimension: fp_risk
default_severity: warning
profiles: { strict: warning, sigmahq: warning, local: warning }
---

# FP001 — Single broad selection with no filter

## What it checks
The rule's `detection.condition` is a single, unfiltered selection that
references only one wide-matching predicate (e.g. just `selection`
matching a common process name).

## Why
Such rules typically generate high-volume noise in production
deployments.

## Bad example
detection:
  selection: { Image|endswith: '\powershell.exe' }
  condition: selection

## Good example
detection:
  selection: { Image|endswith: '\powershell.exe' }
  filter:    { ParentImage|endswith: ['\explorer.exe', '\cmd.exe'] }
  condition: selection and not filter

## How to fix
Add a negated `filter`/`filter_*` selector that excludes the common
benign cases, or narrow the selection.
```

## What it checks

A strict **validity gate** (Sigma 2.1.0 JSON schema + condition parser) plus
six **quality dimensions** with 22 rules:

- `ATK###` — MITRE ATT&CK technique alignment (4 rules)
- `TAX###` — Sigma taxonomy and modifier correctness (3 rules)
- `FP###` — false-positive risk heuristics (4 rules)
- `META###` — metadata completeness (6 rules)
- `RED###` — redundancy with the public SigmaHQ corpus (2 rules)
- `STY###` — Sigma interoperability style (3 rules)

Run `sigmalint list-rules` for the full catalog; `sigmalint explain <ID>` for
per-rule documentation.

## In CI

```yaml
- uses: ni5h4nt/sigmalint@v0.1.0
  with:
    path: rules/
    format: github
    fail-on: error
    min-score: 90
```

`format: github` annotates findings inline on PRs via workflow commands.
Other formats: `text` (default), `json`, `sarif`.

## Profiles

Three built-in profiles tune the rule set for different contexts:

| Profile | Intent |
|---|---|
| `strict` | Maximum policy enforcement; treats every quality signal as actionable |
| `sigmahq` *(default)* | Match SigmaHQ submission expectations |
| `local` | Internal corpus where ids/authors aren't shared and naming is org-specific |

Override per rule via `.sigmalintrc.yml`. See `docs/profiles.md`.

## Configuration

`.sigmalintrc.yml` in your repo root, all keys optional:

```yaml
profile: sigmahq
target_sigma_version: 2.1.0   # reserved; multi-version arrives in v0.2
disable: [RED001]
severities:
  TAX003: warning
weights:
  dimensions:
    redundancy: 0.10
fail_on: error
min_score: 90
```

See `docs/configuration.md` for the full schema.

## Compared to other Sigma tooling

- **`sigma-cli` / pySigma** — schema validation and rule → SIEM
  conversion. Verify that a rule is well-formed; do not measure
  quality dimensions.
- **SigmaHQ contribution pipeline** — quality checks specific to the
  public-repo submission process (filename conventions, `references`
  URL liveness, license markers). Specialized to that workflow; not
  portable to internal corpora.
- **`yaraQA`** — comparable concept for the sibling [YARA](https://github.com/VirusTotal/yara)
  rule format. sigmalint applies the same idea to Sigma.

sigmalint is the only tool that scores Sigma rules across multiple
quality dimensions with stable, citeable rule IDs.

## Roadmap

- **v0.2** — additional rule formats (Splunk SPL detections, Elastic
  detection rules), expanded false-positive heuristics, optional
  AI-assisted rule explanations.
- **v0.3** — multi-version Sigma support (1.0.x / 2.0.x / 2.1.x),
  benchmark dataset integration.
- **v1.0** — stable rule IDs guaranteed across releases, language
  plugin API for adding new rule formats out-of-tree.

## Documentation

- `docs/architecture.md` — layered design, condition parser, validity gate
- `docs/scoring.md` — validity gate + weighted quality scoring
- `docs/profiles.md` — per-profile rule severities
- `docs/configuration.md` — config schema
- `docs/versioning.md` — semver policy and rule-ID stability
- `docs/maintainers.md` — release process and spec-update playbook
- `docs/rules/<ID>.md` — per-rule pages (also surfaced by `sigmalint explain`)

## Contributing

The headline contribution path is **adding a new lint rule** — see
`CONTRIBUTING.md` for the four-step contract (rule class, fixtures, parametrize
entry, doc page). Issues use a structured **new rule proposal** template.

## Citation

If you use sigmalint in research, cite via the Zenodo DOI
[`10.5281/zenodo.20371168`](https://doi.org/10.5281/zenodo.20371168)
(concept DOI — always resolves to the latest archived version) or via
`CITATION.cff`.

This implementation accompanies a forthcoming paper, *Static Quality
Assessment of Sigma Detection Rules: Framework and Empirical Evaluation*
(preprint pending).

## License

MIT — see `LICENSE`.

---

*This project is not affiliated with or endorsed by SigmaHQ or The MITRE
Corporation. Sigma is a project of SigmaHQ. ATT&CK® is a registered
trademark of The MITRE Corporation.*
