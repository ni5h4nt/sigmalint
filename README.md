# sigmalint

[![CI](https://github.com/ni5h4nt/sigmalint/actions/workflows/ci.yml/badge.svg)](https://github.com/ni5h4nt/sigmalint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sigmalint.svg)](https://pypi.org/project/sigmalint/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![codecov](https://codecov.io/gh/ni5h4nt/sigmalint/branch/main/graph/badge.svg)](https://codecov.io/gh/ni5h4nt/sigmalint)

ESLint-style linter for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.
Validates against Sigma 2.1.0, scores rules across six quality dimensions, and
emits findings with stable rule IDs that you can cite, suppress, or tune.

## Quickstart

```bash
pip install sigmalint
sigmalint lint rules/
```

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

If you use sigmalint in research, please cite via `CITATION.cff`.
This implementation accompanies a forthcoming paper, *Static Quality Assessment of Sigma Detection Rules: Framework and Empirical Evaluation* (preprint pending).

## License

MIT — see `LICENSE`.
