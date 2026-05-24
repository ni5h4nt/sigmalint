# Architecture

Sigmalint is a layered, side-effect-light Python package. The layering
is enforced by `import-linter` (`.importlinter.cfg`).

```
cli      ──▶ reporting ──▶ core ──▶ data
                 └──────────▶ rules ──▶ core
                                  └──▶ data
```

The `rules → data` edge is explicit: most rules cannot evaluate
without a reference dataset. `ATK*` rules need ATT&CK STIX bundles
loaded from `core/data` (techniques, platforms, kill-chain phases);
`TAX*` rules need Sigma's modifier and taxonomy lists; `RED*` rules
need the SigmaHQ corpus fingerprint index; `SCHEMA*` rules need the
Sigma JSON schema. Removing the `data/` layer breaks the quality
dimensions, not just the user-facing CLI — they are not stylistic
checks.

## Layers

- **`core/`** — pure types and engines: `Rule`, `Finding`, `Severity`,
  the condition parser, the validity gate, profiles, config, the
  runner, scoring.
- **`rules/`** — the 24 user-facing rule classes (SCHEMA002+, ATK,
  TAX, FP, META, RED, STY). Each subclasses `core.rule.Rule`,
  registers itself via `@register`, and has zero side effects beyond
  yielding findings.
- **`data/`** — vendored & cached reference datasets (Sigma JSON
  schema, ATT&CK STIX, SigmaHQ corpus fingerprints). The package ships
  vendored snapshots under `data/vendored/`; refreshes go into the
  user-cache `data_dir` (default `~/.cache/sigmalint/`). Refresh is
  performed by `sigmalint update-data`.
- **`reporting/`** — formatters (text/Rich, JSON, SARIF) that consume
  `LintResult` objects produced by the runner.
- **`cli/`** — the Typer-based CLI entrypoints.

## Condition parser

`core/condition.py` implements a hand-written recursive-descent parser
for `detection.condition` expressions. The AST exposes the set of
referenced selectors, used by `SCHEMA004` and several FP rules. The
parser is total — every syntactically invalid expression yields a
`ConditionParseError` rather than a Python exception.

## Validity gate

The runner emits `SCHEMA001` (YAML parse) and `INTERNAL001` (rule
crashed) directly. If any SCHEMA-dimension error is present, the file
is marked **invalid** and excluded from quality scoring. See
[scoring.md](./scoring.md).

## Data refresh model

Two storage tiers:

1. **Vendored** (`src/sigmalint/data/vendored/`) — snapshot checked
   into the repo; guarantees a working `sigmalint lint` with no
   network access.
2. **User cache** (`data_dir`, default `~/.cache/sigmalint/`) — written
   by `sigmalint update-data`, with `--dry-run` and `--corpus` flags.

The loader prefers the user cache when present and falls back to the
vendored snapshot. Cache invalidation is by file mtime + a stored
metadata manifest.
