---
id: SCHEMA001
dimension: schema
default_severity: error
profiles: { strict: error, sigmahq: error, local: error }
runner_emitted: true
---

# SCHEMA001 — YAML parses

## What it checks
The file is well-formed YAML. Emitted directly by the runner before any
other rule executes; on failure the file is marked **invalid** and no
further rules run.

## Why
A Sigma rule that does not parse cannot be validated, scored, or
deployed. This is the floor of the validity gate.

## Bad example
```yaml
title: Bad
detection:
  selection:
    Image: x
    : missing-key
```
(YAML parse error.)

## Good example
Any file that loads via `yaml.safe_load`.

## How to fix
Open the file in a YAML-aware editor; check indentation, quotes, and
stray colons. Run `python -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" file.yml`.

## References
- Sigma 2.1.0 spec
- `src/sigmalint/core/runner.py`
