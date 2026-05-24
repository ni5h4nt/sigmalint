---
id: INTERNAL001
dimension: schema
default_severity: error
profiles: { strict: error, sigmahq: error, local: error }
runner_emitted: true
---

# INTERNAL001 — internal rule failure

## What it checks
A registered rule raised an unhandled exception. Emitted by the runner
as a finding so a single buggy rule cannot crash the whole pipeline.

## Why
Sigmalint refuses to silently drop work. A surfaced INTERNAL001
finding is a defect in the rule itself, not in the lint target.

## Bad example
Not applicable — produced by the runner, not by user input.

## Good example
Not applicable.

## How to fix
File a bug with the offending rule ID, sigmalint version, and the
truncated traceback from the finding `message`.

## References
- `src/sigmalint/core/runner.py`
