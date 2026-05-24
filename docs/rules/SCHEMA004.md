---
id: SCHEMA004
dimension: schema
default_severity: error
profiles: { strict: error, sigmahq: error, local: error }
---

# SCHEMA004 — detection.condition parses and references only existing selectors

## What it checks
`detection.condition` parses via sigmalint's condition grammar, and
every selector it references is defined under `detection`. Wildcard
patterns must match at least one defined selector.

## Why
A condition that references a non-existent selector is dead — backends
will silently drop or reject it.

## Why this lives in the validity gate, not in quality

`SCHEMA004` is the criterion of **executable correctness**, not of
quality. An unused selector means the rule's condition references
something undefined; no SIEM backend can run such a rule, and any
quality score on top would be measuring a corpse. The rule therefore
participates in the validity gate alongside `SCHEMA001`–`SCHEMA003`
and `INTERNAL001`: if it fires at error severity, the file is marked
`invalid` and dropped from quality scoring entirely (`status: invalid`,
`total: null`).

## Bad example
```yaml
detection:
  selection: { Image: x }
  condition: selection and filter   # filter is not defined
```

## Good example
```yaml
detection:
  selection:   { Image: x }
  filter_proc: { ParentImage: y }
  condition: selection and not filter_proc
```

## How to fix
Define the selector under `detection`, or remove the reference from
`condition`.

## References
- Sigma 2.1.0 spec — Condition grammar
- `src/sigmalint/core/condition.py`
