---
id: META005
dimension: metadata
default_severity: warning
profiles: { strict: warning, sigmahq: warning, local: warning }
---

# META005 — status (if present) is a Sigma-2.1.0 vocabulary value

## What it checks
If `status:` is set, its value is one of the Sigma 2.1.0 vocabulary
values: `stable`, `test`, `experimental`, `deprecated`, `unsupported`.

## Why
Off-vocabulary statuses (`prod`, `beta`, …) break SIEM ingestion and
governance filters.

## Bad example
```yaml
status: prod
```

## Good example
```yaml
status: stable
```

## How to fix
Use one of the five allowed values. Omitting the key is also fine.

## References
- Sigma 2.1.0 spec — Status Vocabulary
