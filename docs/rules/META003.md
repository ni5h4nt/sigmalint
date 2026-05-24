---
id: META003
dimension: metadata
default_severity: warning
profiles: { strict: warning, sigmahq: warning, local: OFF }
---

# META003 — references non-empty when level is high or critical

## What it checks
When `level` is `high` or `critical`, the `references:` list must be
non-empty.

## Why
High-severity rules drive alerts; defenders need a citation trail to
triage and to justify the level.

## Bad example
```yaml
level: high
references: []
```

## Good example
```yaml
level: high
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://example.org/incident-writeup
```

## How to fix
Add at least one authoritative URL or paper to `references:`.

## References
- SigmaHQ rule-quality guide
