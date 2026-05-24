---
id: SCHEMA003
dimension: schema
default_severity: error
profiles: { strict: error, sigmahq: error, local: error }
---

# SCHEMA003 — Required top-level + detection.condition keys present

## What it checks
The required keys `title`, `logsource`, `detection` exist at the top
level, and `detection.condition` exists.

## Why
A rule missing any of these cannot be evaluated by a Sigma backend.

## Bad example
```yaml
title: T
detection:
  selection: { Image: x }
# missing logsource; missing detection.condition
```

## Good example
```yaml
title: T
logsource:
  category: process_creation
detection:
  selection: { Image: x }
  condition: selection
```

## How to fix
Add the missing blocks. See `tests/fixtures/SCHEMA003/pass.yml`.

## References
- Sigma 2.1.0 spec — Required Fields
