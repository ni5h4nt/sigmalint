---
id: META001a
dimension: metadata
default_severity: warning
profiles: { strict: error, sigmahq: warning, local: info }
---

# META001a — Rule has an id

## What it checks
The top-level `id:` key is present.

## Why
A stable rule ID is required for deduplication, version tracking, and
downstream SIEM mapping.

## Bad example
```yaml
title: T
# no id
detection: { sel: { Image: x }, condition: sel }
```

## Good example
```yaml
id: 11111111-2222-3333-4444-555555555555
title: T
```

## How to fix
Add an `id:` line. Generate one with
`python -c "import uuid; print(uuid.uuid4())"`.

## References
- Sigma 2.1.0 spec — Rule Identification
