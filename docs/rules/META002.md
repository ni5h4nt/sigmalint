---
id: META002
dimension: metadata
default_severity: warning
profiles: { strict: warning, sigmahq: warning, local: info }
---

# META002 — author, date, description, level populated

## What it checks
The keys `author`, `date`, `description`, and `level` exist and are
non-empty.

## Why
These fields support attribution, triage, and severity routing in
downstream pipelines.

## Bad example
```yaml
title: T
detection: { sel: { Image: x }, condition: sel }
```

## Good example
```yaml
title: T
author: Jane Doe
date: 2026-01-01
description: Detects suspicious cmd.exe under explorer.exe.
level: medium
```

## How to fix
Populate all four keys.

## References
- Sigma 2.1.0 spec — Metadata Fields
