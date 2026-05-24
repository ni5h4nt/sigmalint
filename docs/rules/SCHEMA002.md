---
id: SCHEMA002
dimension: schema
default_severity: error
profiles: { strict: error, sigmahq: error, local: error }
---

# SCHEMA002 — Sigma JSON schema validation

## What it checks
Validates the rule against the bundled Sigma 2.1.0 JSON schema.

## Why
The JSON schema is the canonical machine-readable description of a
Sigma rule's structure. Failing it means the rule cannot be reliably
consumed by downstream tooling.

## Bad example
```yaml
title: 42                     # title must be a string
logsource:
  category: process_creation
detection:
  selection: { Image: x }
  condition: selection
```

## Good example
```yaml
title: Suspicious cmd.exe child of explorer.exe
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    ParentImage|endswith: '\explorer.exe'
  condition: selection
```

## How to fix
Read the specific schema message printed in the finding and adjust the
offending field's type or value to match the spec.

## References
- Sigma 2.1.0 JSON Schema (bundled under `src/sigmalint/data/vendored/`)
