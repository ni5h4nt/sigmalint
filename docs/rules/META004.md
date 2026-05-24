---
id: META004
dimension: metadata
default_severity: info
profiles: { strict: info, sigmahq: info, local: info }
---

# META004 — falsepositives non-empty and not literally 'Unknown'

## What it checks
`falsepositives:` is present, non-empty, and is not just the literal
string `Unknown` (in any case).

## Why
`Unknown` is a tell that the author did not think about FP scenarios.
Naming concrete FP causes helps the on-call.

## Bad example
```yaml
falsepositives:
  - Unknown
```

## Good example
```yaml
falsepositives:
  - Software deployment frameworks that legitimately spawn cmd.exe
  - Administrative scripts run from explorer.exe shortcuts
```

## How to fix
Replace `Unknown` with at least one realistic FP scenario.

## References
- SigmaHQ rule-quality guide
