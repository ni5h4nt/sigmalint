---
id: META001b
dimension: metadata
default_severity: error
profiles: { strict: error, sigmahq: error, local: error }
---

# META001b — id, if present, is a valid UUIDv4

## What it checks
When `id:` is present, it must be a syntactically valid UUIDv4.

## Why
UUIDv4 is the format mandated by the Sigma spec; other formats break
upstream tools.

## Bad example
```yaml
id: not-a-uuid
```

## Good example
```yaml
id: 11111111-2222-4333-8444-555555555555
```

## How to fix
Regenerate with `python -c "import uuid; print(uuid.uuid4())"` and
replace the value.

## References
- RFC 4122 § 4.4
- Sigma 2.1.0 spec
