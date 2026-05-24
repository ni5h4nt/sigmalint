---
id: META001b
dimension: metadata
default_severity: warning
profiles: { strict: warning, sigmahq: warning, local: warning }
---

# META001b — id, if present, is a valid UUID (UUIDv4 recommended)

## What it checks

When `id:` is present, it must be a syntactically valid UUID. UUIDv4 is
the format the Sigma spec recommends; other UUID versions are accepted
by most tooling but raise a warning here so authors know to migrate.

## Severity split

This rule emits findings at two severities depending on the failure mode:

- **error** — `id` is present but cannot be parsed as any UUID (e.g. a
  short string, missing dashes, non-hex characters). Most SIEMs will
  not treat such a value as a stable identifier.
- **warning** — `id` parses as a UUID but is not v4. The rule still has
  a globally-unique identifier, but Sigma recommends v4 specifically
  because v1 leaks the author's MAC address and creation timestamp.

## Why

The Sigma spec marks `id` as optional but strongly recommends UUIDv4
for any rule intended for sharing. UUIDv1 (timestamp + node id) and
UUIDv3/v5 (name-based hashes) are still globally unique, but they
either leak metadata about the author's machine (v1) or imply a
deterministic relationship to a name (v3/v5) that isn't true here.

## Bad examples

```yaml
# error — not parseable
id: not-a-uuid
```

```yaml
# warning — valid UUIDv1 (notice the `1` at position 13: `9062-11ed`)
id: 572b12d4-9062-11ed-a1eb-0242ac120002
```

## Good example

```yaml
# UUIDv4 — version nibble (position 13) is `4`, variant nibble (position 17) is 8/9/a/b
id: 11111111-2222-4333-8444-555555555555
```

## How to fix

Regenerate with `python -c "import uuid; print(uuid.uuid4())"` and
replace the value. UUIDv1 ids in existing rules are best left in place
unless you control the corpus — changing an id breaks any references to
that rule from Sigma Filters or downstream catalogs.

## References

- RFC 4122 § 4.4 (random-based UUIDs)
- Sigma 2.1.0 spec, "id" field
