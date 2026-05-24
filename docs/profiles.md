# Profiles

A profile is a named mapping of rule IDs to effective severities.
Three profiles ship with sigmalint. The source of truth is
`src/sigmalint/core/profiles.py`.

Cells marked `—` fall through to the rule's `default_severity`. Cells
marked `OFF` mean the rule is disabled under that profile.

| Rule     | strict  | sigmahq (default) | local   |
|----------|---------|-------------------|---------|
| META001a | error   | warning           | info    |
| META002  | warning | warning           | info    |
| META003  | warning | warning           | OFF     |
| META005  | warning | warning           | warning |
| TAX001   | warning | warning           | warning |
| TAX003   | warning | info              | OFF     |
| FP002    | warning | info              | info    |
| RED001   | —       | —                 | OFF     |
| RED002   | —       | —                 | OFF     |

All other rule IDs fall through to their declared `default_severity` —
see the per-rule pages under [`rules/`](./rules/) for those defaults.

## Choosing a profile

- **strict** — for new development and contribution gates. Quality
  problems become warnings or errors.
- **sigmahq** — the default. Mirrors SigmaHQ public-repo expectations.
- **local** — for triage runs against environment-specific or
  proprietary rules. Silences redundancy and tightens nothing.

Override on the CLI:

```
sigmalint lint --profile strict path/to/rules/
```

Or in `.sigmalintrc.yml`:

```yaml
profile: strict
```

## Listing live

```
sigmalint profiles
```

Prints every profile and its rule-severity overrides.
