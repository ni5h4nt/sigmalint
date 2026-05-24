# Configuration — `.sigmalintrc.yml`

All keys are optional. Defaults shown.

```yaml
profile: sigmahq                     # strict | sigmahq | local
disable: []                          # rule IDs to skip (overrides profile)
enable_only: null                    # if set, only these run
severities:                          # per-rule severity overrides
  TAX003: warning
weights:
  dimensions:                        # override default dimension weights
    redundancy: 0.10
  rules:                             # per-rule penalty multiplier
    FP003: 2.0
taxonomy: sigma                      # sigma | <custom-name>
# target_sigma_version: 2.1.0        # reserved; v0.1 supports only 2.1.0
filters_paths:                       # globs for Sigma Filter files
  - filters/**/*.yml
data_dir: ~/.cache/sigmalint         # corpus + STIX cache (writable)
fail_on: error                       # error | warning | never
min_score: null                      # numeric or null
```

## Resolution order

For a rule's effective severity:

1. `severities[<rule_id>]` if set
2. `profiles[<profile>][<rule_id>]` if set
3. The rule's `default_severity`

`disable` (rule IDs) and `enable_only` (rule IDs) are applied last:
disabled rules emit no findings; if `enable_only` is set, only listed
rules run.

## File discovery

Sigmalint searches `./.sigmalintrc.yml` first, then walks upward to the
nearest one. Pass `--config <path>` to override.

## Schema stability

The config schema follows the project's semver policy (see
[versioning.md](./versioning.md)): additive keys are minor changes,
removed/renamed keys are major.

## Reference

- Example: [`.sigmalintrc.example.yml`](../.sigmalintrc.example.yml)
- Loader: `src/sigmalint/core/config.py`
