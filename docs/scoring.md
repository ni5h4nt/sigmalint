# Scoring

Sigmalint scores each rule file in two layers: a **validity gate**
followed by a **weighted quality score**. Both are deterministic.

## Validity gate

Any SCHEMA-dimension finding at `error` severity makes the file
**invalid**. Invalid files have `status: invalid` and `total: null` in
the JSON output. The gate exists because a rule that does not parse or
does not satisfy the Sigma 2.1.0 schema cannot be meaningfully scored
on quality.

The runner-emitted findings `SCHEMA001` (YAML parses) and
`INTERNAL001` (rule crash) participate in the gate.

## Quality score

For valid files, sigmalint computes a per-dimension score and then a
weighted total in `[0, 100]`.

### Step 1 — penalties per dimension

Each finding contributes a penalty:

```
penalty(finding) = severity_weight[finding.severity]
                 * config.rule_weights.get(finding.rule_id, 1.0)
```

Base severity weights:

| Severity | Weight |
|----------|--------|
| error    | 10.0   |
| warning  |  3.0   |
| info     |  1.0   |

### Step 2 — dimension scores

```
dim_score(d) = max(0.0, 100.0 - sum(penalty for findings in d))
```

### Step 3 — weighted total

```
total = sum(dim_score(d) * (w(d) / sum(w)))   for d in enabled dims
```

Defaults (overridable via `weights.dimensions` in `.sigmalintrc.yml`):

| Dimension  | Weight |
|------------|--------|
| attack     | 0.22   |
| taxonomy   | 0.20   |
| fp_risk    | 0.20   |
| metadata   | 0.18   |
| redundancy | 0.10   |
| style      | 0.10   |

## Profile interaction

Profiles change the *effective severity* per rule before scoring, so
they directly move scores. The validity gate is unaffected by profiles
(SCHEMA errors are always errors).

## CI gating

`fail_on` (`error` | `warning` | `never`) and `min_score` (number or
null) are the two CI knobs. They are applied **after** scoring; the
score itself is independent of them.
