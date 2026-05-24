# Scoring

Sigmalint scores each rule file in two layers: a **validity gate**
followed by a **weighted quality score**. Both are deterministic.

## Validity gate

Any SCHEMA-dimension finding at `error` severity makes the file
**invalid**. Invalid files have `status: invalid` and `total: null` in
the JSON output. The gate exists because a rule that does not parse or
does not satisfy the Sigma 2.1.0 schema cannot be meaningfully scored
on quality.

The validity gate's scope is precisely the following rules at error
severity:

| rule id     | emitter | meaning |
|-------------|---------|---------|
| `SCHEMA001` | runner  | YAML did not parse |
| `INTERNAL001` | runner | a rule's `check()` raised an exception |
| `SCHEMA002` | rule    | document fails the Sigma JSON schema |
| `SCHEMA003` | rule    | `logsource` missing required keys |
| `SCHEMA004` | rule    | `detection.condition` does not parse OR references a selector that is not defined under `detection` |

Validity is the criterion of **executable correctness**: a SIEM
cannot run a rule that fails any of the above. Quality dimensions
(`attack`, `taxonomy`, `fp_risk`, `metadata`, `redundancy`, `style`)
score how *good* a runnable rule is, not whether it can run.

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

### Step 2 — dimension scores (size-invariant normalization)

```
dim_score(d) = max(0.0, 100 * (1 - sum(penalty in d) / max_penalty(d)))
```

where `max_penalty(d)` is the penalty the dimension would incur if
every enabled rule in `d` fired at `error` severity with its
configured rule_weight:

```
max_penalty(d) = sum( ERROR_WEIGHT * rule_weights.get(r.id, 1.0)
                      for r in enabled_rules if r.dimension == d )
```

If `max_penalty(d) == 0` (no enabled rules in the dimension), the
score is `100.0`.

**Worked example.** Suppose the `attack` dimension hosts 4 rules and
the `redundancy` dimension hosts 2 rules, all with default
`rule_weight = 1.0`. Both dimensions accumulate one `warning` finding
(penalty `3.0`):

| dimension   | N_rules | max_penalty | penalty | dim_score (old: `100 - penalty`) | dim_score (new) |
|-------------|--------:|------------:|--------:|---------------------------------:|----------------:|
| attack      |       4 |          40 |       3 |                              97  |            92.5 |
| redundancy  |       2 |          20 |       3 |                              97  |            85.0 |

Under the old formula the two dimensions are indistinguishable
(`97` each), even though a single warning in `redundancy` represents
half of that dimension's rule budget firing, versus a quarter in
`attack`. The new formula reflects this: `redundancy` drops further
because a larger fraction of its rule budget has fired.

The property is **size invariance**: doubling the number of rules in
a dimension without changing the *rate* of firing leaves `dim_score`
unchanged (the numerator and denominator scale together). This makes
adding new rules to a dimension a deliberate calibration decision,
not an accidental score-collapse.

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

These dimension weights are a **starting point**, not a normative
claim. The contribution of this project is the *structure* of the
score — validity gate + per-dimension penalties + size-invariant
aggregation — not the specific numbers. Deployments are expected to
tune dimension weights and per-rule weights to local priorities; the
defaults reflect a generic SOC's relative concern for attack-mapping
correctness over stylistic consistency.

The `rule_weights` default of `1.0` for every rule is a **uniformity
assumption**: in the absence of empirical evidence that one rule's
firings should count more than another's, all firings carry equal
weight inside a dimension. Future work should empirically calibrate
individual rule weights against analyst-labeled rule corpora.

### Linearity

The total is a linear combination of per-dimension scores, which are
themselves linear in penalty units. This is a **deliberate
simplification**: real rule-quality interactions are not linear (e.g.
an unfilterd noisy logsource that *also* lacks a description
compounds rather than adds), but encoding interactions requires
empirical interaction data this project does not yet have. Future
work: empirical interaction analysis against labeled false-positive
incidents.

## Profile interaction

Profiles change the *effective severity* per rule before scoring, so
they directly move scores. The validity gate is unaffected by profiles
(SCHEMA errors are always errors).

## CI gating

`fail_on` (`error` | `warning` | `never`) and `min_score` (number or
null) are the two CI knobs. They are applied **after** scoring; the
score itself is independent of them.
