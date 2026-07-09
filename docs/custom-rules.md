# Custom Rules & Plugins

sigmalint ships 22 built-in quality rules. For org-specific policy — internal
tagging conventions, required fields, house style — you can add your own rules
without modifying the package or sending a PR.

Two extension points, configured in `.sigmalintrc.yml`:

| Extension | When to use |
|---|---|
| `custom_rules:` YAML DSL | Simple field checks — presence, patterns, enumerations, cross-field guards. No Python needed. |
| `load_plugins:` Python modules | Complex logic — multi-field conditions, external data lookups, anything the DSL can't express. |

Both produce findings that flow through the same scoring, suppression, and
reporting pipeline as built-in rules.

---

## `custom_rules:` — YAML rule definitions

Add a `custom_rules:` block to `.sigmalintrc.yml`. Each key is a rule ID
(must not collide with any built-in ID; convention: `ORG###`, `CORP###`,
`TEAM###`):

```yaml
custom_rules:
  ORG001:
    message: "All rules must have an org.ref tag"   # required
    given: tags                                      # dot-path into the Sigma doc
    when: null                                       # optional guard (see below)
    then:                                            # required
      function: contains_match
      options: {pattern: "^org\\.ref\\."}
    severity: warning                                # error | warning | info (default: warning)
    dimension: metadata                              # any dimension (default: metadata)
    fix_hint: "Add a tag matching 'org.ref.<id>'"   # optional
```

### `given` — selecting the value to check

Dot-notation path into the parsed Sigma YAML document. The resolved value is
passed to the check function.

| Path | Resolves to |
|---|---|
| `tags` | the list under `tags:` |
| `level` | the scalar string |
| `logsource.category` | nested key |
| `detection.condition` | the condition string |
| `.` | the entire document dict |

Returns `None` (not an error) when any intermediate key is missing — the
`required` function fires on `None`.

### `when` — conditional guard

The rule only fires when the guard holds. Evaluated against the value at
`given`. When `given` resolves to a **list**, `equals` and `matches` use
any-item semantics; `in` checks whether any list item appears in the set.

```yaml
when: {equals: process_creation}       # value == scalar
when: {matches: "^proc_"}             # value matches regex
when: {in: [high, critical]}          # value is one of a set
when: {exists: true}                  # field is present and non-null
when: {not_exists: true}              # field is absent or null
```

### `then` — the check to apply

`function` names a built-in function (or a function registered by a plugin).
`options` is function-specific.

### Built-in check functions

All functions are predicates: `True` = check passes (no finding),
`False` = check fails (finding emitted).

#### Structural

| Function | Options | Fires when |
|---|---|---|
| `required` | — | field is absent or `null` |
| `pattern` | `match: <regex>` | field value does not match regex |
| `enum` | `values: [...]` | field value is not in the allowed set |
| `min_length` | `min: <int>` | string or list length is below minimum |
| `max_length` | `max: <int>` | string or list length exceeds maximum |

#### List membership

| Function | Options | Fires when |
|---|---|---|
| `contains_match` | `pattern: <regex>` | **no** item in a list field matches the pattern |
| `all_match` | `pattern: <regex>` | **any** item in a list field does not match the pattern |

Both work on scalar values too (treated as a single-item list).

#### Condition-aware

| Function | Options | Fires when |
|---|---|---|
| `condition_has_filter` | — | `detection.condition` has no `and not filter*` clause |
| `condition_references_selector` | `name: <str or regex>` | condition does not reference a selector matching the name |

#### Cross-field

| Function | Options | Fires when |
|---|---|---|
| `field_required` | `field: <dot-path>` | the field at `field` (resolved from **document root**, not from `given`) is absent or null |

### Full example

```yaml
custom_rules:

  # Every rule must carry a tag matching "org.ref.<id>"
  ORG001:
    message: "All rules must have an org.ref tag"
    given: tags
    then:
      function: contains_match
      options: {pattern: "^org\\.ref\\."}
    severity: warning
    dimension: metadata
    fix_hint: "Add a tag like 'org.ref.JIRA-1234'"

  # Critical rules must have a non-empty references field
  ORG002:
    message: "Critical rules must have references"
    given: level
    when: {equals: critical}
    then:
      function: field_required
      options: {field: references}
    severity: error
    dimension: metadata

  # process_creation rules must have a negated filter in detection.condition
  ORG003:
    message: "process_creation rules must have a filter selector"
    given: logsource.category
    when: {equals: process_creation}
    then:
      function: condition_has_filter
    severity: warning
    dimension: fp_risk

  # rule title must be at least 10 characters
  ORG004:
    message: "Rule title is too short (minimum 10 characters)"
    given: title
    then:
      function: min_length
      options: {min: 10}
    severity: info
    dimension: metadata

  # status must be one of the org-approved values
  ORG005:
    message: "status must be stable, test, or experimental"
    given: status
    then:
      function: enum
      options: {values: [stable, test, experimental]}
    severity: warning
    dimension: metadata
```

### Inline suppression

Custom rule IDs work identically to built-in IDs for inline suppression:

```yaml
# sigmalint: disable=ORG001
title: Legacy rule (pre-tagging policy)
...
```

---

## `load_plugins:` — Python plugins

For checks that need multi-field logic, external data, or anything beyond
the DSL, write a Python module and list it in `load_plugins:`.

```yaml
load_plugins:
  - my_org.sigmalint_rules      # importable dotted name (must be on sys.path)
  - ./local_rules.py            # relative path from the .sigmalintrc.yml file
```

Plugins are imported **before** `custom_rules:` is compiled, so functions
registered by a plugin are immediately available to the YAML DSL in the same
config file.

### Two plugin patterns

#### Pattern 1: Register a custom check function

Use `register_function` to add a new predicate to the built-in vocabulary.
Once registered, it can be called from `custom_rules:` YAML via `then.function`.

```python
# my_org_sigmalint_rules.py
from sigmalint.core.check_functions import register_function
from typing import Any


def _has_tlp_tag(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    """True if the rule has at least one TLP classification tag."""
    import re
    items = value if isinstance(value, list) else ([value] if value is not None else [])
    return any(
        re.match(r"^tlp\.(red|amber|green|clear|white)$", str(t), re.IGNORECASE)
        for t in items
    )


register_function("has_tlp_tag", _has_tlp_tag)
```

Then in `.sigmalintrc.yml`:

```yaml
load_plugins:
  - ./my_org_sigmalint_rules.py

custom_rules:
  ORG010:
    message: "All rules must carry a TLP classification tag"
    given: tags
    then:
      function: has_tlp_tag    # registered by the plugin
    severity: warning
    dimension: metadata
```

**Function signature:** `(value, options, parsed, ctx) -> bool`

| Argument | Type | Description |
|---|---|---|
| `value` | `Any` | Resolved value at the `given` path |
| `options` | `dict` | Contents of `then.options` in the YAML rule |
| `parsed` | `ParsedRule` | Full parsed Sigma document (`parsed.data`, `parsed.path`) |
| `ctx` | `RunContext` | Shared context (`ctx.attack`, `ctx.taxonomy`, `ctx.corpus`, …) |

Return `True` if the check passes (no finding). Return `False` if it fails —
the DSL engine creates the `Finding` using the rule's `message`, `severity`,
`dimension`, and `fix_hint`.

#### Pattern 2: Register a full Rule subclass

For complex checks — cross-referencing ATT&CK data, multi-field logic,
generating multiple findings per file — subclass `Rule` directly and use
`@register`:

```python
# my_org_sigmalint_rules.py
import re
from collections.abc import Iterable
from typing import Any

from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


@register
class ORG020(Rule):
    """High/critical rules must cite at least one CVE or CWE in references."""

    id = "ORG020"
    dimension = Dimension.METADATA
    default_severity = Severity.WARNING
    summary = "High/critical rules must cite at least one CVE or CWE reference"

    _CVE_CWE = re.compile(r"CVE-\d{4}-\d+|CWE-\d+", re.IGNORECASE)

    def check(self, parsed: ParsedRule, ctx: Any) -> Iterable[Finding]:
        level = parsed.data.get("level", "")
        if level not in ("high", "critical"):
            return

        references = parsed.data.get("references") or []
        if not any(self._CVE_CWE.search(str(ref)) for ref in references):
            yield Finding(
                rule_id=self.id,
                dimension=self.dimension,
                severity=self.default_severity,
                message=(
                    f"Rule with level={level!r} should cite at least one CVE or CWE"
                ),
                file=parsed.path,
                fix_hint="Add a reference URL containing 'CVE-YYYY-NNNNN' or 'CWE-NNN'",
            )
```

Rule subclasses registered this way appear in `sigmalint list-rules` output,
respect `disable:` and `--enable-only`, and contribute to scoring under
their declared `dimension`.

### Complete example plugin

A ready-to-use example is at `examples/my_org_sigmalint_rules.py`. It
demonstrates both patterns (two `register_function` calls and one `@register`
Rule subclass) and can be used as a starting point for an org plugin package.

To try it locally:

```bash
# Reference by relative path (no install needed)
echo "load_plugins:\n  - ./examples/my_org_sigmalint_rules.py" >> .sigmalintrc.yml
sigmalint lint rules/
```

---

## Resolution and scoring

Custom rule findings flow through the same pipeline as built-in findings:

- **Severity resolution:** `severities[<id>]` in config overrides the rule's
  declared `severity`.
- **Disable/enable:** `disable: [ORG001]` and `--enable-only ORG001` work
  exactly as they do for built-in IDs.
- **Scoring:** findings contribute a penalty to their declared `dimension`.
  A custom rule with `dimension: fp_risk` and `severity: warning` deducts
  the same 3-point penalty from the `fp_risk` dimension score as a built-in
  `warning`-severity FP rule.
- **Inline suppression:** `# sigmalint: disable=ORG001` on any line in the
  rule file suppresses that finding.
- **Profiles:** custom rule IDs are not in the built-in profile tables, so
  they always fall through to their declared `severity` unless you override
  them explicitly in `severities:`.

---

## Error handling

**Config errors** (startup, `exit 2`)

- Plugin module not found or raises on import
- Unknown `then.function` name
- Invalid `severity` or `dimension` value
- Missing required keys (`message`, `then.function`)
- Rule ID collision with a built-in

**Runtime errors** (per-file `INTERNAL001` finding, run continues)

If a custom rule's `check()` raises an uncaught exception, the runner catches
it and emits an `INTERNAL001` error finding against that file. The rest of
the lint run continues normally.

---

## Reference

- Example plugin: `examples/my_org_sigmalint_rules.py`
- Example config: `.sigmalintrc.example.yml`
- Config schema: `docs/configuration.md`
- Scoring model: `docs/scoring.md`
