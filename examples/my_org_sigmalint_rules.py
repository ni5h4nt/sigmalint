"""Example sigmalint plugin — org-specific rules for my_org.

Drop this file anywhere on sys.path (e.g. install it as a package) and add
it to .sigmalintrc.yml:

    load_plugins:
      - my_org_sigmalint_rules

Or reference it by relative path without installing:

    load_plugins:
      - ./examples/my_org_sigmalint_rules.py

Two extension points are shown:

1. register_function — add a new check function usable in custom_rules: YAML
2. @register         — add a full Rule subclass for logic too complex for YAML
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from sigmalint.core.check_functions import register_function
from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity

# ── Custom check function ────────────────────────────────────────────────────
#
# register_function adds a new predicate to the built-in vocabulary so it
# can be used in custom_rules: YAML blocks via then.function.
#
# Signature: (value, options, parsed, ctx) -> bool
#   value   — resolved value at the rule's `given` path
#   options — dict from then.options in the YAML rule
#   parsed  — full ParsedRule (access parsed.data for any field)
#   ctx     — RunContext (access ctx.attack, ctx.taxonomy, etc.)
#   returns True  → check passes (no finding)
#   returns False → check fails (finding is emitted by the DSL engine)


def _has_tlp_tag(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    """Return True if the rule's tags include at least one TLP tag.

    Usage in .sigmalintrc.yml:
        custom_rules:
          ORG010:
            message: "All rules must carry a TLP classification tag"
            given: tags
            then:
              function: has_tlp_tag
            severity: warning
            dimension: metadata
    """
    items = value if isinstance(value, list) else ([value] if value is not None else [])
    return any(re.match(r"^tlp\.(red|amber|green|clear|white)$", str(t), re.IGNORECASE)
               for t in items)


register_function("has_tlp_tag", _has_tlp_tag)


def _max_tag_count(value: Any, options: dict[str, Any], parsed: Any, ctx: Any) -> bool:
    """Return True if the number of tags does not exceed options['max'].

    Usage in .sigmalintrc.yml:
        custom_rules:
          ORG011:
            message: "Rules must not have more than 10 tags"
            given: tags
            then:
              function: max_tag_count
              options: {max: 10}
            severity: info
            dimension: metadata
    """
    items = value if isinstance(value, list) else ([value] if value is not None else [])
    return len(items) <= int(options.get("max", 20))


register_function("max_tag_count", _max_tag_count)


# ── Full Rule subclass ───────────────────────────────────────────────────────
#
# Use @register + a Rule subclass when the check needs logic too complex for
# the YAML DSL — multiple fields, cross-referencing external data, etc.


@register
class ORG020(Rule):
    """Require that high/critical rules cite at least one CVE or CWE reference.

    This rule cannot be expressed in the YAML DSL because it combines a
    level check with a regex scan over the references list.
    """

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
                    f"Rule with level={level!r} should cite at least one CVE or CWE "
                    "in its references list"
                ),
                file=parsed.path,
                fix_hint=(
                    "Add a reference URL containing 'CVE-YYYY-NNNNN' or 'CWE-NNN', "
                    "e.g. https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
                ),
            )
