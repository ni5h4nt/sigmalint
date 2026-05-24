"""Built-in profiles: strict, sigmahq, local.

A profile maps rule IDs to severity, or to None (disabled). Missing IDs
fall through to the rule's default_severity.
"""

from __future__ import annotations

from sigmalint.core.errors import ConfigError
from sigmalint.core.types import Severity

E, W, I, OFF = Severity.ERROR, Severity.WARNING, Severity.INFO, None  # noqa: E741

PROFILES: dict[str, dict[str, Severity | None]] = {
    "strict": {
        # Schema is always strict.
        # Quality: everything that matters is at least a warning.
        "META001a": E,
        "META002": W,
        "META003": W,
        "META005": W,
        "TAX001": W,
        "TAX003": W,
        "FP002": W,
    },
    "sigmahq": {  # default
        "META001a": W,
        "META002": W,
        "META003": W,
        "META005": W,
        "TAX001": W,
        "TAX003": I,
        "FP002": I,
    },
    "local": {
        "META001a": I,
        "META002": I,
        "META003": OFF,
        "META005": W,
        "TAX001": W,
        "TAX003": OFF,
        "RED001": OFF,
        "RED002": OFF,
        "FP002": I,
    },
}

DEFAULT_PROFILE = "sigmahq"


def resolve_severity(profile_name: str, rule_id: str, default: Severity) -> Severity | None:
    """Return the effective severity for `rule_id` under `profile_name`."""
    if profile_name not in PROFILES:
        raise ConfigError(f"Unknown profile: {profile_name!r}. Known: {sorted(PROFILES)}")
    return PROFILES[profile_name].get(rule_id, default)
