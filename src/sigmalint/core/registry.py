"""Module-level rule registry with a @register decorator."""

from __future__ import annotations

from collections.abc import Iterable

from sigmalint.core.errors import ConfigError
from sigmalint.core.rule import Rule

_REGISTRY: dict[str, type[Rule]] = {}


def register(cls: type[Rule]) -> type[Rule]:
    """Class decorator: add a Rule subclass to the registry by its `id` attribute."""
    if not getattr(cls, "id", None):
        raise ConfigError(f"Rule {cls.__name__} has no 'id'")
    if cls.id in _REGISTRY:
        raise ConfigError(f"Duplicate rule id {cls.id} from {cls.__name__}")
    _REGISTRY[cls.id] = cls
    return cls


def all_rules() -> list[Rule]:
    """Return one instance of every registered rule, sorted by id."""
    return [cls() for _, cls in sorted(_REGISTRY.items())]


def enabled_rules(disabled: Iterable[str], enable_only: Iterable[str] | None) -> list[Rule]:
    """Return rule instances after applying disable/enable_only filters."""
    disabled_set = set(disabled)
    if enable_only is not None:
        enable_set = set(enable_only)
        unknown = enable_set - _REGISTRY.keys()
        if unknown:
            raise ConfigError(f"Unknown rule id(s) in enable_only: {sorted(unknown)}")
        return [
            cls()
            for rid, cls in sorted(_REGISTRY.items())
            if rid in enable_set and rid not in disabled_set
        ]
    unknown = disabled_set - _REGISTRY.keys()
    if unknown:
        raise ConfigError(f"Unknown rule id(s) in disable: {sorted(unknown)}")
    return [cls() for rid, cls in sorted(_REGISTRY.items()) if rid not in disabled_set]


def reset_registry_for_tests() -> None:
    """Test helper. Clears the registry."""
    _REGISTRY.clear()
