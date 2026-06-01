"""Compile custom rule definitions from .sigmalintrc.yml into Rule subclasses."""
from __future__ import annotations

import importlib
import importlib.util
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigmalint.core.check_functions import get_function
from sigmalint.core.errors import ConfigError
from sigmalint.core.registry import register
from sigmalint.core.rule import Rule
from sigmalint.core.types import Dimension, Finding, ParsedRule, Severity


def resolve_path(data: dict[str, Any], path: str) -> Any:
    """Walk a dot-notation path in a dict. Returns None if any key is missing."""
    if path == ".":
        return data
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def evaluate_when(value: Any, when: dict[str, Any]) -> bool:
    """Return True if the when guard holds for value."""
    if "equals" in when:
        target = when["equals"]
        if isinstance(value, list):
            return bool(target in value)
        return bool(value == target)
    if "matches" in when:
        pattern = when["matches"]
        if isinstance(value, list):
            return any(re.search(pattern, str(item)) for item in value)
        return bool(re.search(pattern, str(value)))
    if "in" in when:
        return bool(value in when["in"])
    if "exists" in when:
        return bool((value is not None) == when["exists"])
    if "not_exists" in when:
        return bool((value is None) == when["not_exists"])
    return True


@dataclass(frozen=True, slots=True)
class CustomRuleDefinition:
    id: str
    message: str
    severity: Severity = Severity.WARNING
    dimension: Dimension = Dimension.METADATA
    given: str = "."
    when: dict[str, Any] | None = None
    then_function: str = ""
    then_options: dict[str, Any] = field(default_factory=dict)
    fix_hint: str | None = None


def _validate_path(rule_id: str, path: str) -> None:
    if path != "." and ".." in path:
        raise ConfigError(f"Custom rule '{rule_id}' given path '{path}' is invalid")


def _parse_definition(rule_id: str, d: dict[str, Any]) -> CustomRuleDefinition:
    if "message" not in d:
        raise ConfigError(f"Custom rule '{rule_id}' missing required key 'message'")
    then = d.get("then") or {}
    fn_name = then.get("function", "")
    if not fn_name:
        raise ConfigError(f"Custom rule '{rule_id}' missing required key 'then.function'")
    if get_function(fn_name) is None:
        raise ConfigError(
            f"Custom rule '{rule_id}' references unknown function '{fn_name}'"
        )
    given = d.get("given", ".")
    _validate_path(rule_id, given)
    try:
        severity = Severity(d.get("severity", "warning"))
        dimension = Dimension(d.get("dimension", "metadata"))
    except ValueError as e:
        raise ConfigError(f"Custom rule '{rule_id}': {e}") from e
    return CustomRuleDefinition(
        id=rule_id,
        message=d.get("message", ""),
        severity=severity,
        dimension=dimension,
        given=given,
        when=d.get("when"),
        then_function=fn_name,
        then_options=dict(then.get("options") or {}),
        fix_hint=d.get("fix_hint"),
    )


def _build_rule_class(defn: CustomRuleDefinition) -> type[Rule]:
    fn = get_function(defn.then_function)
    assert fn is not None  # validated in _parse_definition

    def check(self: Rule, parsed: ParsedRule, ctx: Any) -> Iterable[Finding]:
        value = resolve_path(parsed.data, defn.given)
        if defn.when is not None and not evaluate_when(value, defn.when):
            return
        if not fn(value, defn.then_options, parsed, ctx):
            yield Finding(
                rule_id=defn.id,
                dimension=defn.dimension,
                severity=defn.severity,
                message=defn.message,
                file=parsed.path,
                fix_hint=defn.fix_hint,
            )

    return type(
        defn.id,
        (Rule,),
        {
            "id": defn.id,
            "dimension": defn.dimension,
            "default_severity": defn.severity,
            "summary": defn.message[:60],
            "check": check,
        },
    )


class CustomRuleLoader:
    @staticmethod
    def compile(custom_rules: dict[str, Any]) -> list[type[Rule]]:
        """Compile custom rule dicts into Rule subclasses and register them."""
        compiled: list[type[Rule]] = []
        for rule_id, rule_dict in custom_rules.items():
            defn = _parse_definition(rule_id, rule_dict)
            rule_cls = _build_rule_class(defn)
            register(rule_cls)
            compiled.append(rule_cls)
        return compiled


def import_plugin(module_spec: str, config_dir: Path) -> None:
    """Import a plugin module by dotted name or relative file path.

    Relative paths (starting with './' or '../') are resolved from config_dir.
    """
    if module_spec.startswith("./") or module_spec.startswith("../"):
        path = (config_dir / module_spec).resolve()
        if not path.exists():
            raise ConfigError(f"plugin path '{module_spec}' not found (resolved: {path})")
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            raise ConfigError(f"plugin path '{module_spec}' could not be loaded")
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception as e:
            raise ConfigError(
                f"plugin path '{module_spec}' failed to load: {e}"
            ) from e
        sys.modules[path.stem] = mod
    else:
        try:
            importlib.import_module(module_spec)
        except ModuleNotFoundError as e:
            raise ConfigError(f"cannot import plugin '{module_spec}': {e}") from e
        except Exception as e:
            raise ConfigError(f"plugin '{module_spec}' failed to load: {e}") from e
