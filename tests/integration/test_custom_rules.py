# tests/integration/test_custom_rules.py
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from sigmalint.core.check_functions import _REGISTRY as fn_registry
from sigmalint.core.config import Config
from sigmalint.core.custom_rule import CustomRuleLoader, import_plugin
from sigmalint.core.registry import all_rules, reset_registry_for_tests
from sigmalint.core.runner import RunContext, lint
from sigmalint.core.types import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


_BUILTIN_RULE_MODULES = [
    "sigmalint.rules.schema",
    "sigmalint.rules.attack",
    "sigmalint.rules.taxonomy",
    "sigmalint.rules.fp_risk",
    "sigmalint.rules.redundancy",
    "sigmalint.rules.metadata",
    "sigmalint.rules.style",
]


@pytest.fixture(autouse=True)
def clean_registry():
    """Reset rule registry between tests, then re-register built-ins."""
    import sys

    yield
    reset_registry_for_tests()
    # Remove rule modules from sys.modules so that import_module re-executes
    # them and re-registers their rules into the freshly cleared registry.
    for mod_name in _BUILTIN_RULE_MODULES:
        sys.modules.pop(mod_name, None)
    for mod_name in _BUILTIN_RULE_MODULES:
        importlib.import_module(mod_name)


def _make_ctx() -> RunContext:
    from sigmalint.data.attack import AttackTaxonomy
    from sigmalint.data.corpus import RuleCorpus
    from sigmalint.data.sigma_schema import SigmaSchema
    from sigmalint.data.taxonomy import AttackLogsourceMap, SigmaModifiers, SigmaTaxonomy

    data_dir = Path("~/.cache/sigmalint").expanduser()
    cfg = Config()
    return RunContext(
        attack=AttackTaxonomy(data_dir),
        sigma_schema=SigmaSchema(data_dir, version="2.1.0"),
        taxonomy=SigmaTaxonomy(data_dir, version="2.1.0"),
        modifiers=SigmaModifiers(data_dir, version="2.1.0"),
        attack_logsource=AttackLogsourceMap(data_dir),
        corpus=RuleCorpus(data_dir),
        config=cfg,
        filters=[],
    )


def test_custom_rule_finding_on_fail_fixture() -> None:
    CustomRuleLoader.compile(
        {
            "ORG001": {
                "message": "All rules must have an org.ref tag",
                "given": "tags",
                "then": {
                    "function": "contains_match",
                    "options": {"pattern": "^org\\.ref\\."},
                },
                "severity": "warning",
                "dimension": "metadata",
            }
        }
    )
    ctx = _make_ctx()
    rules = [r for r in all_rules() if r.id == "ORG001"]
    results = lint([FIXTURES / "ORG001" / "fail.yml"], rules, ctx)
    findings = [f for r in results for f in r.findings]
    assert any(f.rule_id == "ORG001" for f in findings)


def test_custom_rule_no_finding_on_pass_fixture() -> None:
    CustomRuleLoader.compile(
        {
            "ORG001": {
                "message": "All rules must have an org.ref tag",
                "given": "tags",
                "then": {
                    "function": "contains_match",
                    "options": {"pattern": "^org\\.ref\\."},
                },
            }
        }
    )
    ctx = _make_ctx()
    rules = [r for r in all_rules() if r.id == "ORG001"]
    results = lint([FIXTURES / "ORG001" / "pass.yml"], rules, ctx)
    findings = [f for r in results for f in r.findings if f.rule_id == "ORG001"]
    assert findings == []


def test_custom_rule_respects_inline_suppression(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text(
        "# sigmalint: disable=ORG001\n"
        "title: Test\n"
        "id: 00000000-0000-4000-a000-000000000003\n"
        "status: test\n"
        "description: x\n"
        "author: x\n"
        "logsource:\n  product: windows\n  category: process_creation\n"
        "detection:\n  selection:\n    Image: x\n  condition: selection\n"
        "tags: [attack.defense_evasion]\n"
        "level: medium\n"
    )
    CustomRuleLoader.compile(
        {
            "ORG001": {
                "message": "Need org tag",
                "given": "tags",
                "then": {"function": "contains_match", "options": {"pattern": "^org\\."}},
            }
        }
    )
    ctx = _make_ctx()
    rules = [r for r in all_rules() if r.id == "ORG001"]
    results = lint([rule_file], rules, ctx)
    findings = [f for r in results for f in r.findings if f.rule_id == "ORG001"]
    assert findings == []


def test_plugin_registered_function_usable_in_custom_rules(tmp_path: Path) -> None:
    plugin = tmp_path / "org_plugin.py"
    plugin.write_text(
        "from sigmalint.core.check_functions import register_function\n\n"
        "def _has_custom_field(value, options, parsed, ctx):\n"
        "    return parsed.data.get('custom_org_field') is not None\n\n"
        "register_function('has_custom_org_field', _has_custom_field)\n"
    )
    import_plugin(f"./{plugin.name}", config_dir=tmp_path)

    CustomRuleLoader.compile(
        {
            "ORG003": {
                "message": "custom_org_field must be present",
                "then": {"function": "has_custom_org_field"},
            }
        }
    )
    assert "has_custom_org_field" in fn_registry

    ctx = _make_ctx()
    rules = [r for r in all_rules() if r.id == "ORG003"]

    no_field = tmp_path / "no_field.yml"
    no_field.write_text(
        "title: T\nid: 00000000-0000-4000-a000-000000000004\nstatus: test\n"
        "description: x\nauthor: x\nlogsource:\n  product: windows\n"
        "detection:\n  selection:\n    Image: x\n  condition: selection\n"
        "tags: []\nlevel: low\n"
    )
    results = lint([no_field], rules, ctx)
    findings = [f for r in results for f in r.findings if f.rule_id == "ORG003"]
    assert len(findings) == 1
