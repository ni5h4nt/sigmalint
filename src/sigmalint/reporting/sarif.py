"""SARIF 2.1.0 formatter — minimum-viable wrapper around the canonical report."""

from __future__ import annotations

import json as _json
from typing import Any, TextIO

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_SEVERITY_TO_SARIF_LEVEL = {
    "error": "error",
    "warning": "warning",
    "info": "note",
}


def _result(finding: dict[str, Any], file_path: str) -> dict[str, Any]:
    region: dict[str, Any] = {}
    line = finding.get("line")
    col = finding.get("col")
    if isinstance(line, int):
        region["startLine"] = line
    if isinstance(col, int):
        region["startColumn"] = col

    physical_location: dict[str, Any] = {
        "artifactLocation": {"uri": file_path},
    }
    if region:
        physical_location["region"] = region

    result: dict[str, Any] = {
        "ruleId": finding.get("rule_id", ""),
        "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.get("severity", "info"), "none"),
        "message": {"text": finding.get("message", "")},
        "locations": [{"physicalLocation": physical_location}],
    }
    fix_hint = finding.get("fix_hint")
    if fix_hint:
        result["properties"] = {"fix_hint": fix_hint}
    return result


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Return a SARIF 2.1.0 log document built from the canonical report."""
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for file_entry in report.get("files", []):
        path = file_entry.get("path", "")
        for finding in file_entry.get("findings") or []:
            rule_id = finding.get("rule_id", "")
            if rule_id and rule_id not in rules_seen:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": finding.get("message", rule_id),
                    },
                }
            results.append(_result(finding, path))

    return {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sigmalint",
                        "version": report.get("sigmalint_version", ""),
                        "informationUri": "https://github.com/nishant/sigmalint",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render(report: dict[str, Any], stream: TextIO) -> None:
    """Write a SARIF 2.1.0 log built from *report* to *stream*."""
    stream.write(_json.dumps(build_sarif(report), indent=2))
    stream.write("\n")
