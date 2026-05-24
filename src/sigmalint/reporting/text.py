"""Text formatter — rich Table summary of the canonical report."""
from __future__ import annotations

from typing import Any, TextIO

from rich.console import Console
from rich.table import Table


def _format_score(file_entry: dict[str, Any]) -> str:
    scores = file_entry.get("scores")
    if not scores:
        return "-"
    total = scores.get("total")
    return f"{total:.1f}" if isinstance(total, (int, float)) else "-"


def _top_findings(file_entry: dict[str, Any], limit: int = 3) -> str:
    findings = file_entry.get("findings") or []
    if not findings:
        return ""
    severity_order = {"error": 0, "warning": 1, "info": 2}
    ordered = sorted(
        findings, key=lambda f: severity_order.get(f.get("severity", "info"), 99)
    )
    bits = []
    for f in ordered[:limit]:
        bits.append(f"{f['rule_id']} ({f['severity']})")
    if len(ordered) > limit:
        bits.append(f"+{len(ordered) - limit} more")
    return ", ".join(bits)


def render(report: dict[str, Any], stream: TextIO) -> None:
    """Render the canonical report as a rich Table."""
    console = Console(file=stream, force_terminal=False, highlight=False)
    table = Table(title=f"sigmalint {report.get('sigmalint_version', '')}")
    table.add_column("file", overflow="fold")
    table.add_column("status")
    table.add_column("score", justify="right")
    table.add_column("findings")
    table.add_column("top findings", overflow="fold")

    for file_entry in report.get("files", []):
        finding_count = len(file_entry.get("findings") or [])
        table.add_row(
            file_entry.get("path", ""),
            file_entry.get("status", ""),
            _format_score(file_entry),
            str(finding_count),
            _top_findings(file_entry),
        )

    console.print(table)

    summary = report.get("summary") or {}
    by_sev = summary.get("by_severity") or {}
    mean = summary.get("mean_score")
    mean_str = f"{mean:.2f}" if isinstance(mean, (int, float)) else "n/a"
    console.print(
        f"files={summary.get('files', 0)} "
        f"valid={summary.get('valid', 0)} "
        f"invalid={summary.get('invalid', 0)} "
        f"findings={summary.get('findings', 0)} "
        f"errors={by_sev.get('error', 0)} "
        f"warnings={by_sev.get('warning', 0)} "
        f"info={by_sev.get('info', 0)} "
        f"mean_score={mean_str}"
    )
