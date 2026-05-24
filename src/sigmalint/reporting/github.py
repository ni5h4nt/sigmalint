"""GitHub Actions workflow-command formatter.

Emits one `::error|warning|notice file=…,line=…,col=…::message` line per finding,
plus a final summary line. Annotations show up inline on pull requests.
"""

from __future__ import annotations

from typing import Any, TextIO

_SEVERITY_TO_COMMAND = {
    "error": "error",
    "warning": "warning",
    "info": "notice",
}


def _escape(value: str) -> str:
    # GitHub workflow-command escaping for the message portion: %25, %0D, %0A.
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render(report: dict[str, Any], stream: TextIO) -> None:
    """Render workflow commands + summary line for GitHub Actions."""
    for file_entry in report.get("files", []):
        path = file_entry.get("path", "")
        for finding in file_entry.get("findings") or []:
            severity = finding.get("severity", "info")
            command = _SEVERITY_TO_COMMAND.get(severity, "notice")
            params = [f"file={path}"]
            line = finding.get("line")
            col = finding.get("col")
            if isinstance(line, int):
                params.append(f"line={line}")
            if isinstance(col, int):
                params.append(f"col={col}")
            params.append(f"title={finding.get('rule_id', '')}")
            message = _escape(finding.get("message", ""))
            stream.write(f"::{command} {','.join(params)}::{message}\n")

    summary = report.get("summary") or {}
    by_sev = summary.get("by_severity") or {}
    mean = summary.get("mean_score")
    mean_str = f"{mean:.2f}" if isinstance(mean, (int, float)) else "n/a"
    stream.write(
        f"sigmalint: files={summary.get('files', 0)} "
        f"valid={summary.get('valid', 0)} "
        f"invalid={summary.get('invalid', 0)} "
        f"errors={by_sev.get('error', 0)} "
        f"warnings={by_sev.get('warning', 0)} "
        f"info={by_sev.get('info', 0)} "
        f"mean_score={mean_str}\n"
    )
