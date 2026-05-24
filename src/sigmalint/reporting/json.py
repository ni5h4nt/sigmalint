"""JSON formatter — serialises the canonical report dict."""
from __future__ import annotations

import json as _json
from typing import Any, TextIO


def render(report: dict[str, Any], stream: TextIO) -> None:
    """Write the canonical report to *stream* as indented JSON."""
    stream.write(_json.dumps(report, indent=2, sort_keys=False))
    stream.write("\n")
