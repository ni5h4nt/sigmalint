"""Refresh reference data into the user cache dir (`cfg.data_dir`).

Spec §11: `update-data` refreshes **all** reference datasets the linter
consults at runtime. It NEVER mutates files inside the installed package — it
only writes to `cfg.data_dir`. Sidecar version files (e.g.
`attack-version.txt`) are written next to each dataset so loaders can report a
reproducible version under the report's `data_versions` block.
"""
from __future__ import annotations

import shutil
import subprocess
from importlib.resources import files
from pathlib import Path

import requests
import typer

ATTACK_TAG = "v16.1"
SIGMA_SCHEMA_TAG = "v2.1.0"

# (relative cache filename, fetch URL or None for vendored mirror, sidecar)
DATASETS: list[tuple[str, str | None, tuple[str, str] | None]] = [
    (
        "enterprise-attack.json",
        f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-{ATTACK_TAG}"
        "/enterprise-attack/enterprise-attack.json",
        ("attack-version.txt", ATTACK_TAG),
    ),
    (
        "sigma-schema.json",
        f"https://raw.githubusercontent.com/SigmaHQ/sigma-specification/"
        f"{SIGMA_SCHEMA_TAG}/json-schema/sigma-detection-rule-schema.json",
        ("sigma-schema-version.txt", SIGMA_SCHEMA_TAG),
    ),
    # Sigma modifiers + field taxonomy + ATT&CK→logsource map ship as
    # opinionated YAML fixtures maintained in this repo. `update-data` mirrors
    # the package-vendored copies into the cache so users on stale wheels can
    # pick up project-side refreshes without reinstalling.
    ("sigma-modifiers.yml", None, None),
    ("fields.yml", None, None),
    ("attack-logsource-map.yml", None, None),
]


def refresh(corpus: bool = False, dry_run: bool = False) -> None:
    """Refresh datasets into `cfg.data_dir`. Never touches the install root."""
    from sigmalint.core.config import Config

    cfg = Config()
    cache = Path(cfg.data_dir).expanduser()
    cache.mkdir(parents=True, exist_ok=True)

    for filename, url, sidecar in DATASETS:
        dest = cache / filename
        if url:
            typer.echo(f"  fetch {url} -> {dest}")
            if not dry_run:
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                dest.write_bytes(r.content)
        else:
            src = Path(str(files("sigmalint.data.vendored") / filename))
            typer.echo(f"  mirror {src} -> {dest}")
            if not dry_run and src.exists():
                shutil.copyfile(src, dest)
        if sidecar and not dry_run:
            (cache / sidecar[0]).write_text(sidecar[1] + "\n", encoding="utf-8")

    if corpus:
        repo = cache / "corpus"
        if repo.exists():
            typer.echo(f"  pull {repo}")
            if not dry_run:
                subprocess.check_call(
                    ["git", "-C", str(repo), "pull", "--ff-only"]
                )
        else:
            typer.echo(f"  clone SigmaHQ/sigma -> {repo}")
            if not dry_run:
                subprocess.check_call(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "https://github.com/SigmaHQ/sigma.git",
                        str(repo),
                    ]
                )

    typer.echo("done.")
