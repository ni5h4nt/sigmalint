"""sigmalint CLI."""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from sigmalint import __version__
from sigmalint.core.config import Config, load_config
from sigmalint.core.errors import DataLoadError, SigmalintError
from sigmalint.core.filters import discover_filters
from sigmalint.core.profiles import PROFILES, resolve_severity
from sigmalint.core.registry import all_rules, enabled_rules
from sigmalint.core.runner import RunContext
from sigmalint.core.runner import lint as run_lint
from sigmalint.core.scoring import score_file
from sigmalint.data.attack import AttackTaxonomy
from sigmalint.data.corpus import RuleCorpus
from sigmalint.data.sigma_schema import SigmaSchema
from sigmalint.data.taxonomy import AttackLogsourceMap, SigmaModifiers, SigmaTaxonomy
from sigmalint.reporting import github as gha
from sigmalint.reporting import json as jsn
from sigmalint.reporting import sarif as sar
from sigmalint.reporting import text as txt
from sigmalint.reporting.model import build_report

# Import rule modules to register them. The cli is the ONLY layer permitted
# to import sigmalint.rules (enforced by import-linter).
from sigmalint.rules import attack as _a  # noqa: F401
from sigmalint.rules import fp_risk as _fp  # noqa: F401
from sigmalint.rules import metadata as _m  # noqa: F401
from sigmalint.rules import redundancy as _r  # noqa: F401
from sigmalint.rules import schema as _s  # noqa: F401
from sigmalint.rules import style as _st  # noqa: F401
from sigmalint.rules import taxonomy as _t  # noqa: F401

app = typer.Typer(
    add_completion=False,
    help="ESLint-style linter for Sigma detection rules.",
)


def _collect_paths(paths: list[Path]) -> list[Path]:
    """Recursively collect *.yml and *.yaml files. STY002 then flags .yaml."""
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            collected: list[Path] = []
            for pat in ("*.yml", "*.yaml"):
                collected.extend(p.rglob(pat))
            out.extend(sorted(set(collected)))
        elif p.is_file():
            out.append(p)
    return out


def _data_versions(ctx: RunContext) -> dict[str, Any]:
    """Record every dataset that contributed to a scoring decision.

    Reproducibility contract: if two runs produce the same `data_versions`
    block AND the same input file, they must produce the same findings.
    TAX002 reads `modifiers`; ATK003 reads `attack_logsource_map`; both must
    appear here, not just the schema/STIX/taxonomy datasets.
    """
    # RunContext fields are typed as `object` for layering reasons; the cli
    # is the only place that knows their concrete shape.
    return {
        "sigma_schema": ctx.sigma_schema.data_version,  # type: ignore[attr-defined]
        "attack": ctx.attack.data_version,  # type: ignore[attr-defined]
        "taxonomy": ctx.taxonomy.data_version,  # type: ignore[attr-defined]
        "modifiers": ctx.modifiers.data_version,  # type: ignore[attr-defined]
        "attack_logsource_map": ctx.attack_logsource.data_version,  # type: ignore[attr-defined]
        "corpus": ctx.corpus.data_version,  # type: ignore[attr-defined]
    }


def _compute_exit(report: dict[str, Any], cfg: Config) -> int:
    severities = {
        f["severity"] for fobj in report["files"] for f in fobj["findings"]
    }
    if cfg.fail_on == "error" and "error" in severities:
        return 1
    if cfg.fail_on == "warning" and {"error", "warning"} & severities:
        return 1
    mean = report["summary"]["mean_score"]
    if cfg.min_score is not None and mean is not None and mean < cfg.min_score:
        return 1
    return 0


@app.command()
def lint(
    paths: list[Path],
    fmt: Annotated[str, typer.Option("--format", "-f")] = "text",
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    profile: Annotated[str | None, typer.Option("--profile", "-p")] = None,
    disable: Annotated[list[str] | None, typer.Option("--disable")] = None,
    enable_only: Annotated[list[str] | None, typer.Option("--enable-only")] = None,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = None,
    min_score: Annotated[float | None, typer.Option("--min-score")] = None,
    debug: Annotated[bool, typer.Option("--debug")] = False,
) -> None:
    """Lint Sigma rule file(s) or directory(ies)."""
    try:
        cfg = load_config(config) if config else load_config(Path(".sigmalintrc.yml"))
        # Config is frozen + slotted — use dataclasses.replace, not __dict__.
        if profile:
            cfg = dataclasses.replace(cfg, profile=profile)
        if fail_on:
            cfg = dataclasses.replace(cfg, fail_on=fail_on)
        if min_score is not None:
            cfg = dataclasses.replace(cfg, min_score=min_score)

        data_dir = Path(cfg.data_dir).expanduser()
        v = cfg.target_sigma_version
        try:
            ctx = RunContext(
                attack=AttackTaxonomy(data_dir),
                sigma_schema=SigmaSchema(data_dir, version=v),
                taxonomy=SigmaTaxonomy(data_dir, version=v),
                modifiers=SigmaModifiers(data_dir, version=v),
                attack_logsource=AttackLogsourceMap(data_dir),
                corpus=RuleCorpus(data_dir),
                config=cfg,
                filters=list(discover_filters(list(cfg.filters_paths), Path.cwd())),
            )
        except DataLoadError as e:
            typer.secho(f"sigmalint: {e}", err=True, fg=typer.colors.RED)
            raise typer.Exit(3) from e

        all_paths = _collect_paths(paths)
        disable_set = list(cfg.disable) + (disable or [])
        enable_set = enable_only or (
            list(cfg.enable_only) if cfg.enable_only else None
        )
        rules = enabled_rules(disabled=disable_set, enable_only=enable_set)
        # Severity resolution order (later wins):
        #   1. rule.default_severity
        #   2. profile override (PROFILES[cfg.profile])
        #   3. user override (cfg.severities)
        # A None at any layer means "disabled" and the rule is dropped.
        kept = []
        for r in rules:
            eff = resolve_severity(cfg.profile, r.id, r.default_severity)
            if eff is None:
                continue
            if r.id in cfg.severities:
                eff = cfg.severities[r.id]
            r.default_severity = eff
            kept.append(r)
        rules = kept

        results = run_lint(all_paths, rules, ctx)
        scores = [score_file(res, cfg) for res in results]

        report = build_report(results, scores, cfg.profile, _data_versions(ctx))
        out = sys.stdout
        if fmt == "json":
            jsn.render(report, out)
        elif fmt == "sarif":
            sar.render(report, out)
        elif fmt == "github":
            gha.render(report, out)
        else:
            txt.render(report, out)

        raise typer.Exit(_compute_exit(report, cfg))
    except DataLoadError as e:
        typer.secho(f"sigmalint: {e}", err=True, fg=typer.colors.RED)
        raise typer.Exit(3) from e
    except SigmalintError as e:
        typer.secho(f"sigmalint: {e}", err=True, fg=typer.colors.RED)
        raise typer.Exit(2) from e


@app.command(name="list-rules")
def list_rules(
    profile: Annotated[str, typer.Option("--profile", "-p")] = "sigmahq",
) -> None:
    """List all registered rules with effective severity under a profile."""
    if profile not in PROFILES:
        typer.secho(
            f"sigmalint: unknown profile {profile!r}. Known: {sorted(PROFILES)}",
            err=True,
            fg=typer.colors.RED,
        )
        raise typer.Exit(2)
    for r in all_rules():
        eff = resolve_severity(profile, r.id, r.default_severity)
        sev = eff.value if eff is not None else "OFF"
        typer.echo(
            f"{r.id:<10} [{r.dimension.value:<10}] {sev:<8}  {r.summary}"
        )


@app.command()
def explain(rule_id: str) -> None:
    """Print the rule documentation for `rule_id`."""
    doc = (
        Path(__file__).parent.parent.parent.parent
        / "docs"
        / "rules"
        / f"{rule_id}.md"
    )
    if not doc.exists():
        typer.echo(f"No documentation for {rule_id}.", err=True)
        raise typer.Exit(2)
    typer.echo(doc.read_text())


@app.command()
def profiles() -> None:
    """Print every built-in profile and its rule-severity overrides."""
    for name, mapping in PROFILES.items():
        typer.echo(f"\n## {name}")
        for rid, sev in sorted(mapping.items()):
            typer.echo(f"  {rid:<10} -> {sev.value if sev else 'OFF'}")


@app.command(name="update-data")
def update_data_cmd(
    corpus: Annotated[bool, typer.Option("--corpus")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Refresh reference datasets into the user cache dir."""
    from sigmalint.cli.update_data import refresh

    refresh(corpus=corpus, dry_run=dry_run)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sigmalint {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Print version and exit.",
        ),
    ] = None,
) -> None:
    if ctx.invoked_subcommand is None and not version:
        typer.echo(ctx.get_help())
        raise typer.Exit()
