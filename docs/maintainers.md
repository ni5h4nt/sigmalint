# Maintainers' Guide

## Branch protection

`main` is protected:

- Require pull request before merging (1 approval).
- Require status checks: `lint`, `test`, `coverage` (>= 90%),
  `importlinter`, `mypy`.
- Require linear history.
- Disallow force pushes.
- Restrict direct pushes to maintainers.

Apply via `gh api -X PUT repos/<org>/sigmalint/branches/main/protection ...`
or the GitHub UI.

## Release process

1. Update `CHANGELOG.md` — move `[Unreleased]` entries into a new
   `[X.Y.Z]` block and date it.
2. Bump `version` in `pyproject.toml`.
3. Commit `chore: release vX.Y.Z`.
4. Tag: `git tag -s vX.Y.Z -m "vX.Y.Z"`.
5. Push tag → CI builds wheel + sdist and uploads to PyPI via OIDC.
6. Create a GitHub Release from the tag, copy the CHANGELOG section
   into the body.
7. Run `sigmalint update-data` against the latest ATT&CK and SigmaHQ
   commits; if the vendored snapshot moves, that is a separate PR.

## Type-strictness roadmap

- **v0.1 (current)** — mypy in default mode on `src/sigmalint/`. CI
  passes; some `Any` permitted at I/O edges.
- **v0.2** — turn on `--strict` for `core/`, `rules/`,
  `reporting/`. CLI may remain in default mode.
- **v0.3** — `--strict` everywhere; no `# type: ignore` without a
  comment justifying it.
- **v1.0** — public API annotated; runtime type-checks at edges via
  pydantic or msgspec for config and JSON output.

## Spec-update playbook

When SigmaHQ ships a Sigma spec change, classify the impact:

- **Tier 1 — vocabulary drift.** New `status:` value, a new modifier,
  a new top-level taxonomy field. Patch release. Update vendored data,
  add tests, ship.
- **Tier 2 — semantic change.** A condition operator's meaning
  changes; a previously-valid construct is now an error. Minor
  release. Add a new rule and/or refine an existing one. Provide a
  migration note in `CHANGELOG.md`.
- **Tier 3 — schema break.** A new Sigma major version arrives. Major
  release. Honor `target_sigma_version` so the user can opt back into
  the old schema for one release cycle.

## Issue triage cadence

Weekly. Use `.github/ISSUE_TEMPLATE/new_rule_proposal.yml` submissions
as the primary backlog for new rules; cluster duplicates and link.
