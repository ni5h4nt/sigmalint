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

## Branch-protection escalation

The settings are designed to evolve with the project; the table below
documents the trigger event for each change so no one has to rediscover
the right configuration when the moment arrives.

> **Current status:** Branch protection is **active** on `main` (enabled
> after upgrading to GitHub Pro for the private repo). Required CI
> contexts: `test (3.10)`, `test (3.11)`, `test (3.12)`, `test (3.13)`.
> Admins are included. Force-push and deletion are blocked. Linear
> history is required. Required reviewers count is `0` — placeholder
> for the second-maintainer transition. Reproducible via
> `.github/scripts/apply-branch-protection.sh`.

| Trigger event | What changes |
|---|---|
| **Today (solo, protected)** | Required CI status checks (`test (3.10/.11/.12/.13)`), block force-push, block deletion, linear history, include administrators, require conversation resolution. Required reviewers = 0. |
| **First public push (repo flips public)** | Enable **Private vulnerability reporting** at <https://github.com/ni5h4nt/sigmalint/settings/security_analysis>. This feature is not available for personal-account private repos and the setting is genuinely absent from the UI until the repo is public. `SECURITY.md` cites the GitHub advisories URL as a secondary path; that URL only resolves once PVR is enabled. |
| **First external PR merged** | No protection change required. Confirm `CONTRIBUTING.md` and the PR template are sufficient for a non-maintainer's first encounter. |
| **Second maintainer joins** | Flip required reviewers `0 → 1`. Enable Code-Owner enforcement, "dismiss stale reviews on new push", and "require approval of most-recent reviewable push". Add new maintainer to `MAINTAINERS.md` and `CODEOWNERS`. |
| **v1.0 cut** | Require signed commits. Restrict pushes to `main` to maintainers only (no admin override). Lock the public JSON output shape and rule-ID universe per `docs/versioning.md`. |

The transition from solo to two-maintainer is the lowest-friction one:

```bash
gh api -X PATCH \
  /repos/ni5h4nt/sigmalint/branches/main/protection/required_pull_request_reviews \
  -f required_approving_review_count=1 \
  -f require_code_owner_reviews=true \
  -f dismiss_stale_reviews=true \
  -f require_last_push_approval=true
```

One command, no migration.

## Review-time expectations

A maintainer review on a new contributor's PR is targeted at 7 days. If
no maintainer responds within 7 days, contributors are explicitly
invited (in `PULL_REQUEST_TEMPLATE.md`) to ping the PR. We are a small
team and PRs can get lost.
