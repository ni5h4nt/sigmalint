# Contributing to sigmalint

Thanks for your interest. The most valuable contributions are **new
rules** and **rule improvements**.

## How to add a new rule

A new rule is four files. That's the whole contract.

1. **Write the rule class** in the appropriate dimension module under
   `src/sigmalint/rules/` (`attack.py`, `fp_risk.py`, `metadata.py`,
   `redundancy.py`, `schema.py`, `style.py`, or `taxonomy.py`).
   Subclass `core.rule.Rule`, decorate with `@register`, set `id`,
   `dimension`, `default_severity`, `summary`, and implement
   `check(parsed, ctx) -> Iterable[Finding]`.

2. **Write pass + fail fixtures** under
   `tests/fixtures/<RULE_ID>/{pass,fail}.yml`. Keep them minimal — the
   smallest Sigma rule that exercises the check.

3. **Add a one-line parametrize entry** to the corresponding
   `tests/unit/rules/test_<dimension>.py` so the fixtures run.

4. **Write the user-facing page** at `docs/rules/<RULE_ID>.md` using
   the template from any existing rule page (frontmatter + What it
   checks / Why / Bad / Good / Fix / References).

That's it. Open a PR — the PR template lists these four items as
checkboxes.

## Local dev quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pre-commit install
pytest -q
sigmalint lint tests/fixtures/SCHEMA003/pass.yml
```

## Quality gates

CI must pass on every PR:

- `pytest` with coverage >= 90%
- `ruff check` + `ruff format --check`
- `mypy src/`
- `lint-imports` (architectural layering)
- `sigmalint lint` on the in-repo fixture set (self-lint)

## Rule-ID conventions

- Dimension prefix + 3-digit number: `ATK001`, `META005`, `FP003`, …
- Letter suffix for closely-related splits: `META001a`, `META001b`.
- Once shipped, an ID is stable. See [docs/versioning.md](docs/versioning.md).

## New-rule proposals

Open an issue with `.github/ISSUE_TEMPLATE/new_rule_proposal.yml`
before writing code — it lets maintainers green-light the dimension,
severity, and check shape so your implementation work isn't wasted.

## Code of Conduct

Participation is governed by the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
