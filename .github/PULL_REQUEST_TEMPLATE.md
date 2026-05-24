## Summary

<!-- One or two sentences on what this PR changes. -->

## Type of change

- [ ] New rule
- [ ] Rule fix or refinement
- [ ] New CLI feature / flag
- [ ] Reference-data refresh
- [ ] Docs only
- [ ] CI / tooling

## Rule-authoring checklist (skip if not adding/changing a rule)

- [ ] Rule class added under `src/sigmalint/rules/<dimension>.py`
- [ ] Pass and fail fixtures added under `tests/fixtures/<RULE_ID>/`
- [ ] Parametrize entry added to the matching `tests/integration/test_rules_<dimension>.py`
- [ ] Per-rule doc added under `docs/rules/<RULE_ID>.md`
- [ ] Profile assignments reviewed in `src/sigmalint/core/profiles.py`

## Standard checks

- [ ] `sigmalint lint tests/fixtures/` (self-lint) passes
- [ ] `pytest --cov=sigmalint --cov-fail-under=90` passes
- [ ] `ruff check .` and `mypy src/sigmalint` clean
- [ ] CHANGELOG.md updated under the next-release section

## Notes for reviewers

<!-- Anything non-obvious about the approach, alternatives considered,
     or follow-up work this PR defers. -->
