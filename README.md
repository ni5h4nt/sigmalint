# sigmalint

ESLint-style linter for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.

Validates against Sigma 2.1.0, scores rules across six quality dimensions (ATT&CK alignment, taxonomy correctness, false-positive risk, metadata completeness, redundancy with the public corpus, and style), and emits findings with stable rule IDs.

> **Status:** v0.1 in development. See `docs/superpowers/specs/2026-05-23-sigmalint-design.md` and `docs/plans/2026-05-23-sigmalint-v0.1.md`.

## Quickstart (preview)

```bash
pip install sigmalint
sigmalint lint rules/
```

This README is a placeholder; final polish ships in Phase 21 with badges, sample output, GitHub Action usage, and the SoK paper citation.
