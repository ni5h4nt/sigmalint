#!/usr/bin/env bash
# Apply main-branch protection. Runs successfully only after the repo is
# public OR upgraded to GitHub Pro. See docs/maintainers.md for context.

set -euo pipefail

REPO="${REPO:-ni5h4nt/sigmalint}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "Applying branch protection to ${REPO}:main"
gh api -X PUT "/repos/${REPO}/branches/main/protection" \
  --input "${HERE}/branch-protection.json"
echo "Done. Current state:"
gh api "/repos/${REPO}/branches/main/protection" | jq '{required_status_checks, enforce_admins, required_linear_history, allow_force_pushes, allow_deletions, required_conversation_resolution}'
