#!/bin/bash
set -e

# Sync branch with origin
echo "Pushing branch feat/phase2-global-vault to origin..."
git push -u origin feat/phase2-global-vault

# Create PR via GH CLI using the body file
echo "Creating Pull Request..."
gh pr create \
  --title "feat: Global Vault Integration (Phase 2 PR 2)" \
  --body-file scripts/pr_body_2.md \
  --base feat/phase2-multi-recipient \
  --head feat/phase2-global-vault \
  --milestone "Phase 2: The Safety Net"
