#!/bin/bash
set -e

# Sync branch with origin
echo "Pushing branch feat/phase2-multi-recipient to origin..."
git push -u origin feat/phase2-multi-recipient

# Create PR via GH CLI using the body file
echo "Creating Pull Request..."
gh pr create \
  --title "feat: Multi-Recipient Encryption Foundation (Phase 2 PR 1)" \
  --body-file scripts/pr_body.md \
  --base main \
  --head feat/phase2-multi-recipient
