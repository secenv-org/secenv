#!/bin/bash
set -e

REPO="secenv-org/secenvs"
MILESTONE_TITLE="Phase 2: The Safety Net"

echo "Creating remaining issues for the roadmap..."

# 4. Git Hook Safety Net
gh issue create \
  --repo $REPO \
  --title "Phase 2 PR 4: Git Hook Safety Net" \
  --body "Implement a pre-commit hook that blocks plaintext \`.env\` files from being committed.

- Add hook installation/uninstallation logic.
- Add \`install-hooks\` CLI command.
- Prompt for hook installation during \`secenvs init\`." \
  --milestone "$MILESTONE_TITLE" \
  --label "enhancement"

# 5. Polyglot Runner
gh issue create \
  --repo $REPO \
  --title "Phase 2 PR 5: Polyglot Runner" \
  --body "Inject decrypted secrets into any subprocess (Python, Go, Ruby, shell scripts).

- Implement process runner with env injection.
- Add \`secenvs run -- <cmd>\` command." \
  --milestone "$MILESTONE_TITLE" \
  --label "enhancement"

# 6. Docs, Cleanup & Release
gh issue create \
  --repo $REPO \
  --title "Phase 2 PR 6: Docs, Cleanup & Release" \
  --body "Final integration task for Phase 2.

- Update documentation for all new CLI commands.
- Finalize Phase 2 roadmap in TIMELINE.md.
- Version bump and release." \
  --milestone "$MILESTONE_TITLE" \
  --label "documentation"

echo "Roadmap issues created."
echo "Linking existing PR #1 to the milestone..."
gh pr edit 1 --repo $REPO --milestone "$MILESTONE_TITLE"
