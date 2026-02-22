#!/bin/bash
set -e

REPO="secenv-org/secenvs"
MILESTONE_TITLE="Phase 2: The Safety Net"

echo "Creating milestone: $MILESTONE_TITLE..."
# Try to create milestone, ignore if it already exists
gh api repos/$REPO/milestones -f title="$MILESTONE_TITLE" -f description="Transitioning SECENVS into a team-ready secret management platform. Enhancing security for teams and polyglot environments." || echo "Milestone might already exist."

echo "Creating issues for the roadmap..."

# 2. Global Vault
gh issue create \
  --repo $REPO \
  --title "Phase 2 PR 2: Global Vault Integration" \
  --body "Enable cross-project secret sharing via \`~/.secenvs/vault.age\`.

- Implement vault storage and retrieval logic.
- Add \`vault:\` protocol support in the SDK.
- Add \`secenvs vault\` CLI commands.
- Add unit and integration tests." \
  --milestone "$MILESTONE_TITLE" \
  --label "enhancement"

# 3. Migration Engine
gh issue create \
  --repo $REPO \
  --title "Phase 2 PR 3: Migration Engine" \
  --body "Interactive \`.env\` → \`.secenvs\` conversion with dry-run support.

- Implement migration logic to parse existing environment files.
- Add interactive prompting for key resolution.
- Add \`secenvs migrate\` CLI command." \
  --milestone "$MILESTONE_TITLE" \
  --label "enhancement"

# 4. Git Hook Safety Net
gh issue create \
  --repo $REPO \
  --title "Phase 2 PR 4: Git Hook Safety Net" \
  --body "Implement a pre-commit hook that blocks plaintext \`.env\` files from being committed.

- Add hook installation/uninstallation logic.
- Add \`install-hooks\` CLI command.
- Prompt for hook installation during \`secenvs init\`." \
  --milestone "$MILESTONE_TITLE" \
  --label "security"

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

echo "Roadmap issues created and linked to milestone."
