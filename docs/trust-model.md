# Trust Model & Social Security

`secenvs` relies on a combination of **strong cryptography** and **transparent version control** to manage
team access. This document explains how the trust model works and answers common security concerns.

## The Recipients Block (in `.secenvs`)

The recipient list is stored directly within the `.secenvs` file using the `_RECIPIENT` key.

- **Authoritative Source:** The CLI reads these metadata lines every time you run `secenvs set`, `rotate`, or
  `trust`.
- **Public Keys Only:** These lines contain no sensitive data. It is perfectly safe (and required) to commit
  the `.secenvs` file to Git to share access.

## Common Scenario: The "Snooping" Attempt

**Question:** _"If a developer is removed from the recipients but manually adds their public key back to the
file, will they regain access?"_

**Answer: No.**

### The Mechanism

Encryption is a physical transformation of data. When you "untrust" someone, the CLI re-encrypts every secret
in the `.secenvs` file using only the _remaining_ public keys.

1. **Re-encryption:** The data is physically wrapped into a new format that only authorized keys can open.
2. **The "List" vs. the "Data":** Even if an unauthorized person adds their key as a `_RECIPIENT` in
   `.secenvs`, the actual ciphertext strings for existing secrets were never made for them. Their private key
   will fail to open the lock because the physical lock doesn't recognize them.

## Social Security & Git

Because the recipient metadata is tracked in Git (within the `.secenvs` file), it falls under your standard
**Code Review** process.

### The Guardrail

If an attacker or a former team member tries to sneak their key back in, it will appear as a blatant addition
in your Git diff:

```diff
# .secenvs
  _RECIPIENT=age1pjh...
+ _RECIPIENT=age1attacker...
```

**Security Rule:** Never merge a Pull Request that adds a `_RECIPIENT` key unless you know exactly who that
public key belongs to. Treat these lines with the same level of scrutiny as your `CODEOWNERS` or `sudoers`
files.

## When does a key on the list get access?

A key in the recipients list only gains access to a secret when:

1. The secret is **newly created** while that key is in the list.
2. The secret is **rotated** or updated while that key is in the list.
3. A teammate runs `secenvs trust` (which triggers a full re-encryption for everyone on the list).

By ensuring all changes to the recipient list go through a Pull Request, you maintain a perfect audit trail of
who had access to what and when.

## Defense-in-Depth: Git Pre-Commit Hooks

While `secenvs` encrypts variables directly, accidents can still happen—such as inadvertently committing a
plaintext `.env` file containing temporary unencrypted credentials.

By running `secenvs install-hooks`, a pre-commit hook is deployed directly into your local `.git/hooks`
directory.

- **Proactive Blocking:** This hook scans the files included in your commit explicitly looking for hardcoded
  `# secenvs-plaintext` fallbacks or trailing `.env` files.
- **Fail-Safe Mechanism:** It will block the entire `git commit` transaction if a leak is detected,
  effectively providing an offline, local security barrier without relying on a remote CI pipeline to catch
  the mistake after the fact.
