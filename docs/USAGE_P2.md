# secenvs: Safety & Collaboration

Phase 2 introduces global vault integration, migration tools, team collaboration, and safety hooks to ensure
your secrets never leak.

## 1. Global Vault

Store secrets that need to be shared across multiple projects.

### Setup

The global vault is initialized automatically when you first use vault commands:

```bash
$ secenvs vault set STRIPE_LIVE_KEY sk_live_12345
✓ Stored in ~/.secenvs/vault.age
```

### Using Vault Secrets in Projects

Reference a vault secret in your project's `.secenvs` file:

```env
# .secenvs
STRIPE_API_KEY=vault:STRIPE_LIVE_KEY
```

**At runtime**, the SDK fetches `STRIPE_API_KEY` from your local global vault. This allows you to update your
Stripe key in one place and have it reflect across all projects on your machine.

### Vault Commands

```bash
# Store in vault (no local entry)
$ secenvs vault set STRIPE_KEY sk-...

# Get from vault
$ secenvs vault get STRIPE_KEY

# List all vault keys
$ secenvs vault list

# Delete from vault
$ secenvs vault delete STRIPE_KEY
```

## 2. Team Collaboration (Multi-Recipient)

Share secrets with teammates and servers using public keys. No shared passwords.

### Adding a Teammate

1. Ask your teammate for their public key:
   ```bash
   $ secenvs doctor # They run this to see their key
   age1alice123...
   ```
2. Add them to the project:
   ```bash
   $ secenvs trust age1alice123...
   ✓ Added key to .secenvs (2 total recipients)
   ✓ Re-encrypted all secrets
   ```
3. Commit and push. Alice can now decrypt `.secenvs` using her own private key.

### Removing Access

If a member leaves the team:

```bash
$ secenvs untrust age1alice123...
✓ Removed key from .secenvs (1 remaining)
✓ Re-encrypted all secrets with the updated recipient set
```

**Security Note:** When removing access, you should also rotate sensitive secrets (API keys, tokens) using
`secenvs rotate KEY` to ensure the ex-member can't use old values they may have captured.

## 3. Cryptographic Audit Log

Every state-changing operation (`set`, `delete`, `trust`, `untrust`) is automatically recorded in a
**cryptographically verifiable hash chain** within the `.secenvs` file.

```bash
$ secenvs log
Audit Log for Local Workspace (5 entries):

ST | TIMESTAMP                | ACTION     | KEY        | ACTOR
---|--------------------------|------------|------------|------------------------------------------------------------
✅ | 2026-02-23T10:00:00.320Z | INIT       | -          | age1alice...
✅ | 2026-02-23T10:05:00.120Z | SET        | API_KEY    | age1alice...
✅ | 2026-02-23T10:10:00.980Z | TRUST      | age1bob... | age1alice...
```

### Verification

- **Hash Chain**: Each entry contains a SHA-256 hash of the current entry plus the previous entry's hash.
- **TAMPER DETECTED**: If a file is edited manually or an entry is deleted, the CLI will display `❌` and exit
  with an error.

### Global Vault Audit

You can also inspect the audit trail for your global vault:

```bash
$ secenvs log --global
Audit Log for Global Vault (2 entries):
...
```

## 4. First-Class Deno 2 Support

Secenvs is built for the modern edge. It works natively in **Deno 2.x** with full TypeScript support and
secure permission handling.

```typescript
// main.ts
import { env } from "https://deno.land/x/secenvs/mod.ts"
const apiKey = await env.API_KEY
```

Run with standard Deno permissions:

```bash
$ deno run --allow-env --allow-read --allow-sys main.ts
```

## 5. Migration Engine

Migrate existing `.env` files to encrypted `.secenvs`.

```bash
$ secenvs migrate
Found 12 variables in .env

How would you like to handle 'DATABASE_URL'?
1) Encrypt locally in .secenvs (Default)
2) Move to global vault (~/.secenvs/vault.age)
3) Keep as plaintext in .secenvs
4) Skip
Select an option: 1

✓ Created .secenvs
✓ Original .env renamed to .env.bak
```

## 5. Git Safety Hooks

Prevent accidental leaks before they happen.

```bash
# Install safety hooks for the current repo
$ secenvs install-hooks
✓ Successfully installed secenvs pre-commit hook.
```

**What the hook blocks:**

- Commits containing `.env` files (including `.env.local`, `.env.prod`, etc.)
- Commits that would leak plaintext secrets.

## 6. Polyglot & Environment Injection

Use `secenvs` with any language or tool, even without a native SDK. This is the recommended way to use
`secenvs` for non-JavaScript projects (Python, Go, Rust, etc.).

```bash
# Inject secrets into a Python script
$ secenvs run -- python main.py

# Inject secrets into a Go app
$ secenvs run -- go run main.go

# Inject secrets into a npm script
$ secenvs run -- npm run staging
```

The command runs with all decrypted secrets available in its environment. Your code simply reads from standard
environment variables (e.g., `os.getenv("API_KEY")`).

## 7. Zod Integration

First-class support for type-safe configuration in TypeScript:

```typescript
import { z } from "zod"
import { createEnv } from "secenvs"

const env = await createEnv(
   z.object({
      DATABASE_URL: z.string().url(),
      PORT: z.coerce.number().default(3000),
      NODE_ENV: z.enum(["development", "production"]).default("development"),
   })
)

console.log(`Server running on port ${env.PORT}`)
```
