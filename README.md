# secenvs

**Make `.env` secure again. Commit to GitHub without fear.**

Follow the journey on X: [@YogeshDev215](https://x.com/YogeshDev215) 🚀

secenvs encrypts your environment variables so you can safely commit them to version control. It's `.env` you
can actually share—without the security headaches.

## Why secenvs?

- **Zero wrapper needed** — Import and use secrets directly in your code
- **Team-friendly** — Peer-to-peer encryption for multiple recipients
- **Cross-project vault** — Share shared secrets (like Stripe/AWS keys) across all your projects
- **Lightning fast** — Cold start <50ms, cached access <1ms
- **Battle-tested encryption** — AEAD encryption via [age](https://github.com/FiloSottile/age)
- **CI/CD ready** — Works seamlessly with GitHub Actions and other pipelines
- **Defense-first** — Private fields prevent memory-scanning attacks

## Quick Start

### Runtime

Support for **Node.js** and **Bun**.

```bash
# Install
npm install secenvs

# Initialize (one-time setup)
npx secenvs init

# Add a secret
npx secenvs set API_KEY "your-secret-key"

# Use in code
import { env } from 'secenvs';

const apiKey = await env.API_KEY;
```

## CLI Commands

You can run commands directly with `npx secenvs <command>` or by installing globally.

```bash
secenvs init              # Initialize identity and project
secenvs set KEY VALUE     # Set a secret (encrypted)
secenvs get KEY           # Get a secret (decrypted)
secenvs list              # List all keys
secenvs rotate KEY        # Rotate a secret
secenvs delete KEY        # Delete a secret
secenvs trust PUBKEY      # Add a team member (recipient)
secenvs untrust PUBKEY    # Remove a team member
secenvs vault <cmd>       # Global vault (set, get, list, delete)
secenvs migrate [file]    # Migrate an existing .env file
secenvs run -- <cmd>      # Inject secrets into any subprocess (Python, Go, etc.)
secenvs install-hooks     # Install git pre-commit hooks to block plaintext .env files
secenvs uninstall-hooks   # Remove the git pre-commit hooks
secenvs doctor            # Verify setup and encryption
secenvs key export        # Export private key for CI
```

## SDK Usage

### Proxy-Based Access

The `env` export is a **Proxy object**. It:

1. Intercepts property access (e.g., `env.API_KEY`)
2. Checks `process.env` first (high priority)
3. Falls back to encrypted values in `.secenvs` (low priority)
4. Throw if the key is missing entirely (strict mode)

```typescript
import { env } from "secenvs"

// Access like a normal object property
const dbUrl = await env.DATABASE_URL
const apiKey = await env.API_KEY
```

### Fallback to process.env

The SDK checks `process.env` first, then falls back to your `.secenvs` file:

```typescript
// In production, set DATABASE_URL in your deployment platform
// Locally, use .secenvs
const dbUrl = await env.DATABASE_URL
```

### Error Handling

```typescript
import { env, SecretNotFoundError } from "secenvs"

try {
   const key = await env.MISSING_KEY
} catch (e) {
   if (e instanceof SecretNotFoundError) {
      console.error("Secret not found in .secenvs")
   }
}
```

### Schema Validation (Zod)

`secenvs` provides built-in support for validating your environment at runtime using Zod. This guarantees type
safety and catches missing configuration immediately.

```bash
# Zod is an optional peer dependency
npm install zod
```

```typescript
import { z } from "zod"
import { createEnv } from "secenvs"

// Define your schema (z.object is required)
const schema = z.object({
   DATABASE_URL: z.string().url(),
   PORT: z.coerce.number().default(3000),
   NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
})

// Eagerly decrypt and validate.
// 'env' is fully typed and synchronous going forward!
export const env = await createEnv(schema)

// Use fully typed variables safely
console.log(`Starting server on port ${env.PORT} in ${env.NODE_ENV}`)
```

Set `{ strict: false }` to handle the `SafeParseReturnType` manually instead of throwing an error:
`await createEnv(schema, { strict: false })`

### Programmatic API

```typescript
import { createSecenv } from "secenvs"

const sdk = await createSecenv()
await sdk.set("API_KEY", "secret-value")
const value = await sdk.get("API_KEY")
```

## The `.secenvs` File

Store secrets in `.secenvs` in your project root:

```env
# Encrypted values (auto-decrypted)
API_KEY=enc:age:AGE-SECRET-KEY-1XYZ...

# Plaintext values (non-sensitive config)
PORT=3000
NODE_ENV=development
```

Use `--base64` flag for binary values like certificates:

```bash
secenvs set TLS_CERT --base64 < server.crt
```

## Team Sharing (Multi-Recipient)

`secenvs` supports **Multi-Recipient Encryption**. This means you can encrypt secrets so that multiple team
members can decrypt them with their own unique private keys.

### Adding a Team Member

```bash
# Get your colleague's age public key
secenvs trust age1pjh...

# This adds the key to .secenvs as metadata and
# re-encrypts all project secrets for both of you.
```

### Removing a Team Member

```bash
secenvs untrust age1pjh...
```

The `.secenvs` file (containing encrypted secrets and recipient metadata) is committed to your repository so
the project always knows who is authorized to manage secrets.

## Global Vault (Cross-Project Secrets)

Stop copy-pasting your Stripe API key into every project. Store it once in your **Global Vault** and reference
it anywhere.

### 1. Store a global secret

```bash
secenvs vault set STRIPE_KEY "sk_live_..."
```

### 2. Reference it in your project

In your project's `.secenvs` or `.env` file:

```env
# .secenvs
STRIPE_API_KEY=vault:STRIPE_KEY
```

### 3. Automatic Resolution

The SDK resolves `vault:` references at runtime. It's completely transparent to your code:

```typescript
const stripeKey = await env.STRIPE_API_KEY // Returns the decrypted value from the vault
```

The vault is stored at `~/.secenvs/vault.age` and is encrypted specifically for your local identity. It never
leaves your machine.

## Polyglot Support (Non-JS Languages)

`secenvs` isn't just for Node.js. Use the native cross-platform CLI runner to seamlessly inject decrypted
secrets into **any** subprocess, script, or language (Python, Go, Rust, Ruby, Docker).

```bash
secenvs run -- python app.py
secenvs run -- go run main.go
secenvs run -- npm run dev
```

Under the hood, `secenvs` securely spawns the process with the decrypted values injected straight into memory.
Your code simply reads from standard environment variables (e.g., `os.environ['API_KEY']`), keeping your
non-JS codebase 100% wrapper-free.

## Git Hook Safety Net

Never accidentally commit a plaintext `.env` file to your repository again.

```bash
# Install the secenvs pre-commit hook
secenvs install-hooks

# To remove the hook later
secenvs uninstall-hooks
```

This installs a lightweight, native Git pre-commit hook that actively scans your commits and blocks the
transaction if it detects any hardcoded `.env` files trying to leak into your Git history.

## CI/CD Integration

### 1. Export your identity

```bash
secenvs key export
```

### 2. Add to CI secrets

Add the output as `SECENV_ENCODED_IDENTITY` in your CI provider (GitHub Secrets, etc.).

### 3. Use in CI

```yaml
# GitHub Actions example
- name: Run app
  env:
     SECENV_ENCODED_IDENTITY: ${{ secrets.SECENV_ENCODED_IDENTITY }}
  run: npm run start
```

## Security

- **AEAD encryption** — Each secret is encrypted separately with age
- **Private fields** — JavaScript private class fields protect against memory-scanning
- **Constant-time lookups** — Prevents timing attacks
- **Symlink protection** — Blocks symlink attacks

For deeper technical details and the educational breakdown of our security model, see our documentation:

- [Trust Model & Social Security](./docs/trust-model.md) — How we handle team access and manual edits.
- [How It Works](./docs/how-it-works.md) — Under the hood of the encryption and SDK resolution.
- [Full Security Overview](./SECURITY.md) — Formal security posture and threat model.

## Requirements

- Node.js 18+
- No external dependencies (age encryption bundled)

## License

MIT
