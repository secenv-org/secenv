# secenvs Phase 1: The Minimal Breeze

Phase 1 focuses on validating the **"Zero Wrapper"** developer experience with local-only encryption. The goal
is to prove that managing secrets can be as simple as using a standard `.env` file, but with the security of
`age` encryption.

## 1. Installation

```bash
# Install the CLI globally for setup and management
$ npm install -g secenvs

# Install the SDK in your TypeScript/JavaScript project
$ npm install secenvs
```

## 2. First-Time Setup

Initialize your identity. This only needs to be done once per machine.

```bash
$ secenvs init
✓ Created ~/.secenvs/keys/default.key (600 permissions)
✓ Created .secenvs in current directory
✓ Added .env to .gitignore
```

**Important**: Backup your `~/.secenvs/keys/default.key` immediately. Loss = data loss.

## 3. Project Workflow

### Adding Secrets

**Primary Method (one-liner):**

```bash
$ secenvs set DATABASE_URL postgres://localhost:5432/mydb
✓ Encrypted and stored in .secenvs
```

**Interactive Fallback (masked input):**

```bash
$ secenvs set OPENAI_API_KEY
? Enter value: *****...
✓ Encrypted and stored in .secenvs
```

**Non-sensitive values (plaintext):**

```bash
$ echo "PORT=3000" >> .secenvs
$ echo "NODE_ENV=development" >> .secenvs
```

### Retrieving Secrets (CLI)

```bash
# Get a specific key (decrypted)
$ secenvs get OPENAI_API_KEY
sk-proj-12345...

# List all keys (names only, values hidden)
$ secenvs list
DATABASE_URL
OPENAI_API_KEY
PORT
NODE_ENV
```

### Managing Secrets

```bash
# Update an existing secret
$ secenvs rotate OPENAI_API_KEY
? Enter new value: *****...
✓ Updated and re-encrypted in .secenvs

# Delete a secret
$ secenvs delete OBSOLETE_KEY
✓ Removed from .secenvs

# Export all secrets (requires --force + confirmation)
$ secenvs export --force
⚠️  WARNING: You are about to export ALL secrets in PLAINTEXT.
This is DANGEROUS. Are you sure? (type "yes" to continue): yes
DATABASE_URL=postgres://...
OPENAI_API_KEY=sk-...
```

### Health Check

```bash
$ secenvs doctor
✓ Identity: ~/.secenvs/keys/default.key (valid age key)
✓ File: .secenvs (readable, 4 keys, 2 encrypted)
✓ Syntax: All encrypted values parseable
✓ Decryption: Tested decrypt on 2 encrypted keys (SUCCESS)
```

**What doctor checks:**

1. Identity exists and is valid
2. `.secenvs` exists and is readable
3. Syntax is valid (no malformed lines)
4. **Identity can actually decrypt the encrypted values** (catches wrong key scenario)

**Note:** `doctor` doesn't know which keys are "required" (schema validation is Phase 2).

## 4. TypeScript SDK (The Magic)

The core value of Phase 1 is the **Zero Wrapper** execution. You don't need `secenvs run -- npm start`. Just
import and use.

```typescript
import { env } from "secenvs"

// The Proxy automatically resolves:
// 1. process.env (highest priority)
// 2. Local .secenvs (decrypted via ~/.secenvs/keys/default.key)

const dbUrl = env.DATABASE_URL
const apiKey = env.OPENAI_API_KEY

console.log(`Connecting to ${dbUrl}...`)
```

**SDK Behavior:**

- **Lazy Decryption**: First access triggers decryption.
- **In-Memory Cache**: Decrypted values persist for app lifetime.
- **Error Handling**: Throws `SecretNotFoundError` if key not found.
- **CI Support**: Detects `SECENV_ENCODED_IDENTITY` automatically.

**Error Handling:**

```typescript
import { env } from "secenvs"

try {
   const key = env.MISSING_KEY
} catch (e) {
   if (e.code === "SECRET_NOT_FOUND") {
      console.error("Secret not found! Check .secenvs")
   }
}
```

## 5. The `.secenvs` Format (Phase 1)

**NO recipient header** in Phase 1 (implicit single recipient = `default.key`). _Note: Phase 2 introduces the
unified format using `_RECIPIENT=key` lines._

```env
DATABASE_URL=enc:age:AGE-SECRET-KEY-1XYZ...[encrypted_blob]
OPENAI_API_KEY=enc:age:AGE-SECRET-KEY-1ABC...[encrypted_blob]
PORT=3000
NODE_ENV=development
# ^ Non-sensitive values stay plaintext
```

**Format Rules:**

- `KEY=enc:age:...` - Encrypted value (decrypt with local key)
- `KEY=plaintext` - Unencrypted (for non-sensitive config)
- **No header** in Phase 1 (Phase 2 uses `_RECIPIENT=` metadata)
- **No multiline values** - Use `--base64` for certificates/keys

**Binary Values:**

```bash
# Store certificate with newlines
$ secenvs set TLS_CERT --base64 < server.crt

# Retrieve raw
$ secenvs get TLS_CERT --base64
```

## 6. CI/CD Support

```bash
# Export your private key (base64 encoded)
$ secenvs key export-private
AGE-SECRET-KEY-1Q2W3E4R5T...

# Add to GitHub Actions Secrets as SECENV_ENCODED_IDENTITY
```

**GitHub Actions:**

```yaml
- name: Run with secrets
  env:
     SECENV_ENCODED_IDENTITY: ${{ secrets.SECENV_ENCODED_IDENTITY }}
  run: npm run start
```

## 7. Portability & Backup

Phase 1 keeps everything local for maximum simplicity.

```bash
# Backup your identity
cp ~/.secenvs/keys/default.key /secure/location/

# Restore on new machine
mkdir -p ~/.secenvs/keys
cp /secure/location/default.key ~/.secenvs/keys/
chmod 600 ~/.secenvs/keys/default.key
```

**Windows Note:** Store in an encrypted volume (file permissions not enforced).

## 8. What's NOT in Phase 1

Phase 1 is intentionally minimal:

- ❌ Global Vault (`~/.secenvs/vault.age`)
- ❌ `vault:` prefix and `secenvs link`
- ❌ Multi-recipient metadata (`_RECIPIENT=...`)
- ❌ Zod integration
- ❌ Migration from `.env`
- ❌ Team collaboration (`trust`/`untrust`)
- ❌ Polyglot wrapper (`secenvs run --`)
- ❌ Git pre-commit hooks

These are **Phase 2** features, all of which are now strictly implemented and live (see `README.md`).

---

## Phase 1 Success Criteria

**Can you:**

1. ✅ Install and initialize in < 30 seconds?
2. ✅ Encrypt a secret in one command (`secenvs set KEY VALUE`)?
3. ✅ Use the secret in TypeScript without wrappers?
4. ✅ Recover from a fresh clone in < 60 seconds?
5. ✅ Use in CI with `SECENV_ENCODED_IDENTITY`?
6. ✅ Verify decryption works with `secenvs doctor`?

If yes, Phase 1 is complete.
