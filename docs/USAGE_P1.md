# secenv Phase 1: The Minimal Breeze

Phase 1 focuses on validating the **"Zero Wrapper"** developer experience with local-only encryption. The goal is to prove that managing secrets can be as simple as using a standard `.env` file, but with the security of `age` encryption.

## 1. Installation

```bash
# Install the CLI globally for setup and management
$ npm install -g secenv

# Install the SDK in your TypeScript/JavaScript project
$ npm install secenv
```

## 2. First-Time Setup

Initialize your identity. This only needs to be done once per machine.

```bash
$ secenv init
✓ Created ~/.secenv/keys/default.key (600 permissions)
✓ Created .env.enc in current directory
✓ Added .env to .gitignore
```

**Important**: Backup your `~/.secenv/keys/default.key` immediately. Loss = data loss.

## 3. Project Workflow

### Adding Secrets

**Primary Method (one-liner):**

```bash
$ secenv set DATABASE_URL postgres://localhost:5432/mydb
✓ Encrypted and stored in .env.enc
```

**Interactive Fallback (masked input):**

```bash
$ secenv set OPENAI_API_KEY
? Enter value: *****...
✓ Encrypted and stored in .env.enc
```

**Non-sensitive values (plaintext):**

```bash
$ echo "PORT=3000" >> .env.enc
$ echo "NODE_ENV=development" >> .env.enc
```

### Retrieving Secrets (CLI)

```bash
# Get a specific key (decrypted)
$ secenv get OPENAI_API_KEY
sk-proj-12345...

# List all keys (names only, values hidden)
$ secenv list
DATABASE_URL
OPENAI_API_KEY
PORT
NODE_ENV
```

### Managing Secrets

```bash
# Update an existing secret
$ secenv rotate OPENAI_API_KEY
? Enter new value: *****...
✓ Updated and re-encrypted in .env.enc

# Delete a secret
$ secenv delete OBSOLETE_KEY
✓ Removed from .env.enc

# Export all secrets (requires --force + confirmation)
$ secenv export --force
⚠️  WARNING: You are about to export ALL secrets in PLAINTEXT.
This is DANGEROUS. Are you sure? (type "yes" to continue): yes
DATABASE_URL=postgres://...
OPENAI_API_KEY=sk-...
```

### Health Check

```bash
$ secenv doctor
✓ Identity: ~/.secenv/keys/default.key (valid age key)
✓ File: .env.enc (readable, 4 keys, 2 encrypted)
✓ Syntax: All encrypted values parseable
✓ Decryption: Tested decrypt on 2 encrypted keys (SUCCESS)
```

**What doctor checks:**
1. Identity exists and is valid
2. `.env.enc` exists and is readable
3. Syntax is valid (no malformed lines)
4. **Identity can actually decrypt the encrypted values** (catches wrong key scenario)

**Note:** `doctor` doesn't know which keys are "required" (schema validation is Phase 2).

## 4. TypeScript SDK (The Magic)

The core value of Phase 1 is the **Zero Wrapper** execution. You don't need `secenv run -- npm start`. Just import and use.

```typescript
import { env } from "secenv";

// The Proxy automatically resolves:
// 1. process.env (highest priority)
// 2. Local .env.enc (decrypted via ~/.secenv/keys/default.key)

const dbUrl = env.DATABASE_URL;
const apiKey = env.OPENAI_API_KEY;

console.log(`Connecting to ${dbUrl}...`);
```

**SDK Behavior:**

- **Lazy Decryption**: First access triggers decryption.
- **In-Memory Cache**: Decrypted values persist for app lifetime.
- **Error Handling**: Throws `SecretNotFoundError` if key not found.
- **CI Support**: Detects `SECENV_ENCODED_IDENTITY` automatically.

**Error Handling:**

```typescript
import { env } from "secenv";

try {
  const key = env.MISSING_KEY
} catch (e) {
  if (e.code === 'SECRET_NOT_FOUND') {
    console.error('Secret not found! Check .env.enc')
  }
}
```

## 5. The `.env.enc` Format (Phase 1)

**NO recipient header** in Phase 1 (implicit single recipient = `default.key`):

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
- **No header** in Phase 1
- **No multiline values** - Use `--base64` for certificates/keys

**Binary Values:**

```bash
# Store certificate with newlines
$ secenv set TLS_CERT --base64 < server.crt

# Retrieve raw
$ secenv get TLS_CERT --base64
```

## 6. CI/CD Support

```bash
# Export your private key (base64 encoded)
$ secenv key export-private
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
cp ~/.secenv/keys/default.key /secure/location/

# Restore on new machine
mkdir -p ~/.secenv/keys
cp /secure/location/default.key ~/.secenv/keys/
chmod 600 ~/.secenv/keys/default.key
```

**Windows Note:** Store in an encrypted volume (file permissions not enforced).

## 8. What's NOT in Phase 1

Phase 1 is intentionally minimal:

- ❌ Global Vault (`~/.secenv/vault.age`)
- ❌ `vault:` prefix and `secenv link`
- ❌ Multi-recipient header (`# secenv-recipients:`)
- ❌ Zod integration
- ❌ Migration from `.env`
- ❌ Team collaboration (`trust`/`untrust`)
- ❌ Polyglot wrapper (`secenv run --`)
- ❌ Git pre-commit hooks

These are Phase 2 features.

---

## Phase 1 Success Criteria

**Can you:**

1. ✅ Install and initialize in < 30 seconds?
2. ✅ Encrypt a secret in one command (`secenv set KEY VALUE`)?
3. ✅ Use the secret in TypeScript without wrappers?
4. ✅ Recover from a fresh clone in < 60 seconds?
5. ✅ Use in CI with `SECENV_ENCODED_IDENTITY`?
6. ✅ Verify decryption works with `secenv doctor`?

If yes, Phase 1 is complete.
