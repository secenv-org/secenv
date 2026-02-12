# secenv Phase 1: The Minimal Breeze Plan

Phase 1 focuses on the core "Zero Wrapper" developer experience with **local-only encryption**. The goal is to prove the resolution pipeline and the simplicity of single-recipient encryption without vault complexity.

## 1. Core Philosophy (Phase 1)

- **Identity over Passwords**: Authorized via a local `default.key`.
- **Single Source of Truth**: The `.env.enc` file serves as both storage and schema.
- **Process Environment First**: Runtime overrides take highest priority.
- **Zero Wrapper Dependency**: TypeScript apps use `import { env }` instead of shell wrappers.
- **No Vault**: All secrets are local-only in Phase 1.
- **Fail-Fast on Errors**: Malformed files throw immediately with line numbers.

## 2. Technical Specification

### The `.env.enc` Format

**NO recipient header in Phase 1** (implicit single recipient = `default.key`):

```env
DATABASE_URL=enc:age:AGEEncryptedBlob...
OPENAI_API_KEY=enc:age:AGEEncryptedBlob...
PORT=3000
NODE_ENV=development
```

**Format Rules:**

- `KEY=enc:age:...` - Encrypted value (decrypt with local key)
- `KEY=plaintext` - Unencrypted value (for non-sensitive config)
- **No header** in Phase 1
- **No multiline values** - Use `--base64` for certificates/keys

### The Resolution Pipeline (Corrected Order)

When `env.KEY` is accessed, the SDK resolves it in this order:

1. **Process Environment**: Check `process.env` for overrides (highest priority).
2. **Local Project**: Parse `./.env.enc`.
   - If plaintext: Return value.
   - If `enc:...`: Decrypt with local key and return.
3. **Error**: Throw `SecretNotFoundError` if key not found (no vault in Phase 1).

**Why Process First?** In production/CI, you want env vars to override everything. Local files should not be the strongest link.

### Binary Values

Secrets containing newlines (certificates, private keys) require special handling:

```bash
# Encode binary file as base64
$ secenv set TLS_CERT --base64 < server.crt

# Decrypt and output raw
$ secenv get TLS_CERT --base64
```

**Phase 1 Policy:** Reject multiline values. Use `--base64` flag explicitly.

## 3. Identity & Storage

- **Storage Location**:
  - Unix/Mac: `~/.secenv/keys/default.key`
  - Windows: `%USERPROFILE%\.secenv\keys\default.key`
- **File Permissions**: `600` (owner read/write only) on Unix/Mac.
- **Windows Note**: Store in encrypted volume (permissions not enforced).
- **Encryption Standard**: Single-recipient `age` encryption.
- **No Global Vault**: Phase 1 is local-only.

## 4. Phase 1 CLI Command Suite

| Command               | Description                                              |
| :-------------------- | :------------------------------------------------------ |
| `secenv init`         | Bootstrap identity and create `.env.enc`/`.gitignore`.  |
| `secenv set KEY VALUE`| Encrypt a value into `.env.enc` (primary method).       |
| `secenv set KEY`      | Interactive entry if VALUE not provided.                |
| `secenv get KEY`      | Decrypt and print a specific key value.                 |
| `secenv list`         | List all available key names (values hidden).           |
| `secenv delete KEY`   | Remove a key from `.env.enc`.                           |
| `secenv rotate KEY`   | Update a secret value and re-encrypt.                   |
| `secenv export`       | Dump all decrypted values (requires `--force`).         |
| `secenv doctor`       | Health check: identity, file integrity, decryption test.|

### Command Details

**`secenv set KEY VALUE` (Primary Method):**
```bash
$ secenv set OPENAI_API_KEY sk-12345
✓ Encrypted and stored in .env.enc
```

**`secenv set KEY` (Interactive Fallback):**
```bash
$ secenv set OPENAI_API_KEY
? Enter value: ********
✓ Encrypted and stored in .env.enc
```

**`secenv rotate KEY`:**
```bash
$ secenv rotate OPENAI_API_KEY
? Enter new value: ********
✓ Updated and re-encrypted in .env.enc
```

**`secenv export` (Requires --force):**
```bash
$ secenv export --force
⚠️  WARNING: You are about to export ALL secrets in PLAINTEXT.
This is DANGEROUS. Are you sure? (type "yes" to continue): yes
DATABASE_URL=postgres://...
OPENAI_API_KEY=sk-12345...
```

### `secenv doctor` Output (With Decryption Check)

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
4. **Identity can actually decrypt encrypted values** (catches wrong key scenario)

## 5. Phase 1 SDK Features

### The `env` Proxy

```typescript
import { env } from "secenv";

const dbUrl = env.DATABASE_URL; // Decrypts on first access
const apiKey = env.API_KEY;     // Cached in memory thereafter
```

**Behavior Specification:**

- **Lazy Decryption**: First access triggers decryption.
- **In-Memory Cache**: Decrypted values persist for app lifetime.
- **Error Handling**: Throws `SecretNotFoundError` if key missing.
- **CI/CD Support**: Detects `SECENV_ENCODED_IDENTITY` automatically.

### Error Types with Codes

```typescript
// Specific error types for programmatic handling
class IdentityNotFoundError extends SecenvError {
  code = 'IDENTITY_NOT_FOUND'
  message = 'Identity key not found. Run `secenv init`.'
}

class DecryptionError extends SecenvError {
  code = 'DECRYPTION_FAILED'
  message = 'Failed to decrypt value. Check identity key.'
}

class SecretNotFoundError extends SecenvError {
  code = 'SECRET_NOT_FOUND'
  message = 'Secret not found in .env.enc or process.env.'
}

class ParseError extends SecenvError {
  code = 'PARSE_ERROR'
  constructor(public line: number, public raw: string) {
    super(`Failed to parse .env.enc at line ${line}: ${raw}`)
  }
}
```

### CI/CD Support (Basic)

```typescript
// SDK boot logic - 5 lines of code
function loadIdentity(): Buffer {
  if (process.env.SECENV_ENCODED_IDENTITY) {
    return Buffer.from(process.env.SECENV_ENCODED_IDENTITY, 'base64')
  }
  return fs.readFileSync(path.join(os.homedir(), '.secenv/keys/default.key'))
}
```

## 6. Performance Targets (TBD)

Performance targets will be set **after implementation and benchmarking**.

| Metric                    | Target                                    |
| :------------------------ | :---------------------------------------- |
| First access (any key)    | TBD (measure after implementation)        |
| Subsequent access (cache) | O(1) hash lookup                          |
| Memory overhead           | Proportional to decrypted value sizes     |

## 7. Phase 1 Success Metrics

- **Setup Speed**: Can a developer encrypt a secret and use it in TypeScript in **< 90 seconds**?
- **Validation**: Does it successfully handle an OpenAI API key on a fresh repo with zero boilerplate?
- **Reliability**: Zero data loss or corruption in normal usage.
- **CI Ready**: Can a CI pipeline use `SECENV_ENCODED_IDENTITY` to decrypt?
- **Doctor Check**: Does `secenv doctor` verify decryption succeeds?

## 8. What's NOT in Phase 1

- Global Vault (`~/.secenv/vault.age`)
- `vault:` prefix and `secenv link`
- Multi-recipient header (`# secenv-recipients:`)
- Zod integration
- Migration engine (`secenv migrate`)
- Git pre-commit hooks
- `secenv run` polyglot wrapper

---

## 9. Phase 1 Implementation Checklist

### Implementation (Single Package)

**Shared Core (src/age.ts, src/parse.ts):**
- [ ] Age encryption/decryption wrappers
- [ ] .env.enc parser with line number tracking

**CLI (src/cli.ts):**
- [ ] `secenv init` - Generate key (600 perm), create `.env.enc`, update `.gitignore`
- [ ] `secenv set KEY VALUE` - Encrypt and append to `.env.enc`
- [ ] `secenv set KEY` - Interactive masked input, fallback
- [ ] `secenv get KEY` - Decrypt and print to stdout
- [ ] `secenv list` - Print key names only (one per line)
- [ ] `secenv delete KEY` - Remove key from `.env.enc`
- [ ] `secenv rotate KEY` - Update existing key value
- [ ] `secenv export` - Dump all decrypted (require `--force` + confirmation)
- [ ] `secenv doctor` - Check identity, file, syntax, AND test decryption

**SDK (src/env.ts):**
- [ ] `env` Proxy for lazy access
- [ ] Resolution: process.env → .env.enc → throw
- [ ] In-memory cache for decrypted values
- [ ] Error types with codes
- [ ] CI support via `SECENV_ENCODED_IDENTITY`

**Build & Packaging:**
- [ ] TypeScript compilation to /lib
- [ ] esbuild bundle for CLI binary
- [ ] package.json with both `bin` and `main` fields
- [ ] TypeScript type definitions (.d.ts)

### Infrastructure

- [ ] Atomic writes: Write to `.env.enc.tmp` → `fsync()` → `rename()`
- [ ] Cross-platform paths via `os.homedir()`
- [ ] File permissions `600` (Unix/Mac only)
- [ ] Parse error recovery with line numbers
- [ ] Reject multiline values (or require `--base64`)

### Testing

- [ ] Test on macOS, Linux, Windows, WSL
- [ ] Test corruption recovery
- [ ] Test concurrent access (two terminals)
- [ ] Benchmark performance
- [ ] Test with 0, 1, 10, 100, 1000 keys

---

## 10. File Format (Phase 1)

**CORRECT (NO HEADER):**
```env
DATABASE_URL=enc:age:AGE-SECRET-KEY-1XYZ...[encrypted_blob]
PORT=3000
NODE_ENV=development
```

**INCORRECT (Phase 2 only):**
```env
# secenv-recipients: age1xyz...
DATABASE_URL=enc:age:...
```

---

## 11. Package Structure

### Single Package, Dual Mode

`secenv` is a **single npm package** that works as both CLI and SDK.

**package.json:**
```json
{
  "name": "secenv",
  "version": "1.0.0",
  "bin": {
    "secenv": "./bin/secenv"
  },
  "main": "./lib/index.js",
  "exports": {
    "import": "./lib/index.js",
    "require": "./lib/index.cjs"
  }
}
```

**Directory Structure:**
```
/secenv
  /bin
    secenv              # CLI entrypoint
  /src
    /cli.ts             # CLI commands
    /env.ts             # SDK: env proxy
    /age.ts             # Shared: age encryption
    /parse.ts           # Shared: .env.enc parser
  /lib                  # Compiled output
  package.json
  tsconfig.json
```

**Technology Stack:**
- **Build**: TypeScript → Node.js bundle via esbuild (single binary)
- **Encryption**: `age` via TypeScript wrapper
- **SDK**: Native TypeScript, no runtime dependency

---

_Phase 1 goal: Ship a working local-only secret manager in 2 weeks. Prove the DX before adding vault complexity._
