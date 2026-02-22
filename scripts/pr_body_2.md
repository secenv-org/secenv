# Global Vault Integration (Phase 2 PR 2)

Enable cross-project secret sharing by storing shared secrets in a global vault (`~/.secenvs/vault.age`) and
referencing them in project-specific `.secenvs` files.

## Key Changes

### 🏦 Core Vault Logic (`src/vault.ts`)

- **Global Storage**: Implemented `vault.age` management in `$SECENV_HOME` (defaults to `~/.secenvs/`).
- **Atomic Operations**: Applied file locking and atomic rename patterns to ensure vault integrity under
  concurrent access.
- **In-Memory Caching**: Implemented caching for decrypted vault contents to minimize performance overhead.
- **Local Identity Encryption**: The vault is encrypted specifically for the user's local identity, making it
  a personal global store.

### 🚀 SDK Integration (`src/env.ts`, `src/parse.ts`)

- **`vault:` Resolution**: Enhanced `SecenvSDK.get()` to automatically resolve global references. This works
  for both plaintext and encrypted project secrets.
- **Performance**: Resolved vault values are cached in the SDK's primary secret cache.

### 🛠️ CLI Vault Management (`src/cli.ts`)

Added a new `vault` command group:

- `secenvs vault set <key> [value]` — Store a secret in the global vault.
- `secenvs vault get <key>` — Retrieve a secret from the vault.
- `secenvs vault list` — List all stored global keys.
- `secenvs vault delete <key>` — Remove a secret from the vault.

### ✅ Verification

- **Unit Tests**: `tests/unit/vault.test.ts` (8 tests) covering CRUD, persistence, and encryption.
- **Integration Tests**: `tests/integration/vault-references.test.ts` (6 tests) covering the full CLI-to-SDK
  flow.
- **Regression**: Verified stability across the existing 360+ tests.

---

Part of the **Phase 2: The Safety Net** roadmap.
