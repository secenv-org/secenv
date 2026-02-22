# Multi-Recipient Encryption Foundation (Phase 2 PR 1)

Establishing the foundation for multi-recipient encryption. This allows secrets to be encrypted for multiple team members simultaneously, enabling secure collaboration without sharing private keys.

## Key Changes

### 🔐 Core Crypto (`src/age.ts`, `src/errors.ts`)
- **Multi-Recipient `encrypt()`**: Updated the core encryption function to accept an array of age public keys.
- **Recipient Management**:
  - `loadRecipients(projectDir)`: Reads public keys from `.secenvs.recipients`.
  - `saveRecipients(projectDir, keys)`: Writes public keys to `.secenvs.recipients`.
  - `validatePublicKey(key)`: Ensures public keys follow the `age1...` bech32 format.
- **Backward Compatibility**: Projects without a `.secenvs.recipients` file automatically fall back to the local identity's public key, maintaining Phase 1 functionality.
- **Error Handling**: Added `RecipientError` for specific recipient-related failures (e.g., invalid keys, removing last recipient).

### 🛠️ CLI Enhancements (`src/cli.ts`)
- **`secenvs trust <pubkey>`**: Adds a new recipient to the project and automatically re-encrypts all existing secrets for the new recipient set.
- **`secenvs untrust <pubkey>`**: Removes a recipient and re-encrypts all secrets. Includes a guard to prevent removing the last recipient.
- **`secenvs set`**: Now automatically encrypts for all trusted recipients.

### ✅ Verification & Tests
- **New Unit Tests**: `tests/unit/recipients.test.ts` covers public key validation, multi-recipient encrypt/decrypt logic, and recipient file I/O (19 tests).
- **New Integration Tests**: `tests/integration/trust-untrust.test.ts` validates the full CLI flow, including re-encryption and cross-identity decryption (9 tests).
- **Regression Testing**: Updated and verified all 360 existing tests to support the new internal encryption signature.

---
Part of the **Phase 2: The Safety Net** roadmap.
