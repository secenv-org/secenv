# Product Roadmap & Timeline

Secenvs is being built in three distinct phases, moving from a single-player utility to a robust team
ecosystem.

## 🚀 Phase 1: The "Minimal Breeze" (Live)

**Goal:** Prove the "Zero Wrapper" developer experience with local-only encryption.  
**Status:** ✅ **Shipped (v1.0)**

We stripped secret management down to the absolute essentials. No servers, no complex config, just code.

### Core Features

- **Local Encryption:** Secrets are encrypted locally using `age` encryption.
- **Zero-Wrapper SDK:** Just `import { env } from 'secenvs'`. No `dotenv`, no wrappers.
- **Process Priority:** `process.env` always overrides local secrets (CI/CD friendly).
- **Basic CLI:** `init`, `set`, `get`, `rotate`, `doctor`.
- **CI Support:** Works with GitHub Actions via `SECENV_ENCODED_IDENTITY`.
- **Single Recipient:** Optimized for the solo developer.

---

## 🛡️ Phase 2: The "Safety Net" (Live)

**Goal:** Make secenvs the default choice for teams and production apps.  
**Focus:** Collaboration, Migration, and Mistakes-Prevention. **Status:** ✅ **Shipped (v0.2.0)**

### Shipped Features

- **Multi-Recipient Encryption (Unified Format):**
   - Manage recipients directly in `.secenvs` (no extra files).
   - alice and bob can decrypt with their own private keys.
- **Global Vault Integration:**
   - Store secrets once in `~/.secenvs/vault.age`.
   - Reference them across projects with `KEY=vault:stripe_live_key`.
- **Migration Engine:**
   - `secenvs migrate` to convert legacy `.env` files automatically.
   - Interactive prompts: "Keep local? Move to vault?"
- **Schema Validation:**
   - Native SDK `createEnv` wrapper for runtime validation via Zod.
- **Polyglot Support:**
   - `secenvs run -- python app.py` to seamlessly inject decrypted secrets into non-JS environments.
- **Git Hook Safety Nets:**
   - Pre-commit hooks via `secenvs install-hooks` to proactively block plaintext `.env` files from being
     committed.

---

## 🏢 Phase 3: The Ecosystem (Future)

**Goal:** Enterprise-grade security and frictionless adoption.  
**Focus:** compliance, auditing, and deep integration.

### Planned Features

- **Leak Detection:** `secenvs doctor --git-history` to scan your repo for past leaks.
- **VS Code Extension:**
   - Hover-to-reveal secrets.
   - One-click migration.
- **Cloud Sync:** patterns for syncing vaults via Dropbox/iCloud/Drive.
- **Advanced Security:**
   - Mandatory rotation policies.
   - Audit logging for secret access.

---

_This roadmap is subject to change based on community feedback. We build for real problems, not
hypotheticals._
