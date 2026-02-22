import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import {
   loadIdentity,
   getPublicKey,
   encrypt,
   decryptString,
   identityExists,
   getDefaultKeyPath,
} from "./age.js"
import { withLock, writeAtomicRaw } from "./parse.js"
import { VaultError, IdentityNotFoundError } from "./errors.js"
import { sanitizePath, ensureSafeDir, safeReadFile } from "./filesystem.js"
import { validateKey, validateValue } from "./validators.js"

const SECENV_DIR = ".secenvs"
const VAULT_FILE = "vault.age"

let vaultCache: Map<string, string> | null = null
let vaultLastMtime: number = 0
let vaultLastSize: number = 0

export function getVaultPath(): string {
   const baseDir = process.env.SECENV_HOME || os.homedir()
   const sanitizedBase = sanitizePath(baseDir)
   return path.join(sanitizedBase, SECENV_DIR, VAULT_FILE)
}

/**
 * Decrypts and loads the global vault into memory.
 * Caches the result after the first successful load.
 */
export async function loadVault(): Promise<Map<string, string>> {
   if (vaultCache) {
      return vaultCache
   }

   const vaultPath = getVaultPath()
   if (!fs.existsSync(vaultPath)) {
      vaultCache = new Map()
      vaultLastMtime = 0
      vaultLastSize = 0
      return vaultCache
   }

   // 1. Check for staleness
   try {
      const stats = fs.statSync(vaultPath)
      if (vaultCache && stats.mtimeMs === vaultLastMtime && stats.size === vaultLastSize) {
         return vaultCache
      }
      vaultLastMtime = stats.mtimeMs
      vaultLastSize = stats.size
   } catch (error) {
      // If we can't stat, force reload
   }

   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }

   const identity = await loadIdentity()
   try {
      const encrypted = safeReadFile(vaultPath)
      const decrypted = await decryptString(identity, encrypted)

      const map = new Map<string, string>()
      const lines = decrypted.split("\n")
      for (const line of lines) {
         const trimmed = line.trim()
         if (!trimmed || trimmed.startsWith("#")) continue

         const eqIndex = trimmed.indexOf("=")
         if (eqIndex !== -1) {
            const key = trimmed.slice(0, eqIndex).trim()
            const value = trimmed.slice(eqIndex + 1).trim()
            if (key) {
               map.set(key, value)
            }
         }
      }

      vaultCache = map
      return map
   } catch (error: any) {
      throw new VaultError(`Failed to load vault: ${error.message}`)
   }
}

/**
 * Re-encrypts and saves the vault to disk atomically.
 */
async function saveVault(data: Map<string, string>): Promise<void> {
   const vaultPath = getVaultPath()
   const vaultDir = path.dirname(vaultPath)

   ensureSafeDir(vaultDir)

   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }

   const identity = await loadIdentity()
   const pubkey = await getPublicKey(identity)

   // Format as KEY=VALUE
   let content = ""
   for (const [key, value] of data.entries()) {
      content += `${key}=${value}\n`
   }

   try {
      const encrypted = await encrypt([pubkey], content)
      await writeAtomicRaw(vaultPath, encrypted)
      // Enforce restrictive permissions
      await fs.promises.chmod(vaultPath, 0o600)

      vaultCache = data
      try {
         const stats = fs.statSync(vaultPath)
         vaultLastMtime = stats.mtimeMs
         vaultLastSize = stats.size
      } catch (e) {}
   } catch (error: any) {
      throw new VaultError(`Failed to save vault: ${error.message}`)
   }
}

export async function vaultGet(key: string): Promise<string | undefined> {
   const cache = await loadVault()
   return cache.get(key)
}

export async function vaultSet(key: string, value: string): Promise<void> {
   validateKey(key)
   validateValue(value)

   await withLock(getVaultPath(), async () => {
      // Reload under lock to be sure we have latest if another process wrote
      // Clearing cache first to force reload
      vaultCache = null
      const latest = await loadVault()
      latest.set(key, value)
      await saveVault(latest)
   })
}

export async function vaultDelete(key: string): Promise<void> {
   validateKey(key)

   await withLock(getVaultPath(), async () => {
      vaultCache = null
      const latest = await loadVault()
      if (latest.delete(key)) {
         await saveVault(latest)
      }
   })
}

export async function listVaultKeys(): Promise<string[]> {
   const cache = await loadVault()
   return Array.from(cache.keys())
}

/** Clear the in-memory cache (mainly for testing) */
export function clearVaultCache(): void {
   vaultCache = null
}
