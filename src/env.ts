import * as fs from "fs"
import * as path from "path"
import * as age from "age-encryption"
import { loadIdentity, identityExists, decrypt as decryptValue, getDefaultKeyPath } from "./age.js"
import { parseEnvFile, findKey, getEnvPath, ENCRYPTED_PREFIX, isVaultReference } from "./parse.js"
import { DecryptionError, SecretNotFoundError, IdentityNotFoundError, VaultError } from "./errors.js"
import { constantTimeHas } from "./crypto-utils.js"
import { vaultGet } from "./vault.js"

interface CacheEntry {
   value: string
   decryptedAt: number
}

class SecenvSDK {
   #identity: string | null = null
   #identityPromise: Promise<string> | null = null
   #cache: Map<string, CacheEntry> = new Map()
   #cacheTimestamp: number = 0
   #cacheSize: number = 0
   #parsedEnv: ReturnType<typeof parseEnvFile> | null = null
   #lastPath: string = ""

   get #envPath(): string {
      return path.resolve(getEnvPath())
   }

   constructor() {
      this.#cache = new Map()
   }

   private async loadIdentity(): Promise<string> {
      if (this.#identity) {
         return this.#identity
      }

      if (this.#identityPromise) {
         return this.#identityPromise
      }

      if (process.env.SECENV_ENCODED_IDENTITY) {
         const encoded = process.env.SECENV_ENCODED_IDENTITY.trim()

         // Detect URL-safe base64 or other invalid characters for our strict policy
         if (
            encoded.includes("-") ||
            encoded.includes("_") ||
            encoded.includes(" ") ||
            encoded.includes("\n") ||
            encoded.includes("\r")
         ) {
            throw new IdentityNotFoundError("SECENV_ENCODED_IDENTITY")
         }

         const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
         if (!base64Regex.test(encoded)) {
            throw new IdentityNotFoundError("SECENV_ENCODED_IDENTITY")
         }

         try {
            const decoded = Buffer.from(encoded, "base64")
            const privateKey = decoded.toString("utf-8")
            if (!privateKey.startsWith("AGE-SECRET-KEY-1")) {
               throw new Error("Invalid age identity")
            }
            this.#identity = privateKey
            return this.#identity
         } catch (error) {
            throw new IdentityNotFoundError("SECENV_ENCODED_IDENTITY")
         }
      }

      if (!identityExists()) {
         throw new IdentityNotFoundError(getDefaultKeyPath())
      }

      this.#identityPromise = loadIdentity().then((identity) => {
         this.#identity = identity
         this.#identityPromise = null
         return this.#identity
      })

      return this.#identityPromise
   }

   private reloadEnv(): void {
      const currentPath = this.#envPath

      // If the path changed (e.g. CWD change), clear cache and force reload
      if (currentPath !== this.#lastPath) {
         this.clearCache()
         this.#lastPath = currentPath
      }

      if (!fs.existsSync(currentPath)) {
         this.#parsedEnv = null
         this.#cache.clear()
         this.#cacheTimestamp = 0
         this.#cacheSize = 0
         return
      }

      const stats = fs.statSync(currentPath)
      const newTimestamp = stats.mtimeMs
      const newSize = stats.size

      if (newTimestamp !== this.#cacheTimestamp || newSize !== this.#cacheSize || !this.#parsedEnv) {
         this.#parsedEnv = parseEnvFile(currentPath)
         this.#cacheTimestamp = newTimestamp
         this.#cacheSize = newSize
         this.#cache.clear() // Clear cache when file changes
      }
   }

   async get<T extends string = string>(key: string): Promise<T> {
      // 1. Check process.env first (highest priority)
      let envValue: string | undefined = undefined
      for (const k in process.env) {
         if (k === key) {
            envValue = process.env[k]
         }
      }
      if (envValue !== undefined) {
         return envValue as T
      }

      this.reloadEnv()

      // Cache lookup - using true private field
      let cachedValue: string | undefined = undefined
      for (const [k, entry] of this.#cache.entries()) {
         if (k === key) {
            cachedValue = entry.value
         }
      }
      if (cachedValue !== undefined) {
         return cachedValue as T
      }

      if (!this.#parsedEnv) {
         throw new SecretNotFoundError(key)
      }

      const line = findKey(this.#parsedEnv, key)
      if (!line) {
         throw new SecretNotFoundError(key)
      }

      if (!line.encrypted) {
         const value = line.value

         // 4. Handle vault references in plaintext
         if (isVaultReference(value)) {
            const vaultKey = value.slice("vault:".length)
            const vaultValue = await vaultGet(vaultKey)
            if (vaultValue === undefined) {
               throw new VaultError(
                  `Vault key '${vaultKey}' referenced by '${key}' not found in global vault.`
               )
            }
            this.#cache.set(key, { value: vaultValue, decryptedAt: Date.now() })
            return vaultValue as T
         }

         this.#cache.set(key, { value, decryptedAt: Date.now() })
         return value as T
      }

      const identity = await this.loadIdentity()
      const encryptedMessage = line.value.slice(ENCRYPTED_PREFIX.length)
      const decrypted = await decryptValue(identity, encryptedMessage)
      const decryptedString = decrypted.toString("utf-8")

      this.#cache.set(key, { value: decryptedString, decryptedAt: Date.now() })

      // 5. Handle vault references if decrypted value starts with vault:
      if (isVaultReference(decryptedString)) {
         const vaultKey = decryptedString.slice("vault:".length)
         const vaultValue = await vaultGet(vaultKey)
         if (vaultValue === undefined) {
            throw new VaultError(`Vault key '${vaultKey}' referenced by '${key}' not found in global vault.`)
         }
         this.#cache.set(key, { value: vaultValue, decryptedAt: Date.now() })
         return vaultValue as T
      }

      return decryptedString as T
   }

   has(key: string): boolean {
      let found = false
      for (const k in process.env) {
         if (k === key) {
            found = true
         }
      }

      this.reloadEnv()
      if (this.#parsedEnv) {
         if (constantTimeHas(this.#parsedEnv.keys, key)) {
            found = true
         }
      }
      return found
   }

   keys(): string[] {
      const allKeys = new Set(Object.keys(process.env))
      this.reloadEnv()
      if (this.#parsedEnv) {
         for (const key of this.#parsedEnv.keys) {
            allKeys.add(key)
         }
      }
      return Array.from(allKeys)
   }

   toJSON(): Record<string, unknown> {
      return {}
   }

   clearCache(): void {
      this.#cache.clear()
      this.#cacheTimestamp = 0
      this.#cacheSize = 0
      this.#parsedEnv = null
   }
}

const globalSDK = new SecenvSDK()

function wrapInProxy(sdk: SecenvSDK): Secenv {
   return new Proxy(sdk, {
      get(target, prop) {
         const value = Reflect.get(target, prop)
         if (value !== undefined) {
            if (typeof value === "function") {
               return value.bind(target)
            }
            return value
         }
         if (typeof prop === "string") {
            return target.get(prop)
         }
         return value
      },
   }) as unknown as Secenv
}

export function createSecenv(): Secenv {
   return wrapInProxy(new SecenvSDK())
}

export const env = wrapInProxy(globalSDK)

export type Secenv = { [key: string]: Promise<string> } & SecenvSDK

export { SecenvSDK }
