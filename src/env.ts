import * as fs from "fs"
import * as path from "path"
import * as age from "age-encryption"
import { loadIdentity, identityExists, decrypt as decryptValue, getDefaultKeyPath } from "./age.js"
import { parseEnvFile, findKey, getEnvPath, ENCRYPTED_PREFIX, isVaultReference } from "./parse.js"
import {
   DecryptionError,
   SecretNotFoundError,
   IdentityNotFoundError,
   VaultError,
   SchemaValidationError,
} from "./errors.js"
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
      if (!line || line.key.startsWith("_")) {
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
            // Do not cache vault-derived values in the project cache to avoid serving stale data if the vault changes.
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
         // Do not cache vault-derived values in the project cache to avoid serving stale data if the vault changes.
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
      if (this.#parsedEnv && !key.startsWith("_")) {
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
            if (!key.startsWith("_")) {
               allKeys.add(key)
            }
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

// --- Zod Schema Validation ---

/**
 * Validates the environment against a provided Zod schema.
 *
 * @param schema A Zod schema (e.g. `z.object({ ... })`)
 * @param options Configuration options. `strict` defaults to `true` (throws on error).
 * @returns A promise that resolves to the fully typed and validated environment object.
 */
export async function createEnv<T extends Record<string, any>>(
   schema: { parseAsync: (data: unknown) => Promise<T>; parse: (data: unknown) => T, safeParseAsync?: (data: unknown) => Promise<any>, safeParse?: (data: unknown) => any },
   options?: { strict?: true }
): Promise<T>

export async function createEnv<T extends Record<string, any>>(
   schema: { parseAsync: (data: unknown) => Promise<T>; parse: (data: unknown) => T, safeParseAsync?: (data: unknown) => Promise<any>, safeParse?: (data: unknown) => any },
   options: { strict: false }
): Promise<{ success: true; data: T } | { success: false; error: any }>

export async function createEnv<T extends Record<string, any>>(
   schema: { parseAsync: (data: unknown) => Promise<T>; parse: (data: unknown) => T, safeParseAsync?: (data: unknown) => Promise<any>, safeParse?: (data: unknown) => any },
   options: { strict?: boolean } = {}
): Promise<T | { success: true; data: T } | { success: false; error: any }> {
   const { strict = true } = options

   // We must dynamically import zod only if they use it, to avoid forcing the dependency
   let z: any
   try {
      // @ts-ignore - Ignore the TypeScript error for optional peer dependency
      z = await import("zod").then((m) => m.default || m)
   } catch (err) {
      throw new Error(
         "The 'zod' package is required to use createEnv. Please install it with 'npm install zod'."
      )
   }

   // 1. Wait, we don't need to try and extract `.shape` which breaks on `.refine()` (ZodEffects)
   // We can simply feed the *entire* available environment to Zod and let `.parse()` strip unrecognized keys.
   const rawEnv: Record<string, string | undefined> = {}

   // Combine `process.env` and `.secenvs` dynamically:
   const keys = env.keys()

   for (const key of keys) {
      try {
         rawEnv[key] = await env[key]
      } catch (error) {
         if (error instanceof SecretNotFoundError) {
            rawEnv[key] = undefined
         } else {
            throw error // Rethrow Vault/Decryption/File errors
         }
      }
   }

   // 3. Validate the gathered object against the schema
   if (strict === false) {
      // Return safe output object (mimicking SafeParseReturnType)
      try {
         const data = schema.safeParseAsync ? await schema.safeParseAsync(rawEnv) : schema.safeParse!(rawEnv)
         return data as { success: true; data: T } | { success: false; error: any }
      } catch (error) {
         // fallback if safeParse isn't cleanly implemented
         return { success: false, error }
      }
   }

   try {
      if (schema.parseAsync) {
         return (await schema.parseAsync(rawEnv)) as T
      }
      return schema.parse(rawEnv) as T
   } catch (error: any) {
      throw new SchemaValidationError("Environment schema validation failed.", error.issues || [])
   }
}
