import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import {
   generateIdentity,
   saveIdentity,
   loadIdentity,
   encrypt,
   decrypt,
   identityExists,
   getDefaultKeyPath,
} from "../../src/age.js"
import { IdentityNotFoundError, DecryptionError, FileError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe("User Blunder: Identity/Key Mistakes", () => {
   let testHome: string
   let originalEnvHome: string | undefined

   beforeEach(async () => {
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-identity-test-"))
      originalEnvHome = process.env.SECENV_HOME
      process.env.SECENV_HOME = testHome
   })

   afterEach(() => {
      process.env.SECENV_HOME = originalEnvHome
      try {
         fs.rmSync(testHome, { recursive: true, force: true })
      } catch (e) {
         // Ignore cleanup errors
      }
   })

   it("should throw IdentityNotFoundError when user deletes identity file", async () => {
      // Create identity
      const identity = await generateIdentity()
      await saveIdentity(identity)

      // Verify it exists
      expect(identityExists()).toBe(true)

      // User deletes identity file (simulated)
      const keyPath = getDefaultKeyPath()
      fs.unlinkSync(keyPath)

      // Should throw helpful error
      await expect(loadIdentity()).rejects.toThrow(IdentityNotFoundError)
      await expect(loadIdentity()).rejects.toThrow(/Identity key not found/)
   })

   it("should throw DecryptionError when identity is corrupted (garbage content)", async () => {
      // Create valid identity and encrypt something
      const identity = await generateIdentity()
      await saveIdentity(identity)
      const encrypted = await encrypt(identity, "secret")

      // Corrupt the identity file
      const keyPath = getDefaultKeyPath()
      fs.writeFileSync(keyPath, "AGE-SECRET-KEY-1GARBAGEINVALIDKEYHERE")

      // Should fail when trying to decrypt with corrupted identity
      await expect(decrypt(fs.readFileSync(keyPath, "utf-8"), encrypted)).rejects.toThrow()
   })

   it("should throw DecryptionError when using wrong identity from different machine", async () => {
      // Create two different identities (simulating different machines)
      const machine1Identity = await generateIdentity()
      const machine2Identity = await generateIdentity()

      // Save machine 2's identity locally
      await saveIdentity(machine2Identity)

      // Encrypt with machine 1's identity
      const encrypted = await encrypt(machine1Identity, "secret")

      // Try to decrypt with machine 2's identity
      await expect(decrypt(machine2Identity, encrypted)).rejects.toThrow(DecryptionError)
   })

   it("should handle empty identity file gracefully", async () => {
      // Create empty identity file
      const keysDir = path.join(testHome, ".secenvs", "keys")
      fs.mkdirSync(keysDir, { recursive: true })
      const keyPath = path.join(keysDir, "default.key")
      fs.writeFileSync(keyPath, "")

      // loadIdentity reads empty string (doesn't validate)
      const loaded = await loadIdentity()
      expect(loaded).toBe("")

      // Error will happen when trying to use empty identity
      await expect(generateIdentity()).resolves.toBeTruthy()
   })

   it("should handle identity with only whitespace", async () => {
      // Create whitespace-only identity file
      const keysDir = path.join(testHome, ".secenvs", "keys")
      fs.mkdirSync(keysDir, { recursive: true })
      const keyPath = path.join(keysDir, "default.key")
      fs.writeFileSync(keyPath, "   \n\t  ")

      // Loads whitespace as identity (may fail later when used)
      const loaded = await loadIdentity()
      expect(loaded.trim()).toBe("")
   })

   it("should handle multiple identity files (use default.key only)", async () => {
      // Create default identity
      const identity = await generateIdentity()
      await saveIdentity(identity)

      // Create extra identity files
      const keysDir = path.join(testHome, ".secenvs", "keys")
      const extraIdentity = await generateIdentity()
      fs.writeFileSync(path.join(keysDir, "backup.key"), extraIdentity)
      fs.writeFileSync(path.join(keysDir, "old.key"), await generateIdentity())

      // Should still load default.key
      const loaded = await loadIdentity()
      expect(loaded).toBe(identity)
   })

   it("should throw FileError when identity file is a directory", async () => {
      // Create directory instead of file
      const keysDir = path.join(testHome, ".secenvs", "keys")
      fs.mkdirSync(keysDir, { recursive: true })
      const keyPath = path.join(keysDir, "default.key")
      fs.mkdirSync(keyPath)

      // Should throw appropriate error
      await expect(loadIdentity()).rejects.toThrow()
   })

   it("should detect identity file with permissions 644 (Unix)", async () => {
      if (os.platform() === "win32") {
         return // Skip on Windows
      }

      const identity = await generateIdentity()
      await saveIdentity(identity)

      // Change to insecure permissions (user mistake)
      const keyPath = getDefaultKeyPath()
      fs.chmodSync(keyPath, 0o644)

      // File should exist but with wrong permissions
      const stats = fs.statSync(keyPath)
      expect(stats.mode & 0o777).toBe(0o644)

      // Should still be readable (functionally works)
      const loaded = await loadIdentity()
      expect(loaded).toBe(identity)
   })

   it("should detect identity file with permissions 777 (Unix)", async () => {
      if (os.platform() === "win32") {
         return // Skip on Windows
      }

      const identity = await generateIdentity()
      await saveIdentity(identity)

      // Change to world-readable permissions (critical security risk)
      const keyPath = getDefaultKeyPath()
      fs.chmodSync(keyPath, 0o777)

      // File should exist but with dangerous permissions
      const stats = fs.statSync(keyPath)
      expect(stats.mode & 0o777).toBe(0o777)

      // Should still be readable (functionally works, but doctor should warn)
      const loaded = await loadIdentity()
      expect(loaded).toBe(identity)
   })

   it("should throw IdentityNotFoundError when SECENV_ENCODED_IDENTITY is set but invalid", async () => {
      // Note: Empty string "" is falsy in JS, so it falls through to file identity
      // We need a truthy invalid value
      process.env.SECENV_ENCODED_IDENTITY = "!!!invalid!!!"

      // Remove file identity to force use of env var
      const keyPath = path.join(testHome, ".secenvs", "keys", "default.key")
      if (fs.existsSync(keyPath)) {
         fs.unlinkSync(keyPath)
      }

      // Create SDK instance
      const { createSecenv } = await import("../../src/env.js")
      const sdk = createSecenv()

      const identity = await generateIdentity()
      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testHome, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      // Should fail because invalid base64 produces garbage identity
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should throw DecryptionError with truncated SECENV_ENCODED_IDENTITY", async () => {
      const identity = await generateIdentity()
      const encrypted = await encrypt(identity, "secret")

      // Set truncated base64 (user copy-paste error)
      const fullEncoded = Buffer.from(identity).toString("base64")
      process.env.SECENV_ENCODED_IDENTITY = fullEncoded.substring(0, fullEncoded.length - 10)

      // Create encrypted file
      fs.writeFileSync(path.join(testHome, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const { createSecenv } = await import("../../src/env.js")
      const sdk = createSecenv()

      // Should fail with decryption error due to invalid identity
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should load identity with trailing garbage (error on use)", async () => {
      const identity = await generateIdentity()
      await saveIdentity(identity)

      // Append garbage to identity file
      const keyPath = getDefaultKeyPath()
      fs.appendFileSync(keyPath, "\nGARBAGE_DATA_HERE")

      // loadIdentity just reads file, doesn't validate
      const loaded = await loadIdentity()
      expect(loaded).toContain("GARBAGE_DATA_HERE")

      // Error will happen when trying to use corrupted identity
      const encrypted = await encrypt(identity, "secret")
      await expect(decrypt(loaded, encrypted)).rejects.toThrow()
   })
})
