import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import {
   vaultSet,
   vaultGet,
   vaultDelete,
   listVaultKeys,
   clearVaultCache,
   getVaultPath,
   loadVault,
} from "../../src/vault.js"
import { generateIdentity, saveIdentity } from "../../src/age.js"
import { VaultError, IdentityNotFoundError } from "../../src/errors.js"

describe("Vault Unit Tests", () => {
   let testHome: string
   let originalEnvHome: string | undefined

   beforeEach(async () => {
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-vault-test-"))
      originalEnvHome = process.env.SECENV_HOME
      process.env.SECENV_HOME = testHome

      // Setup identity
      const identity = await generateIdentity()
      await saveIdentity(identity)

      clearVaultCache()
   })

   afterEach(() => {
      process.env.SECENV_HOME = originalEnvHome
      try {
         fs.rmSync(testHome, { recursive: true, force: true })
      } catch (e) {}
   })

   it("should set and get a vault value", async () => {
      await vaultSet("MY_TOKEN", "secret-token")
      expect(await vaultGet("MY_TOKEN")).toBe("secret-token")
   })

   it("should persist vault values between loads", async () => {
      await vaultSet("PERSISTENT", "value123")

      // Clear cache and reload
      clearVaultCache()
      expect(await vaultGet("PERSISTENT")).toBe("value123")
   })

   it("should list all keys in the vault", async () => {
      await vaultSet("A", "1")
      await vaultSet("B", "2")
      await vaultSet("C", "3")

      const keys = await listVaultKeys()
      expect(keys.sort()).toEqual(["A", "B", "C"])
   })

   it("should delete a key from the vault", async () => {
      await vaultSet("TO_DELETE", "gone")
      expect(await vaultGet("TO_DELETE")).toBe("gone")

      await vaultDelete("TO_DELETE")
      expect(await vaultGet("TO_DELETE")).toBeUndefined()

      const keys = await listVaultKeys()
      expect(keys).not.toContain("TO_DELETE")
   })

   it("should return undefined for missing keys", async () => {
      expect(await vaultGet("NON_EXISTENT")).toBeUndefined()
   })

   it("should handle empty vault list", async () => {
      expect(await listVaultKeys()).toEqual([])
   })

   it("should store the vault file in the expected location", () => {
      const vaultPath = getVaultPath()
      expect(vaultPath).toBe(path.join(testHome, ".secenvs", "vault.age"))
   })

   it("should encrypt the vault file (not plaintext)", async () => {
      await vaultSet("SENSITIVE", "very-secret")
      const vaultPath = getVaultPath()
      const content = fs.readFileSync(vaultPath, "utf-8")
      const decoded = Buffer.from(content, "base64").toString("utf-8")
      expect(decoded).toContain("age-encryption.org/v1")
      expect(decoded).not.toContain("very-secret")
   })
})

describe("Vault loadVault() Direct Tests", () => {
   let testHome: string
   let originalEnvHome: string | undefined

   beforeEach(async () => {
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-loadvault-test-"))
      originalEnvHome = process.env.SECENV_HOME
      process.env.SECENV_HOME = testHome

      const identity = await generateIdentity()
      await saveIdentity(identity)

      clearVaultCache()
   })

   afterEach(() => {
      process.env.SECENV_HOME = originalEnvHome
      try {
         fs.rmSync(testHome, { recursive: true, force: true })
      } catch (e) {}
   })

   it("should return empty map when vault file does not exist", async () => {
      // No vault file created — should return empty map, not throw
      const map = await loadVault()
      expect(map).toBeInstanceOf(Map)
      expect(map.size).toBe(0)
   })

   it("should return populated map after vaultSet", async () => {
      await vaultSet("LOAD_KEY", "load-value")
      clearVaultCache()

      const map = await loadVault()
      expect(map.get("LOAD_KEY")).toBe("load-value")
   })

   it("should return cached map on repeated calls without clearing", async () => {
      await vaultSet("CACHED", "abc")
      clearVaultCache()

      const map1 = await loadVault()
      const map2 = await loadVault()
      // Same reference — returned from cache
      expect(map1).toBe(map2)
   })

   it("should reload from disk after clearVaultCache()", async () => {
      await vaultSet("FIRST", "one")
      clearVaultCache()
      const map1 = await loadVault()
      expect(map1.get("FIRST")).toBe("one")

      // Write a second value and force cache clear
      await vaultSet("SECOND", "two")
      clearVaultCache()
      const map2 = await loadVault()
      expect(map2.get("SECOND")).toBe("two")
   })

   it("should throw VaultError when vault file is corrupt (invalid ciphertext)", async () => {
      // Write garbage directly as the vault file
      const vaultPath = getVaultPath()
      const vaultDir = path.dirname(vaultPath)
      fs.mkdirSync(vaultDir, { recursive: true })
      fs.writeFileSync(vaultPath, "this-is-not-valid-age-ciphertext")
      clearVaultCache()

      await expect(loadVault()).rejects.toThrow(VaultError)
   })

   it("should throw IdentityNotFoundError when vault exists but no identity", async () => {
      // First store something so the vault file exists
      await vaultSet("EXISTS", "val")

      // Now point to a home without an identity
      const emptyHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-no-identity-"))
      process.env.SECENV_HOME = emptyHome

      // Copy the vault file to the new home's path so it "exists" there
      // (we just need to test the identity-not-found branch)
      const vaultPath = getVaultPath()
      const vaultDir = path.dirname(vaultPath)
      fs.mkdirSync(vaultDir, { recursive: true })
      // Write an invalid placeholder so the file exists
      fs.writeFileSync(vaultPath, "placeholder")

      clearVaultCache()

      try {
         await expect(loadVault()).rejects.toThrow(IdentityNotFoundError)
      } finally {
         process.env.SECENV_HOME = testHome
         fs.rmSync(emptyHome, { recursive: true, force: true })
      }
   })

   it("should handle vault with multiple entries correctly", async () => {
      await vaultSet("ALPHA", "a")
      await vaultSet("BETA", "b")
      await vaultSet("GAMMA", "c")
      clearVaultCache()

      const map = await loadVault()
      expect(map.get("ALPHA")).toBe("a")
      expect(map.get("BETA")).toBe("b")
      expect(map.get("GAMMA")).toBe("c")
      expect(map.size).toBe(3)
   })

   it("should return undefined for keys not in the vault", async () => {
      const map = await loadVault()
      expect(map.get("NONEXISTENT")).toBeUndefined()
   })
})
