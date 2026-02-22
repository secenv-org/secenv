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
} from "../../src/vault.js"
import { generateIdentity, saveIdentity } from "../../src/age.js"

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
