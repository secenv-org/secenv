import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { generateIdentity, saveIdentity, getPublicKey, encrypt } from "../../src/age.js"
import {
   vaultGet,
   vaultSet,
   vaultDelete,
   listVaultKeys,
   clearVaultCache,
   getVaultPath,
} from "../../src/vault.js"
import { VaultError } from "../../src/errors.js"

describe("Vault Edge Cases", () => {
   let testHome: string
   let originalHome: string | undefined

   beforeEach(() => {
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-vault-edge-"))
      originalHome = process.env.SECENV_HOME
      process.env.SECENV_HOME = testHome
      clearVaultCache()
   })

   afterEach(async () => {
      process.env.SECENV_HOME = originalHome
      clearVaultCache()
      fs.rmSync(testHome, { recursive: true, force: true })
   })

   const setupIdentity = async () => {
      const identity = await generateIdentity()
      await saveIdentity(identity)
      return identity
   }

   it("should return empty map when vault file does not exist", async () => {
      await setupIdentity()
      // No vault file created — should return empty list
      const keys = await listVaultKeys()
      expect(keys).toEqual([])
   })

   it("should handle vault file with only comments (decrypts to comments only)", async () => {
      const identity = await setupIdentity()
      const pubkey = await getPublicKey(identity)

      const vaultPath = getVaultPath()
      fs.mkdirSync(path.dirname(vaultPath), { recursive: true })
      const encrypted = await encrypt([pubkey], "# This is a comment\n# Another comment\n")
      fs.writeFileSync(vaultPath, encrypted)
      clearVaultCache()

      const keys = await listVaultKeys()
      expect(keys).toEqual([])
   })

   it("should handle vault file with only newlines", async () => {
      const identity = await setupIdentity()
      const pubkey = await getPublicKey(identity)

      const vaultPath = getVaultPath()
      fs.mkdirSync(path.dirname(vaultPath), { recursive: true })
      const encrypted = await encrypt([pubkey], "\n\n\n")
      fs.writeFileSync(vaultPath, encrypted)
      clearVaultCache()

      const keys = await listVaultKeys()
      expect(keys).toEqual([])
   })

   it("should handle malformed vault with garbage content (not valid age ciphertext)", async () => {
      await setupIdentity()
      const vaultPath = getVaultPath()
      fs.mkdirSync(path.dirname(vaultPath), { recursive: true })
      fs.writeFileSync(vaultPath, "this is not valid encrypted content")

      await expect(listVaultKeys()).rejects.toThrow(VaultError)
   })

   it("should handle vault with truncated encrypted data", async () => {
      const identity = await setupIdentity()
      const pubkey = await getPublicKey(identity)

      const vaultPath = getVaultPath()
      fs.mkdirSync(path.dirname(vaultPath), { recursive: true })
      const encrypted = await encrypt([pubkey], "KEY=VALUE\n")
      const truncated = encrypted.slice(0, Math.floor(encrypted.length / 2))
      fs.writeFileSync(vaultPath, truncated)

      await expect(listVaultKeys()).rejects.toThrow(VaultError)
   })

   it("should handle vault with corrupted base64", async () => {
      await setupIdentity()
      const vaultPath = getVaultPath()
      fs.mkdirSync(path.dirname(vaultPath), { recursive: true })
      fs.writeFileSync(vaultPath, "not-valid-base64!!!")

      await expect(listVaultKeys()).rejects.toThrow(VaultError)
   })

   it("should handle value with equals sign in vault", async () => {
      await setupIdentity()
      await vaultSet("URL", "https://example.com?a=b&c=d")

      const value = await vaultGet("URL")
      expect(value).toBe("https://example.com?a=b&c=d")
   })

   it("should handle empty key in vault content gracefully", async () => {
      const identity = await setupIdentity()
      const pubkey = await getPublicKey(identity)

      const vaultPath = getVaultPath()
      fs.mkdirSync(path.dirname(vaultPath), { recursive: true })
      const encrypted = await encrypt([pubkey], "=VALUE\nVALID_KEY=abc\n")
      fs.writeFileSync(vaultPath, encrypted)
      clearVaultCache()

      const value = await vaultGet("VALID_KEY")
      expect(value).toBe("abc")
   })

   it("should handle duplicate keys in vault content (last wins)", async () => {
      const identity = await setupIdentity()
      const pubkey = await getPublicKey(identity)

      const vaultPath = getVaultPath()
      fs.mkdirSync(path.dirname(vaultPath), { recursive: true })
      const encrypted = await encrypt([pubkey], "KEY=first\nKEY=second\n")
      fs.writeFileSync(vaultPath, encrypted)
      clearVaultCache()

      const value = await vaultGet("KEY")
      expect(value).toBe("second")
   })

   it("should return undefined for non-existent key in vault", async () => {
      await setupIdentity()
      await vaultSet("EXISTING", "value")

      const value = await vaultGet("NON_EXISTENT")
      expect(value).toBeUndefined()
   })

   it("should handle unicode values in vault", async () => {
      await setupIdentity()
      await vaultSet("UNICODE_VAL", "hello_world_value")

      const value = await vaultGet("UNICODE_VAL")
      expect(value).toBe("hello_world_value")
   })

   it("should delete non-existent key without error", async () => {
      await setupIdentity()
      await vaultDelete("NON_EXISTENT")
   })

   it("should handle very long value in vault", async () => {
      await setupIdentity()
      const longValue = "x".repeat(10000)

      await vaultSet("LONG_VAL", longValue)

      const value = await vaultGet("LONG_VAL")
      expect(value).toBe(longValue)
   }, 30000)

   it("should preserve other keys when deleting one", async () => {
      await setupIdentity()
      await vaultSet("KEY1", "value1")
      await vaultSet("KEY2", "value2")
      await vaultSet("KEY3", "value3")

      await vaultDelete("KEY2")

      expect(await vaultGet("KEY1")).toBe("value1")
      expect(await vaultGet("KEY2")).toBeUndefined()
      expect(await vaultGet("KEY3")).toBe("value3")

      const keys = await listVaultKeys()
      expect(keys).toContain("KEY1")
      expect(keys).not.toContain("KEY2")
      expect(keys).toContain("KEY3")
   }, 30000)
})
