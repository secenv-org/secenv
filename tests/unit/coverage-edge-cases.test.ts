import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
<<<<<<< HEAD
import { createEnv } from "../../src/env.js"
=======
import { createEnv, env, createSecenv } from "../../src/env.js"
>>>>>>> 8c329dc (Add comprehensive edge case tests to achieve 96.66% line coverage)
import { writeAtomicRaw, withLock, setKey, deleteKey } from "../../src/parse.js"
import { vaultSet, vaultGet, clearVaultCache } from "../../src/vault.js"
import { FileError } from "../../src/errors.js"
import { sanitizePath, ensureSafeDir } from "../../src/filesystem.js"
<<<<<<< HEAD
import { generateIdentity, saveIdentity } from "../../src/age.js"
=======
import { generateIdentity, saveIdentity, loadIdentity, encrypt, getPublicKey } from "../../src/age.js"
>>>>>>> 8c329dc (Add comprehensive edge case tests to achieve 96.66% line coverage)

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe("Edge Cases for 100% Coverage", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(async () => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-edge-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-edge-home-"))
      process.env.SECENV_HOME = secenvHome
      fs.mkdirSync(path.join(secenvHome, ".secenvs"), { recursive: true })

      // Setup identity
      const identity = await generateIdentity()
      await saveIdentity(identity)

      process.chdir(testDir)
   })

   afterEach(() => {
      process.chdir(__dirname)
      delete process.env.SECENV_HOME
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   it("should handle write error in writeAtomicRaw", async () => {
      const filePath = path.join(testDir, "readonly", "file")
      fs.mkdirSync(path.dirname(filePath))

      // Make directory readonly
      fs.chmodSync(path.dirname(filePath), 0o444)

      try {
         await expect(writeAtomicRaw(filePath, "content")).rejects.toThrow(FileError)
      } finally {
         fs.chmodSync(path.dirname(filePath), 0o755)
      }
   })

   it("should throw on symlink in sanitizePath", () => {
      const realFile = path.join(testDir, "real")
      fs.writeFileSync(realFile, "content")
      const symlinkPath = path.join(testDir, "symlink")
      fs.symlinkSync(realFile, symlinkPath)

      expect(() => sanitizePath(symlinkPath)).toThrow("Symlink detected")
   })

   it("should throw on symlink in ensureSafeDir", () => {
      const realDir = path.join(testDir, "realDir")
      fs.mkdirSync(realDir)
      const symlinkDir = path.join(testDir, "symlinkDir")
      fs.symlinkSync(realDir, symlinkDir)

      expect(() => ensureSafeDir(symlinkDir)).toThrow("Symlink detected")
   })

   it("should handle error in ensureSafeDir catch", () => {
      // Use an invalid path that causes fs.lstatSync to throw
      const invalidPath = path.join(testDir, "invalid\x00path") // Null byte to make it invalid

      expect(() => ensureSafeDir(invalidPath)).toThrow(FileError)
   })

   it("should update existing key in setKey", async () => {
      const filePath = path.join(testDir, "test.env")
      fs.writeFileSync(filePath, "KEY1=value1\nKEY2=value2\n")

      await setKey(filePath, "KEY1", "updated")

      const content = fs.readFileSync(filePath, "utf-8")
      expect(content).toContain("KEY1=updated")
      expect(content).toContain("KEY2=value2")
   })

   it("should delete key in deleteKey", async () => {
      const filePath = path.join(testDir, "test.env")
      fs.writeFileSync(filePath, "KEY1=value1\nKEY2=value2\n")

      await deleteKey(filePath, "KEY1")

      const content = fs.readFileSync(filePath, "utf-8")
      expect(content).not.toContain("KEY1=")
      expect(content).toContain("KEY2=value2")
   })

   it("should hit vault cache", async () => {
      // Set a vault key
      await vaultSet("TESTKEY", "testvalue")
      clearVaultCache()

      // First call loads
      await vaultGet("TESTKEY")

      // Second call should hit cache (line 51)
      const val = await vaultGet("TESTKEY")
      expect(val).toBe("testvalue")
   })

   it("should throw identity not found in saveVault", async () => {
      // Remove identity
      const keyPath = path.join(secenvHome, ".secenvs", "keys", "default.key")
      if (fs.existsSync(keyPath)) {
         fs.unlinkSync(keyPath)
      }

      // Try to set vault key
      await expect(vaultSet("KEY", "value")).rejects.toThrow("Identity key not found")
   })
<<<<<<< HEAD
=======

   it("should access proxy methods and properties", async () => {
      // Method access returns value (line 248)
      const keys = env.keys()
      expect(Array.isArray(keys)).toBe(true)

      // Property access calls target.get (line 253)
      await expect(env["nonexistent"]).rejects.toThrow("not found")
   })

   it("should access proxy methods and properties", async () => {
      // Method access returns value (line 248)
      const keys = env.keys()
      expect(Array.isArray(keys)).toBe(true)

      // Property access calls target.get (line 253)
      await expect(env["nonexistent"]).rejects.toThrow("not found")
   })

   it("should use schema.parse in createEnv", async () => {
      const schema = { parse: (data: any) => ({ test: "value" }) } as any
      const result = await createEnv(schema)
      expect(result).toEqual({ test: "value" })
   })
>>>>>>> 8c329dc (Add comprehensive edge case tests to achieve 96.66% line coverage)
})
