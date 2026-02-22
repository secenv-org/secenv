import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { execa } from "execa"
import { createSecenv, SecenvSDK } from "../../src/env.js"
import { clearVaultCache } from "../../src/vault.js"
import { SecretNotFoundError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("SDK Cache Consistency", () => {
   let testDir: string
   let secenvHome: string
   let originalHome: string | undefined
   let originalCwd: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-sdk-cache-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-sdk-home-"))
      originalHome = process.env.SECENV_HOME
      originalCwd = process.cwd()
      process.env.SECENV_HOME = secenvHome
      process.chdir(testDir)
      clearVaultCache()
   })

   afterEach(() => {
      process.chdir(originalCwd)
      process.env.SECENV_HOME = originalHome
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const runCLI = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })
   }

   it("should detect file changes via mtime", async () => {
      await runCLI(["init"])
      await runCLI(["set", "KEY1", "value1"])

      const env = createSecenv() as SecenvSDK
      const val1 = await env.get("KEY1")
      expect(val1).toBe("value1")

      await runCLI(["set", "KEY1", "value2"])

      const val2 = await env.get("KEY1")
      expect(val2).toBe("value2")
   })

   it("should detect file changes via size", async () => {
      await runCLI(["init"])
      await runCLI(["set", "KEY", "short"])

      const env = createSecenv() as SecenvSDK
      const val1 = await env.get("KEY")
      expect(val1).toBe("short")

      await runCLI(["set", "KEY", "much longer value that changes size"])

      const val2 = await env.get("KEY")
      expect(val2).toBe("much longer value that changes size")
   })

   it("should clear cache when file is deleted", async () => {
      await runCLI(["init"])
      await runCLI(["set", "KEY", "value"])

      const env = createSecenv() as SecenvSDK
      expect(await env.get("KEY")).toBe("value")

      fs.unlinkSync(path.join(testDir, ".secenvs"))

      await expect(env.get("KEY")).rejects.toThrow(SecretNotFoundError)
   })

   it("should clear cache when file is created after not existing", async () => {
      await runCLI(["init"])

      const env = createSecenv() as SecenvSDK

      await expect(env.get("NEW_KEY")).rejects.toThrow(SecretNotFoundError)

      await runCLI(["set", "NEW_KEY", "newvalue"])

      const val = await env.get("NEW_KEY")
      expect(val).toBe("newvalue")
   })

   it("should not serve stale cache after clearCache()", async () => {
      await runCLI(["init"])
      await runCLI(["set", "CACHE_KEY", "original"])

      const env = createSecenv() as SecenvSDK
      expect(await env.get("CACHE_KEY")).toBe("original")

      env.clearCache()

      await runCLI(["set", "CACHE_KEY", "updated"])

      expect(await env.get("CACHE_KEY")).toBe("updated")
   })

   it("should handle has() correctly after key deletion", async () => {
      await runCLI(["init"])
      await runCLI(["set", "TO_DELETE", "value"])

      const env = createSecenv() as SecenvSDK
      expect(env.has("TO_DELETE")).toBe(true)

      await runCLI(["delete", "TO_DELETE"])

      expect(env.has("TO_DELETE")).toBe(false)
   })

   it("should filter metadata keys from keys()", async () => {
      await runCLI(["init"])
      await runCLI(["set", "USER_KEY", "value"])

      const env = createSecenv() as SecenvSDK
      const allKeys = env.keys()

      expect(allKeys).toContain("USER_KEY")
      expect(allKeys).not.toContain("_RECIPIENT")
   })

   it("should prioritize process.env over .secenvs", async () => {
      await runCLI(["init"])
      await runCLI(["set", "OVERRIDE_TEST", "from-file"])

      const env = createSecenv() as SecenvSDK

      process.env.OVERRIDE_TEST = "from-env"

      try {
         const val = await env.get("OVERRIDE_TEST")
         expect(val).toBe("from-env")
      } finally {
         delete process.env.OVERRIDE_TEST
      }
   })

   it("should handle has() for process.env keys", async () => {
      const env = createSecenv() as SecenvSDK

      process.env.UNIQUE_TEST_KEY_12345 = "exists"

      try {
         expect(env.has("UNIQUE_TEST_KEY_12345")).toBe(true)
      } finally {
         delete process.env.UNIQUE_TEST_KEY_12345
      }
   })

   it("should handle keys() including process.env", async () => {
      const env = createSecenv() as SecenvSDK

      process.env.SECENV_TEST_KEY_123 = "test"

      try {
         const allKeys = env.keys()
         expect(allKeys).toContain("SECENV_TEST_KEY_123")
      } finally {
         delete process.env.SECENV_TEST_KEY_123
      }
   })

   it("should handle get on key that was never in file", async () => {
      await runCLI(["init"])

      const env = createSecenv() as SecenvSDK

      await expect(env.get("NEVER_EXISTED")).rejects.toThrow(SecretNotFoundError)
   })

   it("should handle concurrent reads while file is being modified", async () => {
      await runCLI(["init"])
      await runCLI(["set", "CONCURRENT_KEY", "initial"])

      const env = createSecenv() as SecenvSDK

      const readPromises = [env.get("CONCURRENT_KEY"), env.get("CONCURRENT_KEY"), env.get("CONCURRENT_KEY")]

      await runCLI(["set", "CONCURRENT_KEY", "updated"])

      const results = await Promise.all(readPromises)
      const uniqueResults = new Set(results)

      expect(uniqueResults.size).toBe(1)
   }, 10000)
})
