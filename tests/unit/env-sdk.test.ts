import { SecenvSDK, createSecenv } from "../../src/env.js"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { generateIdentity, saveIdentity, encrypt, getPublicKey } from "../../src/age.js"
import { SecretNotFoundError, IdentityNotFoundError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const PROJECT_ROOT = path.resolve(__dirname, "../..")

describe("Secenv SDK (env.ts)", () => {
   let testCwd: string
   let testHome: string
   let originalEnvHome: string | undefined
   let identity: string

   beforeEach(async () => {
      testCwd = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-sdk-cwd-"))
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-sdk-home-"))
      originalEnvHome = process.env.SECENV_HOME

      process.chdir(testCwd)
      process.env.SECENV_HOME = testHome

      identity = await generateIdentity()
      await saveIdentity(identity)
   })

   afterEach(() => {
      process.chdir(PROJECT_ROOT)
      process.env.SECENV_HOME = originalEnvHome
      fs.rmSync(testCwd, { recursive: true, force: true })
      fs.rmSync(testHome, { recursive: true, force: true })
      delete process.env.TEST_OVERRIDE
      delete process.env.TEST_KEY
      delete process.env.SECENV_ENCODED_IDENTITY
      delete process.env.PROC_KEY
      delete process.env.K1
   })

   it("should return value from process.env if present (priority 1)", async () => {
      process.env.TEST_KEY = "process-value"
      const sdk = createSecenv()

      const value = await sdk.get("TEST_KEY")
      expect(value).toBe("process-value")
   })

   it("should return plaintext value from .secenvs", async () => {
      fs.writeFileSync(".secenvs", "PLAIN_KEY=plaintext-value\n")
      const sdk = createSecenv()

      const value = await sdk.get("PLAIN_KEY")
      expect(value).toBe("plaintext-value")
   })

   it("should return decrypted value from .secenvs", async () => {
      const pubkey = await getPublicKey(identity)
      const encrypted = await encrypt([pubkey], "secret-value")
      fs.writeFileSync(".secenvs", `SECRET_KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      const value = await sdk.get("SECRET_KEY")
      expect(value).toBe("secret-value")
   })

   it("should throw SecretNotFoundError if key missing in both", async () => {
      fs.writeFileSync(".secenvs", "SOME_KEY=value\n")
      const sdk = createSecenv()

      await expect(sdk.get("MISSING_KEY")).rejects.toThrow(SecretNotFoundError)
   })

   it("should prioritize process.env over .secenvs", async () => {
      process.env.TEST_OVERRIDE = "overridden"
      fs.writeFileSync(".secenvs", "TEST_OVERRIDE=original\n")

      const sdk = createSecenv()
      const value = await sdk.get("TEST_OVERRIDE")
      expect(value).toBe("overridden")
   })

   it("should cache decrypted values", async () => {
      const pubkey = await getPublicKey(identity)
      const encrypted = await encrypt([pubkey], "cache-me")
      fs.writeFileSync(".secenvs", `CACHE_KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()

      // First call (decrypts)
      const val1 = await sdk.get("CACHE_KEY")
      expect(val1).toBe("cache-me")

      // Delete identity - if cached, second call should still work
      const keyPath = path.join(testHome, ".secenvs", "keys", "default.key")
      fs.unlinkSync(keyPath)

      const val2 = await sdk.get("CACHE_KEY")
      expect(val2).toBe("cache-me")
   })

   it("should invalidate cache if .secenvs is modified", async () => {
      fs.writeFileSync(".secenvs", "VAL=first\n")
      const sdk = createSecenv()

      expect(await sdk.get("VAL")).toBe("first")

      // Small delay to ensure mtime changes
      await new Promise((resolve) => setTimeout(resolve, 100))

      fs.writeFileSync(".secenvs", "VAL=second\n")

      expect(await sdk.get("VAL")).toBe("second")
   })

   it("should handle SECENV_ENCODED_IDENTITY in CI", async () => {
      const encoded = Buffer.from(identity).toString("base64")
      process.env.SECENV_ENCODED_IDENTITY = encoded

      // Remove local identity file to prove it uses the env var
      const keyPath = path.join(testHome, ".secenvs", "keys", "default.key")
      fs.unlinkSync(keyPath)

      const pubkey = await getPublicKey(identity)
      const encrypted = await encrypt([pubkey], "ci-secret")
      fs.writeFileSync(".secenvs", `CI_KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      const value = await sdk.get("CI_KEY")
      expect(value).toBe("ci-secret")
   })

   it("should throw IdentityNotFoundError if no identity available", async () => {
      const keyPath = path.join(testHome, ".secenvs", "keys", "default.key")
      fs.unlinkSync(keyPath)

      const pubkey2 = await getPublicKey(identity)
      const encrypted = await encrypt([pubkey2], "fails")
      fs.writeFileSync(".secenvs", `FAIL_KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      await expect(sdk.get("FAIL_KEY")).rejects.toThrow(IdentityNotFoundError)
   })

   it("has() should check both process.env and .secenvs", async () => {
      process.env.PROC_KEY = "val"
      fs.writeFileSync(".secenvs", "FILE_KEY=val\n")

      const sdk = createSecenv()
      expect(sdk.has("PROC_KEY")).toBe(true)
      expect(sdk.has("FILE_KEY")).toBe(true)
      expect(sdk.has("MISSING")).toBe(false)
   })

   it("keys() should return all keys", async () => {
      process.env.K1 = "v1"
      fs.writeFileSync(".secenvs", "K2=v2\nK3=v3\n")

      const sdk = createSecenv()
      const allKeys = sdk.keys()

      expect(allKeys).toContain("K1")
      expect(allKeys).toContain("K2")
      expect(allKeys).toContain("K3")
   })

   it("clearCache() should reset internal state", async () => {
      fs.writeFileSync(".secenvs", "KEY=val1\n")
      const sdk = createSecenv()

      await sdk.get("KEY")
      sdk.clearCache()

      fs.writeFileSync(".secenvs", "KEY=val2\n")
      expect(await sdk.get("KEY")).toBe("val2")
   })

   describe("Metadata Filtering", () => {
      it("get() should throw SecretNotFoundError for keys starting with _", async () => {
         fs.writeFileSync(".secenvs", "_RECIPIENT=age1xyz\nSECRET=val\n")
         const sdk = createSecenv()
         await expect(sdk.get("_RECIPIENT")).rejects.toThrow(SecretNotFoundError)
         expect(await sdk.get("SECRET")).toBe("val")
      })

      it("has() should return false for keys starting with _", () => {
         fs.writeFileSync(".secenvs", "_RECIPIENT=age1xyz\n")
         const sdk = createSecenv()
         expect(sdk.has("_RECIPIENT")).toBe(false)
      })

      it("keys() should not include keys starting with _", () => {
         fs.writeFileSync(".secenvs", "_RECIPIENT=age1xyz\nSECRET=val\n")
         const sdk = createSecenv()
         const keys = sdk.keys()
         expect(keys).toContain("SECRET")
         expect(keys).not.toContain("_RECIPIENT")
      })

      it("proxy access should throw SecretNotFoundError for keys starting with _", async () => {
         fs.writeFileSync(".secenvs", "_RECIPIENT=age1xyz\n")
         const sdk = createSecenv()
         const proxy: any = sdk
         await expect(proxy._RECIPIENT).rejects.toThrow(SecretNotFoundError)
      })
   })
})
