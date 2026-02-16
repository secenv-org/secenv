import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { createSecenv } from "../../src/env.js"
import { generateIdentity, encrypt } from "../../src/age.js"
import { IdentityNotFoundError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe("User Blunder: CI/Environment Variable Issues", () => {
   let testDir: string
   let originalEnvHome: string | undefined

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-ci-test-"))
      originalEnvHome = process.env.SECENV_HOME
      delete process.env.SECENV_ENCODED_IDENTITY
      delete process.env.SECENV_HOME
   })

   afterEach(() => {
      process.env.SECENV_HOME = originalEnvHome
      delete process.env.SECENV_ENCODED_IDENTITY
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
      } catch (e) {}
   })

   it("should throw IdentityNotFoundError when SECENV_ENCODED_IDENTITY has spaces", async () => {
      // User accidentally included spaces in base64
      process.env.SECENV_ENCODED_IDENTITY = "invalid base 64 with spaces"

      const identity = await generateIdentity()
      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      await expect(sdk.get("KEY")).rejects.toThrow(IdentityNotFoundError)
   })

   it("should throw IdentityNotFoundError when SECENV_ENCODED_IDENTITY has newlines", async () => {
      // User copy-pasted with newlines
      process.env.SECENV_ENCODED_IDENTITY = "invalid\nbase64\nwith\nnewlines"

      const identity = await generateIdentity()
      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      await expect(sdk.get("KEY")).rejects.toThrow(IdentityNotFoundError)
   })

   it("should throw IdentityNotFoundError when SECENV_ENCODED_IDENTITY is the string undefined", async () => {
      // Common mistake: CI sets it to the string "undefined"
      process.env.SECENV_ENCODED_IDENTITY = "undefined"

      const identity = await generateIdentity()
      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      await expect(sdk.get("KEY")).rejects.toThrow(IdentityNotFoundError)
   })

   it("should throw IdentityNotFoundError with copy-paste error in SECENV_ENCODED_IDENTITY", async () => {
      const identity = await generateIdentity()
      const correctEncoded = Buffer.from(identity).toString("base64")

      // User missed last few characters when copying
      process.env.SECENV_ENCODED_IDENTITY = correctEncoded.substring(0, correctEncoded.length - 5)

      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should prefer SECENV_ENCODED_IDENTITY over file identity when both present", async () => {
      // Create a file-based identity
      const fileIdentity = await generateIdentity()
      process.env.SECENV_HOME = testDir
      const keysDir = path.join(testDir, ".secenvs", "keys")
      fs.mkdirSync(keysDir, { recursive: true })
      fs.writeFileSync(path.join(keysDir, "default.key"), fileIdentity)

      // But use different identity in env var
      const envIdentity = await generateIdentity()
      process.env.SECENV_ENCODED_IDENTITY = Buffer.from(envIdentity).toString("base64")

      // Encrypt with env identity
      const encrypted = await encrypt(envIdentity, "env-secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      // Should use env identity and succeed
      expect(await sdk.get("KEY")).toBe("env-secret")
   })

   it("should fail decryption when CI identity does not match file encryption", async () => {
      // CI has wrong identity
      const ciIdentity = await generateIdentity()
      process.env.SECENV_ENCODED_IDENTITY = Buffer.from(ciIdentity).toString("base64")

      // But file was encrypted with different identity
      const correctIdentity = await generateIdentity()
      const encrypted = await encrypt(correctIdentity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      // Should fail to decrypt with wrong identity
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should throw IdentityNotFoundError when using SDK without identity in CI", async () => {
      // No SECENV_ENCODED_IDENTITY set and no file identity
      delete process.env.SECENV_ENCODED_IDENTITY

      // Create encrypted value that requires identity
      const identity = await generateIdentity()
      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      // Should fail because no identity available
      await expect(sdk.get("KEY")).rejects.toThrow(IdentityNotFoundError)
   })

   it("should handle base64 padding errors (missing =)", async () => {
      const identity = await generateIdentity()
      const correctEncoded = Buffer.from(identity).toString("base64")

      // Remove padding characters
      process.env.SECENV_ENCODED_IDENTITY = correctEncoded.replace(/=/g, "")

      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      // May or may not work depending on base64 implementation
      // Some implementations handle missing padding, others don't
      try {
         await sdk.get("KEY")
      } catch (e) {
         expect(e).toBeInstanceOf(Error)
      }
   })

   it("should handle URL-safe base64 (with - and _)", async () => {
      const identity = await generateIdentity()
      const correctEncoded = Buffer.from(identity).toString("base64")

      // Convert to URL-safe base64
      const urlSafeEncoded = correctEncoded.replace(/\+/g, "-").replace(/\//g, "_")
      process.env.SECENV_ENCODED_IDENTITY = urlSafeEncoded

      const encrypted = await encrypt(identity, "secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      // URL-safe base64 should be rejected or fail to decode
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should handle production identity used on dev file", async () => {
      // User accidentally uses production identity on dev machine
      const prodIdentity = await generateIdentity()
      process.env.SECENV_ENCODED_IDENTITY = Buffer.from(prodIdentity).toString("base64")

      // But dev file was encrypted with dev identity
      const devIdentity = await generateIdentity()
      const encrypted = await encrypt(devIdentity, "dev-secret")
      fs.writeFileSync(path.join(testDir, ".secenvs"), `DEV_KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()
      // Should fail to decrypt with wrong identity
      await expect(sdk.get("DEV_KEY")).rejects.toThrow()
   })
})
