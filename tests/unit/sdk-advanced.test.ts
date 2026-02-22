import { SecenvSDK, createSecenv } from "../../src/env.js"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { generateIdentity, saveIdentity, encrypt, getPublicKey } from "../../src/age.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe("SDK Advanced Features", () => {
   let testCwd: string
   let testHome: string
   let originalCwd: string
   let otherDir: string | null = null

   beforeEach(async () => {
      originalCwd = process.cwd()
      testCwd = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-sdk-adv-cwd-"))
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-sdk-adv-home-"))

      process.chdir(testCwd)
      process.env.SECENV_HOME = testHome

      const identity = await generateIdentity()
      await saveIdentity(identity)
   })

   afterEach(() => {
      // Ensure we're back to original cwd before cleanup
      try {
         process.chdir(originalCwd)
      } catch (e) {
         // If originalCwd was deleted, try to chdir to a safe place
         process.chdir(os.tmpdir())
      }

      delete process.env.SECENV_HOME

      try {
         fs.rmSync(testCwd, { recursive: true, force: true })
      } catch (e) {
         // Ignore cleanup errors
      }

      try {
         fs.rmSync(testHome, { recursive: true, force: true })
      } catch (e) {
         // Ignore cleanup errors
      }

      if (otherDir) {
         try {
            fs.rmSync(otherDir, { recursive: true, force: true })
         } catch (e) {
            // Ignore cleanup errors
         }
         otherDir = null
      }

      delete process.env.TEST_KEY
   })

   it("should detect CWD changes and clear cache", async () => {
      // Create first .secenvs in current directory
      fs.writeFileSync(".secenvs", "KEY1=value1\n")

      const sdk = createSecenv()
      expect(await sdk.get("KEY1")).toBe("value1")

      // Change to a different directory
      otherDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-sdk-other-"))
      process.chdir(otherDir)

      // Create different .secenvs here
      fs.writeFileSync(".secenvs", "KEY2=value2\n")

      // SDK should detect path change and read from new location
      // This tests the path change detection at lines 68-71
      expect(await sdk.get("KEY2")).toBe("value2")

      // Old value should not be accessible anymore
      expect(sdk.has("KEY1")).toBe(false)
   })

   it("toJSON should return empty object to prevent secret leakage", async () => {
      fs.writeFileSync(".secenvs", "SECRET=mysecret\n")
      const sdk = createSecenv()

      // toJSON is called by JSON.stringify
      const json = JSON.stringify(sdk)
      expect(json).toBe("{}")

      // Direct call should also return empty object
      expect(sdk.toJSON()).toEqual({})
   })

   it("should handle SECENV_ENCODED_IDENTITY with invalid base64", async () => {
      // First create a valid identity and encrypt a value
      const validIdentity = await generateIdentity()
      const validPubkey = await getPublicKey(validIdentity)
      const encrypted = await encrypt([validPubkey], "secret")

      // Set invalid base64
      process.env.SECENV_ENCODED_IDENTITY = "!!!invalid_base64!!!"

      // Remove the local identity file to force use of env var
      const keyPath = path.join(testHome, ".secenvs", "keys", "default.key")
      fs.unlinkSync(keyPath)

      fs.writeFileSync(".secenvs", `KEY=enc:age:${encrypted}\n`)
      const sdk = createSecenv()

      // Should throw IdentityNotFoundError when trying to decrypt with invalid identity
      // This tests the error handling at lines 46-48 in env.ts
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should handle SECENV_ENCODED_IDENTITY with valid base64 but invalid key", async () => {
      // Set valid base64 but invalid key content
      process.env.SECENV_ENCODED_IDENTITY = Buffer.from("not-a-valid-key").toString("base64")

      const identity = await generateIdentity()
      const pubkey = await getPublicKey(identity)
      const encrypted = await encrypt([pubkey], "secret")
      fs.writeFileSync(".secenvs", `ENC_KEY=enc:age:${encrypted}\n`)

      const sdk = createSecenv()

      // Should fail when trying to decrypt with invalid identity
      await expect(sdk.get("ENC_KEY")).rejects.toThrow()
   })
})
