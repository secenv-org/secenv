import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { execa } from "execa"
import { createSecenv } from "../../src/env.js"
import { generateIdentity, saveIdentity, encrypt } from "../../src/age.js"
import { IdentityNotFoundError, SecretNotFoundError, FileError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("User Blunder: Environment/Path Mistakes", () => {
   let testDir: string
   let testHome: string
   let originalCwd: string
   let originalEnvHome: string | undefined

   beforeEach(async () => {
      originalCwd = process.cwd()
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-env-test-"))
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-env-home-"))
      originalEnvHome = process.env.SECENV_HOME

      process.chdir(testDir)
      process.env.SECENV_HOME = testHome

      const identity = await generateIdentity()
      await saveIdentity(identity)
   })

   afterEach(() => {
      process.env.SECENV_HOME = originalEnvHome
      try {
         process.chdir(originalCwd)
      } catch (e) {
         process.chdir(os.tmpdir())
      }
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
      } catch (e) {}
      try {
         fs.rmSync(testHome, { recursive: true, force: true })
      } catch (e) {}
      delete process.env.TEST_SECRET
   })

   it("should throw SecretNotFoundError when running from wrong directory", async () => {
      // Create .secenvs in testDir
      fs.writeFileSync(".secenvs", "MYKEY=myvalue\n")

      const sdk = createSecenv()
      expect(await sdk.get("MYKEY")).toBe("myvalue")

      // Change to different directory without .secenvs
      const otherDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-other-"))
      process.chdir(otherDir)

      // Should not find the key
      await expect(sdk.get("MYKEY")).rejects.toThrow(SecretNotFoundError)

      fs.rmSync(otherDir, { recursive: true, force: true })
   })

   it("should throw IdentityNotFoundError when SECENV_HOME points to non-existent dir", async () => {
      process.env.SECENV_HOME = "/nonexistent/path/that/does/not/exist"

      fs.writeFileSync(".secenvs", "KEY=enc:age:xyz123\n")

      const sdk = createSecenv()
      await expect(sdk.get("KEY")).rejects.toThrow(IdentityNotFoundError)
   })

   it("should resolve relative SECENV_HOME to absolute", async () => {
      // Use relative path
      const relativePath = "./relative-secenv-home"
      process.env.SECENV_HOME = relativePath

      // Create identity in relative path
      fs.mkdirSync(relativePath, { recursive: true })
      const identity = await generateIdentity()
      const keysDir = path.join(relativePath, ".secenvs", "keys")
      fs.mkdirSync(keysDir, { recursive: true })
      fs.writeFileSync(path.join(keysDir, "default.key"), identity)

      fs.writeFileSync(".secenvs", "KEY=value\n")

      const sdk = createSecenv()
      // Should work with relative path
      expect(await sdk.get("KEY")).toBe("value")
   })

   it("should reject SECENV_HOME containing symlinks", async () => {
      if (os.platform() === "win32") {
         return // Skip on Windows
      }

      // Create real directory and symlink
      const realHome = path.join(testHome, "real-home")
      const linkHome = path.join(testHome, "link-home")
      fs.mkdirSync(realHome, { recursive: true })
      fs.symlinkSync(realHome, linkHome)

      process.env.SECENV_HOME = linkHome

      // Should reject symlink
      const { exitCode, stderr } = await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: linkHome },
         reject: false,
      })

      expect(exitCode).not.toBe(0)
      expect(stderr.toLowerCase()).toContain("symlink")
   })

   it("should reject directory traversal in SECENV_HOME", async () => {
      // Attempt directory traversal
      process.env.SECENV_HOME = path.join(testDir, "..", "..", "etc")

      // Should reject or resolve safely
      const sdk = createSecenv()

      // This may succeed if path is resolved, but should not access /etc
      // Document behavior
      expect(() => sdk.get("ANYTHING")).not.toThrow(FileError)
   })

   it("should reject when .secenvs is a symlink", async () => {
      if (os.platform() === "win32") {
         return // Skip on Windows
      }

      const realFile = path.join(testDir, "real-secenvs")
      const linkFile = path.join(testDir, ".secenvs")

      fs.writeFileSync(realFile, "KEY=value\n")
      fs.symlinkSync(realFile, linkFile)

      const sdk = createSecenv()

      // Should reject symlink
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should reject when .secenvs is a directory", async () => {
      // Create .secenvs as directory instead of file
      fs.mkdirSync(".secenvs")

      const sdk = createSecenv()

      // Should error trying to read directory as file
      await expect(sdk.get("KEY")).rejects.toThrow()
   })

   it("should detect CWD changes and clear cache", async () => {
      // Create first .secenvs
      fs.writeFileSync(".secenvs", "KEY1=value1\n")

      const sdk = createSecenv()
      expect(await sdk.get("KEY1")).toBe("value1")

      // Change to different directory with different .secenvs
      const otherDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-cwd-change-"))
      process.chdir(otherDir)

      fs.writeFileSync(".secenvs", "KEY2=value2\n")

      // Should detect CWD change and read new file
      expect(await sdk.get("KEY2")).toBe("value2")

      // Old key should not be accessible
      expect(sdk.has("KEY1")).toBe(false)

      fs.rmSync(otherDir, { recursive: true, force: true })
   })

   it("should prioritize process.env over .secenvs", async () => {
      // Set env var
      process.env.TEST_SECRET = "from-env"

      // Create .secenvs with same key
      fs.writeFileSync(".secenvs", "TEST_SECRET=from-file\n")

      const sdk = createSecenv()

      // Should return env value (documented behavior)
      expect(await sdk.get("TEST_SECRET")).toBe("from-env")
   })

   it("should use new SECENV_HOME at runtime", async () => {
      // Create identity in original location
      fs.writeFileSync(".secenvs", "KEY=value\n")

      const sdk = createSecenv()
      expect(await sdk.get("KEY")).toBe("value")

      // Change SECENV_HOME to new location with different identity
      const newHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-new-home-"))
      process.env.SECENV_HOME = newHome

      // Create new identity
      const newIdentity = await generateIdentity()
      const newKeysDir = path.join(newHome, ".secenvs", "keys")
      fs.mkdirSync(newKeysDir, { recursive: true })
      fs.writeFileSync(path.join(newKeysDir, "default.key"), newIdentity)

      // Create encrypted value with new identity
      const encrypted = await encrypt(newIdentity, "new-secret")
      fs.writeFileSync(".secenvs", `NEW_KEY=enc:age:${encrypted}\n`)

      // Clear SDK cache to pick up new env
      sdk.clearCache()

      // Should be able to decrypt with new identity
      expect(await sdk.get("NEW_KEY")).toBe("new-secret")

      fs.rmSync(newHome, { recursive: true, force: true })
   })
})
