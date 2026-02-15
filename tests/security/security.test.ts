import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { generateIdentity, encrypt, decrypt } from "../../src/age.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("Security Tests", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-sec-cwd-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-sec-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const runCLI = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })
   }

   it("should never print encrypted values in plaintext in logs/errors", async () => {
      await runCLI(["init"])
      const secret = "MY_SUPER_SECRET"
      await runCLI(["set", "S", secret])

      // Try to get with wrong key (simulate error)
      const otherIdentity = await generateIdentity()
      const encodedOther = Buffer.from(otherIdentity).toString("base64")

      const result = await execa("node", [BIN_PATH, "get", "S"], {
         cwd: testDir,
         env: { SECENV_ENCODED_IDENTITY: encodedOther },
         reject: false,
      })

      expect(result.exitCode).toBe(1)
      expect(result.stdout).not.toContain(secret)
      expect(result.stderr).not.toContain(secret)
   })

   it("should use different ciphertexts for same plaintext (nonce randomness)", async () => {
      const identity = await generateIdentity()
      const plaintext = "same-value"

      const enc1 = await encrypt(identity, plaintext)
      const enc2 = await encrypt(identity, plaintext)

      expect(enc1).not.toBe(enc2)

      expect((await decrypt(identity, enc1)).toString()).toBe(plaintext)
      expect((await decrypt(identity, enc2)).toString()).toBe(plaintext)
   })

   it("should protect identity file with 600 permissions", async () => {
      if (os.platform() === "win32") return

      await runCLI(["init"])
      const keyPath = path.join(secenvHome, ".secenvs", "keys", "default.key")
      const stats = fs.statSync(keyPath)
      expect(stats.mode & 0o777).toBe(0o600)
   })

   it("should include .secenv in .gitignore during init", async () => {
      await runCLI(["init"])
      const gitignore = fs.readFileSync(path.join(testDir, ".gitignore"), "utf-8")
      expect(gitignore).toContain(".secenvs")
   })

   it("should not leak secrets to stdout on set command", async () => {
      const secret = "ultra-secret-123"
      const { stdout, stderr } = await runCLI(["set", "KEY", secret])

      expect(stdout).not.toContain(secret)
      expect(stderr).not.toContain(secret)
   })
})
