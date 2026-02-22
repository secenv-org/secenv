import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { generateIdentity, saveIdentity } from "../../src/age.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("Doctor Command Depth", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(async () => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-doctor-depth-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-doctor-home-"))

      const identity = await generateIdentity()
      process.env.SECENV_HOME = secenvHome
      await saveIdentity(identity)
   })

   afterEach(() => {
      delete process.env.SECENV_HOME
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
      } catch (e) {}
      try {
         fs.rmSync(secenvHome, { recursive: true, force: true })
      } catch (e) {}
   })

   describe("Identity check", () => {
      it("should pass when identity exists with correct permissions", async () => {
         fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY=value\n")

         const { stdout, exitCode } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(exitCode).toBe(0)
         expect(stdout).toContain("checks passed")

         if (os.platform() !== "win32") {
            expect(stdout).toContain("Identity:")
         }
      })

      it("should fail when identity is missing", async () => {
         // Delete identity
         fs.unlinkSync(path.join(secenvHome, ".secenvs", "keys", "default.key"))

         const { stdout, exitCode } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
            reject: false,
         })

         expect(exitCode).toBe(0) // Doctor still exits 0 but shows failures
         expect(stdout).toContain("not found")
      })

      it("should warn about wrong permissions (644)", async () => {
         if (os.platform() === "win32") return

         fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY=value\n")

         const keyPath = path.join(secenvHome, ".secenvs", "keys", "default.key")
         fs.chmodSync(keyPath, 0o644)

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("permissions")
         expect(stdout).toContain("644")
      })
   })

   describe("File existence check", () => {
      it("should warn when .secenvs file is missing", async () => {
         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("not found")
      })

      it("should pass when .secenvs exists", async () => {
         fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY=value\n")

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("exists")
      })
   })

   describe("Syntax check", () => {
      it("should detect invalid syntax", async () => {
         fs.writeFileSync(path.join(testDir, ".secenvs"), "INVALID LINE\n")

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
            reject: false,
         })

         expect(stdout).toContain("Syntax")
         expect(stdout).toContain("Error")
      })

      it("should validate correct syntax", async () => {
         fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY1=value1\nKEY2=value2\n")

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("lines")
         expect(stdout).toContain("encrypted")
      })

      it("should count encrypted vs plaintext", async () => {
         const identity = await generateIdentity()
         await saveIdentity(identity)

         const { encrypt, getPublicKey } = await import("../../src/age.js")
         const encrypted = await encrypt([await getPublicKey(identity)], "secret")

         fs.writeFileSync(path.join(testDir, ".secenvs"), `PLAIN=plaintext\nENC=enc:age:${encrypted}\n`)

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("1 encrypted")
         expect(stdout).toContain("1 plaintext")
      })
   })

   describe("Decryption check", () => {
      it("should verify all encrypted values can be decrypted", async () => {
         const identity = await generateIdentity()
         await saveIdentity(identity)

         const { encrypt, getPublicKey } = await import("../../src/age.js")
         const encrypted = await encrypt([await getPublicKey(identity)], "test-value")

         fs.writeFileSync(path.join(testDir, ".secenvs"), `TEST=enc:age:${encrypted}\n`)

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("verified")
      })

      it("should detect corrupted encrypted values", async () => {
         fs.writeFileSync(path.join(testDir, ".secenvs"), "TEST=enc:age:CORRUPTED_DATA_HERE\n")

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
            reject: false,
         })

         expect(stdout).toContain("failed")
      })

      it("should skip decryption check if no identity", async () => {
         fs.unlinkSync(path.join(secenvHome, ".secenvs", "keys", "default.key"))
         fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY=value\n")

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("skipped")
      })
   })

   describe("Summary output", () => {
      it("should show pass/fail count", async () => {
         fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY=value\n")

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toMatch(/\d+\/\d+ checks passed/)
      })

      it("should show all check categories", async () => {
         fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY=value\n")

         const { stdout } = await execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
         })

         expect(stdout).toContain("Identity:")
         expect(stdout).toContain("File:")
         expect(stdout).toContain("Syntax:")
         expect(stdout).toContain("Decryption:")
      })
   })
})
