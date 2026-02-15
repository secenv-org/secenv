import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("CLI Init Edge Cases", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-init-edge-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-init-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })
   }

   it("should warn when identity already exists during init", async () => {
      // First init
      await run(["init"])

      // Second init should warn
      const { stdout, exitCode } = await run(["init"])

      expect(exitCode).toBe(0)
      expect(stdout).toContain("already exists")
      expect(stdout).toContain("doctor")
   })

   it("should add .secenvs to .gitignore without trailing newline", async () => {
      // Create .gitignore without trailing newline
      fs.writeFileSync(path.join(testDir, ".gitignore"), "node_modules", { flag: "w" })

      await run(["init"])

      const gitignoreContent = fs.readFileSync(path.join(testDir, ".gitignore"), "utf-8")

      // Should add newline before .secenvs entry
      expect(gitignoreContent).toContain("node_modules\n.secenvs\n")
   })

   it("should not duplicate .secenvs in .gitignore if already present", async () => {
      // Create .gitignore with .secenvs already in it
      fs.writeFileSync(path.join(testDir, ".gitignore"), ".secenvs\n")

      await run(["init"])

      const gitignoreContent = fs.readFileSync(path.join(testDir, ".gitignore"), "utf-8")

      // Should only have one occurrence
      const matches = gitignoreContent.match(/\.secenvs/g)
      expect(matches).toHaveLength(1)
   })

   it("should handle .gitignore with multiple existing entries", async () => {
      fs.writeFileSync(path.join(testDir, ".gitignore"), "node_modules\n.env\n*.log\n")

      await run(["init"])

      const gitignoreContent = fs.readFileSync(path.join(testDir, ".gitignore"), "utf-8")

      expect(gitignoreContent).toContain("node_modules")
      expect(gitignoreContent).toContain(".env")
      expect(gitignoreContent).toContain("*.log")
      expect(gitignoreContent).toContain(".secenvs")
   })

   it("should create .gitignore if it does not exist", async () => {
      await run(["init"])

      expect(fs.existsSync(path.join(testDir, ".gitignore"))).toBe(true)
      const content = fs.readFileSync(path.join(testDir, ".gitignore"), "utf-8")
      expect(content).toContain(".secenvs")
   })

   it("should not overwrite existing .secenvs file during init", async () => {
      // Create existing .secenvs with content
      fs.writeFileSync(path.join(testDir, ".secenvs"), "EXISTING_KEY=existing_value\n")

      await run(["init"])

      const content = fs.readFileSync(path.join(testDir, ".secenvs"), "utf-8")
      expect(content).toContain("EXISTING_KEY=existing_value")
   })
})

describe("CLI Plaintext Value Handling", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-plaintext-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-plain-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })
   }

   it("should get plaintext values without decryption", async () => {
      await run(["init"])

      // Manually create a plaintext entry
      fs.writeFileSync(path.join(testDir, ".secenvs"), "PLAIN_TEXT=plaintext_value\n")

      const { stdout, exitCode } = await run(["get", "PLAIN_TEXT"])

      expect(exitCode).toBe(0)
      expect(stdout).toBe("plaintext_value")
   })

   it("should export plaintext values", async () => {
      await run(["init"])

      // Mix of encrypted and plaintext
      await run(["set", "ENC_KEY", "encrypted_value"])
      fs.appendFileSync(path.join(testDir, ".secenvs"), "PLAIN_KEY=plain_value\n")

      const { stdout, exitCode } = await run(["export", "--force"])

      expect(exitCode).toBe(0)
      expect(stdout).toContain("ENC_KEY=encrypted_value")
      expect(stdout).toContain("PLAIN_KEY=plain_value")
   })

   it("should handle values with equals signs", async () => {
      await run(["init"])

      // Value containing = characters
      fs.writeFileSync(path.join(testDir, ".secenvs"), "EQUATION=a=b+c=d\n")

      const { stdout, exitCode } = await run(["get", "EQUATION"])

      expect(exitCode).toBe(0)
      expect(stdout).toBe("a=b+c=d")
   })
})

describe("CLI Doctor Command", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-doctor-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-doc-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })
   }

   it("should warn about incorrect permissions on identity file", async () => {
      if (os.platform() === "win32") {
         return // Skip on Windows
      }

      await run(["init"])

      // Change permissions to something other than 0600
      const keyPath = path.join(secenvHome, ".secenvs", "keys", "default.key")
      fs.chmodSync(keyPath, 0o644)

      const { stdout, exitCode } = await run(["doctor"])

      expect(exitCode).toBe(0)
      expect(stdout).toContain("permissions should be 0600")
      expect(stdout).toContain("found 644")
   })

   it("should pass doctor when permissions are correct", async () => {
      if (os.platform() === "win32") {
         return // Skip on Windows
      }

      await run(["init"])
      await run(["set", "TEST", "value"])

      const { stdout, exitCode } = await run(["doctor"])

      expect(exitCode).toBe(0)
      expect(stdout).toContain("checks passed")
      expect(stdout).not.toContain("permissions should be 0600")
   })

   it("should show warning when .secenvs file does not exist", async () => {
      await run(["init"])

      // Delete .secenvs
      fs.unlinkSync(path.join(testDir, ".secenvs"))

      const { stdout, exitCode } = await run(["doctor"])

      expect(exitCode).toBe(0)
      expect(stdout).toContain("not found")
   })
})
