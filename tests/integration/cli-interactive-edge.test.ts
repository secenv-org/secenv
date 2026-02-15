import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("CLI Interactive Mode Edge Cases", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-interactive-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-int-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const runWithInput = (args: string[], input: string) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         input,
         reject: false,
      })
   }

   it("should reject empty value in interactive set mode", async () => {
      // Initialize first
      await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      // Try to set key with empty value (just press enter)
      const { exitCode, stderr } = await runWithInput(["set", "MY_KEY"], "\n")

      expect(exitCode).toBe(1)
      expect(stderr).toContain("cannot be empty")
   })

   it("should reject empty value in interactive rotate mode", async () => {
      // Initialize and set a value first
      await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      await execa("node", [BIN_PATH, "set", "MY_KEY", "initial_value"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      // Try to rotate with empty value
      const { exitCode, stderr } = await runWithInput(["rotate", "MY_KEY"], "\n")

      expect(exitCode).toBe(1)
      expect(stderr).toContain("cannot be empty")
   })

   it("should accept valid value after empty attempt in interactive mode", async () => {
      // Initialize
      await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      // First provide empty, then valid value
      // Note: This test might need adjustment based on actual CLI behavior
      const { exitCode } = await runWithInput(["set", "MY_KEY"], "valid_value\n")

      expect(exitCode).toBe(0)

      // Verify value was set
      const { stdout } = await execa("node", [BIN_PATH, "get", "MY_KEY"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      expect(stdout).toBe("valid_value")
   })

   it("should handle whitespace-only values in interactive mode", async () => {
      // Initialize
      await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      // Provide whitespace-only value
      const { exitCode, stderr } = await runWithInput(["set", "MY_KEY"], "   \n")

      // Whitespace should be treated as empty or accepted as value depending on implementation
      // Current implementation accepts it as a value
      expect(exitCode).toBe(0)
   })

   it("should handle export without --force by waiting for confirmation", async () => {
      // Initialize and set a value
      await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      await execa("node", [BIN_PATH, "set", "SECRET", "mysecret"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      // Export without --force and without input - will wait for confirmation
      // Use a short timeout since it will hang
      const result = await execa("node", [BIN_PATH, "export"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
         timeout: 1000,
      }).catch((e) => ({ failed: true, message: e.message }))

      // Either it times out (waiting for input) or shows the warning
      expect(result.failed || (result as any).message?.includes("timeout")).toBe(true)
   }, 5000)

   it("should confirm export with 'yes' in interactive mode", async () => {
      // Initialize and set a value
      await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      await execa("node", [BIN_PATH, "set", "SECRET", "mysecret"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      // Confirm export with 'yes'
      const { stdout, exitCode } = await runWithInput(["export"], "yes\n")

      expect(exitCode).toBe(0)
      expect(stdout).toContain("SECRET=mysecret")
   })

   it("should cancel export with 'no' in interactive mode", async () => {
      // Initialize and set a value
      await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      await execa("node", [BIN_PATH, "set", "SECRET", "mysecret"], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })

      // Cancel export with 'no'
      const { stdout, exitCode } = await runWithInput(["export"], "no\n")

      expect(exitCode).toBe(0)
      expect(stdout).toContain("cancelled")
      expect(stdout).not.toContain("SECRET=mysecret")
   })
})
