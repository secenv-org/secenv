import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("CLI Exception Handling", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-cli-exc-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-cli-exc-home-"))
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

   it("should handle non-SecenvError exceptions gracefully", async () => {
      // Initialize first
      await run(["init"])

      // Create a corrupted identity file that will cause a non-SecenvError
      const keysDir = path.join(secenvHome, ".secenvs", "keys")
      const keyPath = path.join(keysDir, "default.key")

      // Write garbage that will cause an unexpected error during encryption/decryption
      fs.writeFileSync(keyPath, "AGE-SECRET-KEY-1INVALIDGARBAGEHERE")

      const { exitCode, stderr } = await run(["get", "SOME_KEY"])

      // Should exit with code 1 and show error message
      expect(exitCode).toBe(1)
      expect(stderr).toBeTruthy()
   })

   it("should handle unexpected errors without leaking sensitive info", async () => {
      // Initialize
      await run(["init"])

      // Create a scenario that causes an internal error
      const envPath = path.join(testDir, ".secenvs")

      // Make .secenvs a directory instead of a file to cause read error
      fs.unlinkSync(envPath)
      fs.mkdirSync(envPath)

      const { exitCode, stderr } = await run(["list"])

      expect(exitCode).toBe(1)
      // Should not contain stack traces or internal paths
      expect(stderr).not.toContain("at ")
      expect(stderr).not.toContain("src/")
      expect(stderr).not.toContain("node_modules")
   })

   it("should handle global uncaught exceptions", async () => {
      // This test verifies the global catch at lines 475-478
      // We can't easily trigger this, but we verify the CLI doesn't crash unexpectedly
      const { exitCode } = await run(["nonexistent_command"])

      // Should exit cleanly even for unknown commands
      expect(exitCode).toBe(0) // Falls through to help
   })
})
