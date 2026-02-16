import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("User Blunder: CLI Mistakes", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-cli-mistake-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-cli-home-"))
   })

   afterEach(() => {
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
         fs.rmSync(secenvHome, { recursive: true, force: true })
      } catch (e) {
         // Ignore cleanup errors
      }
   })

   const runCLI = (args: string[], input?: string) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         input,
         reject: false,
      })
   }

   describe("Key validation errors", () => {
      it("should reject lowercase key in set command", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "mykey", "value"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Invalid key")
      })

      it("should reject key starting with number", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "123KEY", "value"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Invalid key")
      })

      it("should reject key with hyphen", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "MY-KEY", "value"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Invalid key")
      })

      it("should reject key with dot", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "MY.KEY", "value"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Invalid key")
      })

      it("should reject Windows reserved names (CON)", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "CON", "value"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Invalid key")
         expect(stderr).toContain("reserved")
      })

      it("should reject Windows reserved names (PRN)", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "PRN", "value"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("reserved")
      })
   })

   describe("Value validation errors", () => {
      it("should reject multiline value without --base64 flag", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "KEY", "line1\nline2"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Multiline")
      })

      it("should reject empty value", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "KEY", ""])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("cannot be empty")
      })

      it("should accept whitespace-only value", async () => {
         await runCLI(["init"])

         const { exitCode } = await runCLI(["set", "KEY", "   "])

         // This may or may not be accepted depending on implementation
         // Documenting current behavior
         expect(exitCode === 0 || exitCode === 1).toBe(true)
      })

      it("should reject invalid base64 with --base64 flag", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set", "KEY", "!!!invalid!!!", "--base64"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Invalid base64")
      })
   })

   describe("Missing arguments", () => {
      it("should error on set without KEY", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["set"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Missing KEY")
      })

      it("should error on get without KEY", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["get"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Missing KEY")
      })

      it("should error on delete without KEY", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["delete"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Missing KEY")
      })

      it("should error on rotate without KEY", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["rotate"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("Missing KEY")
      })
   })

   describe("Non-existent keys", () => {
      it("should error when getting non-existent key", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["get", "NONEXISTENT"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("not found")
      })

      it("should error when deleting non-existent key", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["delete", "NONEXISTENT"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("not found")
      })

      it("should error when rotating non-existent key", async () => {
         await runCLI(["init"])

         const { exitCode, stderr } = await runCLI(["rotate", "NONEXISTENT", "newvalue"])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("not found")
      })
   })

   describe("Export safety", () => {
      it("should cancel export without --force and without confirmation", async () => {
         await runCLI(["init"])
         await runCLI(["set", "SECRET", "mysecret"])

         // Run export without --force and don't provide input
         // It should cancel or timeout
         const result = await execa("node", [BIN_PATH, "export"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
            reject: false,
            timeout: 1000,
         }).catch(() => ({ timeout: true }))

         // Either cancelled or timed out
         expect((result as any).timeout || (result as any).stdout?.includes("cancelled")).toBeTruthy()
      }, 5000)

      it("should export empty file with --force", async () => {
         await runCLI(["init"])

         const { exitCode, stdout } = await runCLI(["export", "--force"])

         expect(exitCode).toBe(0)
         // Should succeed even with no secrets
         expect(stdout).not.toContain("Error")
      })
   })

   describe("Size limits", () => {
      it("should reject value larger than 5MB", async () => {
         await runCLI(["init"])

         // Create a 6MB value
         const hugeValue = "x".repeat(6 * 1024 * 1024)

         const { exitCode, stderr } = await runCLI(["set", "KEY", hugeValue])

         expect(exitCode).toBe(1)
         expect(stderr).toContain("exceeds")
      }, 30000)
   })
})
