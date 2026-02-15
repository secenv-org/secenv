import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"

import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
// Use a stable absolute path for the binary resolved at load time
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("CLI Behavior Integration", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-cli-test-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-home-test-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const runCLI = (args: string[], input?: string) => {
      const proc = execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         input: input,
      })
      return proc
   }

   it("should perform full lifecycle: init -> set -> get -> rotate -> delete", async () => {
      // 1. Init
      const initResult = await runCLI(["init"])
      expect(initResult.stdout).toContain("Identity created")
      expect(fs.existsSync(path.join(testDir, ".secenvs"))).toBe(true)

      // 2. Set
      const setResult = await runCLI(["set", "DATABASE_URL", "postgres://localhost:5432"])
      expect(setResult.stdout).toContain("Encrypted and stored DATABASE_URL")

      // 3. Get
      const getResult = await runCLI(["get", "DATABASE_URL"])
      expect(getResult.stdout).toBe("postgres://localhost:5432")

      // 4. List
      const listResult = await runCLI(["list"])
      expect(listResult.stdout).toContain("DATABASE_URL  [encrypted]")

      // 5. Rotate
      const rotateResult = await runCLI(["rotate", "DATABASE_URL", "postgres://prod:5432"])
      expect(rotateResult.stdout).toContain("Rotated DATABASE_URL")
      const getRotated = await runCLI(["get", "DATABASE_URL"])
      expect(getRotated.stdout).toBe("postgres://prod:5432")

      // 6. Delete
      const deleteResult = await runCLI(["delete", "DATABASE_URL"])
      expect(deleteResult.stdout).toContain("Deleted DATABASE_URL")
      await expect(runCLI(["get", "DATABASE_URL"])).rejects.toThrow()
   })

   it("should handle --base64 flag correctly", async () => {
      await runCLI(["init"])
      const secret = "hello world binary"
      const b64 = Buffer.from(secret).toString("base64")

      await runCLI(["set", "CERT", b64, "--base64"])
      const getResult = await runCLI(["get", "CERT"])
      expect(getResult.stdout).toBe(secret)
   })

   it("should support key export for CI/CD", async () => {
      await runCLI(["init"])
      const exportResult = await runCLI(["key", "export"])
      expect(exportResult.stdout).toMatch(/^AGE-SECRET-KEY-1/)
   })

   it("should support doctor command", async () => {
      await runCLI(["init"])
      await runCLI(["set", "TEST_KEY", "test-value"])
      const doctorResult = await runCLI(["doctor"])
      expect(doctorResult.stdout).toContain("checks passed")
      expect(doctorResult.stdout).toContain("Decryption: 1/1 keys verified")
   })

   it("should support export --force", async () => {
      await runCLI(["init"])
      await runCLI(["set", "K1", "V1"])
      await runCLI(["set", "K2", "V2"])

      const exportResult = await runCLI(["export", "--force"])
      expect(exportResult.stdout).toContain("K1=V1")
      expect(exportResult.stdout).toContain("K2=V2")
   })
})
