import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { generateIdentity, getPublicKey } from "../../src/age.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("CLI Error Handling", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-cli-err-cwd-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-cli-err-home-"))
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

   it("should fail when key is missing in set command", async () => {
      const { exitCode, stderr } = await run(["set"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Missing KEY argument")
   })

   it("should fail when key is missing in get command", async () => {
      const { exitCode, stderr } = await run(["get"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Missing KEY argument")
   })

   it("should fail when key is missing in delete command", async () => {
      const { exitCode, stderr } = await run(["delete"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Missing KEY argument")
   })

   it("should fail when get is called without init", async () => {
      const { exitCode, stderr } = await run(["get", "SOME_KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Identity key not found")
   })

   it("should fail when set is called without init", async () => {
      const { exitCode, stderr } = await run(["set", "SOME_KEY", "val"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Identity key not found")
   })

   it("should fail when secret not found in get command", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["get", "MISSING_KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Secret 'MISSING_KEY' not found")
   })

   it("should fail when secret not found in delete command", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["delete", "MISSING_KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Secret 'MISSING_KEY' not found")
   })

   it("should fail when multiline value is set without --base64", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["set", "MULTI", "line1\nline2"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Multiline values are not allowed")
   })

   it("should handle corrupted .secenvs", async () => {
      await run(["init"])
      fs.writeFileSync(path.join(testDir, ".secenvs"), "INVALID_LINE\n")
      const { exitCode, stderr } = await run(["get", "KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Invalid line: missing '=' separator")
   })

   it("should handle duplicate keys in .secenvs", async () => {
      await run(["init"])
      fs.writeFileSync(path.join(testDir, ".secenvs"), "KEY=1\nKEY=2\n")
      const { exitCode, stderr } = await run(["get", "KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Duplicate key 'KEY'")
   })

   it("should warn when init is called but identity already exists", async () => {
      await run(["init"])
      const { stdout } = await run(["init"])
      expect(stdout).toContain("already exists")
   })

   it("should fail get on non-existent .secenvs file", async () => {
      await run(["init"])
      fs.unlinkSync(path.join(testDir, ".secenvs"))
      const { exitCode, stderr } = await run(["get", "KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("not found")
   })

   it("should handle trust with same key twice", async () => {
      await run(["init"])
      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)

      await run(["trust", bobPubkey])
      const { stdout: stdout2 } = await run(["trust", bobPubkey])
      expect(stdout2).toContain("already")
   })

   it("should fail untrust on key not in recipients", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["untrust", "age1notvalid1234567890"])
      expect(exitCode).toBe(1)
   })

   it("should handle export when no .secenvs file exists", async () => {
      await run(["init"])
      fs.unlinkSync(path.join(testDir, ".secenvs"))
      const { stdout, stderr } = await run(["export", "--force"])
      expect(stdout).toContain("No .secenvs file found")
   })

   it("should fail vault get for non-existent key without identity", async () => {
      const { exitCode, stderr } = await run(["vault", "get", "KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("not found")
   })

   it("should handle key export without identity", async () => {
      const { exitCode, stderr } = await run(["key", "export"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Identity")
   })

   it("should fail rotate on non-existent key", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["rotate", "MISSING_KEY"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("not found")
   })

   it("should show usage for invalid subcommand", async () => {
      const { exitCode, stdout } = await run(["invalid-command"])
      expect(exitCode).toBe(0)
      expect(stdout).toContain("Usage")
   })

   it("should handle invalid vault subcommand", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["vault", "invalid"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Invalid vault subcommand")
   })

   it("should handle invalid trust command format", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["trust"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Missing")
   })

   it("should fail set with invalid key format", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["set", "invalid-key", "value"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Invalid key")
   })

   it("should fail set with empty key", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["set", "", "value"])
      expect(exitCode).toBe(1)
   })

   it("should fail set with empty value without --base64", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["set", "KEY", ""])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("empty")
   })

   it("should handle missing subcommand for vault", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["vault"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Invalid vault subcommand")
   })

   it("should handle missing key for vault get", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["vault", "get"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Missing")
   })

   it("should handle missing key for vault delete", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["vault", "delete"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Missing")
   })

   it("should handle invalid key export subcommand", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["key", "invalid"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Invalid key subcommand")
   })

   it("should handle missing file for migrate", async () => {
      await run(["init"])
      const { exitCode, stderr } = await run(["migrate", "nonexistent.env"])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("File not found")
   })
})
