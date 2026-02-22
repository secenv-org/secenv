import * as fs from "fs"
import * as path from "path"
import { execa, execaSync } from "execa"
import { getEnvPath } from "../../src/parse.js"
import { parseEnvFile } from "../../src/parse.js"
import { loadIdentity, decrypt } from "../../src/age.js"
import { ENCRYPTED_PREFIX } from "../../src/parse.js"

describe("CLI - migrate command", () => {
   let tempDir: string
   let originalCwd: string
   let cliPath: string

   beforeEach(() => {
      originalCwd = process.cwd()
      tempDir = path.join(originalCwd, `.test-migrate-${Date.now()}`)
      fs.mkdirSync(tempDir)
      process.chdir(tempDir)
      cliPath = path.join(originalCwd, "bin/secenvs.js")

      // Init a secenvs environment
      execaSync("node", [cliPath, "init"])
   })

   afterEach(() => {
      process.chdir(originalCwd)
      if (fs.existsSync(tempDir)) {
         fs.rmSync(tempDir, { recursive: true, force: true })
      }
   })

   it("should migrate a legacy .env file automatically", async () => {
      fs.writeFileSync(".env", "FOO=bar\nBAZ=qux\n")

      await execa("node", [cliPath, "migrate", ".env", "--auto"])

      const envPath = getEnvPath()
      expect(fs.existsSync(envPath)).toBe(true)

      const parsed = parseEnvFile(envPath)
      expect(parsed.keys.has("FOO")).toBe(true)
      expect(parsed.keys.has("BAZ")).toBe(true)
      expect(parsed.encryptedCount).toBe(2)

      const identity = await loadIdentity()

      const fooLine = parsed.lines.find((l) => l.key === "FOO")!
      const bazLine = parsed.lines.find((l) => l.key === "BAZ")!

      const fooDecrypted = await decrypt(identity, fooLine.value.slice(ENCRYPTED_PREFIX.length))
      expect(fooDecrypted.toString()).toBe("bar")

      const bazDecrypted = await decrypt(identity, bazLine.value.slice(ENCRYPTED_PREFIX.length))
      expect(bazDecrypted.toString()).toBe("qux")
   })

   it("should handle newlines properly and encode them as base64", async () => {
      fs.writeFileSync(".env", 'KEY="line1\\nline2"\n')
      await execa("node", [cliPath, "migrate", ".env", "--auto"])

      const envPath = getEnvPath()
      const parsed = parseEnvFile(envPath)
      expect(parsed.keys.has("KEY")).toBe(true)

      const identity = await loadIdentity()
      const line = parsed.lines.find((l) => l.key === "KEY")!
      const decrypted = await decrypt(identity, line.value.slice(ENCRYPTED_PREFIX.length))
      
      expect(decrypted.toString()).toBe("line1\nline2")
   })

   it("should not crash on invalid keys and should skip them", async () => {
      fs.writeFileSync(".env", "1INVALID=value\nVALID=1\n")
      await execa("node", [cliPath, "migrate", ".env", "--auto"])

      const envPath = getEnvPath()
      const parsed = parseEnvFile(envPath)
      expect(parsed.keys.has("VALID")).toBe(true)
      expect(parsed.keys.has("1INVALID")).toBe(false)
   })
})
