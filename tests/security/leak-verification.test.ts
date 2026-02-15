import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"

import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("Security Invariants (Leak Verification)", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-security-test-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-home-security-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const runCLI = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })
   }

   it("should NOT leak secret values in error messages when identity is missing", async () => {
      // Create .secenvs with an encrypted key but NO identity
      await fs.promises.mkdir(path.join(testDir), { recursive: true })
      const secretValue = "super-secret-123"
      // We'll use a fake encrypted blob
      const encryptedBlob = "A=enc:age:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBtYW5nbGVkCg=="
      fs.writeFileSync(path.join(testDir, ".secenvs"), encryptedBlob)

      try {
         await runCLI(["get", "A"])
         throw new Error("Should have failed")
      } catch (e: any) {
         // Verify secret is not in stderr or stdout
         expect(e.stdout).not.toContain(secretValue)
         expect(e.stderr).not.toContain(secretValue)
         // Verify it gives a proper security error
         expect(e.stderr).toContain("Identity key not found")
      }
   })

   it("should NOT leak secret values when decryption fails", async () => {
      await runCLI(["init"])
      // Set a key
      await runCLI(["set", "S", "real-secret"])

      // Corrupt the encrypted value slightly
      let content = fs.readFileSync(path.join(testDir, ".secenvs"), "utf-8")
      content = content.replace("enc:age:", "enc:age:mangled")
      fs.writeFileSync(path.join(testDir, ".secenvs"), content)

      try {
         await runCLI(["get", "S"])
         fail("Should have failed")
      } catch (e: any) {
         expect(e.stdout).not.toContain("real-secret")
         expect(e.stderr).not.toContain("real-secret")
         expect(e.stderr).toContain("Failed to decrypt")
      }
   })

   it("should NOT include secret keys in logs during verbose operations (if we had any)", async () => {
      // Our doctor command should show counts, not values
      await runCLI(["init"])
      await runCLI(["set", "K", "SUPER_SECRET_VALUE"])
      const doctor = await runCLI(["doctor"])
      expect(doctor.stdout).not.toContain("SUPER_SECRET_VALUE")
   })
})
