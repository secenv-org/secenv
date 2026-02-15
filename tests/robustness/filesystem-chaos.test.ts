import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"

import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("Filesystem Chaos", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-chaos-fs-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-home-fs-"))
   })

   afterEach(() => {
      // Restore permissions before deletion just in case
      try {
         fs.chmodSync(testDir, 0o777)
      } catch {}
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const runCLI = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })
   }

   it("should fail gracefully when .secenvs is unwritable", async () => {
      await runCLI(["init"])
      // To prevent atomic writes (rename), we must make the DIRECTORY read-only
      fs.chmodSync(testDir, 0o555)

      try {
         await runCLI(["set", "K", "V"])
         throw new Error("Should have failed")
      } catch (e: any) {
         // execa error message contains stderr
         const msg = e.message || e.stderr || ""
         expect(msg).toContain("EACCES")
      } finally {
         // Restore permissions so afterEach can clean up
         fs.chmodSync(testDir, 0o777)
      }
   })

   it("should reject symlinks for .secenvs (Security Policy)", async () => {
      // Initialize properly to get an identity
      await runCLI(["init"])
      // Remove the real .secenvs created by init
      fs.unlinkSync(path.join(testDir, ".secenvs"))

      const realFile = path.join(os.tmpdir(), "real-secrets")
      fs.writeFileSync(realFile, "K=V\n")
      const symlinkPath = path.join(testDir, ".secenvs")
      try {
         fs.symlinkSync(realFile, symlinkPath)
      } catch (err) {
         // on some systems symlinks might fail (e.g. Windows without privs), skip if so
         console.warn("Skipping symlink test due to creation failure")
         return
      }

      try {
         await runCLI(["get", "K"])
         throw new Error("Should have failed")
      } catch (e: any) {
         expect(e.stderr || e.message).toContain("Symlink detected")
      } finally {
         try {
            fs.unlinkSync(realFile)
         } catch {}
      }
   })

   it("should handle missing SECENV_HOME gracefully", async () => {
      const result = await execa("node", [BIN_PATH, "init"], {
         cwd: testDir,
         env: { SECENV_HOME: "/non/existent/path/that/cannot/be/created" },
      }).catch((e) => e)

      expect(result.stderr).toContain("Failed to ensure safe directory")
   })

   it("should handle lock file permission errors", async () => {
      await runCLI(["init"])
      const lockPath = path.join(testDir, ".secenvs.lock")
      // Create a directory where the lock file should be, to cause EEXIST or similar
      // or just make the directory unwritable
      fs.chmodSync(testDir, 0o555) // Read and execute only

      try {
         await runCLI(["set", "K", "V"])
         fail("Should have failed")
      } catch (e: any) {
         expect(e.stderr).toContain("Failed to acquire lock")
      }
   })
})
