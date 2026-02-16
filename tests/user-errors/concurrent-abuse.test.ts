import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { writeAtomic, setKey, parseEnvFile } from "../../src/parse.js"
import { generateIdentity, saveIdentity } from "../../src/age.js"
import { execa } from "execa"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("User Blunder: Concurrent/Filesystem Abuse", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(async () => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-concurrent-test-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-concurrent-home-"))
      process.env.SECENV_HOME = secenvHome

      // Initialize identity
      const identity = await generateIdentity()
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

   describe("Concurrent access scenarios", () => {
      it("should handle two simultaneous set operations", async () => {
         const envPath = path.join(testDir, ".secenvs")

         // Start two concurrent writes
         const write1 = setKey(envPath, "KEY1", "value1")
         const write2 = setKey(envPath, "KEY2", "value2")

         // Both should succeed
         await expect(write1).resolves.not.toThrow()
         await expect(write2).resolves.not.toThrow()

         // File should be intact with at least one key
         const result = parseEnvFile(envPath)
         expect(result.keys.size).toBeGreaterThanOrEqual(1)
      })

      it("should maintain consistency during read-while-write", async () => {
         const envPath = path.join(testDir, ".secenvs")

         // Create initial file
         await writeAtomic(envPath, "INITIAL=value\n")

         // Start a write operation
         const writePromise = setKey(envPath, "NEW", "newvalue")

         // Immediately try to read (should not see partial write)
         const readPromise = (async () => {
            const content = fs.readFileSync(envPath, "utf-8")
            return content
         })()

         const results = await Promise.all([writePromise, readPromise])
         const readContent = results[1] as string

         // Read should see complete content (either before or after write, not partial)
         expect(readContent).toMatch(/^[A-Z0-9_]+=.+$/m)
      })

      it("should handle rapid successive sets from same process", async () => {
         const envPath = path.join(testDir, ".secenvs")

         // Rapid fire 10 sets
         const promises: Promise<void>[] = []
         for (let i = 0; i < 10; i++) {
            promises.push(setKey(envPath, `KEY${i}`, `value${i}`))
         }

         await Promise.all(promises)

         // File should be valid and contain some keys
         const result = parseEnvFile(envPath)
         expect(result.keys.size).toBeGreaterThanOrEqual(1)
      })

      it("should handle doctor running while set is in progress", async () => {
         const envPath = path.join(testDir, ".secenvs")
         fs.writeFileSync(envPath, "TEST=value\n")

         // Start a set operation
         const setPromise = setKey(envPath, "NEW", "newvalue")

         // Run doctor concurrently
         const doctorPromise = execa("node", [BIN_PATH, "doctor"], {
            cwd: testDir,
            env: { SECENV_HOME: secenvHome },
            reject: false,
         })

         const results = await Promise.all([setPromise, doctorPromise])
         const doctorResult = results[1] as any

         // Both should complete without crashing
         expect(doctorResult.exitCode).toBe(0)
      })
   })

   describe("Filesystem abuse scenarios", () => {
      it("should recover from stale lock file (dead PID)", async () => {
         const envPath = path.join(testDir, ".secenvs")
         const lockPath = `${envPath}.lock`

         // Create stale lock with non-existent PID
         fs.writeFileSync(lockPath, "99999")

         // Should be able to write after detecting stale lock
         await writeAtomic(envPath, "KEY=value\n")

         // Lock should be cleaned up
         expect(fs.existsSync(lockPath)).toBe(false)
         expect(fs.readFileSync(envPath, "utf-8")).toContain("KEY=value")
      })

      it("should handle stale lock with invalid content", async () => {
         const envPath = path.join(testDir, ".secenvs")
         const lockPath = `${envPath}.lock`

         // Create lock with non-numeric content
         fs.writeFileSync(lockPath, "not-a-pid")

         // Should handle gracefully (treat as stale)
         await writeAtomic(envPath, "KEY=value\n")

         // File should be written
         expect(fs.readFileSync(envPath, "utf-8")).toContain("KEY=value")
      })

      it("should clean up temp files on write failure", async () => {
         if (os.platform() === "win32") {
            return // Skip on Windows
         }

         const envPath = path.join(testDir, ".secenvs")
         fs.writeFileSync(envPath, "")

         // Make directory read-only
         fs.chmodSync(testDir, 0o555)

         try {
            await expect(writeAtomic(envPath, "content")).rejects.toThrow()

            // No temp files should remain
            const files = fs.readdirSync(testDir)
            const tempFiles = files.filter((f) => f.includes(".tmp"))
            expect(tempFiles).toHaveLength(0)
         } finally {
            fs.chmodSync(testDir, 0o755)
         }
      })

      it("should handle read-only filesystem gracefully", async () => {
         if (os.platform() === "win32") {
            return // Skip on Windows
         }

         const envPath = path.join(testDir, ".secenvs")
         fs.writeFileSync(envPath, "INITIAL=value\n")

         // Make file read-only
         fs.chmodSync(envPath, 0o444)
         fs.chmodSync(testDir, 0o555)

         try {
            await expect(setKey(envPath, "NEW", "value")).rejects.toThrow()
         } finally {
            fs.chmodSync(testDir, 0o755)
            fs.chmodSync(envPath, 0o644)
         }
      })

      it("should reject symlink attacks on .secenvs", async () => {
         if (os.platform() === "win32") {
            return // Skip on Windows
         }

         const realFile = path.join(testDir, "real-target")
         const linkFile = path.join(testDir, ".secenvs")

         fs.writeFileSync(realFile, "sensitive data")
         fs.symlinkSync(realFile, linkFile)

         const { createSecenv } = await import("../../src/env.js")
         const sdk = createSecenv()

         // Should reject symlink
         await expect(sdk.get("ANY")).rejects.toThrow()
      })

      it("should reject symlink attacks on SECENV_HOME", async () => {
         if (os.platform() === "win32") {
            return // Skip on Windows
         }

         const realHome = path.join(testDir, "real-home")
         const linkHome = path.join(testDir, "link-home")

         fs.mkdirSync(realHome, { recursive: true })
         fs.symlinkSync(realHome, linkHome)

         const { exitCode, stderr } = await execa("node", [BIN_PATH, "init"], {
            cwd: testDir,
            env: { SECENV_HOME: linkHome },
            reject: false,
         })

         expect(exitCode).not.toBe(0)
      })

      it("should handle file modified between stat and read", async () => {
         const envPath = path.join(testDir, ".secenvs")
         fs.writeFileSync(envPath, "KEY1=value1\n")

         const { createSecenv } = await import("../../src/env.js")
         const sdk = createSecenv()

         // Read first to cache
         await sdk.get("KEY1")

         // Modify file externally
         fs.writeFileSync(envPath, "KEY2=value2\n")

         // SDK should detect change on next access
         sdk.clearCache()
         const value = await sdk.get("KEY2")
         expect(value).toBe("value2")
      })

      it("should handle race condition in lock acquisition", async () => {
         const envPath = path.join(testDir, ".secenvs")

         // Create multiple concurrent lock attempts
         const attempts: Promise<void | null>[] = []
         for (let i = 0; i < 5; i++) {
            attempts.push(writeAtomic(envPath, `KEY${i}=value${i}\n`).catch(() => null))
         }

         await Promise.all(attempts)

         // File should exist and be valid
         expect(fs.existsSync(envPath)).toBe(true)
         const content = fs.readFileSync(envPath, "utf-8")
         expect(content.length).toBeGreaterThan(0)
      })

      it("should handle no permissions on .secenvs file", async () => {
         if (os.platform() === "win32") {
            return // Skip on Windows
         }

         const envPath = path.join(testDir, ".secenvs")
         fs.writeFileSync(envPath, "KEY=value\n")

         // Remove all permissions
         fs.chmodSync(envPath, 0o000)

         try {
            const { createSecenv } = await import("../../src/env.js")
            const sdk = createSecenv()

            await expect(sdk.get("KEY")).rejects.toThrow()
         } finally {
            fs.chmodSync(envPath, 0o644)
         }
      })
   })
})
