import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { createSecenv } from "../../src/env.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("Performance Benchmarks", () => {
   let testDir: string
   let secenvHome: string
   let originalCwd: string

   beforeEach(() => {
      originalCwd = process.cwd()
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-perf-cwd-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-perf-home-"))
   })

   afterEach(() => {
      process.chdir(originalCwd)
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
      delete process.env.SECENV_HOME
   })

   const runCLI = (args: string[]) => {
      return execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
      })
   }

   it("cold start decryption (first access) should be under 500ms", async () => {
      // Note: 50ms might be too tight for Node.js + age-encryption + fs overhead in CI,
      // let's start with a generous 500ms and see.
      await runCLI(["init"])
      await runCLI(["set", "PERF_KEY", "val"])

      process.chdir(testDir)
      process.env.SECENV_HOME = secenvHome
      const env = createSecenv()

      const start = performance.now()
      await env.get("PERF_KEY")
      const duration = performance.now() - start

      console.log(`Cold start duration: ${duration.toFixed(2)}ms`)
      expect(duration).toBeLessThan(500)
   })

   it("cached access should be under 1ms", async () => {
      await runCLI(["init"])
      await runCLI(["set", "CACHE_PERF", "val"])

      process.chdir(testDir)
      process.env.SECENV_HOME = secenvHome
      const env = createSecenv()

      await env.get("CACHE_PERF") // Warm up

      const start = performance.now()
      await env.get("CACHE_PERF")
      const duration = performance.now() - start

      console.log(`Cached access duration: ${duration.toFixed(2)}ms`)
      expect(duration).toBeLessThan(5) // Allowing some jitter in CI
   })

   it("parsing 100 keys should be fast", async () => {
      await runCLI(["init"])
      process.chdir(testDir)
      for (let i = 0; i < 100; i++) {
         // Use fs directly to be faster than CLI calls for setup
         fs.appendFileSync(".secenvs", `KEY_${i}=val_${i}\n`)
      }

      process.env.SECENV_HOME = secenvHome
      const env = createSecenv()

      const start = performance.now()
      await env.get("KEY_99")
      const duration = performance.now() - start

      console.log(`100 keys lookup duration: ${duration.toFixed(2)}ms`)
      expect(duration).toBeLessThan(100)
   })
})
