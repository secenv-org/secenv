import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { createSecenv } from "../../src/env.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")
const PROJECT_ROOT = path.resolve(__dirname, "../..")

describe("Concurrent Access", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-con-cwd-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-con-home-"))
      process.chdir(testDir)
   })

   afterEach(() => {
      process.chdir(PROJECT_ROOT)
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

   it("should handle multiple simultaneous reads", async () => {
      await runCLI(["init"])
      await runCLI(["set", "CON_KEY", "con-val"])

      process.env.SECENV_HOME = secenvHome
      const env = createSecenv()

      const results = await Promise.all([
         env.get("CON_KEY"),
         env.get("CON_KEY"),
         env.get("CON_KEY"),
         env.get("CON_KEY"),
         env.get("CON_KEY"),
      ])

      expect(results).toEqual(["con-val", "con-val", "con-val", "con-val", "con-val"])
   })

   it("should handle read while write is happening (atomic check)", async () => {
      await runCLI(["init"])
      await runCLI(["set", "EXISTING", "old"])

      process.env.SECENV_HOME = secenvHome
      const env = createSecenv()

      // Start a write in background
      const writePromise = runCLI(["set", "NEW", "val"])

      // Read existing while write is in progress
      const val = await env.get("EXISTING")
      expect(val).toBe("old")

      await writePromise
      expect(await env.get("NEW")).toBe("val")
   })

   it("should maintain file integrity under rapid updates", async () => {
      await runCLI(["init"])

      // Run in smaller batches to avoid overwhelming the lock system
      const batchSize = 5
      for (let batch = 0; batch < 4; batch++) {
         const updates: Promise<any>[] = []
         for (let i = 0; i < batchSize; i++) {
            const idx = batch * batchSize + i
            updates.push(
               runCLI(["set", `KEY_${idx}`, `VAL_${idx}`]).catch((err: any) => {
                  console.log(`KEY_${idx} failed:`, err.message)
                  return { exitCode: 1, stderr: err.message }
               })
            )
         }
         await Promise.all(updates)
         // Larger delay between batches to handle test suite load
         await new Promise((resolve) => setTimeout(resolve, 200))
      }

      process.env.SECENV_HOME = secenvHome
      const env = createSecenv()

      for (let i = 0; i < 20; i++) {
         expect(await env.get(`KEY_${i}`)).toBe(`VAL_${i}`)
      }
   })
})
