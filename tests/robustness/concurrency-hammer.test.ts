import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("High-Stake Concurrency Hammer", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-hammer-test-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-home-hammer-"))
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

   it("should handle 500+ parallel write/read operations without race conditions", async () => {
      await runCLI(["init"])

      const count = 500
      const workers = []

      // Mix of sets and lists
      for (let i = 0; i < count; i++) {
         if (i % 2 === 0) {
            workers.push(runCLI(["set", `CONC_KEY_${i}`, `VAL_${i}`]))
         } else {
            workers.push(runCLI(["list"]))
         }
      }

      const results = await Promise.allSettled(workers)

      const fulfilled = results.filter((r) => r.status === "fulfilled").length
      const rejected = results.filter((r) => r.status === "rejected").length

      console.log(
         `Concurrency Results: ${fulfilled} succeeded, ${rejected} failed (expected if lock timed out)`
      )

      // The critical piece is that the file is NOT corrupted
      const doctor = await runCLI(["doctor"])
      expect(doctor.stdout).toContain("checks passed")

      // And we can still read at least some of the keys we set
      const list = await runCLI(["list"])
      expect(list.stdout).toContain("CONC_KEY_")
   }, 60000)
})
