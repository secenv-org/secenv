import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("Atomic Write Integrity (Chaos Testing)", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-chaos-test-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-home-test-"))
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

   it("should maintain integrity when killed during large write operation", async () => {
      await runCLI(["init"])

      const initialKey = "KEY_INITIAL=value_initial\n"
      fs.writeFileSync(path.join(testDir, ".secenvs"), initialKey)

      // We will spawn a process that tries to write 500 keys, and kill it early.
      const workerContent = `
import { execa } from 'execa';
const BIN_PATH = '${BIN_PATH}';
async function run() {
    for (let i = 0; i < 500; i++) {
        await execa('node', [BIN_PATH, 'set', 'STRESS_' + i, 'val_' + i], {
            cwd: '${testDir}',
            env: { SECENV_HOME: '${secenvHome}' }
        });
    }
}
run();
      `
      const workerPath = path.join(testDir, "worker.ts")
      fs.writeFileSync(workerPath, workerContent)

      const worker = execa("bun", [workerPath])

      // Wait a short randomized bit and then kill it
      await new Promise((r) => setTimeout(r, Math.random() * 2000 + 500))
      worker.kill("SIGKILL")

      try {
         await worker
      } catch (e) {}

      // Verify .secenvs is still valid
      // 1. It shouldn't be empty
      const content = fs.readFileSync(path.join(testDir, ".secenvs"), "utf-8")
      expect(content.length).toBeGreaterThan(0)

      // 2. It should at least contain the initial key OR be a valid new state
      // 3. The doctor should pass
      const doctor = await runCLI(["doctor"])
      expect(doctor.stdout).toContain("checks passed")

      // 4. We should be able to read a key (initial or one of the new ones)
      const list = await runCLI(["list"])
      expect(list.stdout).toContain("KEY_INITIAL")
   }, 30000)
})
