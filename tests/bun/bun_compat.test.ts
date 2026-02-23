import { expect, test, describe, beforeAll, afterAll } from "bun:test"
import { env } from "../../src/index.ts"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"

describe("Bun Compatibility Support", () => {
   let tempDir: string
   let originalEnvHome: string | undefined

   beforeAll(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-bun-test-"))
      originalEnvHome = process.env.SECENV_HOME
      process.env.SECENV_HOME = tempDir
   })

   afterAll(() => {
      process.env.SECENV_HOME = originalEnvHome
      fs.rmSync(tempDir, { recursive: true, force: true })
   })

   test("Bun: env proxy should access process.env", async () => {
      process.env.BUN_TEST_VAR = "bun_rocks"
      const val = await env.BUN_TEST_VAR
      expect(val).toBe("bun_rocks")
   })

   test("Bun: env proxy should access .secenvs secrets", async () => {
      // Manually create a .secenvs file for testing
      // We can't easily use the CLI in a unit-like test without build,
      // but the SDK handles plaintext in .secenvs fine.
      const oldCwd = process.cwd()
      process.chdir(tempDir)
      fs.writeFileSync(".secenvs", "BUN_SECRET=plaintext_in_secenvs\n")

      try {
         const val = await env.BUN_SECRET
         expect(val).toBe("plaintext_in_secenvs")
      } finally {
         process.chdir(oldCwd)
      }
   })
})
