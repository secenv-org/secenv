import { createSecenv } from "../../src/index.js"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { execa } from "execa"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const projectRoot = path.resolve(__dirname, "../..")
const originalCwd = process.env.SECENV_ORIGINAL_CWD || projectRoot

describe("SDK Proxy & Isolation Integration", () => {
   let testDir: string
   let secenvHome: string
   let oldHome: string | undefined

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-sdk-test-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-sdk-home-"))
      oldHome = process.env.SECENV_HOME
      process.env.SECENV_HOME = secenvHome
      process.chdir(testDir)
   })

   afterEach(() => {
      process.chdir(originalCwd)
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
         fs.rmSync(secenvHome, { recursive: true, force: true })
      } catch {}
      process.env.SECENV_HOME = oldHome
   })

   it("should allow direct property access to plaintext values (via fresh instance)", async () => {
      fs.writeFileSync(path.join(testDir, ".secenvs"), "THE_KEY=the-value\n")
      const sdk = createSecenv() as any
      // Await twice to ensure reload and cache are engaged
      const val = await sdk.THE_KEY
      expect(val).toBe("the-value")
   })

   it("should verify the 'env' export works in a fresh process", async () => {
      fs.writeFileSync(path.join(testDir, ".secenvs"), "PROCESS_KEY=process-value\n")

      const libPath = path.resolve(originalCwd, "lib/index.js")
      const scriptContent = `
import { env } from '${libPath}';
// Small delay to ensure FS consistency in CI environments
await new Promise(r => setTimeout(r, 100));

try {
  const val = await env.PROCESS_KEY;
  if (val !== 'process-value') {
      console.error('Expected process-value, got ' + val);
      process.exit(1);
  }
  console.log(val);
} catch (e) {
  console.error(e);
  process.exit(1);
}
      `
      fs.writeFileSync(path.join(testDir, "test-script.mjs"), scriptContent)

      const result = await execa("node", ["test-script.mjs"], {
         cwd: testDir,
         env: { ...process.env, SECENV_HOME: secenvHome },
      })
      expect(result.stdout.trim()).toBe("process-value")
   })

   it("should prioritize process.env over .secenvs", async () => {
      fs.writeFileSync(path.join(testDir, ".secenvs"), "OVERRIDE_ME=from-file\n")
      process.env.OVERRIDE_ME = "from-env"

      const sdk = createSecenv() as any
      const val = await sdk.OVERRIDE_ME
      expect(val).toBe("from-env")

      delete process.env.OVERRIDE_ME
   })

   it("should throw SecretNotFoundError for missing keys", async () => {
      fs.writeFileSync(path.join(testDir, ".secenvs"), "EXISTING=value\n")
      const sdk = createSecenv() as any
      await expect(sdk.MISSING_KEY).rejects.toThrow(/Secret 'MISSING_KEY' not found/)
   })

   it("should isolate private fields (Runtime Inspection)", async () => {
      const sdk = createSecenv() as any

      // Use property names to check for leaks
      const props = Object.getOwnPropertyNames(sdk)
      expect(props).not.toContain("cache")
      expect(props).not.toContain("#cache")
      expect(props).not.toContain("identity")
      expect(props).not.toContain("#identity")

      // Verify JSON stringification doesn't leak
      const json = JSON.stringify(sdk)
      expect(json).not.toContain("value") // Secrets shouldn't be in JSON
   })

   it("should handle property access for SDK methods (binding check)", async () => {
      fs.writeFileSync(path.join(testDir, ".secenvs"), "K=V\n")
      const sdk = createSecenv() as any

      const hasK = sdk.has("K")
      expect(hasK).toBe(true)

      const keys = sdk.keys()
      expect(keys).toContain("K")
   })
})
