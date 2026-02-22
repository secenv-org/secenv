import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { execa } from "execa"
import { createSecenv } from "../../src/env.js"
import { vaultSet, clearVaultCache, listVaultKeys } from "../../src/vault.js"
import { generateIdentity, saveIdentity } from "../../src/age.js"
import { VaultError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("Vault Integration Tests", () => {
   let testDir: string
   let testHome: string
   let originalEnvHome: string | undefined
   let originalCwd: string

   beforeEach(async () => {
      originalCwd = process.cwd()
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-vault-integration-"))
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-vault-home-"))
      originalEnvHome = process.env.SECENV_HOME

      process.chdir(testDir)
      process.env.SECENV_HOME = testHome

      // Setup identity
      const identity = await generateIdentity()
      await saveIdentity(identity)

      clearVaultCache()
   })

   afterEach(() => {
      process.env.SECENV_HOME = originalEnvHome
      try {
         process.chdir(originalCwd)
      } catch (e) {}
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
         fs.rmSync(testHome, { recursive: true, force: true })
      } catch (e) {}
   })

   it("should resolve vault: references via SDK", async () => {
      // 1. Set a value in the global vault
      await vaultSet("GLOBAL_DB_URL", "postgres://localhost:5432")

      // 2. Reference it in a project .secenvs file
      fs.writeFileSync(".secenvs", "DB_URL=vault:GLOBAL_DB_URL\n")

      // 3. Access via SDK
      const sdk = createSecenv()
      expect(await sdk.get("DB_URL")).toBe("postgres://localhost:5432")
   })

   it("should resolve vault references inside encrypted values", async () => {
      // 1. Set a value in the global vault
      await vaultSet("SECRET_API_KEY", "ak_test_12345")

      // 2. Encrypt a "vault:..." reference for the project
      // We need to use a real encrypted value here.
      // But for the sake of this test, we'll manually construct the .secenvs if needed
      // or just use the CLI to set it.

      await execa("node", [BIN_PATH, "set", "API_KEY", "vault:SECRET_API_KEY"], {
         env: { SECENV_HOME: testHome },
      })

      // 3. Access via SDK
      const sdk = createSecenv()
      expect(await sdk.get("API_KEY")).toBe("ak_test_12345")
   })

   it("should throw VaultError when a referenced vault key is missing", async () => {
      fs.writeFileSync(".secenvs", "BROKEN_REF=vault:NON_EXISTENT\n")

      const sdk = createSecenv()
      await expect(sdk.get("BROKEN_REF")).rejects.toThrow(VaultError)
      await expect(sdk.get("BROKEN_REF")).rejects.toThrow(/not found in global vault/)
   })

   it("should allow setting and getting via CLI", async () => {
      // Set via CLI
      await execa("node", [BIN_PATH, "vault", "set", "CLI_KEY", "cli-value"], {
         env: { SECENV_HOME: testHome },
      })

      // Get via CLI
      const { stdout } = await execa("node", [BIN_PATH, "vault", "get", "CLI_KEY"], {
         env: { SECENV_HOME: testHome },
      })
      expect(stdout.trim()).toBe("cli-value")
   })

   it("should list vault keys via CLI", async () => {
      await vaultSet("KEY1", "val1")
      await vaultSet("KEY2", "val2")

      const { stdout } = await execa("node", [BIN_PATH, "vault", "list"], {
         env: { SECENV_HOME: testHome },
      })
      expect(stdout).toContain("KEY1")
      expect(stdout).toContain("KEY2")
   })

   it("should delete vault keys via CLI", async () => {
      await vaultSet("TEMP_KEY", "temp")

      await execa("node", [BIN_PATH, "vault", "delete", "TEMP_KEY"], {
         env: { SECENV_HOME: testHome },
      })

      clearVaultCache()
      const keys = await listVaultKeys()
      expect(keys).not.toContain("TEMP_KEY")
   })
})
