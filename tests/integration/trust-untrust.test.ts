import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { generateIdentity, getPublicKey, RECIPIENT_METADATA_KEY } from "../../src/age.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("CLI Integration: trust / untrust", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(async () => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-trust-test-cwd-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-trust-test-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[], extraEnv: Record<string, string> = {}) =>
      execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome, ...extraEnv },
      })

   it("set prints recipient count", async () => {
      await run(["init"])
      const { stdout } = await run(["set", "API_KEY", "test-value"])
      expect(stdout).toContain("1 recipient")
   })

   it("trust adds a public key to the recipients file and re-encrypts", async () => {
      await run(["init"])
      await run(["set", "SECRET", "hello"])

      // Generate a second identity to trust
      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)

      const { stdout } = await run(["trust", bobPubkey])
      expect(stdout).toContain("Added key")
      expect(stdout).toContain("2 total recipients")
      expect(stdout).toContain("Re-encrypted 1 secret")

      // .secenvs file should now contain Bob's key
      const content = fs.readFileSync(
         path.join(testDir, ".secenvs"),
         "utf-8"
      )
      expect(content).toContain(`${RECIPIENT_METADATA_KEY}=${bobPubkey}`)
   })

   it("Bob can decrypt after being trusted", async () => {
      await run(["init"])
      await run(["set", "SECRET", "team-value"])

      const bobHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-bob-home-"))
      try {
         // Generate Bob's identity and save it to Bob's home
         const bobIdentity = await generateIdentity()
         const bobKeyDir = path.join(bobHome, ".secenvs", "keys")
         fs.mkdirSync(bobKeyDir, { recursive: true, mode: 0o700 })
         fs.writeFileSync(path.join(bobKeyDir, "default.key"), bobIdentity, { mode: 0o600 })

         const bobPubkey = await getPublicKey(bobIdentity)
         await run(["trust", bobPubkey])

         // Bob reads the secret using his identity
         const { stdout } = await execa("node", [BIN_PATH, "get", "SECRET"], {
            cwd: testDir,
            env: { SECENV_HOME: bobHome },
         })
         expect(stdout).toBe("team-value")
      } finally {
         fs.rmSync(bobHome, { recursive: true, force: true })
      }
   })

   it("trust is idempotent — warns when key already present", async () => {
      await run(["init"])

      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)

      await run(["trust", bobPubkey])
      const { stdout } = await run(["trust", bobPubkey])

      expect(stdout).toContain("already in")
   })

   it("untrust removes a public key and re-encrypts", async () => {
      await run(["init"])
      await run(["set", "SECRET", "private"])

      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)

      await run(["trust", bobPubkey])
      const { stdout } = await run(["untrust", bobPubkey])

      expect(stdout).toContain("Removed key")
      expect(stdout).toContain("Re-encrypted 1 secret")

      const content = fs.readFileSync(
         path.join(testDir, ".secenvs"),
         "utf-8"
      )
      expect(content).not.toContain(`${RECIPIENT_METADATA_KEY}=${bobPubkey}`)
   })

   it("untrust warns when key is not present", async () => {
      await run(["init"])

      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)

      const { stdout } = await run(["untrust", bobPubkey])
      expect(stdout).toContain("not found")
   })

   it("untrust refuses to remove the last recipient", async () => {
      await run(["init"])
      // The only recipient is the local identity's pubkey (from the fallback)
      // To make it removable-testable we first need to trust a second key,
      // then try to untrust the local key leaving only one (that is already
      // in .secenvs.recipients after the first trust call seeds the file).
      const identityRaw = fs.readFileSync(
         path.join(secenvHome, ".secenvs", "keys", "default.key"),
         "utf-8"
      )
      const localPubkey = await getPublicKey(identityRaw)

      // Trust a second key to create the file with exactly 2 entries
      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)
      await run(["trust", bobPubkey])

      // Now untrust Bob so only local key remains — that should succeed
      await run(["untrust", bobPubkey])

      // Now try to untrust the last remaining key — should fail
      const result = await run(["untrust", localPubkey]).catch((e) => e)
      expect(result.exitCode).toBe(1)
      expect(result.stderr).toContain("Cannot remove the last recipient")
   })

   it("trust rejects an invalid public key", async () => {
      await run(["init"])
      const result = await run(["trust", "not-a-valid-age-key"]).catch((e) => e)
      expect(result.exitCode).toBe(1)
   })

   it("trust requires an argument", async () => {
      await run(["init"])
      const result = await run(["trust"]).catch((e) => e)
      expect(result.exitCode).toBe(1)
      expect(result.stderr).toContain("Missing public key argument")
   })
})
