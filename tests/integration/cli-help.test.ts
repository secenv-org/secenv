import { execa } from "execa"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { generateIdentity, getPublicKey } from "../../src/age.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const BIN_PATH = path.resolve(__dirname, "../../bin/secenvs")

describe("CLI Help Command", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-help-cwd-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-help-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[]) =>
      execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })

   it("should show help with 'help' command", async () => {
      const { stdout, exitCode } = await run(["help"])
      expect(exitCode).toBe(0)
      expect(stdout).toContain("secenvs")
      expect(stdout).toContain("init")
      expect(stdout).toContain("set")
      expect(stdout).toContain("get")
      expect(stdout).toContain("list")
      expect(stdout).toContain("delete")
      expect(stdout).toContain("export")
      expect(stdout).toContain("doctor")
      expect(stdout).toContain("migrate")
      expect(stdout).toContain("trust")
      expect(stdout).toContain("untrust")
      expect(stdout).toContain("vault")
   })

   it("should show help with no arguments", async () => {
      const { stdout, exitCode } = await run([])
      expect(exitCode).toBe(0)
      expect(stdout).toContain("secenvs")
      expect(stdout).toContain("Usage:")
      expect(stdout).toContain("Commands:")
   })

   it("should show vault subcommands in help", async () => {
      const { stdout } = await run(["help"])
      expect(stdout).toContain("vault set")
      expect(stdout).toContain("vault get")
      expect(stdout).toContain("vault list")
      expect(stdout).toContain("vault delete")
   })

   it("should show key export usage in help", async () => {
      const { stdout } = await run(["help"])
      expect(stdout).toContain("key export")
   })

   it("should exit 0 with unknown command (shows help)", async () => {
      const { exitCode } = await run(["unknown-command-xyz"])
      expect(exitCode).toBe(0)
   })
})

describe("CLI Export Edge Cases", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-export-edge-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-export-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[]) =>
      execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })

   it("should print 'No .secenvs file found' when exporting without init", async () => {
      // init (creates identity) but do NOT create a .secenvs file
      await run(["init"])
      // Remove the .secenvs file that init creates
      const secenvsFile = path.join(testDir, ".secenvs")
      if (fs.existsSync(secenvsFile)) {
         fs.unlinkSync(secenvsFile)
      }

      const { stdout, exitCode } = await run(["export", "--force"])
      expect(exitCode).toBe(0)
      expect(stdout).toContain("No .secenvs file found")
   })

   it("should export empty .secenvs with no output lines", async () => {
      await run(["init"])
      // .secenvs is created empty by init
      const { stdout, exitCode } = await run(["export", "--force"])
      expect(exitCode).toBe(0)
      // No KEY=VALUE lines
      expect(stdout).not.toMatch(/^\w+=/)
   })

   it("should export multiple keys in order", async () => {
      await run(["init"])
      await run(["set", "ALPHA", "first"])
      await run(["set", "BETA", "second"])
      await run(["set", "GAMMA", "third"])

      const { stdout, exitCode } = await run(["export", "--force"])
      expect(exitCode).toBe(0)
      expect(stdout).toContain("ALPHA=first")
      expect(stdout).toContain("BETA=second")
      expect(stdout).toContain("GAMMA=third")

      // Order should match insertion order
      const alphaPos = stdout.indexOf("ALPHA=first")
      const betaPos = stdout.indexOf("BETA=second")
      const gammaPos = stdout.indexOf("GAMMA=third")
      expect(alphaPos).toBeLessThan(betaPos)
      expect(betaPos).toBeLessThan(gammaPos)
   })
})

describe("CLI Doctor Details", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-doctor-detail-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-doctor-dh-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[]) =>
      execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })

   it("should output a check count summary line", async () => {
      await run(["init"])
      const { stdout } = await run(["doctor"])
      // e.g. "Doctor: 4/4 checks passed"
      expect(stdout).toMatch(/Doctor:\s+\d+\/\d+\s+checks passed/)
   })

   it("should show decryption count when keys exist", async () => {
      await run(["init"])
      await run(["set", "K1", "v1"])
      await run(["set", "K2", "v2"])

      const { stdout } = await run(["doctor"])
      expect(stdout).toContain("Decryption: 2/2 keys verified")
   })

   it("should show zero-key decryption when file is empty", async () => {
      await run(["init"])
      // .secenvs is empty after init
      const { stdout } = await run(["doctor"])
      expect(stdout).toContain("Decryption: 0/0 keys verified")
   })

   it("should report identity not found when no init", async () => {
      // No init — no identity
      const { stdout, exitCode } = await run(["doctor"])
      expect(exitCode).toBe(0)
      // Should mention identity not found
      expect(stdout).toContain("not found")
   })

   it("should show syntax line count", async () => {
      await run(["init"])
      await run(["set", "A", "1"])
      await run(["set", "B", "2"])

      const { stdout } = await run(["doctor"])
      // Should show encrypted count
      expect(stdout).toContain("encrypted")
   })
})

describe("CLI Vault Stdin", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-vaultstdin-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-vaultstdin-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[], input?: string) =>
      execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         input,
         reject: false,
      })

   it("should store vault value provided via stdin", async () => {
      await run(["init"])
      // vault set with no value argument — reads from stdin
      const { exitCode, stdout } = await run(["vault", "set", "SECRET_TOKEN"], "my-vault-secret\n")
      expect(exitCode).toBe(0)
      expect(stdout).toContain("Stored SECRET_TOKEN")

      // Verify it can be retrieved
      const { stdout: getOut } = await run(["vault", "get", "SECRET_TOKEN"])
      expect(getOut).toContain("my-vault-secret")
   })

   it("should read vault value with trailing newline stripped from stdin", async () => {
      await run(["init"])
      await run(["vault", "set", "MY_KEY"], "newline-test-value\n")

      const { stdout } = await run(["vault", "get", "MY_KEY"])
      // The trailing newline should be stripped (promptSecret removes last newline)
      expect(stdout).toContain("newline-test-value")
      expect(stdout).not.toContain("newline-test-value\n\n")
   })
})

describe("CLI Untrust Self", () => {
   let testDir: string
   let secenvHome: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-untrustself-"))
      secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-untrustself-home-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
      fs.rmSync(secenvHome, { recursive: true, force: true })
   })

   const run = (args: string[]) =>
      execa("node", [BIN_PATH, ...args], {
         cwd: testDir,
         env: { SECENV_HOME: secenvHome },
         reject: false,
      })

   it("should refuse to untrust own key when it's the only recipient", async () => {
      await run(["init"])
      await run(["set", "SECRET", "value"])

      // Get own public key
      const keyPath = path.join(secenvHome, ".secenvs", "keys", "default.key")
      const identity = fs.readFileSync(keyPath, "utf-8").trim()
      const ownPubkey = await getPublicKey(identity)

      // Trust a second key so that own key is seeded into the recipients file
      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)
      await run(["trust", bobPubkey])

      // Untrust Bob — that's fine, own key remains
      await run(["untrust", bobPubkey])

      // Now try to untrust own key — this is the only remaining recipient
      const { exitCode, stderr } = await run(["untrust", ownPubkey])
      expect(exitCode).toBe(1)
      expect(stderr).toContain("Cannot remove the last recipient")
   })

   it("should allow untrusting self when another recipient exists", async () => {
      await run(["init"])
      await run(["set", "SECRET", "value"])

      const keyPath = path.join(secenvHome, ".secenvs", "keys", "default.key")
      const identity = fs.readFileSync(keyPath, "utf-8").trim()
      const ownPubkey = await getPublicKey(identity)

      const bobIdentity = await generateIdentity()
      const bobPubkey = await getPublicKey(bobIdentity)

      // Trust Bob first (seeds own key + bob into recipients)
      await run(["trust", bobPubkey])

      // Now untrust self — Bob is still a recipient, so this should succeed
      const { exitCode, stdout } = await run(["untrust", ownPubkey])
      expect(exitCode).toBe(0)
      expect(stdout).toContain("Removed key")

      // Verify own key is no longer in .secenvs
      const content = fs.readFileSync(path.join(testDir, ".secenvs"), "utf-8")
      expect(content).not.toContain(ownPubkey)
   })
})
