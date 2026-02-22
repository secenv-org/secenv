import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import {
   generateIdentity,
   saveIdentity,
   getPublicKey,
   encrypt,
   decrypt,
   loadRecipients,
   saveRecipients,
   validatePublicKey,
   RECIPIENT_METADATA_KEY,
} from "../../src/age.js"
import { RecipientError, IdentityNotFoundError } from "../../src/errors.js"

describe("Multi-Recipient Encryption (recipients)", () => {
   let testHome: string
   let projectDir: string
   const originalEnvHome = process.env.SECENV_HOME

   beforeEach(() => {
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-recipients-test-"))
      projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-project-test-"))
      process.env.SECENV_HOME = testHome
   })

   afterEach(() => {
      fs.rmSync(testHome, { recursive: true, force: true })
      fs.rmSync(projectDir, { recursive: true, force: true })
      process.env.SECENV_HOME = originalEnvHome
   })

   // ─── validatePublicKey ────────────────────────────────────────────────────

   describe("validatePublicKey()", () => {
      it("accepts a valid age X25519 public key", () => {
         // generated real key structure
         const validKey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
         expect(() => validatePublicKey(validKey)).not.toThrow()
      })

      it("rejects a key that doesn't start with 'age1'", () => {
         expect(() => validatePublicKey("AGE-SECRET-KEY-1abc")).toThrow(RecipientError)
      })

      it("rejects an empty string", () => {
         expect(() => validatePublicKey("")).toThrow(RecipientError)
      })

      it("rejects a key with uppercase chars after age1", () => {
         expect(() => validatePublicKey("age1ABCDEF")).toThrow(RecipientError)
      })
   })

   // ─── encrypt / decrypt multi-recipient ────────────────────────────────────

   describe("encrypt() with multiple recipients", () => {
      it("encrypts to a single recipient (backward-compat)", async () => {
         const identity = await generateIdentity()
         const pubkey = await getPublicKey(identity)
         const plaintext = "single recipient secret"

         const encrypted = await encrypt([pubkey], plaintext)
         const decrypted = await decrypt(identity, encrypted)
         expect(decrypted.toString()).toBe(plaintext)
      })

      it("encrypts to two recipients and both can decrypt", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)
         const plaintext = "shared team secret"

         const encrypted = await encrypt([pubkeyA, pubkeyB], plaintext)

         const decryptedA = await decrypt(identityA, encrypted)
         const decryptedB = await decrypt(identityB, encrypted)

         expect(decryptedA.toString()).toBe(plaintext)
         expect(decryptedB.toString()).toBe(plaintext)
      })

      it("a third party (not a recipient) cannot decrypt", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const identityC = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)

         const encrypted = await encrypt([pubkeyA, pubkeyB], "secret")

         const { DecryptionError } = await import("../../src/errors.js")
         await expect(decrypt(identityC, encrypted)).rejects.toThrow(DecryptionError)
      })

      it("throws EncryptionError when recipients list is empty", async () => {
         const { EncryptionError } = await import("../../src/errors.js")
         await expect(encrypt([], "secret")).rejects.toThrow(EncryptionError)
      })

      it("encrypts and decrypts empty string to multiple recipients", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)

         const encrypted = await encrypt([pubkeyA, pubkeyB], "")
         const decrypted = await decrypt(identityA, encrypted)
         expect(decrypted.toString()).toBe("")
      })

      it("encrypts Buffer to multiple recipients", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)
         const data = Buffer.from("binary data \x00\x01\x02")

         const encrypted = await encrypt([pubkeyA, pubkeyB], data)
         const decryptedA = await decrypt(identityA, encrypted)
         const decryptedB = await decrypt(identityB, encrypted)
         expect(decryptedA).toEqual(data)
         expect(decryptedB).toEqual(data)
      })
   })

   // ─── loadRecipients / saveRecipients ─────────────────────────────────────

   describe("loadRecipients()", () => {
      it("falls back to local identity pubkey when no recipients file exists", async () => {
         const identity = await generateIdentity()
         await saveIdentity(identity)
         const pubkey = await getPublicKey(identity)

         const recipients = await loadRecipients(projectDir)
         expect(recipients).toEqual([pubkey])
      })

      it("throws IdentityNotFoundError when no recipients file and no identity", async () => {
         // testHome is fresh — no identity saved
         await expect(loadRecipients(projectDir)).rejects.toThrow(IdentityNotFoundError)
      })

      it("reads keys from an existing .secenvs file", async () => {
         const identity = await generateIdentity()
         const pubkey = await getPublicKey(identity)

         const envFile = path.join(projectDir, ".secenvs")
         fs.writeFileSync(envFile, `# Metadata\n${RECIPIENT_METADATA_KEY}=${pubkey}\n`)

         const recipients = await loadRecipients(projectDir)
         expect(recipients).toEqual([pubkey])
      })

      it("skips non-recipient lines in .secenvs file", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)

         const content = `OTHER_KEY=value\n${RECIPIENT_METADATA_KEY}=${pubkeyA}\n\n# Comment\n${RECIPIENT_METADATA_KEY}=${pubkeyB}\n`
         fs.writeFileSync(path.join(projectDir, ".secenvs"), content)

         const recipients = await loadRecipients(projectDir)
         expect(recipients).toEqual([pubkeyA, pubkeyB])
      })

      it("falls back to local identity if .secenvs exists but contains no recipients", async () => {
         const identity = await generateIdentity()
         await saveIdentity(identity)
         const pubkey = await getPublicKey(identity)

         const envFile = path.join(projectDir, ".secenvs")
         fs.writeFileSync(envFile, "SOME_SECRET=value\n")

         const recipients = await loadRecipients(projectDir)
         expect(recipients).toEqual([pubkey])
      })

      it("throws RecipientError when .secenvs contains an invalid recipient key", async () => {
         const envFile = path.join(projectDir, ".secenvs")
         fs.writeFileSync(envFile, `${RECIPIENT_METADATA_KEY}=not-an-age-key\n`)

         await expect(loadRecipients(projectDir)).rejects.toThrow(RecipientError)
      })
   })

   describe("saveRecipients()", () => {
      it("writes keys as metadata to the .secenvs file", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)

         await saveRecipients(projectDir, [pubkeyA, pubkeyB])

         const content = fs.readFileSync(path.join(projectDir, ".secenvs"), "utf-8")
         expect(content).toContain(`${RECIPIENT_METADATA_KEY}=${pubkeyA}`)
         expect(content).toContain(`${RECIPIENT_METADATA_KEY}=${pubkeyB}`)
      })

      it("throws RecipientError if an invalid key is included", async () => {
         await expect(saveRecipients(projectDir, ["not-valid"])).rejects.toThrow(RecipientError)
      })

      it("overwrites existing recipients in .secenvs while preserving other lines", async () => {
         const envFile = path.join(projectDir, ".secenvs")
         fs.writeFileSync(envFile, "API_KEY=secret\n_RECIPIENT=oldkey\n")

         const identity = await generateIdentity()
         const pubkey = await getPublicKey(identity)

         await saveRecipients(projectDir, [pubkey])

         const content = fs.readFileSync(envFile, "utf-8")
         expect(content).toContain("API_KEY=secret")
         expect(content).toContain(`${RECIPIENT_METADATA_KEY}=${pubkey}`)
         expect(content).not.toContain("oldkey")
      })
   })
})
