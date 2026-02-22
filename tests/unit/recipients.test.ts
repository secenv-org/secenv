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
   RECIPIENTS_FILE,
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

      it("reads keys from an existing recipients file", async () => {
         const identity = await generateIdentity()
         const pubkey = await getPublicKey(identity)

         const recipientsFile = path.join(projectDir, RECIPIENTS_FILE)
         fs.writeFileSync(recipientsFile, `# Team recipients\n${pubkey}\n`)

         const recipients = await loadRecipients(projectDir)
         expect(recipients).toEqual([pubkey])
      })

      it("skips comment lines and blank lines in recipients file", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)

         const content = `# Alice\n${pubkeyA}\n\n# Bob\n${pubkeyB}\n`
         fs.writeFileSync(path.join(projectDir, RECIPIENTS_FILE), content)

         const recipients = await loadRecipients(projectDir)
         expect(recipients).toEqual([pubkeyA, pubkeyB])
      })

      it("throws RecipientError when recipients file has no valid keys", async () => {
         const recipientsFile = path.join(projectDir, RECIPIENTS_FILE)
         fs.writeFileSync(recipientsFile, "# only comments\n\n")

         await expect(loadRecipients(projectDir)).rejects.toThrow(RecipientError)
      })

      it("throws RecipientError when recipients file contains an invalid key", async () => {
         const recipientsFile = path.join(projectDir, RECIPIENTS_FILE)
         fs.writeFileSync(recipientsFile, "not-an-age-key\n")

         await expect(loadRecipients(projectDir)).rejects.toThrow(RecipientError)
      })
   })

   describe("saveRecipients()", () => {
      it("writes keys one-per-line to the recipients file", async () => {
         const identityA = await generateIdentity()
         const identityB = await generateIdentity()
         const pubkeyA = await getPublicKey(identityA)
         const pubkeyB = await getPublicKey(identityB)

         await saveRecipients(projectDir, [pubkeyA, pubkeyB])

         const content = fs.readFileSync(path.join(projectDir, RECIPIENTS_FILE), "utf-8")
         expect(content).toBe(`${pubkeyA}\n${pubkeyB}\n`)
      })

      it("throws RecipientError if an invalid key is included", async () => {
         await expect(saveRecipients(projectDir, ["not-valid"])).rejects.toThrow(RecipientError)
      })

      it("overwrites an existing recipients file", async () => {
         const identity = await generateIdentity()
         const pubkey = await getPublicKey(identity)

         await saveRecipients(projectDir, [pubkey])
         const identityB = await generateIdentity()
         const pubkeyB = await getPublicKey(identityB)
         await saveRecipients(projectDir, [pubkeyB])

         const content = fs.readFileSync(path.join(projectDir, RECIPIENTS_FILE), "utf-8")
         expect(content).toBe(`${pubkeyB}\n`)
      })
   })
})
