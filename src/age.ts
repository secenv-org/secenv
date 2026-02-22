import * as age from "age-encryption"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import {
   IdentityNotFoundError,
   DecryptionError,
   EncryptionError,
   FileError,
   RecipientError,
} from "./errors.js"
import { ensureSafeDir, sanitizePath, safeReadFile } from "./filesystem.js"
import { parseEnvFile, getEnvPath, withLock, writeAtomicRaw } from "./parse.js"

const SECENV_DIR = ".secenvs"
const KEYS_DIR = "keys"
const DEFAULT_KEY_FILE = "default.key"

/** Name of the metadata key used in .secenvs to store recipients. */
export const RECIPIENT_METADATA_KEY = "_RECIPIENT"

/** Regex for a valid age X25519 public key (bech32 charset). */
const AGE_PUBKEY_REGEX = /^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/

function stream(a: Uint8Array): ReadableStream<Uint8Array> {
   return new ReadableStream({
      start(controller) {
         controller.enqueue(a)
         controller.close()
      },
   })
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
   if (!(stream instanceof ReadableStream)) {
      throw new Error("readAll expects a ReadableStream<Uint8Array>")
   }
   return new Uint8Array(await new Response(stream).arrayBuffer())
}

export function getKeysDir(): string {
   const baseDir = process.env.SECENV_HOME || os.homedir()
   const sanitizedBase = sanitizePath(baseDir)
   return path.join(sanitizedBase, SECENV_DIR, KEYS_DIR)
}

export function getDefaultKeyPath(): string {
   return path.join(getKeysDir(), DEFAULT_KEY_FILE)
}

export function ensureSecenvDir(): void {
   const keysDir = getKeysDir()
   ensureSafeDir(keysDir)
}

export async function generateIdentity(): Promise<string> {
   return age.generateX25519Identity()
}

export async function saveIdentity(identity: string): Promise<string> {
   ensureSecenvDir()
   const keyPath = getDefaultKeyPath()
   fs.writeFileSync(keyPath, identity, { mode: 0o600 })
   return keyPath
}

export async function loadIdentity(): Promise<string> {
   const keyPath = getDefaultKeyPath()

   if (!fs.existsSync(keyPath)) {
      throw new IdentityNotFoundError(keyPath)
   }

   return fs.readFileSync(keyPath, "utf-8")
}

/**
 * Validates an age X25519 public key and returns the normalized (trimmed) version.
 * Throws RecipientError if invalid.
 */
export function validatePublicKey(pubkey: string): string {
   const trimmed = pubkey.trim()
   if (!AGE_PUBKEY_REGEX.test(trimmed)) {
      throw new RecipientError(`Invalid age public key: '${trimmed}'. Expected format: age1<bech32-string>`)
   }
   return trimmed
}

export async function loadRecipients(projectDir: string): Promise<string[]> {
   const envPath = path.join(projectDir, ".secenvs")

   // 1. Load from .secenvs
   if (fs.existsSync(envPath)) {
      const parsed = parseEnvFile(envPath)
      const keys = parsed.lines
         .filter((line) => line.key === RECIPIENT_METADATA_KEY)
         .map((line) => line.value.trim())

      if (keys.length > 0) {
         return keys.map((k) => validatePublicKey(k))
      }
   }

   // 3. Fallback: single-recipient from local identity
   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }
   const identity = await loadIdentity()
   const pubkey = await getPublicKey(identity)
   return [pubkey]
}

/**
 * Writes the recipients list directly into the .secenvs file.
 * This preserves comments and existing secrets while updating the recipient block.
 */
export async function saveRecipients(projectDir: string, pubkeys: string[]): Promise<void> {
   const normalizedKeys = pubkeys.map((k) => validatePublicKey(k))
   const envPath = path.join(projectDir, ".secenvs")

   await withLock(envPath, async () => {
      const content = fs.existsSync(envPath) ? safeReadFile(envPath) : ""
      const lines = content.split("\n")

      // 1. Remote existing _RECIPIENT lines
      const otherLines = lines.filter((line) => {
         const trimmed = line.trim()
         if (!trimmed || trimmed.startsWith("#")) return true
         const eqIndex = trimmed.indexOf("=")
         if (eqIndex === -1) return true
         return trimmed.slice(0, eqIndex).trim() !== RECIPIENT_METADATA_KEY
      })

      // 2. Add new _RECIPIENT lines (usually at the top for visibility, but we'll append for safety if not found)
      // Actually, let's put them at the top after any initial comments
      const newLines: string[] = []
      let inserted = false

      for (const key of normalizedKeys) {
         newLines.push(`${RECIPIENT_METADATA_KEY}=${key}`)
      }

      const finalLines = [...newLines, ...otherLines]

      const finalContent =
         finalLines
            .join("\n")
            .replace(/\n{3,}/g, "\n\n") // Cleanup excessive whitespace
            .trim() + "\n"

      await writeAtomicRaw(envPath, finalContent)
   })
}

/**
 * Encrypt plaintext to one or more age public-key recipients.
 *
 * @param recipients - Age X25519 public keys (e.g. "age1...").
 *                     Pass a single-element array for the Phase-1 / single-recipient path.
 * @param plaintext  - Data to encrypt.
 *
 * Previously this function accepted a private-key identity string as the first argument.
 * That signature is now replaced: pass `[await getPublicKey(identity)]` for the equivalent
 * single-recipient behavior from Phase 1.
 */
export async function encrypt(
   recipients: string[],
   plaintext: string | Buffer | Uint8Array
): Promise<string> {
   if (!recipients || recipients.length === 0) {
      throw new EncryptionError("At least one recipient public key is required for encryption.")
   }

   const encrypter = new age.Encrypter()
   for (const pubkey of recipients) {
      const normalized = validatePublicKey(pubkey)
      encrypter.addRecipient(normalized)
   }

   const data = typeof plaintext === "string" ? Buffer.from(plaintext) : plaintext
   const encryptedStream = await encrypter.encrypt(
      stream(data instanceof Buffer ? data : new Uint8Array(data))
   )
   const encryptedBytes = await readAll(encryptedStream)
   return Buffer.from(encryptedBytes).toString("base64")
}

export async function decrypt(identity: string, encryptedMessage: string): Promise<Buffer> {
   try {
      const decrypter = new age.Decrypter()
      decrypter.addIdentity(identity)
      const armoredStream = stream(Buffer.from(encryptedMessage, "base64"))
      const decryptedStream = await decrypter.decrypt(armoredStream)
      const decryptedBytes = await readAll(decryptedStream)
      return Buffer.from(decryptedBytes)
   } catch (error) {
      throw new DecryptionError(`Failed to decrypt value: ${error}`)
   }
}

export async function decryptString(identity: string, encryptedMessage: string): Promise<string> {
   const buffer = await decrypt(identity, encryptedMessage)
   return buffer.toString("utf-8")
}

export function identityExists(): boolean {
   const keyPath = getDefaultKeyPath()
   return fs.existsSync(keyPath)
}

export async function getPublicKey(identity: string): Promise<string> {
   return age.identityToRecipient(identity)
}
