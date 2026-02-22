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
import { writeAtomic } from "./parse.js"

const SECENV_DIR = ".secenvs"
const KEYS_DIR = "keys"
const DEFAULT_KEY_FILE = "default.key"

/** Name of the per-project recipients file (committed to git). */
export const RECIPIENTS_FILE = ".secenvs.recipients"

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

/**
 * Reads recipients from <projectDir>/.secenvs.recipients.
 * Each non-blank, non-comment line is treated as an age public key.
 * Falls back to the local identity's public key if the file doesn't exist,
 * preserving full backward-compatibility with Phase 1 projects.
 */
export async function loadRecipients(projectDir: string): Promise<string[]> {
   const recipientsPath = path.join(projectDir, RECIPIENTS_FILE)

   if (!fs.existsSync(recipientsPath)) {
      // Backward-compat: single-recipient from local identity
      if (!identityExists()) {
         throw new IdentityNotFoundError(getDefaultKeyPath())
      }
      const identity = await loadIdentity()
      const pubkey = await getPublicKey(identity)
      return [pubkey]
   }

   const content = safeReadFile(recipientsPath)
   const keys = content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"))

   if (keys.length === 0) {
      throw new RecipientError(
         `${RECIPIENTS_FILE} exists but contains no valid public keys. Add at least one age public key or delete the file.`
      )
   }

   for (let i = 0; i < keys.length; i++) {
      keys[i] = validatePublicKey(keys[i])
   }

   return keys
}

/**
 * Writes a recipients list to <projectDir>/.secenvs.recipients.
 * Overwrites the file completely; callers are responsible for the full key list.
 */
export async function saveRecipients(projectDir: string, pubkeys: string[]): Promise<void> {
   const normalizedKeys: string[] = []
   for (const key of pubkeys) {
      normalizedKeys.push(validatePublicKey(key))
   }
   const recipientsPath = path.join(projectDir, RECIPIENTS_FILE)
   const content = normalizedKeys.join("\n") + "\n"
   await writeAtomic(recipientsPath, content)
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
