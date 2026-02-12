import * as age from 'age-encryption';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  IdentityNotFoundError,
  DecryptionError,
  EncryptionError,
  FileError
} from './errors.js';

const SECENV_DIR = '.secenv';
const KEYS_DIR = 'keys';
const DEFAULT_KEY_FILE = 'default.key';

function stream(a: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(a);
      controller.close();
    }
  });
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  if (!(stream instanceof ReadableStream)) {
    throw new Error("readAll expects a ReadableStream<Uint8Array>");
  }
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function getKeysDir(): string {
  const baseDir = process.env.SECENV_HOME || os.homedir();
  return path.join(baseDir, SECENV_DIR, KEYS_DIR);
}

export function getDefaultKeyPath(): string {
  return path.join(getKeysDir(), DEFAULT_KEY_FILE);
}

export function ensureSecenvDir(): void {
  const keysDir = getKeysDir();
  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  }
}

export async function generateIdentity(): Promise<string> {
  return age.generateX25519Identity();
}

export async function saveIdentity(identity: string): Promise<string> {
  ensureSecenvDir();
  const keyPath = getDefaultKeyPath();
  fs.writeFileSync(keyPath, identity, { mode: 0o600 });
  return keyPath;
}

export async function loadIdentity(): Promise<string> {
  const keyPath = getDefaultKeyPath();

  if (!fs.existsSync(keyPath)) {
    throw new IdentityNotFoundError(keyPath);
  }

  return fs.readFileSync(keyPath, 'utf-8');
}

export async function encrypt(identity: string, plaintext: string): Promise<string> {
  const recipient = await age.identityToRecipient(identity);
  const encrypter = new age.Encrypter();
  encrypter.addRecipient(recipient);
  const encryptedStream = await encrypter.encrypt(stream(Buffer.from(plaintext)));
  const encryptedBytes = await readAll(encryptedStream);
  return Buffer.from(encryptedBytes).toString('base64');
}

export async function decrypt(identity: string, encryptedMessage: string): Promise<string> {
  try {
    const decrypter = new age.Decrypter();
    decrypter.addIdentity(identity);
    const armoredStream = stream(Buffer.from(encryptedMessage, 'base64'));
    const decryptedStream = await decrypter.decrypt(armoredStream);
    const decryptedBytes = await readAll(decryptedStream);
    return new TextDecoder().decode(decryptedBytes);
  } catch (error) {
    throw new DecryptionError(`Failed to decrypt value: ${error}`);
  }
}

export function identityExists(): boolean {
  const keyPath = getDefaultKeyPath();
  return fs.existsSync(keyPath);
}

export async function getPublicKey(identity: string): Promise<string> {
  return age.identityToRecipient(identity);
}
