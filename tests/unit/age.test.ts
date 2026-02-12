import { 
  generateIdentity, 
  saveIdentity, 
  loadIdentity, 
  identityExists, 
  getPublicKey, 
  encrypt, 
  decrypt,
  getDefaultKeyPath,
  getKeysDir
} from '../../src/age.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { DecryptionError, IdentityNotFoundError } from '../../src/errors.js';

describe('Age Encryption (age.ts)', () => {
  const testHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-age-test-'));
  const originalEnvHome = process.env.SECENV_HOME;

  beforeAll(() => {
    process.env.SECENV_HOME = testHome;
  });

  afterAll(() => {
    fs.rmSync(testHome, { recursive: true, force: true });
    process.env.SECENV_HOME = originalEnvHome;
  });

  it('should generate a valid X25519 identity', async () => {
    const identity = await generateIdentity();
    expect(identity).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]+$/);
  });

  it('should save and load identity', async () => {
    const identity = await generateIdentity();
    const keyPath = await saveIdentity(identity);
    
    expect(fs.existsSync(keyPath)).toBe(true);
    
    const loaded = await loadIdentity();
    expect(loaded).toBe(identity);
  });

  it('should verify identity exists', async () => {
    // Already saved in previous test, but let's be explicit
    const identity = await generateIdentity();
    await saveIdentity(identity);
    expect(identityExists()).toBe(true);
  });

  it('should return false if identity does not exist', () => {
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-fake-home-'));
    const oldHome = process.env.SECENV_HOME;
    process.env.SECENV_HOME = fakeHome;
    
    expect(identityExists()).toBe(false);
    
    process.env.SECENV_HOME = oldHome;
    fs.rmSync(fakeHome, { recursive: true, force: true });
  });

  it('should derive public key (recipient) from identity', async () => {
    const identity = await generateIdentity();
    const publicKey = await getPublicKey(identity);
    expect(publicKey).toMatch(/^age1[a-z0-9]+$/);
  });

  it('should encrypt and decrypt a string', async () => {
    const identity = await generateIdentity();
    const plaintext = 'Hello, Antigravity!';
    
    const encrypted = await encrypt(identity, plaintext);
    expect(encrypted).not.toBe(plaintext);
    
    const decrypted = await decrypt(identity, encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt UTF-8 characters', async () => {
    const identity = await generateIdentity();
    const plaintext = '🔒 Secenv is cool! 🚀 \u1234';
    
    const encrypted = await encrypt(identity, plaintext);
    const decrypted = await decrypt(identity, encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt empty string', async () => {
    const identity = await generateIdentity();
    const plaintext = '';
    
    const encrypted = await encrypt(identity, plaintext);
    const decrypted = await decrypt(identity, encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it('should throw DecryptionError with wrong identity', async () => {
    const identity1 = await generateIdentity();
    const identity2 = await generateIdentity();
    const plaintext = 'Secret Message';
    
    const encrypted = await encrypt(identity1, plaintext);
    
    await expect(decrypt(identity2, encrypted)).rejects.toThrow(DecryptionError);
  });

  it('should throw DecryptionError with corrupted ciphertext', async () => {
    const identity = await generateIdentity();
    const encrypted = await encrypt(identity, 'test');
    const corrupted = encrypted.substring(0, encrypted.length - 10) + 'invalid';
    
    await expect(decrypt(identity, corrupted)).rejects.toThrow(DecryptionError);
  });

  it('should throw IdentityNotFoundError when loading missing key', async () => {
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-missing-key-'));
    const oldHome = process.env.SECENV_HOME;
    process.env.SECENV_HOME = fakeHome;
    
    await expect(loadIdentity()).rejects.toThrow(IdentityNotFoundError);
    
    process.env.SECENV_HOME = oldHome;
    fs.rmSync(fakeHome, { recursive: true, force: true });
  });

  it('should set 0600 permissions on identity file (Unix)', async () => {
    if (os.platform() === 'win32') {
      return; // Skip on Windows
    }
    
    const identity = await generateIdentity();
    const keyPath = await saveIdentity(identity);
    
    const stats = fs.statSync(keyPath);
    // 0600 is 384 in decimal
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it('should create keys directory with 0700 permissions (Unix)', async () => {
    if (os.platform() === 'win32') {
      return; // Skip on Windows
    }
    
    const identity = await generateIdentity();
    await saveIdentity(identity);
    
    const keysDir = getKeysDir();
    const stats = fs.statSync(keysDir);
    // 0700 is 448 in decimal
    expect(stats.mode & 0o777).toBe(0o700);
  });
});
