import { SecenvSDK, createSecenv } from '../../src/env.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';
import { 
  generateIdentity, 
  saveIdentity, 
  encrypt 
} from '../../src/age.js';
import { SecretNotFoundError, IdentityNotFoundError } from '../../src/errors.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('Secenv SDK (env.ts)', () => {
  let testCwd: string;
  let testHome: string;
  let originalCwd: string;
  let originalEnvHome: string;
  let identity: string;

  beforeAll(async () => {
    identity = await generateIdentity();
  });

  beforeEach(async () => {
    testCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-sdk-cwd-'));
    testHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-sdk-home-'));
    originalCwd = process.cwd();
    originalEnvHome = process.env.SECENV_HOME || '';
    
    process.chdir(testCwd);
    process.env.SECENV_HOME = testHome;
    
    // Save identity in test home
    await saveIdentity(identity);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    process.env.SECENV_HOME = originalEnvHome;
    fs.rmSync(testCwd, { recursive: true, force: true });
    fs.rmSync(testHome, { recursive: true, force: true });
    // Clean up environment variables used in tests
    delete process.env.TEST_OVERRIDE;
    delete process.env.TEST_KEY;
    delete process.env.SECENV_ENCODED_IDENTITY;
  });

  it('should return value from process.env if present (priority 1)', async () => {
    process.env.TEST_KEY = 'process-value';
    const sdk = createSecenv();
    
    const value = await sdk.get('TEST_KEY');
    expect(value).toBe('process-value');
  });

  it('should return plaintext value from .env.enc', async () => {
    fs.writeFileSync('.env.enc', 'PLAIN_KEY=plaintext-value\n');
    const sdk = createSecenv();
    
    const value = await sdk.get('PLAIN_KEY');
    expect(value).toBe('plaintext-value');
  });

  it('should return decrypted value from .env.enc', async () => {
    const encrypted = await encrypt(identity, 'secret-value');
    fs.writeFileSync('.env.enc', `SECRET_KEY=enc:age:${encrypted}\n`);
    
    const sdk = createSecenv();
    const value = await sdk.get('SECRET_KEY');
    expect(value).toBe('secret-value');
  });

  it('should throw SecretNotFoundError if key missing in both', async () => {
    fs.writeFileSync('.env.enc', 'SOME_KEY=value\n');
    const sdk = createSecenv();
    
    await expect(sdk.get('MISSING_KEY')).rejects.toThrow(SecretNotFoundError);
  });

  it('should prioritize process.env over .env.enc', async () => {
    process.env.TEST_OVERRIDE = 'overridden';
    fs.writeFileSync('.env.enc', 'TEST_OVERRIDE=original\n');
    
    const sdk = createSecenv();
    const value = await sdk.get('TEST_OVERRIDE');
    expect(value).toBe('overridden');
  });

  it('should cache decrypted values', async () => {
    const encrypted = await encrypt(identity, 'cache-me');
    fs.writeFileSync('.env.enc', `CACHE_KEY=enc:age:${encrypted}\n`);
    
    const sdk = createSecenv();
    
    // First call (decrypts)
    const val1 = await sdk.get('CACHE_KEY');
    expect(val1).toBe('cache-me');
    
    // Delete identity - if cached, second call should still work
    const keyPath = path.join(testHome, '.secenv', 'keys', 'default.key');
    fs.unlinkSync(keyPath);
    
    const val2 = await sdk.get('CACHE_KEY');
    expect(val2).toBe('cache-me');
  });

  it('should invalidate cache if .env.enc is modified', async () => {
    fs.writeFileSync('.env.enc', 'VAL=first\n');
    const sdk = createSecenv();
    
    expect(await sdk.get('VAL')).toBe('first');
    
    // Small delay to ensure mtime changes
    await new Promise(resolve => setTimeout(resolve, 100));
    
    fs.writeFileSync('.env.enc', 'VAL=second\n');
    
    expect(await sdk.get('VAL')).toBe('second');
  });

  it('should handle SECENV_ENCODED_IDENTITY in CI', async () => {
    const encoded = Buffer.from(identity).toString('base64');
    process.env.SECENV_ENCODED_IDENTITY = encoded;
    
    // Remove local identity file to prove it uses the env var
    const keyPath = path.join(testHome, '.secenv', 'keys', 'default.key');
    fs.unlinkSync(keyPath);
    
    const encrypted = await encrypt(identity, 'ci-secret');
    fs.writeFileSync('.env.enc', `CI_KEY=enc:age:${encrypted}\n`);
    
    const sdk = createSecenv();
    const value = await sdk.get('CI_KEY');
    expect(value).toBe('ci-secret');
  });

  it('should throw IdentityNotFoundError if no identity available', async () => {
    const keyPath = path.join(testHome, '.secenv', 'keys', 'default.key');
    fs.unlinkSync(keyPath);
    
    const encrypted = await encrypt(identity, 'fails');
    fs.writeFileSync('.env.enc', `FAIL_KEY=enc:age:${encrypted}\n`);
    
    const sdk = createSecenv();
    await expect(sdk.get('FAIL_KEY')).rejects.toThrow(IdentityNotFoundError);
  });

  it('has() should check both process.env and .env.enc', async () => {
    process.env.PROC_KEY = 'val';
    fs.writeFileSync('.env.enc', 'FILE_KEY=val\n');
    
    const sdk = createSecenv();
    expect(sdk.has('PROC_KEY')).toBe(true);
    expect(sdk.has('FILE_KEY')).toBe(true);
    expect(sdk.has('MISSING')).toBe(false);
  });

  it('keys() should return all keys', async () => {
    process.env.K1 = 'v1';
    fs.writeFileSync('.env.enc', 'K2=v2\nK3=v3\n');
    
    const sdk = createSecenv();
    const allKeys = sdk.keys();
    
    expect(allKeys).toContain('K1');
    expect(allKeys).toContain('K2');
    expect(allKeys).toContain('K3');
  });

  it('clearCache() should reset internal state', async () => {
    fs.writeFileSync('.env.enc', 'KEY=val1\n');
    const sdk = createSecenv();
    
    await sdk.get('KEY');
    sdk.clearCache();
    
    fs.writeFileSync('.env.enc', 'KEY=val2\n');
    expect(await sdk.get('KEY')).toBe('val2');
  });
});
