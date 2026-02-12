import { execa } from 'execa';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';
import { createSecenv } from '../../src/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenv');

describe('CI/CD Scenarios', () => {
  let testDir: string;
  let secenvHome: string;
  let originalCwd: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-ci-cwd-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-ci-home-'));
    originalCwd = process.cwd();
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
    delete process.env.SECENV_ENCODED_IDENTITY;
    delete process.env.SECENV_HOME;
  });

  const runCLI = (args: string[]) => {
    return execa('node', [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
  };

  it('should work with SECENV_ENCODED_IDENTITY even if .env.enc has different owner/context', async () => {
    // 1. Setup identity and encrypted file in "dev" environment
    await runCLI(['init']);
    await runCLI(['set', 'CI_SECRET', 'top-secret']);
    
    const identityPath = path.join(secenvHome, '.secenv', 'keys', 'default.key');
    const identity = fs.readFileSync(identityPath, 'utf-8');
    const encodedIdentity = Buffer.from(identity).toString('base64');
    
    const envEncContent = fs.readFileSync('.env.enc', 'utf-8');

    // 2. Simulate "CI" environment: new temp dir, no identity file, only env var and .env.enc
    const ciDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-ci-sim-'));
    const ciHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-ci-home-sim-'));
    
    fs.writeFileSync(path.join(ciDir, '.env.enc'), envEncContent);
    
    process.chdir(ciDir);
    process.env.SECENV_ENCODED_IDENTITY = encodedIdentity;
    process.env.SECENV_HOME = ciHome; // Should be ignored if encoded identity present

    const env = createSecenv();
    expect(await env.get('CI_SECRET')).toBe('top-secret');

    fs.rmSync(ciDir, { recursive: true, force: true });
    fs.rmSync(ciHome, { recursive: true, force: true });
  });

  it('should fail gracefully in CI if identity is missing', async () => {
    fs.writeFileSync('.env.enc', 'SECRET=enc:age:abc\n');
    
    // No local identity, no SECENV_ENCODED_IDENTITY
    process.env.SECENV_HOME = secenvHome; // Empty home
    
    const env = createSecenv();
    await expect(env.get('SECRET')).rejects.toThrow('Identity key not found');
  });

  it('should fail in CI if SECENV_ENCODED_IDENTITY is invalid base64', async () => {
    fs.writeFileSync('.env.enc', 'SECRET=enc:age:abc\n');
    process.env.SECENV_ENCODED_IDENTITY = '!!!not-base64!!!';
    
    const env = createSecenv();
    // age-encryption might fail later during decryption, or loadIdentity might fail.
    // Actually, Buffer.from with invalid base64 might just produce garbage.
    // But if it's garbage, decryption WILL fail.
    await expect(env.get('SECRET')).rejects.toThrow();
  });
});
