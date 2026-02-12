import { execa } from 'execa';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';
import { createSecenv } from '../../src/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenv');

describe('E2E Workflow', () => {
  let testDir: string;
  let secenvHome: string;
  let originalCwd: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-e2e-cwd-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-e2e-home-'));
    originalCwd = process.cwd();
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
  });

  const runCLI = (args: string[]) => {
    return execa('node', [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
  };

  it('should work from CLI to SDK', async () => {
    // 1. Initialize via CLI
    await runCLI(['init']);

    // 2. Set an encrypted secret via CLI
    await runCLI(['set', 'DB_PASSWORD', 'super-secret-password']);

    // 3. Set a plaintext config via CLI (manually adding to .env.enc for now since 'set' encrypts by default)
    fs.appendFileSync(path.join(testDir, '.env.enc'), 'PORT=5432\n');

    // 4. Access via SDK
    // Note: We need to point the SDK to the test environment
    process.env.SECENV_HOME = secenvHome;
    
    const env = createSecenv();
    
    const dbPassword = await env.get('DB_PASSWORD');
    expect(dbPassword).toBe('super-secret-password');

    const port = await env.get('PORT');
    expect(port).toBe('5432');

    expect(env.has('DB_PASSWORD')).toBe(true);
    expect(env.has('PORT')).toBe(true);
    expect(env.has('NON_EXISTENT')).toBe(false);
  });

  it('should prioritize process.env over .env.enc', async () => {
    await runCLI(['init']);
    await runCLI(['set', 'OVERRIDE_ME', 'original']);
    
    process.env.SECENV_HOME = secenvHome;
    process.env.OVERRIDE_ME = 'overridden';

    const env = createSecenv();
    const value = await env.get('OVERRIDE_ME');
    expect(value).toBe('overridden');

    // Cleanup process.env to not affect other tests if any
    delete process.env.OVERRIDE_ME;
  });

  it('should work with SECENV_ENCODED_IDENTITY', async () => {
    await runCLI(['init']);
    await runCLI(['set', 'CI_SECRET', 'ci-value']);

    const identityPath = path.join(secenvHome, '.secenv', 'keys', 'default.key');
    const identity = fs.readFileSync(identityPath, 'utf-8');
    const encodedIdentity = Buffer.from(identity).toString('base64');

    // Simulate CI environment where local key doesn't exist but env var does
    fs.rmSync(secenvHome, { recursive: true, force: true });
    
    process.env.SECENV_ENCODED_IDENTITY = encodedIdentity;
    
    const env = createSecenv();
    const value = await env.get('CI_SECRET');
    expect(value).toBe('ci-value');

    delete process.env.SECENV_ENCODED_IDENTITY;
  });

  it('should handle multiple keys and mixed types', async () => {
    await runCLI(['init']);
    await runCLI(['set', 'SECRET_1', 'val1']);
    await runCLI(['set', 'SECRET_2', 'val2']);
    fs.appendFileSync(path.join(testDir, '.env.enc'), 'PLAIN=plain-val\n');

    process.env.SECENV_HOME = secenvHome;
    const env = createSecenv();

    expect(await env.get('SECRET_1')).toBe('val1');
    expect(await env.get('SECRET_2')).toBe('val2');
    expect(await env.get('PLAIN')).toBe('plain-val');

    const keys = env.keys();
    expect(keys).toContain('SECRET_1');
    expect(keys).toContain('SECRET_2');
    expect(keys).toContain('PLAIN');
  });

  it('should handle base64 values (certificates)', async () => {
    await runCLI(['init']);
    const cert = '-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIJAJ...\n-----END CERTIFICATE-----';
    const certBase64 = Buffer.from(cert).toString('base64');
    
    await runCLI(['set', 'TLS_CERT', certBase64, '--base64']);

    process.env.SECENV_HOME = secenvHome;
    const env = createSecenv();
    
    const retrievedBase64 = await env.get('TLS_CERT');
    expect(retrievedBase64).toBe(certBase64);
    
    const retrievedCert = Buffer.from(retrievedBase64, 'base64').toString('utf-8');
    expect(retrievedCert).toBe(cert);
  });
});
