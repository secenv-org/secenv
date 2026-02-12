import { execa } from 'execa';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenv');

describe('CLI Error Handling', () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-cli-err-cwd-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-cli-err-home-'));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
  });

  const run = (args: string[]) => {
    return execa('node', [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome },
      reject: false
    });
  };

  it('should fail when key is missing in set command', async () => {
    const { exitCode, stderr } = await run(['set']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Missing KEY argument');
  });

  it('should fail when key is missing in get command', async () => {
    const { exitCode, stderr } = await run(['get']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Missing KEY argument');
  });

  it('should fail when key is missing in delete command', async () => {
    const { exitCode, stderr } = await run(['delete']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Missing KEY argument');
  });

  it('should fail when get is called without init', async () => {
    const { exitCode, stderr } = await run(['get', 'SOME_KEY']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Identity key not found');
  });

  it('should fail when set is called without init', async () => {
    const { exitCode, stderr } = await run(['set', 'SOME_KEY', 'val']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Identity key not found');
  });

  it('should fail when secret not found in get command', async () => {
    await run(['init']);
    const { exitCode, stderr } = await run(['get', 'MISSING_KEY']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("Secret 'MISSING_KEY' not found");
  });

  it('should fail when secret not found in delete command', async () => {
    await run(['init']);
    const { exitCode, stderr } = await run(['delete', 'MISSING_KEY']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("Secret 'MISSING_KEY' not found");
  });

  it('should fail when multiline value is set without --base64', async () => {
    await run(['init']);
    const { exitCode, stderr } = await run(['set', 'MULTI', 'line1\nline2']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Multiline values are not allowed');
  });

  it('should handle corrupted .env.enc', async () => {
    await run(['init']);
    fs.writeFileSync(path.join(testDir, '.env.enc'), 'INVALID_LINE\n');
    const { exitCode, stderr } = await run(['get', 'KEY']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Invalid line: missing \'=\' separator');
  });

  it('should handle duplicate keys in .env.enc', async () => {
    await run(['init']);
    fs.writeFileSync(path.join(testDir, '.env.enc'), 'KEY=1\nKEY=2\n');
    const { exitCode, stderr } = await run(['get', 'KEY']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("Duplicate key 'KEY'");
  });
});
