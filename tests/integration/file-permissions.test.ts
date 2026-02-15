import { execa } from 'execa';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenvs');

describe('File Permissions (Unix)', () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-perm-cwd-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-perm-home-'));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
  });

  const run = (args: string[]) => {
    return execa('node', [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
  };

  it('should enforce 0600 on identity file', async () => {
    if (os.platform() === 'win32') {
      return; // Skip on Windows
    }

    await run(['init']);
    const keyPath = path.join(secenvHome, '.secenvs', 'keys', 'default.key');
    const stats = fs.statSync(keyPath);
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it('should enforce 0700 on keys directory', async () => {
    if (os.platform() === 'win32') {
      return; // Skip on Windows
    }

    await run(['init']);
    const keysDir = path.join(secenvHome, '.secenvs', 'keys');
    const stats = fs.statSync(keysDir);
    expect(stats.mode & 0o777).toBe(0o700);
  });

  it('should doctor warn if permissions are too open', async () => {
    if (os.platform() === 'win32') {
      return; // Skip on Windows
    }

    await run(['init']);
    const keyPath = path.join(secenvHome, '.secenvs', 'keys', 'default.key');
    
    // Make it too open
    fs.chmodSync(keyPath, 0o644);
    
    const { stdout } = await run(['doctor']);
    expect(stdout).toContain('permissions should be 0600');
  });
});
