import { execa } from 'execa';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenvs');

describe('CLI Interactive', () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-cli-int-cwd-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-cli-int-home-'));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
  });

  const run = (args: string[], input?: string) => {
    return execa('node', [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome },
      reject: false,
      input: input ? input + '\n' : undefined
    });
  };

  it('should prompt for value in set command if not provided', async () => {
    await execa('node', [BIN_PATH, 'init'], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });

    const child = run(['set', 'INTERACTIVE_KEY'], 'secret-from-stdin');
    const { stdout, exitCode } = await child;

    expect(exitCode).toBe(0);
    expect(stdout).toContain('Encrypted and stored INTERACTIVE_KEY');

    const getChild = run(['get', 'INTERACTIVE_KEY']);
    const getResult = await getChild;
    expect(getResult.stdout).toBe('secret-from-stdin');
  });

  it('should prompt for confirmation in export command', async () => {
    await execa('node', [BIN_PATH, 'init'], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
    await execa('node', [BIN_PATH, 'set', 'K', 'V'], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });

    // Case 1: Say no
    const childNo = run(['export'], 'no');
    const resultNo = await childNo;
    expect(resultNo.stdout).toContain('Export cancelled');
    expect(resultNo.stdout).not.toContain('K=V');

    // Case 2: Say yes
    const childYes = run(['export'], 'yes');
    const resultYes = await childYes;
    expect(resultYes.stdout).toContain('K=V');
  });

  it('should prompt for new value in rotate command', async () => {
    await execa('node', [BIN_PATH, 'init'], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
    await execa('node', [BIN_PATH, 'set', 'R_KEY', 'old-val'], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });

    const child = run(['rotate', 'R_KEY'], 'new-val');
    const result = await child;
    expect(result.stdout).toContain('Rotated R_KEY');

    const getResult = await execa('node', [BIN_PATH, 'get', 'R_KEY'], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
    expect(getResult.stdout).toBe('new-val');
  });
});
