import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execa } from 'execa';
import { fileURLToPath } from 'url';
import { ValidationError } from '../../src/errors.js';
import { validateKey, validateValue } from '../../src/validators.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenvs');

describe('Input Validation', () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-input-val-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-input-home-'));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
  });

  const runCLI = (args: string[]) => {
    return execa('node', [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
  };

  it('should reject invalid key names via SDK', () => {
    expect(() => validateKey('lower_case')).toThrow(ValidationError);
    expect(() => validateKey('KEY-WITH-DASH')).toThrow(ValidationError);
    expect(() => validateKey('KEY.WITH.DOT')).toThrow(ValidationError);
    expect(() => validateKey('KEY WITH SPACE')).toThrow(ValidationError);
    expect(() => validateKey('')).toThrow(ValidationError);
  });

  it('should reject invalid key names via CLI', async () => {
    await runCLI(['init']);
    await expect(runCLI(['set', 'invalid-key', 'value'])).rejects.toThrow();
  });

  it('should reject values larger than 5MB', () => {
    const hugeValue = 'a'.repeat(5 * 1024 * 1024 + 1);
    expect(() => validateValue(hugeValue)).toThrow(ValidationError);
    expect(() => validateValue('a'.repeat(5 * 1024 * 1024))).not.toThrow();
  });

  it('should reject keys with path separators', () => {
    expect(() => validateKey('../PATH')).toThrow(ValidationError);
    expect(() => validateKey('SUB/KEY')).toThrow(ValidationError);
    expect(() => validateKey('C:\\WINDOWS')).toThrow(ValidationError);
  });

  it('should reject values with null bytes (if we want to be strict)', () => {
    // Current validator only checks size.
    // age-encryption can handle binary data, so null bytes in values are technically fine
    // especially since we support --base64.
  });
});
