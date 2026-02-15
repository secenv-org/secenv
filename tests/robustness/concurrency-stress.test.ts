import { execa } from 'execa';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenvs');

describe('Concurrency Stress Test', () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-stress-cwd-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-stress-home-'));
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

  it('should handle 50 concurrent writes without corruption', async () => {
    await runCLI(['init']);
    
    // 50 is a safe number for most systems, 100 might hit EMFILE or other limits
    const count = 50;
    const promises = [];
    
    for (let i = 0; i < count; i++) {
      promises.push(runCLI(['set', `STRESS_KEY_${i}`, `VAL_${i}`]));
    }
    
    // Some might fail with lock timeout if it's too much, but they shouldn't corrupt the file
    const results = await Promise.allSettled(promises);
    
    const succeeded = results.filter(r => r.status === 'fulfilled').length;
    console.log(`Succeeded writes: ${succeeded}/${count}`);
    
    // Check if file is still valid
    const { stdout } = await runCLI(['list']);
    expect(stdout).toContain('STRESS_KEY_');
  }, 30000); // Higher timeout for stress test
});
