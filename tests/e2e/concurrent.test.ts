import { execa } from 'execa';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath } from 'url';
import { createSecenv } from '../../src/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, '../../bin/secenv');

describe('Concurrent Access', () => {
  let testDir: string;
  let secenvHome: string;
  let originalCwd: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-con-cwd-'));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secenv-con-home-'));
    originalCwd = process.cwd();
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
    delete process.env.SECENV_HOME;
  });

  const runCLI = (args: string[]) => {
    return execa('node', [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome }
    });
  };

  it('should handle multiple simultaneous reads', async () => {
    await runCLI(['init']);
    await runCLI(['set', 'CON_KEY', 'con-val']);
    
    process.env.SECENV_HOME = secenvHome;
    const env = createSecenv();
    
    const results = await Promise.all([
      env.get('CON_KEY'),
      env.get('CON_KEY'),
      env.get('CON_KEY'),
      env.get('CON_KEY'),
      env.get('CON_KEY')
    ]);
    
    expect(results).toEqual(['con-val', 'con-val', 'con-val', 'con-val', 'con-val']);
  });

  it('should handle read while write is happening (atomic check)', async () => {
    await runCLI(['init']);
    await runCLI(['set', 'EXISTING', 'old']);
    
    process.env.SECENV_HOME = secenvHome;
    const env = createSecenv();
    
    // Start a write in background
    const writePromise = runCLI(['set', 'NEW', 'val']);
    
    // Read existing while write is in progress
    const val = await env.get('EXISTING');
    expect(val).toBe('old');
    
    await writePromise;
    expect(await env.get('NEW')).toBe('val');
  });

  it('should maintain file integrity under rapid updates', async () => {
    await runCLI(['init']);
    
    const updates = [];
    for (let i = 0; i < 20; i++) {
      updates.push(runCLI(['set', `KEY_${i}`, `VAL_${i}`]));
    }
    
    await Promise.all(updates);
    
    process.env.SECENV_HOME = secenvHome;
    const env = createSecenv();
    
    for (let i = 0; i < 20; i++) {
      expect(await env.get(`KEY_${i}`)).toBe(`VAL_${i}`);
    }
  });
});
