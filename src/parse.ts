import * as fs from 'fs';
import * as path from 'path';
import { ParseError, FileError } from './errors.js';

export interface ParsedLine {
  key: string;
  value: string;
  encrypted: boolean;
  lineNumber: number;
  raw: string;
}

export interface ParsedEnv {
  lines: ParsedLine[];
  keys: Set<string>;
  encryptedCount: number;
  plaintextCount: number;
}

export const ENCRYPTED_PREFIX = 'enc:age:';
const VAULT_PREFIX = 'vault:';

export function isEncryptedValue(value: string): boolean {
  return value.startsWith(ENCRYPTED_PREFIX);
}

export function isVaultReference(value: string): boolean {
  return value.startsWith(VAULT_PREFIX);
}

export function parseEnvFile(filePath: string): ParsedEnv {
  if (!fs.existsSync(filePath)) {
    return { lines: [], keys: new Set(), encryptedCount: 0, plaintextCount: 0 };
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const parsedLines: ParsedLine[] = [];
  const keys = new Set<string>();
  let encryptedCount = 0;
  let plaintextCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const raw = lines[i];
    const trimmed = raw.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      parsedLines.push({
        key: '',
        value: trimmed,
        encrypted: false,
        lineNumber,
        raw
      });
      continue;
    }

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) {
      throw new ParseError(
        lineNumber,
        raw,
        `Invalid line: missing '=' separator`
      );
    }

    const key = trimmed.slice(0, eqIndex);
    const value = trimmed.slice(eqIndex + 1);

    if (!key) {
      throw new ParseError(
        lineNumber,
        raw,
        `Invalid line: missing key before '='`
      );
    }

    if (keys.has(key)) {
      throw new ParseError(
        lineNumber,
        raw,
        `Duplicate key '${key}'`
      );
    }

    const encrypted = isEncryptedValue(value);

    parsedLines.push({
      key,
      value,
      encrypted,
      lineNumber,
      raw
    });

    keys.add(key);

    if (encrypted) {
      encryptedCount++;
    } else {
      plaintextCount++;
    }
  }

  return {
    lines: parsedLines,
    keys,
    encryptedCount,
    plaintextCount
  };
}

export function findKey(env: ParsedEnv, key: string): ParsedLine | null {
  for (const line of env.lines) {
    if (line.key === key) {
      return line;
    }
  }
  return null;
}

export function setKey(
  filePath: string,
  key: string,
  encryptedValue: string
): void {
  withLock(filePath, () => {
    const content = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : '';
    const lines = content.split('\n');
    let found = false;
    const newLines: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        newLines.push(line);
        continue;
      }

      const eqIndex = trimmed.indexOf('=');
      if (eqIndex !== -1) {
        const existingKey = trimmed.slice(0, eqIndex);
        if (existingKey === key) {
          newLines.push(`${key}=${encryptedValue}`);
          found = true;
          continue;
        }
      }
      newLines.push(line);
    }

    if (!found) {
      newLines.push(`${key}=${encryptedValue}`);
    }

    // Filter out extra empty lines at the end and join with newlines
    const finalContent = newLines.filter((l, i) => l.trim() !== '' || i < newLines.length - 1).join('\n').trim() + '\n';
    writeAtomicRaw(filePath, finalContent);
  });
}

export function deleteKey(filePath: string, key: string): void {
  withLock(filePath, () => {
    const content = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : '';
    const lines = content.split('\n');
    const newLines: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        newLines.push(line);
        continue;
      }

      const eqIndex = trimmed.indexOf('=');
      if (eqIndex !== -1) {
        const existingKey = trimmed.slice(0, eqIndex);
        if (existingKey === key) {
          continue;
        }
      }
      newLines.push(line);
    }

    const finalContent = newLines.filter((l, i) => l.trim() !== '' || i < newLines.length - 1).join('\n').trim() + '\n';
    writeAtomicRaw(filePath, finalContent);
  });
}

function withLock(filePath: string, fn: () => void): void {
  const lockPath = `${filePath}.lock`;
  let lockFd: number | null = null;
  let retries = 100;
  
  while (retries > 0) {
    try {
      lockFd = fs.openSync(lockPath, 'wx');
      break;
    } catch (e: any) {
      if (e.code === 'EEXIST') {
        retries--;
        const delay = Math.floor(Math.random() * 50) + 10;
        const start = Date.now();
        while (Date.now() - start < delay) {}
      } else {
        throw new FileError(`Failed to acquire lock on ${filePath}: ${e}`);
      }
    }
  }

  if (!lockFd) {
    throw new FileError(`Timeout waiting for lock on ${filePath}`);
  }

  try {
    fn();
  } finally {
    fs.closeSync(lockFd);
    try {
      fs.unlinkSync(lockPath);
    } catch {}
  }
}

export function writeAtomic(filePath: string, content: string): void {
  withLock(filePath, () => {
    writeAtomicRaw(filePath, content);
  });
}

function writeAtomicRaw(filePath: string, content: string): void {
  const tmpPath = `${filePath}.tmp.${Date.now()}`;
  try {
    fs.writeFileSync(tmpPath, content, { mode: 0o644 });
    fs.fsyncSync(fs.openSync(tmpPath, 'r'));
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    try {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
    } catch {}
    throw new FileError(`Failed to write ${filePath}: ${error}`);
  }
}

export function getEnvPath(): string {
  return path.join(process.cwd(), '.env.enc');
}
