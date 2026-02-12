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

const ENCRYPTED_PREFIX = 'enc:age:';
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

  writeAtomic(filePath, newLines.join('\n'));
}

export function deleteKey(filePath: string, key: string): void {
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

  writeAtomic(filePath, newLines.join('\n'));
}

export function writeAtomic(filePath: string, content: string): void {
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
