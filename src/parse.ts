import * as fs from "fs";
import * as path from "path";
import { ParseError, FileError } from "./errors.js";
import { safeReadFile } from "./filesystem.js";
import { validateKey, validateValue } from "./validators.js";
import { constantTimeEqual } from "./crypto-utils.js";

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

export const ENCRYPTED_PREFIX = "enc:age:";
const VAULT_PREFIX = "vault:";

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

  let content = safeReadFile(filePath);
  if (content.startsWith("\uFEFF")) {
    content = content.slice(1);
  }
  const lines = content.split("\n");
  const parsedLines: ParsedLine[] = [];
  const keys = new Set<string>();
  let encryptedCount = 0;
  let plaintextCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const raw = lines[i];
    const trimmed = raw.trim();

    if (!trimmed || trimmed.startsWith("#")) {
      parsedLines.push({
        key: "",
        value: trimmed,
        encrypted: false,
        lineNumber,
        raw,
      });
      continue;
    }

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) {
      throw new ParseError(
        lineNumber,
        raw,
        `Invalid line: missing '=' separator`,
      );
    }

    const key = trimmed.slice(0, eqIndex);
    const value = trimmed.slice(eqIndex + 1);

    if (!key) {
      throw new ParseError(
        lineNumber,
        raw,
        `Invalid line: missing key before '='`,
      );
    }

    // Strict validation
    validateKey(key);

    if (keys.has(key)) {
      throw new ParseError(lineNumber, raw, `Duplicate key '${key}'`);
    }

    const encrypted = isEncryptedValue(value);

    parsedLines.push({
      key,
      value,
      encrypted,
      lineNumber,
      raw,
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
    plaintextCount,
  };
}

export function findKey(env: ParsedEnv, key: string): ParsedLine | null {
  let result: ParsedLine | null = null;
  for (const line of env.lines) {
    if (constantTimeEqual(line.key, key)) {
      result = line;
    }
  }
  return result;
}

export async function setKey(
  filePath: string,
  key: string,
  encryptedValue: string,
): Promise<void> {
  validateKey(key);
  validateValue(encryptedValue);

  await withLock(filePath, async () => {
    const content = fs.existsSync(filePath) ? safeReadFile(filePath) : "";
    const lines = content.split("\n");
    let found = false;
    const newLines: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        newLines.push(line);
        continue;
      }

      const eqIndex = trimmed.indexOf("=");
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

    const finalContent =
      newLines
        .filter((l, i) => l.trim() !== "" || i < newLines.length - 1)
        .join("\n")
        .trim() + "\n";
    await writeAtomicRaw(filePath, finalContent);
  });
}

export async function deleteKey(filePath: string, key: string): Promise<void> {
  validateKey(key);

  await withLock(filePath, async () => {
    const content = fs.existsSync(filePath) ? safeReadFile(filePath) : "";
    const lines = content.split("\n");
    const newLines: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        newLines.push(line);
        continue;
      }

      const eqIndex = trimmed.indexOf("=");
      if (eqIndex !== -1) {
        const existingKey = trimmed.slice(0, eqIndex);
        if (existingKey === key) {
          continue;
        }
      }
      newLines.push(line);
    }

    const finalContent =
      newLines
        .filter((l, i) => l.trim() !== "" || i < newLines.length - 1)
        .join("\n")
        .trim() + "\n";
    await writeAtomicRaw(filePath, finalContent);
  });
}

async function withLock(
  filePath: string,
  fn: () => Promise<void> | void,
): Promise<void> {
  const lockPath = `${filePath}.lock`;
  let lockHandle: fs.promises.FileHandle | null = null;
  let retries = 100;
  let delay = 10;

  while (retries > 0) {
    try {
      lockHandle = await fs.promises.open(lockPath, "wx");
      await lockHandle.write(process.pid.toString());
      break;
    } catch (e: any) {
      if (e.code === "EEXIST") {
        // Stale lock detection
        try {
          const pidStr = await fs.promises.readFile(lockPath, "utf-8");
          const pid = parseInt(pidStr.trim(), 10);
          if (!isNaN(pid)) {
            try {
              process.kill(pid, 0);
            } catch (err: any) {
              if (err.code === "ESRCH") {
                try {
                  await fs.promises.unlink(lockPath);
                  continue;
                } catch {}
              }
            }
          }
        } catch {}

        retries--;
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay = Math.min(delay * 1.5 + Math.random() * 50, 5000);
      } else {
        throw new FileError(`Failed to acquire lock on ${filePath}: ${e}`);
      }
    }
  }

  if (!lockHandle) {
    throw new FileError(`Timeout waiting for lock on ${filePath}`);
  }

  try {
    await fn();
  } finally {
    await lockHandle.close();
    try {
      await fs.promises.unlink(lockPath);
    } catch {}
  }
}

export async function writeAtomic(
  filePath: string,
  content: string,
): Promise<void> {
  await withLock(filePath, async () => {
    await writeAtomicRaw(filePath, content);
  });
}

async function writeAtomicRaw(
  filePath: string,
  content: string,
): Promise<void> {
  const tmpPath = `${filePath}.tmp.${Date.now()}`;
  try {
    await fs.promises.writeFile(tmpPath, content, { mode: 0o644 });
    const fd = await fs.promises.open(tmpPath, "r");
    await fd.sync();
    await fd.close();
    await fs.promises.rename(tmpPath, filePath);
  } catch (error) {
    try {
      if (fs.existsSync(tmpPath)) {
        await fs.promises.unlink(tmpPath);
      }
    } catch {}
    throw new FileError(`Failed to write ${filePath}: ${error}`);
  }
}

export function getEnvPath(): string {
  return path.join(process.cwd(), ".secenv");
}
