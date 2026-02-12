import * as fs from 'fs';
import * as path from 'path';
import * as age from 'age-encryption';
import {
  loadIdentity,
  identityExists,
  decrypt as decryptValue,
  getDefaultKeyPath
} from './age.js';
import {
  parseEnvFile,
  findKey,
  getEnvPath,
  ENCRYPTED_PREFIX
} from './parse.js';
import {
  DecryptionError,
  SecretNotFoundError,
  IdentityNotFoundError
} from './errors.js';

interface CacheEntry {
  value: string;
  decryptedAt: number;
}

class SecenvSDK {
  private identity: string | null = null;
  private identityPromise: Promise<string> | null = null;
  private cache: Map<string, CacheEntry> = new Map();
  private cacheTimestamp: number = 0;
  private envPath: string = '';
  private parsedEnv: ReturnType<typeof parseEnvFile> | null = null;

  constructor() {
    this.envPath = getEnvPath();
  }

  private async loadIdentity(): Promise<string> {
    if (this.identity) {
      return this.identity;
    }

    if (this.identityPromise) {
      return this.identityPromise;
    }

    if (process.env.SECENV_ENCODED_IDENTITY) {
      try {
        const decoded = Buffer.from(process.env.SECENV_ENCODED_IDENTITY, 'base64');
        const privateKey = decoded.toString('utf-8');
        this.identity = privateKey;
        return this.identity;
      } catch (error) {
        throw new IdentityNotFoundError('SECENV_ENCODED_IDENTITY');
      }
    }

    if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath());
    }

    this.identityPromise = loadIdentity().then((identity) => {
      this.identity = identity;
      this.identityPromise = null;
      return this.identity;
    });

    return this.identityPromise;
  }

  private reloadEnv(): void {
    if (!fs.existsSync(this.envPath)) {
      this.parsedEnv = null;
      this.cache.clear();
      this.cacheTimestamp = 0;
      return;
    }

    const newTimestamp = fs.statSync(this.envPath).mtimeMs;
    if (newTimestamp !== this.cacheTimestamp) {
      this.parsedEnv = parseEnvFile(this.envPath);
      this.cacheTimestamp = newTimestamp;
      this.cache.clear(); // Clear cache when file changes
    }
  }

  async get<T extends string = string>(key: string): Promise<T> {
    // 1. Check process.env first (highest priority)
    if (process.env[key] !== undefined) {
      return process.env[key] as T;
    }

    this.reloadEnv();

    if (this.cache.has(key)) {
      return this.cache.get(key)!.value as T;
    }

    if (!this.parsedEnv) {
      throw new SecretNotFoundError(key);
    }

    const line = findKey(this.parsedEnv, key);
    if (!line) {
      throw new SecretNotFoundError(key);
    }

    if (!line.encrypted) {
      const value = line.value;
      this.cache.set(key, { value, decryptedAt: Date.now() });
      return value as T;
    }

    const identity = await this.loadIdentity();
    const encryptedMessage = line.value.slice(ENCRYPTED_PREFIX.length);
    const decrypted = await decryptValue(identity, encryptedMessage);

    this.cache.set(key, { value: decrypted, decryptedAt: Date.now() });
    return decrypted as T;
  }

  has(key: string): boolean {
    if (process.env[key] !== undefined) {
      return true;
    }
    this.reloadEnv();
    if (!this.parsedEnv) {
      return false;
    }
    return this.parsedEnv.keys.has(key);
  }

  keys(): string[] {
    const allKeys = new Set(Object.keys(process.env));
    this.reloadEnv();
    if (this.parsedEnv) {
      for (const key of this.parsedEnv.keys) {
        allKeys.add(key);
      }
    }
    return Array.from(allKeys);
  }

  clearCache(): void {
    this.cache.clear();
    this.cacheTimestamp = 0;
    this.parsedEnv = null;
  }
}

const globalSDK = new SecenvSDK();

export function createSecenv(): SecenvSDK {
  return new SecenvSDK();
}

export const env = globalSDK as unknown as { [key: string]: string };

export type Secenv = { [key: string]: string };

export { SecenvSDK };
