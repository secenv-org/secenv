import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";
import {
  generateIdentity,
  saveIdentity,
  loadIdentity,
  identityExists,
  getPublicKey,
  getDefaultKeyPath,
  ensureSecenvDir,
  encrypt as encryptValue,
  decrypt as decryptValue,
} from "./age.js";
import {
  parseEnvFile,
  setKey,
  deleteKey,
  findKey,
  getEnvPath,
  isEncryptedValue,
  writeAtomic,
} from "./parse.js";
import {
  IdentityNotFoundError,
  DecryptionError,
  SecretNotFoundError,
  ParseError,
  FileError,
  EncryptionError,
  SecenvError,
} from "./errors.js";

const ENCRYPTED_PREFIX = "enc:age:";

function print(msg: string, color: string = "reset", isError: boolean = false) {
  const colors: Record<string, string> = {
    reset: "\x1b[0m",
    green: "\x1b[32m",
    red: "\x1b[31m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    cyan: "\x1b[36m",
  };
  const stream = isError ? process.stderr : process.stdout;
  stream.write(`${colors[color] || colors.reset}${msg}${colors.reset}\n`);
}

function printSuccess(msg: string) {
  print(`✓ ${msg}`, "green");
}

function printError(msg: string) {
  print(`✗ ${msg}`, "red", true);
}

function printWarning(msg: string) {
  print(`⚠ ${msg}`, "yellow");
}

function printInfo(msg: string) {
  print(`ℹ ${msg}`, "cyan");
}

async function promptSecret(promptText: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve, reject) => {
    rl.question(promptText, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function confirm(message: string): Promise<boolean> {
  const answer = await promptSecret(`${message} (yes/no): `);
  return answer.toLowerCase() === "yes";
}

async function cmdInit() {
  if (identityExists()) {
    printWarning('Identity already exists. Run "secenv doctor" to check.');
    return;
  }

  printInfo("Generating identity key...");
  const identity = await generateIdentity();
  const keyPath = await saveIdentity(identity);
  printSuccess(`Identity created at ${keyPath}`);

  const envPath = getEnvPath();
  if (!fs.existsSync(envPath)) {
    await writeAtomic(envPath, "");
    printSuccess(`Created ${envPath}`);
  }

  const gitignorePath = path.join(process.cwd(), ".gitignore");
  let gitignoreContent = "";
  if (fs.existsSync(gitignorePath)) {
    gitignoreContent = fs.readFileSync(gitignorePath, "utf-8");
  }

  const gitignoreEntry = ".secenv\n";
  if (!gitignoreContent.includes(gitignoreEntry)) {
    if (gitignoreContent && !gitignoreContent.endsWith("\n")) {
      gitignoreContent += "\n";
    }
    gitignoreContent += gitignoreEntry;
    fs.writeFileSync(gitignorePath, gitignoreContent);
    printSuccess(`Updated .gitignore`);
  }

  const publicKey = await getPublicKey(identity);
  printInfo(`Your public key: ${publicKey}`);
  printInfo("Keep your private key safe!");
}

async function cmdSet(key: string, value?: string, isBase64: boolean = false) {
  if (!identityExists()) {
    throw new IdentityNotFoundError(getDefaultKeyPath());
  }

  let secretValue = value;

  if (!secretValue) {
    secretValue = await promptSecret(`Enter value for ${key}: `);
  }

  if (!secretValue) {
    throw new EncryptionError("Value cannot be empty");
  }

  if (isBase64) {
    try {
      Buffer.from(secretValue, "base64");
    } catch (e) {
      throw new EncryptionError("Invalid base64 value");
    }
  } else if (secretValue.includes("\n") || secretValue.includes("\r")) {
    throw new EncryptionError(
      "Multiline values are not allowed. Use --base64 for binary data.",
    );
  }

  const identity = await loadIdentity();
  const encrypted = await encryptValue(identity, secretValue);
  const encryptedValue = `${ENCRYPTED_PREFIX}${encrypted}`;

  const envPath = getEnvPath();
  await setKey(envPath, key, encryptedValue);
  printSuccess(`Encrypted and stored ${key}`);
}

async function cmdGet(key: string) {
  if (!identityExists()) {
    throw new IdentityNotFoundError(getDefaultKeyPath());
  }

  const identity = await loadIdentity();
  const envPath = getEnvPath();

  if (!fs.existsSync(envPath)) {
    throw new SecretNotFoundError(key);
  }

  const parsed = parseEnvFile(envPath);
  const line = findKey(parsed, key);

  if (!line) {
    throw new SecretNotFoundError(key);
  }

  if (line.encrypted) {
    const decrypted = await decryptValue(
      identity,
      line.value.slice(ENCRYPTED_PREFIX.length),
    );
    process.stdout.write(decrypted);
  } else {
    process.stdout.write(line.value);
  }
}

async function cmdList() {
  const envPath = getEnvPath();

  if (!fs.existsSync(envPath)) {
    return;
  }

  const parsed = parseEnvFile(envPath);

  for (const line of parsed.lines) {
    if (line.key) {
      const status = line.encrypted ? "[encrypted]" : "[plaintext]";
      print(`${line.key}  ${status}`);
    }
  }
}

async function cmdDelete(key: string) {
  const envPath = getEnvPath();

  if (!fs.existsSync(envPath)) {
    throw new SecretNotFoundError(key);
  }

  const parsed = parseEnvFile(envPath);
  const line = findKey(parsed, key);

  if (!line) {
    throw new SecretNotFoundError(key);
  }

  await deleteKey(envPath, key);
  printSuccess(`Deleted ${key}`);
}

async function cmdRotate(key: string, newValue?: string) {
  let secretValue = newValue;

  if (!secretValue) {
    secretValue = await promptSecret(`Enter new value for ${key}: `);
  }

  if (!secretValue) {
    throw new EncryptionError("Value cannot be empty");
  }

  await cmdSet(key, secretValue);
  printSuccess(`Rotated ${key}`);
}

async function cmdExport(force: boolean = false) {
  if (!force) {
    const confirmed = await confirm(
      "WARNING: You are about to export ALL secrets in PLAINTEXT",
    );
    if (!confirmed) {
      print("Export cancelled.");
      return;
    }
  }

  if (!identityExists()) {
    throw new IdentityNotFoundError(getDefaultKeyPath());
  }

  const identity = await loadIdentity();
  const envPath = getEnvPath();

  if (!fs.existsSync(envPath)) {
    print("No .secenv file found.");
    return;
  }

  const parsed = parseEnvFile(envPath);

  for (const line of parsed.lines) {
    if (line.key) {
      let value: string;
      if (line.encrypted) {
        value = await decryptValue(
          identity,
          line.value.slice(ENCRYPTED_PREFIX.length),
        );
      } else {
        value = line.value;
      }
      print(`${line.key}=${value}`);
    }
  }
}

async function cmdDoctor() {
  let checks = 0;
  let passed = 0;

  checks++;
  const identityPath = getDefaultKeyPath();
  if (identityExists()) {
    try {
      const stats = fs.statSync(identityPath);
      const isUnix = process.platform !== "win32";

      if (isUnix && (stats.mode & 0o777) !== 0o600) {
        printWarning(
          `Identity: ${identityPath} (exists, but permissions should be 0600, found ${(stats.mode & 0o777).toString(8)})`,
        );
      } else {
        printSuccess(`Identity: ${identityPath}`);
      }

      const identity = await loadIdentity();
      await getPublicKey(identity);
      printSuccess(`Identity: ${identityPath}`);
      passed++;
    } catch (error) {
      printError(`Identity: ${identityPath} (invalid)`);
    }
  } else {
    printError(`Identity: ${identityPath} (not found)`);
  }

  checks++;
  const envPath = getEnvPath();
  if (fs.existsSync(envPath)) {
    printSuccess(`File: ${envPath} (exists)`);
    passed++;
  } else {
    printWarning(`File: ${envPath} (not found)`);
    passed++;
  }

  checks++;
  if (fs.existsSync(envPath)) {
    try {
      const parsed = parseEnvFile(envPath);
      printSuccess(
        `Syntax: ${parsed.lines.length} lines, ${parsed.encryptedCount} encrypted, ${parsed.plaintextCount} plaintext`,
      );
      passed++;
    } catch (error) {
      if (error instanceof ParseError) {
        printError(`Syntax: Line ${error.line}: ${error.message}`);
      } else {
        printError(`Syntax: ${error}`);
      }
    }
  } else {
    print(`Syntax: (no file)`);
    passed++;
  }

  checks++;
  if (identityExists() && fs.existsSync(envPath)) {
    try {
      const identity = await loadIdentity();
      const parsed = parseEnvFile(envPath);
      let decryptedCount = 0;
      let failedCount = 0;

      for (const line of parsed.lines) {
        if (line.encrypted) {
          try {
            await decryptValue(
              identity,
              line.value.slice(ENCRYPTED_PREFIX.length),
            );
            decryptedCount++;
          } catch (error) {
            failedCount++;
          }
        }
      }

      if (failedCount === 0) {
        printSuccess(
          `Decryption: ${decryptedCount}/${decryptedCount} keys verified`,
        );
        passed++;
      } else {
        printError(
          `Decryption: ${decryptedCount} succeeded, ${failedCount} failed`,
        );
      }
    } catch (error) {
      printError(`Decryption: ${error}`);
    }
  } else {
    print(`Decryption: (skipped - no identity or file)`);
    passed++;
  }

  print("");
  print(`Doctor: ${passed}/${checks} checks passed`);
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "help";

  try {
    switch (command) {
      case "init":
        await cmdInit();
        break;

      case "set": {
        const isBase64 = args.includes("--base64");
        const filteredArgs = args.filter((a) => a !== "--base64");
        const key = filteredArgs[1];
        if (!key) {
          throw new Error(
            "Missing KEY argument. Usage: secenv set KEY [VALUE] [--base64]",
          );
        }
        const value = filteredArgs[2];
        await cmdSet(key, value, isBase64);
        break;
      }

      case "get": {
        const key = args[1];
        if (!key) {
          throw new Error("Missing KEY argument. Usage: secenv get KEY");
        }
        await cmdGet(key);
        break;
      }

      case "list":
        await cmdList();
        break;

      case "delete": {
        const key = args[1];
        if (!key) {
          throw new Error("Missing KEY argument. Usage: secenv delete KEY");
        }
        await cmdDelete(key);
        break;
      }

      case "rotate": {
        const key = args[1];
        if (!key) {
          throw new Error(
            "Missing KEY argument. Usage: secenv rotate KEY [VALUE]",
          );
        }
        const value = args[2];
        await cmdRotate(key, value);
        break;
      }

      case "export": {
        const force = args.includes("--force");
        await cmdExport(force);
        break;
      }

      case "doctor":
        await cmdDoctor();
        break;

      case "help":
      default:
        print("secenv - The Breeze: Secret management without the overhead");
        print("");
        print("Usage: secenv <command> [arguments]");
        print("");
        print("Commands:");
        print(
          "  init              Bootstrap identity and create .secenv/.gitignore",
        );
        print(
          "  set KEY [VALUE]    Encrypt a value into .secenv (primary method)",
        );
        print(
          "  set KEY [VALUE] --base64  Encrypt a base64 value (for binary data)",
        );
        print("  get KEY           Decrypt and print a specific key value");
        print(
          "  list              List all available key names (values hidden)",
        );
        print("  delete KEY        Remove a key from .secenv");
        print("  rotate KEY [VALUE] Update a secret value and re-encrypt");
        print(
          "  export [--force]  Dump all decrypted values (requires --force)",
        );
        print(
          "  doctor            Health check: identity, file integrity, decryption",
        );
        print("");
        break;
    }
  } catch (error) {
    if (error instanceof SecenvError) {
      printError(error.message);
      process.exit(1);
    }
    throw error;
  }
}

main().catch((error) => {
  printError(error.message);
  process.exit(1);
});
