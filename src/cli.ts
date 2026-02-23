import * as fs from "node:fs"
import * as path from "node:path"
import * as readline from "node:readline"
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
   loadRecipients,
   saveRecipients,
   validatePublicKey,
} from "./age.js"
import { vaultGet, vaultSet, vaultDelete, listVaultKeys, getVaultPath } from "./vault.js"
import {
   parseEnvFile,
   setKey,
   deleteKey,
   findKey,
   getEnvPath,
   isEncryptedValue,
   writeAtomic,
} from "./parse.js"
import { parseDotenvFallback, DotenvLine } from "./dotenv-parser.js"
import {
   IdentityNotFoundError,
   DecryptionError,
   SecretNotFoundError,
   ParseError,
   FileError,
   EncryptionError,
   SecenvError,
   ValidationError,
   RecipientError,
   VaultError,
} from "./errors.js"
import { validateKey, validateValue } from "./validators.js"
import { installHooks, uninstallHooks } from "./hooks.js"
import { appendAuditLog, readAuditLog } from "./audit.js"

const ENCRYPTED_PREFIX = "enc:age:"

function print(msg: string, color: string = "reset", isError: boolean = false) {
   const colors: Record<string, string> = {
      reset: "\x1b[0m",
      green: "\x1b[32m",
      red: "\x1b[31m",
      yellow: "\x1b[33m",
      blue: "\x1b[34m",
      cyan: "\x1b[36m",
   }
   const stream = isError ? process.stderr : process.stdout
   stream.write(`${colors[color] || colors.reset}${msg}${colors.reset}\n`)
}

function printSuccess(msg: string) {
   print(`✓ ${msg}`, "green")
}

function printError(msg: string) {
   print(`✗ ${msg}`, "red", true)
}

function printWarning(msg: string) {
   print(`⚠ ${msg}`, "yellow")
}

function printInfo(msg: string) {
   print(`ℹ ${msg}`, "cyan")
}

async function promptSecret(promptText: string): Promise<string> {
   if (!process.stdin.isTTY) {
      // For piped input, read everything from stdin asynchronously
      return new Promise((resolve, reject) => {
         let data = ""
         process.stdin.setEncoding("utf-8")
         process.stdin.on("data", (chunk) => {
            data += chunk
         })
         process.stdin.on("end", () => {
            resolve(data.replace(/\r?\n$/, "")) // Remove only the last newline
         })
         process.stdin.on("error", reject)
      })
   }

   const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
   })

   return new Promise((resolve) => {
      rl.question(promptText, (answer) => {
         rl.close()
         resolve(answer)
      })
   })
}

async function promptSelect(question: string, options: string[]): Promise<number> {
   printInfo(question)
   options.forEach((opt, idx) => {
      print(`${idx + 1}) ${opt}`)
   })

   while (true) {
      const answer = await promptSecret(`Select an option (1-${options.length}): `)
      const choice = parseInt(answer.trim(), 10)
      if (!isNaN(choice) && choice >= 1 && choice <= options.length) {
         return choice - 1
      }
      printError(`Invalid selection. Please enter a number between 1 and ${options.length}.`)
   }
}

async function confirm(message: string): Promise<boolean> {
   const answer = await promptSecret(`${message} (y/N): `)
   return answer.toLowerCase() === "y" || answer.toLowerCase() === "yes"
}

async function cmdInit() {
   if (identityExists()) {
      printWarning('Identity already exists. Run "secenvs doctor" to check.')
      return
   }

   printInfo("Generating identity key...")
   const identity = await generateIdentity()
   const keyPath = await saveIdentity(identity)
   printSuccess(`Identity created at ${keyPath}`)

   const envPath = getEnvPath()
   if (!fs.existsSync(envPath)) {
      await writeAtomic(envPath, "")
      printSuccess(`Created ${envPath}`)
   }

   const gitignorePath = path.join(process.cwd(), ".gitignore")
   let gitignoreContent = ""
   if (fs.existsSync(gitignorePath)) {
      gitignoreContent = fs.readFileSync(gitignorePath, "utf-8")
   }

   const gitignoreEntry = ".secenvs\n"
   if (!gitignoreContent.includes(gitignoreEntry)) {
      if (gitignoreContent && !gitignoreContent.endsWith("\n")) {
         gitignoreContent += "\n"
      }
      gitignoreContent += gitignoreEntry
      fs.writeFileSync(gitignorePath, gitignoreContent)
      printSuccess(`Updated .gitignore`)
   }

   const publicKey = await getPublicKey(identity)
   printInfo(`Your public key: ${publicKey}`)
   printInfo("Keep your private key safe!")

   await appendAuditLog("INIT")
}

async function cmdSet(key: string, value?: string, isBase64: boolean = false) {
   validateKey(key)

   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }

   let secretValue = value

   if (secretValue === undefined) {
      secretValue = await promptSecret(`Enter value for ${key}: `)
   }

   validateValue(secretValue, { isBase64 })

   const recipients = await loadRecipients(process.cwd())
   const dataToEncrypt = isBase64 ? Buffer.from(secretValue, "base64") : secretValue
   const encrypted = await encryptValue(recipients, dataToEncrypt)
   const encryptedValue = `${ENCRYPTED_PREFIX}${encrypted}`

   const envPath = getEnvPath()
   await setKey(envPath, key, encryptedValue)
   await appendAuditLog("SET", key)
   printSuccess(
      `Encrypted and stored ${key} (${recipients.length} recipient${recipients.length > 1 ? "s" : ""})`
   )
}

async function cmdGet(key: string) {
   validateKey(key)

   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }

   const identity = await loadIdentity()
   const envPath = getEnvPath()

   if (!fs.existsSync(envPath)) {
      throw new SecretNotFoundError(key)
   }

   const parsed = parseEnvFile(envPath)
   const line = findKey(parsed, key)

   if (!line) {
      throw new SecretNotFoundError(key)
   }

   if (line.encrypted) {
      const decrypted = await decryptValue(identity, line.value.slice(ENCRYPTED_PREFIX.length))
      process.stdout.write(decrypted.toString("utf-8"))
   } else {
      process.stdout.write(line.value)
   }
}

async function cmdList() {
   const envPath = getEnvPath()

   if (!fs.existsSync(envPath)) {
      return
   }

   const parsed = parseEnvFile(envPath)

   for (const line of parsed.lines) {
      if (line.key) {
         const status = line.encrypted ? "[encrypted]" : "[plaintext]"
         print(`${line.key}  ${status}`)
      }
   }
}

async function cmdDelete(key: string) {
   validateKey(key)

   const envPath = getEnvPath()

   if (!fs.existsSync(envPath)) {
      throw new SecretNotFoundError(key)
   }

   const parsed = parseEnvFile(envPath)
   const line = findKey(parsed, key)

   if (!line) {
      throw new SecretNotFoundError(key)
   }

   await deleteKey(envPath, key)
   await appendAuditLog("DELETE", key)
   printSuccess(`Deleted ${key}`)
}

async function cmdRotate(key: string, newValue?: string) {
   validateKey(key)

   const envPath = getEnvPath()
   if (!fs.existsSync(envPath)) {
      throw new SecretNotFoundError(key)
   }

   const parsed = parseEnvFile(envPath)
   if (!findKey(parsed, key)) {
      throw new SecretNotFoundError(key)
   }

   let secretValue = newValue

   if (secretValue === undefined) {
      secretValue = await promptSecret(`Enter new value for ${key}: `)
   }

   await cmdSet(key, secretValue)
   printSuccess(`Rotated ${key}`)
}

/**
 * Re-encrypts every encrypted secret in .secenvs using the given recipients list.
 * Used internally by trust/untrust to atomically rotate the recipient set.
 */
async function reEncryptAllSecrets(recipients: string[]): Promise<number> {
   const envPath = getEnvPath()
   if (!fs.existsSync(envPath)) {
      return 0
   }

   const identity = await loadIdentity()
   const parsed = parseEnvFile(envPath)
   let count = 0

   for (const line of parsed.lines) {
      if (!line.key || !line.encrypted) continue
      const decrypted = await decryptValue(identity, line.value.slice(ENCRYPTED_PREFIX.length))
      const reEncrypted = await encryptValue(recipients, decrypted)
      await setKey(envPath, line.key, `${ENCRYPTED_PREFIX}${reEncrypted}`)
      await appendAuditLog("RE-ENCRYPT", line.key)
      count++
   }
   return count
}

async function cmdTrust(pubkey: string) {
   const normalized = validatePublicKey(pubkey)

   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }

   // Build the current recipients list (seeded from identity if file doesn't exist yet)
   const currentRecipients = await loadRecipients(process.cwd())

   if (currentRecipients.includes(normalized)) {
      printWarning(`Public key is already in .secenvs — nothing to do.`)
      return
   }

   const newRecipients = [...currentRecipients, normalized]
   await saveRecipients(process.cwd(), newRecipients)
   await appendAuditLog("TRUST", normalized)
   printSuccess(
      `Added key to .secenvs (${newRecipients.length} total recipient${newRecipients.length > 1 ? "s" : ""})`
   )

   printInfo("Re-encrypting all secrets to the new recipient set...")
   const count = await reEncryptAllSecrets(newRecipients)
   printSuccess(`Re-encrypted ${count} secret${count !== 1 ? "s" : ""}`)
}

async function cmdUntrust(pubkey: string) {
   const normalized = validatePublicKey(pubkey)

   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }

   const currentRecipients = await loadRecipients(process.cwd())

   if (!currentRecipients.includes(normalized)) {
      printWarning(`Public key not found in .secenvs — nothing to do.`)
      return
   }

   const newRecipients = currentRecipients.filter((k) => k !== normalized)

   if (newRecipients.length === 0) {
      throw new RecipientError(
         "Cannot remove the last recipient — at least one key must remain to decrypt secrets."
      )
   }

   await saveRecipients(process.cwd(), newRecipients)
   await appendAuditLog("UNTRUST", normalized)
   printSuccess(`Removed key from .secenvs (${newRecipients.length} remaining)`)

   printInfo("Re-encrypting all secrets with the updated recipient set...")
   const count = await reEncryptAllSecrets(newRecipients)
   printSuccess(`Re-encrypted ${count} secret${count !== 1 ? "s" : ""}`)
}

async function cmdExport(force: boolean = false) {
   if (!force) {
      const confirmed = await confirm("WARNING: You are about to export ALL secrets in PLAINTEXT")
      if (!confirmed) {
         print("Export cancelled.")
         return
      }
   }

   if (!identityExists()) {
      throw new IdentityNotFoundError(getDefaultKeyPath())
   }

   const identity = await loadIdentity()
   const envPath = getEnvPath()

   if (!fs.existsSync(envPath)) {
      print("No .secenvs file found.")
      return
   }

   const parsed = parseEnvFile(envPath)

   for (const line of parsed.lines) {
      if (line.key) {
         let value: string
         if (line.encrypted) {
            const decrypted = await decryptValue(identity, line.value.slice(ENCRYPTED_PREFIX.length))
            value = decrypted.toString("utf-8")
         } else {
            value = line.value
         }
         print(`${line.key}=${value}`)
      }
   }
}

async function cmdDoctor() {
   let checks = 0
   let passed = 0

   checks++
   const identityPath = getDefaultKeyPath()
   if (identityExists()) {
      try {
         const stats = fs.statSync(identityPath)
         const isUnix = process.platform !== "win32"
         if (isUnix && (stats.mode & 0o777) !== 0o600) {
            print(
               `⚠ Identity: ${identityPath} (exists, but permissions should be 0600, found ${(stats.mode & 0o777).toString(8)})`,
               "yellow",
               false
            )
         }

         const identity = await loadIdentity()
         await getPublicKey(identity)
         print(`✓ Identity: ${identityPath}`, "green", false)
         passed++
      } catch (error) {
         print(`✗ Identity: ${identityPath} (invalid)`, "red", false)
      }
   } else {
      print(`✗ Identity: ${identityPath} (not found)`, "red", false)
   }

   checks++
   const envPath = getEnvPath()
   if (fs.existsSync(envPath)) {
      print(`✓ File: ${envPath} (exists)`, "green", false)
      passed++
   } else {
      print(`⚠ File: ${envPath} (not found)`, "yellow", false)
      passed++
   }

   checks++
   if (fs.existsSync(envPath)) {
      try {
         const parsed = parseEnvFile(envPath)
         print(
            `✓ Syntax: ${parsed.lines.length} lines, ${parsed.encryptedCount} encrypted, ${parsed.plaintextCount} plaintext`,
            "green",
            false
         )
         passed++
      } catch (error) {
         if (error instanceof ParseError) {
            print(`✗ Syntax: Line ${error.line}: ${error.message}`, "red", false)
         } else {
            print(`✗ Syntax: ${error}`, "red", false)
         }
      }
   } else {
      print(`Syntax: (no file)`, "reset", false)
      passed++
   }

   checks++
   if (identityExists() && fs.existsSync(envPath)) {
      try {
         const identity = await loadIdentity()
         const parsed = parseEnvFile(envPath)
         let decryptedCount = 0
         let failedCount = 0

         for (const line of parsed.lines) {
            if (line.encrypted) {
               try {
                  await decryptValue(identity, line.value.slice(ENCRYPTED_PREFIX.length))
                  decryptedCount++
               } catch (error) {
                  failedCount++
               }
            }
         }

         if (failedCount === 0) {
            print(`✓ Decryption: ${decryptedCount}/${decryptedCount} keys verified`, "green", false)
            passed++
         } else {
            print(`✗ Decryption: ${decryptedCount} succeeded, ${failedCount} failed`, "red", false)
         }
      } catch (error) {
         print(`✗ Decryption: ${error}`, "red", false)
      }
   } else {
      print(`Decryption: (skipped - no identity or file)`, "reset", false)
      passed++
   }

   checks++
   if (fs.existsSync(envPath)) {
      const logs = readAuditLog(envPath)
      const tampered = logs.some((l) => !l.verified)
      if (tampered) {
         print(`✗ Audit: Cryptographic chain verification failed!`, "red", false)
      } else {
         print(`✓ Audit: ${logs.length} entries verified`, "green", false)
         passed++
      }
   } else {
      print(`Audit: (no file)`, "reset", false)
      passed++
   }

   checks++
   const vaultPath = getVaultPath()
   if (fs.existsSync(vaultPath)) {
      try {
         const logs = readAuditLog(vaultPath)
         const tampered = logs.some((l) => !l.verified)
         if (tampered) {
            print(`✗ Global Vault: Audit chain corrupted`, "red", false)
         } else {
            print(`✓ Global Vault: Found at ${vaultPath}`, "green", false)
            passed++
         }
      } catch {
         print(`⚠ Global Vault: Exists but unreadable`, "yellow", false)
         passed++
      }
   } else {
      print(`✓ Global Vault: (not used)`, "green", false)
      passed++
   }

   print("")
   print(`Doctor: ${passed}/${checks} checks passed`)
}

async function cmdLog(options?: { global?: boolean }) {
   const filePath = options?.global ? getVaultPath() : getEnvPath()
   const entries = readAuditLog(filePath)
   if (entries.length === 0) {
      printInfo(`No audit log entries found for ${options?.global ? "global vault" : "local workspace"}.`)
      return
   }

   printInfo(
      `Audit Log for ${options?.global ? "Global Vault" : "Local Workspace"} (${entries.length} entries):`
   )
   print("")
   print(`ST | TIMESTAMP                | ACTION     | KEY        | ACTOR`, "cyan")
   print(
      `---|--------------------------|------------|------------|------------------------------------------------------------`
   )

   let hasTampered = false
   for (const entry of entries) {
      if (!entry.verified) hasTampered = true
      const status = entry.verified ? "✅" : "❌"
      const timestamp = entry.timestamp.slice(0, 24).padEnd(24)
      const action = entry.action.padEnd(10)
      const key = entry.key.padEnd(10)
      const actor = entry.actor
      print(`${status} | ${timestamp} | ${action} | ${key} | ${actor}`)
   }

   if (hasTampered) {
      print("")
      printError(
         "WARNING: AUDIT LOG TAMPERING DETECTED! Mathematical verification failed for one or more entries."
      )
      process.exit(1)
   }
}

async function cmdMigrate(filePath: string = ".env", auto: boolean = false) {
   if (!fs.existsSync(filePath)) {
      throw new FileError(`File not found: ${filePath}`)
   }

   printInfo(`Parsing ${filePath}...`)
   const lines = parseDotenvFallback(filePath)

   if (lines.length === 0) {
      printInfo(`No valid environment variables found in ${filePath}`)
      return
   }

   const envPath = getEnvPath()
   let existingParsed = fs.existsSync(envPath) ? parseEnvFile(envPath) : null

   let migratedCount = 0
   let skippedCount = 0

   for (const line of lines) {
      const { key, value } = line

      try {
         validateKey(key)
      } catch {
         printWarning(`Skipping invalid key '${key}' at line ${line.lineNumber}`)
         skippedCount++
         continue
      }

      if (existingParsed && findKey(existingParsed, key)) {
         if (!auto) {
            const shouldOverwrite = await confirm(`Key '${key}' already exists in .secenvs. Overwrite?`)
            if (!shouldOverwrite) {
               skippedCount++
               continue
            }
         }
      }

      const hasNewlines = value.includes("\n") || value.includes("\r")
      let processValue = value
      let isBase64 = false

      if (hasNewlines) {
         printWarning(`Key '${key}' contains newlines. It will be Base64-encoded automatically.`)
         processValue = Buffer.from(value).toString("base64")
         isBase64 = true
      }

      if (auto) {
         printInfo(`Auto-encrypting '${key}' locally...`)
         await cmdSet(key, processValue, isBase64)
         migratedCount++
      } else {
         print("")
         const choice = await promptSelect(`How would you like to handle '${key}'?`, [
            "Encrypt locally in .secenvs (Default)",
            "Move to global vault (~/.secenvs/vault.age)",
            "Keep as plaintext in .secenvs",
            "Skip",
         ])

         switch (choice) {
            case 0:
               await cmdSet(key, processValue, isBase64)
               migratedCount++
               break
            case 1:
               await vaultSet(key, processValue)
               // Automatically create the vault reference in local .secenvs
               const vaultRef = `vault:${key}`
               await setKey(envPath, key, vaultRef)
               await appendAuditLog("SET", key)
               printSuccess(`Stored ${key} in global vault and linked in .secenvs`)
               migratedCount++
               break
            case 2:
               // Validated plaintext appending
               await setKey(envPath, key, processValue)
               await appendAuditLog("SET", key)
               printSuccess(`Added ${key} as plaintext in .secenvs`)
               migratedCount++
               break
            case 3:
               printInfo(`Skipped '${key}'`)
               skippedCount++
               break
         }
      }

      // Update our parsed state so we don't accidentally add duplicates in the loop
      if (fs.existsSync(envPath)) {
         existingParsed = parseEnvFile(envPath)
      }
   }

   print("")
   printSuccess(`Migration complete: ${migratedCount} migrated, ${skippedCount} skipped.`)

   if (!auto) {
      const backup = await confirm(
         `Would you like to rename ${filePath} to ${filePath}.bak to avoid accidental commits?`
      )
      if (backup) {
         fs.renameSync(filePath, `${filePath}.bak`)
         printSuccess(`Renamed ${filePath} to ${filePath}.bak`)
      }
   }
}

async function cmdInstallHooks() {
   const result = installHooks(process.cwd())
   if (result.success) {
      printSuccess(result.message)
   } else {
      printError(result.message)
      process.exit(1)
   }
}

async function cmdUninstallHooks() {
   const result = uninstallHooks(process.cwd())
   if (result.success) {
      printSuccess(result.message)
   } else {
      printError(result.message)
      process.exit(1)
   }
}

async function cmdRun(runArgs: string[]) {
   if (runArgs.length === 0) {
      throw new Error("Missing command. Usage: secenvs run -- <command> [args...]")
   }

   const [command, ...args] = runArgs

   // Dynamic import to avoid loading env on other commands unless necessary
   const { env } = await import("./env.js")
   const { spawnSync } = await import("node:child_process")

   // 1. Fetch and decrypt all available keys
   const decryptedEnv: Record<string, string> = {}
   for (const key of env.keys()) {
      try {
         decryptedEnv[key] = await env[key]
      } catch (error) {
         if (error instanceof SecretNotFoundError) {
            continue
         }
         throw error
      }
   }

   // 2. Merge decrypted secrets into process.env
   const childEnv = { ...process.env, ...decryptedEnv }

   // 3. Spawn child process synchronously
   const result = spawnSync(command, args, {
      stdio: "inherit",
      env: childEnv,
      shell: process.platform === "win32", // Windows prefers shell: true for many commands, UNIX standardizes on false as default but we can keep it false there if direct binary. But for broad polyglot support, `shell: true` or `shell: false`? We'll leave it `shell: true` to handle aliases like `npm run ...` smoothly cross-platform, though `node:child_process` handles `npm.cmd` internally if we just don't use it. We'll stick to true.
   })

   // 4. Handle exit codes and signals seamlessly
   if (result.signal) {
      process.kill(process.pid, result.signal)
   }

   process.exit(result.status ?? 1)
}

async function main() {
   const args = process.argv.slice(2)
   const command = args[0] || "help"

   try {
      switch (command) {
         case "init":
            await cmdInit()
            break

         case "set": {
            const isBase64 = args.includes("--base64")
            const filteredArgs = args.filter((a) => a !== "--base64")
            const key = filteredArgs[1]
            if (!key) {
               throw new Error("Missing KEY argument. Usage: secenvs set KEY [VALUE] [--base64]")
            }
            const value = filteredArgs[2]
            await cmdSet(key, value, isBase64)
            break
         }

         case "get": {
            const key = args[1]
            if (!key) {
               throw new Error("Missing KEY argument. Usage: secenvs get KEY")
            }
            await cmdGet(key)
            break
         }

         case "list":
            await cmdList()
            break

         case "delete": {
            const key = args[1]
            if (!key) {
               throw new Error("Missing KEY argument. Usage: secenvs delete KEY")
            }
            await cmdDelete(key)
            break
         }

         case "rotate": {
            const key = args[1]
            if (!key) {
               throw new Error("Missing KEY argument. Usage: secenvs rotate KEY [VALUE]")
            }
            const value = args[2]
            await cmdRotate(key, value)
            break
         }

         case "export": {
            const force = args.includes("--force")
            await cmdExport(force)
            break
         }

         case "log": {
            const global = args.includes("--global")
            await cmdLog({ global })
            break
         }

         case "trust": {
            const pubkey = args[1]
            if (!pubkey) {
               throw new Error("Missing public key argument. Usage: secenvs trust <age-public-key>")
            }
            await cmdTrust(pubkey)
            break
         }

         case "untrust": {
            const pubkey = args[1]
            if (!pubkey) {
               throw new Error("Missing public key argument. Usage: secenvs untrust <age-public-key>")
            }
            await cmdUntrust(pubkey)
            break
         }

         case "vault": {
            const subCommand = args[1]
            switch (subCommand) {
               case "set": {
                  const key = args[2]
                  let value = args[3]
                  if (!key) {
                     throw new Error("Missing key. Usage: secenvs vault set KEY [VALUE]")
                  }
                  if (value === undefined) {
                     value = await promptSecret(`Enter global vault value for ${key}: `)
                  }
                  validateKey(key)
                  validateValue(value)
                  await vaultSet(key, value)
                  printSuccess(`Stored ${key} in global vault`)
                  break
               }
               case "get": {
                  const key = args[2]
                  if (!key) {
                     throw new Error("Missing key. Usage: secenvs vault get KEY")
                  }
                  const value = await vaultGet(key)
                  if (value === undefined) {
                     throw new VaultError(`Key '${key}' not found in global vault`)
                  }
                  process.stdout.write(value + "\n")
                  break
               }
               case "list": {
                  const keys = await listVaultKeys()
                  if (keys.length === 0) {
                     printInfo("Global vault is empty")
                  } else {
                     printInfo(`Found ${keys.length} keys in global vault:`)
                     for (const key of keys.sort()) {
                        print(`  ${key}`)
                     }
                  }
                  break
               }
               case "delete": {
                  const key = args[2]
                  if (!key) {
                     throw new Error("Missing key. Usage: secenvs vault delete KEY")
                  }
                  await vaultDelete(key)
                  printSuccess(`Deleted ${key} from global vault`)
                  break
               }
               default:
                  throw new Error("Invalid vault subcommand. Usage: secenvs vault <set|get|list|delete>")
            }
            break
         }

         case "key": {
            const subCommand = args[1]
            if (subCommand === "export") {
               if (!identityExists()) {
                  throw new IdentityNotFoundError(getDefaultKeyPath())
               }
               const identity = await loadIdentity()
               process.stdout.write(identity)
               break
            }
            throw new Error("Invalid key subcommand. Usage: secenvs key export")
         }

         case "migrate": {
            const auto = args.includes("--auto")
            const fileArgs = args.filter((a) => a !== "migrate" && a !== "--auto")
            const fileToMigrate = fileArgs[0] || ".env"
            await cmdMigrate(fileToMigrate, auto)
            break
         }

         case "run": {
            const dashDashIndex = process.argv.indexOf("--")
            if (dashDashIndex === -1) {
               throw new Error("Missing '--' separator. Usage: secenvs run -- <command> [args...]")
            }
            const runArgs = process.argv.slice(dashDashIndex + 1)
            await cmdRun(runArgs)
            break
         }

         case "install-hooks":
            await cmdInstallHooks()
            break

         case "uninstall-hooks":
            await cmdUninstallHooks()
            break

         case "doctor":
            await cmdDoctor()
            break

         case "help":
         default:
            print("secenvs - The Breeze: Secret management without the overhead")
            print("")
            print("Usage: secenvs <command> [arguments]")
            print("")
            print("Commands:")
            print("  init              Bootstrap identity and create .secenvs/.gitignore")
            print("  set KEY [VALUE]    Encrypt a value into .secenvs (primary method)")
            print("  set KEY [VALUE] --base64  Encrypt a base64 value (for binary data)")
            print("  get KEY           Decrypt and print a specific key value")
            print("  log               Show the cryptographically recorded audit log")
            print("  list              List all available key names (values hidden)")
            print("  delete KEY        Remove a key from .secenvs")
            print("  rotate KEY [VALUE] Update a secret value and re-encrypt")
            print("  export [--force]  Dump all decrypted secrets (requires --force)")
            print("  key export        Export private key for CI/CD")
            print("  doctor            Health check: identity, file integrity, decryption")
            print("  migrate [file]    Migrate an existing .env file interactively")
            print("  run -- <cmd>      Run an arbitrary command with decrypted secrets injected")
            print("  install-hooks     Install git pre-commit hooks to block plaintext .env files")
            print("  uninstall-hooks   Remove the git pre-commit hooks")
            print("  trust <pubkey>    Add a recipient; re-encrypts all secrets")
            print("  untrust <pubkey>  Remove a recipient; re-encrypts all secrets")
            print("  vault <cmd>       Global vault: set, get, list, delete")
            print("")
            print("Vault Commands:")
            print("  vault set KEY [VAL]  Store a shared secret in $SECENV_HOME/.secenvs/vault.age")
            print("                       (defaults to ~/.secenvs/vault.age)")
            print("  vault get KEY        Print a value from the global vault")
            print("  vault list           List all keys in the global vault")
            print("  vault delete KEY     Remove a key from the global vault")
            print("")
            break
      }
   } catch (error) {
      if (error instanceof SecenvError) {
         printError(error.message)
         process.exit(1)
      }
      throw error
   }
}

// Graceful exit on signals
process.on("SIGINT", () => {
   const { cleanupTempFiles } = require("./parse.js")
   cleanupTempFiles()
   process.stdout.write("\n")
   process.exit(130)
})
process.on("SIGTERM", () => {
   const { cleanupTempFiles } = require("./parse.js")
   cleanupTempFiles()
   process.exit(143)
})

main().catch((error) => {
   printError(error.message)
   process.exit(1)
})
