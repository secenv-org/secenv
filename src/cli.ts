import * as fs from "fs"
import * as path from "path"
import * as readline from "readline"
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
} from "./age.js"
import {
   parseEnvFile,
   setKey,
   deleteKey,
   findKey,
   getEnvPath,
   isEncryptedValue,
   writeAtomic,
} from "./parse.js"
import {
   IdentityNotFoundError,
   DecryptionError,
   SecretNotFoundError,
   ParseError,
   FileError,
   EncryptionError,
   SecenvError,
   ValidationError,
} from "./errors.js"
import { validateKey, validateValue } from "./validators.js"

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
      // For large piped input, readline might have limits.
      // Read everything from stdin synchronously if not a TTY.
      try {
         const data = fs.readFileSync(0, "utf-8")
         return data.replace(/\r?\n$/, "") // Remove only the last newline
      } catch (e) {
         // Fallback to readline if readFileSync(0) fails
      }
   }

   const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
   })

   return new Promise((resolve, reject) => {
      rl.question(promptText, (answer) => {
         rl.close()
         resolve(answer)
      })
   })
}

async function confirm(message: string): Promise<boolean> {
   const answer = await promptSecret(`${message} (yes/no): `)
   return answer.toLowerCase() === "yes"
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

   const identity = await loadIdentity()
   const dataToEncrypt = isBase64 ? Buffer.from(secretValue, "base64") : secretValue
   const encrypted = await encryptValue(identity, dataToEncrypt)
   const encryptedValue = `${ENCRYPTED_PREFIX}${encrypted}`

   const envPath = getEnvPath()
   await setKey(envPath, key, encryptedValue)
   printSuccess(`Encrypted and stored ${key}`)
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
         } else {
            print(`✓ Identity: ${identityPath}`, "green", false)
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

   print("")
   print(`Doctor: ${passed}/${checks} checks passed`)
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
            print("  list              List all available key names (values hidden)")
            print("  delete KEY        Remove a key from .secenvs")
            print("  rotate KEY [VALUE] Update a secret value and re-encrypt")
            print("  export [--force]  Dump all decrypted secrets (requires --force)")
            print("  key export        Export private key for CI/CD")
            print("  doctor            Health check: identity, file integrity, decryption")
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
   process.exit(130)
})
process.on("SIGTERM", () => {
   process.exit(143)
})

main().catch((error) => {
   printError(error.message)
   process.exit(1)
})
