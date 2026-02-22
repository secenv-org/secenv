import { execSync } from "child_process"
import * as path from "path"
import * as fs from "fs"
import * as os from "os"

const CLI_PATH = path.resolve(process.cwd(), "bin/secenvs.js")

describe("E2E: Polyglot Support (secenvs run)", () => {
   let tempDir: string
   let originalCwd: string
   let originalEnv: NodeJS.ProcessEnv

   beforeEach(() => {
      originalCwd = process.cwd()
      originalEnv = { ...process.env }
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-e2e-run-"))
      process.chdir(tempDir)

      // Isolate SECENV_HOME
      process.env.SECENV_HOME = tempDir

      // Initialize workspace
      execSync(`node ${CLI_PATH} init`, { stdio: "ignore" })
   })

   afterEach(() => {
      process.chdir(originalCwd)
      process.env = originalEnv
      fs.rmSync(tempDir, { recursive: true, force: true })
   })

   it("injects decrypted secrets into child process via --", () => {
      // 1. Set a secret
      execSync(`node ${CLI_PATH} set SECRET_DB_PASS supersecret123`, { stdio: "ignore" })

      // 2. Set an unencrypted standard variable
      fs.appendFileSync(".secenvs", "PUBLIC_VAR=public_info\n")

      // 3. Run a polyglot test command (using node to mock)
      const output = execSync(
         `node ${CLI_PATH} run -- node -e "console.log(process.env.SECRET_DB_PASS + '|' + process.env.PUBLIC_VAR)"`,
         {
            encoding: "utf-8",
         }
      )

      expect(output.trim()).toBe("supersecret123|public_info")
   })

   it("throws an error if -- separator is missing", () => {
      expect(() => {
         execSync(`node ${CLI_PATH} run echo hello`, { stdio: "pipe" })
      }).toThrow(/Usage: secenvs run --/)
   })

   it("exits with the same code as the child process", () => {
      let exitCode = 0
      try {
         // This child process exits with code 42
         execSync(`node ${CLI_PATH} run -- node -e "process.exit(42)"`, { stdio: "ignore" })
      } catch (error: any) {
         exitCode = error.status
      }
      expect(exitCode).toBe(42)
   })

   it("injects global vault references automatically", () => {
      // 1. Set a global vault secret
      // Note: we're using SECENV_HOME isolated to tempDir, so global vault is isolated
      execSync(`node ${CLI_PATH} vault set GLOBAL_DB "global_master"`, { stdio: "ignore" })

      // 2. Reference it locally
      fs.appendFileSync(".secenvs", "DB_URL=vault:GLOBAL_DB\n")

      // 3. Run assertion
      const output = execSync(`node ${CLI_PATH} run -- node -e "console.log(process.env.DB_URL)"`, {
         encoding: "utf-8",
      })

      expect(output.trim()).toBe("global_master")
   })

   it("allows transparent use of npm shell commands", () => {
      const pkgPath = path.join(tempDir, "package.json")
      fs.writeFileSync(
         pkgPath,
         JSON.stringify({
            scripts: {
               "test-script": 'node -e "console.log(process.env.SHELL_TEST)"',
            },
         })
      )

      execSync(`node ${CLI_PATH} set SHELL_TEST shell_value`, { stdio: "ignore" })

      const output = execSync(`node ${CLI_PATH} run -- npm run test-script`, { encoding: "utf-8" })

      expect(output).toContain("shell_value")
   })

   it("injects multiple decrypted secrets into child process", () => {
      // Set multiple secrets
      execSync(`node ${CLI_PATH} set SECRET1 value1`, { stdio: "ignore" })
      execSync(`node ${CLI_PATH} set SECRET2 value2`, { stdio: "ignore" })
      execSync(`node ${CLI_PATH} set SECRET3 value3`, { stdio: "ignore" })

      // Run command that accesses multiple secrets
      const output = execSync(
         `node ${CLI_PATH} run -- node -e "console.log(process.env.SECRET1 + ',' + process.env.SECRET2 + ',' + process.env.SECRET3)"`,
         { encoding: "utf-8" }
      )

      expect(output.trim()).toBe("value1,value2,value3")
   })

   it("handles secrets with special characters like quotes and newlines", () => {
      // Set a secret with newlines using base64
      const specialValue = "line1\nline2\nline3"
      const base64Value = Buffer.from(specialValue).toString("base64")
      execSync(`node ${CLI_PATH} set SPECIAL_SECRET --base64 ${base64Value}`, { stdio: "ignore" })

      // Run command that outputs the secret
      const output = execSync(
         `node ${CLI_PATH} run -- node -e "console.log(JSON.stringify(process.env.SPECIAL_SECRET))"`,
         {
            encoding: "utf-8",
         }
      )

      expect(JSON.parse(output.trim())).toBe(specialValue)
   })

   it("overrides existing environment variables with decrypted secrets", () => {
      // Set an existing env var
      process.env.OVERRIDE_VAR = "original_value"

      // Set a secret with the same name
      execSync(`node ${CLI_PATH} set OVERRIDE_VAR secret_value`, { stdio: "ignore" })

      // Run command that checks the value
      const output = execSync(`node ${CLI_PATH} run -- node -e "console.log(process.env.OVERRIDE_VAR)"`, {
         encoding: "utf-8",
      })

      expect(output.trim()).toBe("secret_value")
   })

   it("throws error for non-existent vault references", () => {
      // Reference a non-existent vault key
      fs.appendFileSync(".secenvs", "MISSING_VAR=vault:NON_EXISTENT\n")

      // Run command should fail
      expect(() => {
         execSync(`node ${CLI_PATH} run -- node -e "console.log(process.env.MISSING_VAR)"`, {
            stdio: "ignore",
         })
      }).toThrow()
   })

   it("handles commands that write to stderr", () => {
      execSync(`node ${CLI_PATH} set STDERR_TEST value`, { stdio: "ignore" })

      // Command that writes to stderr
      const output = execSync(
         `node ${CLI_PATH} run -- node -e "console.error(process.env.STDERR_TEST); console.log('stdout')"`,
         {
            encoding: "utf-8",
         }
      )

      // Should capture stdout, stderr goes to inherit
      expect(output.trim()).toBe("stdout")
   })

   it("handles empty secret values", () => {
      // Set a secret with spaces
      execSync(`node ${CLI_PATH} set SPACED_SECRET "value with spaces"`, { stdio: "ignore" })

      // Run command
      const output = execSync(
         `node ${CLI_PATH} run -- node -e "console.log('[' + process.env.SPACED_SECRET + ']')"`,
         {
            encoding: "utf-8",
         }
      )

      expect(output.trim()).toBe("[value with spaces]")
   })

   it("handles base64 encoded secrets", () => {
      // Set a secret with base64 encoded data
      const originalData = "Hello, world! 🌍"
      const base64Data = Buffer.from(originalData).toString("base64")
      execSync(`node ${CLI_PATH} set BASE64_SECRET --base64 ${base64Data}`, { stdio: "ignore" })

      // Run command that checks the decoded data
      const output = execSync(`node ${CLI_PATH} run -- node -e "console.log(process.env.BASE64_SECRET)"`, {
         encoding: "utf-8",
      })

      expect(output.trim()).toBe(originalData)
   })

   it("handles secrets containing equals signs", () => {
      execSync(`node ${CLI_PATH} set EQUALS_SECRET "key=value=more"`, { stdio: "ignore" })

      const output = execSync(`node ${CLI_PATH} run -- node -e "console.log(process.env.EQUALS_SECRET)"`, {
         encoding: "utf-8",
      })

      expect(output.trim()).toBe("key=value=more")
   })

   it("handles commands with multiple arguments including spaces", () => {
      execSync(`node ${CLI_PATH} set ARGS_SECRET value`, { stdio: "ignore" })

      const output = execSync(
         `node ${CLI_PATH} run -- node -e "console.log(process.argv.slice(1).join('|'))" arg1 "arg with spaces" arg3`,
         {
            encoding: "utf-8",
         }
      )

      expect(output.trim()).toBe("arg1|arg with spaces|arg3")
   })

   it("handles very long secret values", () => {
      const longValue = "A".repeat(10000)
      execSync(`node ${CLI_PATH} set LONG_SECRET "${longValue}"`, { stdio: "ignore" })

      const output = execSync(
         `node ${CLI_PATH} run -- node -e "console.log(process.env.LONG_SECRET.length)"`,
         {
            encoding: "utf-8",
         }
      )

      expect(output.trim()).toBe("10000")
   })

   it("captures non-zero exit codes if command does not exist", () => {
      let exitCode = 0
      try {
         execSync(`node ${CLI_PATH} run -- definitely_not_exist_command_123`, { stdio: "ignore" })
      } catch (error: any) {
         exitCode = error.status
      }
      expect(exitCode).not.toBe(0)
   })
})
