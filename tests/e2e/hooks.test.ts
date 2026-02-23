import { execSync } from "child_process"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"

// Helper to run commands
function run(cmd: string, cwd: string): { stdout: string; stderr: string; status: number | null } {
   try {
      const output = execSync(cmd, { cwd, encoding: "utf-8", stdio: "pipe" })
      return { stdout: output, stderr: "", status: 0 }
   } catch (error: any) {
      return { stdout: error.stdout || "", stderr: error.stderr || "", status: error.status }
   }
}

describe("Git Pre-commit Hooks (E2E)", () => {
   let repoDir: string
   let originalCwd: string

   beforeAll(() => {
      originalCwd = process.cwd()
      // Build index.js from typescript via build script or ensure it's built
      execSync("npm run build", { cwd: process.cwd(), stdio: "ignore" })
   })

   beforeEach(() => {
      // Create a new temporary directory for each test
      repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenvs-test-repo-"))

      // Initialize a git repo
      run("git init", repoDir)

      // Configure dummy git user so commits work
      run("git config user.name 'Test User'", repoDir)
      run("git config user.email 'test@example.com'", repoDir)

      // Create an initial commit so we have a HEAD
      fs.writeFileSync(path.join(repoDir, "README.md"), "# Test Repo")
      run("git add README.md", repoDir)
      run("git commit -m 'Initial commit'", repoDir)
   })

   afterEach(() => {
      // Cleanup temp dir
      if (fs.existsSync(repoDir)) {
         fs.rmSync(repoDir, { recursive: true, force: true })
      }
   })

   it("should install hooks and block plaintext .env files", () => {
      // 1. Install hooks using the built CLI binary
      const cliPath = path.join(originalCwd, "bin", "secenvs.js")
      const result = run(`node ${cliPath} install-hooks`, repoDir)
      expect(result.status).toBe(0)
      expect(result.stdout).toContain("Successfully installed secenvs pre-commit hook")

      // 2. Verify the hook file was created
      const hookPath = path.join(repoDir, ".git", "hooks", "pre-commit")
      expect(fs.existsSync(hookPath)).toBe(true)

      // 3. Try committing a standard file (should succeed)
      fs.writeFileSync(path.join(repoDir, "index.js"), "console.log('hello')")
      run("git add index.js", repoDir)
      const commitValid = run("git commit -m 'Add index.js'", repoDir)
      expect(commitValid.status).toBe(0)

      // 4. Try committing a plaintext .env file (should fail)
      fs.writeFileSync(path.join(repoDir, ".env"), "SECRET=plaintext")
      run("git add .env", repoDir)
      const commitEnv = run("git commit -m 'Add plaintext .env'", repoDir)
      expect(commitEnv.status).not.toBe(0) // hook should block it
      expect(commitEnv.stdout + commitEnv.stderr).toContain("ERROR: secenvs blocked a commit")
   })

   it("should handle real-world complexities correctly", () => {
      const cliPath = path.join(originalCwd, "bin", "secenvs.js")
      run(`node ${cliPath} install-hooks`, repoDir)

      // 1. .env.example should NOT be blocked
      fs.writeFileSync(path.join(repoDir, ".env.example"), "SECRET=example")
      run("git add .env.example", repoDir)
      const commitExample = run("git commit -m 'Add .env.example'", repoDir)
      expect(commitExample.status).toBe(0)

      // 2. config/api.env.ts should NOT be blocked
      fs.mkdirSync(path.join(repoDir, "config"))
      fs.writeFileSync(path.join(repoDir, "config", "api.env.ts"), "export {}")
      run("git add config/api.env.ts", repoDir)
      const commitApiEnvTs = run("git commit -m 'Add api.env.ts'", repoDir)
      expect(commitApiEnvTs.status).toBe(0)

      // 3. .secenvs should NOT be blocked
      fs.writeFileSync(path.join(repoDir, ".secenvs"), "SECRET=enc:age:123")
      run("git add .secenvs", repoDir)
      const commitSecenvs = run("git commit -m 'Add .secenvs'", repoDir)
      expect(commitSecenvs.status).toBe(0)

      // 4. Subdirectory .env SHOULD be blocked
      fs.mkdirSync(path.join(repoDir, "apps"))
      fs.writeFileSync(path.join(repoDir, "apps", ".env"), "SECRET=plaintext")
      run("git add apps/.env", repoDir)
      const commitNested = run("git commit -m 'Add apps/.env'", repoDir)
      expect(commitNested.status).not.toBe(0)
      expect(commitNested.stdout + commitNested.stderr).toContain("apps/.env")
      // restore to clean state so next test works
      run("git restore --staged apps/.env", repoDir)

      // 5. Space in path .env.local SHOULD be blocked
      fs.mkdirSync(path.join(repoDir, "my app"))
      fs.writeFileSync(path.join(repoDir, "my app", ".env.local"), "SECRET=local")
      // note: git add doesn't need quotes in execSync if passed properly, but we use shell string
      run("git add 'my app/.env.local'", repoDir)
      const commitSpace = run("git commit -m 'Add .env.local with space'", repoDir)
      expect(commitSpace.status).not.toBe(0)
      expect(commitSpace.stdout + commitSpace.stderr).toContain("my app/.env.local")
      run("git restore --staged 'my app/.env.local'", repoDir)

      // 6. Deleting a .env file SHOULD NOT trigger the hook
      fs.writeFileSync(path.join(repoDir, ".env"), "FOO=bar")
      // bypass hook to commit it
      run("git add .env", repoDir)
      run("git commit --no-verify -m 'Force add .env'", repoDir)
      // Now delete it
      run("git rm .env", repoDir)
      const commitDelete = run("git commit -m 'Delete .env'", repoDir)
      expect(commitDelete.status).toBe(0)
   })

   it("should uninstall hooks and allow plaintext .env files again", () => {
      const cliPath = path.join(originalCwd, "bin", "secenvs.js")

      // Install first
      run(`node ${cliPath} install-hooks`, repoDir)

      // Create .env
      fs.writeFileSync(path.join(repoDir, ".env"), "SECRET=plaintext")
      run("git add .env", repoDir)

      // Verify blocked
      const commitBlocked = run("git commit -m 'Blocked'", repoDir)
      expect(commitBlocked.status).not.toBe(0)

      // Uninstall
      const uninstallRes = run(`node ${cliPath} uninstall-hooks`, repoDir)
      expect(uninstallRes.status).toBe(0)
      expect(uninstallRes.stdout).toContain("Successfully removed secenvs")

      // Try commit again, should succeed
      const commitAllowed = run("git commit -m 'Allowed'", repoDir)
      expect(commitAllowed.status).toBe(0)
   })

   it("should append and remove secenvs block correctly from existing hook", () => {
      const hookPath = path.join(repoDir, ".git", "hooks", "pre-commit")
      const hooksDir = path.dirname(hookPath)
      if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true })

      // Create existing hook
      fs.writeFileSync(hookPath, "#!/bin/sh\\necho 'existing hook'")

      const cliPath = path.join(originalCwd, "bin", "secenvs.js")

      // Install
      run(`node ${cliPath} install-hooks`, repoDir)

      const contentAfterInstall = fs.readFileSync(hookPath, "utf-8")
      expect(contentAfterInstall.includes("echo 'existing hook'")).toBe(true)
      expect(contentAfterInstall.includes("# SECENVS_HOOK_START")).toBe(true)

      // Uninstall
      run(`node ${cliPath} uninstall-hooks`, repoDir)
      const contentAfterUninstall = fs.readFileSync(hookPath, "utf-8")
      expect(contentAfterUninstall.includes("echo 'existing hook'")).toBe(true)
      expect(contentAfterUninstall.includes("# SECENVS_HOOK_START")).toBe(false)
   })
})
