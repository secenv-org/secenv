import * as fs from "fs"
import * as path from "path"

export const SECENVS_HOOK_START = "# SECENVS_HOOK_START"
export const SECENVS_HOOK_END = "# SECENVS_HOOK_END"

export const HOOK_SCRIPT = `${SECENVS_HOOK_START}
#!/bin/sh
# secenvs pre-commit hook

# Check if any .env files are being committed
# We use grep -E '(^|/)\.env($|\.)' to match .env, foo/.env, .env.local, .env.development
# We use grep -vE '\.(example|sample|template)$' to allow safe template files
STAGED_ENV_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '(^|/)\\.env($|\\.)' | grep -vE '\\.(example|sample|template)$' || true)

if [ -n "$STAGED_ENV_FILES" ]; then
    echo "🚨 ERROR: secenvs blocked a commit containing plaintext .env files!"
    echo "$STAGED_ENV_FILES" | while IFS= read -r file; do
        echo "  - $file"
    done
    echo ""
    echo "Please remove these files from the commit and use secenvs instead:"
    echo "  git restore --staged <file>"
    echo "  secenvs migrate (if migrating to secenvs)"
    exit 1
fi
${SECENVS_HOOK_END}`

export function findGitRoot(currentDir: string): string | null {
   let dir = currentDir
   while (true) {
      if (fs.existsSync(path.join(dir, ".git"))) {
         return dir
      }
      const parent = path.dirname(dir)
      if (parent === dir) {
         return null // root directory reached
      }
      dir = parent
   }
}

export function installHooks(cwd: string): { success: boolean; message: string } {
   const gitRoot = findGitRoot(cwd)
   if (!gitRoot) {
      return { success: false, message: "Not a git repository (or any of the parent directories)" }
   }

   const hooksDir = path.join(gitRoot, ".git", "hooks")
   if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true })
   }

   const preCommitPath = path.join(hooksDir, "pre-commit")

   // Check if modifying an existing hook
   let existingContent = ""
   if (fs.existsSync(preCommitPath)) {
      existingContent = fs.readFileSync(preCommitPath, "utf-8")
      if (existingContent.includes(SECENVS_HOOK_START)) {
         return { success: true, message: "secenvs pre-commit hook is already installed." }
      }
      // Need to append, ensure we add a newline if the file doesn't end with one
      if (existingContent && !existingContent.endsWith("\n")) {
         existingContent += "\n"
      }
   }

   // if there was no existing content, we ensure it has #!/bin/sh
   // actually, our HOOK_SCRIPT already has #!/bin/sh right after SECENVS_HOOK_START
   // However, if we append to an existing one, it might already have #!/bin/sh, but having it again inside our block is harmless bash

   // To be clean, if the file is new, we just write the HOOK script.
   // If it's existing, we append the HOOK script.
   const newContent = existingContent + HOOK_SCRIPT + "\n"

   fs.writeFileSync(preCommitPath, newContent, "utf-8")
   fs.chmodSync(preCommitPath, 0o755) // Make it executable

   return { success: true, message: "Successfully installed secenvs pre-commit hook." }
}

export function uninstallHooks(cwd: string): { success: boolean; message: string } {
   const gitRoot = findGitRoot(cwd)
   if (!gitRoot) {
      return { success: false, message: "Not a git repository (or any of the parent directories)" }
   }

   const preCommitPath = path.join(gitRoot, ".git", "hooks", "pre-commit")
   if (!fs.existsSync(preCommitPath)) {
      return { success: true, message: "secenvs pre-commit hook not found." }
   }

   const content = fs.readFileSync(preCommitPath, "utf-8")
   if (!content.includes(SECENVS_HOOK_START)) {
      return { success: true, message: "secenvs pre-commit hook not found." }
   }

   // Read lines and strip out the secenvs block
   const lines = content.replace(/\r/g, "").split("\n")
   const newLines: string[] = []
   let inSecenvsBlock = false

   for (const line of lines) {
      if (line.trim() === SECENVS_HOOK_START) {
         inSecenvsBlock = true
         continue
      }
      if (line.trim() === SECENVS_HOOK_END) {
         inSecenvsBlock = false
         continue
      }
      if (!inSecenvsBlock) {
         newLines.push(line)
      }
   }

   const newContent = newLines.join("\n").trim()

   if (newContent === "" || newContent === "#!/bin/sh") {
      // Safe to delete the file
      fs.unlinkSync(preCommitPath)
      return { success: true, message: "Successfully removed secenvs pre-commit hook file entirely." }
   } else {
      // Rewrite without the secenvs block
      fs.writeFileSync(preCommitPath, newContent + "\n", "utf-8")
      return { success: true, message: "Successfully removed secenvs block from pre-commit hook." }
   }
}
