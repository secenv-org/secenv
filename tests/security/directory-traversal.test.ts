import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { sanitizePath, safeReadFile, ensureSafeDir } from "../../src/filesystem.js"
import { FileError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe("Filesystem Security - Directory Traversal", () => {
   let testDir: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-traversal-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
   })

   it("should detect directory traversal with baseDir parameter", () => {
      const baseDir = path.join(testDir, "allowed")
      fs.mkdirSync(baseDir, { recursive: true })

      // Attempt to access file outside baseDir
      const traversalPath = path.join(baseDir, "..", "..", "etc", "passwd")

      expect(() => sanitizePath(traversalPath, baseDir)).toThrow(FileError)
      expect(() => sanitizePath(traversalPath, baseDir)).toThrow(/Directory traversal detected/)
   })

   it("should allow paths within baseDir", () => {
      const baseDir = path.join(testDir, "allowed")
      fs.mkdirSync(baseDir, { recursive: true })

      // Valid path within baseDir
      const validPath = path.join(baseDir, "subdir", "file.txt")
      fs.mkdirSync(path.dirname(validPath), { recursive: true })
      fs.writeFileSync(validPath, "content")

      // Should not throw
      const result = sanitizePath(validPath, baseDir)
      expect(result).toBe(path.resolve(validPath))
   })

   it("should handle complex relative paths", () => {
      const baseDir = path.join(testDir, "base")
      fs.mkdirSync(baseDir, { recursive: true })
      fs.mkdirSync(path.join(baseDir, "subdir"), { recursive: true })
      fs.writeFileSync(path.join(baseDir, "subdir", "file.txt"), "content")

      // Path that goes up and back down within bounds
      const validRelative = path.join(baseDir, "subdir", "..", "subdir", "file.txt")
      const result = sanitizePath(validRelative, baseDir)
      expect(result).toBe(path.resolve(baseDir, "subdir", "file.txt"))
   })

   it("should reject absolute paths outside baseDir", () => {
      const baseDir = path.join(testDir, "base")
      fs.mkdirSync(baseDir, { recursive: true })

      // Absolute path outside baseDir
      const outsidePath = "/etc/passwd"

      expect(() => sanitizePath(outsidePath, baseDir)).toThrow(FileError)
   })

   it("should handle symlink detection in safeReadFile", () => {
      const targetFile = path.join(testDir, "target.txt")
      const linkFile = path.join(testDir, "link.txt")

      fs.writeFileSync(targetFile, "secret data")
      fs.symlinkSync(targetFile, linkFile)

      expect(() => safeReadFile(linkFile)).toThrow(FileError)
      expect(() => safeReadFile(linkFile)).toThrow(/Symlink detected/)
   })

   it("should handle broken symlinks", () => {
      const linkFile = path.join(testDir, "broken-link.txt")

      // Create symlink to non-existent file
      fs.symlinkSync("/nonexistent/path", linkFile)

      expect(() => safeReadFile(linkFile)).toThrow(FileError)
   })

   it("should ensureSafeDir reject symlink directories", () => {
      const realDir = path.join(testDir, "real")
      const linkDir = path.join(testDir, "link")

      fs.mkdirSync(realDir)
      fs.symlinkSync(realDir, linkDir)

      expect(() => ensureSafeDir(linkDir)).toThrow(FileError)
   })

   it("should allow regular directories in ensureSafeDir", () => {
      const regularDir = path.join(testDir, "regular")
      fs.mkdirSync(regularDir)

      // Should not throw
      expect(() => ensureSafeDir(regularDir)).not.toThrow()
   })

   it("should create directory if it does not exist", () => {
      const newDir = path.join(testDir, "new", "nested", "dir")

      // Should create the directory
      ensureSafeDir(newDir)

      expect(fs.existsSync(newDir)).toBe(true)
      expect(fs.statSync(newDir).isDirectory()).toBe(true)
   })

   it("should handle files posing as directories", () => {
      const filePath = path.join(testDir, "notadir")
      fs.writeFileSync(filePath, "I am a file")

      // ensureSafeDir only checks if path exists and is not a symlink
      // It doesn't validate if it's a file vs directory
      // The function will succeed because the path exists and is not a symlink
      expect(() => ensureSafeDir(filePath)).not.toThrow()
   })
})

describe("Filesystem Security - File Operations", () => {
   let testDir: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-fileops-"))
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
   })

   it("should read file content successfully", () => {
      const filePath = path.join(testDir, "test.txt")
      fs.writeFileSync(filePath, "Hello World")

      const content = safeReadFile(filePath)
      expect(content).toBe("Hello World")
   })

   it("should throw for non-existent files", () => {
      const filePath = path.join(testDir, "nonexistent.txt")

      expect(() => safeReadFile(filePath)).toThrow(FileError)
   })

   it("should throw for directories", () => {
      const dirPath = path.join(testDir, "adir")
      fs.mkdirSync(dirPath)

      expect(() => safeReadFile(dirPath)).toThrow(FileError)
   })

   it("should handle special characters in filenames", () => {
      const filePath = path.join(testDir, "file with spaces & symbols.txt")
      fs.writeFileSync(filePath, "content")

      const content = safeReadFile(filePath)
      expect(content).toBe("content")
   })
})
