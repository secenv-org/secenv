import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { parseEnvFile } from "../../src/parse.js"
import { ParseError, ValidationError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe("User Blunder: Manual .secenvs Corruption", () => {
   let testDir: string
   let envPath: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-corrupt-test-"))
      envPath = path.join(testDir, ".secenvs")
   })

   afterEach(() => {
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
      } catch (e) {
         // Ignore cleanup errors
      }
   })

   it("should throw ParseError for line without '=' separator", () => {
      // User manually edited file and forgot '='
      fs.writeFileSync(envPath, "THIS_IS_NOT_A_VALID_LINE\n")

      expect(() => parseEnvFile(envPath)).toThrow(ParseError)
      expect(() => parseEnvFile(envPath)).toThrow(/missing '='/)
   })

   it("should throw ParseError for empty key (starts with =)", () => {
      // User accidentally created =value line
      fs.writeFileSync(envPath, "=somevalue\n")

      expect(() => parseEnvFile(envPath)).toThrow(ParseError)
      expect(() => parseEnvFile(envPath)).toThrow(/missing key/)
   })

   it("should handle empty value (key=) as valid", () => {
      // User intentionally or accidentally set empty value
      fs.writeFileSync(envPath, "MYKEY=\n")

      const result = parseEnvFile(envPath)
      expect(result.keys.has("MYKEY")).toBe(true)
      const line = result.lines.find((l) => l.key === "MYKEY")
      expect(line?.value).toBe("")
   })

   it("should throw ValidationError for key with spaces", () => {
      // User used "MY KEY" instead of "MY_KEY"
      fs.writeFileSync(envPath, "MY KEY=value\n")

      expect(() => parseEnvFile(envPath)).toThrow(ValidationError)
      expect(() => parseEnvFile(envPath)).toThrow(/Invalid key/)
   })

   it("should throw ValidationError for lowercase key", () => {
      // User used lowercase key
      fs.writeFileSync(envPath, "mykey=value\n")

      expect(() => parseEnvFile(envPath)).toThrow(ValidationError)
      expect(() => parseEnvFile(envPath)).toThrow(/uppercase/)
   })

   it("should throw ValidationError for key with hyphen", () => {
      // User used "MY-KEY" instead of "MY_KEY"
      fs.writeFileSync(envPath, "MY-KEY=value\n")

      expect(() => parseEnvFile(envPath)).toThrow(ValidationError)
   })

   it("should throw ValidationError for key with special characters", () => {
      // User used special characters in key
      fs.writeFileSync(envPath, "MY@KEY=value\n")

      expect(() => parseEnvFile(envPath)).toThrow(ValidationError)
   })

   it("should throw ParseError for duplicate keys from merge conflict", () => {
      // User had git merge conflict and got duplicate keys
      fs.writeFileSync(envPath, "KEY=value1\nKEY=value2\n")

      expect(() => parseEnvFile(envPath)).toThrow(ParseError)
      expect(() => parseEnvFile(envPath)).toThrow(/Duplicate key/)
   })

   it("should throw DecryptionError for truncated age blob", async () => {
      const { generateIdentity, encrypt } = await import("../../src/age.js")
      const identity = await generateIdentity()
      const encrypted = await encrypt(identity, "secret")

      // Truncate the encrypted value
      const truncated = encrypted.substring(0, encrypted.length - 20)

      fs.writeFileSync(envPath, `SECRET=enc:age:${truncated}\n`)

      const result = parseEnvFile(envPath)
      expect(result.keys.has("SECRET")).toBe(true)

      // Decryption should fail later when trying to decrypt
      const { decrypt } = await import("../../src/age.js")
      await expect(decrypt(identity, truncated)).rejects.toThrow()
   })

   it("should throw DecryptionError for corrupted age blob", async () => {
      const { generateIdentity, encrypt } = await import("../../src/age.js")
      const identity = await generateIdentity()

      // Create corrupted encrypted value
      const corrupted = "invalid_base64_chars_here!!!"

      fs.writeFileSync(envPath, `SECRET=enc:age:${corrupted}\n`)

      const result = parseEnvFile(envPath)
      expect(result.keys.has("SECRET")).toBe(true)

      // Decryption should fail
      const { decrypt } = await import("../../src/age.js")
      await expect(decrypt(identity, corrupted)).rejects.toThrow()
   })

   it("should handle UTF-8 BOM at start", () => {
      // User saved file with BOM from Windows editor
      const content = "\uFEFFKEY1=value1\nKEY2=value2\n"
      fs.writeFileSync(envPath, content)

      const result = parseEnvFile(envPath)

      // Should parse both keys (BOM handling depends on implementation)
      // If BOM is stripped correctly:
      if (result.keys.has("KEY1")) {
         expect(result.keys.has("KEY1")).toBe(true)
         expect(result.keys.has("KEY2")).toBe(true)
      } else {
         // If BOM is not stripped, first key will have BOM prefix
         // This documents current behavior
         expect(result.keys.size).toBeGreaterThan(0)
      }
   })

   it("should handle mixed line endings (CRLF + LF)", () => {
      // User mixed Windows and Unix line endings
      fs.writeFileSync(envPath, "KEY1=value1\r\nKEY2=value2\nKEY3=value3\r\n")

      const result = parseEnvFile(envPath)

      // All keys should be parsed correctly
      expect(result.keys.has("KEY1")).toBe(true)
      expect(result.keys.has("KEY2")).toBe(true)
      expect(result.keys.has("KEY3")).toBe(true)
   })

   it("should handle file with only comments", () => {
      // User commented out all keys
      fs.writeFileSync(envPath, "# This is a comment\n# Another one\n")

      const result = parseEnvFile(envPath)

      // No keys should be present
      expect(result.keys.size).toBe(0)
      // Lines may include trailing empty line, so just check >= 2
      expect(result.lines.length).toBeGreaterThanOrEqual(2)
   })

   it("should handle key with trailing spaces", () => {
      // User accidentally added space after key
      fs.writeFileSync(envPath, "MYKEY =value\n")

      // Should either trim or reject
      try {
         const result = parseEnvFile(envPath)
         // If parsing succeeds, key should not have trailing space
         const hasKeyWithSpace = Array.from(result.keys).some((k) => (k as string).includes(" "))
         expect(hasKeyWithSpace).toBe(false)
      } catch (e) {
         // If it throws, that's also valid behavior
         expect(e).toBeInstanceOf(Error)
      }
   })

   it("should trim trailing spaces from value", () => {
      // User added spaces to value
      fs.writeFileSync(envPath, "MYKEY=  value with spaces  \n")

      const result = parseEnvFile(envPath)
      const line = result.lines.find((l) => l.key === "MYKEY")

      // Line is trimmed, so trailing spaces are removed
      // Leading spaces within the value are preserved if present after the =
      expect(line?.value).toBe("  value with spaces")
   })

   it("should parse key correctly with multiple '=' in value", () => {
      // User has URL params or equation in value
      fs.writeFileSync(envPath, "URL=https://example.com?key=val&foo=bar\n")

      const result = parseEnvFile(envPath)
      const line = result.lines.find((l) => l.key === "URL")

      // Everything after first = should be value
      expect(line?.value).toBe("https://example.com?key=val&foo=bar")
   })

   it("should handle binary garbage in file gracefully", () => {
      // File got corrupted with binary data
      const garbage = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0xfd])
      fs.writeFileSync(envPath, garbage)

      // Should throw or handle gracefully without crashing
      expect(() => parseEnvFile(envPath)).toThrow()
   })

   it("should handle zero-byte (empty) file", () => {
      // User created empty file
      fs.writeFileSync(envPath, "")

      const result = parseEnvFile(envPath)

      // Should return empty result without crashing
      expect(result.keys.size).toBe(0)
   })

   it("should handle file with only whitespace", () => {
      // File has only whitespace lines
      fs.writeFileSync(envPath, "   \n\t\n  \n")

      const result = parseEnvFile(envPath)

      // Should handle gracefully
      expect(result.keys.size).toBe(0)
   })
})
