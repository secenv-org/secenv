import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { parseEnvFile } from "../../src/parse.js"
import { ParseError } from "../../src/errors.js"

describe("Corruption Recovery", () => {
   let testDir: string
   let envPath: string

   beforeEach(() => {
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-robustness-"))
      envPath = path.join(testDir, ".secenvs")
   })

   afterEach(() => {
      fs.rmSync(testDir, { recursive: true, force: true })
   })

   it("should handle UTF-8 BOM at start of file", () => {
      const content = "\uFEFFKEY=VALUE\n"
      fs.writeFileSync(envPath, content)
      const result = parseEnvFile(envPath)
      // BOM should be stripped, key should be parsed correctly
      expect(result.keys.has("KEY")).toBe(true)
      const line = result.lines.find((l) => l.key === "KEY")
      expect(line?.value).toBe("VALUE")
   })

   it("should handle UTF-8 BOM before first key", () => {
      const content = "\uFEFF\nKEY1=value1\nKEY2=value2\n"
      fs.writeFileSync(envPath, content)
      const result = parseEnvFile(envPath)
      expect(result.keys.has("KEY1")).toBe(true)
      expect(result.keys.has("KEY2")).toBe(true)
   })

   it("should throw validation error for UTF-16 BE BOM content", () => {
      const bom = Buffer.from([0xfe, 0xff])
      const content = Buffer.concat([bom, Buffer.from("KEY=value\n", "utf16le")])
      fs.writeFileSync(envPath, content)
      // UTF-16 content with BOM will produce invalid keys, should throw validation error
      expect(() => parseEnvFile(envPath)).toThrow()
   })

   it("should throw validation error for UTF-16 LE BOM content", () => {
      const bom = Buffer.from([0xff, 0xfe])
      const content = Buffer.concat([bom, Buffer.from("KEY=value\n", "utf16le")])
      fs.writeFileSync(envPath, content)
      // UTF-16 content with BOM will produce invalid keys, should throw validation error
      expect(() => parseEnvFile(envPath)).toThrow()
   })

   it("should handle empty files", () => {
      fs.writeFileSync(envPath, "")
      const result = parseEnvFile(envPath)
      expect(result.keys.size).toBe(0)
      expect(result.lines.length).toBe(1) // ['']
   })

   it("should handle files with only comments", () => {
      fs.writeFileSync(envPath, "# This is a comment\n# Another one")
      const result = parseEnvFile(envPath)
      expect(result.keys.size).toBe(0)
      expect(result.lines.length).toBe(2)
   })

   it("should throw ParseError for random garbage", () => {
      fs.writeFileSync(envPath, "this is not a valid env file format")
      expect(() => parseEnvFile(envPath)).toThrow(ParseError)
   })

   it("should handle partial writes (e.g. key without equals)", () => {
      fs.writeFileSync(envPath, "KEY_WITHOUT_EQUALS")
      expect(() => parseEnvFile(envPath)).toThrow(ParseError)
   })
})
