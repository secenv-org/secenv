import * as fs from "fs"
import * as path from "path"
import { parseDotenvFallback } from "../../src/dotenv-parser.js"

describe("Dotenv Parser", () => {
   let tempFile: string

   beforeEach(() => {
      tempFile = path.join(process.cwd(), `.env.test.${Date.now()}`)
   })

   afterEach(() => {
      if (fs.existsSync(tempFile)) {
         fs.unlinkSync(tempFile)
      }
   })

   it("should parse normal key-value pairs", () => {
      fs.writeFileSync(tempFile, "FOO=bar\nBAZ=qux\n")
      const parsed = parseDotenvFallback(tempFile)

      expect(parsed).toHaveLength(2)
      expect(parsed[0].key).toBe("FOO")
      expect(parsed[0].value).toBe("bar")
      expect(parsed[1].key).toBe("BAZ")
      expect(parsed[1].value).toBe("qux")
   })

   it("should strip export prefixes", () => {
      fs.writeFileSync(tempFile, "export FOO=bar\n  export BAZ=qux\n")
      const parsed = parseDotenvFallback(tempFile)

      expect(parsed).toHaveLength(2)
      expect(parsed[0].key).toBe("FOO")
      expect(parsed[0].value).toBe("bar")
      expect(parsed[1].key).toBe("BAZ")
      expect(parsed[1].value).toBe("qux")
   })

   it("should handle stripping quotes", () => {
      fs.writeFileSync(tempFile, "FOO=\"bar\"\nBAZ='qux'\n")
      const parsed = parseDotenvFallback(tempFile)

      expect(parsed).toHaveLength(2)
      expect(parsed[0].value).toBe("bar")
      expect(parsed[1].value).toBe("qux")
   })

   it("should handle unescaping newlines in quotes", () => {
      fs.writeFileSync(tempFile, 'FOO="line1\\nline2"\n')
      const parsed = parseDotenvFallback(tempFile)

      expect(parsed).toHaveLength(1)
      expect(parsed[0].value).toBe("line1\nline2")
   })

   it("should ignore empty lines and full line comments", () => {
      fs.writeFileSync(tempFile, "\n# this is a comment\nFOO=bar\n\n# another comment\n")
      const parsed = parseDotenvFallback(tempFile)

      expect(parsed).toHaveLength(1)
      expect(parsed[0].key).toBe("FOO")
   })

   it("should strip inline comments without quotes", () => {
      fs.writeFileSync(tempFile, "FOO=bar # comment here\n")
      const parsed = parseDotenvFallback(tempFile)

      expect(parsed).toHaveLength(1)
      expect(parsed[0].value).toBe("bar")
   })

   it("should return empty array if file does not exist", () => {
      const parsed = parseDotenvFallback(tempFile + ".nonexistent")
      expect(parsed).toEqual([])
   })
})
