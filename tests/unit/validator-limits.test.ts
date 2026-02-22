import { validateKey, validateValue } from "../../src/validators.js"
import { ValidationError } from "../../src/errors.js"

describe("Validator Limit Tests", () => {
   describe("Key Length Limits", () => {
      const MAX_KEY_LENGTH = 64

      it("should accept key exactly at max length", () => {
         const maxKey = "A".repeat(MAX_KEY_LENGTH)
         expect(() => validateKey(maxKey)).not.toThrow()
      })

      it("should reject key exceeding max length", () => {
         const longKey = "A".repeat(MAX_KEY_LENGTH + 1)
         expect(() => validateKey(longKey)).toThrow(ValidationError)
         expect(() => validateKey(longKey)).toThrow(/exceeds maximum length/)
      })

      it("should reject key just one character over limit", () => {
         const overByOne = "K".repeat(65)
         expect(() => validateKey(overByOne)).toThrow(ValidationError)
      })

      it("should handle very long keys (100+ characters)", () => {
         const veryLongKey = "X".repeat(100)
         expect(() => validateKey(veryLongKey)).toThrow(ValidationError)
      })
   })

   describe("Value Size Limits", () => {
      const MAX_VALUE_SIZE = 5 * 1024 * 1024 // 5MB

      it("should accept value at exactly 5MB", () => {
         const maxValue = "x".repeat(MAX_VALUE_SIZE)
         expect(() => validateValue(maxValue)).not.toThrow()
      })

      it("should reject value exceeding 5MB", () => {
         const overLimit = "x".repeat(MAX_VALUE_SIZE + 1)
         expect(() => validateValue(overLimit)).toThrow(ValidationError)
         expect(() => validateValue(overLimit)).toThrow(/exceeds maximum/)
      })

      it("should reject value just 1 byte over limit", () => {
         const overByOne = "a".repeat(MAX_VALUE_SIZE + 1)
         expect(() => validateValue(overByOne)).toThrow(ValidationError)
      })

      it("should reject empty string as value", () => {
         expect(() => validateValue("")).toThrow(ValidationError)
      })

      it("should silently accept null/undefined values (handled elsewhere)", () => {
         expect(() => validateValue(undefined as any)).not.toThrow()
         expect(() => validateValue(null as any)).not.toThrow()
      })

      it("should handle large UTF-8 values correctly", () => {
         const utf8Value = "🎌".repeat(Math.floor(MAX_VALUE_SIZE / 4))
         const byteSize = Buffer.byteLength(utf8Value, "utf-8")
         if (byteSize <= MAX_VALUE_SIZE) {
            expect(() => validateValue(utf8Value)).not.toThrow()
         } else {
            expect(() => validateValue(utf8Value)).toThrow(ValidationError)
         }
      })
   })

   describe("Windows Reserved Names", () => {
      const windowsReserved = [
         "CON",
         "PRN",
         "AUX",
         "NUL",
         "COM1",
         "COM2",
         "COM3",
         "COM4",
         "COM5",
         "COM6",
         "COM7",
         "COM8",
         "COM9",
         "LPT1",
         "LPT2",
         "LPT3",
         "LPT4",
         "LPT5",
         "LPT6",
         "LPT7",
         "LPT8",
         "LPT9",
      ]

      it("should reject Windows reserved names", () => {
         for (const reserved of windowsReserved) {
            expect(() => validateKey(reserved)).toThrow(ValidationError)
            expect(() => validateKey(reserved)).toThrow(/reserved/)
         }
      })

      it("should reject lowercase reserved names (fail regex before reserved check)", () => {
         expect(() => validateKey("con")).toThrow(ValidationError)
         expect(() => validateKey("prn")).toThrow(ValidationError)
         expect(() => validateKey("aux")).toThrow(ValidationError)
      })

      it("should reject reserved names with extension — dots not allowed in keys", () => {
         expect(() => validateKey("COM1.txt")).toThrow(ValidationError)
         expect(() => validateKey("NUL.txt")).toThrow(ValidationError)
      })
   })

   describe("Key Format Validation", () => {
      it("should reject keys starting with number", () => {
         expect(() => validateKey("1KEY")).toThrow(ValidationError)
         expect(() => validateKey("123")).toThrow(ValidationError)
         expect(() => validateKey("0")).toThrow(ValidationError)
      })

      it("should accept keys starting with underscore", () => {
         expect(() => validateKey("_KEY")).not.toThrow()
         expect(() => validateKey("_PRIVATE_KEY")).not.toThrow()
      })

      it("should accept keys with numbers after first character", () => {
         expect(() => validateKey("KEY1")).not.toThrow()
         expect(() => validateKey("MY_VAR_2")).not.toThrow()
         expect(() => validateKey("A1B2C3")).not.toThrow()
      })

      it("should reject keys with hyphens", () => {
         expect(() => validateKey("my-key")).toThrow(ValidationError)
         expect(() => validateKey("KEY-NAME")).toThrow(ValidationError)
      })

      it("should reject keys with dots", () => {
         expect(() => validateKey("my.key")).toThrow(ValidationError)
         expect(() => validateKey("KEY.NAME")).toThrow(ValidationError)
      })

      it("should reject keys with spaces", () => {
         expect(() => validateKey("MY KEY")).toThrow(ValidationError)
         expect(() => validateKey("KEY ")).toThrow(ValidationError)
         expect(() => validateKey(" KEY")).toThrow(ValidationError)
      })

      it("should reject empty key", () => {
         expect(() => validateKey("")).toThrow(ValidationError)
         expect(() => validateKey("   ")).toThrow(ValidationError)
      })
   })

   describe("Value Validation", () => {
      it("should reject multiline values without base64 flag", () => {
         expect(() => validateValue("line1\nline2")).toThrow(ValidationError)
         expect(() => validateValue("line1\r\nline2")).toThrow(ValidationError)
         expect(() => validateValue("value\r")).toThrow(ValidationError)
      })

      it("should accept multiline values with base64 flag", () => {
         const base64Value = "SGVsbG8gV29ybGQ="
         expect(() => validateValue(base64Value, { isBase64: true })).not.toThrow()
      })

      it("should reject invalid base64 with base64 flag", () => {
         expect(() => validateValue("not-valid-base64!!", { isBase64: true })).toThrow(ValidationError)
         expect(() => validateValue("abc=def", { isBase64: true })).toThrow(ValidationError)
      })

      it("should accept valid base64 with base64 flag", () => {
         const validBase64 = "SGVsbG8gV29ybGQh" // "Hello World!"
         expect(() => validateValue(validBase64, { isBase64: true })).not.toThrow()
      })

      it("should accept value with equals sign", () => {
         expect(() => validateValue("a=b=c")).not.toThrow()
         expect(() => validateValue("url=https://example.com?x=1")).not.toThrow()
      })

      it("should accept value with special characters", () => {
         expect(() => validateValue("!@#$%^&*()")).not.toThrow()
         expect(() => validateValue("value with spaces")).not.toThrow()
      })
   })
})
