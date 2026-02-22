import {
   SecenvError,
   IdentityNotFoundError,
   DecryptionError,
   SecretNotFoundError,
   ParseError,
   FileError,
   EncryptionError,
   ValidationError,
   VaultError,
   RecipientError,
   SchemaValidationError,
   SECENV_ERROR_CODES,
} from "../../src/errors.js"

describe("Error Classes (errors.ts)", () => {
   it("should have correct error codes", () => {
      expect(SECENV_ERROR_CODES.IDENTITY_NOT_FOUND).toBe("IDENTITY_NOT_FOUND")
      expect(SECENV_ERROR_CODES.DECRYPTION_FAILED).toBe("DECRYPTION_FAILED")
      expect(SECENV_ERROR_CODES.SECRET_NOT_FOUND).toBe("SECRET_NOT_FOUND")
      expect(SECENV_ERROR_CODES.PARSE_ERROR).toBe("PARSE_ERROR")
      expect(SECENV_ERROR_CODES.FILE_ERROR).toBe("FILE_ERROR")
      expect(SECENV_ERROR_CODES.ENCRYPTION_FAILED).toBe("ENCRYPTION_FAILED")
      expect(SECENV_ERROR_CODES.VALIDATION_ERROR).toBe("VALIDATION_ERROR")
      expect(SECENV_ERROR_CODES.RECIPIENT_ERROR).toBe("RECIPIENT_ERROR")
      expect(SECENV_ERROR_CODES.VAULT_ERROR).toBe("VAULT_ERROR")
      expect(SECENV_ERROR_CODES.SCHEMA_VALIDATION_ERROR).toBe("SCHEMA_VALIDATION_ERROR")
   })

   it("IdentityNotFoundError should have correct code and message", () => {
      const error = new IdentityNotFoundError("/path/to/key")
      expect(error.code).toBe(SECENV_ERROR_CODES.IDENTITY_NOT_FOUND)
      expect(error.message).toContain("/path/to/key")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("DecryptionError should have correct code and message", () => {
      const error = new DecryptionError("custom message")
      expect(error.code).toBe(SECENV_ERROR_CODES.DECRYPTION_FAILED)
      expect(error.message).toBe("custom message")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("DecryptionError should have default message", () => {
      const error = new DecryptionError()
      expect(error.message).toContain("decrypt")
   })

   it("SecretNotFoundError should have correct code and message", () => {
      const error = new SecretNotFoundError("MY_KEY")
      expect(error.code).toBe(SECENV_ERROR_CODES.SECRET_NOT_FOUND)
      expect(error.message).toContain("MY_KEY")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("ParseError should have correct code, message, and properties", () => {
      const error = new ParseError(10, "KEY VAL", "Missing equals")
      expect(error.code).toBe(SECENV_ERROR_CODES.PARSE_ERROR)
      expect(error.message).toBe("Missing equals")
      expect(error.line).toBe(10)
      expect(error.raw).toBe("KEY VAL")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("FileError should have correct code and message", () => {
      const error = new FileError("disk full")
      expect(error.code).toBe(SECENV_ERROR_CODES.FILE_ERROR)
      expect(error.message).toBe("disk full")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("EncryptionError should have correct code and message", () => {
      const error = new EncryptionError("invalid input")
      expect(error.code).toBe(SECENV_ERROR_CODES.ENCRYPTION_FAILED)
      expect(error.message).toBe("invalid input")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("EncryptionError should have default message", () => {
      const error = new EncryptionError()
      expect(error.message).toContain("encrypt")
   })

   it("SecenvError should be an instance of Error", () => {
      const error = new SecenvError(SECENV_ERROR_CODES.FILE_ERROR, "msg")
      expect(error).toBeInstanceOf(Error)
      expect(error.name).toBe("SecenvError")
   })

   it("ValidationError should have correct code and message", () => {
      const error = new ValidationError("key is invalid")
      expect(error.code).toBe(SECENV_ERROR_CODES.VALIDATION_ERROR)
      expect(error.message).toBe("key is invalid")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("VaultError should have correct code and message", () => {
      const error = new VaultError("vault decryption failed")
      expect(error.code).toBe(SECENV_ERROR_CODES.VAULT_ERROR)
      expect(error.message).toBe("vault decryption failed")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("RecipientError should have correct code and message", () => {
      const error = new RecipientError("invalid public key format")
      expect(error.code).toBe(SECENV_ERROR_CODES.RECIPIENT_ERROR)
      expect(error.message).toBe("invalid public key format")
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("SchemaValidationError should have correct code, message, and issues", () => {
      const issues = [{ path: ["API_KEY"], message: "Required" }]
      const error = new SchemaValidationError("Schema validation failed", issues)
      expect(error.code).toBe(SECENV_ERROR_CODES.SCHEMA_VALIDATION_ERROR)
      expect(error.message).toBe("Schema validation failed")
      expect(error.issues).toEqual(issues)
      expect(error).toBeInstanceOf(SecenvError)
   })

   it("SchemaValidationError should default to empty issues array", () => {
      const error = new SchemaValidationError("validation failed")
      expect(error.issues).toEqual([])
   })

   it("all error classes should be catchable as SecenvError", () => {
      const errors: SecenvError[] = [
         new ValidationError("v"),
         new VaultError("v"),
         new RecipientError("v"),
         new SchemaValidationError("v"),
         new IdentityNotFoundError("/p"),
         new DecryptionError("v"),
         new SecretNotFoundError("K"),
         new FileError("v"),
         new EncryptionError("v"),
      ]
      for (const err of errors) {
         expect(err).toBeInstanceOf(SecenvError)
         expect(err).toBeInstanceOf(Error)
         expect(typeof err.code).toBe("string")
         expect(typeof err.message).toBe("string")
      }
   })
})
