export const SECENV_ERROR_CODES = {
   IDENTITY_NOT_FOUND: "IDENTITY_NOT_FOUND",
   DECRYPTION_FAILED: "DECRYPTION_FAILED",
   SECRET_NOT_FOUND: "SECRET_NOT_FOUND",
   PARSE_ERROR: "PARSE_ERROR",
   FILE_ERROR: "FILE_ERROR",
   ENCRYPTION_FAILED: "ENCRYPTION_FAILED",
   VALIDATION_ERROR: "VALIDATION_ERROR",
   RECIPIENT_ERROR: "RECIPIENT_ERROR",
   VAULT_ERROR: "VAULT_ERROR",
} as const

export type SecenvErrorCode = (typeof SECENV_ERROR_CODES)[keyof typeof SECENV_ERROR_CODES]

export class SecenvError extends Error {
   code: SecenvErrorCode

   constructor(code: SecenvErrorCode, message: string) {
      super(message)
      this.name = "SecenvError"
      this.code = code
   }
}

export class ValidationError extends SecenvError {
   constructor(message: string) {
      super(SECENV_ERROR_CODES.VALIDATION_ERROR, message)
   }
}

export class IdentityNotFoundError extends SecenvError {
   constructor(path: string) {
      super(
         SECENV_ERROR_CODES.IDENTITY_NOT_FOUND,
         `Identity key not found at ${path}. Run 'secenv init' to create one.`
      )
   }
}

export class DecryptionError extends SecenvError {
   constructor(message: string = "Failed to decrypt value. Check identity key.") {
      super(SECENV_ERROR_CODES.DECRYPTION_FAILED, message)
   }
}

export class SecretNotFoundError extends SecenvError {
   constructor(key: string) {
      super(SECENV_ERROR_CODES.SECRET_NOT_FOUND, `Secret '${key}' not found in .secenvs or process.env.`)
   }
}

export class ParseError extends SecenvError {
   line: number
   raw: string

   constructor(line: number, raw: string, message: string) {
      super(SECENV_ERROR_CODES.PARSE_ERROR, message)
      this.line = line
      this.raw = raw
   }
}

export class FileError extends SecenvError {
   constructor(message: string) {
      super(SECENV_ERROR_CODES.FILE_ERROR, message)
   }
}

export class EncryptionError extends SecenvError {
   constructor(message: string = "Failed to encrypt value.") {
      super(SECENV_ERROR_CODES.ENCRYPTION_FAILED, message)
   }
}

export class RecipientError extends SecenvError {
   constructor(message: string) {
      super(SECENV_ERROR_CODES.RECIPIENT_ERROR, message)
   }
}

export class VaultError extends SecenvError {
   constructor(message: string) {
      super(SECENV_ERROR_CODES.VAULT_ERROR, message)
   }
}
