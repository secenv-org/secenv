import { ValidationError } from "./errors.js"

const KEY_REGEX = /^[A-Z_][A-Z0-9_]*$/
const MAX_KEY_LENGTH = 64
const MAX_VALUE_SIZE = 5 * 1024 * 1024 // 5MB

const WINDOWS_RESERVED_NAMES = new Set([
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
])

export function validateKey(key: string): void {
   if (!key) {
      throw new ValidationError("Key cannot be empty")
   }
   if (!KEY_REGEX.test(key)) {
      throw new ValidationError(
         `Invalid key: '${key}'. Keys must start with an uppercase letter and only contain uppercase letters, numbers, and underscores (^[A-Z][A-Z0-9_]*$).`
      )
   }
   if (key.length > MAX_KEY_LENGTH) {
      throw new ValidationError(`Key '${key}' exceeds maximum length of ${MAX_KEY_LENGTH} characters`)
   }
   if (WINDOWS_RESERVED_NAMES.has(key)) {
      throw new ValidationError(`Invalid key: '${key}' is a reserved system name.`)
   }
}

export function validateValue(value: string, options: { isBase64?: boolean } = {}): void {
   if (!value && value !== "") {
      return // Allow undefined/null if handled elsewhere
   }

   if (value === "") {
      throw new ValidationError("Value cannot be empty")
   }

   if (Buffer.byteLength(value, "utf-8") > MAX_VALUE_SIZE) {
      throw new ValidationError(`Value size exceeds maximum limit of 5MB`)
   }

   if (options.isBase64) {
      const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
      if (!base64Regex.test(value)) {
         throw new ValidationError("Invalid base64 value")
      }
   } else if (value.includes("\n") || value.includes("\r")) {
      throw new ValidationError("Multiline values are not allowed. Use --base64 for binary data.")
   }
}
