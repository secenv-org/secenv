import { isEncryptedValue, isVaultReference } from "../../src/parse.js"

describe("Parse Helper Functions", () => {
   describe("isEncryptedValue()", () => {
      it("should return true for valid encrypted value prefix", () => {
         expect(isEncryptedValue("enc:age:base64encodeddata")).toBe(true)
         expect(isEncryptedValue("enc:age:")).toBe(true)
         expect(isEncryptedValue("enc:age:something")).toBe(true)
      })

      it("should return false for non-encrypted values", () => {
         expect(isEncryptedValue("plain-value")).toBe(false)
         expect(isEncryptedValue("enc:")).toBe(false)
         expect(isEncryptedValue("age:something")).toBe(false)
         expect(isEncryptedValue("ENC:age:value")).toBe(false)
         expect(isEncryptedValue("Enc:age:value")).toBe(false)
      })

      it("should return false for empty string", () => {
         expect(isEncryptedValue("")).toBe(false)
      })

      it("should return false for values with leading spaces", () => {
         expect(isEncryptedValue(" enc:age:value")).toBe(false)
      })

      it("should return true for values with trailing spaces (startsWith check only)", () => {
         expect(isEncryptedValue("enc:age:value ")).toBe(true)
      })

      it("should return false for similar but wrong prefixes", () => {
         expect(isEncryptedValue("enc:age")).toBe(false)
         expect(isEncryptedValue("encrage:value")).toBe(false)
         expect(isEncryptedValue("ENC:AGE:value")).toBe(false)
      })
   })

   describe("isVaultReference()", () => {
      it("should return true for valid vault reference", () => {
         expect(isVaultReference("vault:MY_KEY")).toBe(true)
         expect(isVaultReference("vault:")).toBe(true)
         expect(isVaultReference("vault:DB_PASSWORD")).toBe(true)
      })

      it("should return false for non-vault references", () => {
         expect(isVaultReference("plain-value")).toBe(false)
         expect(isVaultReference("vault")).toBe(false)
         expect(isVaultReference("VAULT:key")).toBe(false)
         expect(isVaultReference("Vault:key")).toBe(false)
      })

      it("should return false for empty string", () => {
         expect(isVaultReference("")).toBe(false)
      })

      it("should return false for values with leading spaces", () => {
         expect(isVaultReference(" vault:key")).toBe(false)
      })

      it("should return true for values with trailing spaces (startsWith check only)", () => {
         expect(isVaultReference("vault:key ")).toBe(true)
      })

      it("should return false for similar but wrong prefixes", () => {
         expect(isVaultReference("vaults:key")).toBe(false)
         expect(isVaultReference("vaulty:key")).toBe(false)
         expect(isVaultReference("VAULT:key")).toBe(false)
      })
   })
})
