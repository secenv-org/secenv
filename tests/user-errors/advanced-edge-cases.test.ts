import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { createSecenv } from "../../src/env.js"
import { generateIdentity, saveIdentity, encrypt, identityExists, getPublicKey } from "../../src/age.js"
import { setKey, parseEnvFile } from "../../src/parse.js"
import { ValidationError } from "../../src/errors.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe("Advanced Edge Cases", () => {
   let testDir: string
   let testHome: string
   let originalCwd: string

   beforeEach(async () => {
      originalCwd = process.cwd()
      testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-edge-"))
      testHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-edge-home-"))
      process.chdir(testDir)
      process.env.SECENV_HOME = testHome

      const identity = await generateIdentity()
      await saveIdentity(identity)
   })

   afterEach(() => {
      delete process.env.SECENV_HOME
      try {
         process.chdir(originalCwd)
      } catch (e) {
         process.chdir(os.tmpdir())
      }
      try {
         fs.rmSync(testDir, { recursive: true, force: true })
      } catch (e) {}
      try {
         fs.rmSync(testHome, { recursive: true, force: true })
      } catch (e) {}
   })

   describe("Very Long Values", () => {
      it("should handle value at exactly 5MB limit", async () => {
         const limit = 5 * 1024 * 1024
         const value = "x".repeat(limit)

         // Should succeed (limit is inclusive)
         await expect(setKey(path.join(testDir, ".secenvs"), "LARGE", value)).resolves.not.toThrow()
      })

      it("should handle value just under 5MB limit", async () => {
         const limit = 5 * 1024 * 1024 - 100
         const value = "x".repeat(limit)

         // Should succeed
         await expect(setKey(path.join(testDir, ".secenvs"), "LARGE_OK", value)).resolves.not.toThrow()
      })
   })

   describe("Unicode and Special Characters", () => {
      it("should handle Unicode emojis in value", async () => {
         fs.writeFileSync(".secenvs", "EMOJI=🎉🚀💻🔐\n")

         const sdk = createSecenv()
         const value = await sdk.get("EMOJI")
         expect(value).toBe("🎉🚀💻🔐")
      })

      it("should handle Chinese characters in value", async () => {
         fs.writeFileSync(".secenvs", "CHINESE=你好世界\n")

         const sdk = createSecenv()
         const value = await sdk.get("CHINESE")
         expect(value).toBe("你好世界")
      })

      it("should handle Arabic characters in value", async () => {
         fs.writeFileSync(".secenvs", "ARABIC=مرحبا\n")

         const sdk = createSecenv()
         const value = await sdk.get("ARABIC")
         expect(value).toBe("مرحبا")
      })

      it("should handle Japanese characters in value", async () => {
         fs.writeFileSync(".secenvs", "JAPANESE=こんにちは\n")

         const sdk = createSecenv()
         const value = await sdk.get("JAPANESE")
         expect(value).toBe("こんにちは")
      })

      it("should handle Cyrillic characters in value", async () => {
         fs.writeFileSync(".secenvs", "CYRILLIC=Привет\n")

         const sdk = createSecenv()
         const value = await sdk.get("CYRILLIC")
         expect(value).toBe("Привет")
      })

      it("should handle zero-width characters in value", async () => {
         fs.writeFileSync(".secenvs", "ZWS=test\u200Bvalue\n")

         const sdk = createSecenv()
         const value = await sdk.get("ZWS")
         expect(value).toContain("\u200B")
      })

      it("should handle combining characters in value", async () => {
         fs.writeFileSync(".secenvs", "COMBINING=é\n")

         const sdk = createSecenv()
         const value = await sdk.get("COMBINING")
         expect(value).toBe("é")
      })
   })

   describe("Key Edge Cases", () => {
      it("should handle key at maximum reasonable length", async () => {
         const longKey = "A".repeat(100)
         fs.writeFileSync(".secenvs", `${longKey}=value\n`)

         expect(() => parseEnvFile(".secenvs")).toThrow(ValidationError)
      })

      it("should handle many keys in single file", async () => {
         let content = ""
         for (let i = 0; i < 1000; i++) {
            content += `KEY${i}=value${i}\n`
         }
         fs.writeFileSync(".secenvs", content)

         const result = parseEnvFile(".secenvs")
         expect(result.keys.size).toBe(1000)
      })
   })

   describe("Path Edge Cases", () => {
      it("should handle paths with spaces", async () => {
         const spacedDir = path.join(testDir, "path with spaces")
         fs.mkdirSync(spacedDir, { recursive: true })
         process.chdir(spacedDir)

         fs.writeFileSync(".secenvs", "KEY=value\n")

         const sdk = createSecenv()
         expect(await sdk.get("KEY")).toBe("value")

         process.chdir(testDir)
         fs.rmSync(spacedDir, { recursive: true, force: true })
      })

      it("should handle paths with special characters", async () => {
         const specialDir = path.join(testDir, "path-with-unicode-🎉")
         fs.mkdirSync(specialDir, { recursive: true })
         process.chdir(specialDir)

         fs.writeFileSync(".secenvs", "KEY=value\n")

         const sdk = createSecenv()
         expect(await sdk.get("KEY")).toBe("value")

         process.chdir(testDir)
         fs.rmSync(specialDir, { recursive: true, force: true })
      })
   })

   describe("Docker/Container Edge Cases", () => {
      it("should handle readonly root filesystem scenario", async () => {
         if (os.platform() === "win32") return

         // Simulate: home is read-only
         const roHome = path.join(testDir, "readonly-home")
         fs.mkdirSync(roHome, { recursive: true })

         // Try to initialize (should fail if truly RO)
         // This documents behavior in container environments
         const identity = await generateIdentity()
         await saveIdentity(identity)

         // Should work (test environment has write)
         expect(identityExists()).toBe(true)
      })

      it("should handle NFS-style atomic rename", async () => {
         // NFS may have different atomic rename semantics
         const envPath = path.join(testDir, ".secenvs")

         await setKey(envPath, "KEY1", "value1")
         await setKey(envPath, "KEY2", "value2")

         const result = parseEnvFile(envPath)
         expect(result.keys.has("KEY1")).toBe(true)
         expect(result.keys.has("KEY2")).toBe(true)
      })
   })

   describe("Encrypted Value Edge Cases", () => {
      it("should handle encrypted value with special characters", async () => {
         const identity = await generateIdentity()
         await saveIdentity(identity)

         const specialValue = "Special: chars!@#$%^&*()\n\t\"'"
         const pubkey = await getPublicKey(identity)
         const encrypted = await encrypt([pubkey], specialValue)

         fs.writeFileSync(".secenvs", `ENC=enc:age:${encrypted}\n`)

         const sdk = createSecenv()
         const decrypted = await sdk.get("ENC")
         expect(decrypted).toBe(specialValue)
      })

      it("should handle binary data via base64", async () => {
         const identity = await generateIdentity()
         await saveIdentity(identity)

         // Simulate binary data as base64
         const binaryBase64 = Buffer.from([0x00, 0x01, 0xff, 0xfe]).toString("base64")

         // setKey takes 3 args: filePath, key, encryptedValue
         // This tests SDK behavior, not CLI --base64 flag
         const envPath = path.join(testDir, ".secenvs")
         await expect(setKey(envPath, "BINARY", binaryBase64)).resolves.not.toThrow()
      })
   })
})
