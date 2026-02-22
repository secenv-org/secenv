import * as fs from "fs"
import * as path from "path"
import { z } from "zod"
import { createEnv } from "../../src/env.js"
import { SchemaValidationError } from "../../src/errors.js"

// Note: To make secenvs work we need to mock or setup .secenvs.
// However, since we're using createEnv which calls `env` underneath, and `env` reads from process.env primarily,
// we can easily test validation logic using process.env first!

describe("createEnv (Zod Validation)", () => {
   const originalEnv = process.env

   beforeEach(() => {
      process.env = { ...originalEnv }
      process.env.TEST_DB_URL = "postgres://user:pass@localhost:5432/db"
      process.env.TEST_PORT = "3000"
   })

   afterEach(() => {
      process.env = originalEnv
   })

   it("should parse valid environment variables successfully", async () => {
      const schema = z.object({
         TEST_DB_URL: z.string().url(),
         TEST_PORT: z.coerce.number().min(1000).max(9999),
         OPTIONAL_KEY: z.string().default("fallback"),
      })

      const result = await createEnv(schema)

      expect(result).toEqual({
         TEST_DB_URL: "postgres://user:pass@localhost:5432/db",
         TEST_PORT: 3000,
         OPTIONAL_KEY: "fallback",
      })
   })

   it("should throw a SchemaValidationError if strict is true and validation fails", async () => {
      const schema = z.object({
         TEST_DB_URL: z.string().url(),
         TEST_PORT: z.string(), // Will fail because it expects a string but we passed it a string? Wait, process.env is a string. Valid.
         MISSING_REQUIRED: z.string(), // No default -> will fail!
      })

      await expect(createEnv(schema)).rejects.toThrow(SchemaValidationError)
   })

   it("should return SafeParse results if strict is false", async () => {
      const schema = z.object({
         MISSING_REQUIRED: z.string(),
      })

      const result = (await createEnv(schema, { strict: false })) as any
      expect(result.success).toBe(false)
      expect(result.error.issues[0].path[0]).toBe("MISSING_REQUIRED")
   })
})
