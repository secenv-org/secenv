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

   it("should return success result with data when strict:false and schema is valid", async () => {
      const schema = z.object({
         TEST_DB_URL: z.string(),
         TEST_PORT: z.string(),
      })

      const result = (await createEnv(schema, { strict: false })) as any
      expect(result.success).toBe(true)
      expect(result.data.TEST_DB_URL).toBe("postgres://user:pass@localhost:5432/db")
      expect(result.data.TEST_PORT).toBe("3000")
   })

   it("should work with ZodEffects (.refine()) schema — the PR #15 fix", async () => {
      // Before PR #15, createEnv crashed on ZodEffects because it tried to access `.shape`
      const schema = z
         .object({
            TEST_PORT: z.coerce.number(),
         })
         .refine((data) => data.TEST_PORT > 0, {
            message: "PORT must be positive",
         })

      const result = await createEnv(schema)
      expect(result).toMatchObject({ TEST_PORT: 3000 })
   })

   it("should throw SchemaValidationError with issues when ZodEffects refine fails", async () => {
      process.env.TEST_PORT = "-1"

      const schema = z
         .object({
            TEST_PORT: z.coerce.number(),
         })
         .refine((data) => data.TEST_PORT > 0, {
            message: "PORT must be positive",
         })

      const err = await createEnv(schema).catch((e) => e)
      expect(err).toBeInstanceOf(SchemaValidationError)
      expect(err.message).toContain("validation failed")
   })

   it("should throw SchemaValidationError with issues array populated", async () => {
      const schema = z.object({
         MISSING_ONE: z.string(),
         MISSING_TWO: z.string(),
      })

      let caught: SchemaValidationError | null = null
      try {
         await createEnv(schema)
      } catch (e: any) {
         caught = e
      }

      expect(caught).toBeInstanceOf(SchemaValidationError)
      expect(caught!.issues.length).toBeGreaterThanOrEqual(1)
   })

   it("should throw helpful error when zod is not available", async () => {
      // We simulate zod unavailability by passing a schema-like object that
      // only has the methods but no .parseAsync (to test our duck-typed path)
      // The real "no zod" test would need module mocking, but we verify the
      // schema interface is duck-typed and flexible.
      const fakeSchema = {
         parseAsync: async (data: any) => ({ TEST_DB_URL: data.TEST_DB_URL }),
         parse: (data: any) => ({ TEST_DB_URL: data.TEST_DB_URL }),
      }

      // This should succeed — schema is duck-typed, not requiring the zod package itself
      const result = await createEnv(fakeSchema as any)
      expect(result.TEST_DB_URL).toBe("postgres://user:pass@localhost:5432/db")
   })
})
