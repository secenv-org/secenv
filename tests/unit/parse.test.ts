import { parseEnvFile, ParsedLine } from "../../src/parse.js";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ParseError } from "../../src/errors.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("Parser (parse.ts)", () => {
  const testEnvPath = path.join(__dirname, "test.secenvs");

  afterEach(() => {
    if (fs.existsSync(testEnvPath)) {
      fs.unlinkSync(testEnvPath);
    }
  });

  it("should return empty result if file does not exist", () => {
    const result = parseEnvFile("non-existent-file");
    expect(result.lines).toEqual([]);
    expect(result.keys.size).toBe(0);
  });

  it("should parse simple plaintext values", () => {
    fs.writeFileSync(testEnvPath, "PORT=3000\nNODE_ENV=development");
    const result = parseEnvFile(testEnvPath);

    expect(result.keys.has("PORT")).toBe(true);
    expect(result.keys.has("NODE_ENV")).toBe(true);
    expect(result.plaintextCount).toBe(2);
    expect(result.encryptedCount).toBe(0);

    const portLine = result.lines.find((l: ParsedLine) => l.key === "PORT");
    expect(portLine?.value).toBe("3000");
  });

  it("should identify encrypted values", () => {
    fs.writeFileSync(testEnvPath, "SECRET=enc:age:xyz\nPUBLIC=123");
    const result = parseEnvFile(testEnvPath);

    expect(result.encryptedCount).toBe(1);
    expect(result.plaintextCount).toBe(1);

    const secretLine = result.lines.find((l: ParsedLine) => l.key === "SECRET");
    expect(secretLine?.encrypted).toBe(true);
  });

  it("should handle comments and empty lines", () => {
    fs.writeFileSync(testEnvPath, "# comment\n\nKEY=VAL");
    const result = parseEnvFile(testEnvPath);

    expect(result.lines.length).toBe(3);
    expect(result.keys.size).toBe(1);
    expect(result.lines[0].key).toBe("");
    expect(result.lines[1].key).toBe("");
  });

  it("should throw ParseError on missing equals sign", () => {
    fs.writeFileSync(testEnvPath, "INVALID_LINE");
    expect(() => parseEnvFile(testEnvPath)).toThrow(ParseError);
    expect(() => parseEnvFile(testEnvPath)).toThrow(/missing '=' separator/);
  });

  it("should throw ParseError on duplicate keys", () => {
    fs.writeFileSync(testEnvPath, "KEY=VAL1\nKEY=VAL2");
    expect(() => parseEnvFile(testEnvPath)).toThrow(ParseError);
    expect(() => parseEnvFile(testEnvPath)).toThrow(/Duplicate key 'KEY'/);
  });
});
