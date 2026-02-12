import { parseEnvFile } from "../../src/parse.js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { ParseError, ValidationError } from "../../src/errors.js";

describe("Parser Edge Cases (parse.ts)", () => {
  let testDir: string;
  let envPath: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-parse-edge-"));
    envPath = path.join(testDir, ".secenv");
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it("should handle values with equals signs", () => {
    fs.writeFileSync(envPath, "URL=https://example.com?a=b&c=d");
    const result = parseEnvFile(envPath);
    expect(result.keys.has("URL")).toBe(true);
    expect(result.lines.find((l) => l.key === "URL")?.value).toBe(
      "https://example.com?a=b&c=d",
    );
  });

  it("should throw ValidationError for keys with special characters", () => {
    fs.writeFileSync(envPath, "MY-KEY.SUB=value\nANOTHER_KEY=123");
    expect(() => parseEnvFile(envPath)).toThrow(ValidationError);
  });

  it("should handle unicode characters", () => {
    fs.writeFileSync(envPath, "UNICODE_KEY=🚀_value_\u1234");
    const result = parseEnvFile(envPath);
    expect(result.lines.find((l) => l.key === "UNICODE_KEY")?.value).toBe(
      "🚀_value_\u1234",
    );
  });

  it("should handle trailing whitespace in values", () => {
    // Current implementation trims the whole line, so trailing space is lost if not quoted (but we don't support quotes yet)
    fs.writeFileSync(envPath, "KEY=value   ");
    const result = parseEnvFile(envPath);
    expect(result.lines.find((l) => l.key === "KEY")?.value).toBe("value");
  });

  it("should handle very long values", () => {
    const longVal = "a".repeat(10000);
    fs.writeFileSync(envPath, `LONG=${longVal}`);
    const result = parseEnvFile(envPath);
    expect(result.lines.find((l) => l.key === "LONG")?.value).toBe(longVal);
  });

  it("should throw ParseError for empty key", () => {
    fs.writeFileSync(envPath, "=value");
    expect(() => parseEnvFile(envPath)).toThrow(ParseError);
    expect(() => parseEnvFile(envPath)).toThrow(/Invalid line/);
  });

  it("should handle multiple consecutive empty lines", () => {
    fs.writeFileSync(envPath, "K1=V1\n\n\nK2=V2");
    const result = parseEnvFile(envPath);
    expect(result.lines.length).toBe(4);
    expect(result.keys.size).toBe(2);
  });

  it("should handle file without trailing newline", () => {
    fs.writeFileSync(envPath, "K1=V1");
    const result = parseEnvFile(envPath);
    expect(result.keys.has("K1")).toBe(true);
  });

  it("should handle CRLF line endings", () => {
    fs.writeFileSync(envPath, "K1=V1\r\nK2=V2\r\n");
    const result = parseEnvFile(envPath);
    expect(result.keys.has("K1")).toBe(true);
    expect(result.keys.has("K2")).toBe(true);
    expect(result.lines.find((l) => l.key === "K1")?.value).toBe("V1");
  });
});
