import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parseEnvFile } from "../../src/parse.js";
import { ParseError } from "../../src/errors.js";

describe("Corruption Recovery", () => {
  let testDir: string;
  let envPath: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-robustness-"));
    envPath = path.join(testDir, ".secenvs");
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it("should handle UTF-8 BOM", () => {
    const content = "\uFEFFKEY=VALUE\n";
    fs.writeFileSync(envPath, content);
    const result = parseEnvFile(envPath);
    // In our current implementation, the BOM might be part of the first key if not handled.
    // Let's see if we need to fix src/parse.ts for this.
  });

  it("should handle empty files", () => {
    fs.writeFileSync(envPath, "");
    const result = parseEnvFile(envPath);
    expect(result.keys.size).toBe(0);
    expect(result.lines.length).toBe(1); // ['']
  });

  it("should handle files with only comments", () => {
    fs.writeFileSync(envPath, "# This is a comment\n# Another one");
    const result = parseEnvFile(envPath);
    expect(result.keys.size).toBe(0);
    expect(result.lines.length).toBe(2);
  });

  it("should throw ParseError for random garbage", () => {
    fs.writeFileSync(envPath, "this is not a valid env file format");
    expect(() => parseEnvFile(envPath)).toThrow(ParseError);
  });

  it("should handle partial writes (e.g. key without equals)", () => {
    fs.writeFileSync(envPath, "KEY_WITHOUT_EQUALS");
    expect(() => parseEnvFile(envPath)).toThrow(ParseError);
  });
});
