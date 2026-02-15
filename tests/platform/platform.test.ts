import { parseEnvFile } from "../../src/parse.js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

describe("Platform Compatibility", () => {
  let testDir: string;
  let envPath: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-plat-"));
    envPath = path.join(testDir, ".secenvs");
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it("should handle LF line endings (Unix/macOS)", () => {
    fs.writeFileSync(envPath, "K1=V1\nK2=V2\n");
    const result = parseEnvFile(envPath);
    expect(result.keys.size).toBe(2);
    expect(result.lines.find((l) => l.key === "K1")?.value).toBe("V1");
  });

  it("should handle CRLF line endings (Windows)", () => {
    fs.writeFileSync(envPath, "K1=V1\r\nK2=V2\r\n");
    const result = parseEnvFile(envPath);
    expect(result.keys.size).toBe(2);
    expect(result.lines.find((l) => l.key === "K1")?.value).toBe("V1");
  });

  it("should handle mixed line endings", () => {
    fs.writeFileSync(envPath, "K1=V1\nK2=V2\r\nK3=V3");
    const result = parseEnvFile(envPath);
    expect(result.keys.size).toBe(3);
    expect(result.lines.find((l) => l.key === "K2")?.value).toBe("V2");
  });
});
