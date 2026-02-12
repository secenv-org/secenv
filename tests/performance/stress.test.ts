import { execa } from "execa";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";
import { createSecenv } from "../../src/env.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, "../../bin/secenv");

describe("Stress Tests", () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-stress-cwd-"));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-stress-home-"));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
    delete process.env.SECENV_HOME;
  });

  it("should handle 1000 keys in .secenv", async () => {
    process.chdir(testDir);
    process.env.SECENV_HOME = secenvHome;

    // Setup 1000 keys
    const lines = [];
    for (let i = 0; i < 1000; i++) {
      lines.push(`KEY_${i}=value_${i}`);
    }
    fs.writeFileSync(".secenv", lines.join("\n"));

    const env = createSecenv();

    // Test access to first, middle and last
    expect(await env.get("KEY_0")).toBe("value_0");
    expect(await env.get("KEY_500")).toBe("value_500");
    expect(await env.get("KEY_999")).toBe("value_999");

    const allKeys = env.keys();
    for (let i = 0; i < 1000; i++) {
      expect(allKeys).toContain(`KEY_${i}`);
    }
  }, 30000); // Higher timeout for 1000 keys

  it("should handle large values (1MB)", async () => {
    process.chdir(testDir);
    process.env.SECENV_HOME = secenvHome;

    const largeVal = "a".repeat(1024 * 1024); // 1MB
    fs.writeFileSync(".secenv", `LARGE=${largeVal}\n`);

    const env = createSecenv();
    const result = await env.get("LARGE");
    expect(result.length).toBe(1024 * 1024);
    expect(result).toBe(largeVal);
  });

  it("should handle many SDK instances without leaking memory (basic check)", async () => {
    process.chdir(testDir);
    process.env.SECENV_HOME = secenvHome;
    fs.writeFileSync(".secenv", "K=V\n");

    for (let i = 0; i < 100; i++) {
      const env = createSecenv();
      await env.get("K");
    }
    // If it didn't crash, it's a good start.
  });
});
