import { execa } from "execa";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, "../../bin/secenv");

describe("CLI Integration", () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-test-cwd-"));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-test-home-"));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
  });

  const run = (args: string[]) => {
    return execa("node", [BIN_PATH, ...args], {
      cwd: testDir,
      env: { SECENV_HOME: secenvHome },
    });
  };

  it("should initialize successfully", async () => {
    const { stdout } = await run(["init"]);
    expect(stdout).toContain("Identity created");
    expect(stdout).toContain("Created");
    expect(stdout).toContain("Updated .gitignore");

    const keyPath = path.join(secenvHome, ".secenv", "keys", "default.key");
    expect(fs.existsSync(keyPath)).toBe(true);
    expect(fs.existsSync(path.join(testDir, ".secenv"))).toBe(true);
    expect(
      fs.readFileSync(path.join(testDir, ".gitignore"), "utf-8"),
    ).toContain(".secenv");
  });

  it("should set and get values", async () => {
    await run(["init"]);
    await run(["set", "MY_KEY", "my-secret-value"]);

    const { stdout } = await run(["get", "MY_KEY"]);
    expect(stdout).toBe("my-secret-value");

    const envContent = fs.readFileSync(path.join(testDir, ".secenv"), "utf-8");
    expect(envContent).toContain("MY_KEY=enc:age:");
    expect(envContent).not.toContain("my-secret-value");
  });

  it("should list keys", async () => {
    await run(["init"]);
    await run(["set", "KEY1", "val1"]);
    await run(["set", "KEY2", "val2"]);

    const { stdout } = await run(["list"]);
    expect(stdout).toContain("KEY1  [encrypted]");
    expect(stdout).toContain("KEY2  [encrypted]");
  });

  it("should delete keys", async () => {
    await run(["init"]);
    await run(["set", "KEY_TO_DELETE", "val"]);
    await run(["delete", "KEY_TO_DELETE"]);

    const { stdout } = await run(["list"]);
    expect(stdout).not.toContain("KEY_TO_DELETE");
  });

  it("should export values with --force", async () => {
    await run(["init"]);
    await run(["set", "EXPORT_KEY", "secret-content"]);

    const { stdout } = await run(["export", "--force"]);
    expect(stdout).toContain("EXPORT_KEY=secret-content");
  });

  it("should reject multiline values without --base64", async () => {
    await run(["init"]);
    await expect(run(["set", "MULTI", "line1\nline2"])).rejects.toThrow();
  });

  it("should accept multiline values with --base64", async () => {
    await run(["init"]);
    const base64Value = Buffer.from("line1\nline2").toString("base64");
    await run(["set", "MULTI", base64Value, "--base64"]);

    const { stdout } = await run(["get", "MULTI"]);
    expect(stdout).toBe(base64Value);
  });
});
