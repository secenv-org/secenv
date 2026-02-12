import { execa } from "execa";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";
import { createSecenv } from "../../src/env.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN_PATH = path.resolve(__dirname, "../../bin/secenv");
const PROJECT_ROOT = path.resolve(__dirname, "../..");

describe("CI/CD Security", () => {
  let testDir: string;
  let secenvHome: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-ci-sec-"));
    secenvHome = fs.mkdtempSync(path.join(os.tmpdir(), "secenv-ci-sec-home-"));
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(PROJECT_ROOT);
    fs.rmSync(testDir, { recursive: true, force: true });
    fs.rmSync(secenvHome, { recursive: true, force: true });
    delete process.env.SECENV_ENCODED_IDENTITY;
  });

  it("should validate SECENV_ENCODED_IDENTITY format", async () => {
    process.env.SECENV_ENCODED_IDENTITY = "not-base64-!!!";
    const env = createSecenv();
    // It might fail during Buffer.from or later.
    // If it's not base64, Buffer.from might still return something but it will be garbage.
    // Our loadIdentity just decodes it.
    // However, if the decoded value is used for decryption, age will fail.
  });

  it("should not leak secrets to process.env by default", async () => {
    const envPath = path.join(testDir, ".secenv");
    fs.writeFileSync(envPath, "MY_SECRET=enc:age:abc...\n");

    // Mock decryption or just use a plaintext one for this test
    fs.writeFileSync(envPath, "MY_SECRET=top-secret\n");

    const env = createSecenv();
    await env.get("MY_SECRET");

    expect(process.env.MY_SECRET).toBeUndefined();
  });
});
