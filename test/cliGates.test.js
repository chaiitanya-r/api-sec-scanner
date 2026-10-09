import { describe, it, expect, beforeAll, afterAll } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createTestbedApp } from "../testbed/server.js";
import { runCli } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("CLI Security Gates & Options", () => {
  let server;
  let baseUrl;
  const specPath = path.resolve(__dirname, "../testbed/openapi.yaml");

  beforeAll(async () => {
    const app = createTestbedApp();
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", () => {
        baseUrl = `http://127.0.0.1:${server.address().port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    server?.close();
    try {
      const fs = await import("node:fs/promises");
      await fs.unlink(path.resolve(__dirname, "../report.json"));
    } catch {
      // Ignore if not present
    }
  });

  it("should exit with code 2 when vulnerabilities meet or exceed --fail-on threshold", async () => {
    // The testbed has HIGH findings (e.g. unauthenticated private profile)
    const args = [
      "node",
      "src/index.js",
      "--spec",
      specPath,
      "--base-url",
      baseUrl,
      "--checks",
      "auth",
      "--fail-on",
      "high"
    ];

    const exitCode = await runCli(args);
    expect(exitCode).toBe(2);
  });

  it("should exit with code 0 when findings are below the --fail-on threshold", async () => {
    // Testbed has 0 CRITICAL findings
    const args = [
      "node",
      "src/index.js",
      "--spec",
      specPath,
      "--base-url",
      baseUrl,
      "--checks",
      "headers,cors",
      "--fail-on",
      "critical"
    ];

    const exitCode = await runCli(args);
    expect(exitCode).toBe(0);
  });

  it("should reject invalid --fail-on argument with exit code 1", async () => {
    const args = [
      "node",
      "src/index.js",
      "--spec",
      specPath,
      "--base-url",
      baseUrl,
      "--fail-on",
      "invalid_level"
    ];

    const exitCode = await runCli(args);
    expect(exitCode).toBe(1);
  });
});
