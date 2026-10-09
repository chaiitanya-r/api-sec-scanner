import { describe, it, expect, beforeAll, afterAll } from "vitest";
import path from "node:path";
import fs from "node:fs/promises";
import { createTestbedApp } from "../testbed/server.js";
import { runCli } from "../src/index.js";

describe("Integration End-to-End Scan", () => {
  let server;
  let baseUrl;
  const specPath = path.resolve(__dirname, "../testbed/openapi.yaml");
  const testJsonOut = path.resolve(__dirname, "test-output-report.json");
  const testHtmlOut = path.resolve(__dirname, "test-output-report.html");

  beforeAll(async () => {
    const app = createTestbedApp();
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    server?.close();
    try {
      await fs.unlink(testJsonOut);
      await fs.unlink(testHtmlOut);
    } catch {
      // Ignore if not created
    }
  });

  it("should execute end-to-end scan, generate reports, and verify zero false positives on secure control", async () => {
    const args = [
      "node",
      "src/index.js",
      "--spec",
      specPath,
      "--base-url",
      baseUrl,
      "--out",
      testJsonOut,
      "--html",
      testHtmlOut,
      "--checks",
      "headers,cors,auth,rate",
      "--burst",
      "10"
    ];

    const exitCode = await runCli(args);
    expect(exitCode).toBe(0);

    // Verify reports generated
    const jsonContent = await fs.readFile(testJsonOut, "utf-8");
    const report = JSON.parse(jsonContent);

    expect(report.scanner).toBe("api-sec-scanner");
    expect(report.summary.total).toBeGreaterThan(0);

    // 1. Check expected vulnerabilities detected
    const findingTitles = report.findings.map((f) => f.title);
    expect(findingTitles).toContain("Protected endpoint does not enforce authentication");
    expect(findingTitles).toContain("Wildcard CORS Access-Control-Allow-Origin: *");
    expect(findingTitles).toContain("Missing Rate Limiting Enforcement");
    expect(findingTitles).toContain("Server Technology Leakage via X-Powered-By");

    // 2. Check secure control endpoint does NOT produce false positives
    const secureControlFindings = report.findings.filter((f) => f.endpoint === "/api/secure-control");
    expect(secureControlFindings.length).toBe(0);

    // Verify HTML report exists
    const htmlContent = await fs.readFile(testHtmlOut, "utf-8");
    expect(htmlContent).toContain("<!DOCTYPE html>");
    expect(htmlContent).toContain("api-sec-scanner Audit Report");
  });

  it("should reject burst counts exceeding maximum safe threshold (100)", async () => {
    const args = [
      "node",
      "src/index.js",
      "--spec",
      specPath,
      "--base-url",
      baseUrl,
      "--burst",
      "150"
    ];

    const exitCode = await runCli(args);
    expect(exitCode).toBe(1);
  });

  it("should reject invalid check names", async () => {
    const args = [
      "node",
      "src/index.js",
      "--spec",
      specPath,
      "--base-url",
      baseUrl,
      "--checks",
      "headers,invalid_check"
    ];

    const exitCode = await runCli(args);
    expect(exitCode).toBe(1);
  });
});
