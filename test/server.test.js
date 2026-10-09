import { describe, it, expect, beforeAll, afterAll } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServerApp } from "../src/server.js";
import { createTestbedApp } from "../testbed/server.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("Dashboard & API Server", () => {
  let appServer;
  let testbedServer;
  let serverBaseUrl;
  let testbedBaseUrl;

  beforeAll(async () => {
    // Start testbed
    const testbedApp = createTestbedApp();
    await new Promise((resolve) => {
      testbedServer = testbedApp.listen(0, "127.0.0.1", () => {
        testbedBaseUrl = `http://127.0.0.1:${testbedServer.address().port}`;
        resolve();
      });
    });

    // Start server app
    const app = createServerApp();
    await new Promise((resolve) => {
      appServer = app.listen(0, "127.0.0.1", () => {
        serverBaseUrl = `http://127.0.0.1:${appServer.address().port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    testbedServer?.close();
    appServer?.close();
    try {
      const fs = await import("node:fs/promises");
      await fs.unlink(path.resolve(__dirname, "../report.json"));
    } catch {
      // Ignore if not present
    }
  });

  it("should respond to /api/health with status ok and version", async () => {
    const res = await fetch(`${serverBaseUrl}/api/health`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe("ok");
    expect(data.scanner).toBe("api-sec-scanner");
    expect(data.version).toBe("1.0.0");
  });

  it("should return scan reports via /api/report", async () => {
    const res = await fetch(`${serverBaseUrl}/api/report`);
    // Should either find report or 404 if clean
    expect([200, 404]).toContain(res.status);
    if (res.status === 200) {
      const data = await res.json();
      expect(data).toHaveProperty("findings");
    }
  });

  it("should execute an audit via POST /api/scan against testbed", async () => {
    const specPath = path.resolve(__dirname, "../testbed/openapi.yaml");
    const res = await fetch(`${serverBaseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        baseUrl: testbedBaseUrl,
        specPath,
        checks: "headers,cors",
        burst: 5
      })
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.report).toBeDefined();
    expect(data.report.findings.length).toBeGreaterThan(0);
  });

  it("should block unauthorized external targets in POST /api/scan via Scope Guard", async () => {
    const specPath = path.resolve(__dirname, "../testbed/openapi.yaml");
    const res = await fetch(`${serverBaseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        baseUrl: "https://example.com",
        specPath,
        iOwnThisTarget: false
      })
    });

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe("Scope Guard Blocked Request");
  });
});
