import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createTestbedApp } from "../testbed/server.js";
import { createHttpClient } from "../src/runner/httpClient.js";
import { checkRateLimiting } from "../src/checks/rateLimiting.js";

describe("Rate Limiting Check", () => {
  let server;
  let client;

  beforeAll(async () => {
    const app = createTestbedApp();
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", () => {
        const port = server.address().port;
        client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
        resolve();
      });
    });
  });

  afterAll(() => {
    server?.close();
  });

  it("should detect missing rate limiting on unthrottled endpoint", async () => {
    const endpoint = {
      path: "/api/action-burst",
      resolvedPath: "/api/action-burst",
      method: "POST",
      requiresAuth: false,
      parameters: [],
      expectedResponses: ["200"]
    };

    const findings = await checkRateLimiting(client, endpoint, { burst: 10 });
    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe("RATE-LIMIT-001");
  });

  it("should recognize rate limiting and produce NO findings when 429 is encountered", async () => {
    const endpoint = {
      path: "/api/secure-control",
      resolvedPath: "/api/secure-control",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200"]
    };

    // The secure control endpoint throttles after 5 requests
    const findings = await checkRateLimiting(client, endpoint, { burst: 15 });
    expect(findings.length).toBe(0);
  });
});
