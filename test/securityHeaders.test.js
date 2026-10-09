import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createTestbedApp } from "../testbed/server.js";
import { createHttpClient } from "../src/runner/httpClient.js";
import { checkSecurityHeaders } from "../src/checks/securityHeaders.js";

describe("Security Headers Check", () => {
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

  it("should detect missing security headers and X-Powered-By leakage on vulnerable endpoint", async () => {
    const endpoint = {
      path: "/api/private-profile",
      resolvedPath: "/api/private-profile",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200"]
    };

    const findings = await checkSecurityHeaders(client, endpoint);

    expect(findings.length).toBeGreaterThan(0);
    const findingIds = findings.map((f) => f.id);
    expect(findingIds).toContain("HDR-CSP-001");
    expect(findingIds).toContain("HDR-CTO-001");
    expect(findingIds).toContain("HDR-XFO-001");
    expect(findingIds).toContain("INFO-LEAK-001"); // X-Powered-By
  });

  it("should NOT report false positives on hardened secure control endpoint", async () => {
    const endpoint = {
      path: "/api/secure-control",
      resolvedPath: "/api/secure-control",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200"]
    };

    const findings = await checkSecurityHeaders(client, endpoint);

    // The secure control sets CSP, HSTS, X-Content-Type-Options, X-Frame-Options and strips X-Powered-By/Server
    const findingIds = findings.map((f) => f.id);
    expect(findingIds).not.toContain("HDR-CSP-001");
    expect(findingIds).not.toContain("HDR-CTO-001");
    expect(findingIds).not.toContain("HDR-XFO-001");
    expect(findingIds).not.toContain("INFO-LEAK-001");
    expect(findingIds).not.toContain("INFO-LEAK-002");
  });
});
