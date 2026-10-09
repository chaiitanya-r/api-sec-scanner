import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createTestbedApp } from "../testbed/server.js";
import { createHttpClient } from "../src/runner/httpClient.js";
import { checkCorsMisconfig } from "../src/checks/corsMisconfig.js";

describe("CORS Misconfiguration Check", () => {
  let server;
  let client;

  beforeAll(async () => {
    const app = createTestbedApp();

    // Additional test route to verify reflected origin with credentials
    app.options("/api/reflected-cors", (req, res) => {
      const origin = req.headers["origin"];
      res.setHeader("Access-Control-Allow-Origin", origin || "*");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
      res.sendStatus(204);
    });

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

  it("should detect wildcard CORS on /api/public-data", async () => {
    const endpoint = {
      path: "/api/public-data",
      resolvedPath: "/api/public-data",
      method: "GET",
      requiresAuth: false,
      parameters: [],
      expectedResponses: ["200"]
    };

    const findings = await checkCorsMisconfig(client, endpoint);
    expect(findings.length).toBeGreaterThan(0);
    const wildcardFinding = findings.find((f) => f.id === "CORS-WILD-001");
    expect(wildcardFinding).toBeDefined();
    expect(wildcardFinding?.severity).toBe("MEDIUM");
  });

  it("should detect arbitrary reflected origin with credentials allowed", async () => {
    const endpoint = {
      path: "/api/reflected-cors",
      resolvedPath: "/api/reflected-cors",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200"]
    };

    const findings = await checkCorsMisconfig(client, endpoint);
    const reflectedFinding = findings.find((f) => f.id === "CORS-REFLECT-001");
    expect(reflectedFinding).toBeDefined();
    expect(reflectedFinding?.severity).toBe("CRITICAL");
  });

  it("should NOT report CORS vulnerabilities on hardened secure control endpoint", async () => {
    const endpoint = {
      path: "/api/secure-control",
      resolvedPath: "/api/secure-control",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200"]
    };

    const findings = await checkCorsMisconfig(client, endpoint);
    expect(findings.length).toBe(0);
  });
});
