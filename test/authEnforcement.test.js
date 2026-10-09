import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createTestbedApp } from "../testbed/server.js";
import { createHttpClient } from "../src/runner/httpClient.js";
import { checkAuthEnforcement } from "../src/checks/authEnforcement.js";

describe("Authentication Enforcement Check", () => {
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

  it("should detect authentication missing on vulnerable protected endpoint", async () => {
    const endpoint = {
      path: "/api/private-profile",
      resolvedPath: "/api/private-profile",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200", "401"]
    };

    const findings = await checkAuthEnforcement(client, endpoint);
    expect(findings.length).toBeGreaterThan(0);

    const noAuthFinding = findings.find((f) => f.id === "AUTH-001");
    expect(noAuthFinding).toBeDefined();
    expect(noAuthFinding?.severity).toBe("HIGH");

    const malformedFinding = findings.find((f) => f.id === "AUTH-002");
    expect(malformedFinding).toBeDefined();
    expect(malformedFinding?.severity).toBe("HIGH");
  });

  it("should detect expired token vulnerability if configured", async () => {
    // Custom endpoint that accepts expired tokens
    const app = createTestbedApp();
    app.get("/api/flawed-expiry", (req, res) => {
      // Rejects missing auth, but accepts expired token
      if (!req.headers.authorization) return res.status(401).json({ error: "Missing token" });
      res.status(200).json({ ok: true });
    });

    let localServer;
    let localClient;
    await new Promise((resolve) => {
      localServer = app.listen(0, "127.0.0.1", () => {
        const port = localServer.address().port;
        localClient = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
        resolve();
      });
    });

    const endpoint = {
      path: "/api/flawed-expiry",
      resolvedPath: "/api/flawed-expiry",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200", "401"]
    };

    const findings = await checkAuthEnforcement(localClient, endpoint, {
      expiredToken: "expired.jwt.token.placeholder"
    });

    localServer.close();

    const expiredFinding = findings.find((f) => f.id === "AUTH-003");
    expect(expiredFinding).toBeDefined();
    expect(expiredFinding?.severity).toBe("HIGH");
  });

  it("should produce NO findings on hardened secure control endpoint", async () => {
    const endpoint = {
      path: "/api/secure-control",
      resolvedPath: "/api/secure-control",
      method: "GET",
      requiresAuth: true,
      parameters: [],
      expectedResponses: ["200", "401"]
    };

    const findings = await checkAuthEnforcement(client, endpoint, {
      expiredToken: "expired-token-sample"
    });
    // Correctly returns 401 for unauthenticated, malformed, and expired
    expect(findings.length).toBe(0);
  });

  it("should skip authentication checks for public endpoints", async () => {
    const endpoint = {
      path: "/api/public-data",
      resolvedPath: "/api/public-data",
      method: "GET",
      requiresAuth: false,
      parameters: [],
      expectedResponses: ["200"]
    };

    const findings = await checkAuthEnforcement(client, endpoint);
    expect(findings.length).toBe(0);
  });
});
