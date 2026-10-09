import { describe, it, expect } from "vitest";
import path from "node:path";
import {
  parseOpenApiSpec,
  getHarmlessSampleValue,
  resolvePathParameters,
  determineRequiresAuth
} from "../src/parser/openApiParser.js";

describe("OpenAPI Parser & Endpoint Normalizer", () => {
  const yamlSpecPath = path.resolve(__dirname, "sample-openapi.yaml");
  const jsonSpecPath = path.resolve(__dirname, "sample-openapi.json");

  describe("YAML Spec Parsing", () => {
    it("should parse and normalize endpoints from YAML spec", async () => {
      const result = await parseOpenApiSpec(yamlSpecPath);
      expect(result.info.title).toBe("Sample Test API");
      expect(result.endpoints).toBeInstanceOf(Array);
      expect(result.endpoints.length).toBe(4);

      // Verify deterministic ordering (path ascending, then method ascending)
      expect(result.endpoints[0].path).toBe("/items");
      expect(result.endpoints[0].method).toBe("POST");

      expect(result.endpoints[1].path).toBe("/public/health");
      expect(result.endpoints[1].method).toBe("GET");

      expect(result.endpoints[2].path).toBe("/users/{id}");
      expect(result.endpoints[2].method).toBe("GET");

      expect(result.endpoints[3].path).toBe("/users/{id}");
      expect(result.endpoints[3].method).toBe("PUT");
    });

    it("should properly determine requiresAuth based on global and operation rules", async () => {
      const result = await parseOpenApiSpec(yamlSpecPath);
      const publicHealth = result.endpoints.find((e) => e.path === "/public/health");
      const userGet = result.endpoints.find((e) => e.path === "/users/{id}" && e.method === "GET");
      const itemsPost = result.endpoints.find((e) => e.path === "/items");

      expect(publicHealth?.requiresAuth).toBe(false);
      expect(userGet?.requiresAuth).toBe(true);
      expect(itemsPost?.requiresAuth).toBe(true);
    });

    it("should resolve $ref parameters and responses", async () => {
      const result = await parseOpenApiSpec(yamlSpecPath);
      const itemsPost = result.endpoints.find((e) => e.path === "/items");
      expect(itemsPost).toBeDefined();

      const filterParam = itemsPost?.parameters.find((p) => p.name === "filter");
      expect(filterParam).toBeDefined();
      expect(filterParam?.in).toBe("query");
      expect(filterParam?.sampleValue).toBe("active");
      expect(itemsPost?.expectedResponses).toContain("201");
      expect(itemsPost?.expectedResponses).toContain("401");
    });

    it("should substitute path parameters with harmless sample values", async () => {
      const result = await parseOpenApiSpec(yamlSpecPath);
      const userGet = result.endpoints.find((e) => e.path === "/users/{id}" && e.method === "GET");
      expect(userGet?.resolvedPath).toBe("/users/42");
    });
  });

  describe("JSON Spec Parsing", () => {
    it("should parse and normalize endpoints from JSON spec", async () => {
      const result = await parseOpenApiSpec(jsonSpecPath);
      expect(result.info.title).toBe("Sample JSON Test API");
      expect(result.endpoints.length).toBe(3);

      const ping = result.endpoints.find((e) => e.path === "/ping");
      expect(ping?.requiresAuth).toBe(false);

      const productGet = result.endpoints.find((e) => e.path === "/products/{slug}" && e.method === "GET");
      expect(productGet?.requiresAuth).toBe(true);
      expect(productGet?.resolvedPath).toBe("/products/widget-123");
    });
  });

  describe("Helper Functions", () => {
    it("getHarmlessSampleValue should produce safe non-exploit values", () => {
      expect(getHarmlessSampleValue({ schema: { type: "integer" } })).toBe(1);
      expect(getHarmlessSampleValue({ schema: { type: "number" } })).toBe(1);
      expect(getHarmlessSampleValue({ schema: { type: "boolean" } })).toBe(true);
      expect(getHarmlessSampleValue({ schema: { type: "string" } })).toBe("test");
      expect(getHarmlessSampleValue({ schema: { type: "string", format: "uuid" } })).toBe("00000000-0000-0000-0000-000000000001");
      expect(getHarmlessSampleValue({ schema: { type: "string", format: "email" } })).toBe("test@example.com");
      expect(getHarmlessSampleValue({ example: "custom" })).toBe("custom");
    });

    it("resolvePathParameters should handle multiple placeholders safely", () => {
      const path = "/orgs/{orgId}/teams/{teamId}/members/{userId}";
      const params = [
        { name: "orgId", in: "path", schema: { type: "integer", example: 10 } },
        { name: "teamId", in: "path", schema: { type: "string", example: "alpha" } }
        // userId omitted to test default replacement
      ];
      const resolved = resolvePathParameters(path, params);
      expect(resolved).toBe("/orgs/10/teams/alpha/members/1");
    });

    it("determineRequiresAuth respects operation vs global security", () => {
      // Operation explicit empty security overrides global
      expect(determineRequiresAuth({ security: [] }, [{ bearer: [] }])).toBe(false);
      // Operation with security
      expect(determineRequiresAuth({ security: [{ oauth: [] }] }, [])).toBe(true);
      // Inherits global
      expect(determineRequiresAuth({}, [{ apiKey: [] }])).toBe(true);
      // No security
      expect(determineRequiresAuth({}, [])).toBe(false);
      expect(determineRequiresAuth({}, undefined)).toBe(false);
    });
  });

  describe("Error Handling", () => {
    it("should throw error for non-existent file", async () => {
      await expect(parseOpenApiSpec("./non-existent-spec.yaml")).rejects.toThrow();
    });
  });
});
