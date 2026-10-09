import path from "node:path";
import fs from "node:fs/promises";
import SwaggerParser from "@apidevtools/swagger-parser";

const SUPPORTED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"];
const SUPPORTED_LOCATIONS = ["query", "header", "path"];

/**
 * Generates a harmless sample value for a given parameter schema.
 * Never produces exploit or injection strings.
 *
 * @param {Object} param - The parameter definition
 * @returns {*} Harmless sample value
 */
export function getHarmlessSampleValue(param) {
  if (param.example !== undefined) return param.example;
  if (param.schema?.example !== undefined) return param.schema.example;
  if (param.schema?.default !== undefined) return param.schema.default;

  const type = (param.schema?.type || "string").toLowerCase();

  switch (type) {
    case "integer":
      return 1;
    case "number":
      return 1;
    case "boolean":
      return true;
    case "array":
      return [];
    case "object":
      return {};
    case "string":
    default:
      if (param.schema?.format === "uuid") {
        return "00000000-0000-0000-0000-000000000001";
      }
      if (param.schema?.format === "date-time") {
        return "2026-01-01T00:00:00Z";
      }
      if (param.schema?.format === "email") {
        return "test@example.com";
      }
      return "test";
  }
}

/**
 * Replaces `{paramName}` in path template with harmless sample value.
 *
 * @param {string} pathTemplate
 * @param {Array<Object>} pathParams
 * @returns {string} Resolved harmless path
 */
export function resolvePathParameters(pathTemplate, pathParams = []) {
  let resolved = pathTemplate;
  for (const param of pathParams) {
    if (param.in === "path") {
      const sample = param.sampleValue !== undefined ? param.sampleValue : getHarmlessSampleValue(param);
      resolved = resolved.replace(
        new RegExp(`\\{${param.name}\\}`, "g"),
        encodeURIComponent(String(sample))
      );
    }
  }
  // If any unmatched template remains, replace with safe default '1'
  resolved = resolved.replace(/\{[^}]+\}/g, "1");
  return resolved;
}

/**
 * Determines whether an operation requires authentication based on OpenAPI security rules.
 *
 * Rules:
 * - operation.security non-empty -> true
 * - explicit operation.security: [] -> false
 * - otherwise inherits global security (if global security non-empty -> true, else false)
 *
 * @param {Object} operation - Operation definition
 * @param {Array<Object>} [globalSecurity] - Top-level security array
 * @returns {boolean}
 */
export function determineRequiresAuth(operation, globalSecurity) {
  if (Array.isArray(operation.security)) {
    return operation.security.length > 0;
  }
  if (Array.isArray(globalSecurity)) {
    return globalSecurity.length > 0;
  }
  return false;
}

/**
 * Parses and normalizes an OpenAPI 3.x specification file (YAML or JSON).
 * Resolves $ref definitions and validates the specification.
 *
 * @param {string|Object} specInput - Absolute or relative file path or raw spec object
 * @returns {Promise<{ info: Object, endpoints: import('./types.js').NormalizedEndpoint[] }>}
 */
export async function parseOpenApiSpec(specInput) {
  let specPath = specInput;

  // If passed as an object or string content, write or handle via SwaggerParser
  if (typeof specInput === "string") {
    specPath = path.resolve(process.cwd(), specInput);
    // Verify file existence
    await fs.access(specPath);
  }

  // SwaggerParser dereferences $ref and validates schema structure
  const parser = new SwaggerParser();
  const dereferencedApi = await parser.dereference(specPath);

  if (!dereferencedApi || !dereferencedApi.paths) {
    throw new Error("Invalid OpenAPI specification: missing 'paths' object.");
  }

  const globalSecurity = dereferencedApi.security || [];
  const normalizedEndpoints = [];

  for (const [pathKey, pathItem] of Object.entries(dereferencedApi.paths)) {
    if (!pathItem || typeof pathItem !== "object") continue;

    const pathLevelParameters = Array.isArray(pathItem.parameters)
      ? pathItem.parameters
      : [];

    for (const [methodKey, operation] of Object.entries(pathItem)) {
      const upperMethod = methodKey.toUpperCase();
      if (!SUPPORTED_METHODS.includes(upperMethod)) {
        continue;
      }
      if (!operation || typeof operation !== "object") {
        continue;
      }

      const operationParams = Array.isArray(operation.parameters)
        ? operation.parameters
        : [];

      // Combine parameters, operation-level overriding path-level by (name, in)
      const paramMap = new Map();
      for (const p of pathLevelParameters) {
        if (p && p.name && SUPPORTED_LOCATIONS.includes(p.in)) {
          paramMap.set(`${p.in}:${p.name}`, p);
        }
      }
      for (const p of operationParams) {
        if (p && p.name && SUPPORTED_LOCATIONS.includes(p.in)) {
          paramMap.set(`${p.in}:${p.name}`, p);
        }
      }

      const normalizedParams = Array.from(paramMap.values()).map((p) => ({
        name: p.name,
        in: p.in,
        type: p.schema?.type || (p.type ? String(p.type) : "string"),
        required: Boolean(p.required || p.in === "path"),
        sampleValue: getHarmlessSampleValue(p)
      }));

      const requiresAuth = determineRequiresAuth(operation, globalSecurity);
      const resolvedPath = resolvePathParameters(pathKey, normalizedParams);
      const expectedResponses = Object.keys(operation.responses || {}).sort();

      normalizedEndpoints.push({
        path: pathKey,
        resolvedPath,
        method: upperMethod,
        requiresAuth,
        parameters: normalizedParams,
        expectedResponses,
        summary: operation.summary || "",
        operationId: operation.operationId || ""
      });
    }
  }

  // Return deterministic ordering: sorted by path ascending, then method ascending
  normalizedEndpoints.sort((a, b) => {
    const pathCmp = a.path.localeCompare(b.path);
    if (pathCmp !== 0) return pathCmp;
    return a.method.localeCompare(b.method);
  });

  return {
    info: dereferencedApi.info || { title: "API Specification", version: "1.0.0" },
    endpoints: normalizedEndpoints
  };
}
