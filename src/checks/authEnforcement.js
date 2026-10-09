import { getCvssScore } from "../reporter/cvss.js";

const DUMMY_MALFORMED_TOKEN = "Bearer malformed_placeholder_token_invalid_12345";

/**
 * Checks authentication enforcement on endpoints marked as requiring authentication.
 * Uses only controlled benign baseline requests. Never attempts brute-forcing or guessing.
 *
 * @param {import('../runner/httpClient.js').createHttpClient} httpClient
 * @param {import('../parser/types.js').NormalizedEndpoint} endpoint
 * @param {Object} [options]
 * @param {string} [options.expiredToken] - Optional explicitly provided known expired token
 * @returns {Promise<import('../reporter/types.js').AuditFinding[]>}
 */
export async function checkAuthEnforcement(httpClient, endpoint, options = {}) {
  // Only execute check if the OpenAPI spec designates this endpoint as requiring auth
  if (!endpoint.requiresAuth) {
    return [];
  }

  const findings = [];
  const targetPath = endpoint.resolvedPath || endpoint.path;

  // Case 1: Unauthenticated request (no Authorization header)
  try {
    const unauthRes = await httpClient.sendRequest({
      method: endpoint.method,
      path: targetPath,
      headers: {}
    });

    // If endpoint responds with 2xx/3xx instead of 401 or 403
    if (unauthRes.status >= 200 && unauthRes.status < 400) {
      findings.push({
        id: "AUTH-001",
        title: "Protected endpoint does not enforce authentication",
        severity: "HIGH",
        cvssScore: getCvssScore("HIGH"),
        endpoint: endpoint.path,
        method: endpoint.method,
        description: `The OpenAPI specification marks this endpoint as requiring authentication, but a request without credentials returned HTTP ${unauthRes.status} instead of 401 or 403.`,
        evidence: unauthRes.evidence,
        remediation: {
          explanation: "Ensure authentication middleware is mounted and actively enforced for this route.",
          codeSnippet: `// Example authentication middleware enforcement\nimport { requireAuth } from "./middleware/auth.js";\n\napp.use("${endpoint.path}", requireAuth);`
        }
      });
    }
  } catch (_err) {
    // Graceful error handling
  }

  // Case 2: Clearly malformed / placeholder token
  try {
    const malformedRes = await httpClient.sendRequest({
      method: endpoint.method,
      path: targetPath,
      headers: {
        Authorization: DUMMY_MALFORMED_TOKEN
      }
    });

    if (malformedRes.status >= 200 && malformedRes.status < 400) {
      findings.push({
        id: "AUTH-002",
        title: "Endpoint accepts malformed or invalid authentication token",
        severity: "HIGH",
        cvssScore: getCvssScore("HIGH"),
        endpoint: endpoint.path,
        method: endpoint.method,
        description: `The endpoint returned HTTP ${malformedRes.status} when supplied with an invalid placeholder token instead of returning 401 or 403.`,
        evidence: malformedRes.evidence,
        remediation: {
          explanation: "Validate token signature, structure, and integrity before granting access.",
          codeSnippet: `// Ensure cryptographic verification\nconst verified = jwt.verify(token, secretKey);`
        }
      });
    }
  } catch (_err) {
    // Graceful error handling
  }

  // Case 3: Expired token (only if explicitly provided in test options)
  if (options.expiredToken) {
    try {
      const expiredRes = await httpClient.sendRequest({
        method: endpoint.method,
        path: targetPath,
        headers: {
          Authorization: options.expiredToken.startsWith("Bearer ")
            ? options.expiredToken
            : `Bearer ${options.expiredToken}`
        }
      });

      if (expiredRes.status >= 200 && expiredRes.status < 400) {
        findings.push({
          id: "AUTH-003",
          title: "Endpoint accepts expired authentication token",
          severity: "HIGH",
          cvssScore: getCvssScore("HIGH"),
          endpoint: endpoint.path,
          method: endpoint.method,
          description: `The endpoint returned HTTP ${expiredRes.status} when supplied with a known expired test token instead of 401 or 403.`,
          evidence: expiredRes.evidence,
          remediation: {
            explanation: "Ensure expiration timestamps (exp claim) are strictly validated.",
            codeSnippet: `// Verify exp expiration claim\nif (Date.now() >= decoded.exp * 1000) {\n  return res.status(401).json({ error: "Token expired" });\n}`
          }
        });
      }
    } catch (_err) {
      // Graceful error handling
    }
  }

  return findings;
}
