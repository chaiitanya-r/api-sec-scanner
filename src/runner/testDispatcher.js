import { checkSecurityHeaders } from "../checks/securityHeaders.js";
import { checkCorsMisconfig } from "../checks/corsMisconfig.js";
import { checkRateLimiting } from "../checks/rateLimiting.js";
import { checkAuthEnforcement } from "../checks/authEnforcement.js";

const SEVERITY_WEIGHTS = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1
};

/**
 * Dispatches enabled security checks across normalized endpoints.
 * Handles concurrency, catches check failures into structured findings,
 * and sorts all findings deterministically.
 *
 * @param {import('../runner/httpClient.js').createHttpClient} httpClient
 * @param {import('../parser/types.js').NormalizedEndpoint[]} endpoints
 * @param {Object} [options]
 * @param {Object} [options.enabledChecks] - Map of enabled checks: { headers, cors, auth, rate }
 * @param {number} [options.burst=30] - Burst count for rate check
 * @param {string} [options.expiredToken] - Optional test expired token
 * @returns {Promise<import('../reporter/types.js').AuditFinding[]>}
 */
export async function runSecurityScan(httpClient, endpoints, options = {}) {
  const enabled = {
    headers: options.enabledChecks?.headers !== false,
    cors: options.enabledChecks?.cors !== false,
    auth: options.enabledChecks?.auth !== false,
    rate: options.enabledChecks?.rate !== false
  };

  const allFindings = [];

  for (const endpoint of endpoints) {
    // 1. Security Headers check
    if (enabled.headers) {
      try {
        const headerFindings = await checkSecurityHeaders(httpClient, endpoint);
        allFindings.push(...headerFindings);
      } catch (err) {
        allFindings.push(createErrorFinding("HDR-ERR-999", "Security Headers Check Failure", endpoint, err));
      }
    }

    // 2. CORS configuration check
    if (enabled.cors) {
      try {
        const corsFindings = await checkCorsMisconfig(httpClient, endpoint);
        allFindings.push(...corsFindings);
      } catch (err) {
        allFindings.push(createErrorFinding("CORS-ERR-999", "CORS Check Failure", endpoint, err));
      }
    }

    // 3. Authentication Enforcement check
    if (enabled.auth && endpoint.requiresAuth) {
      try {
        const authFindings = await checkAuthEnforcement(httpClient, endpoint, {
          expiredToken: options.expiredToken
        });
        allFindings.push(...authFindings);
      } catch (err) {
        allFindings.push(createErrorFinding("AUTH-ERR-999", "Authentication Check Failure", endpoint, err));
      }
    }

    // 4. Rate Limiting check
    if (enabled.rate) {
      try {
        const rateFindings = await checkRateLimiting(httpClient, endpoint, {
          burst: options.burst || 30
        });
        allFindings.push(...rateFindings);
      } catch (err) {
        allFindings.push(createErrorFinding("RATE-ERR-999", "Rate Limiting Check Failure", endpoint, err));
      }
    }
  }

  // Deterministic sorting:
  // 1. Severity weight descending (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)
  // 2. Endpoint path ascending
  // 3. HTTP method ascending
  // 4. Finding ID ascending
  allFindings.sort((a, b) => {
    const weightA = SEVERITY_WEIGHTS[a.severity] || 0;
    const weightB = SEVERITY_WEIGHTS[b.severity] || 0;
    if (weightB !== weightA) return weightB - weightA;

    const pathCmp = (a.endpoint || "").localeCompare(b.endpoint || "");
    if (pathCmp !== 0) return pathCmp;

    const methodCmp = (a.method || "").localeCompare(b.method || "");
    if (methodCmp !== 0) return methodCmp;

    return (a.id || "").localeCompare(b.id || "");
  });

  return allFindings;
}

/**
 * Creates a structured error finding when an unexpected check failure occurs.
 */
function createErrorFinding(id, title, endpoint, error) {
  return {
    id,
    title,
    severity: "INFO",
    cvssScore: 0.0,
    endpoint: endpoint.path,
    method: endpoint.method,
    description: `Internal check error during evaluation: ${error.message || String(error)}`,
    evidence: {
      requestSent: { method: endpoint.method, url: endpoint.path, headers: {} },
      responseReceived: { status: 0, headers: {}, bodyExcerpt: error.stack || String(error) }
    },
    remediation: {
      explanation: "Inspect endpoint logs or reachability.",
      codeSnippet: "// Review testbed error logs."
    }
  };
}
