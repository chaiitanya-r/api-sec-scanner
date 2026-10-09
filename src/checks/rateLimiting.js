import { getCvssScore } from "../reporter/cvss.js";

const DEFAULT_BURST = 30;
const MAX_ALLOWED_BURST = 100;

/**
 * Checks for rate limiting enforcement using a bounded, benign request burst.
 * Never exceeds 100 requests. Never loops indefinitely.
 *
 * @param {import('../runner/httpClient.js').createHttpClient} httpClient
 * @param {import('../parser/types.js').NormalizedEndpoint} endpoint
 * @param {Object} [options]
 * @param {number} [options.burst=30] - Number of requests to send (max 100)
 * @returns {Promise<import('../reporter/types.js').AuditFinding[]>}
 */
export async function checkRateLimiting(httpClient, endpoint, options = {}) {
  const findings = [];
  const targetPath = endpoint.resolvedPath || endpoint.path;

  const burstCount = Math.min(
    MAX_ALLOWED_BURST,
    Math.max(5, options.burst || DEFAULT_BURST)
  );

  let rateLimitEnforced = false;
  let lastEvidence = null;

  // Send bounded batch of requests
  for (let i = 0; i < burstCount; i++) {
    try {
      const res = await httpClient.sendRequest({
        method: endpoint.method === "GET" ? "GET" : "POST",
        path: targetPath,
        headers: {
          "X-Audit-Probe-Id": `rate-check-${i + 1}`
        }
      });

      lastEvidence = res.evidence;

      if (res.status === 429 || res.headers["retry-after"]) {
        rateLimitEnforced = true;
        break; // Early exit once rate limit is confirmed
      }
    } catch {
      // In case of network interruption, don't crash
      break;
    }
  }

  // If burst completed without any 429 or Retry-After, rate limiting is absent
  if (!rateLimitEnforced) {
    const severity = endpoint.requiresAuth ? "HIGH" : "MEDIUM";
    findings.push({
      id: "RATE-LIMIT-001",
      title: "Missing Rate Limiting Enforcement",
      severity,
      cvssScore: getCvssScore(severity),
      endpoint: endpoint.path,
      method: endpoint.method,
      description: `The endpoint did not throttle or return HTTP 429 / Retry-After after a controlled burst of ${burstCount} requests, indicating missing rate limiting protections against automated abuse and resource exhaustion.`,
      evidence: lastEvidence || {
        requestSent: { method: endpoint.method, url: targetPath, headers: {} },
        responseReceived: { status: 200, headers: {}, bodyExcerpt: `Completed ${burstCount} requests without throttling.` }
      },
      remediation: {
        explanation: "Implement rate limiting using express-rate-limit to protect sensitive endpoints from abuse.",
        codeSnippet: `import rateLimit from "express-rate-limit";\n\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 100, // Limit each IP to 100 requests per window\n  standardHeaders: true,\n  legacyHeaders: false,\n  message: { error: "Too many requests, please try again later." }\n});\n\napp.use("${endpoint.path}", limiter);`
      }
    });
  }

  return findings;
}
