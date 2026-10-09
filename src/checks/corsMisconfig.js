import { getCvssScore } from "../reporter/cvss.js";

const BENIGN_PROBE_ORIGIN = "https://audit-probe.example.com";

/**
 * Checks for dangerous CORS configurations (Wildcard origin, arbitrary origin reflection with credentials).
 * Uses strictly benign probe headers.
 *
 * @param {import('../runner/httpClient.js').createHttpClient} httpClient
 * @param {import('../parser/types.js').NormalizedEndpoint} endpoint
 * @returns {Promise<import('../reporter/types.js').AuditFinding[]>}
 */
export async function checkCorsMisconfig(httpClient, endpoint) {
  const findings = [];
  const targetPath = endpoint.resolvedPath || endpoint.path;

  // Probe with both actual method and preflight OPTIONS
  let actualRes;
  let preflightRes;

  try {
    actualRes = await httpClient.sendRequest({
      method: endpoint.method,
      path: targetPath,
      headers: {
        Origin: BENIGN_PROBE_ORIGIN
      }
    });
  } catch (_err) {
    // Graceful error handling
  }

  try {
    preflightRes = await httpClient.sendRequest({
      method: "OPTIONS",
      path: targetPath,
      headers: {
        Origin: BENIGN_PROBE_ORIGIN,
        "Access-Control-Request-Method": endpoint.method
      }
    });
  } catch (_err) {
    // Graceful error handling
  }

  const responsesToCheck = [actualRes, preflightRes].filter((r) => r && r.headers);
  if (responsesToCheck.length === 0) {
    findings.push({
      id: "ERR-CORS-001",
      title: "CORS probe request failed",
      severity: "INFO",
      cvssScore: 0.0,
      endpoint: endpoint.path,
      method: endpoint.method,
      description: "Unable to reach endpoint for CORS probing.",
      evidence: {
        requestSent: { method: endpoint.method, url: targetPath, headers: { Origin: BENIGN_PROBE_ORIGIN } },
        responseReceived: { status: 0, headers: {}, bodyExcerpt: "Connection failed" }
      },
      remediation: {
        explanation: "Verify target endpoint accessibility.",
        codeSnippet: "// Ensure the API server is reachable."
      }
    });
    return findings;
  }

  let reportedReflect = false;
  let reportedWildcard = false;

  for (const response of responsesToCheck) {
    const headers = response.headers || {};
    const allowOrigin = headers["access-control-allow-origin"];
    const allowCreds = headers["access-control-allow-credentials"];

    // 1. Reflected origin with credentials allowed
    if (
      !reportedReflect &&
      allowOrigin === BENIGN_PROBE_ORIGIN &&
      allowCreds &&
      allowCreds.toLowerCase() === "true"
    ) {
      reportedReflect = true;
      findings.push({
        id: "CORS-REFLECT-001",
        title: "Arbitrary Origin Reflection with Credentials Allowed",
        severity: "CRITICAL",
        cvssScore: getCvssScore("CRITICAL"),
        endpoint: endpoint.path,
        method: endpoint.method,
        description: "The API reflects arbitrary Origin request headers in 'Access-Control-Allow-Origin' while enabling 'Access-Control-Allow-Credentials: true'. This allows any external website to read authenticated responses on behalf of users.",
        evidence: response.evidence,
        remediation: {
          explanation: "Validate the incoming Origin against an explicit whitelist of trusted origins before reflecting it, and avoid allowing credentials for untrusted origins.",
          codeSnippet: `import cors from "cors";\n\nconst allowedOrigins = ["https://trusted.example.com"];\n\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || allowedOrigins.includes(origin)) {\n      callback(null, true);\n    } else {\n      callback(new Error("Not allowed by CORS"));\n    }\n  },\n  credentials: true\n}));`
        }
      });
    }

    // 2. Wildcard Access-Control-Allow-Origin: *
    if (!reportedWildcard && allowOrigin === "*") {
      reportedWildcard = true;
      const severity = endpoint.requiresAuth ? "HIGH" : "MEDIUM";
      findings.push({
        id: "CORS-WILD-001",
        title: endpoint.requiresAuth
          ? "Wildcard CORS on Authenticated Endpoint"
          : "Wildcard CORS Access-Control-Allow-Origin: *",
        severity,
        cvssScore: getCvssScore(severity),
        endpoint: endpoint.path,
        method: endpoint.method,
        description: `The API sets 'Access-Control-Allow-Origin: *', allowing any arbitrary domain to access this resource.${
          endpoint.requiresAuth
            ? " This endpoint is marked as requiring authentication in the OpenAPI specification, making wildcard origin permissions risky."
            : ""
        }`,
        evidence: response.evidence,
        remediation: {
          explanation: "Restrict Access-Control-Allow-Origin to specific trusted domains instead of using a wildcard '*'.",
          codeSnippet: `import cors from "cors";\n\napp.use(cors({\n  origin: ["https://app.example.com"]\n}));`
        }
      });
    }
  }

  return findings;
}
