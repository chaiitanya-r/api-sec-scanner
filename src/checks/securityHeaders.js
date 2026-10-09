import { getCvssScore } from "../reporter/cvss.js";

/**
 * Checks for missing defensive security headers and server information leakage.
 *
 * @param {import('../runner/httpClient.js').createHttpClient} httpClient
 * @param {import('../parser/types.js').NormalizedEndpoint} endpoint
 * @returns {Promise<import('../reporter/types.js').AuditFinding[]>}
 */
export async function checkSecurityHeaders(httpClient, endpoint) {
  const findings = [];
  const targetPath = endpoint.resolvedPath || endpoint.path;

  let response;
  try {
    response = await httpClient.sendRequest({
      method: endpoint.method === "GET" ? "GET" : "HEAD",
      path: targetPath
    });
  } catch (err) {
    findings.push({
      id: "ERR-HDR-001",
      title: "Header check request failed",
      severity: "INFO",
      cvssScore: 0.0,
      endpoint: endpoint.path,
      method: endpoint.method,
      description: `Unable to inspect security headers: ${err.message}`,
      evidence: {
        requestSent: { method: endpoint.method, url: targetPath, headers: {} },
        responseReceived: { status: 0, headers: {}, bodyExcerpt: err.message }
      },
      remediation: {
        explanation: "Verify target endpoint accessibility.",
        codeSnippet: "// Ensure the API server is reachable."
      }
    });
    return findings;
  }

  const headers = response.headers || {};
  const isHttps = httpClient.baseUrl?.startsWith("https://");

  // 1. Missing Content-Security-Policy
  if (!headers["content-security-policy"]) {
    findings.push({
      id: "HDR-CSP-001",
      title: "Missing Content-Security-Policy Header",
      severity: "MEDIUM",
      cvssScore: getCvssScore("MEDIUM"),
      endpoint: endpoint.path,
      method: endpoint.method,
      description: "The response does not include a Content-Security-Policy (CSP) header, which helps mitigate Cross-Site Scripting (XSS) and data injection risks.",
      evidence: response.evidence,
      remediation: {
        explanation: "Configure a restrictive Content-Security-Policy header or use Helmet middleware.",
        codeSnippet: `import helmet from "helmet";\n\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"]\n  }\n}));`
      }
    });
  }

  // 2. Missing Strict-Transport-Security (HSTS)
  if (!headers["strict-transport-security"]) {
    const severity = isHttps ? "MEDIUM" : "LOW";
    findings.push({
      id: "HDR-HSTS-001",
      title: "Missing Strict-Transport-Security (HSTS) Header",
      severity,
      cvssScore: getCvssScore(severity),
      endpoint: endpoint.path,
      method: endpoint.method,
      description: isHttps
        ? "The HTTPS response does not enforce HTTP Strict Transport Security (HSTS), leaving connections vulnerable to SSL stripping."
        : "HSTS header is absent. While this scan was conducted over HTTP, ensure HSTS is enabled in production HTTPS environments.",
      evidence: response.evidence,
      remediation: {
        explanation: "Enable HSTS in production to instruct browsers to connect exclusively via HTTPS.",
        codeSnippet: `import helmet from "helmet";\n\n// Enables HSTS with 1 year max-age\napp.use(helmet.hsts({\n  maxAge: 31536000,\n  includeSubDomains: true,\n  preload: true\n}));`
      }
    });
  }

  // 3. Missing X-Content-Type-Options
  if (!headers["x-content-type-options"] || headers["x-content-type-options"].toLowerCase() !== "nosniff") {
    findings.push({
      id: "HDR-CTO-001",
      title: "Missing or Invalid X-Content-Type-Options Header",
      severity: "LOW",
      cvssScore: getCvssScore("LOW"),
      endpoint: endpoint.path,
      method: endpoint.method,
      description: "The 'X-Content-Type-Options: nosniff' header is missing, allowing browsers to perform MIME-type sniffing.",
      evidence: response.evidence,
      remediation: {
        explanation: "Set X-Content-Type-Options: nosniff to prevent MIME type sniffing.",
        codeSnippet: `app.use((req, res, next) => {\n  res.setHeader("X-Content-Type-Options", "nosniff");\n  next();\n});`
      }
    });
  }

  // 4. Missing X-Frame-Options
  if (!headers["x-frame-options"]) {
    findings.push({
      id: "HDR-XFO-001",
      title: "Missing X-Frame-Options Header",
      severity: "LOW",
      cvssScore: getCvssScore("LOW"),
      endpoint: endpoint.path,
      method: endpoint.method,
      description: "The response does not specify X-Frame-Options, leaving the endpoint susceptible to Clickjacking if rendered in a frame.",
      evidence: response.evidence,
      remediation: {
        explanation: "Set X-Frame-Options to DENY or SAMEORIGIN.",
        codeSnippet: `app.use((req, res, next) => {\n  res.setHeader("X-Frame-Options", "DENY");\n  next();\n});`
      }
    });
  }

  // 5. Information Leakage: X-Powered-By
  if (headers["x-powered-by"]) {
    findings.push({
      id: "INFO-LEAK-001",
      title: "Server Technology Leakage via X-Powered-By",
      severity: "LOW",
      cvssScore: getCvssScore("LOW"),
      endpoint: endpoint.path,
      method: endpoint.method,
      description: `The server exposes its underlying framework (${headers["x-powered-by"]}) in the X-Powered-By header, aiding attacker reconnaissance.`,
      evidence: response.evidence,
      remediation: {
        explanation: "Disable the X-Powered-By header in Express.",
        codeSnippet: `app.disable("x-powered-by");\n// Or using helmet:\napp.use(helmet.hidePoweredBy());`
      }
    });
  }

  // 6. Information Leakage: Server header with detailed version
  if (headers["server"] && /\d+\.\d+/.test(headers["server"])) {
    findings.push({
      id: "INFO-LEAK-002",
      title: "Detailed Server Header Information Leakage",
      severity: "LOW",
      cvssScore: getCvssScore("LOW"),
      endpoint: endpoint.path,
      method: endpoint.method,
      description: `The Server response header reveals detailed versioning information (${headers["server"]}).`,
      evidence: response.evidence,
      remediation: {
        explanation: "Strip or sanitize the Server response header in your reverse proxy or application.",
        codeSnippet: `app.use((req, res, next) => {\n  res.removeHeader("Server");\n  next();\n});`
      }
    });
  }

  return findings;
}
