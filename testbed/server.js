import express from "express";

/**
 * Creates and configures the Express testbed application.
 *
 * @returns {express.Express}
 */
export function createTestbedApp() {
  const app = express();
  app.use(express.json());

  // In-memory rate limiting map for the secure control endpoint
  const rateLimitMap = new Map();

  // Vulnerable default middleware: intentionally leaks server identity header
  app.use((req, res, next) => {
    // Only set header leakage on non-secure-control routes
    if (!req.path.startsWith("/api/secure-control")) {
      res.setHeader("X-Powered-By", "Express/4.21.0-Vulnerable");
      res.setHeader("Server", "Vulnerable-DAST-Testbed/1.0");
    }
    next();
  });

  // 1. Protected-by-spec endpoint that incorrectly returns 200 without authentication
  app.get("/api/private-profile", (req, res) => {
    // Intentionally ignores Authorization header and exposes sensitive data
    res.status(200).json({
      id: 42,
      username: "alice_admin",
      email: "alice@company.local",
      role: "administrator"
    });
  });

  // 2. Endpoint with Wildcard CORS misconfiguration & missing rate limiting
  app.get("/api/public-data", (req, res) => {
    // Intentionally permissive wildcard CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.status(200).json({
      items: ["item1", "item2", "item3"],
      isPublic: true
    });
  });

  // 3. Endpoint vulnerable to unlimited request bursts (no rate limiting)
  app.post("/api/action-burst", (req, res) => {
    res.status(200).json({
      success: true,
      action: "burst_processed",
      timestamp: Date.now()
    });
  });

  // 4. Fully hardened Secure Control Endpoint (demonstrating zero false positives)
  app.get("/api/secure-control", (req, res) => {
    const clientIp = req.ip || "127.0.0.1";
    const now = Date.now();

    // Strictly enforce rate limiting (max 5 requests per 10-second window)
    const windowMs = 10000;
    const maxRequests = 5;
    const clientRecord = rateLimitMap.get(clientIp) || { count: 0, resetTime: now + windowMs };

    if (now > clientRecord.resetTime) {
      clientRecord.count = 1;
      clientRecord.resetTime = now + windowMs;
    } else {
      clientRecord.count += 1;
    }
    rateLimitMap.set(clientIp, clientRecord);

    if (clientRecord.count > maxRequests) {
      res.setHeader("Retry-After", "60");
      res.setHeader("Content-Security-Policy", "default-src 'self'");
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");
      res.removeHeader("X-Powered-By");
      res.removeHeader("Server");
      return res.status(429).json({ error: "Too Many Requests", retryAfter: 60 });
    }

    // Strictly enforce security headers
    res.setHeader("Content-Security-Policy", "default-src 'self'");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.removeHeader("X-Powered-By");
    res.removeHeader("Server");

    // Restrictive CORS: only allow a specific trusted origin, never reflect arbitrary origin
    const origin = req.headers["origin"];
    if (origin === "https://trusted.internal.corp") {
      res.setHeader("Access-Control-Allow-Origin", "https://trusted.internal.corp");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }

    // Strictly enforce Authentication
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({ error: "Unauthorized: Missing Authorization header" });
    }

    // Benign check: reject placeholder, malformed, or expired test credentials
    if (
      !authHeader.startsWith("Bearer ") ||
      authHeader.includes("malformed") ||
      authHeader.includes("expired") ||
      authHeader === "Bearer [REDACTED]" ||
      authHeader === "Bearer test"
    ) {
      return res.status(401).json({ error: "Unauthorized: Invalid or expired token" });
    }

    return res.status(200).json({
      status: "secure_control_ok",
      message: "Access granted to authorized control endpoint"
    });
  });

  return app;
}

// Start standalone server if invoked directly
const isDirectRun = process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("testbed/server.js");
if (isDirectRun) {
  const PORT = process.env.PORT || 3000;
  const app = createTestbedApp();
  app.listen(PORT, "127.0.0.1", () => {
    console.log(`[testbed] Mock vulnerable server running at http://127.0.0.1:${PORT}`);
  });
}
