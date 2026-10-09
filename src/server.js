import express from "express";
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseOpenApiSpec } from "./parser/openApiParser.js";
import { createHttpClient } from "./runner/httpClient.js";
import { runSecurityScan } from "./runner/testDispatcher.js";
import { validateTargetScope } from "./safety/scopeGuard.js";
import { buildScanReport, writeJsonReport } from "./reporter/jsonReporter.js";
import { defaultRules } from "./config/defaultRules.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const CLIENT_DIST_DIR = path.join(ROOT_DIR, "client", "dist");
const REPORTS_DIR = path.join(ROOT_DIR, "reports");

/**
 * Creates and configures the API Security Scanner Dashboard & Web Server.
 *
 * @returns {express.Express}
 */
export function createServerApp() {
  const app = express();

  app.use(express.json({ limit: "10mb" }));

  // Basic CORS headers for development/dashboard access
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }
    next();
  });

  // Health check endpoint
  app.get("/api/health", (_req, res) => {
    res.json({
      status: "ok",
      scanner: "api-sec-scanner",
      version: "1.0.0",
      uptimeSeconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    });
  });

  // Fetch the latest scan report
  app.get("/api/report", async (_req, res) => {
    const candidatePaths = [
      path.join(ROOT_DIR, "report.json"),
      path.join(ROOT_DIR, "client", "public", "report.json")
    ];

    // Check reports directory for most recent report
    try {
      const files = await fs.readdir(REPORTS_DIR);
      const jsonReports = files
        .filter((f) => f.endsWith(".json"))
        .sort()
        .reverse();

      if (jsonReports.length > 0) {
        candidatePaths.unshift(path.join(REPORTS_DIR, jsonReports[0]));
      }
    } catch {
      // reports dir might not exist yet
    }

    for (const p of candidatePaths) {
      try {
        const content = await fs.readFile(p, "utf-8");
        const parsed = JSON.parse(content);
        return res.json(parsed);
      } catch {
        continue;
      }
    }

    res.status(404).json({
      error: "No scan report available. Run a scan via CLI or /api/scan first."
    });
  });

  // List historical reports in reports/
  app.get("/api/reports", async (_req, res) => {
    try {
      await fs.mkdir(REPORTS_DIR, { recursive: true });
      const files = await fs.readdir(REPORTS_DIR);
      const jsonReports = files.filter((f) => f.endsWith(".json"));
      res.json({ reports: jsonReports });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Trigger an automated security scan
  app.post("/api/scan", async (req, res) => {
    const {
      baseUrl,
      specPath = "./testbed/openapi.yaml",
      specContent,
      checks = "headers,cors,auth,rate",
      burst = defaultRules.rateLimit.burst,
      concurrency = defaultRules.network.concurrency,
      timeoutMs = defaultRules.network.timeoutMs,
      iOwnThisTarget = false
    } = req.body || {};

    if (!baseUrl) {
      return res.status(400).json({ error: "Missing required parameter: baseUrl" });
    }

    // Validate Scope
    const scopeCheck = validateTargetScope(baseUrl, Boolean(iOwnThisTarget));
    if (!scopeCheck.allowed) {
      return res.status(403).json({
        error: "Scope Guard Blocked Request",
        details: scopeCheck.error
      });
    }

    const burstCount = Math.min(
      Math.max(parseInt(burst, 10) || defaultRules.rateLimit.burst, 1),
      defaultRules.rateLimit.maxBurst
    );

    const checksList = String(checks)
      .split(",")
      .map((c) => c.trim().toLowerCase());

    const enabledChecks = {
      headers: checksList.includes("headers"),
      cors: checksList.includes("cors"),
      auth: checksList.includes("auth"),
      rate: checksList.includes("rate")
    };

    let specFilePath = specPath;
    let tempSpecCreated = false;

    try {
      // If client provided raw spec content, write it to temporary file
      if (specContent) {
        tempSpecCreated = true;
        await fs.mkdir(path.join(ROOT_DIR, "reports"), { recursive: true });
        specFilePath = path.join(ROOT_DIR, "reports", `spec-temp-${Date.now()}.yaml`);
        await fs.writeFile(specFilePath, specContent, "utf-8");
      } else {
        specFilePath = path.isAbsolute(specPath) ? specPath : path.resolve(ROOT_DIR, specPath);
      }

      const parsedSpec = await parseOpenApiSpec(specFilePath);

      const httpClient = createHttpClient({
        baseUrl,
        timeoutMs: parseInt(timeoutMs, 10) || 5000,
        concurrency: parseInt(concurrency, 10) || 5
      });

      const startTime = Date.now();
      const findings = await runSecurityScan(httpClient, parsedSpec.endpoints, {
        enabledChecks,
        burst: burstCount
      });
      const durationMs = Date.now() - startTime;

      const report = buildScanReport({
        target: baseUrl,
        specPath: specPath || "provided-spec",
        durationMs,
        findings,
        version: "1.0.0"
      });

      // Save to reports directory and root report.json
      await fs.mkdir(REPORTS_DIR, { recursive: true });
      const timestampIso = new Date().toISOString().replace(/[:.]/g, "-");
      const reportFilename = `report-${timestampIso}.json`;
      await writeJsonReport(path.join(REPORTS_DIR, reportFilename), report);
      await writeJsonReport(path.join(ROOT_DIR, "report.json"), report);

      res.json({
        success: true,
        report,
        savedTo: reportFilename
      });
    } catch (err) {
      res.status(500).json({
        error: "Scan execution failed",
        details: err.message
      });
    } finally {
      if (tempSpecCreated && specFilePath) {
        try {
          await fs.unlink(specFilePath);
        } catch {
          // ignore cleanup errors
        }
      }
    }
  });

  // Serve static client bundle if built
  app.use(express.static(CLIENT_DIST_DIR));

  // SPA fallback: return index.html for unknown routes if client/dist exists
  app.use(async (_req, res) => {
    const indexPath = path.join(CLIENT_DIST_DIR, "index.html");
    try {
      await fs.access(indexPath);
      res.sendFile(indexPath);
    } catch {
      res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>api-sec-scanner Server</title>
          <style>
            body { font-family: system-ui, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 3rem; text-align: center; }
            h1 { color: #38bdf8; }
            .box { background: #161f30; padding: 2rem; border-radius: 8px; max-width: 600px; margin: 2rem auto; text-align: left; }
            code { background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 4px; color: #a5f3fc; }
          </style>
        </head>
        <body>
          <h1>api-sec-scanner Server</h1>
          <p>The dashboard backend is running.</p>
          <div class="box">
            <p><strong>To launch the React dashboard:</strong></p>
            <p>Run <code>npm run build</code> in the root directory to build the client, then reload this page.</p>
            <p><strong>Available API Endpoints:</strong></p>
            <ul>
              <li><code>GET /api/health</code> - Server status</li>
              <li><code>GET /api/report</code> - Latest scan report</li>
              <li><code>POST /api/scan</code> - Trigger security scan</li>
            </ul>
          </div>
        </body>
        </html>
      `);
    }
  });

  return app;
}

/**
 * Starts the server on the specified port.
 *
 * @param {number} [port]
 * @param {string} [host]
 * @returns {Promise<import('http').Server>}
 */
export async function startServer(port = process.env.PORT || 5000, host = process.env.HOST || "0.0.0.0") {
  const app = createServerApp();
  return new Promise((resolve) => {
    const server = app.listen(port, host, () => {
      console.log(`[dashboard] Web UI running at http://${host === "0.0.0.0" ? "localhost" : host}:${port}`);
      console.log(`[dashboard] API available at http://${host === "0.0.0.0" ? "localhost" : host}:${port}/api/report`);
      resolve(server);
    });
  });
}

// Auto-run if executed directly
const isDirectRun = process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("src/server.js");
if (isDirectRun) {
  const port = parseInt(process.env.PORT, 10) || 5000;
  startServer(port).catch((err) => {
    console.error("Failed to start server:", err);
    process.exit(1);
  });
}
