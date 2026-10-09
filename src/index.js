#!/usr/bin/env node

import { Command } from "commander";
import path from "node:path";
import fs from "node:fs/promises";
import { parseOpenApiSpec } from "./parser/openApiParser.js";
import { createHttpClient } from "./runner/httpClient.js";
import { runSecurityScan } from "./runner/testDispatcher.js";
import { validateTargetScope } from "./safety/scopeGuard.js";
import { buildScanReport, writeJsonReport } from "./reporter/jsonReporter.js";
import { writeHtmlReport } from "./reporter/htmlReporter.js";
import { defaultRules } from "./config/defaultRules.js";
import { startServer } from "./server.js";

const VALID_CHECKS = ["headers", "cors", "auth", "rate"];
const SEVERITY_LEVELS = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

/**
 * Main CLI action runner.
 */
export async function runCli(argv = process.argv) {
  const program = new Command();

  program
    .name("api-sec-scan")
    .description("Automated API Security Scanner & DAST Engine (Defensive Baseline Audit)")
    .version("1.0.0")
    .option("-s, --spec <path>", "Path to OpenAPI 3.x specification (YAML or JSON)")
    .option("-u, --base-url <url>", "Base URL of the target API")
    .option("-o, --out <path>", "Destination for JSON report", "report.json")
    .option("--html <path>", "Destination for standalone HTML report")
    .option("-c, --checks <checks>", "Comma-separated checks to run: headers,cors,auth,rate", "headers,cors,auth,rate")
    .option("-b, --burst <number>", "Rate limit probe burst count (max 100)", String(defaultRules.rateLimit.burst))
    .option("-t, --timeout <number>", "HTTP request timeout in milliseconds", String(defaultRules.network.timeoutMs))
    .option("-k, --concurrency <number>", "Max concurrent requests", String(defaultRules.network.concurrency))
    .option("--i-own-this-target", "Explicit authorization flag required for external/public targets", false)
    .option("--fail-on <severity>", "Exit with non-zero code if findings meet or exceed severity (critical, high, medium, low)")
    .option("--serve [port]", "Start the interactive web dashboard & API server");

  program.exitOverride();

  try {
    program.parse(argv);
  } catch (err) {
    if (err.code === "commander.helpDisplayed" || err.code === "commander.version") {
      return 0;
    }
    console.error(`Error: ${err.message}`);
    return 1;
  }

  const opts = program.opts();

  // Handle --serve flag
  if (opts.serve !== undefined) {
    const port = typeof opts.serve === "string" ? parseInt(opts.serve, 10) : 5000;
    await startServer(port || 5000);
    return 0;
  }

  // Validate required options for scan mode
  if (!opts.spec || !opts.baseUrl) {
    console.error("Error: required options missing: -s, --spec <path> and -u, --base-url <url>");
    console.error("Use --help for usage details, or --serve to start the web dashboard.");
    return 1;
  }

  // 1. Validate burst count
  const burst = parseInt(opts.burst, 10);
  if (isNaN(burst) || burst <= 0 || burst > defaultRules.rateLimit.maxBurst) {
    console.error(`Error: Burst count must be an integer between 1 and ${defaultRules.rateLimit.maxBurst}. Provided: ${opts.burst}`);
    return 1;
  }

  // 2. Validate concurrency
  const concurrency = parseInt(opts.concurrency, 10);
  if (isNaN(concurrency) || concurrency <= 0) {
    console.error(`Error: Concurrency must be an integer greater than 0. Provided: ${opts.concurrency}`);
    return 1;
  }

  // 3. Validate timeout
  const timeoutMs = parseInt(opts.timeout, 10);
  if (isNaN(timeoutMs) || timeoutMs <= 0) {
    console.error(`Error: Timeout must be an integer greater than 0. Provided: ${opts.timeout}`);
    return 1;
  }

  // 4. Validate checks
  const checksList = opts.checks.split(",").map((c) => c.trim().toLowerCase());
  for (const chk of checksList) {
    if (!VALID_CHECKS.includes(chk)) {
      console.error(`Error: Unknown check "${chk}". Allowed checks: ${VALID_CHECKS.join(", ")}`);
      return 1;
    }
  }

  // 5. Validate Base URL & Scope Guard
  const scopeValidation = validateTargetScope(opts.baseUrl, opts.iOwnThisTarget);
  if (!scopeValidation.allowed) {
    console.error(`\n[SCOPE GUARD ERROR] ${scopeValidation.error}\n`);
    return 1;
  }

  if (scopeValidation.warning) {
    console.warn(`\n⚠️  ${scopeValidation.warning}\n`);
  }

  // 6. Validate Spec file exists
  const resolvedSpec = path.resolve(process.cwd(), opts.spec);
  try {
    await fs.access(resolvedSpec);
  } catch {
    console.error(`Error: OpenAPI specification file not found: ${opts.spec}`);
    return 1;
  }

  console.log("API Security Scanner");
  console.log("--------------------");
  console.log(`Target: ${opts.baseUrl}`);
  console.log(`Spec: ${opts.spec}`);
  console.log(`Scope: ${scopeValidation.isLocal ? "LOCAL (Authorized)" : "EXTERNAL (Explicit Authorization)"}`);
  console.log(`Checks: ${checksList.join(", ")}\n`);
  console.log("Scanning...");

  const startTime = Date.now();

  // 7. Parse OpenAPI spec
  let parsedSpec;
  try {
    parsedSpec = await parseOpenApiSpec(resolvedSpec);
    console.log(`✓ Parsed ${parsedSpec.endpoints.length} endpoints`);
  } catch (err) {
    console.error(`Error: Failed to parse OpenAPI specification: ${err.message}`);
    return 1;
  }

  // 8. Initialize HTTP client & run test dispatcher
  const httpClient = createHttpClient({
    baseUrl: opts.baseUrl,
    timeoutMs,
    concurrency
  });

  const enabledChecks = {
    headers: checksList.includes("headers"),
    cors: checksList.includes("cors"),
    auth: checksList.includes("auth"),
    rate: checksList.includes("rate")
  };

  const findings = await runSecurityScan(httpClient, parsedSpec.endpoints, {
    enabledChecks,
    burst
  });

  if (enabledChecks.headers) console.log("✓ Security Headers");
  if (enabledChecks.cors) console.log("✓ CORS");
  if (enabledChecks.auth) console.log("✓ Authentication");
  if (enabledChecks.rate) console.log("✓ Rate Limiting");

  const durationMs = Date.now() - startTime;

  // 9. Build and save report
  const report = buildScanReport({
    target: opts.baseUrl,
    specPath: opts.spec,
    durationMs,
    findings,
    version: "1.0.0"
  });

  console.log("\nFindings:");
  console.log(`  CRITICAL ${report.summary.critical}`);
  console.log(`  HIGH     ${report.summary.high}`);
  console.log(`  MEDIUM   ${report.summary.medium}`);
  console.log(`  LOW      ${report.summary.low}`);
  console.log(`  INFO     ${report.summary.info}\n`);

  if (opts.out) {
    const jsonPath = await writeJsonReport(opts.out, report);
    console.log(`JSON report: ${jsonPath}`);
  }

  if (opts.html) {
    const htmlPath = await writeHtmlReport(opts.html, report);
    console.log(`HTML report: ${htmlPath}`);
  }

  // 10. Optional CI/CD Fail-On Gate Threshold Check
  if (opts.failOn) {
    const thresholdKey = opts.failOn.toUpperCase();
    const minSeverityRank = SEVERITY_LEVELS[thresholdKey];
    if (minSeverityRank === undefined) {
      console.error(`Error: Unknown --fail-on threshold "${opts.failOn}". Allowed: critical, high, medium, low`);
      return 1;
    }

    const failingFindings = report.findings.filter((f) => {
      const rank = SEVERITY_LEVELS[(f.severity || "INFO").toUpperCase()] ?? 0;
      return rank >= minSeverityRank;
    });

    if (failingFindings.length > 0) {
      console.error(`\n🚨 [CI SECURITY GATE FAILED] Found ${failingFindings.length} issue(s) at or above "${thresholdKey}" severity.`);
      return 2;
    }
  }

  return 0;
}

// Auto-run if executed directly as script
const isDirectRun = process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("src/index.js");
if (isDirectRun) {
  runCli(process.argv)
    .then((code) => {
      if (code !== 0) process.exit(code);
    })
    .catch((err) => {
      console.error("Fatal error:", err);
      process.exit(1);
    });
}
