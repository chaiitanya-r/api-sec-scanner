import fs from "node:fs/promises";
import path from "node:path";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/**
 * Aggregates findings and generates a deterministic scan report object.
 *
 * @param {Object} params
 * @param {string} params.target - Target base URL
 * @param {string} params.specPath - Path to OpenAPI spec
 * @param {number} params.durationMs - Scan duration in ms
 * @param {import('./types.js').AuditFinding[]} params.findings - List of findings
 * @param {string} [params.version='1.0.0']
 * @returns {import('./types.js').ScanReport}
 */
export function buildScanReport({
  target,
  specPath,
  durationMs,
  findings = [],
  version = "1.0.0"
}) {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length
  };

  for (const f of findings) {
    const sev = (f.severity || "INFO").toLowerCase();
    if (summary[sev] !== undefined) {
      summary[sev]++;
    } else {
      summary.info++;
    }
  }

  // Ensure findings are deterministically sorted
  const sortedFindings = [...findings].sort((a, b) => {
    const sevA = SEVERITY_ORDER.indexOf(a.severity);
    const sevB = SEVERITY_ORDER.indexOf(b.severity);
    if (sevA !== sevB) return sevA - sevB;

    const pathCmp = (a.endpoint || "").localeCompare(b.endpoint || "");
    if (pathCmp !== 0) return pathCmp;

    const methodCmp = (a.method || "").localeCompare(b.method || "");
    if (methodCmp !== 0) return methodCmp;

    return (a.id || "").localeCompare(b.id || "");
  });

  return {
    scanner: "api-sec-scanner",
    version,
    timestamp: new Date().toISOString(),
    target,
    specPath,
    durationMs,
    summary,
    findings: sortedFindings
  };
}

/**
 * Writes the structured JSON report to a file.
 *
 * @param {string} outPath - Destination path
 * @param {import('./types.js').ScanReport} report - Report data object
 * @returns {Promise<string>} Resolved output path
 */
export async function writeJsonReport(outPath, report) {
  const resolved = path.resolve(process.cwd(), outPath);
  await fs.mkdir(path.dirname(resolved), { recursive: true });
  await fs.writeFile(resolved, JSON.stringify(report, null, 2), "utf-8");
  return resolved;
}
