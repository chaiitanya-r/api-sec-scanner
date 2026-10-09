import fs from "node:fs/promises";
import path from "node:path";

/**
 * Escapes characters for safe HTML injection prevention.
 *
 * @param {string} str
 * @returns {string}
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Maps severity to CSS styling tokens.
 */
const SEVERITY_COLORS = {
  CRITICAL: { bg: "#dc2626", text: "#fee2e2", border: "#ef4444" },
  HIGH: { bg: "#ea580c", text: "#ffedd5", border: "#f97316" },
  MEDIUM: { bg: "#d97706", text: "#fef3c7", border: "#f59e0b" },
  LOW: { bg: "#2563eb", text: "#dbeafe", border: "#3b82f6" },
  INFO: { bg: "#4b5563", text: "#f3f4f6", border: "#6b7280" }
};

/**
 * Generates a standalone HTML report string.
 *
 * @param {import('./types.js').ScanReport} report
 * @returns {string}
 */
export function generateHtmlReport(report) {
  const { summary, findings, target, specPath, timestamp, durationMs, version } = report;

  const findingCardsHtml = findings.map((f, idx) => {
    const sev = (f.severity || "INFO").toUpperCase();
    const colors = SEVERITY_COLORS[sev] || SEVERITY_COLORS.INFO;

    const requestJson = f.evidence?.requestSent
      ? escapeHtml(JSON.stringify(f.evidence.requestSent, null, 2))
      : "N/A";
    const responseJson = f.evidence?.responseReceived
      ? escapeHtml(JSON.stringify(f.evidence.responseReceived, null, 2))
      : "N/A";

    return `
      <div class="finding-card" id="finding-${idx}">
        <div class="finding-header">
          <div class="finding-title-group">
            <span class="badge" style="background-color: ${colors.bg}; color: #ffffff;">${escapeHtml(sev)}</span>
            <span class="finding-id">${escapeHtml(f.id)}</span>
            <h3 class="finding-title">${escapeHtml(f.title)}</h3>
          </div>
          <div class="finding-meta">
            <span class="cvss-tag">CVSS ${escapeHtml(f.cvssScore.toFixed(1))}</span>
            <span class="method-tag method-${escapeHtml(f.method.toLowerCase())}">${escapeHtml(f.method)}</span>
            <code class="endpoint-tag">${escapeHtml(f.endpoint)}</code>
          </div>
        </div>

        <p class="finding-desc">${escapeHtml(f.description)}</p>

        <div class="evidence-section">
          <h4>Evidence</h4>
          <div class="evidence-grid">
            <div class="evidence-block">
              <div class="code-title">Request Sent</div>
              <pre><code>${requestJson}</code></pre>
            </div>
            <div class="evidence-block">
              <div class="code-title">Response Received</div>
              <pre><code>${responseJson}</code></pre>
            </div>
          </div>
        </div>

        <div class="remediation-section">
          <h4>Remediation Guidance</h4>
          <p class="remediation-desc">${escapeHtml(f.remediation?.explanation || "Follow defensive security best practices.")}</p>
          ${
            f.remediation?.codeSnippet
              ? `
            <div class="code-title">Fix Snippet</div>
            <pre class="snippet-pre"><code>${escapeHtml(f.remediation.codeSnippet)}</code></pre>
          `
              : ""
          }
        </div>
      </div>
    `;
  }).join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Security Audit Report — ${escapeHtml(target)}</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem 1.5rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header { margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }
    .header-top { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
    h1 { font-size: 1.75rem; font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 0.5rem; }
    .header-sub { color: var(--text-muted); font-size: 0.875rem; margin-top: 0.5rem; }
    .meta-badge { font-family: monospace; background: #1e293b; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; }
    
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 2.5rem;
    }
    .summary-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      text-align: left;
    }
    .summary-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
    .summary-val { font-size: 1.8rem; font-weight: 700; margin-top: 0.25rem; }
    .c-crit { color: #ef4444; }
    .c-high { color: #f97316; }
    .c-med { color: #f59e0b; }
    .c-low { color: #3b82f6; }
    .c-info { color: #9ca3af; }

    .findings-container { display: flex; flex-direction: column; gap: 1.5rem; }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
    }
    .finding-header {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      margin-bottom: 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      padding-bottom: 0.75rem;
    }
    .finding-title-group { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
    .badge {
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      letter-spacing: 0.05em;
    }
    .finding-id { font-family: monospace; font-size: 0.85rem; color: var(--text-muted); }
    .finding-title { font-size: 1.15rem; font-weight: 600; color: #ffffff; }
    .finding-meta { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
    .cvss-tag { background: #374151; font-size: 0.75rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 4px; }
    .method-tag { font-family: monospace; font-weight: 700; font-size: 0.75rem; padding: 0.15rem 0.45rem; border-radius: 4px; background: #262626; color: #fff; }
    .method-get { background: #065f46; color: #a7f3d0; }
    .method-post { background: #1e40af; color: #bfdbfe; }
    .method-put { background: #854d0e; color: #fef08a; }
    .method-delete { background: #991b1b; color: #fecaca; }
    .endpoint-tag { font-family: monospace; background: #1f2937; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.85rem; color: #38bdf8; }
    .finding-desc { color: #d1d5db; margin-bottom: 1.25rem; font-size: 0.95rem; }

    .evidence-section, .remediation-section { margin-top: 1rem; }
    h4 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem; }
    .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem; }
    .evidence-block { background: #0b0f19; border: 1px solid #1e293b; border-radius: 6px; overflow: hidden; }
    .code-title { background: #1e293b; color: #94a3b8; font-size: 0.75rem; font-weight: 600; padding: 0.35rem 0.75rem; border-bottom: 1px solid #334155; }
    pre { padding: 0.75rem; overflow-x: auto; font-family: "JetBrains Mono", Consolas, monospace; font-size: 0.8rem; color: #e2e8f0; max-height: 250px; }
    .remediation-desc { color: #d1d5db; font-size: 0.9rem; margin-bottom: 0.5rem; }
    .snippet-pre { background: #0b0f19; border: 1px solid #1e293b; border-radius: 6px; }

    footer { text-align: center; margin-top: 3rem; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--border); padding-top: 1.5rem; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-top">
        <h1>🛡️ api-sec-scanner Audit Report</h1>
        <div>
          <span class="meta-badge">v${escapeHtml(version)}</span>
        </div>
      </div>
      <div class="header-sub">
        Target: <strong>${escapeHtml(target)}</strong> | Spec: <code>${escapeHtml(specPath)}</code> | Date: ${escapeHtml(timestamp)} | Scan Duration: ${escapeHtml(String(durationMs))}ms
      </div>
    </header>

    <div class="summary-grid">
      <div class="summary-card">
        <div class="summary-label">Critical</div>
        <div class="summary-val c-crit">${summary.critical}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">High</div>
        <div class="summary-val c-high">${summary.high}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Medium</div>
        <div class="summary-val c-med">${summary.medium}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Low</div>
        <div class="summary-val c-low">${summary.low}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Info</div>
        <div class="summary-val c-info">${summary.info}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Total Findings</div>
        <div class="summary-val" style="color: #ffffff;">${summary.total}</div>
      </div>
    </div>

    <section>
      <h2 style="font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; color: #ffffff;">
        Security Findings (${findings.length})
      </h2>
      <div class="findings-container">
        ${findingCardsHtml || '<p style="color: #9ca3af;">Zero security findings identified. Target API matched security baseline controls.</p>'}
      </div>
    </section>

    <footer>
      Generated autonomously by api-sec-scanner — Defensive API Security &amp; DAST Engine
    </footer>
  </div>
</body>
</html>`;
}

/**
 * Writes the standalone HTML report to a file.
 *
 * @param {string} outPath - Destination path
 * @param {import('./types.js').ScanReport} report - Report data object
 * @returns {Promise<string>} Resolved output path
 */
export async function writeHtmlReport(outPath, report) {
  const resolved = path.resolve(process.cwd(), outPath);
  await fs.mkdir(path.dirname(resolved), { recursive: true });
  await fs.writeFile(resolved, generateHtmlReport(report), "utf-8");
  return resolved;
}
